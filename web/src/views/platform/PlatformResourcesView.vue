<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { resourcesApi, type ResourceView } from '@/api/endpoints'
import { useAuthStore } from '@/stores/auth'
import { usePagedList } from '@/composables/usePagedList'
import { useWriteScope, type WriteScope } from '@/composables/useWriteScope'
import CursorPager from '@/components/CursorPager.vue'

const auth = useAuthStore()
const showCreate = ref(false)
const showEdit = ref(false)
const saving = ref(false)
const editing = ref<ResourceView | null>(null)

const createForm = ref({
  code: '', nameZh: '', sort: 0, parentCode: '',
  permissions: [{ code: '', nameZh: '', grantableToTenants: true }]
})
const editForm = ref({ nameZh: '', sort: 0, status: 'active', expectedRevision: 0 })

const lease = ref<WriteScope | null>(null)
const error = ref('')
let formVersion = 0
const scope = useWriteScope(() => {
  formVersion++; lease.value = null; showCreate.value = false; showEdit.value = false
})
function openCreate() {
  formVersion++; lease.value = scope.capture(); error.value = ''
  createForm.value = { code: '', nameZh: '', sort: 0, parentCode: '', permissions: [{ code: '', nameZh: '', grantableToTenants: true }] }
  showCreate.value = true
}

const resources = usePagedList<ResourceView>(({ limit, cursor, signal }) =>
  resourcesApi.list({ limit, cursor }, signal), { reloadKey: computed(() => auth.currentSnapshot) })

onMounted(() => resources.reload())

function addPermRow() {
  if (createForm.value.permissions.length < 32) {
    createForm.value.permissions.push({ code: '', nameZh: '', grantableToTenants: true })
  }
}
function removePermRow(i: number) {
  createForm.value.permissions.splice(i, 1)
}

async function doCreate() {
  const opened = lease.value; const version = formVersion
  if (saving.value || !scope.current(opened)) return
  if (!createForm.value.code.trim() || !createForm.value.nameZh.trim() || createForm.value.permissions.some(p => !p.code.trim() || !p.nameZh.trim())) { error.value = '请填写资源编码、中文名和全部权限绑定'; return }
  error.value = ''
  saving.value = true
  try {
    await resourcesApi.create({
      expected_context: opened.expected_context,
      code: createForm.value.code,
      name_zh: createForm.value.nameZh,
      sort: createForm.value.sort,
      parent_code: createForm.value.parentCode || null,
      permissions: createForm.value.permissions.map(p => ({
        code: p.code, name_zh: p.nameZh, grantable_to_tenants: p.grantableToTenants
      }))
    })
    if (!scope.current(opened) || version !== formVersion) return
    ElMessage.success('资源已登记')
    showCreate.value = false
    resources.reload()
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : '登记失败'
    if (scope.current(opened) && version === formVersion) error.value = msg
  } finally {
    saving.value = false
  }
}

function openEdit(row: ResourceView) {
  formVersion++; lease.value = scope.capture(); error.value = ''
  editing.value = row
  editForm.value = { nameZh: row.name_zh, sort: row.sort, status: row.status, expectedRevision: row.revision }
  showEdit.value = true
}

async function doEdit() {
  const opened = lease.value; const version = formVersion
  if (!editing.value || saving.value || !scope.current(opened)) return
  saving.value = true
  try {
    await resourcesApi.update(editing.value.code, {
      expected_context: opened.expected_context,
      expected_revision: editForm.value.expectedRevision,
      name_zh: editForm.value.nameZh,
      sort: editForm.value.sort,
      status: editForm.value.status
    })
    if (!scope.current(opened) || version !== formVersion) return
    ElMessage.success('资源已更新')
    showEdit.value = false
    resources.reload()
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : '更新失败'
    if (scope.current(opened) && version === formVersion) error.value = msg
  } finally {
    saving.value = false
  }
}
</script>

<template>
  <div>
    <el-card shadow="never" header="资源目录">
      <template #header>
        <div style="display:flex;justify-content:space-between;align-items:center">
          <span>资源目录</span>
          <el-button v-if="auth.hasPermission('entitlement:manage')" type="primary" @click="openCreate" :disabled="saving">
            登记资源
          </el-button>
        </div>
      </template>
      <el-alert v-if="resources.errorMessage.value" :title="resources.errorMessage.value" type="error" :closable="false" />
      <el-table :data="resources.items.value" v-loading="resources.loading.value" stripe empty-text="暂无资源">
        <el-table-column prop="code" label="资源编码" min-width="200" />
        <el-table-column prop="name_zh" label="中文名" min-width="120" />
        <el-table-column prop="status" label="状态" width="90">
          <template #default="{ row }">
            <el-tag :type="row.status === 'active' ? 'success' : 'info'">{{ row.status === 'active' ? '启用' : '停用' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="revision" label="修订" width="70" />
        <el-table-column label="权限绑定" min-width="200">
          <template #default="{ row }">
            <el-tag v-for="p in row.permissions" :key="p.code" size="small" style="margin:2px">
              {{ p.code }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="100" fixed="right">
          <template #default="{ row }">
            <el-button v-if="auth.hasPermission('entitlement:manage')" size="small" @click="openEdit(row)">编辑</el-button>
          </template>
        </el-table-column>
      </el-table>
      <CursorPager :page-number="resources.pageNumber.value" :has-more="resources.hasMore.value" :loading="resources.loading.value"
        @next="resources.next()" @prev="resources.prev()" />
    </el-card>

    <el-dialog v-model="showCreate" title="登记资源" width="min(560px, 92vw)">
      <el-alert v-if="error" :title="error" type="error" :closable="false" />
      <el-form label-position="top" novalidate>
        <el-form-item label="资源编码" required>
          <el-input v-model="createForm.code" placeholder="knowledge:lib:demo" />
        </el-form-item>
        <el-form-item label="中文名" required>
          <el-input v-model="createForm.nameZh" />
        </el-form-item>
        <el-form-item label="排序号">
          <el-input-number v-model="createForm.sort" :min="0" />
        </el-form-item>
        <el-form-item label="分组（可选）">
          <el-input v-model="createForm.parentCode" placeholder="knowledge" />
        </el-form-item>
        <el-form-item label="权限绑定（至少一项）">
          <div v-for="(p, i) in createForm.permissions" :key="i" class="permission-bind-row">
            <el-input v-model="p.code" placeholder="knowledge:lib:demo:read" style="flex:2" />
            <el-input v-model="p.nameZh" placeholder="中文名" style="flex:1" />
            <el-checkbox v-model="p.grantableToTenants">可下放</el-checkbox>
            <el-button v-if="createForm.permissions.length > 1" @click="removePermRow(i)" size="small">删</el-button>
          </div>
          <el-button @click="addPermRow" size="small">添加权限</el-button>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showCreate = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="doCreate">登记</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="showEdit" title="修改资源" width="min(440px, 92vw)">
      <el-alert v-if="error" :title="error" type="error" :closable="false" />
      <el-form label-position="top" novalidate>
        <el-form-item label="中文名">
          <el-input v-model="editForm.nameZh" />
        </el-form-item>
        <el-form-item label="排序号">
          <el-input-number v-model="editForm.sort" :min="0" />
        </el-form-item>
        <el-form-item label="状态">
          <el-select v-model="editForm.status">
            <el-option label="启用" value="active" />
            <el-option label="停用" value="disabled" />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showEdit = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="doEdit">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.permission-bind-row { display: flex; gap: 8px; margin-bottom: 8px; width: 100%; flex-wrap: wrap; }
.permission-bind-row .el-input { min-width: 125px; }
</style>
