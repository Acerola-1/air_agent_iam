<template>
  <el-card shadow="never" :header="`部门管理 · ${tenantName}`">
    <div class="toolbar">
      <el-button type="success" @click="openCreate">新建部门</el-button>
      <el-button @click="departments.reload()">刷新</el-button>
    </div>
    <el-alert v-if="departments.errorMessage.value" :title="departments.errorMessage.value" type="error" :closable="false" />
    <el-table
      v-loading="departments.loading.value"
      :data="treeRows"
      empty-text="暂无部门"
      stripe
      row-key="id"
      default-expand-all
      :tree-props="{ children: 'children' }"
    >
      <el-table-column prop="code" label="部门编码" min-width="180" />
      <el-table-column prop="name" label="部门名称" min-width="200" />
      <el-table-column label="上级部门" min-width="160">
        <template #default="{ row }">{{ departmentName(row.parent_id) }}</template>
      </el-table-column>
      <el-table-column label="状态" width="90">
        <template #default="{ row }">
          <el-tag :type="row.status === 'active' ? 'success' : 'info'">
            {{ row.status === 'active' ? '正常' : '停用' }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="操作" width="100" fixed="right">
        <template #default="{ row }">
          <el-button link type="primary" @click="openEdit(row)">编辑</el-button>
        </template>
      </el-table-column>
    </el-table>
    <CursorPager
      :page-number="departments.pageNumber.value"
      :has-more="departments.hasMore.value"
      :loading="departments.loading.value"
      @prev="departments.prev()"
      @next="departments.next()"
    />

    <el-dialog v-model="createVisible" title="新建部门" width="min(460px, 92vw)" @keydown.esc.capture="closeDialogOnEscape">
      <el-form label-position="top">
        <el-form-item label="部门编码" required>
          <el-input v-model="createForm.code" />
        </el-form-item>
        <el-form-item label="部门名称" required>
          <el-input v-model="createForm.name" />
        </el-form-item>
        <el-form-item label="上级部门">
          <el-select v-model="createForm.parent_id" clearable class="full-width">
            <el-option v-for="dep in parentOptions" :key="dep.id" :label="dep.name" :value="dep.id" />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="createVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="saveCreate">保存</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="editVisible" title="编辑部门" width="min(460px, 92vw)" v-if="editing" @keydown.esc.capture="closeDialogOnEscape">
      <el-form label-position="top">
        <el-form-item label="部门名称" required>
          <el-input v-model="editForm.name" />
        </el-form-item>
        <el-form-item label="上级部门">
          <el-select v-model="editForm.parent_id" clearable class="full-width">
            <el-option
              v-for="dep in departments.items.value.filter((d) => d.id !== editing?.id)"
              :key="dep.id"
              :label="dep.name"
              :value="dep.id"
            />
          </el-select>
        </el-form-item>
        <el-form-item label="状态">
          <el-radio-group v-model="editForm.status">
            <el-radio value="active">正常</el-radio>
            <el-radio value="disabled">停用</el-radio>
          </el-radio-group>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="editVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="saveEdit">保存</el-button>
      </template>
    </el-dialog>
  </el-card>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import CursorPager from '@/components/CursorPager.vue'
import { departmentsApi } from '@/api/endpoints'
import { ApiError } from '@/api/http'
import { usePagedList } from '@/composables/usePagedList'
import { useAuthStore } from '@/stores/auth'
import type { DepartmentView } from '@/api/types'

const auth = useAuthStore()
const tenantName = computed(() => auth.identity?.current_tenant?.name ?? '')

const departments = usePagedList<DepartmentView>(({ limit, cursor, signal }) =>
  departmentsApi.list({ limit, cursor }, signal)
)
onMounted(() => departments.reload())
watch(
  () => auth.identity?.current_tenant?.id ?? '',
  () => departments.reload()
)

const parentOptions = computed(() => departments.items.value.filter((dep) => dep.status === 'active'))

interface DepartmentRow extends DepartmentView {
  children?: DepartmentRow[]
}

const treeRows = computed<DepartmentRow[]>(() => {
  const byId = new Map<string, DepartmentRow>()
  for (const dep of departments.items.value) {
    byId.set(dep.id, { ...dep, children: [] })
  }
  const roots: DepartmentRow[] = []
  for (const row of byId.values()) {
    if (row.parent_id && byId.has(row.parent_id)) {
      byId.get(row.parent_id)?.children?.push(row)
    } else {
      roots.push(row)
    }
  }
  return roots
})

const saving = ref(false)
const createVisible = ref(false)
const editVisible = ref(false)
const editing = ref<DepartmentView | null>(null)
const formContext = ref<{ tenant_id: string; expected_ctx_version: number } | null>(null)
const createForm = reactive({ code: '', name: '', parent_id: null as string | null })
const editForm = reactive({ name: '', parent_id: null as string | null, status: 'active' })

function closeDialogOnEscape(event: KeyboardEvent): void {
  if (event.isComposing) return
  const target = event.target
  // 展开的下拉框先消费 Escape；已收起的选择框不能拦住弹窗关闭。
  if (target instanceof HTMLElement && target.closest('[aria-expanded="true"]')) return
  event.preventDefault()
  event.stopPropagation()
  createVisible.value = false
  editVisible.value = false
}

function departmentName(id: string | null): string {
  if (!id) {
    return '—'
  }
  return departments.items.value.find((dep) => dep.id === id)?.name ?? id
}

function openCreate(): void {
  const identity = auth.identity
  if (!identity?.current_tenant) return
  formContext.value = { tenant_id: identity.current_tenant.id, expected_ctx_version: identity.context_version }
  createForm.code = ''
  createForm.name = ''
  createForm.parent_id = null
  createVisible.value = true
}

async function saveCreate(): Promise<void> {
  if (!formContext.value) return
  saving.value = true
  try {
    await departmentsApi.create({ ...createForm, ...formContext.value })
    ElMessage.success('部门已建档')
    createVisible.value = false
    departments.reload()
  } catch (e) {
    ElMessage.error(e instanceof ApiError ? e.message : '建档失败')
  } finally {
    saving.value = false
  }
}

function openEdit(row: DepartmentView): void {
  const identity = auth.identity
  if (!identity?.current_tenant) return
  formContext.value = { tenant_id: identity.current_tenant.id, expected_ctx_version: identity.context_version }
  editing.value = row
  editForm.name = row.name
  editForm.parent_id = row.parent_id
  editForm.status = row.status
  editVisible.value = true
}

async function saveEdit(): Promise<void> {
  if (!editing.value || !formContext.value) {
    return
  }
  saving.value = true
  try {
    await departmentsApi.update(editing.value.id, { ...editForm, ...formContext.value })
    ElMessage.success('部门已更新')
    editVisible.value = false
    departments.reload()
  } catch (e) {
    if (e instanceof ApiError && e.status === 409) {
      ElMessage.error('调整形成环路或与他人修改冲突，请调整上级后重试')
    } else {
      ElMessage.error(e instanceof ApiError ? e.message : '更新失败')
    }
  } finally {
    saving.value = false
  }
}
</script>

<style scoped>
.toolbar {
  display: flex;
  gap: 10px;
  margin-bottom: 14px;
}

.full-width {
  width: 100%;
}
</style>
