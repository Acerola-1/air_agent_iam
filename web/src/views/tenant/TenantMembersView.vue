<template>
  <el-card shadow="never" :header="`成员管理 · ${tenantName}`">
    <div class="toolbar">
      <el-button type="success" @click="openCreate">新建/关联成员</el-button>
    </div>
    <el-alert v-if="members.errorMessage.value" :title="members.errorMessage.value" type="error" :closable="false" />
    <el-table v-loading="members.loading.value" :data="members.items.value" empty-text="暂无成员" stripe>
      <el-table-column label="账号" min-width="150">
        <template #default="{ row }">{{ row.user.account }}</template>
      </el-table-column>
      <el-table-column label="显示名" min-width="140">
        <template #default="{ row }">{{ row.user.display_name }}</template>
      </el-table-column>
      <el-table-column label="部门" min-width="140">
        <template #default="{ row }">{{ departmentName(row.department_id) }}</template>
      </el-table-column>
      <el-table-column label="企业角色" min-width="200">
        <template #default="{ row }">
          <el-tag v-for="code in row.roles" :key="code" size="small" type="success" effect="plain" class="perm-tag">
            {{ roleName(code) }}
          </el-tag>
          <span v-if="!row.roles.length" class="muted">—</span>
        </template>
      </el-table-column>
      <el-table-column label="状态" width="90">
        <template #default="{ row }">
          <el-tag :type="row.status === 'active' ? 'success' : 'info'">
            {{ row.status === 'active' ? '正常' : '停用' }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="revision" label="修订" width="70" />
      <el-table-column label="操作" width="240" fixed="right">
        <template #default="{ row }">
          <el-button link type="primary" @click="openEdit(row)">部门/状态</el-button>
          <el-button link type="warning" @click="openRoles(row)">角色</el-button>
          <el-button link type="danger" @click="remove(row)">移除</el-button>
        </template>
      </el-table-column>
    </el-table>
    <CursorPager
      :page-number="members.pageNumber.value"
      :has-more="members.hasMore.value"
      :loading="members.loading.value"
      @prev="members.prev()"
      @next="members.next()"
    />

    <el-dialog v-model="createVisible" title="新建账号并加入 / 关联既有账号" width="min(520px, 92vw)">
      <el-form label-position="top">
        <el-radio-group v-model="createMode" class="mode-group">
          <el-radio value="new">新建账号</el-radio>
          <el-radio value="existing">关联既有账号</el-radio>
        </el-radio-group>
        <template v-if="createMode === 'new'">
          <el-form-item label="账号" required>
            <el-input v-model="createForm.account" autocomplete="off" />
          </el-form-item>
          <el-form-item label="显示名" required>
            <el-input v-model="createForm.display_name" />
          </el-form-item>
          <el-form-item label="初始密码（至少 10 位）" required>
            <el-input v-model="createForm.password" type="password" show-password autocomplete="new-password" />
          </el-form-item>
        </template>
        <el-form-item v-else label="既有账号搜索（选择平台用户）" required>
          <el-select
            v-model="createForm.user_id"
            filterable
            remote
            reserve-keyword
            placeholder="输入账号关键字搜索"
            :remote-method="searchExisting"
            :loading="searching"
            class="full-width"
          >
            <el-option
              v-for="user in existingUsers"
              :key="user.id"
              :label="`${user.display_name}（${user.account}）`"
              :value="user.id"
            />
          </el-select>
        </el-form-item>
        <el-form-item label="部门">
          <el-select v-model="createForm.department_id" clearable class="full-width">
            <el-option v-for="dep in departments" :key="dep.id" :label="dep.name" :value="dep.id" />
          </el-select>
        </el-form-item>
        <el-form-item label="企业角色">
          <el-select v-model="createForm.role_codes" multiple class="full-width">
            <el-option v-for="role in tenantRoles" :key="role.id" :label="role.name" :value="role.code" />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="createVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="saveCreate">保存</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="editVisible" title="调整部门/状态（CAS）" width="min(460px, 92vw)" v-if="editing">
      <el-form label-position="top">
        <el-form-item label="部门">
          <el-select v-model="editForm.department_id" clearable class="full-width">
            <el-option v-for="dep in departments" :key="dep.id" :label="dep.name" :value="dep.id" />
          </el-select>
        </el-form-item>
        <el-form-item label="状态">
          <el-radio-group v-model="editForm.status">
            <el-radio value="active">正常</el-radio>
            <el-radio value="disabled">停用</el-radio>
          </el-radio-group>
        </el-form-item>
        <p class="muted">基于成员修订 {{ editing.revision }} 提交。</p>
      </el-form>
      <template #footer>
        <el-button @click="editVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="saveEdit">保存</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="rolesVisible" title="替换企业角色（CAS）" width="min(460px, 92vw)" v-if="editing">
      <el-select v-model="roleCodes" multiple class="full-width">
        <el-option v-for="role in tenantRoles" :key="role.id" :label="role.name" :value="role.code" />
      </el-select>
      <template #footer>
        <el-button @click="rolesVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="saveRoles">保存授权</el-button>
      </template>
    </el-dialog>
  </el-card>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import CursorPager from '@/components/CursorPager.vue'
import { departmentsApi, membersApi, rolesApi, usersApi } from '@/api/endpoints'
import { useWriteScope, type WriteScope } from '@/composables/useWriteScope'
import { ApiError } from '@/api/http'
import { usePagedList } from '@/composables/usePagedList'
import { useAuthStore } from '@/stores/auth'
import type { DepartmentView, MemberView, RoleView, UserView } from '@/api/types'

const auth = useAuthStore()
const tenantId = computed(() => auth.identity?.current_tenant?.id ?? '')
const tenantName = computed(() => auth.identity?.current_tenant?.name ?? '')

const members = usePagedList<MemberView>(({ limit, cursor, signal }) =>
  membersApi.list({ limit, cursor }, signal)
)
const departments = ref<DepartmentView[]>([])
const tenantRoles = ref<RoleView[]>([])

async function loadCatalogs(): Promise<void> {
  try {
    const [depPage, rolePage] = await Promise.all([
      departmentsApi.list({}, undefined),
      rolesApi.list({ scope: 'tenant', limit: 200 }, undefined)
    ])
    departments.value = depPage.items
    tenantRoles.value = rolePage.items
  } catch (e) {
    ElMessage.error(e instanceof ApiError ? e.message : '部门/角色目录加载失败')
  }
}

onMounted(() => {
  members.reload()
  void loadCatalogs()
})

watch(tenantId, () => {
  members.reload()
  void loadCatalogs()
})

const saving = ref(false)
const createVisible = ref(false)
const editVisible = ref(false)
const rolesVisible = ref(false)
const createMode = ref<'new' | 'existing'>('new')
const searching = ref(false)
const existingUsers = ref<UserView[]>([])
const editing = ref<MemberView | null>(null)
const roleCodes = ref<string[]>([])

const createForm = reactive({
  account: '',
  display_name: '',
  password: '',
  user_id: '' as string,
  department_id: null as string | null,
  role_codes: [] as string[]
})
const editForm = reactive({
  department_id: null as string | null,
  status: 'active'
})

function departmentName(id: string | null): string {
  if (!id) {
    return '—'
  }
  return departments.value.find((dep) => dep.id === id)?.name ?? id
}

function roleName(code: string): string {
  return tenantRoles.value.find((role) => role.code === code)?.name ?? code
}

function resetCreateForm(): void {
  createForm.account = ''
  createForm.display_name = ''
  createForm.password = ''
  createForm.user_id = ''
  createForm.department_id = null
  createForm.role_codes = []
}

function openCreate(): void {
  createLease.value = writeScope.capture()
  resetCreateForm()
  createMode.value = 'new'
  existingUsers.value = []
  createVisible.value = true
}

async function searchExisting(query: string): Promise<void> {
  if (!query.trim()) {
    existingUsers.value = []
    return
  }
  searching.value = true
  try {
    existingUsers.value = (await usersApi.list({ keyword: query, limit: 20 })).items
  } catch (e) {
    ElMessage.error(e instanceof ApiError ? e.message : '用户搜索失败')
  } finally {
    searching.value = false
  }
}

const createLease = ref<WriteScope | null>(null)
const rolesLease = ref<WriteScope | null>(null)
const writeScope = useWriteScope(() => { createVisible.value = false; rolesVisible.value = false; createLease.value = null; rolesLease.value = null })

async function saveCreate(): Promise<void> {
  const opened = createLease.value
  if (saving.value || !writeScope.current(opened)) return
  saving.value = true
  try {
    const body =
      createMode.value === 'existing'
        ? {
            tenant_id: tenantId.value,
            user_id: createForm.user_id,
            department_id: createForm.department_id ?? undefined,
            role_codes: createForm.role_codes
          }
        : {
            tenant_id: tenantId.value,
            account: createForm.account,
            display_name: createForm.display_name,
            password: createForm.password,
            department_id: createForm.department_id ?? undefined,
            role_codes: createForm.role_codes
          }
    await membersApi.create({ ...body, expected_context: opened.expected_context, expected_tenant_revision: opened.expected_tenant_revision })
    if (!writeScope.current(opened)) return
    ElMessage.success('成员关系已建立')
    createVisible.value = false
    members.reload()
  } catch (e) {
    ElMessage.error(e instanceof ApiError ? e.message : '建档失败')
  } finally {
    saving.value = false
  }
}

function openEdit(row: MemberView): void {
  editing.value = row
  editForm.department_id = row.department_id
  editForm.status = row.status
  editVisible.value = true
}

async function saveEdit(): Promise<void> {
  if (!editing.value) {
    return
  }
  saving.value = true
  try {
    await membersApi.update(editing.value.id, {
      department_id: editForm.department_id,
      status: editForm.status,
      expected_revision: editing.value.revision
    })
    ElMessage.success('成员已更新')
    editVisible.value = false
    members.reload()
  } catch (e) {
    if (e instanceof ApiError && e.status === 409) {
      ElMessage.error('修订冲突：成员已被他人修改，请刷新后重试')
    } else {
      ElMessage.error(e instanceof ApiError ? e.message : '更新失败')
    }
  } finally {
    saving.value = false
  }
}

function openRoles(row: MemberView): void {
  rolesLease.value = writeScope.capture()
  editing.value = row
  roleCodes.value = [...row.roles]
  rolesVisible.value = true
}

async function saveRoles(): Promise<void> {
  const opened = rolesLease.value
  if (saving.value || !writeScope.current(opened)) return
  if (!editing.value) {
    return
  }
  saving.value = true
  try {
    await membersApi.replaceRoles(editing.value.id, roleCodes.value, editing.value.revision, { expected_context: opened.expected_context, expected_tenant_revision: opened.expected_tenant_revision })
    if (!writeScope.current(opened)) return
    ElMessage.success('角色已替换')
    rolesVisible.value = false
    members.reload()
  } catch (e) {
    ElMessage.error(e instanceof ApiError ? e.message : '授权失败')
  } finally {
    saving.value = false
  }
}

async function remove(row: MemberView): Promise<void> {
  try {
    await ElMessageBox.confirm(
      `确定将 ${row.user.display_name}（${row.user.account}）移出本企业？`,
      '移除成员',
      { confirmButtonText: '移除', cancelButtonText: '取消', type: 'warning' }
    )
  } catch {
    return
  }
  try {
    await membersApi.remove(row.id)
    ElMessage.success('成员关系已移除')
    members.reload()
  } catch (e) {
    ElMessage.error(e instanceof ApiError ? e.message : '移除失败')
  }
}
</script>

<style scoped>
.toolbar {
  display: flex;
  gap: 10px;
  margin-bottom: 14px;
  flex-wrap: wrap;
}

.toolbar__search {
  width: 240px;
}

.muted {
  color: #94a3b8;
}

.perm-tag {
  margin-right: 4px;
  margin-bottom: 4px;
}

.mode-group {
  margin-bottom: 12px;
}

.full-width {
  width: 100%;
}
</style>
