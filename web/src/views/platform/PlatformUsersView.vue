<template>
  <el-card shadow="never" header="平台用户">
    <div class="toolbar">
      <el-input
        v-model="keyword"
        placeholder="按账号/显示名搜索"
        clearable
        class="toolbar__search"
        @keyup.enter="users.reload()"
        @clear="users.reload()"
      />
      <el-button type="primary" @click="users.reload()">搜索</el-button>
      <el-button
        v-if="auth.hasPermission('platform:user:write')"
        type="success"
        @click="openCreate"
      >新建用户</el-button>
    </div>

    <el-alert v-if="users.errorMessage.value" :title="users.errorMessage.value" type="error" :closable="false" />
    <el-table v-loading="users.loading.value" :data="users.items.value" empty-text="暂无用户" stripe>
      <el-table-column prop="account" label="账号" min-width="160" />
      <el-table-column prop="display_name" label="显示名" min-width="140" />
      <el-table-column label="状态" width="100">
        <template #default="{ row }">
          <el-tag :type="row.status === 'active' ? 'success' : 'info'">{{ statusText(row.status) }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="平台角色" min-width="180">
        <template #default="{ row }">
          <el-tag v-for="code in row.platform_roles" :key="code" size="small" type="danger" effect="plain">{{ code }}</el-tag>
          <span v-if="!row.platform_roles?.length" class="muted">—</span>
        </template>
      </el-table-column>
      <el-table-column prop="auth_revision" label="认证修订" width="90" />
      <el-table-column prop="created_at" label="建档时间" min-width="170">
        <template #default="{ row }">{{ formatTime(row.created_at) }}</template>
      </el-table-column>
      <el-table-column label="操作" width="260" fixed="right">
        <template #default="{ row }">
          <el-button
            v-if="auth.hasPermission('platform:user:write')"
            link type="primary" @click="openEdit(row)"
          >资料/状态</el-button>
          <el-button
            v-if="auth.hasPermission('platform:user:password:reset')"
            link type="warning" @click="openReset(row)"
          >重置密码</el-button>
          <el-button
            v-if="auth.hasPermission('platform:user:role:assign')"
            link type="danger" @click="openRoles(row)"
          >平台角色</el-button>
        </template>
      </el-table-column>
    </el-table>
    <CursorPager
      :page-number="users.pageNumber.value"
      :has-more="users.hasMore.value"
      :loading="users.loading.value"
      @prev="users.prev()"
      @next="users.next()"
    />

    <el-dialog v-model="createVisible" title="新建平台用户" width="min(460px, 92vw)">
      <el-form :model="createForm" label-position="top">
        <el-form-item label="账号" required>
          <el-input v-model="createForm.account" autocomplete="off" />
        </el-form-item>
        <el-form-item label="显示名" required>
          <el-input v-model="createForm.display_name" />
        </el-form-item>
        <el-form-item label="初始密码（至少 10 位）" required>
          <el-input v-model="createForm.password" type="password" show-password autocomplete="new-password" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="createVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="saveCreate">保存</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="editVisible" title="修改资料或状态（CAS）" width="min(460px, 92vw)">
      <el-form label-position="top" v-if="editing">
        <el-form-item label="显示名">
          <el-input v-model="editForm.display_name" />
        </el-form-item>
        <el-form-item label="状态">
          <el-radio-group v-model="editForm.status">
            <el-radio value="active">正常</el-radio>
            <el-radio value="disabled">停用</el-radio>
          </el-radio-group>
        </el-form-item>
        <p class="muted">基于认证修订 {{ editing.auth_revision }} 提交，陈旧修改返回 409。</p>
      </el-form>
      <template #footer>
        <el-button @click="editVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="saveEdit">保存</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="resetVisible" title="重置密码" width="min(460px, 92vw)">
      <el-form label-position="top" v-if="resetting">
        <el-form-item label="账号">
          <span>{{ resetting.account }}</span>
        </el-form-item>
        <el-form-item label="新密码（至少 10 位）" required>
          <el-input v-model="resetPassword" type="password" show-password autocomplete="new-password" />
        </el-form-item>
        <el-alert title="保存后该用户全部既有会话立即失效" type="warning" :closable="false" />
      </el-form>
      <template #footer>
        <el-button @click="resetVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="saveReset">重置</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="rolesVisible" title="平台角色授予（全量替换）" width="min(520px, 92vw)" v-loading="rolesLoading">
      <el-checkbox-group v-model="roleCodes" class="role-group">
        <el-checkbox v-for="role in platformRoles" :key="role.id" :value="role.code">
          {{ role.name }}（{{ role.code }}）
        </el-checkbox>
      </el-checkbox-group>
      <template #footer>
        <el-button @click="rolesVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="saveRoles">保存授权</el-button>
      </template>
    </el-dialog>
  </el-card>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import CursorPager from '@/components/CursorPager.vue'
import { rolesApi, usersApi } from '@/api/endpoints'
import { ApiError } from '@/api/http'
import { usePagedList } from '@/composables/usePagedList'
import { useAuthStore } from '@/stores/auth'
import type { RoleView, UserView } from '@/api/types'

const auth = useAuthStore()
const keyword = ref('')

const users = usePagedList<UserView>(({ limit, cursor, signal }) =>
  usersApi.list({ keyword: keyword.value || undefined, limit, cursor }, signal)
)

onMounted(() => users.reload())

const saving = ref(false)
const createVisible = ref(false)
const editVisible = ref(false)
const resetVisible = ref(false)
const rolesVisible = ref(false)
const rolesLoading = ref(false)
const editing = ref<UserView | null>(null)
const resetting = ref<UserView | null>(null)
const resetPassword = ref('')
const platformRoles = ref<RoleView[]>([])
const roleCodes = ref<string[]>([])

const createForm = reactive({ account: '', display_name: '', password: '' })
const editForm = reactive({ display_name: '', status: 'active' })

function statusText(status: string): string {
  return status === 'active' ? '正常' : status === 'disabled' ? '停用' : status
}

function formatTime(iso: string): string {
  return new Date(iso).toLocaleString('zh-CN', { hour12: false })
}

function openCreate(): void {
  createForm.account = ''
  createForm.display_name = ''
  createForm.password = ''
  createVisible.value = true
}

async function saveCreate(): Promise<void> {
  saving.value = true
  try {
    await usersApi.create({ ...createForm })
    ElMessage.success('用户已建档')
    createVisible.value = false
    users.reload()
  } catch (e) {
    ElMessage.error(e instanceof ApiError ? e.message : '建档失败')
  } finally {
    saving.value = false
  }
}

function openEdit(row: UserView): void {
  editing.value = row
  editForm.display_name = row.display_name
  editForm.status = row.status
  editVisible.value = true
}

async function saveEdit(): Promise<void> {
  if (!editing.value) {
    return
  }
  saving.value = true
  try {
    await usersApi.update(editing.value.id, {
      display_name: editForm.display_name,
      status: editForm.status,
      expected_revision: editing.value.auth_revision
    })
    ElMessage.success('资料已更新')
    editVisible.value = false
    users.reload()
  } catch (e) {
    if (e instanceof ApiError && e.status === 409) {
      ElMessage.error('修订冲突：资料已被他人修改，请刷新列表后重试')
    } else {
      ElMessage.error(e instanceof ApiError ? e.message : '更新失败')
    }
  } finally {
    saving.value = false
  }
}

function openReset(row: UserView): void {
  resetting.value = row
  resetPassword.value = ''
  resetVisible.value = true
}

async function saveReset(): Promise<void> {
  if (!resetting.value) {
    return
  }
  saving.value = true
  try {
    await usersApi.resetPassword(resetting.value.id, resetPassword.value)
    ElMessage.success('密码已重置，旧会话已即时撤销')
    resetVisible.value = false
  } catch (e) {
    ElMessage.error(e instanceof ApiError ? e.message : '重置失败')
  } finally {
    saving.value = false
  }
}

async function openRoles(row: UserView): Promise<void> {
  editing.value = row
  rolesLoading.value = true
  rolesVisible.value = true
  try {
    const [catalog, assigned] = await Promise.all([
      rolesApi.list({ scope: 'platform' }),
      Promise.resolve(row.platform_roles)
    ])
    platformRoles.value = catalog.items
    roleCodes.value = [...assigned]
  } catch (e) {
    ElMessage.error(e instanceof ApiError ? e.message : '角色目录加载失败')
  } finally {
    rolesLoading.value = false
  }
}

async function saveRoles(): Promise<void> {
  if (!editing.value) {
    return
  }
  saving.value = true
  try {
    await usersApi.replacePlatformRoles(editing.value.id, roleCodes.value, editing.value.auth_revision)
    ElMessage.success('平台角色已替换')
    rolesVisible.value = false
    users.reload()
  } catch (e) {
    ElMessage.error(e instanceof ApiError ? e.message : '授权失败')
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
  flex-wrap: wrap;
}

.toolbar__search {
  width: 260px;
}

.muted {
  color: #94a3b8;
}

.role-group {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
</style>
