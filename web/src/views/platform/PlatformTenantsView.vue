<template>
  <el-card shadow="never" header="企业与组织">
    <div class="toolbar">
      <el-button v-if="auth.hasPermission('platform:tenant:write')" type="success" @click="openCreate">
        新建企业
      </el-button>
    </div>

    <el-alert v-if="tenants.errorMessage.value" :title="tenants.errorMessage.value" type="error" :closable="false" />
    <el-table v-loading="tenants.loading.value" :data="tenants.items.value" empty-text="暂无企业" stripe>
      <el-table-column prop="code" label="企业编码" min-width="160" />
      <el-table-column prop="name" label="企业名称" min-width="180" />
      <el-table-column label="状态" width="100">
        <template #default="{ row }">
          <el-tag :type="row.status === 'active' ? 'success' : 'info'">
            {{ row.status === 'active' ? '正常' : '停用' }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="auth_revision" label="修订" width="80" />
      <el-table-column prop="created_at" label="建档时间" min-width="170">
        <template #default="{ row }">{{ formatTime(row.created_at) }}</template>
      </el-table-column>
      <el-table-column label="操作" width="140" fixed="right">
        <template #default="{ row }">
          <el-button
            v-if="auth.hasPermission('platform:tenant:write')"
            link type="primary" @click="openEdit(row)"
          >名称/状态</el-button>
        </template>
      </el-table-column>
    </el-table>
    <CursorPager
      :page-number="tenants.pageNumber.value"
      :has-more="tenants.hasMore.value"
      :loading="tenants.loading.value"
      @prev="tenants.prev()"
      @next="tenants.next()"
    />

    <el-dialog v-model="createVisible" title="新建企业" width="min(440px, 92vw)">
      <el-form label-position="top">
        <el-form-item label="企业编码" required>
          <el-input v-model="createForm.code" placeholder="全局唯一" />
        </el-form-item>
        <el-form-item label="企业名称" required>
          <el-input v-model="createForm.name" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="createVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="saveCreate">保存</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="editVisible" title="修改企业（CAS）" width="min(440px, 92vw)" v-if="editing">
      <el-form label-position="top">
        <el-form-item label="企业名称">
          <el-input v-model="editForm.name" />
        </el-form-item>
        <el-form-item label="状态">
          <el-radio-group v-model="editForm.status">
            <el-radio value="active">正常</el-radio>
            <el-radio value="suspended">停用</el-radio>
          </el-radio-group>
        </el-form-item>
        <p class="muted">基于企业修订 {{ editing.auth_revision }} 提交。</p>
      </el-form>
      <template #footer>
        <el-button @click="editVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="saveEdit">保存</el-button>
      </template>
    </el-dialog>
  </el-card>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import CursorPager from '@/components/CursorPager.vue'
import { tenantsApi } from '@/api/endpoints'
import { ApiError } from '@/api/http'
import { usePagedList } from '@/composables/usePagedList'
import { useAuthStore } from '@/stores/auth'
import type { TenantView } from '@/api/types'

const auth = useAuthStore()
const tenants = usePagedList<TenantView>(({ limit, cursor, signal }) =>
  tenantsApi.list({ limit, cursor }, signal)
)
onMounted(() => tenants.reload())

const saving = ref(false)
const createVisible = ref(false)
const editVisible = ref(false)
const editing = ref<TenantView | null>(null)
const createForm = reactive({ code: '', name: '' })
const editForm = reactive({ name: '', status: 'active' })

function formatTime(iso: string): string {
  return new Date(iso).toLocaleString('zh-CN', { hour12: false })
}

function openCreate(): void {
  createForm.code = ''
  createForm.name = ''
  createVisible.value = true
}

async function saveCreate(): Promise<void> {
  saving.value = true
  try {
    await tenantsApi.create({ ...createForm })
    await auth.hydrate()
    ElMessage.success('企业已建档，创建人已设为首位企业管理员')
    createVisible.value = false
    tenants.reload()
  } catch (e) {
    ElMessage.error(e instanceof ApiError ? e.message : '建档失败')
  } finally {
    saving.value = false
  }
}

function openEdit(row: TenantView): void {
  editing.value = row
  editForm.name = row.name
  editForm.status = row.status
  editVisible.value = true
}

async function saveEdit(): Promise<void> {
  if (!editing.value) {
    return
  }
  saving.value = true
  try {
    await tenantsApi.update(editing.value.id, {
      name: editForm.name,
      status: editForm.status,
      expected_revision: editing.value.auth_revision
    })
    ElMessage.success('企业已更新')
    editVisible.value = false
    tenants.reload()
  } catch (e) {
    if (e instanceof ApiError && e.status === 409) {
      ElMessage.error('修订冲突：企业已被他人修改，请刷新后重试')
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
  flex-wrap: wrap;
}

.muted {
  color: #94a3b8;
}
</style>
