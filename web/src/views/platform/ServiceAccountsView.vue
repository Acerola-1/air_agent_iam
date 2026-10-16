<template>
  <el-card shadow="never" header="服务账号与凭据">
    <div class="toolbar">
      <el-button type="success" @click="openCreate">新建服务账号</el-button>
    </div>
    <el-alert
      title="服务账号凭据仅在创建/轮换时显示一次明文；页面、接口列表与浏览器存储都不会保留。"
      type="warning"
      :closable="false"
      class="hint"
    />
    <el-alert v-if="accounts.errorMessage.value" :title="accounts.errorMessage.value" type="error" :closable="false" />
    <el-table v-loading="accounts.loading.value" :data="accounts.items.value" empty-text="暂无服务账号" stripe>
      <el-table-column prop="account" label="账号" min-width="180" />
      <el-table-column prop="name" label="名称" min-width="160" />
      <el-table-column label="受众" min-width="160">
        <template #default="{ row }">
          <el-tag v-for="aud in row.audiences" :key="aud" size="small" class="perm-tag">{{ aud }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="权限" min-width="200">
        <template #default="{ row }">
          <el-tag v-for="code in row.permissions.slice(0, 3)" :key="code" size="small" type="info" class="perm-tag">
            {{ code }}
          </el-tag>
          <el-tag v-if="row.permissions.length > 3" size="small" type="info">+{{ row.permissions.length - 3 }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="状态" width="90">
        <template #default="{ row }">
          <el-tag :type="row.status === 'active' ? 'success' : 'info'">
            {{ row.status === 'active' ? '启用' : '停用' }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="revision" label="修订" width="70" />
      <el-table-column label="操作" width="170" fixed="right">
        <template #default="{ row }">
          <el-button link type="primary" @click="openDetail(row)">凭据详情</el-button>
        </template>
      </el-table-column>
    </el-table>
    <CursorPager
      :page-number="accounts.pageNumber.value"
      :has-more="accounts.hasMore.value"
      :loading="accounts.loading.value"
      @prev="accounts.prev()"
      @next="accounts.next()"
    />

    <el-dialog v-model="createVisible" title="新建服务账号（最小受众/权限）" width="min(560px, 92vw)">
      <el-form label-position="top">
        <el-form-item label="账号" required>
          <el-input v-model="createForm.account" autocomplete="off" />
        </el-form-item>
        <el-form-item label="名称" required>
          <el-input v-model="createForm.name" />
        </el-form-item>
        <el-form-item label="绑定租户（留空为平台级）">
          <el-input v-model="createForm.tenant_id" placeholder="租户 UUID，可留空" />
        </el-form-item>
        <el-form-item label="受众（最小集合）" required>
          <el-select
            v-model="createForm.audiences"
            multiple
            allow-create
            filterable
            default-first-option
            class="full-width"
            placeholder="如 air-agent / knowledge"
          />
        </el-form-item>
        <el-form-item label="有效期（天，留空按服务默认）">
          <el-input-number v-model="createForm.expires_in_days" :min="1" :max="3650" />
        </el-form-item>
        <el-form-item label="权限码（最小集合）" required>
          <el-select
            v-model="createForm.permissions"
            multiple
            allow-create
            filterable
            default-first-option
            class="full-width"
            placeholder="按权限码精确填写"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="createVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="saveCreate">创建并签发凭据</el-button>
      </template>
    </el-dialog>

    <el-drawer v-model="detailVisible" title="服务账号凭据详情" size="520px">
      <template v-if="detail">
        <el-descriptions :column="1" border>
          <el-descriptions-item label="账号">{{ detail.account.account }}</el-descriptions-item>
          <el-descriptions-item label="名称">{{ detail.account.name }}</el-descriptions-item>
          <el-descriptions-item label="状态">
            <el-tag :type="detail.account.status === 'active' ? 'success' : 'info'">{{ detail.account.status }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="受众">{{ detail.account.audiences.join(', ') }}</el-descriptions-item>
        </el-descriptions>
        <div class="token-actions">
          <el-button type="primary" @click="rotate">轮换凭据</el-button>
          <el-button
            :type="detail.account.status === 'active' ? 'danger' : 'success'"
            @click="toggleStatus"
          >{{ detail.account.status === 'active' ? '停用账号' : '启用账号' }}</el-button>
        </div>
        <el-table :data="detail.tokens" class="token-table" empty-text="尚无凭据">
          <el-table-column prop="credential_id" label="凭据 ID" min-width="180" />
          <el-table-column prop="credential_revision" label="修订" width="70" />
          <el-table-column label="状态" width="90">
            <template #default="{ row }">
              <el-tag size="small" :type="row.status === 'active' ? 'success' : 'info'">{{ row.status }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="expires_at" label="到期" min-width="160">
            <template #default="{ row }">{{ formatTime(row.expires_at) }}</template>
          </el-table-column>
          <el-table-column label="操作" width="90">
            <template #default="{ row }">
              <el-button
                v-if="row.status === 'active'"
                link type="danger" @click="revoke(row.credential_id)"
              >撤销</el-button>
            </template>
          </el-table-column>
        </el-table>
      </template>
    </el-drawer>

    <el-dialog v-model="issuedVisible" title="新凭据明文（仅显示一次）" width="min(560px, 92vw)" :close-on-click-modal="false">
      <el-alert
        title="请立即复制到消费者的受控密钥保管位置。关闭后无法再次获取；轮换后旧凭据按重叠期失效。"
        type="error"
        :closable="false"
        class="issued-alert"
      />
      <el-input :model-value="issued?.secret ?? ''" type="textarea" :rows="3" readonly />
      <template #footer>
        <el-button type="primary" @click="issuedVisible = false">我已安全保存</el-button>
      </template>
    </el-dialog>
  </el-card>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import CursorPager from '@/components/CursorPager.vue'
import { serviceAccountsApi, type ServiceTokenIssued } from '@/api/endpoints'
import { ApiError } from '@/api/http'
import { usePagedList } from '@/composables/usePagedList'
import type { ServiceAccountDetail, ServiceAccountView } from '@/api/types'

const accounts = usePagedList<ServiceAccountView>(({ limit, cursor, signal }) =>
  serviceAccountsApi.list({ limit, cursor }, signal)
)
onMounted(() => accounts.reload())

const saving = ref(false)
const createVisible = ref(false)
const detailVisible = ref(false)
const issuedVisible = ref(false)
const detail = ref<ServiceAccountDetail | null>(null)
const issued = ref<ServiceTokenIssued | null>(null)
const createForm = reactive({
  account: '',
  name: '',
  tenant_id: '',
  audiences: [] as string[],
  expires_in_days: undefined as number | undefined,
  permissions: [] as string[]
})

function formatTime(iso: string | null): string {
  return iso ? new Date(iso).toLocaleString('zh-CN', { hour12: false }) : '—'
}

function openCreate(): void {
  createForm.account = ''
  createForm.name = ''
  createForm.tenant_id = ''
  createForm.audiences = []
  createForm.expires_in_days = undefined
  createForm.permissions = []
  createVisible.value = true
}

async function saveCreate(): Promise<void> {
  saving.value = true
  try {
    const created = await serviceAccountsApi.create({
      account: createForm.account,
      name: createForm.name,
      tenant_id: createForm.tenant_id || null,
      audiences: createForm.audiences,
      expires_in_days: createForm.expires_in_days,
      permissions: createForm.permissions
    })
    const issuedResult = await serviceAccountsApi.rotateToken(created.id)
    issued.value = issuedResult
    issuedVisible.value = true
    createVisible.value = false
    accounts.reload()
  } catch (e) {
    ElMessage.error(e instanceof ApiError ? e.message : '创建失败')
  } finally {
    saving.value = false
  }
}

async function openDetail(row: ServiceAccountView): Promise<void> {
  detailVisible.value = true
  try {
    detail.value = await serviceAccountsApi.get(row.id)
  } catch (e) {
    ElMessage.error(e instanceof ApiError ? e.message : '详情加载失败')
    detailVisible.value = false
  }
}

async function rotate(): Promise<void> {
  if (!detail.value) {
    return
  }
  try {
    await ElMessageBox.confirm('轮换后发放新凭据明文（仅一次），旧凭据按重叠窗口失效。', '轮换凭据', {
      confirmButtonText: '轮换',
      cancelButtonText: '取消',
      type: 'warning'
    })
  } catch {
    return
  }
  try {
    issued.value = await serviceAccountsApi.rotateToken(detail.value.account.id)
    issuedVisible.value = true
    detail.value = await serviceAccountsApi.get(detail.value.account.id)
    accounts.reload()
  } catch (e) {
    ElMessage.error(e instanceof ApiError ? e.message : '轮换失败')
  }
}

async function toggleStatus(): Promise<void> {
  if (!detail.value) {
    return
  }
  const next = detail.value.account.status === 'active' ? 'disabled' : 'active'
  try {
    await serviceAccountsApi.updateStatus(detail.value.account.id, next)
    detail.value = await serviceAccountsApi.get(detail.value.account.id)
    accounts.reload()
    ElMessage.success(next === 'active' ? '账号已启用' : '账号已停用，凭据即时失效')
  } catch (e) {
    ElMessage.error(e instanceof ApiError ? e.message : '状态更新失败')
  }
}

async function revoke(credentialId: string): Promise<void> {
  try {
    await ElMessageBox.confirm('撤销后该凭据立即失效，无法恢复。', '撤销凭据', {
      confirmButtonText: '撤销',
      cancelButtonText: '取消',
      type: 'warning'
    })
  } catch {
    return
  }
  try {
    await serviceAccountsApi.revoke(credentialId)
    if (detail.value) {
      detail.value = await serviceAccountsApi.get(detail.value.account.id)
    }
    ElMessage.success('凭据已撤销')
  } catch (e) {
    ElMessage.error(e instanceof ApiError ? e.message : '撤销失败')
  }
}
</script>

<style scoped>
.toolbar {
  display: flex;
  gap: 10px;
  margin-bottom: 12px;
  flex-wrap: wrap;
}

.hint {
  margin-bottom: 12px;
}

.perm-tag {
  margin-right: 4px;
  margin-bottom: 4px;
}

.full-width {
  width: 100%;
}

.token-actions {
  margin: 16px 0;
  display: flex;
  gap: 10px;
}

.issued-alert {
  margin-bottom: 12px;
}
</style>
