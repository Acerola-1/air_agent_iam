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
        <el-form-item label="目标企业 UUID" required>
          <el-input v-model="createForm.tenant_id" placeholder="填写要授权的企业 UUID" />
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
          >
            <el-option label="knowledge" value="knowledge" />
            <el-option label="air-agent" value="air-agent" />
            <el-option label="langgraph-runtime" value="langgraph-runtime" />
          </el-select>
        </el-form-item>
        <el-form-item label="有效期（天，留空按服务默认）">
          <el-input-number v-model="createForm.expires_in_days" :min="1" :max="365" />
        </el-form-item>
        <el-form-item label="权限（最小集合）" required>
          <el-select v-model="createForm.permissions" multiple filterable class="full-width"
            :loading="optionsLoading" :disabled="!tenantRevision" placeholder="先填写企业，再选择已开通的资源权限">
            <el-option v-for="option in permissionOptions" :key="option.code" :value="option.code"
              :label="`${option.name_zh}（${option.code}）`" />
          </el-select>
        </el-form-item>
        <el-alert v-if="optionsError" :title="optionsError" type="error" :closable="false" />
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

    <el-dialog v-model="issuedVisible" title="新凭据明文（仅显示一次）" width="min(560px, 92vw)" :close-on-click-modal="false" @closed="issued = null">
      <el-alert
        title="请立即复制到消费者的受控密钥保管位置。关闭后无法再次获取；轮换后旧凭据按重叠期失效。"
        type="error"
        :closable="false"
        class="issued-alert"
      />
      <el-input :model-value="issued?.secret ?? ''" type="password" show-password autocomplete="off" readonly aria-label="新凭据（仅本次显示）" />
      <template #footer>
        <el-button type="primary" @click="issuedVisible = false; issued = null">我已安全保存</el-button>
      </template>
    </el-dialog>
  </el-card>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import CursorPager from '@/components/CursorPager.vue'
import { serviceAccountsApi, type ServiceTokenIssued } from '@/api/endpoints'
import { useWriteScope, type WriteScope } from '@/composables/useWriteScope'
import { ApiError } from '@/api/http'
import { usePagedList } from '@/composables/usePagedList'
import type { ServiceAccountDetail, ServiceAccountView } from '@/api/types'

const accounts = usePagedList<ServiceAccountView>(({ limit, cursor, signal }) =>
  serviceAccountsApi.list({ limit, cursor }, signal)
)
onMounted(() => accounts.reload())

const lease = ref<WriteScope | null>(null)
const tenantRevision = ref<number | null>(null)
const permissionOptions = ref<{ code: string; name_zh: string; resource_code: string | null }[]>([])
const optionsLoading = ref(false)
const optionsError = ref('')
let detailVersion = 0
let optionEpoch = 0
let optionsController: AbortController | null = null
const writeScope = useWriteScope(() => {
  optionEpoch++; optionsController?.abort(); createVisible.value = false; issuedVisible.value = false
  detailVersion++; detailVisible.value = false; detail.value = null
  lease.value = null; issued.value = null
})
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
  lease.value = writeScope.capture(); optionsError.value = ''
  createForm.account = ''
  createForm.name = ''
  createForm.tenant_id = ''
  createForm.audiences = []
  createForm.expires_in_days = undefined
  createForm.permissions = []
  createVisible.value = true
}

watch(() => createForm.tenant_id, async target => {
  const epoch = ++optionEpoch
  optionsController?.abort(); optionsController = new AbortController()
  const opened = lease.value
  tenantRevision.value = null; permissionOptions.value = []; createForm.permissions = []; optionsError.value = ''; optionsLoading.value = false
  if (!target || !/^[0-9a-f-]{36}$/i.test(target) || !writeScope.current(opened)) return
  optionsLoading.value = true
  try {
    const result = await serviceAccountsApi.resourceOptions(target, optionsController.signal)
    if (epoch !== optionEpoch || !writeScope.current(opened)) return
    tenantRevision.value = result.tenant_auth_revision; permissionOptions.value = result.permissions
  } catch (e) {
    if (epoch === optionEpoch && writeScope.current(opened) && !(e instanceof DOMException && e.name === 'AbortError')) optionsError.value = e instanceof Error ? e.message : '资源权限加载失败'
  } finally { if (epoch === optionEpoch) optionsLoading.value = false }
})

async function saveCreate(): Promise<void> {
  const opened = lease.value
  if (saving.value || !writeScope.current(opened)) return
  if (!createForm.audiences.length) { optionsError.value = '请至少选择一个受众'; return }
  if (!createForm.permissions.length) { optionsError.value = '请至少选择一项权限'; return }
  if (!tenantRevision.value || optionsLoading.value) { optionsError.value = '请先填写有效企业并等待可选权限加载'; return }
  saving.value = true
  try {
    const created = await serviceAccountsApi.create({
      expected_context: opened.expected_context,
      expected_tenant_revision: tenantRevision.value,
      account: createForm.account,
      name: createForm.name,
      tenant_id: createForm.tenant_id || null,
      audiences: createForm.audiences,
      expires_in_days: createForm.expires_in_days,
      permissions: createForm.permissions
    })
    if (!writeScope.current(opened)) return
    const issuedResult = await serviceAccountsApi.rotateToken(created.id)
    if (!writeScope.current(opened)) return
    issued.value = issuedResult
    issuedVisible.value = true
    createVisible.value = false
    accounts.reload()
  } catch (e) {
    if (writeScope.current(opened)) ElMessage.error(e instanceof ApiError ? e.message : '创建失败')
  } finally {
    saving.value = false
  }
}

async function openDetail(row: ServiceAccountView): Promise<void> {
  const opened = writeScope.capture(); const version = ++detailVersion
  detail.value = null; detailVisible.value = true
  try {
    const result = await serviceAccountsApi.get(row.id)
    if (version === detailVersion && writeScope.current(opened)) detail.value = result
  } catch (e) { if (writeScope.current(opened)) ElMessage.error(e instanceof ApiError ? e.message : '详情加载失败') }
}

async function rotate(): Promise<void> {
  const opened = writeScope.capture(); const target = detail.value?.account.id
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
    if (!writeScope.current(opened) || detail.value?.account.id !== target || !target) return
    const result = await serviceAccountsApi.rotateToken(target)
    if (!writeScope.current(opened) || detail.value?.account.id !== target) return
    issued.value = result; issuedVisible.value = true
    const updated = await serviceAccountsApi.get(target)
    if (writeScope.current(opened) && detail.value?.account.id === target) detail.value = updated
    accounts.reload()
  } catch (e) {
    ElMessage.error(e instanceof ApiError ? e.message : '轮换失败')
  }
}

async function toggleStatus(): Promise<void> {
  const opened = writeScope.capture(); const target = detail.value?.account.id
  if (!detail.value) {
    return
  }
  const next = detail.value.account.status === 'active' ? 'disabled' : 'active'
  try {
    if (next === 'disabled') {
      try { await ElMessageBox.confirm('停用后该账号的全部凭据立即失效，原权限配置保留。', '停用服务账号', { confirmButtonText: '停用', cancelButtonText: '取消', type: 'warning' }) } catch { return }
    }
    if (!writeScope.current(opened) || !target || detail.value?.account.id !== target) return
    await serviceAccountsApi.updateStatus(target, next)
    const updated = await serviceAccountsApi.get(target)
    if (!writeScope.current(opened) || detail.value?.account.id !== target) return
    detail.value = updated
    accounts.reload()
    ElMessage.success(next === 'active' ? '账号已启用' : '账号已停用，凭据即时失效')
  } catch (e) {
    ElMessage.error(e instanceof ApiError ? e.message : '状态更新失败')
  }
}

async function revoke(credentialId: string): Promise<void> {
  const opened = writeScope.capture()
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
    if (!writeScope.current(opened)) return
    await serviceAccountsApi.revoke(credentialId)
    if (!writeScope.current(opened)) return
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
