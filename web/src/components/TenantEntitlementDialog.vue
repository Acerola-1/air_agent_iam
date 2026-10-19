<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { entitlementsApi, type EntitlementView } from '@/api/endpoints'
import { entitlementDisplayName, entitlementStatusLabel } from '@/api/business'
import { usePagedList } from '@/composables/usePagedList'
import { useWriteScope, type WriteScope } from '@/composables/useWriteScope'
import CursorPager from '@/components/CursorPager.vue'

const props = defineProps<{ modelValue: boolean; tenant: { id: string; name: string } | null }>()
const emit = defineEmits<{ 'update:modelValue': [value: boolean]; changed: [] }>()
const lease = ref<WriteScope | null>(null)
const saving = ref<string | null>(null)
const error = ref('')
const scope = useWriteScope(() => { lease.value = null; emit('update:modelValue', false) })
const target = computed(() => props.tenant?.id ?? '')
const rows = usePagedList<EntitlementView>(({ limit, cursor, signal }) => props.tenant
  ? entitlementsApi.listForTenant(props.tenant.id, { limit, cursor }, signal)
  : Promise.resolve({ items: [], next_cursor: null }), { reloadKey: target })
watch(() => props.modelValue, value => {
  if (value) { lease.value = scope.capture(); error.value = ''; rows.reload() }
})

async function change(row: EntitlementView) {
  const opened = lease.value
  const tenant = props.tenant
  if (!tenant || !scope.current(opened) || saving.value) return
  const revoke = row.status === 'active'
  try {
    const label = entitlementDisplayName(row)
    await ElMessageBox.confirm(
      revoke ? `回收「${tenant.name}」的「${label}」后，该企业的相关权限立即失效。原授权配置会保留。`
        : `为「${tenant.name}」开通「${label}」。开通后仍需另行授予成员或服务账号权限。`,
      revoke ? '回收资源' : '开通资源',
      { confirmButtonText: revoke ? '回收' : '开通', cancelButtonText: '取消', type: 'warning' })
  } catch { return }
  if (!scope.current(opened) || tenant.id !== props.tenant?.id) return
  saving.value = row.resource_code
  error.value = ''
  try {
    const result = await entitlementsApi.update(tenant.id, row.resource_code, {
      expected_context: opened.expected_context,
      expected_revision: row.revision,
      expected_tenant_revision: row.tenant_auth_revision,
      status: revoke ? 'revoked' : 'active'
    })
    if (!scope.current(opened) || tenant.id !== props.tenant?.id) return
    ElMessage.success(result.changed ? (revoke ? '资源已回收，原授权配置保留' : '资源已开通，请继续配置成员权限') : '资源状态未变化')
    rows.reload()
    emit('changed')
  } catch (e) {
    if (scope.current(opened)) error.value = e instanceof Error ? e.message : '保存失败，请刷新后重试'
  } finally { saving.value = null }
}
</script>

<template>
  <el-dialog :model-value="modelValue" :title="`${tenant?.name ?? ''} · 资源开通`" width="min(860px, 94vw)"
    @update:model-value="emit('update:modelValue', $event)">
    <p>开通代表企业可被授予该资源，不会自动赋予管理员或成员读取权限。开通变更后，该企业的现有会话可能需要重新登录。</p>
    <el-alert v-if="error || rows.errorMessage.value" :title="error || rows.errorMessage.value" type="error" :closable="false" />
    <el-button :disabled="!!saving" @click="rows.reload()">刷新状态</el-button>
    <el-table :data="rows.items.value" v-loading="rows.loading.value" empty-text="暂无可登记资源">
      <el-table-column label="业务 / 资源（编码）" min-width="260">
        <template #default="{ row }">{{ entitlementDisplayName(row) }}</template>
      </el-table-column>
      <el-table-column label="目录" width="90"><template #default="{ row }">{{ row.resource_status === 'active' ? '启用' : '停用' }}</template></el-table-column>
      <el-table-column label="企业开通" width="150"><template #default="{ row }">{{ entitlementStatusLabel(row) }}</template></el-table-column>
      <el-table-column label="当前可授" width="100"><template #default="{ row }">{{ row.effective ? '是' : '否' }}</template></el-table-column>
      <el-table-column label="操作" width="110" fixed="right"><template #default="{ row }">
        <el-button :type="row.status === 'active' ? 'warning' : 'primary'" :loading="saving === row.resource_code"
          :disabled="rows.loading.value || !!saving || (row.status !== 'active' && row.resource_status !== 'active')" @click="change(row)">
          {{ row.status === 'active' ? '回收' : '开通' }}
        </el-button>
      </template></el-table-column>
    </el-table>
    <CursorPager :page-number="rows.pageNumber.value" :has-more="rows.hasMore.value" :loading="rows.loading.value"
      @prev="rows.prev()" @next="rows.next()" />
    <template #footer><el-button @click="emit('update:modelValue', false)">关闭</el-button></template>
  </el-dialog>
</template>
