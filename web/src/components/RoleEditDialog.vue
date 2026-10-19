<template>
  <el-dialog
    :model-value="modelValue"
    :title="role ? '查看/编辑角色' : `新建${scope === 'platform' ? '平台' : '企业'}角色`"
    width="min(640px, 92vw)"
    @update:model-value="$emit('update:modelValue', $event)"
    @open="load"
  >
    <div v-loading="loading">
      <el-form label-position="top">
        <el-form-item label="角色编码" required>
          <el-input v-model="form.code" :disabled="!!role" placeholder="小写字母/冒号命名，如 tenant_asset_admin" />
        </el-form-item>
        <el-form-item label="角色名称" required>
          <el-input v-model="form.name" />
        </el-form-item>
        <el-form-item label="说明">
          <el-input v-model="form.description" type="textarea" :autosize="{ minRows: 2, maxRows: 6 }" resize="none" />
        </el-form-item>
      </el-form>

      <el-divider content-position="left">可授权限（平台/企业可授边界由后端给出）</el-divider>
      <el-alert
        v-if="role?.builtin"
        title="内置角色受保护：编码不可改，权限调整将被后端拒绝。"
        type="info"
        :closable="false"
        class="builtin-hint"
      />
      <template v-if="scope === 'platform'">
        <div v-if="platformLeaves.length" class="grant-group">
          <h4>平台权限</h4>
          <el-checkbox-group v-model="form.permissionCodes">
            <el-checkbox
              v-for="leaf in platformLeaves"
              :key="leaf.code"
              :value="leaf.code"
              :disabled="role?.builtin"
            >
              {{ leaf.name }}<span class="leaf-code">（{{ leaf.code }}）</span>
            </el-checkbox>
          </el-checkbox-group>
        </div>
      </template>
      <template v-else>
        <div class="grant-group">
          <h4>Agent 业务（仅显示本企业已开通业务）</h4>
          <el-alert
            v-if="!tenantSplit.businesses.length"
            title="当前企业没有可授予的 Agent 业务：可能尚未开通，或当前账号缺少资源授权管理资格。平台开通且账号具备资格后，此处才会出现可选业务。"
            type="info"
            :closable="false"
            class="business-empty"
          />
          <el-checkbox-group v-else v-model="form.permissionCodes">
            <el-checkbox
              v-for="leaf in tenantSplit.businesses"
              :key="leaf.code"
              :value="leaf.code"
              :disabled="role?.builtin"
            >
              {{ businessDisplayName(leaf) }}
            </el-checkbox>
          </el-checkbox-group>
        </div>
        <div v-if="tenantSplit.others.length" class="grant-group">
          <h4>其他企业权限</h4>
          <el-checkbox-group v-model="form.permissionCodes">
            <el-checkbox
              v-for="leaf in tenantSplit.others"
              :key="leaf.code"
              :value="leaf.code"
              :disabled="role?.builtin"
            >
              {{ leaf.name }}<span class="leaf-code">（{{ leaf.code }}）</span>
            </el-checkbox>
          </el-checkbox-group>
        </div>
      </template>
      <div v-if="unavailable.length" class="grant-group">
        <h4>已配置但当前不可新增（可保留或取消勾选以删除）</h4>
        <el-checkbox-group v-model="form.permissionCodes">
          <el-checkbox v-for="item in unavailable" :key="item.code" :value="item.code" :disabled="role?.builtin">
            {{ item.code }} · {{ reasonLabel(item.reason) }}
          </el-checkbox>
        </el-checkbox-group>
      </div>
      <el-empty v-if="!loading && !scopedLeaves.length" description="当前范围没有可授予权限" :image-size="64" />
    </div>
    <template #footer>
      <el-button @click="$emit('update:modelValue', false)">取消</el-button>
      <el-button type="primary" :loading="saving" @click="save">保存</el-button>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { rolesApi } from '@/api/endpoints'
import { businessDisplayName, splitTenantLeaves } from '@/api/business'
import { ApiError } from '@/api/http'
import { useWriteScope, type WriteScope } from '@/composables/useWriteScope'
import type { GrantableTree, RoleView } from '@/api/types'

const props = defineProps<{
  modelValue: boolean
  scope: 'platform' | 'tenant'
  role: RoleView | null
}>()

const emit = defineEmits<{
  'update:modelValue': [value: boolean]
  saved: []
}>()

const lease = ref<WriteScope | null>(null)
const scopeGuard = useWriteScope(() => { lease.value = null; emit('update:modelValue', false) })
const unavailable = computed(() => (props.role?.permission_states ?? []).filter(x => !x.effective || !x.grantable))
function reasonLabel(reason: string | null) {
  return ({ permission_disabled: '权限已停用', role_disabled: '角色已停用', resource_disabled: '资源已停用', not_entitled: '企业未开通', not_entitled_or_resource_disabled: '资源未开通或已停用' } as Record<string, string>)[reason ?? ''] ?? '当前不可新增'
}
const loading = ref(false)
const saving = ref(false)
const tree = ref<GrantableTree>({ groups: [] })
const form = reactive({
  code: '',
  name: '',
  description: '',
  permissionCodes: [] as string[]
})

const platformLeaves = computed(() =>
  tree.value.groups.find((group) => group.scope === 'platform')?.permissions ?? [])
const tenantLeaves = computed(() =>
  tree.value.groups.find((group) => group.scope === 'tenant')?.permissions ?? [])
const tenantSplit = computed(() => splitTenantLeaves(tenantLeaves.value))
const scopedLeaves = computed(() =>
  props.scope === 'platform' ? platformLeaves.value : tenantLeaves.value)

watch(
  () => props.role,
  (role) => {
    form.code = role?.code ?? ''
    form.name = role?.name ?? ''
    form.description = role?.description ?? ''
    form.permissionCodes = role ? [...role.permission_codes] : []
  },
  { immediate: true }
)

async function load(): Promise<void> {
  const opened = scopeGuard.capture(); lease.value = opened
  form.code = props.role?.code ?? ''; form.name = props.role?.name ?? ''; form.description = props.role?.description ?? ''
  form.permissionCodes = [...(props.role?.permission_codes ?? [])]
  loading.value = true
  try {
    const result = await rolesApi.grantableTree()
    if (scopeGuard.current(opened)) tree.value = result
  } catch (e) {
    ElMessage.error(e instanceof ApiError ? e.message : '可授权限树加载失败')
  } finally {
    loading.value = false
  }
}

async function save(): Promise<void> {
  const opened = lease.value
  if (saving.value || !scopeGuard.current(opened)) return
  const context = { expected_context: opened.expected_context, expected_tenant_revision: opened.expected_tenant_revision }
  if (!form.code.trim() || !form.name.trim()) {
    ElMessage.warning('请填写角色编码与名称')
    return
  }
  saving.value = true
  try {
    if (props.role) {
      await rolesApi.update(props.role.id, {
        ...context,
        name: form.name,
        description: form.description,
        status: props.role.status
      })
      if (!props.role.builtin) {
        await rolesApi.replacePermissions(props.role.id, form.permissionCodes, context)
      }
    } else {
      await rolesApi.create({
        ...context,
        scope: props.scope,
        code: form.code.trim(),
        name: form.name.trim(),
        description: form.description,
        permission_codes: form.permissionCodes
      })
    }
    if (!scopeGuard.current(opened)) return
    ElMessage.success('角色已保存')
    emit('update:modelValue', false)
    emit('saved')
  } catch (e) {
    if (scopeGuard.current(opened)) ElMessage.error(e instanceof ApiError ? e.message : '角色保存失败')
  } finally {
    saving.value = false
  }
}
</script>

<style scoped>
.grant-group {
  margin-bottom: 14px;
}

.grant-group h4 {
  margin: 0 0 8px;
  font-size: 14px;
  color: #334155;
}

.leaf-code {
  color: #94a3b8;
  font-size: 12px;
}

.builtin-hint {
  margin-bottom: 10px;
}

.business-empty {
  margin-bottom: 8px;
}
</style>
