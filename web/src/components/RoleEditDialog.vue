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
          <el-input v-model="form.description" type="textarea" :rows="2" />
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
      <div v-for="group in scopedGroups" :key="group.scope + group.name" class="grant-group">
        <h4>{{ group.name }}</h4>
        <el-checkbox-group v-model="form.permissionCodes">
          <el-checkbox
            v-for="leaf in group.permissions"
            :key="leaf.code"
            :value="leaf.code"
            :disabled="role?.builtin"
          >
            {{ leaf.name }}<span class="leaf-code">（{{ leaf.code }}）</span>
          </el-checkbox>
        </el-checkbox-group>
      </div>
      <el-empty v-if="!loading && !scopedGroups.length" description="当前范围没有可授予权限" :image-size="64" />
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
import { ApiError } from '@/api/http'
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

const loading = ref(false)
const saving = ref(false)
const tree = ref<GrantableTree>({ groups: [] })
const form = reactive({
  code: '',
  name: '',
  description: '',
  permissionCodes: [] as string[]
})

const scopedGroups = computed(() => tree.value.groups.filter((group) => group.scope === props.scope))

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
  loading.value = true
  try {
    tree.value = await rolesApi.grantableTree()
  } catch (e) {
    ElMessage.error(e instanceof ApiError ? e.message : '可授权限树加载失败')
  } finally {
    loading.value = false
  }
}

async function save(): Promise<void> {
  if (!form.code.trim() || !form.name.trim()) {
    ElMessage.warning('请填写角色编码与名称')
    return
  }
  saving.value = true
  try {
    if (props.role) {
      await rolesApi.update(props.role.id, {
        name: form.name,
        description: form.description,
        status: props.role.status
      })
      if (!props.role.builtin) {
        await rolesApi.replacePermissions(props.role.id, form.permissionCodes)
      }
    } else {
      await rolesApi.create({
        scope: props.scope,
        code: form.code.trim(),
        name: form.name.trim(),
        description: form.description,
        permission_codes: form.permissionCodes
      })
    }
    ElMessage.success('角色已保存')
    emit('update:modelValue', false)
    emit('saved')
  } catch (e) {
    ElMessage.error(e instanceof ApiError ? e.message : '角色保存失败')
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
</style>
