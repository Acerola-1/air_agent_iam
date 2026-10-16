<template>
  <div class="profile">
    <el-row :gutter="16">
      <el-col :xs="24" :md="12">
        <el-card shadow="never" header="账号与会话">
          <el-descriptions :column="1" border>
            <el-descriptions-item label="账号">{{ identity.user.account }}</el-descriptions-item>
            <el-descriptions-item label="显示名">{{ identity.user.display_name }}</el-descriptions-item>
            <el-descriptions-item label="主体类型">{{ identity.principal.type }}</el-descriptions-item>
            <el-descriptions-item label="受众">{{ identity.audience }}</el-descriptions-item>
            <el-descriptions-item label="当前企业">
              {{ identity.current_tenant ? `${identity.current_tenant.name}（${identity.current_tenant.code}）` : '未选择（平台上下文）' }}
            </el-descriptions-item>
            <el-descriptions-item label="上下文版本">{{ identity.context_version }}</el-descriptions-item>
            <el-descriptions-item label="空闲截止">{{ formatTime(identity.session.idle_expires_at) }}</el-descriptions-item>
            <el-descriptions-item label="绝对截止">{{ formatTime(identity.session.absolute_expires_at) }}</el-descriptions-item>
          </el-descriptions>
          <div class="roles">
            <el-tag v-for="role in identity.platform_roles" :key="role.code" type="danger" effect="plain">
              {{ role.name }}
            </el-tag>
            <el-tag v-for="role in identity.tenant_roles" :key="role.code" type="success" effect="plain">
              {{ role.name }}
            </el-tag>
            <span v-if="!identity.platform_roles.length && !identity.tenant_roles.length" class="muted">无角色</span>
          </div>
        </el-card>
      </el-col>

      <el-col :xs="24" :md="12">
        <el-card shadow="never" header="修改密码">
          <el-form
            ref="formRef"
            :model="form"
            :rules="rules"
            label-position="top"
            @submit.prevent
          >
            <el-form-item label="当前密码" prop="oldPassword">
              <el-input v-model="form.oldPassword" type="password" show-password autocomplete="current-password" />
            </el-form-item>
            <el-form-item label="新密码" prop="newPassword">
              <el-input v-model="form.newPassword" type="password" show-password autocomplete="new-password" />
            </el-form-item>
            <el-form-item label="确认新密码" prop="confirm">
              <el-input v-model="form.confirm" type="password" show-password autocomplete="new-password" />
            </el-form-item>
            <el-button type="primary" :loading="saving" @click="save">保存新密码</el-button>
            <el-alert
              v-if="savedHint"
              title="密码已修改，其他设备会话已即时撤销"
              type="success"
              :closable="false"
              class="saved-hint"
            />
          </el-form>
        </el-card>

        <el-card shadow="never" header="可进入的企业" class="tenants-card">
          <el-empty v-if="!auth.tenants.length" description="暂无企业成员关系" :image-size="72" />
          <el-radio-group v-else :model-value="identity.current_tenant?.id ?? ''" @change="switchTo">
            <el-radio v-for="tenant in auth.tenants" :key="tenant.tenant_id" :value="tenant.tenant_id" class="tenant-radio">
              {{ tenant.name }}（{{ tenant.code }}）
            </el-radio>
          </el-radio-group>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import { ElMessage, type FormInstance, type FormRules } from 'element-plus'
import { authApi } from '@/api/endpoints'
import { ApiError } from '@/api/http'
import { useAuthStore } from '@/stores/auth'

const auth = useAuthStore()
const identity = computed(() => {
  if (!auth.identity) {
    throw new Error('未登录')
  }
  return auth.identity
})

const formRef = ref<FormInstance>()
const saving = ref(false)
const savedHint = ref(false)
const form = reactive({ oldPassword: '', newPassword: '', confirm: '' })

const rules: FormRules<typeof form> = {
  oldPassword: [{ required: true, message: '请输入当前密码', trigger: 'blur' }],
  newPassword: [
    { required: true, message: '请输入新密码', trigger: 'blur' },
    { min: 10, message: '新密码至少 10 位', trigger: 'blur' }
  ],
  confirm: [
    { required: true, message: '请再次输入新密码', trigger: 'blur' },
    {
      validator: (_r, value: string, callback) => {
        if (value !== form.newPassword) {
          callback(new Error('两次输入不一致'))
        } else {
          callback()
        }
      },
      trigger: 'blur'
    }
  ]
}

function formatTime(iso: string): string {
  return new Date(iso).toLocaleString('zh-CN', { hour12: false })
}

async function save(): Promise<void> {
  const valid = await formRef.value?.validate().catch(() => false)
  if (!valid) {
    return
  }
  saving.value = true
  savedHint.value = false
  try {
    await authApi.changePassword(form.oldPassword, form.newPassword)
    savedHint.value = true
    form.oldPassword = ''
    form.newPassword = ''
    form.confirm = ''
    ElMessage.success('密码已修改')
  } catch (e) {
    ElMessage.error(e instanceof ApiError ? e.message : '修改密码失败')
  } finally {
    saving.value = false
  }
}

async function switchTo(tenantId: string | number | boolean): Promise<void> {
  try {
    await auth.switchTenant(String(tenantId))
    ElMessage.success('已切换企业')
  } catch (e) {
    ElMessage.error(e instanceof ApiError ? e.message : '切换企业失败')
  }
}
</script>

<style scoped>
.roles {
  margin-top: 14px;
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.muted {
  color: #94a3b8;
  font-size: 13px;
}

.saved-hint {
  margin-top: 12px;
}

.tenants-card {
  margin-top: 16px;
}

.tenant-radio {
  display: flex;
  margin-bottom: 8px;
}
</style>
