<template>
  <div class="login-page">
    <div class="login-card" aria-labelledby="login-title">
      <div class="brand">
        <img src="/favicon.svg" alt="" width="36" height="36" />
        <div>
          <h1 id="login-title">IAM 共享身份管理后台</h1>
          <p>统一用户 · 企业 · 会话与授权管理</p>
        </div>
      </div>

      <el-form
        ref="formRef"
        :model="form"
        :rules="rules"
        label-position="top"
        size="large"
        @submit.prevent="submit"
      >
        <el-form-item label="账号" prop="account">
          <el-input
            v-model="form.account"
            autocomplete="username"
            placeholder="请输入账号"
            clearable
            :disabled="loading"
            data-testid="login-account"
          />
        </el-form-item>
        <el-form-item label="密码" prop="password">
          <el-input
            v-model="form.password"
            type="password"
            autocomplete="current-password"
            placeholder="请输入密码"
            show-password
            :disabled="loading"
            data-testid="login-password"
          />
        </el-form-item>
        <el-alert
          v-if="errorMessage"
          :title="errorMessage"
          type="error"
          show-icon
          :closable="false"
          class="login-error"
          data-testid="login-error"
        />
        <button
          type="submit"
          class="login-submit"
          :disabled="loading"
          data-testid="login-submit"
        >
          <el-icon v-if="loading" class="is-loading"><Loading /></el-icon>
          <span>{{ loading ? '正在登录…' : '登录' }}</span>
        </button>
      </el-form>
      <p class="login-hint">本机回环环境；浏览器仅保存 HttpOnly 会话句柄，不接触访问令牌。</p>
    </div>
  </div>
</template>

<script setup lang="ts">
import { reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import type { FormInstance, FormRules } from 'element-plus'
import { ApiError } from '@/api/http'
import { useAuthStore } from '@/stores/auth'

const auth = useAuthStore()
const router = useRouter()
const route = useRoute()

const formRef = ref<FormInstance>()
const loading = ref(false)
const errorMessage = ref('')
const form = reactive({ account: '', password: '' })

const rules: FormRules<typeof form> = {
  account: [{ required: true, message: '请输入账号', trigger: 'blur' }],
  password: [{ required: true, message: '请输入密码', trigger: 'blur' }]
}

function describeError(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.status === 401) {
      return '账号或密码不正确'
    }
    if (e.status === 429) {
      return '尝试过于频繁，请稍后再试'
    }
    if (e.dependencyUnavailable) {
      return '身份依赖暂不可用，已安全拒绝登录（HTTP 503）'
    }
    return e.message || `登录失败（HTTP ${e.status}）`
  }
  return '网络不可达，请确认后端服务已启动'
}

async function submit(): Promise<void> {
  if (loading.value) {
    return
  }
  const valid = await formRef.value?.validate().catch(() => false)
  if (!valid) {
    return
  }
  loading.value = true
  errorMessage.value = ''
  try {
    await auth.login(form.account.trim(), form.password)
    const redirect = typeof route.query.redirect === 'string' ? route.query.redirect : '/profile'
    await router.replace(redirect.startsWith('/') ? redirect : '/profile')
  } catch (e) {
    errorMessage.value = describeError(e)
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login-page {
  min-height: 100%;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px 16px;
  background: linear-gradient(160deg, #1e3a8a 0%, #1d4ed8 45%, #0f766e 100%);
}

.login-card {
  width: 100%;
  max-width: 420px;
  background: #fff;
  border-radius: 14px;
  padding: 32px 28px 24px;
  box-shadow: 0 18px 50px rgb(15 23 42 / 25%);
  margin: 0;
}

.brand {
  display: flex;
  gap: 14px;
  align-items: center;
  margin-bottom: 22px;
}

.brand h1 {
  font-size: 18px;
  margin: 0 0 4px;
}

.brand p {
  margin: 0;
  font-size: 13px;
  color: #64748b;
}

.login-submit {
  width: 100%;
  margin-top: 4px;
  padding: 11px 16px;
  border: none;
  border-radius: 8px;
  background: #1d4ed8;
  color: #fff;
  font-size: 15px;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
}

.login-submit:disabled {
  opacity: 0.7;
  cursor: not-allowed;
}

.login-error {
  margin-bottom: 12px;
}

.login-hint {
  margin: 16px 0 0;
  font-size: 12px;
  line-height: 1.6;
  color: #94a3b8;
}
</style>
