<template>
  <el-config-provider :locale="zhCn">
    <router-view v-if="auth.booted" />
    <div v-else class="boot-loading" role="status" aria-live="polite">
      <el-icon :size="28" class="is-loading"><Loading /></el-icon>
      <p>正在恢复会话…</p>
    </div>
  </el-config-provider>
</template>

<script setup lang="ts">
import { ElConfigProvider } from 'element-plus'
import zhCn from 'element-plus/es/locale/lang/zh-cn'
import { useAuthStore } from '@/stores/auth'

const auth = useAuthStore()
</script>

<style>
html,
body,
#app {
  height: 100%;
  margin: 0;
}

body {
  font-family:
    -apple-system, BlinkMacSystemFont, 'Segoe UI', 'PingFang SC', 'Hiragino Sans GB',
    'Microsoft YaHei', sans-serif;
  background: #f5f7fa;
  color: #1f2937;
}

.boot-loading {
  height: 100%;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 12px;
  color: #64748b;
}

@media (max-width: 768px) {
  .el-overlay-message-box .el-message-box {
    width: calc(100vw - 24px);
    max-width: calc(100vw - 24px);
  }
}
</style>
