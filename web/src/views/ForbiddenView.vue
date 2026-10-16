<template>
  <div class="status-page">
    <el-result icon="warning" title="403 · 无访问权限" sub-title="菜单与按钮不构成授权；该资源已被后端实时拒绝。">
      <template #extra>
        <el-button type="primary" @click="goHome">返回个人设置</el-button>
      </template>
    </el-result>
  </div>
</template>

<script setup lang="ts">
import { useRouter } from 'vue-router'

const router = useRouter()
function goHome(): void {
  void router.replace('/profile')
}
</script>

<style scoped>
.status-page {
  min-height: 60vh;
  display: flex;
  align-items: center;
  justify-content: center;
}
</style>
