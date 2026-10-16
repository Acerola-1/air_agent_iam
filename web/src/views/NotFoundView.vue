<template>
  <div class="status-page">
    <el-result icon="info" title="404 · 页面不存在" sub-title="请从左侧菜单进入管理页面；接口路径缺失时服务端会返回 JSON 错误而非本页。">
      <template #extra>
        <el-button type="primary" @click="goHome">返回首页</el-button>
      </template>
    </el-result>
  </div>
</template>

<script setup lang="ts">
import { useRouter } from 'vue-router'

const router = useRouter()
function goHome(): void {
  void router.replace('/')
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
