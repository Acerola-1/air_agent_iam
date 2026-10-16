<template>
  <div class="cursor-pager">
    <el-button size="small" :disabled="pageNumber <= 1 || loading" @click="$emit('prev')">上一页</el-button>
    <span class="cursor-pager__page">第 {{ pageNumber }} 页{{ hasMore ? '（还有更多）' : '' }}</span>
    <el-button size="small" :disabled="!hasMore || loading" @click="$emit('next')">下一页</el-button>
  </div>
</template>

<script setup lang="ts">
defineProps<{
  pageNumber: number
  hasMore: boolean
  loading: boolean
}>()

defineEmits<{
  prev: []
  next: []
}>()
</script>

<style scoped>
.cursor-pager {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-top: 12px;
  justify-content: flex-end;
}

.cursor-pager__page {
  font-size: 13px;
  color: #64748b;
}
</style>
