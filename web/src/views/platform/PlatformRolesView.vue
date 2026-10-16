<template>
  <el-card shadow="never" header="平台角色与权限">
    <div class="toolbar">
      <el-button type="success" @click="openCreate">新建平台角色</el-button>
      <el-button @click="roles.reload()">刷新</el-button>
    </div>
    <el-alert v-if="roles.errorMessage.value" :title="roles.errorMessage.value" type="error" :closable="false" />
    <el-table v-loading="roles.loading.value" :data="roles.items.value" empty-text="暂无平台角色" stripe>
      <el-table-column prop="code" label="角色编码" min-width="200" />
      <el-table-column prop="name" label="名称" min-width="160" />
      <el-table-column label="内置" width="80">
        <template #default="{ row }">
          <el-tag v-if="row.builtin" size="small" type="info">内置</el-tag>
          <span v-else>自定义</span>
        </template>
      </el-table-column>
      <el-table-column label="权限" min-width="260">
        <template #default="{ row }">
          <el-tag v-for="code in row.permission_codes.slice(0, 5)" :key="code" size="small" class="perm-tag">
            {{ code }}
          </el-tag>
          <el-tag v-if="row.permission_codes.length > 5" size="small" type="info">
            +{{ row.permission_codes.length - 5 }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="操作" width="120" fixed="right">
        <template #default="{ row }">
          <el-button link type="primary" @click="openEdit(row)">编辑权限</el-button>
        </template>
      </el-table-column>
    </el-table>
    <CursorPager
      :page-number="roles.pageNumber.value"
      :has-more="roles.hasMore.value"
      :loading="roles.loading.value"
      @prev="roles.prev()"
      @next="roles.next()"
    />

    <RoleEditDialog v-model="dialogVisible" scope="platform" :role="editing" @saved="roles.reload()" />
  </el-card>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import CursorPager from '@/components/CursorPager.vue'
import RoleEditDialog from '@/components/RoleEditDialog.vue'
import { rolesApi } from '@/api/endpoints'
import { usePagedList } from '@/composables/usePagedList'
import type { RoleView } from '@/api/types'

const roles = usePagedList<RoleView>(({ limit, cursor, signal }) =>
  rolesApi.list({ scope: 'platform', limit, cursor }, signal)
)

onMounted(() => roles.reload())

const dialogVisible = ref(false)
const editing = ref<RoleView | null>(null)

function openCreate(): void {
  editing.value = null
  dialogVisible.value = true
}

function openEdit(row: RoleView): void {
  editing.value = row
  dialogVisible.value = true
}
</script>

<style scoped>
.toolbar {
  display: flex;
  gap: 10px;
  margin-bottom: 14px;
}

.perm-tag {
  margin-right: 4px;
  margin-bottom: 4px;
}
</style>
