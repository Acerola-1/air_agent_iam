<script setup lang="ts">
import { computed, onMounted } from 'vue'
import { entitlementsApi, type EntitlementView } from '@/api/endpoints'
import { usePagedList } from '@/composables/usePagedList'
import { useAuthStore } from '@/stores/auth'
import CursorPager from '@/components/CursorPager.vue'

const auth = useAuthStore()
const resources = usePagedList<EntitlementView>(({ limit, cursor, signal }) =>
  entitlementsApi.listCurrentTenant({ limit, cursor }, signal), { reloadKey: computed(() => auth.currentSnapshot) })

onMounted(() => resources.reload())
</script>

<template>
  <el-card shadow="never" header="企业资源">
    <el-alert v-if="resources.errorMessage.value" :title="resources.errorMessage.value" type="error" :closable="false" />
    <el-table :data="resources.items.value" v-loading="resources.loading.value" stripe empty-text="暂无资源开通记录">
      <el-table-column prop="resource_code" label="资源编码" min-width="200" />
      <el-table-column label="开通状态" width="100">
        <template #default="{ row }">
          <el-tag :type="row.status === 'active' ? 'success' : 'info'">{{ row.status === 'active' ? '已开通' : '已回收' }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="有效" width="80">
        <template #default="{ row }">
          <el-tag :type="row.effective ? 'success' : 'warning'">{{ row.effective ? '是' : '否' }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="resource_status" label="目录状态" width="90" />
      <el-table-column prop="granted_at" label="开通时间" min-width="160">
        <template #default="{ row }">{{ row.granted_at || '—' }}</template>
      </el-table-column>
      <el-table-column prop="revoked_at" label="回收时间" min-width="160">
        <template #default="{ row }">{{ row.revoked_at || '—' }}</template>
      </el-table-column>
    </el-table>
    <CursorPager :page-number="resources.pageNumber.value" :has-more="resources.hasMore.value" :loading="resources.loading.value"
      @next="resources.next()" @prev="resources.prev()" />
  </el-card>
</template>
