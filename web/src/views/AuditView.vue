<template>
  <el-card shadow="never" :header="scope === 'platform' ? '平台审计（含平台级与全部租户）' : `企业审计 · ${tenantName}`">
    <div class="toolbar">
      <el-input
        v-model="action"
        placeholder="按动作过滤，如 auth.login"
        clearable
        class="toolbar__search"
        @keyup.enter="logs.reload()"
        @clear="logs.reload()"
      />
      <el-button type="primary" @click="logs.reload()">查询</el-button>
    </div>
    <el-alert v-if="logs.errorMessage.value" :title="logs.errorMessage.value" type="error" :closable="false" />
    <el-table v-loading="logs.loading.value" :data="logs.items.value" empty-text="暂无审计记录" stripe>
      <el-table-column prop="created_at" label="时间" min-width="170">
        <template #default="{ row }">{{ formatTime(row.created_at) }}</template>
      </el-table-column>
      <el-table-column label="主体" width="120">
        <template #default="{ row }">
          <el-tag size="small" :type="actorType(row.actor_type)">{{ actorLabel(row.actor_type) }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="action" label="动作" min-width="180" />
      <el-table-column label="目标" min-width="200">
        <template #default="{ row }">
          {{ row.target_type }}<span v-if="row.target_id" class="muted"> / {{ shortId(row.target_id) }}</span>
        </template>
      </el-table-column>
      <el-table-column v-if="scope === 'platform'" label="租户" min-width="140">
        <template #default="{ row }">{{ row.tenant_id ? shortId(row.tenant_id) : '平台级' }}</template>
      </el-table-column>
      <el-table-column type="expand">
        <template #default="{ row }">
          <pre class="detail-json">{{ formatDetail(row.detail) }}</pre>
          <p class="request-id">request_id：{{ row.request_id }}</p>
        </template>
      </el-table-column>
    </el-table>
    <CursorPager
      :page-number="logs.pageNumber.value"
      :has-more="logs.hasMore.value"
      :loading="logs.loading.value"
      @prev="logs.prev()"
      @next="logs.next()"
    />
  </el-card>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import CursorPager from '@/components/CursorPager.vue'
import { auditApi } from '@/api/endpoints'
import { usePagedList } from '@/composables/usePagedList'
import { useAuthStore } from '@/stores/auth'
import type { AuditView } from '@/api/types'

const route = useRoute()
const auth = useAuthStore()
const scope = computed(() => (route.meta.scope === 'tenant' ? 'tenant' : 'platform'))
const tenantName = computed(() => auth.identity?.current_tenant?.name ?? '')
const action = ref('')

const logs = usePagedList<AuditView>(({ limit, cursor, signal }) =>
  auditApi.list({ action: action.value || undefined, limit, cursor }, signal)
)
onMounted(() => logs.reload())
watch(
  () => (scope.value === 'tenant' ? auth.identity?.current_tenant?.id ?? '' : ''),
  () => {
    action.value = ''
    logs.reload()
  }
)

function formatTime(iso: string): string {
  return new Date(iso).toLocaleString('zh-CN', { hour12: false })
}

function shortId(id: string): string {
  return id.length > 12 ? `${id.slice(0, 8)}…` : id
}

function actorLabel(type: string): string {
  if (type === 'human') {
    return '人类用户'
  }
  if (type === 'service_account') {
    return '服务账号'
  }
  if (type === 'internal_client') {
    return '内部客户端'
  }
  return type
}

function actorType(type: string): 'primary' | 'warning' | 'success' | 'info' {
  if (type === 'human') {
    return 'primary'
  }
  if (type === 'service_account') {
    return 'warning'
  }
  if (type === 'internal_client') {
    return 'success'
  }
  return 'info'
}

function formatDetail(detail: unknown): string {
  return JSON.stringify(detail, null, 2)
}
</script>

<style scoped>
.toolbar {
  display: flex;
  gap: 10px;
  margin-bottom: 14px;
}

.toolbar__search {
  width: 280px;
}

.muted {
  color: #94a3b8;
}

.detail-json {
  margin: 8px 16px;
  padding: 12px;
  background: #0f172a;
  color: #e2e8f0;
  border-radius: 8px;
  font-size: 12px;
  overflow: auto;
}

.request-id {
  margin: 0 16px 12px;
  font-size: 12px;
  color: #64748b;
}
</style>
