<template>
  <div>
    <el-card shadow="never" header="管理总览">
      <p class="intro">
        欢迎，{{ auth.identity?.user.display_name }}。左侧菜单按当前会话的实时权限生成；
        页面与按钮仅用于组织操作，所有授权以后端实时裁决为准，浏览器侧不缓存授权结论。
      </p>
      <el-descriptions :column="1" border class="ctx-desc">
        <el-descriptions-item label="当前主体">
          {{ auth.identity?.principal.type }} / {{ auth.identity?.user.account }}
        </el-descriptions-item>
        <el-descriptions-item label="当前企业">
          {{ auth.identity?.current_tenant?.name ?? '平台上下文（未选企业）' }}
        </el-descriptions-item>
        <el-descriptions-item label="上下文版本">
          {{ auth.identity?.context_version }}
        </el-descriptions-item>
        <el-descriptions-item label="实时权限数">{{ auth.identity?.permissions.length ?? 0 }}</el-descriptions-item>
      </el-descriptions>
    </el-card>

    <el-card shadow="never" header="快捷入口" class="shortcuts">
      <el-space wrap>
        <el-link
          v-for="item in shortcuts"
          :key="item.path"
          :underline="false"
        >
          <router-link :to="item.path" class="shortcut-link">{{ item.name }}</router-link>
        </el-link>
        <span v-if="!shortcuts.length" class="muted">当前上下文暂无可管理项，可在个人设置切换企业。</span>
      </el-space>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useAuthStore } from '@/stores/auth'
import type { MenuItem } from '@/api/types'

const auth = useAuthStore()

const shortcuts = computed<Array<{ name: string; path: string }>>(() => {
  const result: Array<{ name: string; path: string }> = []
  const walk = (items: MenuItem[]): void => {
    for (const item of items) {
      if (item.path && item.visible) {
        result.push({ name: item.name, path: item.path })
      }
      if (item.children) {
        walk(item.children)
      }
    }
  }
  walk(auth.menus)
  return result.slice(0, 8)
})
</script>

<style scoped>
.intro {
  margin: 0 0 16px;
  color: #475569;
  line-height: 1.7;
}

.ctx-desc {
  max-width: 560px;
}

.shortcuts {
  margin-top: 16px;
}

.shortcut-link {
  color: #1d4ed8;
}

.muted {
  color: #94a3b8;
}
</style>
