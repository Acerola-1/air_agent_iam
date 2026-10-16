<template>
  <el-container class="layout">
    <div v-if="isNarrow && drawer" class="drawer-mask" @click="drawer = false" />
    <el-aside
      v-show="!isNarrow || drawer"
      :width="drawer ? '232px' : collapsed ? '64px' : '232px'"
      class="sidebar"
      :class="{ 'sidebar--drawer': drawer }"
    >
      <div class="sidebar__brand">
        <img src="/favicon.svg" alt="" width="28" height="28" />
        <span v-if="drawer || !collapsed">IAM 身份管理</span>
      </div>
      <el-menu
        :default-active="activeMenu"
        :collapse="collapsed && !drawer"
        :collapse-transition="false"
        router
        class="sidebar__menu"
      >
        <template v-for="group in auth.menus" :key="group.code">
          <el-sub-menu v-if="group.children?.length" :index="group.code">
            <template #title>
              <el-icon><component :is="group.icon || 'Menu'"/></el-icon>
              <span>{{ group.name }}</span>
            </template>
            <el-menu-item
              v-for="item in group.children"
              :key="item.code"
              :index="item.path ?? undefined"
            >
              <el-icon><component :is="item.icon || 'Menu'"/></el-icon>
              <span>{{ item.name }}</span>
            </el-menu-item>
          </el-sub-menu>
          <el-menu-item v-else :index="group.path ?? undefined">
            <el-icon><component :is="group.icon || 'Menu'"/></el-icon>
            <template #title>{{ group.name }}</template>
          </el-menu-item>
        </template>
      </el-menu>
    </el-aside>

    <el-container>
      <el-header class="header">
        <div class="header__left">
          <el-button text :aria-label="drawer ? '关闭菜单' : '展开菜单'" @click="toggleSidebar">
            <el-icon :size="20"><Fold v-if="!drawer && !collapsed" /><Expand v-else /></el-icon>
          </el-button>
          <el-tag v-if="currentTenant" type="primary" effect="plain" class="tenant-tag" data-testid="ctx-tenant">
            {{ currentTenant.name }}（{{ currentTenant.code }}）
          </el-tag>
          <el-tag v-else type="info" effect="plain" class="tenant-tag">平台上下文（未选企业）</el-tag>
          <el-dropdown trigger="click" @command="onSwitchTenant" data-testid="tenant-switcher">
            <el-button text :disabled="!auth.tenants.length">
              切换企业<el-icon class="el-icon--right"><ArrowDown /></el-icon>
            </el-button>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item
                  v-for="tenant in auth.tenants"
                  :key="tenant.tenant_id"
                  :command="tenant.tenant_id"
                  :disabled="tenant.tenant_id === currentTenant?.id"
                >
                  {{ tenant.name }}（{{ tenant.code }}）
                </el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
        <div class="header__right">
          <el-dropdown trigger="click" data-testid="user-menu" @command="onUserCommand">
            <el-button text>
              <el-icon><UserFilled /></el-icon>
              <span class="user-name">{{ auth.identity?.user.display_name }}</span>
              <el-icon class="el-icon--right"><ArrowDown /></el-icon>
            </el-button>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item command="profile">个人设置</el-dropdown-item>
                <el-dropdown-item command="renew">续期会话</el-dropdown-item>
                <el-dropdown-item command="logout" divided>退出此设备</el-dropdown-item>
                <el-dropdown-item command="logout-all">退出全部设备</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </el-header>

      <el-alert
        v-if="auth.contextConflict"
        title="企业上下文已被其他操作推进"
        type="warning"
        show-icon
        :closable="false"
        class="ctx-alert"
        data-testid="ctx-conflict"
      >
        <template #default>
          当前页面数据可能已过期。
          <el-button type="primary" link @click="reloadPage">立即刷新上下文</el-button>
        </template>
      </el-alert>

      <el-main class="main">
        <router-view />
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { useAuthStore } from '@/stores/auth'
import { ApiError } from '@/api/http'

const auth = useAuthStore()
const router = useRouter()
const route = useRoute()

const isNarrow = ref(window.matchMedia('(max-width: 768px)').matches)
const collapsed = ref(false)
const drawer = ref(false)

const currentTenant = computed(() => auth.identity?.current_tenant ?? null)
const activeMenu = computed(() => route.path)

function onMediaChange(e: MediaQueryListEvent): void {
  isNarrow.value = e.matches
  if (!e.matches) {
    drawer.value = false
  }
}
const media = window.matchMedia('(max-width: 768px)')
function onKeydown(e: KeyboardEvent): void {
  if (e.key === 'Escape' && isNarrow.value && drawer.value) {
    drawer.value = false
  }
}
onMounted(() => {
  media.addEventListener('change', onMediaChange)
  window.addEventListener('keydown', onKeydown)
  router.afterEach(() => {
    drawer.value = false
  })
})
onBeforeUnmount(() => {
  media.removeEventListener('change', onMediaChange)
  window.removeEventListener('keydown', onKeydown)
})

function toggleSidebar(): void {
  if (isNarrow.value) {
    drawer.value = !drawer.value
  } else {
    collapsed.value = !collapsed.value
  }
}

function reloadPage(): void {
  window.location.reload()
}

async function onSwitchTenant(tenantId: string): Promise<void> {
  try {
    await ElMessageBox.confirm('切换企业后将加载该企业的独立上下文与权限，当前页面草稿不跨企业保留。', '切换企业', {
      confirmButtonText: '切换',
      cancelButtonText: '取消',
      type: 'warning'
    })
  } catch {
    return
  }
  try {
    await auth.switchTenant(tenantId)
    ElMessage.success('已切换企业上下文')
    if (route.path.startsWith('/admin/tenant')) {
      await router.replace({ path: route.path })
    }
  } catch (e) {
    ElMessage.error(e instanceof ApiError ? e.message : '切换企业失败')
  }
}

async function onUserCommand(command: string): Promise<void> {
  if (command === 'profile') {
    await router.push('/profile')
    return
  }
  if (command === 'renew') {
    try {
      await auth.renew()
      ElMessage.success('会话已续期')
    } catch (e) {
      ElMessage.error(e instanceof ApiError ? e.message : '续期失败')
    }
    return
  }
  if (command === 'logout' || command === 'logout-all') {
    try {
      await ElMessageBox.confirm(
        command === 'logout-all' ? '将撤销本账号全部设备的会话，确定退出？' : '确定退出此设备？',
        '退出登录',
        { confirmButtonText: '退出', cancelButtonText: '取消', type: 'warning' }
      )
    } catch {
      return
    }
    await auth.clearSession(command === 'logout-all')
    ElMessage.success('已退出')
    await router.replace('/login')
  }
}
</script>

<style scoped>
.layout {
  height: 100%;
}

.sidebar {
  background: #0f172a;
  transition: width 0.18s ease;
  overflow: hidden;
}

.sidebar__brand {
  height: 56px;
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 0 16px;
  color: #e2e8f0;
  font-weight: 600;
  white-space: nowrap;
}

.sidebar__menu {
  border-right: none;
  background: transparent;
}

.sidebar__menu :deep(.el-menu) {
  background: transparent;
}

.sidebar__menu :deep(.el-sub-menu__title),
.sidebar__menu :deep(.el-menu-item) {
  color: #cbd5e1;
}

.sidebar__menu :deep(.el-sub-menu__title:hover),
.sidebar__menu :deep(.el-menu-item:hover) {
  background: rgb(255 255 255 / 8%);
}

.sidebar__menu :deep(.el-menu-item.is-active) {
  color: #fff;
  background: #1d4ed8;
}

.header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  background: #fff;
  border-bottom: 1px solid #e2e8f0;
  padding: 0 16px;
  height: 56px;
}

.header__left {
  display: flex;
  align-items: center;
  gap: 10px;
  min-width: 0;
}

.tenant-tag {
  max-width: 220px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.user-name {
  margin: 0 4px;
}

.ctx-alert {
  margin: 12px 16px 0;
}

.main {
  padding: 20px;
}

@media (max-width: 768px) {
  .sidebar {
    position: fixed;
    z-index: 2000;
    height: 100%;
  }

  .drawer-mask {
    position: fixed;
    inset: 0;
    z-index: 1999;
    background: rgb(15 23 42 / 45%);
  }

  .main {
    padding: 12px;
  }

  .user-name {
    display: none;
  }
}
</style>
