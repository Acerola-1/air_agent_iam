import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const routes: RouteRecordRaw[] = [
  {
    path: '/login',
    name: 'login',
    component: () => import('@/views/LoginView.vue'),
    meta: { public: true, title: '登录' }
  },
  {
    path: '/',
    component: () => import('@/layouts/AdminLayout.vue'),
    children: [
      { path: '', redirect: '/profile' },
      {
        path: 'profile',
        name: 'profile',
        component: () => import('@/views/ProfileView.vue'),
        meta: { title: '个人设置' }
      },
      {
        path: 'admin',
        name: 'admin-home',
        component: () => import('@/views/DashboardView.vue'),
        meta: { title: '管理总览' }
      },
      {
        path: 'admin/platform/users',
        name: 'platform-users',
        component: () => import('@/views/platform/PlatformUsersView.vue'),
        meta: { title: '平台用户', permission: 'platform:user:read' }
      },
      {
        path: 'admin/platform/tenants',
        name: 'platform-tenants',
        component: () => import('@/views/platform/PlatformTenantsView.vue'),
        meta: { title: '企业与组织', permission: 'platform:tenant:read' }
      },
      {
        path: 'admin/platform/roles',
        name: 'platform-roles',
        component: () => import('@/views/platform/PlatformRolesView.vue'),
        meta: { title: '平台角色', permission: 'platform:role:read' }
      },
      {
        path: 'admin/platform/resources',
        name: 'platform-resources',
        component: () => import('@/views/platform/PlatformResourcesView.vue'),
        meta: { title: '资源目录', permission: 'entitlement:manage' }
      },
      {
        path: 'admin/platform/service-accounts',
        name: 'service-accounts',
        component: () => import('@/views/platform/ServiceAccountsView.vue'),
        meta: { title: '服务账号', permission: 'platform:service:write' }
      },
      {
        path: 'admin/platform/audit',
        name: 'platform-audit',
        component: () => import('@/views/AuditView.vue'),
        meta: { title: '平台审计', permission: 'platform:audit:read', scope: 'platform' }
      },
      {
        path: 'admin/tenant/members',
        name: 'tenant-members',
        component: () => import('@/views/tenant/TenantMembersView.vue'),
        meta: { title: '成员管理', permission: 'tenant:member:read', requireTenant: true }
      },
      {
        path: 'admin/tenant/departments',
        name: 'tenant-departments',
        component: () => import('@/views/tenant/TenantDepartmentsView.vue'),
        meta: { title: '部门管理', permission: 'tenant:department:read', requireTenant: true }
      },
      {
        path: 'admin/tenant/roles',
        name: 'tenant-roles',
        component: () => import('@/views/tenant/TenantRolesView.vue'),
        meta: { title: '企业角色', permission: 'tenant:role:read', requireTenant: true }
      },
      {
        path: 'admin/tenant/resources',
        name: 'tenant-resources',
        component: () => import('@/views/tenant/TenantResourcesView.vue'),
        meta: { title: '企业资源', permission: 'tenant:role:read', requireTenant: true }
      },
      {
        path: 'admin/tenant/audit',
        name: 'tenant-audit',
        component: () => import('@/views/AuditView.vue'),
        meta: { title: '企业审计', permission: 'tenant:audit:read', requireTenant: true, scope: 'tenant' }
      }
    ]
  },
  {
    path: '/403',
    name: 'forbidden',
    component: () => import('@/views/ForbiddenView.vue'),
    meta: { public: true, title: '无权限' }
  },
  {
    path: '/:pathMatch(.*)*',
    name: 'not-found',
    component: () => import('@/views/NotFoundView.vue'),
    meta: { public: true, title: '页面不存在' }
  }
]

export const router = createRouter({
  history: createWebHistory('/'),
  routes,
  scrollBehavior: () => ({ top: 0 })
})

router.beforeEach((to) => {
  const auth = useAuthStore()
  if (to.meta.public) {
    if (to.name === 'login' && auth.isAuthenticated && !auth.needsTenantSelection) {
      return { path: '/profile' }
    }
    return true
  }
  if (!auth.isAuthenticated) {
    return { name: 'login', query: to.fullPath !== '/' ? { redirect: to.fullPath } : undefined }
  }
  if (to.meta.requireTenant && (!auth.identity?.current_tenant || !auth.identity.context_usable)) {
    return { name: 'profile' }
  }
  const permission = to.meta.permission as string | undefined
  if (permission && !auth.hasPermission(permission)) {
    return { name: 'forbidden' }
  }
  return true
})

router.afterEach((to) => {
  document.title = `${(to.meta.title as string | undefined) ?? ''} · IAM 身份管理后台`.replace(/^ · /, '')
})
