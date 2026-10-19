import { del, get, patch, post, put, withQuery } from './http'
import type {
  AuditView,
  DepartmentView,
  GrantableTree,
  Identity,
  MemberView,
  MenuCatalog,
  Page,
  PermissionView,
  RoleView,
  ServiceAccountDetail,
  ServiceAccountView,
  TenantMembershipOption,
  TenantView,
  UserView
} from './types'

export interface ResourceWriteContext {
  expected_context?: { session_id: string; tenant_id: string | null; ctx_version: number }
  expected_tenant_revision?: number
}

// 浏览器会话端点（/web-api/auth）
export const authApi = {
  csrf: () => get<{ csrf_token: string; expires_at: string }>('/web-api/auth/csrf'),
  login: (account: string, password: string) =>
    post<{ identity: Identity; expires_at: string }>('/web-api/auth/login', {
      account,
      password,
      realm: 'workforce'
    }),
  logout: () => post<void>('/web-api/auth/logout'),
  logoutAll: () => post<void>('/web-api/auth/logout-all'),
  me: (signal?: AbortSignal) => get<Identity>('/web-api/auth/me', signal),
  tenants: (signal?: AbortSignal) => get<TenantMembershipOption[]>('/web-api/auth/tenants', signal),
  menus: (signal?: AbortSignal) => get<MenuCatalog>('/web-api/auth/menus', signal),
  switchTenant: (tenantId: string, expectedCtxVersion: number) =>
    post<Identity>('/web-api/auth/switch-tenant', {
      tenant_id: tenantId,
      expected_ctx_version: expectedCtxVersion
    }),
  renew: (expectedCtxVersion: number) => post<{ identity: Identity; absolute_expires_at: string; idle_expires_at: string }>(
    '/web-api/auth/renew', { expected_ctx_version: expectedCtxVersion }
  ),
  changePassword: (oldPassword: string, newPassword: string) =>
    post<void>('/web-api/auth/change-password', {
      old_password: oldPassword,
      new_password: newPassword
    })
}

export type ListQuery = {
  keyword?: string
  limit?: number
  cursor?: string
}

// 契约里用户列表搜索参数为 q；其余列表端点无服务端搜索。
function usersQuery(query: ListQuery): Record<string, string | number> {
  const out: Record<string, string | number> = {}
  if (query.keyword) {
    out.q = query.keyword
  }
  if (query.limit) {
    out.limit = query.limit
  }
  if (query.cursor) {
    out.cursor = query.cursor
  }
  return out
}

// 平台用户管理（/web-api/admin/users）
export const usersApi = {
  list: (query: ListQuery = {}, signal?: AbortSignal) =>
    get<Page<UserView>>(withQuery('/web-api/admin/users', usersQuery(query)), signal),
  get: (id: string) => get<UserView>(`/web-api/admin/users/${id}`),
  create: (body: { account: string; display_name: string; password: string }) =>
    post<UserView>('/web-api/admin/users', body),
  update: (id: string, body: { display_name?: string; status?: string; expected_revision?: number }) =>
    patch<UserView>(`/web-api/admin/users/${id}`, body),
  resetPassword: (id: string, newPassword: string, expectedRevision?: number) =>
    post<void>(`/web-api/admin/users/${id}/password`, {
      new_password: newPassword,
      expected_revision: expectedRevision
    }),
  replacePlatformRoles: (id: string, roleCodes: string[], expectedRevision?: number) =>
    post<UserView>(`/web-api/admin/users/${id}/platform-roles`, {
      role_codes: roleCodes,
      expected_revision: expectedRevision
    })
}

// 企业与组织（/web-api/admin/tenants、members、departments）
export const tenantsApi = {
  list: (query: ListQuery = {}, signal?: AbortSignal) =>
    get<Page<TenantView>>(withQuery('/web-api/admin/tenants', query), signal),
  get: (id: string) => get<TenantView>(`/web-api/admin/tenants/${id}`),
  create: (body: { code: string; name: string }) =>
    post<TenantView>('/web-api/admin/tenants', body),
  update: (id: string, body: { name?: string; status?: string; expected_revision?: number }) =>
    patch<TenantView>(`/web-api/admin/tenants/${id}`, body)
}

export const membersApi = {
  list: (query: ListQuery & { tenant_id?: string; department_id?: string } = {}, signal?: AbortSignal) =>
    get<Page<MemberView>>(withQuery('/web-api/admin/members', query), signal),
  create: (body: ResourceWriteContext & {
    tenant_id: string
    user_id?: string
    account?: string
    display_name?: string
    password?: string
    department_id?: string
    role_codes?: string[]
  }) => post<MemberView>('/web-api/admin/members', body),
  update: (id: string, body: { department_id?: string | null; status?: string; expected_revision?: number }) =>
    patch<MemberView>(`/web-api/admin/members/${id}`, body),
  remove: (id: string) => del<void>(`/web-api/admin/members/${id}`),
  replaceRoles: (id: string, roleCodes: string[], expectedRevision?: number, context: ResourceWriteContext = {}) =>
    post<MemberView>(`/web-api/admin/members/${id}/roles`, {
      role_codes: roleCodes,
      ...context,
      expected_revision: expectedRevision
    })
}

export const departmentsApi = {
  list: (query: ListQuery & { tenant_id?: string } = {}, signal?: AbortSignal) =>
    get<Page<DepartmentView>>(withQuery('/web-api/admin/departments', query), signal),
  create: (body: { code: string; name: string; parent_id?: string | null; tenant_id: string; expected_ctx_version: number }) =>
    post<DepartmentView>('/web-api/admin/departments', body),
  update: (id: string, body: { name?: string; parent_id?: string | null; status?: string; tenant_id: string; expected_ctx_version: number }) =>
    patch<DepartmentView>(`/web-api/admin/departments/${id}`, body)
}

// 角色与权限
export const rolesApi = {
  list: (query: ListQuery & { scope?: string } = {}, signal?: AbortSignal) =>
    get<Page<RoleView>>(withQuery('/web-api/admin/roles', query), signal),
  create: (body: ResourceWriteContext & {
    scope: string
    code: string
    name: string
    description?: string
    permission_codes: string[]
  }) => post<RoleView>('/web-api/admin/roles', body),
  update: (id: string, body: ResourceWriteContext & { name?: string; description?: string; status?: string }) =>
    patch<RoleView>(`/web-api/admin/roles/${id}`, body),
  replacePermissions: (id: string, permissionCodes: string[], context: ResourceWriteContext = {}) =>
    post<RoleView>(`/web-api/admin/roles/${id}/permissions`, { ...context, permission_codes: permissionCodes }),
  permissions: (signal?: AbortSignal) =>
    get<Page<PermissionView>>('/web-api/admin/permissions', signal),
  grantableTree: (signal?: AbortSignal) =>
    get<GrantableTree>('/web-api/admin/grantable-tree', signal)
}

// 审计
export const auditApi = {
  list: (
    query: { limit?: number; cursor?: string; tenant_id?: string; action?: string } = {},
    signal?: AbortSignal
  ) => get<Page<AuditView>>(withQuery('/web-api/admin/audit-logs', query), signal)
}

export interface ServiceTokenIssued {
  credential_id: string
  secret: string
  token_type: string
  expires_at: string
  overlap_until: string | null
  credential_revision: number
}

// 服务账号
export const serviceAccountsApi = {
  resourceOptions: (tenantId: string, signal?: AbortSignal) =>
    get<{ tenant_id: string; tenant_auth_revision: number; permissions: { code: string; name_zh: string; resource_code: string | null }[] }>(
      withQuery('/web-api/admin/service-accounts/resource-options', { tenant_id: tenantId }), signal),
  list: (query: ListQuery & { tenant_id?: string } = {}, signal?: AbortSignal) =>
    get<Page<ServiceAccountView>>(withQuery('/web-api/admin/service-accounts', query), signal),
  get: (id: string) => get<ServiceAccountDetail>(`/web-api/admin/service-accounts/${id}`),
  create: (body: ResourceWriteContext & {
    account: string
    name: string
    tenant_id?: string | null
    audiences: string[]
    expires_in_days?: number
    permissions: string[]
  }) => post<ServiceAccountView>('/web-api/admin/service-accounts', body),
  updateStatus: (id: string, status: string) =>
    patch<ServiceAccountView>(`/web-api/admin/service-accounts/${id}`, { status }),
  rotateToken: (id: string, overlapHours?: number) =>
    post<ServiceTokenIssued>(`/web-api/admin/service-accounts/${id}/tokens`, {
      overlap_hours: overlapHours
    }),
  revoke: (credentialId: string) =>
    post<void>(`/web-api/admin/service-accounts/tokens/${credentialId}/revoke`, {})
}

// ---- 资源目录与企业开通 ----

export interface ResourceBind {
  code: string
  name_zh: string
  scope: string
  grantable_to_tenants: boolean
  status: string
  resource_code: string
}

export interface ResourceView {
  id: string
  code: string
  name_zh: string
  sort: number
  status: string
  kind: string
  parent_code: string | null
  revision: number
  permissions: ResourceBind[]
}

export interface EntitlementView {
  tenant_id: string
  resource_code: string
  resource_name_zh: string
  status: string
  revision: number
  exists: boolean
  resource_status: string
  effective: boolean
  granted_at: string | null
  revoked_at: string | null
  updated_at: string | null
  updated_by: string | null
  tenant_auth_revision: number
  changed: boolean
}

export const resourcesApi = {
  list: (query: { status?: string; limit?: number; cursor?: string } = {}, signal?: AbortSignal) =>
    get<Page<ResourceView>>(withQuery('/web-api/admin/resources', query), signal),
  create: (body: {
    expected_context: { session_id: string; tenant_id: string | null; ctx_version: number }
    code: string
    name_zh: string
    sort?: number
    parent_code?: string | null
    permissions: { code: string; name_zh: string; grantable_to_tenants: boolean }[]
  }) => post<ResourceView>('/web-api/admin/resources', body),
  update: (code: string, body: {
    expected_context: { session_id: string; tenant_id: string | null; ctx_version: number }
    expected_revision: number
    name_zh?: string
    sort?: number
    status?: string
  }) => patch<ResourceView>(`/web-api/admin/resources/${encodeURIComponent(code)}`, body)
}

export const entitlementsApi = {
  listForTenant: (tenantId: string, query: { limit?: number; cursor?: string } = {}, signal?: AbortSignal) =>
    get<Page<EntitlementView>>(withQuery(`/web-api/admin/tenants/${tenantId}/entitlements`, query), signal),
  update: (tenantId: string, resourceCode: string, body: {
    expected_context: { session_id: string; tenant_id: string | null; ctx_version: number }
    expected_revision: number
    expected_tenant_revision: number
    status: string
  }) => put<EntitlementView>(
    `/web-api/admin/tenants/${tenantId}/entitlements/${encodeURIComponent(resourceCode)}`, body),
  listCurrentTenant: (query: { limit?: number; cursor?: string } = {}, signal?: AbortSignal) =>
    get<Page<EntitlementView>>(withQuery('/web-api/admin/tenant/resources', query), signal)
}
