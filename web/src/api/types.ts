// 与后端 iam.identity.v1 安全身份及 /web-api 管理 DTO 对齐的只读类型。
// 命名保持后端 SNAKE_CASE；本文件不出现任何令牌/密钥字段。

export interface Principal {
  type: 'human' | 'service_account' | 'internal_client'
  id: string
  realm?: string
}

export interface SessionInfo {
  id: string
  ctx_version: number
  created_at: string
  expires_at: string
  absolute_expires_at: string
  idle_expires_at: string
}

export interface TenantBrief {
  id: string
  code: string
  name: string
  status: string
}

export interface TenantMembershipOption {
  tenant_id: string
  code: string
  name: string
  status: string
  member_status: string
  is_owner: boolean
}

export interface RoleBrief {
  code: string
  name: string
}

export interface Revisions {
  user_auth_revision: number
  tenant_auth_revision: number
  membership_revision: number
  session_ctx_version: number
}

export interface Identity {
  schema_version: string
  active: boolean
  issuer: string
  audience: string
  principal: Principal
  user: {
    id: string
    account: string
    display_name: string
    status: string
  }
  session: SessionInfo
  current_tenant: TenantBrief | null
  membership: {
    id: string
    department_id: string | null
    status: string
  } | null
  platform_roles: RoleBrief[]
  tenant_roles: RoleBrief[]
  permissions: string[]
  revisions: Revisions
  context_version: number
  platform_admin: boolean
  context_usable: boolean
  needs_tenant_selection: boolean
  evaluated_at: string
}

export interface MenuItem {
  code: string
  name: string
  path: string | null
  icon: string | null
  sort: number
  visible?: boolean
  children?: MenuItem[]
}

export interface MenuCatalog {
  application: string
  items: MenuItem[]
}

export interface ErrorBody {
  error: {
    code: string
    message: string
    request_id?: string
  }
}

export interface Page<T> {
  items: T[]
  next_cursor: string | null
}

export interface UserView {
  id: string
  realm: string
  account: string
  display_name: string
  status: string
  auth_revision: number
  platform_roles: string[]
  created_at: string
}

export interface TenantView {
  id: string
  code: string
  name: string
  status: string
  auth_revision: number
  created_at: string
}

export interface MemberView {
  id: string
  tenant_id: string
  user: UserView
  department_id: string | null
  status: string
  revision: number
  roles: string[]
}

export interface DepartmentView {
  id: string
  tenant_id: string
  parent_id: string | null
  code: string
  name: string
  status: string
}

export interface RoleView {
  id: string
  code: string
  scope: 'platform' | 'tenant'
  tenant_id: string | null
  name: string
  description: string
  builtin: boolean
  status: string
  permission_codes: string[]
  permission_states?: { code: string; configured: boolean; effective: boolean; grantable: boolean; reason: string | null }[]
}

export interface PermissionView {
  code: string
  name: string
  grant_scope: string
  resource_type: string | null
}

export interface GrantableLeaf {
  code: string
  name: string
  resource_code: string | null
  resource_name_zh?: string | null
}

export interface GrantableTree {
  groups: Array<{
    scope: string
    name: string
    permissions: GrantableLeaf[]
  }>
}

export interface AuditView {
  id: number
  tenant_id: string | null
  actor_user_id: string | null
  actor_type: string
  action: string
  target_type: string | null
  target_id: string | null
  detail: unknown
  request_id: string
  created_at: string
}

export interface ServiceAccountView {
  id: string
  account: string
  name: string
  tenant_id: string | null
  status: string
  audiences: string[]
  expires_at: string | null
  revision: number
  permissions: string[]
}

export interface ServiceTokenView {
  credential_id: string
  credential_revision: number
  status: string
  issued_at: string
  expires_at: string
  overlap_until: string | null
  revoked_at: string | null
}

export interface ServiceAccountDetail {
  account: ServiceAccountView
  tokens: ServiceTokenView[]
}
