import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { useAuthStore } from './auth'
import { ApiError } from '@/api/http'
import type { Identity } from '@/api/types'

vi.mock('@/api/endpoints', () => ({
  authApi: {
    csrf: vi.fn(),
    login: vi.fn(),
    logout: vi.fn(),
    logoutAll: vi.fn(),
    me: vi.fn(),
    menus: vi.fn(),
    tenants: vi.fn(),
    switchTenant: vi.fn(),
    renew: vi.fn()
  }
}))

import { authApi } from '@/api/endpoints'
import type { MenuCatalog } from '@/api/types'

const menuCatalog: MenuCatalog = {
  application: 'iam-admin',
  items: [{ code: 'g1', name: '分组', path: null, icon: 'Menu', sort: 1 }]
}

function identity(over: Partial<Identity> = {}): Identity {
  return {
    schema_version: 'iam.identity.v1',
    active: true,
    issuer: 'air-agent-iam',
    audience: 'iam-admin',
    principal: { type: 'human', id: 'u1', realm: 'workforce' },
    user: { id: 'u1', account: 'alice', display_name: 'Alice', status: 'active' },
    session: {
      id: 's1',
      ctx_version: 1,
      created_at: '',
      expires_at: '',
      absolute_expires_at: '',
      idle_expires_at: ''
    },
    current_tenant: null,
    membership: null,
    platform_roles: [],
    tenant_roles: [],
    permissions: [],
    revisions: {
      user_auth_revision: 1,
      tenant_auth_revision: 1,
      membership_revision: 1,
      session_ctx_version: 1
    },
    context_version: 1,
    platform_admin: false,
    context_usable: true,
    needs_tenant_selection: false,
    evaluated_at: '',
    ...over
  }
}

const tenantOptions = [
  { tenant_id: 't1', code: 'UIAA', name: '企业甲', status: 'active', member_status: 'active', is_owner: true },
  { tenant_id: 't2', code: 'UIAB', name: '企业乙', status: 'active', member_status: 'active', is_owner: true }
]

function deferred<T>() {
  let resolve!: (v: T) => void
  let reject!: (e: unknown) => void
  const promise = new Promise<T>((res, rej) => {
    resolve = res
    reject = rej
  })
  return { promise, resolve, reject }
}

describe('auth store', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.mocked(authApi.csrf).mockResolvedValue({ csrf_token: 'x', expires_at: '' })
    vi.mocked(authApi.login).mockResolvedValue({ identity: identity(), expires_at: '' })
    vi.mocked(authApi.menus).mockResolvedValue(menuCatalog)
    vi.mocked(authApi.tenants).mockResolvedValue(tenantOptions)
    vi.mocked(authApi.logout).mockResolvedValue(undefined)
  })

  it('登录成功后身份、菜单与可进入企业一并落库（快照取在身份提交之后）', async () => {
    const store = useAuthStore()
    await store.login('alice', 'pw')
    expect(store.identity?.user.id).toBe('u1')
    expect(store.menus).toHaveLength(1)
    expect(store.tenants.map((t) => t.tenant_id)).toEqual(['t1', 't2'])
  })

  it('登录在途时若会话纪元已被退出推进，迟到的菜单/企业响应必须丢弃', async () => {
    const menusD = deferred<MenuCatalog>()
    const tenantsD = deferred<typeof tenantOptions>()
    vi.mocked(authApi.menus).mockReturnValueOnce(menusD.promise)
    vi.mocked(authApi.tenants).mockReturnValueOnce(tenantsD.promise)

    const store = useAuthStore()
    const loginPromise = store.login('alice', 'pw')
    await vi.waitFor(() => expect(store.identity?.user.id).toBe('u1'))

    await store.clearSession(false)
    expect(store.identity).toBeNull()

    menusD.resolve({ application: 'iam-admin', items: [] })
    tenantsD.resolve(tenantOptions)
    await loginPromise

    expect(store.identity).toBeNull()
    expect(store.menus).toEqual([])
    expect(store.tenants).toEqual([])
  })

  it('切换企业收到 409 时显示冲突条并按最新服务端身份刷新', async () => {
    const store = useAuthStore()
    await store.login('alice', 'pw')
    expect(store.contextConflict).toBe(false)

    vi.mocked(authApi.switchTenant).mockRejectedValueOnce(
      new ApiError(409, 'context_version_mismatch', '上下文已被推进', null)
    )
    const refreshed = identity({
      context_version: 2,
      current_tenant: { id: 't1', code: 'UIAA', name: '企业甲', status: 'active' }
    })
    vi.mocked(authApi.me).mockResolvedValueOnce(refreshed)
    vi.mocked(authApi.menus).mockResolvedValueOnce({ application: 'iam-admin', items: [] })
    vi.mocked(authApi.tenants).mockResolvedValueOnce([])

    await store.switchTenant('t2')
    expect(store.contextConflict).toBe(true)
    expect(store.identity?.context_version).toBe(2)
    expect(store.identity?.current_tenant?.id).toBe('t1')
  })

  it('旧切换响应在退出并登录新账号后不能覆盖新身份', async () => {
    const store = useAuthStore()
    await store.login('alice', 'pw')
    const late = deferred<Identity>()
    vi.mocked(authApi.switchTenant).mockReturnValueOnce(late.promise)
    const switching = store.switchTenant('t1')
    await store.clearSession(false)
    vi.mocked(authApi.login).mockResolvedValueOnce({
      identity: identity({ user: { id: 'u2', account: 'bob', display_name: 'Bob', status: 'active' } }),
      expires_at: ''
    })
    await store.login('bob', 'pw')
    late.resolve(identity({ context_version: 2, current_tenant: {
      id: 't1', code: 'UIAA', name: '企业甲', status: 'active'
    } }))
    await switching
    expect(store.identity?.user.id).toBe('u2')
    expect(store.identity?.current_tenant).toBeNull()
  })

  it('续期提交当前上下文版本', async () => {
    const store = useAuthStore()
    await store.login('alice', 'pw')
    vi.mocked(authApi.renew).mockResolvedValueOnce({
      identity: identity(), absolute_expires_at: '', idle_expires_at: ''
    })
    await store.renew()
    expect(authApi.renew).toHaveBeenCalledWith(1)
  })

})
