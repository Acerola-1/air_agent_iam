import { describe, expect, it } from 'vitest'
import { isFresh, sameScope, scopeOf, type EpochSnapshot } from './scope'
import type { Identity } from './types'

function identity(overrides: Partial<Identity> & {
  user?: Identity['user']
  current_tenant?: Identity['current_tenant']
  context_version?: number
}): Identity {
  return {
    schema_version: 'iam.identity.v1',
    active: true,
    issuer: 'air-agent-iam',
    audience: 'iam-admin',
    principal: { type: 'human', id: overrides.user?.id ?? 'u1', realm: 'workforce' },
    user: overrides.user ?? {
      id: 'u1',
      account: 'alice',
      display_name: 'Alice',
      status: 'active'
    },
    session: {
      id: 's1',
      ctx_version: 1,
      created_at: '',
      expires_at: '',
      absolute_expires_at: '',
      idle_expires_at: ''
    },
    current_tenant: overrides.current_tenant ?? { id: 't-a', code: 'A', name: '甲企业', status: 'active' },
    membership: null,
    platform_roles: [],
    tenant_roles: [],
    permissions: [],
    revisions: {
      user_auth_revision: 0,
      tenant_auth_revision: 0,
      membership_revision: 0,
      session_ctx_version: 0
    },
    context_version: overrides.context_version ?? 1,
    platform_admin: false,
    context_usable: true,
    needs_tenant_selection: false,
    evaluated_at: ''
  }
}

function snapshot(epoch: number, scope: ReturnType<typeof scopeOf>): EpochSnapshot {
  return { ...scope, epoch }
}

describe('scopeOf', () => {
  it('空身份为全空作用域', () => {
    expect(scopeOf(null)).toEqual({ userId: null, tenantId: null, ctxVersion: 0 })
  })

  it('提取用户/企业/上下文版本', () => {
    expect(scopeOf(identity({}))).toEqual({ userId: 'u1', tenantId: 't-a', ctxVersion: 1 })
  })
})

describe('sameScope', () => {
  const a = scopeOf(identity({}))
  it('用户不同则不同作用域', () => {
    const b = scopeOf(identity({ user: { id: 'u2', account: 'bob', display_name: 'B', status: 'active' } }))
    expect(sameScope(a, b)).toBe(false)
  })
  it('企业不同则不同作用域', () => {
    const b = scopeOf(identity({ current_tenant: { id: 't-b', code: 'B', name: '乙', status: 'active' } }))
    expect(sameScope(a, b)).toBe(false)
  })
  it('上下文版本不同则不同作用域', () => {
    const b = scopeOf(identity({ context_version: 2 }))
    expect(sameScope(a, b)).toBe(false)
  })
})

describe('isFresh / 单调纪元（C29 迟到响应）', () => {
  const a = scopeOf(identity({}))
  const b = scopeOf(
    identity({
      user: { id: 'u1', account: 'alice', display_name: 'A', status: 'active' },
      current_tenant: { id: 't-b', code: 'B', name: '乙企业', status: 'active' },
      context_version: 1
    })
  )
  const a2 = scopeOf(
    identity({
      user: { id: 'u1', account: 'alice', display_name: 'A', status: 'active' },
      current_tenant: { id: 't-a', code: 'A', name: '甲企业', status: 'active' },
      context_version: 2
    })
  )

  it('A→B→A：首个 A 的迟到响应因纪元落后被丢弃', () => {
    const firstA = snapshot(1, a)
    const currentB = snapshot(2, b)
    expect(isFresh(firstA, currentB)).toBe(false)
    const currentAGain = snapshot(3, a2)
    expect(isFresh(firstA, currentAGain)).toBe(false)
  })

  it('退出登录后旧响应不得写入（纪元推进+空作用域）', () => {
    const loggedIn = snapshot(1, a)
    const loggedOut: EpochSnapshot = { userId: null, tenantId: null, ctxVersion: 0, epoch: 4 }
    expect(isFresh(loggedIn, loggedOut)).toBe(false)
  })

  it('并发切企业 409 后重新水合：当前快照与最新纪元一致才接受', () => {
    const current = snapshot(5, a2)
    expect(isFresh(snapshot(5, a2), current)).toBe(true)
    expect(isFresh(snapshot(5, a), current)).toBe(false)
  })
})
