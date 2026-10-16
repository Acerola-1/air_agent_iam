import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { effectScope, nextTick } from 'vue'
import type { Identity } from '@/api/types'
import { useAuthStore } from '@/stores/auth'
import { useWriteScope } from './useWriteScope'

function identity(session = 'session-a', tenant = 'tenant-a', version = 1): Identity {
  return {
    schema_version: 'iam.identity.v1', active: true, issuer: 'air-agent-iam', audience: 'iam-admin',
    principal: { type: 'human', id: 'user-a', realm: 'workforce' },
    user: { id: 'user-a', account: 'synthetic', display_name: '合成账号', status: 'active' },
    session: { id: session, ctx_version: version, created_at: '', expires_at: '', absolute_expires_at: '', idle_expires_at: '' },
    current_tenant: { id: tenant, code: tenant, name: tenant, status: 'active' },
    membership: null, platform_roles: [], tenant_roles: [], permissions: [],
    revisions: { user_auth_revision: 1, tenant_auth_revision: 3, membership_revision: 1, session_ctx_version: version },
    context_version: version, platform_admin: false, context_usable: true, needs_tenant_selection: false, evaluated_at: ''
  }
}

beforeEach(() => setActivePinia(createPinia()))

describe('write scopes', () => {
  it('rejects another session even for the same user, tenant and version', async () => {
    const auth = useAuthStore(); auth.identity = identity()
    const invalidated = vi.fn(); const effects = effectScope()
    const guard = effects.run(() => useWriteScope(invalidated))!
    const lease = guard.capture()
    auth.identity = identity('session-b')
    await nextTick()
    expect(guard.current(lease)).toBe(false)
    expect(invalidated).toHaveBeenCalledOnce()
    effects.stop()
  })
  it('never reuses an A form after A to B to A', async () => {
    const auth = useAuthStore(); auth.identity = identity()
    const effects = effectScope(); const guard = effects.run(() => useWriteScope())!
    const lease = guard.capture()
    auth.identity = identity('session-a', 'tenant-b', 2); await nextTick()
    auth.identity = identity('session-a', 'tenant-a', 3); await nextTick()
    expect(guard.current(lease)).toBe(false)
    expect(lease.expected_context.ctx_version).toBe(1)
    effects.stop()
  })
  it('preserves a form on a read refresh with identical scope', async () => {
    const auth = useAuthStore(); auth.identity = identity()
    const invalidated = vi.fn(); const effects = effectScope()
    const guard = effects.run(() => useWriteScope(invalidated))!
    const lease = guard.capture()
    auth.identity = identity(); await nextTick()
    expect(guard.current(lease)).toBe(true)
    expect(invalidated).not.toHaveBeenCalled()
    effects.stop()
  })
  it('retains the captured CAS revision and refuses logout', async () => {
    const auth = useAuthStore(); auth.identity = identity()
    const effects = effectScope(); const guard = effects.run(() => useWriteScope())!
    const lease = guard.capture()
    auth.identity.revisions.tenant_auth_revision = 9
    expect(lease.expected_tenant_revision).toBe(3)
    auth.identity = null; await nextTick()
    expect(guard.current(lease)).toBe(false)
    effects.stop()
  })
})
