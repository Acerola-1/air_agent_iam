import { watch } from 'vue'
import { isFresh, type EpochSnapshot } from '@/api/scope'
import { useAuthStore } from '@/stores/auth'

/** A write lease belongs to the identity and context that opened the form. */
export interface WriteScope {
  snapshot: EpochSnapshot
  expected_context: { session_id: string; tenant_id: string | null; ctx_version: number }
  expected_tenant_revision: number
}

export function useWriteScope(invalidate: () => void = () => {}) {
  const auth = useAuthStore()
  watch(() => ({ ...auth.currentSnapshot, sessionId: auth.identity?.session.id }), (next, previous) => {
    if (!isFresh(previous, next) || previous.sessionId !== next.sessionId) invalidate()
  })
  function capture(): WriteScope {
    if (!auth.identity) throw new Error('请重新登录')
    return {
      snapshot: { ...auth.currentSnapshot },
      expected_context: {
        session_id: auth.identity.session.id,
        tenant_id: auth.identity.current_tenant?.id ?? null,
        ctx_version: auth.identity.session.ctx_version
      },
      expected_tenant_revision: auth.identity.revisions.tenant_auth_revision
    }
  }
  function current(scope: WriteScope | null): scope is WriteScope {
    return !!scope && isFresh(scope.snapshot, auth.currentSnapshot)
      && scope.expected_context.session_id === auth.identity?.session.id
  }
  return { capture, current }
}
