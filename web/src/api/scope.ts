// 会话作用域与单调纪元：所有异步结果落库前必须复核，
// 防止跨用户/跨企业/跨上下文版本的迟到响应覆盖当前页面。

export interface Scope {
  userId: string | null
  tenantId: string | null
  ctxVersion: number
}

export interface EpochSnapshot extends Scope {
  epoch: number
}

export function scopeOf(identity: {
  user: { id: string }
  current_tenant: { id: string } | null
  context_version: number
} | null): Scope {
  if (!identity) {
    return { userId: null, tenantId: null, ctxVersion: 0 }
  }
  return {
    userId: identity.user.id,
    tenantId: identity.current_tenant?.id ?? null,
    ctxVersion: identity.context_version
  }
}

export function sameScope(a: Scope, b: Scope): boolean {
  return a.userId === b.userId && a.tenantId === b.tenantId && a.ctxVersion === b.ctxVersion
}

export function isFresh(snapshot: EpochSnapshot, current: EpochSnapshot): boolean {
  return snapshot.epoch === current.epoch && sameScope(snapshot, current)
}
