import { computed, ref } from 'vue'
import { defineStore } from 'pinia'
import { authApi } from '@/api/endpoints'
import { ApiError } from '@/api/http'
import { isFresh, scopeOf, type EpochSnapshot } from '@/api/scope'
import type { Identity, MenuItem, TenantMembershipOption } from '@/api/types'

export const useAuthStore = defineStore('auth', () => {
  const identity = ref<Identity | null>(null)
  const menus = ref<MenuItem[]>([])
  const tenants = ref<TenantMembershipOption[]>([])
  const booted = ref(false)
  const contextConflict = ref(false)
  const epoch = ref(0)

  const scope = computed(() => scopeOf(identity.value))
  const currentSnapshot = computed<EpochSnapshot>(() => ({ ...scope.value, epoch: epoch.value }))
  const isAuthenticated = computed(() => !!identity.value?.active)
  const needsTenantSelection = computed(() => !!identity.value?.needs_tenant_selection)
  const permissions = computed(() => new Set(identity.value?.permissions ?? []))

  function bumpEpoch(): void {
    epoch.value += 1
    contextConflict.value = false
  }

  function resetIdentity(): void {
    identity.value = null
    menus.value = []
    tenants.value = []
  }

  function hasPermission(code: string): boolean {
    if (!identity.value) {
      return false
    }
    return identity.value.platform_admin || permissions.value.has(code)
  }

  function commitIfFresh(snapshot: EpochSnapshot, patch: Partial<{
    identity: Identity
    menus: MenuItem[]
    tenants: TenantMembershipOption[]
  }>): boolean {
    if (!isFresh(snapshot, currentSnapshot.value)) {
      return false
    }
    if (patch.identity !== undefined) {
      identity.value = patch.identity
    }
    if (patch.menus !== undefined) {
      menus.value = patch.menus
    }
    if (patch.tenants !== undefined) {
      tenants.value = patch.tenants
    }
    contextConflict.value = false
    return true
  }

  async function hydrate(signal?: AbortSignal): Promise<boolean> {
    const snapshot = currentSnapshot.value
    const [meResult, menuResult, tenantResult] = await Promise.allSettled([
      authApi.me(signal),
      authApi.menus(signal),
      authApi.tenants(signal)
    ])
    if (meResult.status === 'rejected') {
      if (meResult.reason instanceof ApiError && meResult.reason.unauthenticated) {
        if (isFresh(snapshot, currentSnapshot.value)) {
          resetIdentity()
          return true
        }
      }
      throw meResult.reason
    }
    const identityValue = meResult.value
    const menuItems = menuResult.status === 'fulfilled' ? menuResult.value.items : []
    const tenantItems = tenantResult.status === 'fulfilled' ? tenantResult.value : []
    return commitIfFresh(snapshot, {
      identity: identityValue,
      menus: menuItems,
      tenants: tenantItems
    })
  }

  // 首次进入：建立匿名句柄/CSRF，再尝试恢复登录态。
  async function bootstrap(): Promise<void> {
    try {
      await authApi.csrf()
    } catch {
      // 后端不可达时保留未登录态，登录页会给出网络错误
    }
    try {
      await hydrate()
    } catch {
      resetIdentity()
    } finally {
      booted.value = true
    }
  }

  async function login(account: string, password: string): Promise<void> {
    bumpEpoch()
    const preIdentitySnapshot = currentSnapshot.value
    await authApi.csrf()
    const result = await authApi.login(account, password)
    if (!isFresh(preIdentitySnapshot, currentSnapshot.value)) {
      return
    }
    identity.value = result.identity
    const snapshot = currentSnapshot.value
    const [menuResult, tenantResult] = await Promise.allSettled([
      authApi.menus(),
      authApi.tenants()
    ])
    if (!isFresh(snapshot, currentSnapshot.value)) {
      return
    }
    menus.value = menuResult.status === 'fulfilled' ? menuResult.value.items : []
    tenants.value = tenantResult.status === 'fulfilled' ? tenantResult.value : []
    contextConflict.value = false
  }

  async function switchTenant(tenantId: string): Promise<void> {
    const startingSnapshot = currentSnapshot.value
    const expected = identity.value?.context_version ?? 0
    try {
      const fresh = await authApi.switchTenant(tenantId, expected)
      if (!isFresh(startingSnapshot, currentSnapshot.value)) {
        return
      }
      bumpEpoch()
      identity.value = fresh
      const snapshot = currentSnapshot.value
      const [menuResult, tenantResult] = await Promise.allSettled([authApi.menus(), authApi.tenants()])
      if (!isFresh(snapshot, currentSnapshot.value)) {
        return
      }
      menus.value = menuResult.status === 'fulfilled' ? menuResult.value.items : []
      tenants.value = tenantResult.status === 'fulfilled' ? tenantResult.value : []
      contextConflict.value = false
    } catch (e) {
      if (!isFresh(startingSnapshot, currentSnapshot.value)) {
        return
      }
      if (e instanceof ApiError && e.contextChanged) {
        await hydrate().catch(() => undefined)
        contextConflict.value = true
        return
      }
      throw e
    }
  }

  async function clearSession(all: boolean): Promise<void> {
    bumpEpoch()
    const snapshot = currentSnapshot.value
    resetIdentity()
    try {
      if (all) {
        await authApi.logoutAll()
      } else {
        await authApi.logout()
      }
    } finally {
      if (snapshot.epoch === epoch.value) {
        resetIdentity()
      }
    }
  }

  async function renew(): Promise<void> {
    const snapshot = currentSnapshot.value
    const result = await authApi.renew(identity.value?.context_version ?? 0)
    commitIfFresh(snapshot, { identity: result.identity })
  }

  return {
    identity,
    menus,
    tenants,
    booted,
    contextConflict,
    epoch,
    currentSnapshot,
    isAuthenticated,
    needsTenantSelection,
    hasPermission,
    bumpEpoch,
    bootstrap,
    hydrate,
    login,
    switchTenant,
    clearSession,
    renew,
    commitIfFresh
  }
})
