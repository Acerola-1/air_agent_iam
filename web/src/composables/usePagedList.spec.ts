import { describe, expect, it, vi, beforeEach } from 'vitest'
import { ref } from 'vue'
import { usePagedList } from './usePagedList'
import type { EpochSnapshot } from '@/api/scope'

const snapA: EpochSnapshot = { userId: 'u1', tenantId: 't-a', ctxVersion: 1, epoch: 1 }
const snapB: EpochSnapshot = { userId: 'u1', tenantId: 't-b', ctxVersion: 1, epoch: 2 }
const snapA2: EpochSnapshot = { userId: 'u1', tenantId: 't-a', ctxVersion: 2, epoch: 3 }

const current = ref<EpochSnapshot>(snapA)
vi.mock('@/stores/auth', () => ({
  useAuthStore: () => ({
    get currentSnapshot() {
      return current.value
    }
  })
}))

function deferred<T>() {
  let resolve!: (v: T) => void
  const promise = new Promise<T>((r) => {
    resolve = r
  })
  return { promise, resolve }
}

function page<T>(items: T[]) {
  return { items, next_cursor: null }
}

beforeEach(() => {
  current.value = snapA
})

describe('usePagedList 作用域/纪元守卫（C29）', () => {
  it('A 企业在途响应在切到 B 后返回时被丢弃，不写入列表', async () => {
    const dA = deferred<ReturnType<typeof page<string>>>()
    const fetcher = vi.fn(() => dA.promise)
    const list = usePagedList<string>(fetcher)
    list.reload()
    await Promise.resolve()
    current.value = snapB
    dA.resolve(page(['A企业迟到数据']))
    await Promise.resolve()
    await Promise.resolve()
    expect(list.items.value).toEqual([])

    const dB = deferred<ReturnType<typeof page<string>>>()
    fetcher.mockImplementation(() => dB.promise)
    list.reload()
    dB.resolve(page(['B企业数据']))
    await Promise.resolve()
    await Promise.resolve()
    expect(list.items.value).toEqual(['B企业数据'])
  })

  it('A→B→A：首个 A 的迟到响应即使作用域再次相同也因纪元落后被丢弃', async () => {
    const dA = deferred<ReturnType<typeof page<string>>>()
    const fetcher = vi.fn(() => dA.promise)
    const list = usePagedList<string>(fetcher)
    list.reload()
    await Promise.resolve()
    current.value = snapB
    current.value = snapA2
    dA.resolve(page(['旧A数据']))
    await Promise.resolve()
    await Promise.resolve()
    expect(list.items.value).toEqual([])
    expect(list.errorMessage.value).toBe('')
  })

  it('新请求自动 abort 上一个在途请求', async () => {
    const signals: AbortSignal[] = []
    const d1 = deferred<ReturnType<typeof page<string>>>()
    const d2 = deferred<ReturnType<typeof page<string>>>()
    const fetcher = vi.fn(({ signal }) => {
      signals.push(signal)
      return fetcher.mock.calls.length === 1 ? d1.promise : d2.promise
    })
    const list = usePagedList<string>(fetcher)
    list.reload()
    list.reload()
    expect(signals[0].aborted).toBe(true)
    d2.resolve(page(['第二页数据']))
    await Promise.resolve()
    await Promise.resolve()
    expect(list.items.value).toEqual(['第二页数据'])
  })
})
