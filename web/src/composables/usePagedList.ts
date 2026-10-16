import { onBeforeUnmount, ref, watch, type Ref } from 'vue'
import { isFresh } from '@/api/scope'
import { ApiError } from '@/api/http'
import type { Page } from '@/api/types'
import { useAuthStore } from '@/stores/auth'

interface FetcherOptions {
  limit: number
  cursor?: string
  signal?: AbortSignal
}

// 游标分页 + 会话作用域/纪元守卫：切用户、切企业、退出或 A→B→A 之后，
// 在途响应一律丢弃，绝不写入当前页面。
export function usePagedList<T>(
  fetcher: (options: FetcherOptions) => Promise<Page<T>>,
  options: { pageSize?: number; reloadKey?: Ref<unknown> } = {}
) {
  const auth = useAuthStore()
  const pageSize = options.pageSize ?? 20

  const items = ref<T[]>([]) as Ref<T[]>
  const loading = ref(false)
  const errorMessage = ref('')
  const loaded = ref(false)
  const pageNumber = ref(1)
  const hasMore = ref(false)

  const cursorStack: string[] = []
  let controller: AbortController | null = null
  let requestSerial = 0

  async function load(page: number): Promise<void> {
    controller?.abort()
    const current = new AbortController()
    controller = current
    const serial = ++requestSerial
    const snapshot = auth.currentSnapshot
    loading.value = true
    errorMessage.value = ''
    try {
      const cursor = page > 1 ? cursorStack[page - 2] : undefined
      const result = await fetcher({ limit: pageSize, cursor, signal: current.signal })
      if (serial !== requestSerial || current.signal.aborted) {
        return
      }
      if (!isFresh(snapshot, auth.currentSnapshot)) {
        return
      }
      items.value = result.items
      hasMore.value = !!result.next_cursor
      if (hasMore.value && result.next_cursor) {
        cursorStack[page - 1] = result.next_cursor
      }
      pageNumber.value = page
      loaded.value = true
    } catch (e) {
      if (e instanceof DOMException && e.name === 'AbortError') {
        return
      }
      if (serial !== requestSerial) {
        return
      }
      errorMessage.value = e instanceof ApiError ? e.message : '加载失败'
      items.value = []
    } finally {
      if (serial === requestSerial) {
        loading.value = false
      }
    }
  }

  function reload(): void {
    void load(1)
  }

  function next(): void {
    if (hasMore.value) {
      void load(pageNumber.value + 1)
    }
  }

  function prev(): void {
    if (pageNumber.value > 1) {
      void load(pageNumber.value - 1)
    }
  }

  if (options.reloadKey) {
    watch(options.reloadKey, () => reload(), { deep: true })
  }

  onBeforeUnmount(() => controller?.abort())

  return { items, loading, errorMessage, loaded, pageNumber, hasMore, reload, next, prev }
}
