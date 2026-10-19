import type { EntitlementView } from './endpoints'
import type { GrantableLeaf } from './types'

/** Agent 业务资源的稳定前缀；仅用于展示分组，不参与任何权限判定。 */
export const AGENT_BUSINESS_PREFIX = 'agent:business:'

/** 是否为 Agent 业务资源型权限。 */
export function isAgentBusinessLeaf(leaf: GrantableLeaf): boolean {
  return !!leaf.resource_code && leaf.resource_code.startsWith(AGENT_BUSINESS_PREFIX)
}

/** 把企业可授叶子拆成「已开通 Agent 业务」与「其他企业权限」，保持服务端顺序。 */
export function splitTenantLeaves(leaves: GrantableLeaf[]): {
  businesses: GrantableLeaf[]
  others: GrantableLeaf[]
} {
  return {
    businesses: leaves.filter(isAgentBusinessLeaf),
    others: leaves.filter((leaf) => !isAgentBusinessLeaf(leaf))
  }
}

/** 业务可读名：优先资源中文名，缺失时退回稳定编码，不伪造名称。 */
export function businessDisplayName(leaf: GrantableLeaf): string {
  const name = leaf.resource_name_zh?.trim()
  return name ? `${name}（${leaf.code}）` : leaf.code
}

/** 企业开通行的中文名与编码组合。 */
export function entitlementDisplayName(row: EntitlementView): string {
  const name = row.resource_name_zh?.trim()
  return name ? `${name}（${row.resource_code}）` : row.resource_code
}

/** 企业开通状态的中文文案。 */
export function entitlementStatusLabel(row: EntitlementView): string {
  if (row.status !== 'active') {
    return row.exists ? '已回收' : '未开通'
  }
  if (row.resource_status !== 'active') {
    return '目录已停用'
  }
  return row.effective ? '已开通（可授）' : '已开通（不可授）'
}
