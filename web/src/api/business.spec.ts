import { describe, expect, it } from 'vitest'
import {
  businessDisplayName,
  entitlementDisplayName,
  entitlementStatusLabel,
  isAgentBusinessLeaf,
  splitTenantLeaves
} from './business'
import type { EntitlementView } from './endpoints'
import type { GrantableLeaf } from './types'

const business: GrantableLeaf = {
  code: 'agent:business:basic-qa:use',
  name: '使用基础问答',
  resource_code: 'agent:business:basic-qa',
  resource_name_zh: '基础问答'
}
const analysis: GrantableLeaf = {
  code: 'agent:business:data-analysis:use',
  name: '使用数据分析',
  resource_code: 'agent:business:data-analysis',
  resource_name_zh: '数据分析'
}
const memberRead: GrantableLeaf = {
  code: 'tenant:member:read',
  name: '企业成员查看',
  resource_code: null,
  resource_name_zh: null
}

function entitlement(overrides: Partial<EntitlementView> = {}): EntitlementView {
  return {
    tenant_id: 't-a',
    resource_code: 'agent:business:basic-qa',
    resource_name_zh: '基础问答',
    status: 'active',
    revision: 1,
    exists: true,
    resource_status: 'active',
    effective: true,
    granted_at: '2026-10-19T00:00:00Z',
    revoked_at: null,
    updated_at: null,
    updated_by: null,
    tenant_auth_revision: 1,
    changed: true,
    ...overrides
  }
}

describe('Agent 业务分组', () => {
  it('只把 agent:business 前缀归入业务，其他企业权限保持原顺序', () => {
    const split = splitTenantLeaves([business, memberRead, analysis])
    expect(split.businesses.map((x) => x.code)).toEqual([business.code, analysis.code])
    expect(split.others.map((x) => x.code)).toEqual([memberRead.code])
  })

  it('资源码缺失时不误判为业务', () => {
    expect(isAgentBusinessLeaf(memberRead)).toBe(false)
  })

  it('业务名优先中文资源名，缺失时如实退回权限码', () => {
    expect(businessDisplayName(business)).toBe('基础问答（agent:business:basic-qa:use）')
    expect(businessDisplayName({ ...business, resource_name_zh: null })).toBe(business.code)
  })
})

describe('企业开通中文状态', () => {
  it('开通行同时展示中文名与稳定编码', () => {
    expect(entitlementDisplayName(entitlement())).toBe('基础问答（agent:business:basic-qa）')
    expect(entitlementDisplayName(entitlement({ resource_name_zh: '' })))
      .toBe('agent:business:basic-qa')
  })

  it('区分未开通、已回收、目录停用与不可授', () => {
    expect(entitlementStatusLabel(entitlement({ status: 'revoked', exists: false }))).toBe('未开通')
    expect(entitlementStatusLabel(entitlement({ status: 'revoked' }))).toBe('已回收')
    expect(entitlementStatusLabel(entitlement({ resource_status: 'disabled' }))).toBe('目录已停用')
    expect(entitlementStatusLabel(entitlement({ effective: false }))).toBe('已开通（不可授）')
    expect(entitlementStatusLabel(entitlement())).toBe('已开通（可授）')
  })
})
