package com.airagent.iam.admin.entity;

import java.time.Instant;
import java.util.UUID;

/**
 * iam.tenant_entitlements 行的持久化视图（DO，企业资源开通记录）。
 */
public record TenantEntitlementDO(
        UUID tenantId,
        String resourceCode,
        String status,
        Long revision,
        Instant grantedAt,
        Instant revokedAt,
        UUID updatedBy,
        Instant updatedAt
) {
}
