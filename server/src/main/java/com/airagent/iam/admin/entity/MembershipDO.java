package com.airagent.iam.admin.entity;

import java.util.UUID;

/** 企业组织持久化数据。 */
public record MembershipDO(UUID id, UUID tenantId, UUID userId, UUID departmentId, String status, long revision) {
}
