package com.airagent.iam.admin.entity;

import java.time.OffsetDateTime;
import java.util.UUID;

/** 企业组织持久化数据。 */
public record TenantDO(UUID id, String code, String name, String status, long authRevision, OffsetDateTime createdAt) {
}
