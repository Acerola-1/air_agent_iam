package com.airagent.iam.admin.entity;

import java.util.UUID;

/** 企业组织持久化数据。 */
public record DepartmentDO(UUID id, UUID tenantId, UUID parentId, String code, String name, String status) {
}
