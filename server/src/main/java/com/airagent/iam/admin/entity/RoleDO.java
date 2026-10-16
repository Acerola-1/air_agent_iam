package com.airagent.iam.admin.entity;

import java.util.UUID;

/** 角色持久化数据。 */
public record RoleDO(UUID id, String code, String scope, UUID tenantId, String name,
                      String description, boolean builtin, String status) {
}
