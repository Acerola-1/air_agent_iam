package com.airagent.iam.auth.entity;

import java.util.UUID;

/** 数据库结果对象。 */
public record SessionContextDO(UUID userId, UUID currentTenantId) {
}
