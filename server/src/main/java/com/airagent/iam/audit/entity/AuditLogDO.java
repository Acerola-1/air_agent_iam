package com.airagent.iam.audit.entity;

import java.time.OffsetDateTime;
import java.util.UUID;

/** 审计日志持久化对象；JSON 在数据库边界转换为文本。 */
public record AuditLogDO(long id, UUID tenantId, UUID actorUserId, String actorType,
                         String action, String targetType, String targetId, String detailJson,
                         String requestId, OffsetDateTime createdAt) {
}
