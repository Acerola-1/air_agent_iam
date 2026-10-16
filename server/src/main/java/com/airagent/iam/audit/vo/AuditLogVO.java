package com.airagent.iam.audit.vo;

import tools.jackson.databind.JsonNode;

/** 审计出参，保持既有 snake_case API 字段。 */
public record AuditLogVO(long id, String tenantId, String actorUserId, String actorType,
                         String action, String targetType, String targetId, JsonNode detail,
                         String requestId, String createdAt) {
}
