package com.airagent.iam.internal.entity;

import java.util.UUID;

/** 数据库结果对象。 */
public record VerificationRefDO(UUID sessionId, UUID userId, UUID tenantId, String revisionsJson) {
}
