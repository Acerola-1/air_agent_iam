package com.airagent.iam.serviceaccount.entity;

import java.time.OffsetDateTime;

/** 数据库结果对象。 */
public record ServiceTokenDO(
        String credentialId,
        long credentialRevision,
        String status,
        OffsetDateTime issuedAt,
        OffsetDateTime expiresAt,
        OffsetDateTime overlapUntil,
        OffsetDateTime revokedAt) {
}
