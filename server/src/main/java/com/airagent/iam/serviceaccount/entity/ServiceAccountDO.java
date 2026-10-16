package com.airagent.iam.serviceaccount.entity;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

/** 数据库结果对象。 */
public record ServiceAccountDO(
        UUID id,
        String account,
        String name,
        UUID tenantId,
        String status,
        List<String> audiences,
        OffsetDateTime expiresAt,
        long revision) {
}
