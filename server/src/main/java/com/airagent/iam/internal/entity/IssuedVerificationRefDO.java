package com.airagent.iam.internal.entity;

import java.time.OffsetDateTime;
import java.util.UUID;

/** 数据库结果对象。 */
public record IssuedVerificationRefDO(UUID id, OffsetDateTime validUntil) {
}
