package com.airagent.iam.serviceaccount.entity;

import java.time.OffsetDateTime;

/** 数据库结果对象。 */
public record IssuedTokenDO(long credentialRevision, OffsetDateTime expiresAt, OffsetDateTime overlapUntil) {
}
