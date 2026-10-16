package com.airagent.iam.auth.entity;

import java.time.OffsetDateTime;

/** 数据库结果对象。 */
public record SessionTimerDO(OffsetDateTime absoluteExpiresAt, OffsetDateTime idleExpiresAt) {
}
