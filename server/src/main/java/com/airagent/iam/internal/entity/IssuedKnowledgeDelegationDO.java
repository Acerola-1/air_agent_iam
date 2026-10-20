package com.airagent.iam.internal.entity;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * 新签发知识委托的返回行（DO，仅 Mapper 使用）。
 *
 * @param expiresAt      委托失效时刻（≤60 秒且不超过源引用/会话期限）
 * @param userId         源用户
 * @param sessionId      源会话
 * @param tenantId       当前企业
 * @param membershipId   企业成员关系
 * @param contextVersion 会话上下文代次
 * @param revisionsJson  四项修订（jsonb 文本）
 */
public record IssuedKnowledgeDelegationDO(
        OffsetDateTime expiresAt,
        UUID userId,
        UUID sessionId,
        UUID tenantId,
        UUID membershipId,
        Long contextVersion,
        String revisionsJson) {
}
