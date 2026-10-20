package com.airagent.iam.internal.entity;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * {@code iam.knowledge_delegations} 单行的持久化视图（DO，仅 Mapper 使用，不直接对外）。
 *
 * <p>该行只保存委托令牌的 SHA-256 摘要，不含原始令牌；{@code operation} 是单一只读操作。
 * 有效期在数据库内已按"签发时 TTL ≤ 60 秒、源引用期限、会话绝对期限"三者取小。
 *
 * @param id              委托行 id
 * @param issuingClientId 申请该委托的 Agent 内部客户端
 * @param userId          源用户
 * @param sessionId       源登录会话
 * @param tenantId        源会话当前企业
 * @param membershipId    该企业内的成员关系
 * @param operation       单一只读操作
 * @param contextVersion  源会话上下文代次
 * @param revisionsJson   签发时的四项修订（jsonb 文本）
 * @param expiresAt       委托失效时刻
 */
public record KnowledgeDelegationDO(
        UUID id,
        String issuingClientId,
        UUID userId,
        UUID sessionId,
        UUID tenantId,
        UUID membershipId,
        String operation,
        Long contextVersion,
        String revisionsJson,
        OffsetDateTime expiresAt) {
}
