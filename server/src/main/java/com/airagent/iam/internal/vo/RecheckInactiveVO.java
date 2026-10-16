package com.airagent.iam.internal.vo;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 执行引用复查不通过结论（VO，引用复查模式的失败响应，HTTP 仍为 200）。
 *
 * <p>分层位置：由
 * {@link com.airagent.iam.internal.service.impl.IntrospectionServiceImpl} 的复查分支构造，
 * 覆盖四种真实情形：引用查不到（伪造、跨客户端、受众不符或已过期）、原会话权威快照不可用、
 * 修订三方不全等、PG 判定通过但 Redis 中会话摘要已不存活。
 *
 * <p>{@code contextMatches} 为 {@code false} 的唯一出口就是本结构——{@code active:false} 与
 * {@code contextMatches:false} 总是一同出现，消费方应据 {@code reason} 区分"该重新核验/重新登录"
 * 与"该丢弃这条迟到结果"。本结构不返回任何当前修订值，避免把新上下文泄露给持有旧引用的调用方。
 *
 * @param active          恒为 {@code false}
 * @param contextMatches  恒为 {@code false}（复查通过时使用 {@link RecheckActiveVO}）
 * @param reason          不通过原因：{@code invalid_or_revoked}（引用无效/会话撤销/Redis 失联）、
 *                        {@code revision_mismatch}（基线与登记值或实时值不一致）、
 *                        {@code account_disabled} / {@code tenant_suspended} /
 *                        {@code membership_disabled}（快照给出的已知停用类状态）
 * @param evaluatedAt     服务端评估时刻（UTC ISO-8601 文本）
 * @author Acerola
 */
@Schema(description = "引用复查不通过：active 与 context_matches 双 false，并给出原因码。"
        + "不回当前修订，消费方据此丢弃迟到结果或重新走令牌核验")
public record RecheckInactiveVO(

        @Schema(description = "主体是否仍有效；本结构恒为 false")
        boolean active,

        @Schema(description = "上下文是否匹配；本结构恒为 false")
        boolean contextMatches,

        @Schema(description = "不通过原因码", example = "revision_mismatch",
                allowableValues = {"invalid_or_revoked", "revision_mismatch", "account_disabled",
                        "tenant_suspended", "membership_disabled", "context_required"})
        String reason,

        @Schema(description = "服务端评估时刻（UTC ISO-8601 文本）", example = "2026-10-16T02:11:00Z")
        String evaluatedAt
) {
}
