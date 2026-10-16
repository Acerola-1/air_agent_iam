package com.airagent.iam.internal.vo;

import com.airagent.iam.internal.dto.RevisionsDTO;
import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 执行引用复查通过结论（VO，引用复查模式的成功响应）。
 *
 * <p>分层位置：由
 * {@link com.airagent.iam.internal.service.impl.IntrospectionServiceImpl} 的复查分支构造，
 * 仅当同一次主库往返内三个条件同时成立才产生：引用仍有效且属于本次客户端与受众、
 * 原会话权威快照判 {@code ok}、引用登记修订 == 调用方声明修订 == 当前实时修订；
 * 事务外还要求 Redis 中该会话令牌摘要仍存活。
 *
 * <p>不扩大权限：本结论只声明"原会话上下文仍未变化"，不返回身份、权限码或企业信息，
 * 也不构成新的授权——复查通过不能让运行获得比首次内省更多的东西，引用有效期与会话有效期
 * 都不因此延长。
 *
 * @param active          恒为 {@code true}（不通过时使用 {@link RecheckInactiveVO}）
 * @param contextMatches  恒为 {@code true}——本结构只在全等比较通过后装配，
 *                        {@code false} 的情形一律走 {@link RecheckInactiveVO}
 * @param revisions       当前实时的四项修订（与引用登记值、调用方声明值三者相同），
 *                        消费方可用它的 {@code session_ctx_version} 作为下一轮 CAS 基线
 * @param evaluatedAt     服务端评估时刻（UTC ISO-8601 文本）
 * @author Acerola
 */
@Schema(description = "引用复查通过：主体仍有效且上下文与登记基线一致。不返回身份细节，不重新授予权限")
public record RecheckActiveVO(

        @Schema(description = "主体是否仍有效；本结构恒为 true")
        boolean active,

        @Schema(description = "上下文是否匹配；本结构恒为 true（不匹配时返回 active/context_matches 双 false 的结构）")
        boolean contextMatches,

        @Schema(description = "当前实时的四项权威修订")
        RevisionsDTO revisions,

        @Schema(description = "服务端评估时刻（UTC ISO-8601 文本）", example = "2026-10-16T02:11:00Z")
        String evaluatedAt
) {
}
