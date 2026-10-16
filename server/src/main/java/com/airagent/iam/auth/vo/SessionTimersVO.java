package com.airagent.iam.auth.vo;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 续期后的会话时限视图（VO，{@code POST /v1/auth/renew} 的响应体）。
 *
 * <p>分层位置：由 {@link com.airagent.iam.auth.service.SessionService#renew(String,
 * com.airagent.iam.auth.dto.RenewDTO)} 从数据库函数 {@code iam_auth.renew_session} 的返回值装配，
 * 时间戳统一转为 UTC ISO-8601 文本，与 {@code IdentityVO.Session} 的文本口径一致。
 *
 * <p>语义：续期只推进空闲到期时刻且单调不减，同时被绝对到期时刻夹住——两者相等即表示
 * 空闲窗口已被绝对上限截断，此后无论怎样续期都不会再延长会话。
 *
 * @param absoluteExpiresAt 绝对到期时刻（UTC ISO-8601 文本），续期不改变；
 *                          数据库返回为空时为 {@code null}
 * @param idleExpiresAt     续期后的空闲到期时刻（UTC ISO-8601 文本）；
 *                          数据库返回为空时为 {@code null}
 * @author Acerola
 */
@Schema(name = "SessionTimersVO", description = "续期结果：绝对与空闲两个到期时刻（UTC ISO-8601 文本）")
public record SessionTimersVO(

        @Schema(description = "绝对到期时刻，续期不改变；与 idle_expires_at 相等说明空闲窗口已顶到绝对上限",
                example = "2026-11-08T02:00:00Z", nullable = true)
        String absoluteExpiresAt,

        @Schema(description = "续期后的空闲到期时刻（同时作为会话当前到期时刻）",
                example = "2026-10-23T02:00:00Z", nullable = true)
        String idleExpiresAt
) {
}
