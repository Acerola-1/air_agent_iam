package com.airagent.iam.webapi.vo;

import com.airagent.iam.auth.vo.IdentityVO;
import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 浏览器会话续期响应体（VO，{@code POST /web-api/auth/renew}）。
 *
 * <p>分层位置：由 {@link com.airagent.iam.webapi.controller.WebApiAuthController#renew} 装配，
 * 合并 {@link com.airagent.iam.auth.vo.SessionTimersVO} 的两个到期时刻与续期后重新读取的
 * 实时身份视图——因此前端可在一次调用内既拿到新时限、又拿到可能已变化的权限/企业上下文。
 *
 * <p>时限语义（与 {@link com.airagent.iam.auth.vo.SessionTimersVO} 一致）：续期只推进空闲到期
 * 时刻且单调不减、被绝对上限夹住；两者相等即空闲窗口已顶到绝对上限，此后<em>无法</em>再延长。
 * 会话撤销/过期不存在"复活"路径（数据库以 28000 拒绝续期）。
 *
 * @param absoluteExpiresAt 绝对到期时刻，UTC ISO-8601 文本；续期不改变，数据库返回为空时
 *                          为 {@code null}
 * @param idleExpiresAt     续期后的空闲到期时刻（即会话当前到期时刻），UTC ISO-8601 文本；
 *                          为空时为 {@code null}
 * @param identity          续期后经
 *                          {@link com.airagent.iam.auth.service.SessionService#requireCurrentBySessionId(java.util.UUID)}
 *                          重读并装配的实时身份视图（受众 {@code iam-admin}）
 * @author Acerola
 */
@Schema(name = "WebRenewVO", description = "浏览器续期结果：绝对与空闲到期时刻（UTC ISO-8601）加续期后实时身份视图")
public record WebRenewVO(

        @Schema(description = "绝对到期时刻，续期不改变；与 idle 相等说明已顶到绝对上限",
                example = "2026-11-08T02:00:00Z", nullable = true)
        String absoluteExpiresAt,

        @Schema(description = "续期后的空闲到期时刻（会话当前到期时刻）",
                example = "2026-10-23T02:00:00Z", nullable = true)
        String idleExpiresAt,

        @Schema(description = "续期后重读的实时身份视图（受众 iam-admin）")
        IdentityVO identity
) {
}
