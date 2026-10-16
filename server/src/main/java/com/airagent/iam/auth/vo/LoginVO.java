package com.airagent.iam.auth.vo;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 登录/SSO 兑换成功响应体（VO）。
 *
 * <p>分层位置：由 {@link com.airagent.iam.auth.service.SessionService} 装配，
 * {@code accessToken} 是原始不透明令牌的唯一一次出口——数据库与 Redis 只保存其 SHA-256 摘要，
 * 一旦响应丢失只能重新登录。后续请求须以 {@code Authorization: Bearer <accessToken>} 携带。
 *
 * <p>{@code expiresIn} 取空闲时限秒数（配置 {@code iam.session.idle-timeout-seconds}），
 * 不是绝对上限：绝对到期时刻见 {@code identity.session.absoluteExpiresAt}。
 * 本类覆写 {@code toString()} 输出固定脱敏文本，令牌不会经日志外泄。
 *
 * @param accessToken 原始不透明访问令牌（URL-safe Base64 无填充），只在本响应中出现一次；不回显于日志
 * @param tokenType   令牌类型，固定 {@code Bearer}
 * @param expiresIn   空闲有效期，单位秒；持续活动可经续期端点延长，但不会越过绝对上限
 * @param identity    登录后的实时身份视图（含会话纪元与受众裁剪后的权限码）
 * @author Acerola
 */
@Schema(name = "LoginVO", description = "登录结果：一次性下发的不透明 Bearer 令牌、类型、空闲有效期与实时身份视图")
public record LoginVO(

        @Schema(description = "原始访问令牌，仅在本次响应中出现；服务端只存摘要，不回显于任何后续接口",
                readOnly = true)
        String accessToken,

        @Schema(description = "令牌类型，固定 Bearer", example = "Bearer")
        String tokenType,

        @Schema(description = "空闲有效期，单位秒（iam.session.idle-timeout-seconds），非绝对上限",
                example = "604800")
        long expiresIn,

        @Schema(description = "会话建立并二次核验成功后的实时身份视图")
        IdentityVO identity
) {

    /**
     * 固定脱敏输出，防止访问令牌经日志或异常信息外泄。
     *
     * @return 不含任何字段值的常量文本
     */
    @Override
    public String toString() {
        return "LoginVO[sensitive fields redacted]";
    }
}
