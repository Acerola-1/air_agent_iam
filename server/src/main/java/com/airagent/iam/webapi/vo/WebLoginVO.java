package com.airagent.iam.webapi.vo;

import com.airagent.iam.auth.vo.IdentityVO;
import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 浏览器登录成功响应体（VO，{@code POST /web-api/auth/login}）。
 *
 * <p>分层位置：由 {@link com.airagent.iam.webapi.controller.WebApiAuthController#login} 装配。
 * 与 Bearer 面的 {@link IdentityVO} 结构一致，但<em>刻意不含</em>人类访问令牌——原始令牌
 * 只存在于服务端会话（Redis Sa-Token 与 PG 摘要），浏览器侧仅通过 HttpOnly 会话句柄 Cookie
 * 间接引用它，任何 JS 可读位置都拿不到令牌（"人类令牌从不进入浏览器"）。
 *
 * @param identity   登录后的实时身份视图（主体、会话纪元、当前企业上下文与按受众裁剪的权限码）；
 *                   受众固定为 {@code iam-admin}
 * @param expiresAt  会话当前到期时刻（等于空闲到期时刻），ISO-8601 文本，取自
 *                   {@code identity.session.expires_at}；绝对上限见 {@code identity.session.absolute_expires_at}
 * @author Acerola
 */
@Schema(name = "WebLoginVO", description = "浏览器登录结果：安全身份视图与会话到期时刻；不回传任何人类访问令牌")
public record WebLoginVO(

        @Schema(description = "登录并二次核验成功后的实时身份视图（受众 iam-admin）")
        IdentityVO identity,

        @Schema(description = "会话当前到期时刻（= 空闲到期），ISO-8601 文本",
                example = "2026-10-23T02:00:00Z")
        String expiresAt
) {
}
