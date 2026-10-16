package com.airagent.iam.webapi.vo;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * CSRF 获取响应体（VO，{@code GET /web-api/csrf} 与 {@code /web-api/auth/csrf}）。
 *
 * <p>分层位置：由 {@link com.airagent.iam.webapi.controller.BrowserCsrfController} 装配，
 * 值取自 {@link com.airagent.iam.webapi.service.BrowserSessionService.IssuedHandle}。
 * 本视图<em>不含</em>任何口令、令牌或会话密钥——浏览器后续写操作把这里的 {@code csrfToken}
 * 放进 {@code X-CSRF-Token} 头，权威比对以 iam.browser_handles 中该句柄绑定的值为准（双提交）。
 *
 * <p>下发时机：同一响应还会通过 {@code Set-Cookie} 写入 HttpOnly 会话句柄 Cookie 与
 * JS 可读的 CSRF Cookie；本体的 {@code csrfToken} 与 CSRF Cookie 值一致，前端既可从
 * 响应体取、也可从 Cookie 取。
 *
 * @param csrfToken 本次句柄绑定的双提交 CSRF 值（{@code OpaqueTokens.newRawToken()} 生成的
 *                  URL-safe Base64 随机串）；写操作需在 {@code X-CSRF-Token} 头原样回传
 * @param expiresAt 句柄到期时刻，UTC ISO-8601 文本（{@code OffsetDateTime#toString()} 原样透传），
 *                  前端可据此在过期前重新获取
 * @author Acerola
 */
@Schema(name = "CsrfVO", description = "浏览器双提交 CSRF：令牌值与句柄到期时刻（UTC ISO-8601 文本）；不含口令或会话令牌")
public record CsrfVO(

        @Schema(description = "写操作需在 X-CSRF-Token 头回传的令牌值；权威值以句柄库绑定为准",
                example = "wOnGv3fLm0Qz2t8Yc1Rd6kEaPbJhSxUvNqYt4gZm7Kl")
        String csrfToken,

        @Schema(description = "句柄到期时刻（UTC ISO-8601 文本），与下发 Cookie 的 Max-Age 一致",
                example = "2026-10-23T02:00:00Z")
        String expiresAt
) {
}
