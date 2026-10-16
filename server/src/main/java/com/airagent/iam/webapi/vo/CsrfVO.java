package com.airagent.iam.webapi.vo;

/** HTTP 出参；普通身份视图不含口令摘要。 */
public record CsrfVO(String csrfToken, String expiresAt) {
}
