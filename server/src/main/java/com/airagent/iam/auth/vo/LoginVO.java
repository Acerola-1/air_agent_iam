package com.airagent.iam.auth.vo;

/** HTTP 出参；普通身份视图不含口令摘要。 */
public record LoginVO(
        String accessToken,
        String tokenType,
        long expiresIn,
        IdentityVO identity
) {
    @Override
    public String toString() {
        return "LoginVO[sensitive fields redacted]";
    }
}
