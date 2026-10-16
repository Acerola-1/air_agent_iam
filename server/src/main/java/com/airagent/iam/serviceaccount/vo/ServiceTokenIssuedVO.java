package com.airagent.iam.serviceaccount.vo;

/** HTTP 出参；普通身份视图不含口令摘要。 */
public record ServiceTokenIssuedVO(
        String credentialId,
        String secret,
        String tokenType,
        String expiresAt,
        String overlapUntil,
        long credentialRevision
) {
    @Override
    public String toString() {
        return "ServiceTokenIssuedVO[sensitive fields redacted]";
    }
}
