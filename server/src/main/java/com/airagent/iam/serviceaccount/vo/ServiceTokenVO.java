package com.airagent.iam.serviceaccount.vo;

/** HTTP 出参；普通身份视图不含口令摘要。 */
public record ServiceTokenVO(
        String credentialId,
        long credentialRevision,
        String status,
        String issuedAt,
        String expiresAt,
        String overlapUntil,
        String revokedAt
) {
}
