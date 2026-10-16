package com.airagent.iam.internal.vo;

/** 内部核验协议出参。 */
public record RecheckInactiveVO(
        boolean active,
        boolean contextMatches,
        String reason,
        String evaluatedAt
) {
}
