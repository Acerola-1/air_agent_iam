package com.airagent.iam.internal.vo;

/** 内部核验协议出参。 */
public record InactiveIntrospectionVO(
        String schemaVersion,
        boolean active,
        String reason,
        String evaluatedAt
) {
}
