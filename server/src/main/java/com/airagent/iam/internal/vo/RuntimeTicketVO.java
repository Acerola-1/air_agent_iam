package com.airagent.iam.internal.vo;

/** 内部核验协议出参。 */
public record RuntimeTicketVO(
        String ticket,
        String tokenType,
        String expiresAt,
        long expiresIn,
        String audience,
        String format
) {
    @Override
    public String toString() {
        return "RuntimeTicketVO[sensitive fields redacted]";
    }
}
