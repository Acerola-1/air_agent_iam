package com.airagent.iam.internal.dto;

/** 内部核验协议入参。 */
public record RuntimeTicketDTO(
        String subjectToken,
        String audience,
        String targetTenantId,
        Long expectedCtxVersion
) {
    @Override
    public String toString() {
        return "RuntimeTicketDTO[sensitive fields redacted]";
    }
}
