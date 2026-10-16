package com.airagent.iam.internal.dto;

/** 内部核验协议入参。 */
public record IntrospectDTO(
        String subjectToken,
        ExecutionContextRefDTO executionContext,
        String audience,
        ExpectedContextDTO expectedContext,
        Boolean includeExecutionContext
) {
    @Override
    public String toString() {
        return "IntrospectDTO[sensitive fields redacted]";
    }
}
