package com.airagent.iam.internal.dto;

/** 内部核验协议入参。 */
public record ExpectedContextDTO(String tenantId, Long ctxVersion) {
}
