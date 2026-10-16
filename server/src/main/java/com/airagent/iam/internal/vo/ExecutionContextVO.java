package com.airagent.iam.internal.vo;

import com.airagent.iam.internal.dto.RevisionsDTO;

/** 内部核验协议出参。 */
public record ExecutionContextVO(
        String verificationRef,
        String audience,
        String sessionId,
        RevisionsDTO revisions,
        String validUntil
) {
}
