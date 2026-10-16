package com.airagent.iam.internal.dto;

/** 内部核验协议入参。 */
public record ExecutionContextRefDTO(String verificationRef, RevisionsDTO expectedRevisions) {
}
