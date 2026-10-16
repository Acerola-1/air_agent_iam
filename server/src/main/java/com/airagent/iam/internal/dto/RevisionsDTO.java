package com.airagent.iam.internal.dto;

/** 内部核验协议入参。 */
public record RevisionsDTO(
        Long userAuthRevision,
        Long tenantAuthRevision,
        Long membershipRevision,
        Long sessionCtxVersion
) {
}
