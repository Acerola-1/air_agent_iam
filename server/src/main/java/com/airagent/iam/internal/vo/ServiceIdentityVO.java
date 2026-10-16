package com.airagent.iam.internal.vo;

import com.airagent.iam.internal.dto.RevisionsDTO;

/** 内部核验协议出参。 */
public record ServiceIdentityVO(
        String schemaVersion,
        boolean active,
        String issuer,
        String audience,
        Principal principal,
        Object user,
        Object session,
        Object membership,
        Tenant currentTenant,
        java.util.List<String> permissions,
        long serviceAccountRevision,
        String credentialId,
        long credentialRevision,
        String credentialExpiresAt,
        String overlapUntil,
        RevisionsDTO revisions,
        String evaluatedAt
) {
    public record Principal(String type, String id, String realm) {
    }

    public record Tenant(String id, String code, String name, String status) {
    }
}
