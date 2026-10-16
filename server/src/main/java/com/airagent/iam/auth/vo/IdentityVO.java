package com.airagent.iam.auth.vo;

import java.util.List;

/**
 * iam.identity.v1 安全身份 DTO。字段命名由全局 SNAKE_CASE 策略输出，
 * 与 contracts/schemas/identity.schema.json 对齐。
 */
public record IdentityVO(
        String schemaVersion,
        boolean active,
        String issuer,
        String audience,
        Principal principal,
        User user,
        Session session,
        Tenant currentTenant,
        Membership membership,
        List<Role> platformRoles,
        List<Role> tenantRoles,
        List<String> permissions,
        Revisions revisions,
        long contextVersion,
        boolean platformAdmin,
        boolean contextUsable,
        boolean needsTenantSelection,
        String evaluatedAt
) {
    public record Principal(String type, String id, String realm) {
    }

    public record User(String id, String account, String displayName, String status) {
    }

    public record Session(
            String id,
            long ctxVersion,
            String createdAt,
            String expiresAt,
            String absoluteExpiresAt,
            String idleExpiresAt
    ) {
    }

    public record Tenant(String id, String code, String name, String status) {
    }

    public record Membership(
            String id,
            String tenantId,
            String departmentId,
            String status,
            long revision
    ) {
    }

    public record Role(String code, String name) {
    }

    public record Revisions(
            long userAuthRevision,
            long tenantAuthRevision,
            long membershipRevision,
            long sessionCtxVersion
    ) {
    }
}
