package com.airagent.iam.auth;

import com.airagent.iam.auth.vo.IdentityVO;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;

/**
 * 权威快照 → iam.identity.v1 线 DTO。
 * I1：资源型权限尚未开通，非 iam-admin 受众不返回业务权限码（资源开通在 I1a）。
 */
@Component
public class IdentityAssembler {

    private static final String SCHEMA_VERSION = "iam.identity.v1";

    public IdentityVO toIdentity(AuthoritySnapshot snapshot, String issuer) {
        return build(snapshot, issuer, false, snapshot.loginAudience());
    }

    /**
     * 内部 introspection 视图：受众交与主体授权的求交由调用方按客户端白名单裁决；
     * 此处返回主体的实时有效权限全集（资源型权限在授予层与机器身份加载层双重默认拒绝）。
     */
    public IdentityVO toIdentityForIntrospection(AuthoritySnapshot snapshot, String issuer, String audience) {
        return build(snapshot, issuer, true, audience);
    }

    private IdentityVO build(AuthoritySnapshot snapshot, String issuer, boolean internalIntrospection, String audience) {
        JsonNode raw = snapshot.raw();
        JsonNode sessionNode = raw.path("session");
        JsonNode userNode = raw.path("user");
        JsonNode tenantNode = raw.path("tenant");
        JsonNode memberNode = raw.path("membership");
        JsonNode revNode = raw.path("revisions");

        String userId = text(userNode, "id");
        boolean hasTenant = !tenantNode.isNull() && !tenantNode.isMissingNode();
        boolean hasMembership = !memberNode.isNull() && !memberNode.isMissingNode();
        boolean tenantUsable = hasTenant && hasMembership
                && "active".equals(text(tenantNode, "status"))
                && "active".equals(text(memberNode, "status"));
        boolean needsTenantSelection = !hasTenant && snapshot.hasAnyMembership();

        List<IdentityVO.Role> platformRoles = roles(raw.path("platform_roles"));
        List<IdentityVO.Role> tenantRoles = tenantUsable
                ? roles(raw.path("tenant_roles"))
                : List.of();
        boolean platformAdmin = platformRoles.stream()
                .anyMatch(r -> "platform_super_admin".equals(r.code()));

        List<String> permissions;
        if (internalIntrospection) {
            permissions = "iam-admin".equals(audience)
                    ? (tenantUsable ? snapshot.permissions() : platformPermissionsOnly(raw, true))
                    : (tenantUsable ? snapshot.permissions().stream()
                            .filter(code -> !code.startsWith("platform:") && !code.equals("entitlement:manage"))
                            .toList() : List.of());
            if (!"iam-admin".equals(audience)) {
                platformRoles = List.of();
                platformAdmin = false;
            }
        } else {
            permissions = "iam-admin".equals(audience) && tenantUsable
                    ? snapshot.permissions()
                    : platformPermissionsOnly(raw, "iam-admin".equals(audience));
        }

        return new IdentityVO(
                SCHEMA_VERSION,
                true,
                issuer,
                audience,
                new IdentityVO.Principal("human", userId, "workforce"),
                new IdentityVO.User(
                        userId,
                        text(userNode, "account"),
                        text(userNode, "display_name"),
                        text(userNode, "status")),
                new IdentityVO.Session(
                        text(sessionNode, "id"),
                        sessionNode.path("ctx_version").asLong(),
                        text(sessionNode, "created_at"),
                        text(sessionNode, "expires_at"),
                        text(sessionNode, "absolute_expires_at"),
                        text(sessionNode, "idle_expires_at")),
                tenantUsable
                        ? new IdentityVO.Tenant(
                                text(tenantNode, "id"), text(tenantNode, "code"),
                                text(tenantNode, "name"), text(tenantNode, "status"))
                        : null,
                tenantUsable
                        ? new IdentityVO.Membership(
                                text(memberNode, "id"),
                                text(memberNode, "tenant_id"),
                                nullableText(memberNode, "department_id"),
                                text(memberNode, "status"),
                                memberNode.path("revision").asLong())
                        : null,
                platformRoles,
                tenantRoles,
                permissions,
                new IdentityVO.Revisions(
                        revNode.path("user_auth_revision").asLong(),
                        revNode.path("tenant_auth_revision").asLong(),
                        revNode.path("membership_revision").asLong(),
                        revNode.path("session_ctx_version").asLong()),
                sessionNode.path("ctx_version").asLong(),
                platformAdmin,
                tenantUsable,
                needsTenantSelection,
                OffsetDateTime.now(ZoneOffset.UTC).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME)
        );
    }

    /** 无可用企业上下文时：iam-admin 受众可保留平台权限码（平台页可见），其他受众为空。 */
    private List<String> platformPermissionsOnly(JsonNode raw, boolean iamAdminAudience) {
        if (!iamAdminAudience) {
            return List.of();
        }
        List<String> codes = new ArrayList<>();
        raw.path("permissions").forEach(n -> {
            String code = n.asText();
            if (code.startsWith("platform:") || code.equals("entitlement:manage")) {
                codes.add(code);
            }
        });
        return codes;
    }

    private List<IdentityVO.Role> roles(JsonNode array) {
        List<IdentityVO.Role> result = new ArrayList<>();
        array.forEach(n -> result.add(new IdentityVO.Role(n.path("code").asText(),
                n.path("name").asText())));
        return result;
    }

    private String text(JsonNode node, String field) {
        JsonNode value = node.path(field);
        return value.isNull() || value.isMissingNode() ? null : value.asText();
    }

    private String nullableText(JsonNode node, String field) {
        return text(node, field);
    }
}
