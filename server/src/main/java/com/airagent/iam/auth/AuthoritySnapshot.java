package com.airagent.iam.auth;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import tools.jackson.databind.JsonNode;

/**
 * iam_auth.load_authority_snapshot 的 jsonb 结果的类型化视图。
 * 时间戳在 jsonb 中已是 ISO 字符串，直接透传。
 */
public record AuthoritySnapshot(
        String status,
        JsonNode raw
) {

    public static final String OK = "ok";

    public static AuthoritySnapshot of(JsonNode raw) {
        return new AuthoritySnapshot(raw.path("status").asText(), raw);
    }

    public boolean usable() {
        return OK.equals(status);
    }

    public UUID sessionId() {
        return uuidAt("/session/id");
    }

    public UUID userId() {
        return uuidAt("/user/id");
    }

    public String realm() {
        return textAt("/session/realm");
    }

    public String loginAudience() {
        return textAt("/session/login_audience");
    }

    public UUID currentTenantId() {
        String id = textAt("/session/current_tenant_id");
        return id == null || id.isBlank() ? null : UUID.fromString(id);
    }

    public long ctxVersion() {
        return raw.path("session").path("ctx_version").asLong();
    }

    public boolean hasAnyMembership() {
        return raw.path("has_any_membership").asBoolean(false);
    }

    public List<String> permissions() {
        List<String> values = new ArrayList<>();
        raw.path("permissions").forEach(n -> values.add(n.asText()));
        return values;
    }

    public boolean hasPlatformRole(String code) {
        for (JsonNode role : raw.path("platform_roles")) {
            if (code.equals(role.path("code").asText())) {
                return true;
            }
        }
        return false;
    }

    private UUID uuidAt(String pointer) {
        String value = textAt(pointer);
        return value == null || value.isBlank() || "null".equals(value) ? null : UUID.fromString(value);
    }

    private String textAt(String pointer) {
        JsonNode node = raw.at(pointer);
        return node == null || node.isNull() || node.isMissingNode() ? null : node.asText();
    }
}
