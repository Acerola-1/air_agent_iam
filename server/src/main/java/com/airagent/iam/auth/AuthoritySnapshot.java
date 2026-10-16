package com.airagent.iam.auth;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import tools.jackson.databind.JsonNode;

/**
 * {@code iam_auth.load_trusted_authority_snapshot}（内部复用 {@code iam_auth.load_authority_snapshot}）
 * 返回 jsonb 的类型化只读视图（auth 域共享模型，非 DO/VO）。
 *
 * <p>分层位置：Mapper 以 {@code String} 取回 jsonb 文本，{@code SessionServiceImpl} 解析为
 * {@link JsonNode} 后经 {@link #of(JsonNode)} 包装成本视图；Service、Controller 与
 * {@link IdentityAssembler} 一律通过这里定义的访问器读取，不再重复写 JSON 路径。
 *
 * <p>语义边界：判定结论完全由数据库函数给出——会话不存在即 {@code missing}，
 * 状态/时限/授权代次（{@code auth_revision} 与 {@code base_*_revision}）的比较都在 PG 内完成，
 * 本类只做读取与类型转换，不做任何放行推断。时间戳在 jsonb 中已是 ISO 文本，直接透传不重解析；
 * 快照含 {@code user.password_hash}，仅在服务端内存中使用，永不出现在响应或日志。
 *
 * <p>所有访问器都是无副作用的按需读取：每次调用重新遍历 JSON 树，本类不持有缓存副本。
 *
 * @param status 判定状态原文，取值 {@code ok} / {@code missing} / {@code invalid_or_revoked} /
 *               {@code account_disabled} / {@code tenant_suspended} / {@code membership_disabled}；
 *               {@code raw} 中缺失 status 字段时为空串
 * @param raw    数据库返回的完整 jsonb 树，是各访问器的唯一数据来源
 * @author Acerola
 */
public record AuthoritySnapshot(
        String status,
        JsonNode raw
) {

    /** 权威判定通过、会话可继续放行的唯一状态值。 */
    public static final String OK = "ok";

    /**
     * 从解析后的 jsonb 树构建视图。
     *
     * @param raw {@code load_trusted_authority_snapshot} 结果解析出的对象节点；
     *            {@code status} 缺失或为 null 节点时状态取空串（{@link #usable()} 为 {@code false}）
     * @return 只读视图，不对 {@code raw} 做拷贝
     */
    public static AuthoritySnapshot of(JsonNode raw) {
        return new AuthoritySnapshot(raw.path("status").asText(), raw);
    }

    /**
     * 会话是否可继续放行。
     *
     * @return 仅当状态等于 {@link #OK} 时为 {@code true}；其余判定（含 {@code missing}）均为 {@code false}
     */
    public boolean usable() {
        return OK.equals(status);
    }

    /**
     * 会话 id，取自 JSON 指针 {@code /session/id}。
     *
     * @return 会话 UUID；快照状态为 {@code missing}（无 session 节点）时为 {@code null}
     */
    public UUID sessionId() {
        return uuidAt("/session/id");
    }

    /**
     * 会话主体用户 id，取自 {@code /user/id}。
     *
     * @return 用户 UUID；快照状态为 {@code missing} 时为 {@code null}
     */
    public UUID userId() {
        return uuidAt("/user/id");
    }

    /**
     * 账号域，取自 {@code /session/realm}。
     *
     * @return 域文本（当前人类会话为 {@code workforce}）；字段缺失或为 null 时返回 {@code null}
     */
    public String realm() {
        return textAt("/session/realm");
    }

    /**
     * 登录登记的受众，取自 {@code /session/login_audience}。
     *
     * @return 受众文本；字段缺失或为 null 时返回 {@code null}
     */
    public String loginAudience() {
        return textAt("/session/login_audience");
    }

    /**
     * 当前企业 id，取自 {@code /session/current_tenant_id}。
     *
     * @return 企业 UUID；{@code null} 表示该会话尚未选择企业（平台域上下文）
     */
    public UUID currentTenantId() {
        String id = textAt("/session/current_tenant_id");
        return id == null || id.isBlank() ? null : UUID.fromString(id);
    }

    /**
     * 会话上下文代次（会话纪元），取自 {@code /session/ctx_version}。
     *
     * @return 代次值；首次登录为 1，每次成功切企业 +1；字段缺失时为 0
     */
    public long ctxVersion() {
        return raw.path("session").path("ctx_version").asLong();
    }

    /**
     * 该用户是否至少存在一个活跃企业与活跃成员关系（用于判断"需选企业"而非"无任何企业"）。
     *
     * @return 有可选企业时为 {@code true}；{@code has_any_membership} 缺失或为 null 时为 {@code false}
     */
    public boolean hasAnyMembership() {
        return raw.path("has_any_membership").asBoolean(false);
    }

    /**
     * 实时有效权限码全集（平台角色与企业角色授权在 PG 侧 UNION 去重后的结果）。
     *
     * @return 新构造的可变列表，顺序为数据库 jsonb 聚合顺序；无权限时为空列表
     */
    public List<String> permissions() {
        List<String> values = new ArrayList<>();
        raw.path("permissions").forEach(n -> values.add(n.asText()));
        return values;
    }

    /**
     * 判断是否持有指定平台角色（仅遍历 {@code platform_roles}，不含企业角色）。
     *
     * @param code 角色码，如 {@code platform_super_admin}；不可为 {@code null}
     * @return 命中返回 {@code true}；角色数组缺失、为空或无匹配返回 {@code false}
     */
    public boolean hasPlatformRole(String code) {
        for (JsonNode role : raw.path("platform_roles")) {
            if (code.equals(role.path("code").asText())) {
                return true;
            }
        }
        return false;
    }

    /**
     * 按 JSON 指针读取 UUID 文本。
     *
     * @param pointer RFC 6901 JSON 指针（如 {@code /session/id}）
     * @return UUID；节点缺失、为 null、文本空白或字面量 {@code "null"} 时返回 {@code null}
     */
    private UUID uuidAt(String pointer) {
        String value = textAt(pointer);
        return value == null || value.isBlank() || "null".equals(value) ? null : UUID.fromString(value);
    }

    /**
     * 按 JSON 指针读取标量文本。
     *
     * @param pointer RFC 6901 JSON 指针
     * @return 节点的 {@code asText()} 结果；节点缺失或为 null 时返回 {@code null}
     */
    private String textAt(String pointer) {
        JsonNode node = raw.at(pointer);
        return node == null || node.isNull() || node.isMissingNode() ? null : node.asText();
    }
}
