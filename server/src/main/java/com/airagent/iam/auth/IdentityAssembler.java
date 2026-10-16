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
 * 权威快照 → {@code iam.identity.v1} 线视图的装配器（auth 域的投影层组件，无状态、不访问数据库）。
 *
 * <p>两个入口对应两个认证面：{@link #toIdentity} 服务人类会话（登录响应、{@code /me}、
 * 切企业后的回读，受众取会话自身的 login_audience）；
 * {@link #toIdentityForIntrospection} 服务内部端点的令牌内省，受众由调用方按客户端白名单声明。
 *
 * <p>职责边界：本类只做"读取、判空、按受众裁剪"，不产生任何授权决定——可用性判定
 * 已由 {@code iam_auth.load_authority_snapshot} 在 PG 内完成，端点级权限仍由各自服务裁决。
 * 装配出的视图是瞬时值，随每次请求重新计算，调用方不得据此做长期缓存放行。
 *
 * <p>I1 阶段裁剪口径（资源型权限尚未开通，开通在 I1a）：对外视图仅在
 * {@code iam-admin} 受众且企业上下文可用时给出全量权限码，其余受众为空列表；
 * 内省视图则按声明受众给出主体实时有效权限全集（非 {@code iam-admin} 受众剔除
 * {@code platform:*} 与 {@code entitlement:manage}），资源边界由授予层与机器身份加载层双重默认拒绝。
 *
 * @author Acerola
 */
@Component
public class IdentityAssembler {

    /** 身份视图结构版本，与 contracts 中的 schema 标识一致，写入每个响应的 {@code schema_version}。 */
    private static final String SCHEMA_VERSION = "iam.identity.v1";

    /**
     * 装配人类会话对外身份视图。
     *
     * <p>受众取快照中的 {@code session.login_audience}，因此同一令牌在任何端点返回的
     * 权限裁剪口径都稳定；企业上下文不可用时企业、成员关系为空，权限仅剩平台码（且仅
     * {@code iam-admin} 受众可见）。
     *
     * @param snapshot 已通过权威核验的 {@link AuthoritySnapshot}
     * @param issuer   配置 {@code iam.issuer} 的签发方标识
     * @return 实时的 {@link IdentityVO}
     */
    public IdentityVO toIdentity(AuthoritySnapshot snapshot, String issuer) {
        return build(snapshot, issuer, false, snapshot.loginAudience());
    }

    /**
     * 装配内部令牌内省用的身份视图。
     *
     * <p>受众交与主体授权的求交由调用方按客户端白名单裁决；此处返回主体的实时有效权限全集
     * （资源型权限在授予层与机器身份加载层双重默认拒绝）。非 {@code iam-admin} 声明受众下
     * 平台角色与 {@code platform:*}/{@code entitlement:manage} 权限码被剔除，
     * 使消费方无法从内省响应反推平台管理员身份。
     *
     * @param snapshot 已加载的权威快照
     * @param issuer   配置 {@code iam.issuer} 的签发方标识
     * @param audience 内省调用方声明的目标受众
     * @return 按声明受众裁剪的 {@link IdentityVO}
     */
    public IdentityVO toIdentityForIntrospection(AuthoritySnapshot snapshot, String issuer, String audience) {
        return build(snapshot, issuer, true, audience);
    }

    /**
     * 共用装配：读取快照各节点，判定企业上下文可用性，再按受众裁剪权限与平台角色。
     *
     * <p>企业上下文可用（{@code tenantUsable}）要求企业与成员关系节点都存在且状态均为
     * {@code active}；不满足时企业、成员关系与企业角色一律置空，避免把"归属仍在但已被停用"
     * 的上下文当作有效上下文暴露给消费方。{@code needsTenantSelection} 表示尚未选择企业
     * 但存在其它可用企业，供前端引导切换。
     *
     * @param snapshot              权威快照
     * @param issuer                签发方标识
     * @param internalIntrospection {@code true} 走内省裁剪口径，{@code false} 走人类会话对外口径
     * @param audience              本次视图的目标受众
     * @return 装配完成的身份视图（{@code active} 恒为 {@code true}，不可用时调用方已先行拒绝）
     */
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

    /**
     * 无可用企业上下文时的降级权限集：仅保留平台侧权限码。
     *
     * <p>非 {@code iam-admin} 受众一律返回空列表——应用侧不应看到平台管理码；
     * {@code iam-admin} 受众保留 {@code platform:} 前缀与 {@code entitlement:manage}，
     * 使平台管理页面在没有企业上下文时仍可进入（企业维度码已被剔除）。
     *
     * @param raw               权威快照根节点
     * @param iamAdminAudience  本次受众是否为 {@code iam-admin}
     * @return 裁剪后的权限码列表，可能为空
     */
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

    /**
     * 把快照中的角色数组映射为 {@code code + name} 视图。
     *
     * @param array {@code platform_roles} 或 {@code tenant_roles} 节点；缺失或非数组时按空处理
     * @return 新构造的角色列表，顺序与数据库 jsonb 聚合顺序一致；无角色时为空列表
     */
    private List<IdentityVO.Role> roles(JsonNode array) {
        List<IdentityVO.Role> result = new ArrayList<>();
        array.forEach(n -> result.add(new IdentityVO.Role(n.path("code").asText(),
                n.path("name").asText())));
        return result;
    }

    /**
     * 读取对象节点的字符串字段，把 jsonb 的 null/缺失统一折叠为 Java {@code null}。
     *
     * @param node   所属对象节点（由 {@code path} 得到，不会为 {@code null}）
     * @param field  字段名（数据库列名，snake_case）
     * @return 字段文本；缺失或为 null 时返回 {@code null}
     */
    private String text(JsonNode node, String field) {
        JsonNode value = node.path(field);
        return value.isNull() || value.isMissingNode() ? null : value.asText();
    }

    /**
     * 可空字段读取，语义与 {@link #text} 相同（当前仅 {@code department_id} 使用，
     * 保留独立方法以标明显式可空字段）。
     *
     * @param node  所属对象节点
     * @param field 字段名
     * @return 字段文本；缺失或为 null 时返回 {@code null}
     */
    private String nullableText(JsonNode node, String field) {
        return text(node, field);
    }
}
