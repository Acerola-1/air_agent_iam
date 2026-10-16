package com.airagent.iam.auth.vo;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;

/**
 * iam.identity.v1 安全身份视图（VO，{@code /v1/auth/me}、登录与 SSO 兑换响应体的核心结构）。
 *
 * <p>分层位置：由 {@link com.airagent.iam.auth.IdentityAssembler} 从
 * {@link com.airagent.iam.auth.AuthoritySnapshot} 装配，是 PG 权威快照对外可见的投影，
 * 本层不参与任何判定。字段命名由全局 SNAKE_CASE 策略输出，与
 * contracts/schemas/identity.schema.json 对齐。
 *
 * <p>关键语义：本视图只在权威核验通过后产生，因此 {@code active} 恒为 {@code true}；
 * 会话失效/授权代次变旧/账号停用等情形由服务层直接抛 401/403，不会退化成
 * {@code active = false} 的 200 响应。企业上下文不可用时 {@code current_tenant}
 * 与 {@code membership} 为 {@code null}，同时 {@code context_usable} 为 {@code false}。
 *
 * <p>时间字段（session 内各项与 {@code evaluatedAt}）为 ISO-8601 带偏移文本：
 * 快照内的时间戳原样透传（数据库 timestamptz 序列化结果），{@code evaluatedAt}
 * 为服务端评估时刻的 UTC 文本。
 *
 * <p>权限裁剪（I1 阶段资源型权限未开通）：非 {@code iam-admin} 受众的对外视图不返回业务权限码，
 * 仅 {@code iam-admin} 且企业上下文可用时返回全量权限码；详见
 * {@link com.airagent.iam.auth.IdentityAssembler#toIdentity}。
 *
 * @param schemaVersion        结构版本标识，固定 {@code iam.identity.v1}
 * @param active               主体身份是否有效；本视图仅在核验通过后装配，故恒为 {@code true}
 * @param issuer               身份签发方标识（配置 {@code iam.issuer}，默认 {@code air-agent-iam}），不是可校验的 URL
 * @param audience             本次身份的目标受众：对外取会话登录受众，内部 introspection 取调用方声明的受众
 * @param principal            主体三元组（类型/id/域）
 * @param user                 账号基础信息（不含任何口令或摘要）
 * @param session              会话标识、纪元与三类截止时间
 * @param currentTenant        当前企业；未选择企业或企业/成员关系不可用时为 {@code null}
 * @param membership           当前企业内的成员关系；与 {@code currentTenant} 同时为 {@code null}
 * @param platformRoles        活跃平台角色列表；内部 introspection 的非 {@code iam-admin} 受众下清空
 * @param tenantRoles          当前企业的活跃企业角色列表；企业上下文不可用时为空列表
 * @param permissions          按受众裁剪后的有效权限码集合，可能为空列表
 * @param revisions            四项权威代次，用于调用方判断本地缓存是否过期
 * @param contextVersion       会话上下文代次（会话纪元），与 {@code session.ctxVersion} 同值；
 *                             续期与切企业的 CAS 基线
 * @param platformAdmin        是否持有 {@code platform_super_admin} 平台角色
 * @param contextUsable        企业上下文是否可用（企业与成员关系均存在且均为 {@code active}）
 * @param needsTenantSelection 尚未选择当前企业但存在至少一个可用企业成员关系，前端应引导选择企业
 * @param evaluatedAt          服务端装配本视图的时刻（UTC ISO-8601 文本）
 * @author Acerola
 */
@Schema(name = "IdentityVO", description = "iam.identity.v1 实时身份：主体、会话纪元、当前企业上下文与按受众裁剪的权限码。"
        + "仅在权威核验通过后返回，故 active 恒为 true；核验失败以 401/403 表达")
public record IdentityVO(

        @Schema(description = "结构版本，固定 iam.identity.v1", example = "iam.identity.v1")
        String schemaVersion,

        @Schema(description = "身份是否有效；本视图只在权威核验通过后装配，恒为 true")
        boolean active,

        @Schema(description = "签发方标识（iam.issuer）", example = "air-agent-iam")
        String issuer,

        @Schema(description = "受众：air-agent / knowledge / iam-admin，决定权限码裁剪口径",
                example = "iam-admin")
        String audience,

        @Schema(description = "主体标识三元组")
        Principal principal,

        @Schema(description = "账号基础信息，不含口令与摘要")
        User user,

        @Schema(description = "会话标识、纪元与截止时间")
        Session session,

        @Schema(description = "当前企业；未选企业或企业/成员关系不可用时为 null")
        Tenant currentTenant,

        @Schema(description = "当前企业内的成员关系；与 current_tenant 同时为 null")
        Membership membership,

        @Schema(description = "活跃平台角色；内部 introspection 的非 iam-admin 受众下为空")
        List<Role> platformRoles,

        @Schema(description = "当前企业的活跃企业角色；企业上下文不可用时为空")
        List<Role> tenantRoles,

        @Schema(description = "按受众裁剪后的有效权限码；非 iam-admin 受众的对外视图为空")
        List<String> permissions,

        @Schema(description = "权威代次快照，用于调用方判断本地缓存是否过期")
        Revisions revisions,

        @Schema(description = "会话上下文代次（纪元），续期与切企业的 CAS 基线", example = "3")
        long contextVersion,

        @Schema(description = "是否持有 platform_super_admin 角色")
        boolean platformAdmin,

        @Schema(description = "企业上下文是否可用（企业与成员关系均 active）")
        boolean contextUsable,

        @Schema(description = "未选企业但存在可用企业，前端应引导选择")
        boolean needsTenantSelection,

        @Schema(description = "服务端评估时刻，UTC ISO-8601 文本",
                example = "2026-10-16T03:20:00Z")
        String evaluatedAt
) {

    /**
     * 主体标识（身份视图嵌套记录）。
     *
     * @param type  主体类型，人类会话固定 {@code human}
     * @param id    主体用户 id 文本
     * @param realm 主体域，装配时固定 {@code workforce}
     */
    @Schema(name = "IdentityPrincipal", description = "主体标识：类型、id 与账号域")
    public record Principal(

            @Schema(description = "主体类型，人类会话恒为 human", example = "human")
            String type,

            @Schema(description = "主体用户 UUID 文本", example = "01940000-0000-4000-8000-000000000001")
            String id,

            @Schema(description = "账号域，人类会话固定 workforce", example = "workforce")
            String realm) {
    }

    /**
     * 账号基础信息（身份视图嵌套记录），刻意不含口令相关列。
     *
     * @param id          用户 UUID 文本
     * @param account     登录账号
     * @param displayName 显示名
     * @param status      账号状态，仅 {@code active} / {@code disabled}；能出现本视图说明为 {@code active}
     */
    @Schema(name = "IdentityUser", description = "账号基础信息，不含口令摘要")
    public record User(

            @Schema(description = "用户 UUID 文本", example = "01940000-0000-4000-8000-000000000001")
            String id,

            @Schema(description = "登录账号", example = "zhang.acerola")
            String account,

            @Schema(description = "显示名", example = "张三")
            String displayName,

            @Schema(description = "账号状态 active/disabled", example = "active")
            String status) {
    }

    /**
     * 会话标识与时限（身份视图嵌套记录），时间均为数据库产生的 ISO-8601 文本原样透传。
     *
     * @param id                会话 UUID 文本
     * @param ctxVersion        会话上下文代次（纪元），与顶层 {@code contextVersion} 同值
     * @param createdAt         会话创建时刻
     * @param expiresAt         当前生效的到期时刻，等于空闲到期时刻（权威核验按它判定过期）
     * @param absoluteExpiresAt 绝对到期时刻，续期不会改变
     * @param idleExpiresAt     空闲到期时刻，续期只推进它且被绝对上限夹住
     */
    @Schema(name = "IdentitySession", description = "会话纪元与三类截止时间（ISO-8601 文本）")
    public record Session(

            @Schema(description = "会话 UUID 文本", example = "01940000-0000-4000-8000-0000000000c1")
            String id,

            @Schema(description = "会话上下文代次（纪元）", example = "3")
            long ctxVersion,

            @Schema(description = "创建时刻，ISO-8601 文本", example = "2026-10-09T02:00:00.123456+00:00")
            String createdAt,

            @Schema(description = "当前到期时刻，与 idle_expires_at 同值", example = "2026-10-16T02:00:00.123456+00:00")
            String expiresAt,

            @Schema(description = "绝对到期时刻，续期不改变", example = "2026-11-08T02:00:00.123456+00:00")
            String absoluteExpiresAt,

            @Schema(description = "空闲到期时刻", example = "2026-10-16T02:00:00.123456+00:00")
            String idleExpiresAt) {
    }

    /**
     * 当前企业（身份视图嵌套记录）。
     *
     * @param id     企业 UUID 文本
     * @param code   企业编码
     * @param name   企业显示名
     * @param status 企业状态，仅 {@code active} / {@code suspended}；出现本对象说明为 {@code active}
     */
    @Schema(name = "IdentityTenant", description = "会话当前所选企业")
    public record Tenant(

            @Schema(description = "企业 UUID 文本", example = "01940000-0000-4000-8000-0000000000a1")
            String id,

            @Schema(description = "企业编码", example = "fictional-corp")
            String code,

            @Schema(description = "企业显示名", example = "虚构科技有限公司")
            String name,

            @Schema(description = "企业状态 active/suspended", example = "active")
            String status) {
    }

    /**
     * 当前企业内的成员关系（身份视图嵌套记录）。
     *
     * @param id            成员关系 UUID 文本
     * @param tenantId      所属企业 UUID 文本，与 {@code currentTenant.id} 一致
     * @param departmentId  所属部门 UUID 文本；{@code null} 表示未挂部门
     * @param status        成员关系状态，仅 {@code active} / {@code disabled}
     * @param revision      成员代次；成员状态/部门变更或企业角色增删都会推进它，
     *                      与 {@code revisions.membershipRevision} 对应
     */
    @Schema(name = "IdentityMembership", description = "当前企业内的成员关系与部门归属")
    public record Membership(

            @Schema(description = "成员关系 UUID 文本", example = "01940000-0000-4000-8000-0000000000b1")
            String id,

            @Schema(description = "所属企业 UUID 文本", example = "01940000-0000-4000-8000-0000000000a1")
            String tenantId,

            @Schema(description = "所属部门 UUID 文本；未挂部门为 null", nullable = true,
                    example = "01940000-0000-4000-8000-0000000000d1")
            String departmentId,

            @Schema(description = "成员关系状态 active/disabled", example = "active")
            String status,

            @Schema(description = "成员代次", example = "1")
            long revision) {
    }

    /**
     * 角色码与显示名（身份视图嵌套记录）。
     *
     * @param code 角色码，如 {@code platform_super_admin} / {@code tenant_admin}
     * @param name 角色显示名
     */
    @Schema(name = "IdentityRole", description = "角色码与名称")
    public record Role(

            @Schema(description = "角色码", example = "platform_super_admin")
            String code,

            @Schema(description = "角色显示名", example = "平台超级管理员")
            String name) {
    }

    /**
     * 权威代次快照（身份视图嵌套记录），全部为数据库实时值。
     *
     * @param userAuthRevision   用户授权代次（iam.users.auth_revision）；口令或状态变更、
     *                           撤销会话、平台角色与角色权限变化都会推进它
     * @param tenantAuthRevision 企业授权代次（iam.tenants.auth_revision）；无当前企业时为 0
     * @param membershipRevision 成员代次（iam.tenant_memberships.revision）；无成员关系时为 0
     * @param sessionCtxVersion  会话上下文代次（auth_sessions.ctx_version）
     */
    @Schema(name = "IdentityRevisions", description = "四项权威代次；与会话基线不一致即代表旧快照已失效")
    public record Revisions(

            @Schema(description = "用户授权代次", example = "4")
            long userAuthRevision,

            @Schema(description = "企业授权代次，无当前企业时为 0", example = "1")
            long tenantAuthRevision,

            @Schema(description = "成员代次，无成员关系时为 0", example = "2")
            long membershipRevision,

            @Schema(description = "会话上下文代次", example = "3")
            long sessionCtxVersion) {
    }
}
