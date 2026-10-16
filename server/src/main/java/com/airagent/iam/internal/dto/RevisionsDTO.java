package com.airagent.iam.internal.dto;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 四项权威修订基线（DTO，既作执行复查请求的 {@code expected_revisions}，也作响应体
 * {@code revisions} 的结构；内部与对外共用同一形状）。
 *
 * <p>数据来源：权威快照的 {@code revisions} 对象，即
 * {@code iam_auth.load_authority_snapshot}（V3 引入、V12 扩展）读取
 * {@code iam.users} / {@code iam.tenants} / {@code iam.tenant_memberships} /
 * {@code iam.auth_sessions} 的代次列所得。会话登记时保存三项基线
 * （{@code base_user_revision} / {@code base_tenant_revision} /
 * {@code base_membership_revision}），核验时由数据库比较：<b>当前值高于会话基线即判
 * {@code invalid_or_revoked}</b>，因此调用方持有的本结构只是"我看到的是哪一代"的证据，
 * 不产生任何放行效力。
 *
 * <p>推进来源（数据库触发器与函数，非应用代码自增）：
 * <ul>
 *   <li>用户授权代次——口令摘要变更、账号状态变更、平台角色授予/回收、角色权限集合或角色状态变更，
 *       以及会话撤销函数额外 +1；</li>
 *   <li>企业授权代次——企业 {@code status} 变更；无企业上下文时数据库以 {@code 0} 给出；</li>
 *   <li>成员关系代次——成员状态或所属部门变更、成员角色授予/回收、角色权限集合或角色状态变更；
 *       无成员关系时以 {@code 0} 给出；</li>
 *   <li>会话上下文代次——会话纪元，首次登录为 1，每次成功切换企业 +1，续期不改。</li>
 * </ul>
 *
 * <p>请求侧字段名按全局 SNAKE_CASE 解析（user_auth_revision / tenant_auth_revision /
 * membership_revision / session_ctx_version）。复查模式下四项均必填（任一为 {@code null}
 * 返回 400），且必须与引用登记值、当前实时值同时全等，否则复查判为不匹配。
 * 数值为 JSON 数字，全局配置禁止标量强转，字符串形式会被拒绝。
 *
 * @param userAuthRevision     用户授权代次（{@code iam.users.auth_revision}），单调递增，账号建档为 0
 * @param tenantAuthRevision   当前企业授权代次（{@code iam.tenants.auth_revision}），建档为 1；无企业上下文时数据库给 {@code 0}
 * @param membershipRevision   当前企业内成员关系代次（{@code iam.tenant_memberships.revision}），建档为 1；无成员关系时给 {@code 0}
 * @param sessionCtxVersion    会话上下文代次／会话纪元（{@code iam.auth_sessions.ctx_version}），起始 1，切企业时推进
 * @author Acerola
 */
@Schema(description = "四项权威修订：用户授权代次、企业授权代次、成员关系代次与会话上下文代次。"
        + "仅用于一致性比较，任何值本身都不构成授权")
public record RevisionsDTO(

        @Schema(description = "用户授权代次（iam.users.auth_revision，账号建档为 0）；"
                + "口令/账号状态/平台角色或角色权限变化即推进，高于会话基线时该会话核验为失效",
                requiredMode = Schema.RequiredMode.REQUIRED, example = "4")
        Long userAuthRevision,

        @Schema(description = "企业授权代次（iam.tenants.auth_revision，建档为 1）；企业状态变更时推进；"
                + "无企业上下文时快照以 0 给出",
                requiredMode = Schema.RequiredMode.REQUIRED, example = "5")
        Long tenantAuthRevision,

        @Schema(description = "成员关系代次（iam.tenant_memberships.revision，建档为 1）；"
                + "成员状态/部门/成员角色变化时推进；无成员关系时快照以 0 给出",
                requiredMode = Schema.RequiredMode.REQUIRED, example = "3")
        Long membershipRevision,

        @Schema(description = "会话上下文代次（会话纪元，iam.auth_sessions.ctx_version，起始 1）；成功切换企业 +1",
                requiredMode = Schema.RequiredMode.REQUIRED, example = "7")
        Long sessionCtxVersion
) {
}
