package com.airagent.iam.admin.vo;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;

/**
 * 企业成员 HTTP 出参（VO，对外响应模型）。
 *
 * <p>一条成员关系 = 一个账号在某企业内的身份，主键是关系 id 而非账号 id。
 * 账号信息（嵌套 {@link UserVO}）经 {@code iam_auth.member_user_brief} 受控读取，
 * 因此账号停用后其摘要依然可见——这正是改用该函数的原因（直读 users 会因 RLS 取不到行）。
 * 响应不含口令摘要。
 *
 * @param id            成员关系 UUID 文本（{@code iam.tenant_memberships} 主键，PATCH/DELETE 用它而非账号 id）
 * @param tenantId      所属企业 UUID 文本，恒等于会话当前企业上下文
 * @param user          账号摘要；其中 {@code platformRoles} 恒为空列表（成员视图不查询平台角色）
 * @param departmentId  部门归属 UUID 文本；{@code null} 表示未分配部门（成员可先入职后进部门）
 * @param status        成员关系状态，仅 {@code active} / {@code disabled}；停用后该账号在此企业内的
 *                      会话失效，但不影响账号本身与其他企业的成员关系
 * @param revision      成员代次（初始 1）。成员状态或部门变更、成员角色的每次授予与回收都会 +1；
 *                      该值高于会话记录的基线即判定会话授权过期，也是成员 PATCH/角色替换的
 *                      乐观并发基线（expected_revision）
 * @param roles         该成员在此企业内的角色码（按码升序，均为 tenant scope）；未授予时为空列表
 * @author Acerola
 */
@Schema(description = "企业成员视图（成员关系 + 账号摘要 + 企业角色）")
public record MemberVO(
        @Schema(description = "成员关系 UUID（不是账号 UUID）", format = "uuid", requiredMode = Schema.RequiredMode.REQUIRED)
        String id,
        @Schema(description = "所属企业 UUID", format = "uuid", requiredMode = Schema.RequiredMode.REQUIRED)
        String tenantId,
        @Schema(description = "账号摘要；platformRoles 在此视图中恒为空数组", requiredMode = Schema.RequiredMode.REQUIRED)
        UserVO user,
        @Schema(description = "部门 UUID；为 null 表示未分配部门", format = "uuid")
        String departmentId,
        @Schema(description = "成员关系状态；disabled 仅作用于本企业内的身份",
                requiredMode = Schema.RequiredMode.REQUIRED, allowableValues = {"active", "disabled"})
        String status,
        @Schema(description = "成员代次，状态/部门/角色变化都会使其递增；可作为 expected_revision 基线回传",
                requiredMode = Schema.RequiredMode.REQUIRED)
        long revision,
        @Schema(description = "该成员在本企业内的企业角色码（按码升序），可为空数组",
                requiredMode = Schema.RequiredMode.REQUIRED)
        List<String> roles
) {
}
