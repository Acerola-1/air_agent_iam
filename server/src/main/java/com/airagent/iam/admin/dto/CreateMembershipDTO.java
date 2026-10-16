package com.airagent.iam.admin.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;

/**
 * 企业成员新增请求体（DTO，Controller → Service 入参）。
 *
 * <p>场景：向企业添加成员，两种互斥形态——传 {@code userId} 关联既有平台账号，
 * 或传 {@code account + displayName + password} 当场新建 workforce 账号再入企业。
 * 由 {@link com.airagent.iam.admin.controller.TenantAdminController#createMembership} 接收
 * （{@code POST /v1/admin/members}），交给
 * {@link com.airagent.iam.admin.service.TenantAdminService#createMembership} 裁决
 * {@code tenant:member:write}。
 *
 * <p>刻意不返回账号凭据、也不接受任何“按同名自动合并”的隐式行为：同名账号已存在一律 409，
 * 必须显式给出 {@code userId}。用户表 RLS 的 WITH CHECK 只允许平台上下文插入，
 * 因此服务层在同事务内先在平台上下文建档/查重、再切回企业上下文写成员与角色。
 * 请求体可缺省（{@code @RequestBody(required = false)}），缺省返回 400；
 * 字段名按全局 SNAKE_CASE 解析（user_id / display_name / department_id / role_codes 等）。
 *
 * @param tenantId      目标企业 UUID 文本；仅作与会话当前企业的一致性守卫，不用于跨企业写入
 * @param userId        既有账号 UUID 文本，与 account 形态二选一
 * @param account       新建账号的登录账号（可打印 ASCII 3..64）
 * @param displayName   新建账号的显示名
 * @param password      新建账号的初始明文口令（8..256 字符，仅用于生成摘要）
 * @param departmentId  成员挂靠部门 UUID 文本；{@code null}/空白表示不挂靠
 * @param roleCodes     入企业即授予的企业角色码集合；{@code null} 或空集合表示不授角色
 * @param expectedContext 资源写入时打开表单的会话上下文；非资源请求兼容省略
 * @param expectedTenantRevision 资源写入时目标企业授权修订；与操作者当前企业分别处理
 * @author Acerola
 */
@Schema(description = "企业成员新增请求。关联既有账号传 user_id；新建账号传 account/display_name/password。"
        + "同名账号已存在一律 409，禁止按同名自动合并")
public record CreateMembershipDTO(

        @Schema(description = "目标企业 UUID：可省略（取会话当前企业）。若填写必须等于会话当前企业，"
                + "否则 403；未选择企业上下文则 400。真正写入的租户恒取会话 currentTenantId，"
                + "本字段不能把成员写到别的企业。",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED, example = "6c1d9f7b-4e2a-4f83-9d16-8ab0c2e5f7d1")
        String tenantId,

        @Schema(description = "要关联的既有平台账号 UUID（形态一）。需额外权限 platform:user:read（否则 403）；"
                + "账号不存在返回 400（明确禁止隐式建档）；已是本企业成员返回 409。"
                + "与 account 形态互斥，同时给出时以本字段为准。",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED, example = "0f1c2d3e-4b5a-4678-9abc-def012345678")
        String userId,

        @Schema(description = "新建账号的登录账号（形态二，未给 user_id 时必填）：可打印 ASCII 3..64 字符，"
                + "不含空格与控制字符。全库同 realm 唯一；若已有同名 workforce 账号则 409 并要求改传 user_id，"
                + "服务层绝不按同名合并。",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED, example = "eng-bob")
        String account,

        @Schema(description = "新建账号的显示名（形态二必填）：非空白且不超过 128 字符，否则 400。",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED, example = "研发 Bob")
        String displayName,

        @Schema(description = "新建账号的初始明文口令（形态二必填）：长度 8..256 字符，弱口令返回 400。"
                + "服务端只存 BCrypt 摘要，明文不落库、不入日志与审计；成功时会额外写一条"
                + " admin.user.create 审计（detail 不含口令）。",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED, example = "n4ursery-pony-2026")
        String password,

        @Schema(description = "成员挂靠的部门 UUID：必须属于同一企业，否则 400（数据库另有"
                + "同租户复合外键兜底）。null 或空白表示不挂靠，可随时通过成员更新接口调整。",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED, example = "3f2b6a51-9a1e-4c7d-8b0f-2d5c7e9a1b40")
        String departmentId,

        @Schema(description = "入企业时授予的角色码集合（只写 iam.membership_roles）：仅接受 scope=tenant "
                + "且 status=active 的内置模板或本租户自定义角色，出现平台角色/他租户/未知/停用一律 400。"
                + "任一角色的权限集合超出操作者自身权限快照即 403（此处无超级管理员豁免）。"
                + "授予角色额外要求 tenant:role:write。null 或空数组表示先建为无角色成员。",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED)
        List<String> roleCodes,
        @Schema(description = "资源写入时必填：打开表单时的会话上下文") ExpectedContextDTO expectedContext,
        @Schema(description = "资源写入时必填：目标企业授权修订") Long expectedTenantRevision
) {
    /** 兼容既有非资源调用；资源写入必须使用完整构造器提供上下文和企业修订。 */
    public CreateMembershipDTO(String tenantId, String userId, String account, String displayName, String password, String departmentId, List<String> roleCodes) {
        this(tenantId, userId, account, displayName, password, departmentId, roleCodes, null, null);
    }


    /**
     * 摘要化字符串，避免初始明文口令与账号信息经 {@code toString()} 进入日志或异常信息。
     *
     * @return 固定脱敏文本，不含任何组件值
     */
    @Override
    public String toString() {
        return "CreateMembershipDTO[sensitive fields redacted]";
    }
}
