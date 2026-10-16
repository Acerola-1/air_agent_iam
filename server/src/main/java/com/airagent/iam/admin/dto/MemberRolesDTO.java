package com.airagent.iam.admin.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;

/**
 * 企业成员角色全量替换请求体（DTO，Controller → Service 入参）。
 *
 * <p>场景：调整某成员在本企业内的角色集合，由
 * {@link com.airagent.iam.admin.controller.TenantAdminController#replaceMemberRoles} 接收
 * （{@code POST /v1/admin/members/{id}/roles}），交给
 * {@link com.airagent.iam.admin.service.TenantAdminService#replaceMemberRoles} 裁决
 * {@code tenant:role:write}。目标成员与写入租户恒取会话当前企业，载荷不能指定租户。
 *
 * <p>与平台角色替换分属两套授权：本接口写 iam.membership_roles，只接受 {@code scope = tenant}
 * 的角色（内置全局模板或本租户自定义）。请求体可缺省
 * （{@code @RequestBody(required = false)}），缺省即空集合 = 清空该成员在本企业的全部角色。
 * 字段名按全局 SNAKE_CASE 解析，数值组件不接受字符串形式。
 *
 * @param roleCodes        目标企业角色码集合；{@code null} 或空集合表示清空
 * @param expectedRevision 乐观并发基线（成员行 revision）；{@code null} 表示不检查
 * @param expectedContext 资源写入时打开表单的会话上下文；非资源请求兼容省略
 * @param expectedTenantRevision 资源写入时目标企业授权修订；与操作者当前企业分别处理
 * @author Acerola
 */
@Schema(description = "企业成员角色全量替换请求。仅接受企业域角色；未知/停用/平台专属/他企业角色返回 400；"
        + "越出操作者自身权限集合返回 403；替换后成员代次 +1")
public record MemberRolesDTO(

        @Schema(description = "目标企业角色码集合（全量替换，非增量）。码形状限 3..64 字符、小写字母开头、"
                + "可含小写字母/数字/:/_/-。只允许 scope=tenant 且 status=active 的内置模板"
                + "（如 tenant_admin、tenant_reader）或本租户自定义角色；平台角色、他租户角色、"
                + "停用或未知角色一律 400。null 或空数组表示清空该成员在本企业的全部角色。",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED)
        List<String> roleCodes,

        @Schema(description = "乐观并发基线：成员行当前的 revision（成员状态/部门变更、角色增删、"
                + "以及所关联角色的权限或状态变化都会使其 +1）。省略表示不做并发检查；"
                + "与服务层加锁后读到的当前值不一致返回 409。JSON 数字，非字符串。",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED, example = "2")
        Long expectedRevision,
        @Schema(description = "资源写入时必填：打开表单时的会话上下文") ExpectedContextDTO expectedContext,
        @Schema(description = "资源写入时必填：目标企业授权修订") Long expectedTenantRevision
) {
    /** 兼容既有非资源调用；资源写入必须使用完整构造器提供上下文和企业修订。 */
    public MemberRolesDTO(List<String> roleCodes, Long expectedRevision) {
        this(roleCodes, expectedRevision, null, null);
    }

}
