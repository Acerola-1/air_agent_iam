package com.airagent.iam.admin.dto;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 角色局部更新请求体（DTO，PATCH 语义：{@code null} 组件保持原值）。
 *
 * <p>场景：改自定义角色的名称、说明或启停，由
 * {@link com.airagent.iam.admin.controller.RoleAdminController#updateRole} 接收
 * （{@code PATCH /v1/admin/roles/{id}}），交给
 * {@link com.airagent.iam.admin.service.RoleAdminService#updateRole}——授权面按角色自身的 scope
 * 判定（平台角色只认 {@code platform:role:write}，企业角色还要求属于会话当前企业）。
 *
 * <p>本载荷刻意不含 scope / code / tenant_id：域与归属不可迁移，权限集合走
 * {@link RolePermissionsDTO} 的独立接口；也不含修订基线，角色编辑没有乐观并发检查，
 * 冲突由数据库约束与触发器给出。请求体可缺省
 * （{@code @RequestBody(required = false)}），缺省返回 400；字段名按全局 SNAKE_CASE 解析。
 *
 * @param name        新显示名；{@code null} 表示不改
 * @param description 新说明；{@code null} 表示不改，空串表示清空
 * @param status      目标状态；{@code null} 表示不改；仅 active/disabled
 * @param expectedContext 资源写入时打开表单的会话上下文；非资源请求兼容省略
 * @param expectedTenantRevision 资源写入时目标企业授权修订；与操作者当前企业分别处理
 * @author Acerola
 */
@Schema(description = "角色局部更新请求。内置角色不可修改（403）；停用角色会推进所有引用主体的授权代次")
public record UpdateRoleDTO(

        @Schema(description = "新的角色显示名：非空白且不超过 128 字符，越界返回 400；"
                + "省略或 null 表示保持原名（SQL 层 COALESCE，无法借 null 清空）。",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED, example = "发布负责人")
        String name,

        @Schema(description = "新的角色说明：省略或 null 表示保持原值；传空串可以把说明清空"
                + "（列 NOT NULL，默认值即空串）。",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED, example = "仅发布流程相关权限")
        String description,

        @Schema(description = "目标状态，真实枚举仅 active / disabled（平台/企业没有第三种取值）。"
                + "省略或 null 表示不改；其他取值返回 400。状态实际变化时数据库触发器把引用该角色的"
                + "全部账号 auth_revision 与成员 revision +1，旧权限快照即刻失效。注意最后管理员保护"
                + "只覆盖账号状态与授权关系行、不覆盖角色状态，停用超级管理员所持有的角色不会被拦截，"
                + "可能自锁，需自行确认。",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED, example = "disabled")
        String status,
        @Schema(description = "资源写入时必填：打开表单时的会话上下文") ExpectedContextDTO expectedContext,
        @Schema(description = "资源写入时必填：目标企业授权修订") Long expectedTenantRevision
) {
    /** 兼容既有非资源调用；资源写入必须使用完整构造器提供上下文和企业修订。 */
    public UpdateRoleDTO(String name, String description, String status) {
        this(name, description, status, null, null);
    }

}
