package com.airagent.iam.admin.dto;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 修改部门请求体（DTO，PATCH 语义：{@code null} 组件一律保持原值）。
 *
 * <p>场景：部门改名、改挂上级、启停，由
 * {@link com.airagent.iam.admin.controller.TenantAdminController#updateDepartment} 接收
 * （{@code PATCH /v1/admin/departments/{id}} 与 {@code /web-api} 同路径段），
 * 交给 {@link com.airagent.iam.admin.service.TenantAdminService#updateDepartment} 做
 * {@code tenant:department:write} 裁决、上下文设置与 SQL 更新。
 *
 * <p>并发模型：部门行没有修订列，写操作以会话上下文版本做守卫（组件
 * {@code tenantId} / {@code expectedCtxVersion}，控制器要求必填、缺失 400、不一致 409），
 * 真正的行级冲突由数据库唯一键与无环触发器给出 409。请求体可缺省（{@code @RequestBody(required = false)}），
 * 缺省时服务层返回 400。字段名按全局 SNAKE_CASE 输出/解析，数值组件不接受字符串形式。
 *
 * @param name               新部门名；{@code null} 表示不改
 * @param parentId           新上级部门 UUID 文本；{@code null} 表示不改（无法借本接口置为顶级）
 * @param status             目标状态；{@code null} 表示不改；仅 active/disabled
 * @param tenantId           表单声明的企业 UUID 文本，必填，仅用于上下文守卫
 * @param expectedCtxVersion 会话上下文版本基线，必填，见组件 {@code @Schema}
 * @author Acerola
 */
@Schema(description = "修改部门请求。省略字段保持原值（SQL 层 COALESCE）；parent_id 无法置空。"
        + "tenant_id 与 expected_ctx_version 为必填上下文守卫，与会话不一致返回 409（context_changed）")
public record UpdateDepartmentDTO(

        @Schema(description = "新的部门显示名：非空白且不超过 128 字符，越界返回 400；"
                + "省略或 null 表示保持原名（无法用本接口清空名称）。",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED, example = "研发一部")
        String name,

        @Schema(description = "新的上级部门 UUID：必须属于同一企业，否则 400；数据库另有复合外键与"
                + "reject_department_cycle 无环触发器兜底（成环 → 409）。省略/null 表示保持原上级——"
                + "注意 null 不等于“变为顶级”，本接口无法把部门降级为顶级。",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED, example = "3f2b6a51-9a1e-4c7d-8b0f-2d5c7e9a1b40")
        String parentId,

        @Schema(description = "目标状态，真实枚举仅 active / disabled（与企业的 active/suspended 不同）。"
                + "省略或 null 表示不改；其他取值返回 400。停用不会级联停用子部门或成员。",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED, example = "disabled")
        String status,

        @Schema(description = "表单所属企业 UUID：必填（省略时 400），必须等于会话当前企业，否则 409。"
                + "仅用于守卫，更新目标恒按会话 currentTenantId 限定（跨企业部门返回 404）。",
                requiredMode = Schema.RequiredMode.REQUIRED, example = "6c1d9f7b-4e2a-4f83-9d16-8ab0c2e5f7d1")
        String tenantId,

        @Schema(description = "乐观并发基线：会话表 ctx_version（切企业时 +1），不是部门行修订号。"
                + "必填（省略时 400）；与会话当前值不一致返回 409。JSON 数字，非字符串。",
                requiredMode = Schema.RequiredMode.REQUIRED, example = "3")
        Long expectedCtxVersion
) {

    /**
     * 仅携带业务字段的便捷构造器，把两个上下文守卫组件置空。
     *
     * <p>该形态缺少控制器要求的 {@code tenant_id} 与 {@code expected_ctx_version}，
     * 走真实 HTTP 入口会被拒绝（400），主要用于测试内构造局部更新载荷。
     *
     * @param name   新部门名；{@code null} 表示不改
     * @param parentId 新上级部门 UUID 文本；{@code null} 表示不改
     * @param status 目标状态；{@code null} 表示不改
     */
    public UpdateDepartmentDTO(String name, String parentId, String status) {
        this(name, parentId, status, null, null);
    }
}
