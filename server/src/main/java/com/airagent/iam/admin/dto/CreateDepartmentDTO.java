package com.airagent.iam.admin.dto;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 新建部门请求体（DTO，Controller → Service 的入参载体，不落库、不出参）。
 *
 * <p>场景：企业组织树建档，由
 * {@link com.airagent.iam.admin.controller.TenantAdminController#createDepartment} 接收
 * （{@code POST /v1/admin/departments} 与 {@code POST /web-api/admin/departments} 两条路径同能力），
 * 再交给 {@link com.airagent.iam.admin.service.TenantAdminService#createDepartment} 执行
 * {@code tenant:department:write} 裁决、事务与 PostgreSQL 请求上下文设置。
 *
 * <p>本类不带任何校验注解：字符集、长度、上级归属、权限与并发判定全在服务层与数据库约束
 * （部门 RLS、同租户复合外键、无环触发器、{@code (tenant_id, code)} 唯一键）中兜底。
 * 请求体整体可缺省（{@code @RequestBody(required = false)}），缺省时控制器的上下文守卫先抛出 400
 * （tenant_id 与 expected_ctx_version 必填），服务层的 code 校验是第二道。
 *
 * <p>JSON 字段名遵循全局 SNAKE_CASE 策略（code / name / parent_id / tenant_id / expected_ctx_version）；
 * 数值组件必须是 JSON 数字——全局关闭标量强转，字符串形式的数字会被拒绝。
 *
 * @param code               部门编码，1..64 位且首字符为字母或数字、其余限字母数字/_/-；同企业内唯一
 * @param name               部门名称，非空白且不超过 128 字符
 * @param parentId           上级部门 UUID 文本；{@code null} 或空白表示建为顶级部门
 * @param tenantId           表单声明的企业 UUID 文本，必填，仅用于与会话当前企业做一致性守卫
 * @param expectedCtxVersion 会话上下文版本基线，必填，语义见组件 {@code @Schema}
 * @author Acerola
 */
@Schema(description = "新建部门请求。部门只能建在会话当前企业内；tenant_id 与 expected_ctx_version "
        + "是必填的表单上下文守卫，任一缺失返回 400，与会话不一致返回 409（context_changed）")
public record CreateDepartmentDTO(

        @Schema(description = "部门编码：1..64 字符，首字符限字母/数字，其余限字母、数字、下划线、连字符"
                + "（正则 [A-Za-z0-9][A-Za-z0-9_-]{0,63}，服务层裁决）。同一企业内唯一，"
                + "重复触发数据库唯一键 → 409。入库后不可修改。",
                requiredMode = Schema.RequiredMode.REQUIRED, example = "rnd-sh")
        String code,

        @Schema(description = "部门显示名：非空白、长度 1..128 字符，服务层裁决；缺失或空白返回 400。",
                requiredMode = Schema.RequiredMode.REQUIRED, example = "研发中心")
        String name,

        @Schema(description = "上级部门 UUID，必须属于同一企业，否则 400（禁止跨租户挂靠，"
                + "数据库另有复合外键与无环触发器兜底）。null 或空白等价不传，表示建为顶级部门。",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED, example = "3f2b6a51-9a1e-4c7d-8b0f-2d5c7e9a1b40")
        String parentId,

        @Schema(description = "表单所属企业 UUID：必填（省略时 400）。仅作守卫——必须等于会话当前企业，"
                + "否则 409；实际写入的租户恒取会话 currentTenantId，不接受客户端自报目标企业。",
                requiredMode = Schema.RequiredMode.REQUIRED, example = "6c1d9f7b-4e2a-4f83-9d16-8ab0c2e5f7d1")
        String tenantId,

        @Schema(description = "乐观并发基线：客户端读取表单时的会话上下文版本，即会话表 ctx_version"
                + "（切换企业时 +1），不是部门行修订号——部门表没有修订列。必填（省略时 400）；"
                + "与会话当前值不一致说明表单已跨企业漂移，返回 409 要求刷新。JSON 数字，非字符串。",
                requiredMode = Schema.RequiredMode.REQUIRED, example = "3")
        Long expectedCtxVersion
) {

    /**
     * 仅携带业务字段的便捷构造器，把两个上下文守卫组件置空。
     *
     * <p>注意：部门写接口要求 {@code tenant_id} 与 {@code expected_ctx_version} 必填，
     * 用该构造器反序列化出的对象在控制器守卫处即返回 400，仅便于测试内构造半成品载荷。
     *
     * @param code     部门编码
     * @param name     部门显示名
     * @param parentId 上级部门 UUID 文本；{@code null} 表示顶级
     */
    public CreateDepartmentDTO(String code, String name, String parentId) {
        this(code, name, parentId, null, null);
    }
}
