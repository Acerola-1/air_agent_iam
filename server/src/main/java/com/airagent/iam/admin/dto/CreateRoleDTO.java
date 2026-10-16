package com.airagent.iam.admin.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;

/**
 * 新建角色请求体（DTO，Controller → Service 入参）。
 *
 * <p>场景：平台或企业管理员创建自定义角色并可选地带上初始权限集合，由
 * {@link com.airagent.iam.admin.controller.RoleAdminController#createRole} 接收
 * （{@code POST /v1/admin/roles} 与 {@code /web-api} 同名路径），交给
 * {@link com.airagent.iam.admin.service.RoleAdminService#createRole} 依据 scope 分别裁决
 * {@code platform:role:write} 或 {@code tenant:role:write}。
 *
 * <p>scope 决定数据归属与授权面：{@code platform} 角色的 tenant_id 恒为空且只能落在平台上下文；
 * {@code tenant} 角色只能建在会话当前企业内（未选企业返回 400），两者都由 RLS 的 WITH CHECK
 * 与唯一索引共同约束。请求体可缺省（{@code @RequestBody(required = false)}），缺省返回 400。
 * 字段名按全局 SNAKE_CASE 解析（scope / code / name / description / permission_codes）。
 *
 * @param scope           角色域，仅 platform / tenant，决定所需权限与归属租户
 * @param code            角色码，3..64 位小写字母数字/_/-
 * @param name            角色显示名，非空白且不超过 128 字符
 * @param description     角色说明；{@code null} 入库为空串
 * @param permissionCodes 初始权限码集合；{@code null} 或空集合表示先建空角色
 * @author Acerola
 */
@Schema(description = "新建自定义角色请求。scope 必填且只能是 platform/tenant，分别对应平台与企业授权面；"
        + "本接口创建的角色 is_builtin 恒为 false，内置角色模板不可由 API 新建")
public record CreateRoleDTO(

        @Schema(description = "角色域，真实枚举仅 platform / tenant（缺省或其他取值返回 400）。"
                + "platform 需 platform:role:write（否则 403），入库 tenant_id 为空；"
                + "tenant 需 tenant:role:write（否则 403）且必须已选择企业上下文（否则 400），"
                + "角色归属该会话当前企业。",
                requiredMode = Schema.RequiredMode.REQUIRED, example = "tenant")
        String scope,

        @Schema(description = "角色码：3..64 字符，小写字母开头，其后限小写字母、数字、下划线、连字符"
                + "（正则 [a-z][a-z0-9_-]{2,63}，服务层裁决）。platform 域内全局唯一、"
                + "tenant 域内按企业唯一（部分唯一索引），冲突返回 409；创建后不可修改。",
                requiredMode = Schema.RequiredMode.REQUIRED, example = "tenant_release_manager")
        String code,

        @Schema(description = "角色显示名：非空白且不超过 128 字符，缺失或越界返回 400。",
                requiredMode = Schema.RequiredMode.REQUIRED, example = "发布管理员")
        String name,

        @Schema(description = "角色说明，可省略：null 入库为空串（列 NOT NULL DEFAULT 空串）；"
                + "本接口不限制其长度。",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED, example = "管理发布流程相关权限")
        String description,

        @Schema(description = "建角色时一并写入的初始权限码集合（可省略，等价空集合）。"
                + "未知码 400；含资源型权限或给 tenant 角色配平台专属权限 409；"
                + "授予操作者自身不持有的权限 403（平台超级管理员豁免此子集校验）。"
                + "与角色插入同事务，校验不通过则角色整体不创建。",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED)
        List<String> permissionCodes
) {
}
