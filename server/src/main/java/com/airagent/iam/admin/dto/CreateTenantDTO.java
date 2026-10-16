package com.airagent.iam.admin.dto;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 企业建档请求体（DTO，Controller → Service 入参）。
 *
 * <p>场景：平台管理员创建新企业并指定首位管理员，由
 * {@link com.airagent.iam.admin.controller.TenantAdminController#createTenant} 接收
 * （{@code POST /v1/admin/tenants} 与 {@code /web-api} 同名路径），交给
 * {@link com.airagent.iam.admin.service.TenantAdminService#createTenant} 裁决
 * {@code platform:tenant:write} 并开启事务。
 *
 * <p>副作用（同事务，任一失败整体回滚）：插入企业行 → 为首位管理员建成员关系并授予内置
 * {@code tenant_admin} 模板角色 → 写两条审计（企业内 bootstrap 与平台线 create）。
 * 本类无校验注解，格式与存在性判定在服务层；请求体可缺省
 * （{@code @RequestBody(required = false)}），缺省返回 400。字段名按全局 SNAKE_CASE 解析。
 *
 * @param code               企业编码，2..64 位字母数字/_/-，全库唯一
 * @param name               企业显示名，非空白且不超过 128 字符
 * @param initialAdminUserId 首位管理员账号 UUID 文本；{@code null} 表示以操作者本人为首位管理员
 * @author Acerola
 */
@Schema(description = "企业建档请求。仅平台线权限 platform:tenant:write 可用；"
        + "建档会同步生成首位企业成员并授予内置 tenant_admin 角色")
public record CreateTenantDTO(

        @Schema(description = "企业编码：2..64 字符，首字符限字母/数字，其余限字母、数字、下划线、连字符"
                + "（正则 [A-Za-z0-9][A-Za-z0-9_-]{1,63}，服务层裁决）。全库唯一，"
                + "重复触发数据库唯一键返回 409；创建后不可修改。",
                requiredMode = Schema.RequiredMode.REQUIRED, example = "acme-cn")
        String code,

        @Schema(description = "企业显示名：非空白、1..128 字符，服务层裁决，缺失或越界返回 400。",
                requiredMode = Schema.RequiredMode.REQUIRED, example = "示例科技（北京）有限公司")
        String name,

        @Schema(description = "首位企业管理员的账号 UUID：省略时默认取操作者本人。指定他人时额外要求"
                + " platform:user:read（否则 403），且该账号必须存在、状态为 active（否则 400）；"
                + "不校验其是否已是其他企业成员——成员关系本就允许跨企业。",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED, example = "0f1c2d3e-4b5a-4678-9abc-def012345678")
        String initialAdminUserId
) {

    /**
     * 只指定编码与名称的便捷构造器，首位管理员默认取操作者本人。
     *
     * @param code 企业编码
     * @param name 企业显示名
     */
    public CreateTenantDTO(String code, String name) {
        this(code, name, null);
    }
}
