package com.airagent.iam.admin.dto;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 企业信息局部更新请求体（DTO，PATCH 语义：{@code null} 组件保持原值）。
 *
 * <p>场景：平台侧修改企业显示名或停用/恢复，由
 * {@link com.airagent.iam.admin.controller.TenantAdminController#updateTenant} 接收
 * （{@code PATCH /v1/admin/tenants/{id}}），交给
 * {@link com.airagent.iam.admin.service.TenantAdminService#updateTenant} 做
 * {@code platform:tenant:write} 裁决、行锁与修订比对。
 *
 * <p>企业状态是租户级“熔断”开关：置为 {@code suspended} 后，会话权威核验会把落在该企业的
 * 会话判为不可用；同时数据库触发器把企业授权代次 +1，使携带旧基线的会话被拒。
 * 请求体可缺省（{@code @RequestBody(required = false)}），缺省返回 400；
 * 字段名按全局 SNAKE_CASE 解析，数值组件不接受字符串形式。
 *
 * @param name             新企业名；{@code null} 表示不改
 * @param status           目标状态；{@code null} 表示不改；仅 active/suspended
 * @param expectedRevision 乐观并发基线，语义见组件 {@code @Schema}
 * @author Acerola
 */
@Schema(description = "企业局部更新请求。name/status 均可省略（省略即不改）；"
        + "可携带 expected_revision 做乐观并发检查，不一致返回 409")
public record UpdateTenantDTO(

        @Schema(description = "新的企业显示名：非空白且不超过 128 字符，越界返回 400；"
                + "省略或 null 表示保持原名（SQL 层 COALESCE，无法借本接口清空）。"
                + "改名不推进授权代次。",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED, example = "示例科技集团")
        String name,

        @Schema(description = "目标状态，真实枚举仅 active / suspended（表 CHECK 不允许 disabled）。"
                + "省略或 null 表示不改；其他取值返回 400。状态实际变化时触发器把 auth_revision +1，"
                + "该企业下的活跃会话在下次权威核验即被判为租户停用。",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED, example = "suspended")
        String status,

        @Schema(description = "乐观并发基线：企业行当前的 auth_revision（建档时即为 1，仅在状态变化时 +1，"
                + "改名不推进）。省略表示不做并发检查；提交时必须与加锁后读到的当前值一致，否则 409。"
                + "JSON 数字，非字符串。",
                requiredMode = Schema.RequiredMode.NOT_REQUIRED, example = "2")
        Long expectedRevision
) {
}
