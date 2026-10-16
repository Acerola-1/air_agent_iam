package com.airagent.iam.auth.vo;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 单个可切换企业的概览视图（VO，{@code GET /v1/auth/tenants} 的元素，由
 * {@link com.airagent.iam.auth.mapper.SessionMapper#selectTenants} 直接映射）。
 *
 * <p>数据来源为 {@code iam.tenants} 联 {@code iam.tenant_memberships}，SQL 已过滤
 * "成员关系 active 且企业 active"，并按企业 code 升序返回；表为 FORCE RLS，
 * 调用前必须在同一事务内把请求上下文设为该用户自身（见
 * {@code SessionServiceImpl#tenants}）。因此本视图只包含"当前可切入"的企业，
 * 不含停用企业或被禁用的成员关系。
 *
 * @param tenantId     企业 UUID 文本，切企业端点的 {@code tenant_id} 取该值
 * @param code         企业编码（列表排序键）
 * @param name         企业显示名
 * @param status       企业状态，本视图恒为 {@code active}（SQL 已过滤）
 * @param memberStatus 该用户在企业内的成员关系状态，本视图恒为 {@code active}（SQL 已过滤）
 * @param isOwner      字段名为历史遗留：SQL 实际判定的是"该成员关系是否持有活跃的
 *                     {@code tenant_admin} 企业角色"，与企业主（owner）身份无关
 * @author Acerola
 */
@Schema(name = "TenantMembershipVO", description = "当前用户可切入的企业概览（仅活跃企业与活跃成员关系）")
public record TenantMembershipVO(

        @Schema(description = "企业 UUID 文本，作为 switch-tenant 的目标",
                example = "01940000-0000-4000-8000-0000000000a1")
        String tenantId,

        @Schema(description = "企业编码，列表按其升序", example = "fictional-corp")
        String code,

        @Schema(description = "企业显示名", example = "虚构科技有限公司")
        String name,

        @Schema(description = "企业状态，本视图恒为 active", example = "active")
        String status,

        @Schema(description = "成员关系状态，本视图恒为 active", example = "active")
        String memberStatus,

        @Schema(description = "是否持有活跃的 tenant_admin 企业角色（字段名为历史遗留，非企业主判定）")
        boolean isOwner
) {
}
