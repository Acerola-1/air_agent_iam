package com.airagent.iam.admin.dto;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 平台对企业开通/回收的请求体（DTO）。
 *
 * @param expectedContext        期望上下文（操作者身份，不是目标企业）
 * @param expectedRevision       期望开通记录修订号，首次创建为 0
 * @param expectedTenantRevision 期望目标企业 auth_revision
 * @param status                 active/revoked
 */
@Schema(description = "企业资源开通/回收请求")
public record UpdateEntitlementDTO(
        @Schema(description = "期望上下文（操作者身份）", requiredMode = Schema.RequiredMode.REQUIRED)
        ExpectedContextDTO expectedContext,
        @Schema(description = "期望开通记录修订号，首次为 0", requiredMode = Schema.RequiredMode.REQUIRED)
        Long expectedRevision,
        @Schema(description = "期望目标企业 auth_revision", requiredMode = Schema.RequiredMode.REQUIRED)
        Long expectedTenantRevision,
        @Schema(description = "目标状态", requiredMode = Schema.RequiredMode.REQUIRED,
                allowableValues = {"active", "revoked"})
        String status
) {
}
