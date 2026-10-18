package com.airagent.iam.internal.vo;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * Versioned response for an internal service's live tenant-availability check.
 *
 * @param schemaVersion response contract version, currently {@code iam.tenant-status.v1}
 * @param tenantId      canonical IAM tenant UUID checked by the authority
 * @param active        whether that IAM tenant currently has active status; not an authorization grant
 */
@Schema(description = "IAM 权威企业实时状态；不授予任何企业或资源权限")
public record TenantStatusVO(
        @Schema(description = "响应契约版本", example = "iam.tenant-status.v1")
        String schemaVersion,
        @Schema(description = "已核验的 IAM 企业 UUID", example = "01931000-0000-4100-8100-000000001001")
        String tenantId,
        @Schema(description = "企业当前是否 active；不代表授权", example = "true")
        boolean active) {
}
