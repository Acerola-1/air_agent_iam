package com.airagent.iam.internal.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.UUID;

/**
 * Request for a live IAM tenant-status lookup by an authenticated internal client.
 *
 * @param tenantId IAM authoritative tenant UUID; required and never sourced from a consumer projection
 */
@Schema(description = "内部服务实时查询 IAM 权威企业是否可用；该查询不代表授权")
public record TenantStatusDTO(
        @Schema(description = "IAM 权威企业 UUID", requiredMode = Schema.RequiredMode.REQUIRED)
        UUID tenantId) {
}
