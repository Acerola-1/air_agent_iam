package com.airagent.iam.admin.vo;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 企业资源开通状态 HTTP 出参（VO）。
 *
 * <p>effective 仅表示资源在该企业可授，不等于当前用户有读取权限。
 *
 * @param tenantId           目标企业 UUID
 * @param resourceCode       资源编码
 * @param status             active/revoked
 * @param revision           开通记录修订号，无记录为 0
 * @param exists             是否存在开通记录
 * @param resourceStatus     目录状态
 * @param effective          是否有效可授
 * @param grantedAt          开通时间，可空
 * @param revokedAt          回收时间，可空
 * @param updatedAt          更新时间，可空
 * @param updatedBy          操作者，可空
 * @param tenantAuthRevision 目标企业 auth_revision
 */
@Schema(description = "企业资源开通状态")
public record EntitlementVO(
        @Schema(description = "目标企业 UUID", requiredMode = Schema.RequiredMode.REQUIRED)
        String tenantId,
        @Schema(description = "资源编码", requiredMode = Schema.RequiredMode.REQUIRED)
        String resourceCode,
        @Schema(description = "状态", requiredMode = Schema.RequiredMode.REQUIRED, allowableValues = {"active", "revoked"})
        String status,
        @Schema(description = "开通记录修订号，无记录为 0", requiredMode = Schema.RequiredMode.REQUIRED)
        Long revision,
        @Schema(description = "是否存在开通记录", requiredMode = Schema.RequiredMode.REQUIRED)
        boolean exists,
        @Schema(description = "目录状态", requiredMode = Schema.RequiredMode.REQUIRED)
        String resourceStatus,
        @Schema(description = "是否有效可授", requiredMode = Schema.RequiredMode.REQUIRED)
        boolean effective,
        @Schema(description = "开通时间")
        String grantedAt,
        @Schema(description = "回收时间")
        String revokedAt,
        @Schema(description = "更新时间")
        String updatedAt,
        @Schema(description = "操作者 UUID")
        String updatedBy,
        @Schema(description = "目标企业 auth_revision", requiredMode = Schema.RequiredMode.REQUIRED)
        Long tenantAuthRevision,
        @Schema(description = "本次是否实际改变开通状态") boolean changed
) {
}
