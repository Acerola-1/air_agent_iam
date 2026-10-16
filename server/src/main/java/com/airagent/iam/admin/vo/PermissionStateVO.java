package com.airagent.iam.admin.vo;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 角色权限状态项（VO），区分已配置与当前有效。
 *
 * @param code        权限码
 * @param configured  是否已在角色上配置
 * @param effective   当前是否有效（配置∩启用∩目录启用∩企业开通）
 * @param grantable   当前是否可新增
 * @param reason      失效原因，有效时为 null
 */
@Schema(description = "角色权限状态")
public record PermissionStateVO(
        @Schema(description = "权限码", requiredMode = Schema.RequiredMode.REQUIRED)
        String code,
        @Schema(description = "是否已配置", requiredMode = Schema.RequiredMode.REQUIRED)
        boolean configured,
        @Schema(description = "当前是否有效", requiredMode = Schema.RequiredMode.REQUIRED)
        boolean effective,
        @Schema(description = "当前是否可新增", requiredMode = Schema.RequiredMode.REQUIRED)
        boolean grantable,
        @Schema(description = "失效原因；有效时为 null")
        String reason
) {
}
