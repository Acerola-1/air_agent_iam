package com.airagent.iam.admin.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;

/**
 * 登记新资源的请求体（DTO）。
 *
 * @param expectedContext 期望上下文
 * @param code            资源编码，冒号分段小写 ASCII，至少两段
 * @param nameZh          中文名 1–100 字
 * @param sort            排序号，32 位整数
 * @param parentCode      分组字符串，可空
 * @param permissions     权限绑定列表，至少一项
 */
@Schema(description = "登记资源请求")
public record CreateResourceDTO(
        @Schema(description = "期望上下文", requiredMode = Schema.RequiredMode.REQUIRED)
        ExpectedContextDTO expectedContext,
        @Schema(description = "资源编码，如 knowledge:lib:demo", requiredMode = Schema.RequiredMode.REQUIRED)
        String code,
        @Schema(description = "中文名", requiredMode = Schema.RequiredMode.REQUIRED)
        String nameZh,
        @Schema(description = "排序号")
        Integer sort,
        @Schema(description = "分组字符串，可空")
        String parentCode,
        @Schema(description = "权限绑定列表", requiredMode = Schema.RequiredMode.REQUIRED)
        List<PermissionBindDTO> permissions
) {

    /**
     * 权限绑定项。
     *
     * @param code               权限码，须以资源 code + ':' 为前缀
     * @param nameZh             中文名
     * @param grantableToTenants 是否可下放企业
     */
    @Schema(description = "资源权限绑定")
    public record PermissionBindDTO(
            @Schema(description = "权限码", requiredMode = Schema.RequiredMode.REQUIRED)
            String code,
            @Schema(description = "中文名", requiredMode = Schema.RequiredMode.REQUIRED)
            String nameZh,
            @Schema(description = "可下放企业", requiredMode = Schema.RequiredMode.REQUIRED)
            Boolean grantableToTenants
    ) {
    }
}
