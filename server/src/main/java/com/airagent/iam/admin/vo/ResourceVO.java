package com.airagent.iam.admin.vo;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;

/**
 * 资源目录项 HTTP 出参（VO）。
 *
 * @param id          资源 UUID
 * @param code        资源编码
 * @param nameZh      中文名
 * @param sort        排序号
 * @param status      active/disabled
 * @param kind        固定 leaf
 * @param parentCode  分组字符串，可空
 * @param revision    目录修订号
 * @param permissions 显式权限绑定列表
 */
@Schema(description = "资源目录项")
public record ResourceVO(
        @Schema(description = "资源 UUID", requiredMode = Schema.RequiredMode.REQUIRED)
        String id,
        @Schema(description = "资源编码", requiredMode = Schema.RequiredMode.REQUIRED)
        String code,
        @Schema(description = "中文名", requiredMode = Schema.RequiredMode.REQUIRED)
        String nameZh,
        @Schema(description = "排序号", requiredMode = Schema.RequiredMode.REQUIRED)
        Integer sort,
        @Schema(description = "状态", requiredMode = Schema.RequiredMode.REQUIRED, allowableValues = {"active", "disabled"})
        String status,
        @Schema(description = "类型", requiredMode = Schema.RequiredMode.REQUIRED)
        String kind,
        @Schema(description = "分组字符串，可空")
        String parentCode,
        @Schema(description = "目录修订号", requiredMode = Schema.RequiredMode.REQUIRED)
        Long revision,
        @Schema(description = "权限绑定", requiredMode = Schema.RequiredMode.REQUIRED)
        List<Bind> permissions
) {

    /**
     * 权限绑定项。
     *
     * @param code               权限码
     * @param nameZh             中文名
     * @param scope              固定 tenant
     * @param grantableToTenants 可下放企业
     * @param status             active/disabled
     * @param resourceCode       所属资源编码
     */
    @Schema(description = "资源权限绑定")
    public record Bind(
            @Schema(description = "权限码", requiredMode = Schema.RequiredMode.REQUIRED)
            String code,
            @Schema(description = "中文名", requiredMode = Schema.RequiredMode.REQUIRED)
            String nameZh,
            @Schema(description = "域", requiredMode = Schema.RequiredMode.REQUIRED)
            String scope,
            @Schema(description = "可下放企业", requiredMode = Schema.RequiredMode.REQUIRED)
            boolean grantableToTenants,
            @Schema(description = "状态", requiredMode = Schema.RequiredMode.REQUIRED)
            String status,
            @Schema(description = "所属资源编码", requiredMode = Schema.RequiredMode.REQUIRED)
            String resourceCode
    ) {
    }
}
