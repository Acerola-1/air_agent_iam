package com.airagent.iam.admin.vo;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 权限目录项 HTTP 出参（VO，对外响应模型）。
 *
 * <p>来自 {@code iam.permissions} 的静态目录（含中文名与排序号），不是某账号"已具备的权限"。
 * 目录查询在服务端已过滤掉资源型权限，因此本视图的 {@code resourceType} 当前恒为 {@code null}，
 * 字段保留用于后续资源开通（I1a）。
 *
 * @param code         权限码，全库唯一，形如 {@code tenant:member:read}；提交为入参时须为
 *                     3..64 位小写字母、数字与 {@code : _ -}
 * @param name         权限中文名（后台界面展示用，对应 name_zh 列）
 * @param grantScope   权限归属域，仅 {@code platform} / {@code tenant}；企业口径主体查询时只会看到 tenant
 * @param resourceType 资源型权限的资源标识；非资源型权限为 {@code null}，当前目录查询全部为 {@code null}
 * @author Acerola
 */
@Schema(description = "权限目录项（静态目录，非主体已具备权限）")
public record PermissionVO(
        @Schema(description = "权限码，全库唯一，形如 tenant:member:read", requiredMode = Schema.RequiredMode.REQUIRED)
        String code,
        @Schema(description = "权限中文名", requiredMode = Schema.RequiredMode.REQUIRED)
        String name,
        @Schema(description = "权限归属域；企业口径主体只会收到 tenant 权限", requiredMode = Schema.RequiredMode.REQUIRED,
                allowableValues = {"platform", "tenant"})
        String grantScope,
        @Schema(description = "资源型权限的资源标识；当前目录不含资源型权限，恒为 null")
        String resourceType
) {
}
