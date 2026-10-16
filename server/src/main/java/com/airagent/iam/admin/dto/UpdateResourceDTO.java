package com.airagent.iam.admin.dto;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 修改资源的请求体（DTO）。code 与权限绑定创建后不可改。
 *
 * @param expectedContext  期望上下文
 * @param expectedRevision 期望目录修订号
 * @param nameZh           中文名，可选
 * @param sort             排序号，可选
 * @param status           active/disabled，可选
 */
@Schema(description = "修改资源请求")
public record UpdateResourceDTO(
        @Schema(description = "期望上下文", requiredMode = Schema.RequiredMode.REQUIRED)
        ExpectedContextDTO expectedContext,
        @Schema(description = "期望目录修订号", requiredMode = Schema.RequiredMode.REQUIRED)
        Long expectedRevision,
        @Schema(description = "中文名")
        String nameZh,
        @Schema(description = "排序号")
        Integer sort,
        @Schema(description = "状态", allowableValues = {"active", "disabled"})
        String status
) {
}
