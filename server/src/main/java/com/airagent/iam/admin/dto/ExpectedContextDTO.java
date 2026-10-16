package com.airagent.iam.admin.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 新写接口的期望上下文（DTO），用于防止旧表单和迟到响应写入新上下文。
 *
 * @param sessionId  当前会话 UUID
 * @param tenantId   操作者当前企业 UUID，平台上下文为 null
 * @param ctxVersion 会话上下文版本，非负 JSON 整数
 */
@Schema(description = "期望上下文，与实时身份逐项比较")
public record ExpectedContextDTO(
        @Schema(description = "当前会话 UUID", requiredMode = Schema.RequiredMode.REQUIRED)
        String sessionId,
        @Schema(description = "操作者当前企业 UUID；平台上下文为 null")
        @JsonProperty(value = "tenant_id", required = true) String tenantId,
        @Schema(description = "会话上下文版本，非负整数", requiredMode = Schema.RequiredMode.REQUIRED)
        Long ctxVersion
) {
}
