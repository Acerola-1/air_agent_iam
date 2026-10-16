package com.airagent.iam.auth.dto;

/** HTTP 请求参数。 */
public record SwitchTenantDTO(String tenantId, Long expectedCtxVersion) {
}
