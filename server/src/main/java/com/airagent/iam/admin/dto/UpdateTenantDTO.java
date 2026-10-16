package com.airagent.iam.admin.dto;

/** HTTP 请求参数。 */
public record UpdateTenantDTO(
        String name,
        String status,
        Long expectedRevision
) {
}
