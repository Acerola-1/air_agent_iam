package com.airagent.iam.admin.dto;

/** HTTP 请求参数。 */
public record UpdateRoleDTO(
        String name,
        String description,
        String status
) {
}
