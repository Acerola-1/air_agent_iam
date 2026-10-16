package com.airagent.iam.admin.dto;

/** HTTP 请求参数。 */
public record UpdateUserDTO(
        String displayName,
        String status,
        Long expectedRevision
) {
}
