package com.airagent.iam.admin.dto;

import java.util.List;

/** HTTP 请求参数。 */
public record CreateRoleDTO(
        String scope,
        String code,
        String name,
        String description,
        List<String> permissionCodes
) {
}
