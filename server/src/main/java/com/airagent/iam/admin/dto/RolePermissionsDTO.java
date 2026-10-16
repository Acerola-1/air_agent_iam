package com.airagent.iam.admin.dto;

import java.util.List;

/** HTTP 请求参数。 */
public record RolePermissionsDTO(
        List<String> permissionCodes
) {
}
