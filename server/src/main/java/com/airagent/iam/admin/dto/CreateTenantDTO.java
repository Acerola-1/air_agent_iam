package com.airagent.iam.admin.dto;

/** HTTP 请求参数。 */
public record CreateTenantDTO(
        String code,
        String name,
        String initialAdminUserId
) {
    public CreateTenantDTO(String code, String name) {
        this(code, name, null);
    }
}
