package com.airagent.iam.admin.dto;

/** HTTP 请求参数。 */
public record CreateUserDTO(
        String account,
        String displayName,
        String password
) {
    @Override
    public String toString() {
        return "CreateUserDTO[sensitive fields redacted]";
    }
}
