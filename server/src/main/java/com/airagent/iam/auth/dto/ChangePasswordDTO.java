package com.airagent.iam.auth.dto;

/** HTTP 请求参数。 */
public record ChangePasswordDTO(String oldPassword, String newPassword) {
    @Override
    public String toString() {
        return "ChangePasswordDTO[sensitive fields redacted]";
    }
}
