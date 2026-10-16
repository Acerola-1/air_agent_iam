package com.airagent.iam.admin.dto;

/** HTTP 请求参数。 */
public record ResetPasswordDTO(
        String newPassword,
        Long expectedRevision
) {
    @Override
    public String toString() {
        return "ResetPasswordDTO[sensitive fields redacted]";
    }
}
