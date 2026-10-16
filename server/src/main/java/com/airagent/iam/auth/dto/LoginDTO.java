package com.airagent.iam.auth.dto;

/** HTTP 请求参数。 */
public record LoginDTO(String account, String password, String realm, String audience) {
    @Override
    public String toString() {
        return "LoginDTO[sensitive fields redacted]";
    }
}
