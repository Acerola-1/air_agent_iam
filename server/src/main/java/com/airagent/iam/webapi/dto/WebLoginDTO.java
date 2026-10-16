package com.airagent.iam.webapi.dto;

/** HTTP 请求参数。 */
public record WebLoginDTO(String account, String password, String realm) {
    @Override
    public String toString() {
        return "WebLoginDTO[sensitive fields redacted]";
    }
}
