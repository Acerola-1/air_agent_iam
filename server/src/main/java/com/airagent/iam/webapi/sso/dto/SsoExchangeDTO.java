package com.airagent.iam.webapi.sso.dto;

/** HTTP 请求参数。 */
public record SsoExchangeDTO(String ticket, String redirectUri, String state) {
    @Override
    public String toString() {
        return "SsoExchangeDTO[sensitive fields redacted]";
    }
}
