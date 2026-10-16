package com.airagent.iam.web.error;

/**
 * 统一错误信封：{"error":{"code","message","request_id"}}。
 */
public record ErrorEnvelope(Error error) {

    public record Error(String code, String message, String requestId) {
    }

    public static ErrorEnvelope of(String code, String message, String requestId) {
        return new ErrorEnvelope(new Error(code, message, requestId));
    }
}
