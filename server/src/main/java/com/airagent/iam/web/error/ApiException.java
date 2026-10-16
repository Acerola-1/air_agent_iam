package com.airagent.iam.web.error;

/**
 * 业务/协议异常。消息面向调用方，禁止包含口令、令牌、密钥片段。
 */
public class ApiException extends RuntimeException {

    private final int status;
    private final String code;

    public ApiException(int status, String code, String message) {
        super(message);
        this.status = status;
        this.code = code;
    }

    public int status() {
        return status;
    }

    public String code() {
        return code;
    }

    public static ApiException badRequest(String message) {
        return new ApiException(400, "bad_request", message);
    }

    public static ApiException unauthenticated(String message) {
        return new ApiException(401, "unauthenticated", message);
    }

    public static ApiException forbidden(String message) {
        return new ApiException(403, "forbidden", message);
    }

    public static ApiException notFound(String message) {
        return new ApiException(404, "not_found", message);
    }

    public static ApiException contextChanged(String message) {
        return new ApiException(409, "context_changed", message);
    }

    public static ApiException conflict(String message) {
        return new ApiException(409, "conflict", message);
    }

    public static ApiException rateLimited(String message) {
        return new ApiException(429, "rate_limited", message);
    }

    public static ApiException dependencyUnavailable(String message) {
        return new ApiException(503, "dependency_unavailable", message);
    }
}
