package com.airagent.iam.web.error;

/**
 * 业务/协议异常（Web 层错误载体）。
 *
 * <p>携带 HTTP 状态码与机器可读 code，消息面向调用方——禁止包含口令、令牌、
 * 密钥片段；由 GlobalExceptionHandler 统一转 {@link ErrorEnvelope}。
 * 服务层以静态工厂构造，避免在各处手写状态码。
 *
 * @author Acerola
 */
public class ApiException extends RuntimeException {

    /** HTTP 响应状态码。 */
    private final int status;
    /** 错误信封中的机器可读码。 */
    private final String code;

    /**
     * 构造异常。
     *
     * @param status  HTTP 状态码（本项目实际使用 400/401/403/404/409/429/500/503）
     * @param code    机器可读码，如 {@code bad_request}
     * @param message 面向调用方的中文说明，不得含秘密
     */
    public ApiException(int status, String code, String message) {
        super(message);
        this.status = status;
        this.code = code;
    }

    /**
     * 返回 HTTP 状态码。
     *
     * @return 构造时传入的状态码
     */
    public int status() {
        return status;
    }

    /**
     * 返回机器可读错误码。
     *
     * @return 错误信封 {@code error.code} 取值
     */
    public String code() {
        return code;
    }

    /**
     * 请求参数/请求体不合法。
     *
     * @param message 调用方说明
     * @return 400 {@code bad_request}
     */
    public static ApiException badRequest(String message) {
        return new ApiException(400, "bad_request", message);
    }

    /**
     * 未认证或会话失效。
     *
     * @param message 调用方说明
     * @return 401 {@code unauthenticated}
     */
    public static ApiException unauthenticated(String message) {
        return new ApiException(401, "unauthenticated", message);
    }

    /**
     * 已认证但权限、受众或授予范围不足。
     *
     * @param message 调用方说明
     * @return 403 {@code forbidden}
     */
    public static ApiException forbidden(String message) {
        return new ApiException(403, "forbidden", message);
    }

    /**
     * 资源不存在或 RLS 下不可见（两者不区分）。
     *
     * @param message 调用方说明
     * @return 404 {@code not_found}
     */
    public static ApiException notFound(String message) {
        return new ApiException(404, "not_found", message);
    }

    /**
     * 会话企业上下文纪元已变化，客户端应刷新。
     *
     * @param message 调用方说明
     * @return 409 {@code context_changed}
     */
    public static ApiException contextChanged(String message) {
        return new ApiException(409, "context_changed", message);
    }

    /**
     * 乐观修订冲突、唯一约束或业务触发器拒绝。
     *
     * @param message 调用方说明
     * @return 409 {@code conflict}
     */
    public static ApiException conflict(String message) {
        return new ApiException(409, "conflict", message);
    }

    /**
     * 固定窗口限流命中。
     *
     * @param message 调用方说明
     * @return 429 {@code rate_limited}
     */
    public static ApiException rateLimited(String message) {
        return new ApiException(429, "rate_limited", message);
    }

    /**
     * PG/Redis 故障或语句超时，失败关闭。
     *
     * @param message 调用方说明
     * @return 503 {@code dependency_unavailable}
     */
    public static ApiException dependencyUnavailable(String message) {
        return new ApiException(503, "dependency_unavailable", message);
    }
}
