package com.airagent.iam.web.error;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 统一错误信封：全局唯一失败响应形状
 * {@code {"error":{"code","message","request_id"}}}（Jackson SNAKE_CASE）。
 *
 * <p>request_id 与响应头 X-Request-Id（RequestIdFilter 生成）一致，供日志/审计
 * 关联。成功响应不使用本形状，两者互斥。
 *
 * @param error 内层错误对象
 * @author Acerola
 */
@Schema(description = "统一错误信封；任何非 2xx 的 JSON 响应都遵循本形状")
public record ErrorEnvelope(Error error) {

    /**
     * 信封内层。
     *
     * @param code      机器可读错误码（见 ApiException.code()）
     * @param message   面向调用方的中文说明；不含堆栈与秘密
     * @param requestId 本次请求追踪标识；过滤器未运行时可为 {@code null}
     */
    @Schema(description = "错误明细")
    public record Error(String code, String message, String requestId) {
    }

    /**
     * 构造信封。
     *
     * @param code      错误码
     * @param message   说明文本
     * @param requestId 请求追踪标识，可为 {@code null}
     * @return 新信封实例
     */
    public static ErrorEnvelope of(String code, String message, String requestId) {
        return new ErrorEnvelope(new Error(code, message, requestId));
    }
}
