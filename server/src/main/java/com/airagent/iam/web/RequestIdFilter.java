package com.airagent.iam.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.UUID;
import org.slf4j.MDC;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * 请求追踪过滤器：每请求生成/沿用 request_id（Web 层，@Order(1) 高优先级）。
 *
 * <p>入站 {@code X-Request-Id} 头仅接受安全字符集（1..64 位字母数字与 . _ -），
 * 不合规或缺失时服务端生成 UUID；最终值同时写入请求属性、响应头 X-Request-Id、
 * MDC（供日志与错误信封共享）与 {@link #STARTED_NANOS_ATTRIBUTE} 起始时刻
 * （IdentityDeadlineExecutor 以它为总预算基准）。所有响应附加
 * {@code Cache-Control: no-store}。
 *
 * @author Acerola
 */
@Component
@Order(1)
public class RequestIdFilter extends OncePerRequestFilter {

    /** 请求属性键：本请求进入过滤器的单调纳秒时刻，内部端点预算据此倒计。 */
    public static final String STARTED_NANOS_ATTRIBUTE = "iam.requestStartedNanos";
    /** 请求属性键：本次请求最终 request_id。 */
    private static final String REQUEST_ID_ATTRIBUTE = "iam.requestId";

    /**
     * 异步派发同样执行（DeferredResult 二阶段仍需要 MDC request_id 与预算属性）。
     *
     * @return 恒为 {@code false}（不排除异步派发）
     */
    @Override
    protected boolean shouldNotFilterAsyncDispatch() {
        return false;
    }

    /**
     * 解析/生成 request_id，布置响应头与 MDC，链式放行后清理 MDC。
     *
     * @param request     入站请求
     * @param response    出站响应（本方法设置 X-Request-Id 与 Cache-Control）
     * @param filterChain 下游链
     * @throws ServletException 下游抛出时透传
     * @throws IOException      下游 I/O 失败时透传
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        if (request.getAttribute(STARTED_NANOS_ATTRIBUTE) == null) {
            request.setAttribute(STARTED_NANOS_ATTRIBUTE, System.nanoTime());
        }
        String inbound = request.getHeader("X-Request-Id");
        String requestId = request.getAttribute(REQUEST_ID_ATTRIBUTE) instanceof String existing ? existing
                : inbound != null && inbound.matches("[A-Za-z0-9._-]{1,64}")
                ? inbound
                : UUID.randomUUID().toString();
        request.setAttribute(REQUEST_ID_ATTRIBUTE, requestId);
        MDC.put("request_id", requestId);
        response.setHeader("X-Request-Id", requestId);
        response.setHeader("Cache-Control", "no-store");
        try {
            filterChain.doFilter(request, response);
        } finally {
            MDC.remove("request_id");
        }
    }
}
