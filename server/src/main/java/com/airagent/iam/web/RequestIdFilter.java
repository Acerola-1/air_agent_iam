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
 * 每请求 request_id：入站头优先（仅接受安全字符），响应头与 MDC/错误信封共用。
 */
@Component
@Order(1)
public class RequestIdFilter extends OncePerRequestFilter {

    public static final String STARTED_NANOS_ATTRIBUTE = "iam.requestStartedNanos";
    private static final String REQUEST_ID_ATTRIBUTE = "iam.requestId";

    @Override
    protected boolean shouldNotFilterAsyncDispatch() {
        return false;
    }

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
