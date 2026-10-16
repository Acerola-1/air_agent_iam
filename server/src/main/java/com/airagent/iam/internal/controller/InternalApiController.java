package com.airagent.iam.internal.controller;

import com.airagent.iam.internal.dto.IntrospectDTO;
import com.airagent.iam.internal.dto.RuntimeTicketDTO;
import com.airagent.iam.internal.service.IntrospectionService;
import com.airagent.iam.internal.service.RuntimeTicketService;
import com.airagent.iam.internal.vo.RuntimeTicketVO;
import com.airagent.iam.security.internal.InternalClientInterceptor;
import com.airagent.iam.web.RequestIdFilter;
import com.airagent.iam.web.async.IdentityDeadlineExecutor;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.async.DeferredResult;

/**
 * 内部端点：Basic 客户端凭据认证由 {@link InternalClientInterceptor} 统一处理；
 * 不接受人类 Bearer 会话，路径与 /v1/auth、/v1/admin 互斥。
 */
@RestController
@RequestMapping("/v1/internal")
public class InternalApiController {

    private final IntrospectionService introspectionService;
    private final RuntimeTicketService runtimeTicketService;
    private final InternalClientInterceptor clientAuthorization;
    private final IdentityDeadlineExecutor deadlineExecutor;

    public InternalApiController(IntrospectionService introspectionService,
                                 RuntimeTicketService runtimeTicketService,
                                 InternalClientInterceptor clientAuthorization, IdentityDeadlineExecutor deadlineExecutor) {
        this.introspectionService = introspectionService;
        this.runtimeTicketService = runtimeTicketService;
        this.clientAuthorization = clientAuthorization;
        this.deadlineExecutor = deadlineExecutor;
    }

    @PostMapping("/identity/introspect")
    public DeferredResult<Object> introspect(HttpServletRequest request,
                             @RequestBody(required = false) IntrospectDTO body) {
        String authorization = request.getHeader("Authorization");
        String uri = request.getRequestURI();
        return deadlineExecutor.execute(started(request), () -> introspectionService.introspect(
                clientAuthorization.authenticateAndAuthorize(authorization, uri), body));
    }

    @PostMapping("/runtime-tickets")
    public DeferredResult<RuntimeTicketVO> issueRuntimeTicket(HttpServletRequest request,
                                                    @RequestBody(required = false) RuntimeTicketDTO body) {
        String authorization = request.getHeader("Authorization");
        String uri = request.getRequestURI();
        return deadlineExecutor.execute(started(request), () -> runtimeTicketService.issue(
                clientAuthorization.authenticateAndAuthorize(authorization, uri), body));
    }
    private long started(HttpServletRequest request) {
        Object value = request.getAttribute(RequestIdFilter.STARTED_NANOS_ATTRIBUTE);
        return value instanceof Long timestamp ? timestamp : System.nanoTime();
    }
}
