package com.airagent.iam.audit.controller;

import com.airagent.iam.audit.dto.AuditLogQueryDTO;
import com.airagent.iam.audit.service.AuditService;
import com.airagent.iam.audit.vo.AuditLogVO;
import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.common.vo.PageVO;
import com.airagent.iam.web.BearerAuthInterceptor;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** 审计查询 HTTP 入口，沿用原有路由。 */
@RestController
@RequestMapping({"/v1/admin", "/web-api/admin"})
public class AuditController {

    private final AuditService auditService;

    public AuditController(AuditService auditService) {
        this.auditService = auditService;
    }

    @GetMapping("/audit-logs")
    public PageVO<AuditLogVO> list(HttpServletRequest request,
                                @RequestParam(value = "limit", required = false) Integer limit,
                                @RequestParam(value = "cursor", required = false) String cursor,
                                @RequestParam(value = "action", required = false) String action) {
        CurrentSession actor = (CurrentSession) request
                .getAttribute(BearerAuthInterceptor.CURRENT_SESSION_ATTRIBUTE);
        return auditService.list(actor, new AuditLogQueryDTO(limit, cursor, action));
    }
}
