package com.airagent.iam.webapi.sso.controller;

import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.web.BearerAuthInterceptor;
import com.airagent.iam.webapi.BrowserHandleRow;
import com.airagent.iam.webapi.BrowserSessionInterceptor;
import com.airagent.iam.webapi.sso.service.SsoAuthorizeService;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 中央 SSO 起始端点：必须已有中央浏览器会话，登录页由前端引导完成后再发起。
 */
@RestController
public class SsoController {

    private final SsoAuthorizeService authorizeService;

    public SsoController(SsoAuthorizeService authorizeService) {
        this.authorizeService = authorizeService;
    }

    @GetMapping({"/web-api/sso/start", "/v1/sso/authorize"})
    public ResponseEntity<Void> start(
            HttpServletRequest request,
            @RequestParam("client_id") String clientId,
            @RequestParam("redirect_uri") String redirectUri,
            @RequestParam("state") String state) {
        CurrentSession current = (CurrentSession) request
                .getAttribute(BearerAuthInterceptor.CURRENT_SESSION_ATTRIBUTE);
        BrowserHandleRow handle = (BrowserHandleRow) request
                .getAttribute(BrowserSessionInterceptor.HANDLE_ROW_ATTRIBUTE);
        String location = authorizeService.authorize(current, handle, clientId, redirectUri,
                state, request.getHeader("Origin"));
        return ResponseEntity.status(303).location(URI.create(location)).build();
    }
}
