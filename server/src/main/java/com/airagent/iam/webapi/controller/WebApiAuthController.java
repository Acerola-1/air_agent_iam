package com.airagent.iam.webapi.controller;

import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.auth.dto.ChangePasswordDTO;
import com.airagent.iam.auth.dto.LoginDTO;
import com.airagent.iam.auth.dto.RenewDTO;
import com.airagent.iam.auth.dto.SwitchTenantDTO;
import com.airagent.iam.auth.service.SessionService;
import com.airagent.iam.auth.vo.IdentityVO;
import com.airagent.iam.auth.vo.LoginVO;
import com.airagent.iam.auth.vo.SessionTimersVO;
import com.airagent.iam.auth.vo.TenantMembershipVO;
import com.airagent.iam.web.BearerAuthInterceptor;
import com.airagent.iam.webapi.BrowserHandleRow;
import com.airagent.iam.webapi.BrowserSessionInterceptor;
import com.airagent.iam.webapi.MenuCatalog;
import com.airagent.iam.webapi.WebCookies;
import com.airagent.iam.webapi.dto.WebLoginDTO;
import com.airagent.iam.webapi.service.BrowserSessionService;
import com.airagent.iam.webapi.vo.WebLoginVO;
import com.airagent.iam.webapi.vo.WebRenewVO;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * /web-api/auth 浏览器会话端点：Cookie 句柄 + CSRF/Origin，由服务端固定 iam-admin 受众；
 * 登录只返回安全身份 DTO，人类令牌从不进入浏览器 JS 可访问的位置。
 */
@RestController
@RequestMapping("/web-api/auth")
public class WebApiAuthController {

    private static final String ADMIN_AUDIENCE = "iam-admin";

    private final SessionService sessionService;
    private final BrowserSessionService browserSessions;
    private final MenuCatalog menuCatalog;
    private final WebCookies cookies;

    public WebApiAuthController(SessionService sessionService,
                                BrowserSessionService browserSessions,
                                MenuCatalog menuCatalog,
                                WebCookies cookies) {
        this.sessionService = sessionService;
        this.browserSessions = browserSessions;
        this.menuCatalog = menuCatalog;
        this.cookies = cookies;
    }

    @PostMapping("/login")
    public WebLoginVO login(HttpServletRequest request, HttpServletResponse response,
                                  @RequestBody(required = false) WebLoginDTO body) {
        if (body == null || body.account() == null || body.password() == null) {
            throw com.airagent.iam.web.error.ApiException.badRequest("account 与 password 必填");
        }
        String realm = body.realm() == null || body.realm().isBlank() ? "workforce" : body.realm();
        LoginVO result = sessionService.login(
                new LoginDTO(body.account(), body.password(), realm, ADMIN_AUDIENCE));
        UUID sessionId = UUID.fromString(result.identity().session().id());

        String oldRawHandle = (String) request.getAttribute(BrowserSessionInterceptor.HANDLE_RAW_ATTRIBUTE);
        BrowserSessionService.IssuedHandle bound = browserSessions.bind(oldRawHandle, sessionId);
        cookies.issueSession(response, bound.rawHandle());
        cookies.issueCsrf(response, bound.csrfToken());
        return new WebLoginVO(result.identity(), result.identity().session().expiresAt());
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response) {
        CurrentSession current = current(request);
        String rawHandle = (String) request.getAttribute(BrowserSessionInterceptor.HANDLE_RAW_ATTRIBUTE);
        sessionService.logout(current);
        browserSessions.revoke(rawHandle);
        cookies.expireSession(response);
        cookies.expireCsrf(response);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/logout-all")
    public ResponseEntity<Void> logoutAll(HttpServletRequest request, HttpServletResponse response) {
        CurrentSession current = current(request);
        String rawHandle = (String) request.getAttribute(BrowserSessionInterceptor.HANDLE_RAW_ATTRIBUTE);
        sessionService.logoutAll(current);
        browserSessions.revoke(rawHandle);
        cookies.expireSession(response);
        cookies.expireCsrf(response);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/me")
    public IdentityVO me(HttpServletRequest request) {
        return sessionService.identityOf(current(request));
    }

    @GetMapping("/tenants")
    public List<TenantMembershipVO> tenants(HttpServletRequest request) {
        return sessionService.tenants(current(request));
    }

    @GetMapping("/menus")
    public Map<String, Object> menus(HttpServletRequest request) {
        return menuCatalog.build(current(request).snapshot());
    }

    @PostMapping("/switch-tenant")
    public IdentityVO switchTenant(HttpServletRequest request,
                                         @RequestBody(required = false) SwitchTenantDTO body) {
        CurrentSession current = current(request);
        sessionService.switchTenant(current, body);
        CurrentSession fresh = sessionService.requireCurrentBySessionId(current.sessionId());
        BrowserHandleRow row = (BrowserHandleRow) request
                .getAttribute(BrowserSessionInterceptor.HANDLE_ROW_ATTRIBUTE);
        browserSessions.touch(row);
        return sessionService.identityOf(fresh);
    }

    @PostMapping("/renew")
    public WebRenewVO renew(HttpServletRequest request,
                                  @RequestBody(required = false) RenewDTO body) {
        CurrentSession current = current(request);
        SessionTimersVO timers = sessionService.renew(current, body);
        CurrentSession fresh = sessionService.requireCurrentBySessionId(current.sessionId());
        return new WebRenewVO(timers.absoluteExpiresAt(), timers.idleExpiresAt(),
                sessionService.identityOf(fresh));
    }

    @PostMapping("/change-password")
    public ResponseEntity<Void> changePassword(HttpServletRequest request,
                                               @RequestBody(required = false) ChangePasswordDTO body) {
        sessionService.changePassword(current(request), body);
        return ResponseEntity.noContent().build();
    }

    private CurrentSession current(HttpServletRequest request) {
        return (CurrentSession) request.getAttribute(BearerAuthInterceptor.CURRENT_SESSION_ATTRIBUTE);
    }

    private String findCookie(jakarta.servlet.http.Cookie[] requestCookies, String name) {
        if (requestCookies == null) {
            return null;
        }
        for (jakarta.servlet.http.Cookie cookie : requestCookies) {
            if (name.equals(cookie.getName()) && cookie.getValue() != null && !cookie.getValue().isBlank()) {
                return cookie.getValue();
            }
        }
        return null;
    }
}
