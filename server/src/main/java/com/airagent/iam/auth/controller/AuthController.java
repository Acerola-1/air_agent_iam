package com.airagent.iam.auth.controller;

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
import com.airagent.iam.webapi.MenuCatalog;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * /v1/auth 人类 Bearer 会话端点。令牌只在 Authorization 头中出现，不写 cookie（浏览器后台走 /web-api 会话适配）。
 */
@RestController
@RequestMapping("/v1/auth")
public class AuthController {

    private final SessionService sessionService;
    private final MenuCatalog menuCatalog;

    public AuthController(SessionService sessionService, MenuCatalog menuCatalog) {
        this.sessionService = sessionService;
        this.menuCatalog = menuCatalog;
    }

    @PostMapping("/login")
    public LoginVO login(@RequestBody(required = false) LoginDTO request) {
        return sessionService.login(request);
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request) {
        sessionService.logout(BearerAuthInterceptor.bearerToken(request));
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/logout-all")
    public ResponseEntity<Void> logoutAll(HttpServletRequest request) {
        sessionService.logoutAll((String) request.getAttribute(BearerAuthInterceptor.RAW_TOKEN_ATTRIBUTE));
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/me")
    public IdentityVO me(HttpServletRequest request) {
        return sessionService.me((String) request.getAttribute(BearerAuthInterceptor.RAW_TOKEN_ATTRIBUTE));
    }

    @GetMapping("/menus")
    public Map<String, Object> menus(HttpServletRequest request) {
        CurrentSession current = (CurrentSession) request
                .getAttribute(BearerAuthInterceptor.CURRENT_SESSION_ATTRIBUTE);
        return menuCatalog.build(current.snapshot());
    }

    @GetMapping("/tenants")
    public List<TenantMembershipVO> tenants(HttpServletRequest request) {
        return sessionService.tenants((String) request.getAttribute(BearerAuthInterceptor.RAW_TOKEN_ATTRIBUTE));
    }

    @PostMapping("/switch-tenant")
    public IdentityVO switchTenant(HttpServletRequest request,
                                         @RequestBody(required = false) SwitchTenantDTO body) {
        return sessionService.switchTenant(
                (String) request.getAttribute(BearerAuthInterceptor.RAW_TOKEN_ATTRIBUTE), body);
    }

    @PostMapping("/renew")
    public SessionTimersVO renew(HttpServletRequest request,
                               @RequestBody(required = false) RenewDTO body) {
        return sessionService.renew(
                (String) request.getAttribute(BearerAuthInterceptor.RAW_TOKEN_ATTRIBUTE), body);
    }

    @PostMapping("/change-password")
    public ResponseEntity<Void> changePassword(HttpServletRequest request,
                                               @RequestBody(required = false) ChangePasswordDTO body) {
        sessionService.changePassword(
                (String) request.getAttribute(BearerAuthInterceptor.RAW_TOKEN_ATTRIBUTE), body);
        return ResponseEntity.noContent().build();
    }
}
