package com.airagent.iam.serviceaccount.controller;

import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.common.vo.PageVO;
import com.airagent.iam.serviceaccount.dto.CreateServiceAccountDTO;
import com.airagent.iam.serviceaccount.dto.CreateServiceTokenDTO;
import com.airagent.iam.serviceaccount.dto.UpdateServiceAccountDTO;
import com.airagent.iam.serviceaccount.service.ServiceAccountService;
import com.airagent.iam.serviceaccount.vo.ServiceAccountDetailVO;
import com.airagent.iam.serviceaccount.vo.ServiceAccountVO;
import com.airagent.iam.serviceaccount.vo.ServiceTokenIssuedVO;
import com.airagent.iam.web.BearerAuthInterceptor;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * /v1/admin/service-accounts：平台级服务账号与凭据管理。权限在服务层再次裁决
 * （菜单/按钮仅提示，不能替代后端权限）。
 */
@RestController
@RequestMapping({"/v1/admin/service-accounts", "/web-api/admin/service-accounts"})
public class ServiceAccountAdminController {

    private final ServiceAccountService service;

    public ServiceAccountAdminController(ServiceAccountService service) {
        this.service = service;
    }

    @GetMapping
    public PageVO<ServiceAccountVO> list(HttpServletRequest request,
                                         @RequestParam(value = "tenant_id", required = false) String tenantId,
                                         @RequestParam(value = "limit", required = false) Integer limit,
                                         @RequestParam(value = "cursor", required = false) String cursor) {
        return service.list(current(request), tenantId, limit, cursor);
    }

    @PostMapping
    public ServiceAccountVO create(HttpServletRequest request,
                                     @RequestBody(required = false) CreateServiceAccountDTO body) {
        return service.create(current(request), body);
    }

    @GetMapping("/{id}")
    public ServiceAccountDetailVO get(HttpServletRequest request, @PathVariable("id") String id) {
        return service.get(current(request), id);
    }

    @PatchMapping("/{id}")
    public ServiceAccountVO updateStatus(HttpServletRequest request, @PathVariable("id") String id,
                                           @RequestBody(required = false) UpdateServiceAccountDTO body) {
        return service.updateStatus(current(request), id, body);
    }

    @PostMapping("/{id}/tokens")
    public ServiceTokenIssuedVO issueToken(HttpServletRequest request,
                                         @PathVariable("id") String serviceAccountId,
                                         @RequestBody(required = false) CreateServiceTokenDTO body) {
        return service.issueToken(current(request), serviceAccountId, body);
    }

    @PostMapping("/tokens/{credentialId}/revoke")
    public ResponseEntity<Void> revokeToken(HttpServletRequest request,
                                            @PathVariable("credentialId") String credentialId) {
        service.revokeToken(current(request), credentialId);
        return ResponseEntity.noContent().build();
    }

    private CurrentSession current(HttpServletRequest request) {
        return (CurrentSession) request.getAttribute(BearerAuthInterceptor.CURRENT_SESSION_ATTRIBUTE);
    }
}
