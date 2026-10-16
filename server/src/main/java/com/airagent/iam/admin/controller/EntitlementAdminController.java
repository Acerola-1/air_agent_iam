package com.airagent.iam.admin.controller;

import com.airagent.iam.admin.dto.UpdateEntitlementDTO;
import com.airagent.iam.admin.service.ResourceAdminService;
import com.airagent.iam.admin.vo.EntitlementVO;
import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.common.vo.PageVO;
import com.airagent.iam.web.BearerAuthInterceptor;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 企业资源开通管理 HTTP 入口（Controller 层）。
 */
@Tag(name = "企业资源开通", description = "平台给企业开通/回收资源；企业只读本企业资源")
@RestController
@RequestMapping({"/v1/admin", "/web-api/admin"})
public class EntitlementAdminController {

    private final ResourceAdminService service;

    public EntitlementAdminController(ResourceAdminService service) {
        this.service = service;
    }

    @GetMapping("/tenants/{tenantId}/entitlements")
    @Operation(summary = "企业开通列表", description = "按目录投影开通状态，需 entitlement:manage")
    @ApiResponse(responseCode = "200", description = "开通列表")
    @ApiResponse(responseCode = "403", description = "缺少 entitlement:manage")
    @SecurityRequirement(name = "humanBearer")
    @SecurityRequirement(name = "browserCookie")
    public ResponseEntity<PageVO<EntitlementVO>> listTenantEntitlements(
            HttpServletRequest request,
            @PathVariable String tenantId,
            @Parameter(description = "条数") @RequestParam(required = false) Integer limit,
            @Parameter(description = "游标") @RequestParam(required = false) String cursor) {
        CurrentSession actor = current(request);
        return ResponseEntity.ok(service.listTenantEntitlements(actor, tenantId, limit, cursor));
    }

    @PutMapping("/tenants/{tenantId}/entitlements/{resourceCode}")
    @Operation(summary = "开通/回收资源", description = "CAS 设置企业资源开通状态")
    @ApiResponse(responseCode = "200", description = "更新成功")
    @ApiResponse(responseCode = "409", description = "修订/状态冲突")
    @SecurityRequirement(name = "humanBearer")
    @SecurityRequirement(name = "browserCookie")
    public ResponseEntity<EntitlementVO> updateEntitlement(
            HttpServletRequest request,
            @PathVariable String tenantId,
            @PathVariable String resourceCode,
            @RequestBody UpdateEntitlementDTO dto) {
        CurrentSession actor = current(request);
        return ResponseEntity.ok(service.updateEntitlement(actor, tenantId, resourceCode, dto));
    }

    @GetMapping("/tenant/resources")
    @Operation(summary = "本企业资源列表", description = "仅本企业已存在开通记录，需 tenant:role:read")
    @ApiResponse(responseCode = "200", description = "资源列表")
    @ApiResponse(responseCode = "403", description = "缺少权限或无企业上下文")
    @SecurityRequirement(name = "humanBearer")
    @SecurityRequirement(name = "browserCookie")
    public ResponseEntity<PageVO<EntitlementVO>> listCurrentTenantResources(
            HttpServletRequest request,
            @Parameter(description = "条数") @RequestParam(required = false) Integer limit,
            @Parameter(description = "游标") @RequestParam(required = false) String cursor) {
        CurrentSession actor = current(request);
        return ResponseEntity.ok(service.listCurrentTenantResources(actor, limit, cursor));
    }

    private CurrentSession current(HttpServletRequest request) {
        return (CurrentSession) request.getAttribute(BearerAuthInterceptor.CURRENT_SESSION_ATTRIBUTE);
    }
}
