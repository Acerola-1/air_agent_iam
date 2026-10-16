package com.airagent.iam.admin.controller;

import com.airagent.iam.admin.dto.CreateResourceDTO;
import com.airagent.iam.admin.dto.UpdateResourceDTO;
import com.airagent.iam.admin.service.ResourceAdminService;
import com.airagent.iam.admin.vo.ResourceVO;
import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.common.vo.PageVO;
import com.airagent.iam.web.BearerAuthInterceptor;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
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
 * 资源目录管理 HTTP 入口（Controller 层）。
 */
@Tag(name = "资源目录", description = "平台资源登记、修改与列表。需 entitlement:manage")
@RestController
@RequestMapping({"/v1/admin", "/web-api/admin"})
public class ResourceAdminController {

    private final ResourceAdminService service;

    /** 服务账号建档选项仅凭platform:service:write读取，不能管理开通。 */
    @SecurityRequirement(name = "humanBearer")
    @SecurityRequirement(name = "browserCookie")
    @GetMapping("/service-accounts/resource-options")
    @Operation(summary = "服务账号目标企业的可选权限", description = "仅platform:service:write；不授予资源读取能力")
    public com.airagent.iam.admin.vo.ServiceResourceOptionsVO serviceOptions(HttpServletRequest request,
            @RequestParam("tenant_id") String tenantId) {
        return service.serviceResourceOptions(current(request), tenantId);
    }

    public ResourceAdminController(ResourceAdminService service) {
        this.service = service;
    }

    @GetMapping("/resources")
    @Operation(summary = "资源目录列表", description = "分页列出资源目录，含权限绑定")
    @ApiResponse(responseCode = "200", description = "目录列表")
    @ApiResponse(responseCode = "403", description = "缺少 entitlement:manage")
    @SecurityRequirement(name = "humanBearer")
    @SecurityRequirement(name = "browserCookie")
    public ResponseEntity<PageVO<ResourceVO>> list(
            HttpServletRequest request,
            @Parameter(description = "状态过滤") @RequestParam(required = false) String status,
            @Parameter(description = "条数 1-200") @RequestParam(required = false) Integer limit,
            @Parameter(description = "游标") @RequestParam(required = false) String cursor) {
        CurrentSession actor = current(request);
        return ResponseEntity.ok(service.listResources(actor, status, limit, cursor));
    }

    @PostMapping("/resources")
    @Operation(summary = "登记资源", description = "登记新资源及权限绑定")
    @ApiResponse(responseCode = "201", description = "创建成功")
    @ApiResponse(responseCode = "400", description = "字段不合法")
    @ApiResponse(responseCode = "409", description = "code 冲突")
    @SecurityRequirement(name = "humanBearer")
    @SecurityRequirement(name = "browserCookie")
    public ResponseEntity<ResourceVO> create(HttpServletRequest request,
                                              @RequestBody CreateResourceDTO dto) {
        CurrentSession actor = current(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(service.createResource(actor, dto));
    }

    @PatchMapping("/resources/{resourceCode}")
    @Operation(summary = "修改资源", description = "修改中文名、排序或状态；code 与权限绑定不可改")
    @ApiResponse(responseCode = "200", description = "修改成功")
    @ApiResponse(responseCode = "409", description = "修订冲突")
    @SecurityRequirement(name = "humanBearer")
    @SecurityRequirement(name = "browserCookie")
    public ResponseEntity<ResourceVO> update(HttpServletRequest request,
                                              @PathVariable String resourceCode,
                                              @RequestBody UpdateResourceDTO dto) {
        CurrentSession actor = current(request);
        return ResponseEntity.ok(service.updateResource(actor, resourceCode, dto));
    }

    private CurrentSession current(HttpServletRequest request) {
        return (CurrentSession) request.getAttribute(BearerAuthInterceptor.CURRENT_SESSION_ATTRIBUTE);
    }
}
