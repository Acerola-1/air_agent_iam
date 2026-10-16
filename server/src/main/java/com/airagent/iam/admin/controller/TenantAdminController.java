package com.airagent.iam.admin.controller;

import com.airagent.iam.admin.dto.CreateDepartmentDTO;
import com.airagent.iam.admin.dto.CreateMembershipDTO;
import com.airagent.iam.admin.dto.CreateTenantDTO;
import com.airagent.iam.admin.dto.MemberRolesDTO;
import com.airagent.iam.admin.dto.UpdateDepartmentDTO;
import com.airagent.iam.admin.dto.UpdateMembershipDTO;
import com.airagent.iam.admin.dto.UpdateTenantDTO;
import com.airagent.iam.admin.service.TenantAdminService;
import com.airagent.iam.admin.vo.DepartmentVO;
import com.airagent.iam.admin.vo.MemberVO;
import com.airagent.iam.admin.vo.TenantVO;
import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.common.vo.PageVO;
import com.airagent.iam.web.BearerAuthInterceptor;
import com.airagent.iam.web.error.ApiException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 企业、成员、部门管理路由。租户作用域以会话 currentTenantId 为准，
 * tenant_id 查询/正文仅允许缺省或与当前上下文一致，防止越租户写入。
 */
@RestController
@RequestMapping({"/v1/admin", "/web-api/admin"})
public class TenantAdminController {

    private final TenantAdminService service;

    public TenantAdminController(TenantAdminService service) {
        this.service = service;
    }

    // ------------------------------------------------ 企业

    @GetMapping("/tenants")
    public PageVO<TenantVO> listTenants(HttpServletRequest request,
                                        @RequestParam(value = "limit", required = false) Integer limit,
                                        @RequestParam(value = "cursor", required = false) String cursor) {
        return service.listTenants(current(request), limit, cursor);
    }

    @PostMapping("/tenants")
    public ResponseEntity<TenantVO> createTenant(HttpServletRequest request,
                                                   @RequestBody(required = false) CreateTenantDTO body) {
        return ResponseEntity.status(HttpStatus.CREATED).body(service.createTenant(current(request), body));
    }

    @GetMapping("/tenants/{id}")
    public TenantVO getTenant(HttpServletRequest request, @PathVariable String id) {
        return service.getTenant(current(request), id);
    }

    @PatchMapping("/tenants/{id}")
    public TenantVO updateTenant(HttpServletRequest request, @PathVariable String id,
                                   @RequestBody(required = false) UpdateTenantDTO body) {
        return service.updateTenant(current(request), id, body);
    }

    // ------------------------------------------------ 成员

    @GetMapping("/members")
    public PageVO<MemberVO> listMembers(HttpServletRequest request,
                                        @RequestParam(value = "tenant_id", required = false) String tenantId,
                                        @RequestParam(value = "limit", required = false) Integer limit,
                                        @RequestParam(value = "cursor", required = false) String cursor) {
        return service.listMembers(current(request), tenantId, limit, cursor);
    }

    @PostMapping("/members")
    public ResponseEntity<MemberVO> createMembership(
            HttpServletRequest request,
            @RequestBody(required = false) CreateMembershipDTO body) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(service.createMembership(current(request), body));
    }

    @PatchMapping("/members/{id}")
    public MemberVO updateMembership(HttpServletRequest request, @PathVariable String id,
                                       @RequestBody(required = false) UpdateMembershipDTO body) {
        return service.updateMembership(current(request), id, body);
    }

    @DeleteMapping("/members/{id}")
    public ResponseEntity<Void> deleteMembership(HttpServletRequest request, @PathVariable String id) {
        service.deleteMembership(current(request), id);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/members/{id}/roles")
    public MemberVO replaceMemberRoles(HttpServletRequest request, @PathVariable String id,
                                         @RequestBody(required = false) MemberRolesDTO body) {
        return service.replaceMemberRoles(current(request), id, body);
    }

    // ------------------------------------------------ 部门

    @GetMapping("/departments")
    public PageVO<DepartmentVO> listDepartments(
            HttpServletRequest request,
            @RequestParam(value = "tenant_id", required = false) String tenantId,
            @RequestParam(value = "limit", required = false) Integer limit,
            @RequestParam(value = "cursor", required = false) String cursor) {
        return service.listDepartments(current(request), tenantId, limit, cursor);
    }

    @PostMapping("/departments")
    public ResponseEntity<DepartmentVO> createDepartment(
            HttpServletRequest request,
            @RequestParam(value = "tenant_id", required = false) String tenantId,
            @RequestBody(required = false) CreateDepartmentDTO body) {
        requireDepartmentContext(current(request), body == null ? null : body.tenantId(),
                body == null ? null : body.expectedCtxVersion());
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(service.createDepartment(current(request), tenantId, body));
    }

    @PatchMapping("/departments/{id}")
    public DepartmentVO updateDepartment(HttpServletRequest request, @PathVariable String id,
                                           @RequestBody(required = false) UpdateDepartmentDTO body) {
        requireDepartmentContext(current(request), body == null ? null : body.tenantId(),
                body == null ? null : body.expectedCtxVersion());
        return service.updateDepartment(current(request), id, body);
    }

    private void requireDepartmentContext(CurrentSession actor, String tenantId, Long expectedVersion) {
        if (tenantId == null || expectedVersion == null) {
            throw ApiException.badRequest("tenant_id 与 expected_ctx_version 必填");
        }
        if (actor.currentTenantId() == null || !actor.currentTenantId().toString().equals(tenantId)
                || actor.ctxVersion() != expectedVersion) {
            throw ApiException.contextChanged("表单企业上下文已变化，请刷新后重试");
        }
    }

    private CurrentSession current(HttpServletRequest request) {
        return (CurrentSession) request.getAttribute(BearerAuthInterceptor.CURRENT_SESSION_ATTRIBUTE);
    }
}
