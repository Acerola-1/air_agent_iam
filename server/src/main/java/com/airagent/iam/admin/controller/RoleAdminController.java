package com.airagent.iam.admin.controller;

import com.airagent.iam.admin.dto.CreateRoleDTO;
import com.airagent.iam.admin.dto.RolePermissionsDTO;
import com.airagent.iam.admin.dto.UpdateRoleDTO;
import com.airagent.iam.admin.service.RoleAdminService;
import com.airagent.iam.admin.vo.GrantableTreeVO;
import com.airagent.iam.admin.vo.PermissionVO;
import com.airagent.iam.admin.vo.RoleVO;
import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.common.vo.PageVO;
import com.airagent.iam.web.BearerAuthInterceptor;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
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

/** 角色/权限/可授树：/v1/admin、/web-api/admin 下的 roles、permissions、grantable-tree。 */
@RestController
@RequestMapping({"/v1/admin", "/web-api/admin"})
public class RoleAdminController {

    private final RoleAdminService service;

    public RoleAdminController(RoleAdminService service) {
        this.service = service;
    }

    @GetMapping("/roles")
    public PageVO<RoleVO> listRoles(HttpServletRequest request,
                                    @RequestParam(value = "scope", required = false) String scope,
                                    @RequestParam(value = "limit", required = false) Integer limit,
                                    @RequestParam(value = "cursor", required = false) String cursor) {
        return service.listRoles(current(request), scope, limit, cursor);
    }

    @PostMapping("/roles")
    public ResponseEntity<RoleVO> createRole(HttpServletRequest request,
                                               @RequestBody(required = false) CreateRoleDTO body) {
        return ResponseEntity.status(HttpStatus.CREATED).body(service.createRole(current(request), body));
    }

    @PatchMapping("/roles/{id}")
    public RoleVO updateRole(HttpServletRequest request, @PathVariable String id,
                               @RequestBody(required = false) UpdateRoleDTO body) {
        return service.updateRole(current(request), id, body);
    }

    @PostMapping("/roles/{id}/permissions")
    public RoleVO replacePermissions(HttpServletRequest request, @PathVariable String id,
                                       @RequestBody(required = false) RolePermissionsDTO body) {
        return service.replacePermissions(current(request), id, body);
    }

    @GetMapping("/permissions")
    public Object listPermissions(HttpServletRequest request) {
        List<PermissionVO> items = service.listPermissions(current(request));
        return java.util.Map.of("items", items);
    }

    @GetMapping("/grantable-tree")
    public GrantableTreeVO grantableTree(HttpServletRequest request) {
        return service.grantableTree(current(request));
    }

    private CurrentSession current(HttpServletRequest request) {
        return (CurrentSession) request.getAttribute(BearerAuthInterceptor.CURRENT_SESSION_ATTRIBUTE);
    }
}
