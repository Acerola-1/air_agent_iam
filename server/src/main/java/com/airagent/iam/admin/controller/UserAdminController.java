package com.airagent.iam.admin.controller;

import com.airagent.iam.admin.dto.CreateUserDTO;
import com.airagent.iam.admin.dto.PlatformRolesDTO;
import com.airagent.iam.admin.dto.ResetPasswordDTO;
import com.airagent.iam.admin.dto.UpdateUserDTO;
import com.airagent.iam.admin.service.UserAdminService;
import com.airagent.iam.admin.vo.UserVO;
import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.common.vo.PageVO;
import com.airagent.iam.web.BearerAuthInterceptor;
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

/** 平台用户管理：/v1/admin/users。权限在服务层逐一裁决。 */
@RestController
@RequestMapping({"/v1/admin/users", "/web-api/admin/users"})
public class UserAdminController {

    private final UserAdminService service;

    public UserAdminController(UserAdminService service) {
        this.service = service;
    }

    @GetMapping
    public PageVO<UserVO> list(HttpServletRequest request,
                               @RequestParam(value = "limit", required = false) Integer limit,
                               @RequestParam(value = "cursor", required = false) String cursor,
                               @RequestParam(value = "q", required = false) String q) {
        return service.list(current(request), limit, cursor, q);
    }

    @GetMapping("/{id}")
    public UserVO get(HttpServletRequest request, @PathVariable String id) {
        return service.get(current(request), id);
    }

    @PostMapping
    public ResponseEntity<UserVO> create(HttpServletRequest request,
                                           @RequestBody(required = false) CreateUserDTO body) {
        return ResponseEntity.status(HttpStatus.CREATED).body(service.create(current(request), body));
    }

    @PatchMapping("/{id}")
    public UserVO update(HttpServletRequest request, @PathVariable String id,
                           @RequestBody(required = false) UpdateUserDTO body) {
        return service.update(current(request), id, body);
    }

    @PostMapping("/{id}/password")
    public ResponseEntity<Void> resetPassword(HttpServletRequest request, @PathVariable String id,
                                              @RequestBody(required = false) ResetPasswordDTO body) {
        service.resetPassword(current(request), id, body);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{id}/platform-roles")
    public UserVO replacePlatformRoles(HttpServletRequest request, @PathVariable String id,
                                         @RequestBody(required = false) PlatformRolesDTO body) {
        return service.replacePlatformRoles(current(request), id, body);
    }

    private CurrentSession current(HttpServletRequest request) {
        return (CurrentSession) request.getAttribute(BearerAuthInterceptor.CURRENT_SESSION_ATTRIBUTE);
    }
}
