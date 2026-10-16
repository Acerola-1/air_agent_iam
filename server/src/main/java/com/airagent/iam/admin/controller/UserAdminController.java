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
 * 平台用户管理 HTTP 入口（Controller 层，不访问数据库）。
 *
 * <p>同一组能力挂载在两条路径上，对应两个鉴权面：
 * <ul>
 *   <li>{@code /v1/admin/users**} —— 人类 Bearer：经
 *       {@link BearerAuthInterceptor} 校验 {@code Authorization: Bearer <Sa-Token>}；</li>
 *   <li>{@code /web-api/admin/users**} —— 浏览器会话：经 BrowserSessionInterceptor
 *       校验会话 Cookie，并由 CsrfOriginInterceptor 对写操作做同源防护。</li>
 * </ul>
 *
 * <p>本层只做会话提取与参数透传；权限裁决、修订比对、会话撤销与审计全部在
 * {@link UserAdminService} 实现层完成。错误统一由 GlobalExceptionHandler
 * 转为错误信封（HTTP 状态见各操作的 {@code @ApiResponse}）。
 *
 * @author Acerola
 */
@Tag(name = "平台用户管理", description = "平台账号的查询、创建、状态变更、重置密码与平台角色分配。人类 Bearer 与浏览器会话两条路径能力相同")
@RestController
@RequestMapping({"/v1/admin/users", "/web-api/admin/users"})
public class UserAdminController {

    /** 平台账号业务服务。 */
    private final UserAdminService service;

    /**
     * 构造用户管理控制器。
     *
     * @param service 平台账号业务服务（权限与事务在服务层裁决）
     */
    public UserAdminController(UserAdminService service) {
        this.service = service;
    }

    /**
     * keyset 分页拉取平台账号列表。
     *
     * @param limit 单页条数；{@code null} 时取默认 20，合法范围 1..200，越界返回 400
     * @param cursor 不透明游标（上一页末行 id 的 base64url 编码）；{@code null} 或空白表示从首页开始
     * @param q 可选账号检索词，对 account 做大小写不敏感的子串匹配
     * @return 当前页 {@link PageVO}；无后续数据时 {@code nextCursor} 为 {@code null}
     * @param request 当前 HTTP 请求（会话快照由拦截器注入请求属性）
     */
    @Operation(summary = "分页列出平台账号",
            description = "需要 platform:user:read 权限。按 id 升序 keyset 分页；响应不含口令摘要。",
            security = {@SecurityRequirement(name = "humanBearer"), @SecurityRequirement(name = "browserCookie")})
    @ApiResponse(responseCode = "200", description = "查询成功")
    @ApiResponse(responseCode = "400", description = "limit 越界、cursor 或查询参数不合法")
    @ApiResponse(responseCode = "403", description = "缺少权限")
    @GetMapping
    public PageVO<UserVO> list(HttpServletRequest request,
                               @Parameter(description = "单页条数 1..200，缺省 20")
                               @RequestParam(value = "limit", required = false) Integer limit,
                               @Parameter(description = "上一页 nextCursor 原样回传；首页省略")
                               @RequestParam(value = "cursor", required = false) String cursor,
                               @Parameter(description = "账号子串（大小写不敏感）")
                               @RequestParam(value = "q", required = false) String q) {
        return service.list(current(request), limit, cursor, q);
    }

    /**
     * 按 id 查询单个平台账号。
     *
     * @param id 用户 UUID 文本；非 UUID 返回 400
     * @return 用户视图（含当前平台角色码）
     * @param request 当前 HTTP 请求（会话快照由拦截器注入请求属性）
     */
    @Operation(summary = "查询平台账号详情",
            description = "需要 platform:user:read 权限。RLS 决定行可见性。",
            security = {@SecurityRequirement(name = "humanBearer"), @SecurityRequirement(name = "browserCookie")})
    @ApiResponse(responseCode = "200", description = "查询成功")
    @ApiResponse(responseCode = "400", description = "id 不是合法 UUID")
    @ApiResponse(responseCode = "403", description = "缺少权限")
    @ApiResponse(responseCode = "404", description = "用户不存在或不可见")
    @GetMapping("/{id}")
    public UserVO get(HttpServletRequest request,
                      @Parameter(description = "用户 UUID") @PathVariable String id) {
        return service.get(current(request), id);
    }

    /**
     * 创建平台账号（realm 固定为 workforce）。
     *
     * @param body 创建请求；{@code null} 请求体返回 400
     * @return 201 与新账号视图
     * @param request 当前 HTTP 请求（会话快照由拦截器注入请求属性）
     */
    @Operation(summary = "创建平台账号",
            description = "需要 platform:user:write 权限。账号唯一性由 (realm, account) 数据库约束保证；口令强度校验后仅存 BCrypt 摘要。",
            security = {@SecurityRequirement(name = "humanBearer"), @SecurityRequirement(name = "browserCookie")})
    @ApiResponse(responseCode = "201", description = "创建成功")
    @ApiResponse(responseCode = "400", description = "请求体缺失或 account/display_name/口令不合法")
    @ApiResponse(responseCode = "403", description = "缺少权限")
    @ApiResponse(responseCode = "409", description = "同 realm 下账号名已存在")
    @PostMapping
    public ResponseEntity<UserVO> create(HttpServletRequest request,
                                         @RequestBody(required = false) CreateUserDTO body) {
        return ResponseEntity.status(HttpStatus.CREATED).body(service.create(current(request), body));
    }

    /**
     * 局部更新账号（显示名或状态）。
     *
     * @param id 用户 UUID 文本
     * @param body PATCH 请求；未出现的字段不修改
     * @return 更新后的账号视图
     * @param request 当前 HTTP 请求（会话快照由拦截器注入请求属性）
     */
    @Operation(summary = "更新平台账号",
            description = "需要 platform:user:write 权限。status 仅接受 active/disabled；置为 disabled 会立即撤销目标账号全部活跃会话（含其当前会话）并清理 Redis 会话键。"
                    + "可提交 expected_revision 做乐观并发检查，不一致返回 409。",
            security = {@SecurityRequirement(name = "humanBearer"), @SecurityRequirement(name = "browserCookie")})
    @ApiResponse(responseCode = "200", description = "更新成功")
    @ApiResponse(responseCode = "400", description = "字段不合法或 id 非 UUID")
    @ApiResponse(responseCode = "403", description = "缺少权限")
    @ApiResponse(responseCode = "404", description = "用户不存在或不可见")
    @ApiResponse(responseCode = "409", description = "expected_revision 与当前授权代次冲突")
    @PatchMapping("/{id}")
    public UserVO update(HttpServletRequest request,
                         @Parameter(description = "用户 UUID") @PathVariable String id,
                         @RequestBody(required = false) UpdateUserDTO body) {
        return service.update(current(request), id, body);
    }

    /**
     * 管理员重置目标账号口令。
     *
     * @param id 用户 UUID 文本
     * @param body 新口令与可选的修订基线
     * @return 204 空响应体
     * @param request 当前 HTTP 请求（会话快照由拦截器注入请求属性）
     */
    @Operation(summary = "重置平台账号口令",
            description = "需要 platform:user:password:reset 权限。改密后目标账号全部活跃会话（含当前会话）被撤销；"
                    + "新口令须通过强度校验。成功返回 204，不回显任何口令信息。",
            security = {@SecurityRequirement(name = "humanBearer"), @SecurityRequirement(name = "browserCookie")})
    @ApiResponse(responseCode = "204", description = "重置成功")
    @ApiResponse(responseCode = "400", description = "new_password 缺失或强度不足")
    @ApiResponse(responseCode = "403", description = "缺少权限")
    @ApiResponse(responseCode = "404", description = "用户不存在或不可见")
    @ApiResponse(responseCode = "409", description = "expected_revision 冲突")
    @PostMapping("/{id}/password")
    public ResponseEntity<Void> resetPassword(HttpServletRequest request,
                                              @Parameter(description = "用户 UUID") @PathVariable String id,
                                              @RequestBody(required = false) ResetPasswordDTO body) {
        service.resetPassword(current(request), id, body);
        return ResponseEntity.noContent().build();
    }

    /**
     * 全量替换账号的平台角色。
     *
     * @param id 用户 UUID 文本
     * @param body 目标角色码集合；传空集合表示清空全部平台角色
     * @return 更新后的账号视图（platform_roles 为替换后的结果）
     * @param request 当前 HTTP 请求（会话快照由拦截器注入请求属性）
     */
    @Operation(summary = "替换平台角色",
            description = "需要 platform:user:role:assign 权限。非 platform_super_admin 的 actor 只能授予自身权限集合之内的角色，越界返回 403；"
                    + "未知或停用的角色码返回 400。可提交 expected_revision 做乐观并发检查。",
            security = {@SecurityRequirement(name = "humanBearer"), @SecurityRequirement(name = "browserCookie")})
    @ApiResponse(responseCode = "200", description = "替换成功")
    @ApiResponse(responseCode = "400", description = "角色码不合法、未知或已停用")
    @ApiResponse(responseCode = "403", description = "缺少权限或授予超出自身范围的角色")
    @ApiResponse(responseCode = "404", description = "用户不存在或不可见")
    @ApiResponse(responseCode = "409", description = "expected_revision 冲突")
    @PostMapping("/{id}/platform-roles")
    public UserVO replacePlatformRoles(HttpServletRequest request,
                                       @Parameter(description = "用户 UUID") @PathVariable String id,
                                       @RequestBody(required = false) PlatformRolesDTO body) {
        return service.replacePlatformRoles(current(request), id, body);
    }

    /**
     * 取回拦截器注入的请求级会话快照。
     *
     * <p>仅对受保护路径有效；快照已经过 Redis Sa-Token 与 PG 权威双重核验。
     * 若拦截器未注入（配置外路径），返回 {@code null}，由服务层按未授权拒绝。
     *
     * @param request 当前 HTTP 请求
     * @return 已核验的 {@link CurrentSession}，可能为 {@code null}
     */
    private CurrentSession current(HttpServletRequest request) {
        return (CurrentSession) request.getAttribute(BearerAuthInterceptor.CURRENT_SESSION_ATTRIBUTE);
    }
}
