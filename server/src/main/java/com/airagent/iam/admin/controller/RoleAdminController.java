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
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
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

/**
 * 角色、权限目录与可授权限树 HTTP 入口（Controller 层，不访问数据库）。
 *
 * <p>同一组能力挂载在两条路径上，对应两个鉴权面（角色管理的子路径为
 * {@code /roles}、{@code /permissions}、{@code /grantable-tree}）：
 * <ul>
 *   <li>{@code /v1/admin/**} —— 人类 Bearer：经
 *       {@link BearerAuthInterceptor} 校验 {@code Authorization: Bearer <Sa-Token>}；</li>
 *   <li>{@code /web-api/admin/**} —— 浏览器会话：经 BrowserSessionInterceptor
 *       校验会话 Cookie，并由 CsrfOriginInterceptor 对写操作做同源防护。</li>
 * </ul>
 *
 * <p>本层只做会话提取与参数透传。平台/企业两套口径由 {@link RoleAdminService} 依据会话
 * 权限快照自行选择：持 {@code platform:role:*} 走平台上下文（可读全部 scope），仅持
 * {@code tenant:role:*} 则必须先已选择企业上下文（否则 400），且只能操作本企业的自定义角色。
 * 权限子集校验、内置角色保护与可授边界由服务层和数据库触发器共同兜底；错误统一由
 * GlobalExceptionHandler 转为错误信封（HTTP 状态见各操作的 {@code @ApiResponse}）。
 *
 * @author Acerola
 */
@Tag(name = "角色与权限",
        description = "自定义角色（平台/企业两种 scope）的增改与权限装配、权限目录、当前主体可授权限树。"
                + "人类 Bearer 与浏览器会话两条路径能力相同")
@RestController
@RequestMapping({"/v1/admin", "/web-api/admin"})
public class RoleAdminController {

    /** 角色管理业务服务。 */
    private final RoleAdminService service;

    /**
     * 构造角色管理控制器。
     *
     * @param service 角色与权限业务服务（scope 口径选择、越界校验与事务在服务层裁决）
     */
    public RoleAdminController(RoleAdminService service) {
        this.service = service;
    }

    /**
     * keyset 分页拉取角色列表。
     *
     * <p>可见范围取决于 actor 的权限口径：平台口径可读平台与全部企业角色，企业口径仅能读到
     * 全局内置模板与本企业的自定义角色（由 iam.roles 的 RLS 裁决）。列表不过滤状态，
     * 停用（{@code disabled}）与内置（{@code builtin}）角色同样返回。
     *
     * @param request 当前 HTTP 请求（会话快照由拦截器注入）
     * @param scope   可选 scope 过滤，仅接受 {@code platform} 或 {@code tenant}；
     *                tenant始终限定当前企业，platform需平台读权限；省略时企业主体只返回本企业域
     * @param limit   单页条数；{@code null} 时取默认 20，合法范围 1..200，越界返回 400
     * @param cursor  不透明游标（上一页末行 id 的 base64url 编码）；{@code null} 或空白表示从首页开始
     * @return 当前页 {@link PageVO}；无后续数据时 {@code nextCursor} 为 {@code null}
     */
    @Operation(summary = "分页列出角色",
            description = "需 platform:role:read（平台口径）或 tenant:role:read（企业口径）之一，两者皆无返回 403。"
                    + "按 id 升序 keyset 分页；仅持企业口径时必须已选择企业上下文，否则 400。"
                    + "permissionCodes 为该角色当前已装配的权限码（按码升序）。",
            security = {@SecurityRequirement(name = "humanBearer"), @SecurityRequirement(name = "browserCookie")})
    @ApiResponse(responseCode = "200", description = "查询成功（可能为空列表）")
    @ApiResponse(responseCode = "400", description = "scope 非 platform/tenant、limit 越界、cursor 或游标解码后的 id 不合法，或企业口径下未选择企业上下文")
    @ApiResponse(responseCode = "403", description = "缺少平台与企业两类的角色查看权限")
    @GetMapping("/roles")
    public PageVO<RoleVO> listRoles(HttpServletRequest request,
                                    @Parameter(description = "仅支持platform/tenant；tenant限定当前企业及全局企业模板，platform需平台读权限")
                                    @RequestParam(value = "scope", required = false) String scope,
                                    @Parameter(description = "单页条数 1..200，缺省 20")
                                    @RequestParam(value = "limit", required = false) Integer limit,
                                    @Parameter(description = "上一页 nextCursor 原样回传；首页省略")
                                    @RequestParam(value = "cursor", required = false) String cursor) {
        return service.listRoles(current(request), scope, limit, cursor);
    }

    /**
     * 创建自定义角色（平台或企业 scope 由请求体声明）。
     *
     * <p>企业 scope 的角色归属会话当前企业，不接受请求体自报租户；创建时的权限码装配
     * 与"角色权限替换"接口复用同一套越界校验。
     *
     * @param request 当前 HTTP 请求（会话快照由拦截器注入）
     * @param body    创建请求；{@code null} 请求体返回 400（服务层与 code 缺失共用同一 400 分支）
     * @return 201 与新角色视图（含已装配的权限码）
     */
    @Operation(summary = "创建自定义角色",
            description = "scope=platform 需 platform:role:write；scope=tenant 需 tenant:role:write 且必须已选择企业上下文（否则 400）。"
                    + "code 为 3..64 位小写字母数字与 _-，平台 scope 下 code 全局唯一、企业 scope 下 (租户, code) 唯一；"
                    + "未知权限码 400，资源型权限或企业角色携带平台专属权限 409；"
                    + "非平台超管只能授予自身权限集合之内的权限码，越界 403。is_builtin 恒为 false。",
            security = {@SecurityRequirement(name = "humanBearer"), @SecurityRequirement(name = "browserCookie")})
    @ApiResponse(responseCode = "201", description = "创建成功")
    @ApiResponse(responseCode = "400", description = "请求体缺失或 code/name/scope/permission_codes 不合法，或存在未知权限码，或企业口径下未选择企业上下文")
    @ApiResponse(responseCode = "403", description = "缺少对应 scope 的写权限，或授予超出自身可授范围的权限")
    @ApiResponse(responseCode = "409", description = "角色 code 唯一冲突，或权限不在该角色的可授范围内")
    @PostMapping("/roles")
    public ResponseEntity<RoleVO> createRole(HttpServletRequest request,
                                             @RequestBody(required = false) CreateRoleDTO body) {
        return ResponseEntity.status(HttpStatus.CREATED).body(service.createRole(current(request), body));
    }

    /**
     * 局部更新自定义角色（名称、描述或状态）。
     *
     * <p>请求体中未出现的字段保持原值（SQL 侧 COALESCE 语义）。内置角色不可修改，
     * 与"角色不属于当前企业"一样返回 403 而非 404。
     *
     * @param request 当前 HTTP 请求（会话快照由拦截器注入）
     * @param id      角色 UUID 文本；非 UUID 返回 400
     * @param body    PATCH 请求；{@code null} 请求体返回 400；status 仅接受 active/disabled
     * @return 更新后的角色视图
     */
    @Operation(summary = "更新自定义角色",
            description = "平台角色需 platform:role:write，企业角色需 tenant:role:write 且属于当前企业上下文，否则 403；内置角色不可修改（403）。"
                    + "副作用：status 变更后数据库触发器会推进所有持有该角色的账号/成员的授权代次，其旧会话下一次权威核验即失效。",
            security = {@SecurityRequirement(name = "humanBearer"), @SecurityRequirement(name = "browserCookie")})
    @ApiResponse(responseCode = "200", description = "更新成功")
    @ApiResponse(responseCode = "400", description = "请求体缺失、name 不合法、status 非 active/disabled、id 非 UUID，或企业口径下未选择企业上下文")
    @ApiResponse(responseCode = "403", description = "无对应 scope 的写权限、角色不属于当前企业或为内置角色")
    @ApiResponse(responseCode = "404", description = "角色不存在或不可见")
    @PatchMapping("/roles/{id}")
    public RoleVO updateRole(HttpServletRequest request,
                             @Parameter(description = "角色 UUID") @PathVariable String id,
                             @RequestBody(required = false) UpdateRoleDTO body) {
        return service.updateRole(current(request), id, body);
    }

    /**
     * 全量替换角色的权限码集合。
     *
     * <p>delete-then-insert 在同一事务内完成，中途失败整体回滚；传空集合等价于清空全部权限。
     * 资源型权限（resource_code 非空）与企业角色携带平台专属权限（grantable_to_tenants=false）
     * 在应用层即拒绝，数据库触发器 guard_role_assignment_boundary 同时硬拒，构成双保险。
     *
     * @param request 当前 HTTP 请求（会话快照由拦截器注入）
     * @param id      角色 UUID 文本；非 UUID 返回 400
     * @param body    目标权限码集合；{@code null} 或空集合表示清空该角色的全部权限
     * @return 更新后的角色视图（permissionCodes 为替换后的结果，按码升序）
     */
    @Operation(summary = "替换角色权限",
            description = "平台角色需 platform:role:write，企业角色需 tenant:role:write 且属于当前企业上下文，否则 403；内置角色不可修改（403）。"
                    + "权限码须为 3..64 位小写字母数字与 _:-；非平台超管不得授予自身权限集合之外的码（403）。"
                    + "副作用：role_permissions 每次增删都会推进持有该角色的账号/成员的授权代次。",
            security = {@SecurityRequirement(name = "humanBearer"), @SecurityRequirement(name = "browserCookie")})
    @ApiResponse(responseCode = "200", description = "替换成功")
    @ApiResponse(responseCode = "400", description = "权限码格式不合法或存在未知权限码、id 非 UUID，或企业口径下未选择企业上下文")
    @ApiResponse(responseCode = "403", description = "无对应 scope 的写权限、角色不属于当前企业、内置角色或授予超出自身可授范围")
    @ApiResponse(responseCode = "404", description = "角色不存在或不可见")
    @ApiResponse(responseCode = "409", description = "权限不在该角色的可授范围内（资源型权限或企业角色的平台专属权限）")
    @PostMapping("/roles/{id}/permissions")
    public RoleVO replacePermissions(HttpServletRequest request,
                                     @Parameter(description = "角色 UUID") @PathVariable String id,
                                     @RequestBody(required = false) RolePermissionsDTO body) {
        return service.replacePermissions(current(request), id, body);
    }

    /**
     * 拉取权限目录（扁平列表，非分页）。
     *
     * <p>口径与 {@code GET /roles} 一致：平台口径返回全部非资源型权限，企业口径只返回
     * {@code scope=tenant} 的权限。目录不含资源型权限（SQL 侧 resource_code IS NULL 过滤），
     * 因此响应中的 grantScope 之外的 resourceType 字段当前恒为 {@code null}。
     *
     * @param request 当前 HTTP 请求（会话快照由拦截器注入）
     * @return 以 items 单键包装的权限列表；按目录排序号与权限码升序，无匹配时 items 为空数组
     */
    @Operation(summary = "查询权限目录",
            description = "需 platform:role:read 或 tenant:role:read 之一，两者皆无返回 403。"
                    + "平台口径返回全部权限，企业口径只返回 scope=tenant 的权限；不含资源型权限。",
            security = {@SecurityRequirement(name = "humanBearer"), @SecurityRequirement(name = "browserCookie")})
    @ApiResponse(responseCode = "200", description = "查询成功（items 可能为空数组）")
    @ApiResponse(responseCode = "400", description = "企业口径下未选择企业上下文")
    @ApiResponse(responseCode = "403", description = "缺少平台与企业两类的角色查看权限")
    @GetMapping("/permissions")
    public Object listPermissions(HttpServletRequest request) {
        List<PermissionVO> items = service.listPermissions(current(request));
        return java.util.Map.of("items", items);
    }

    /**
     * 拉取当前主体可授权限树（按 scope 分组）。
     *
     * <p>与权限目录的差别在于：本接口按"当前主体能授给别人什么"过滤——非 platform_super_admin
     * 的 actor，每组只保留其自身权限快照中已有的码。资源型权限在资源开通（I1a）之前整组缺席。
     *
     * @param request 当前 HTTP 请求（会话快照由拦截器注入）
     * @return 分组树：平台口径 actor 得到平台组与企业组，企业口径 actor 只得到企业组；
     *         组内 permissions 可能为空列表
     */
    @Operation(summary = "查询可授权限树",
            description = "需 platform:role:read/write 或 tenant:role:read/write 至少一个，否则 403。"
                    + "仅含 status=active、非资源型且（企业组）grantable_to_tenants=true 的权限；"
                    + "非平台超管只能看到自身已具备的权限码。企业口径下未选择企业上下文返回 400。",
            security = {@SecurityRequirement(name = "humanBearer"), @SecurityRequirement(name = "browserCookie")})
    @ApiResponse(responseCode = "200", description = "查询成功（组内权限列表可能为空）")
    @ApiResponse(responseCode = "400", description = "企业口径下未选择企业上下文")
    @ApiResponse(responseCode = "403", description = "缺少可授权限查看权限")
    @GetMapping("/grantable-tree")
    public GrantableTreeVO grantableTree(HttpServletRequest request) {
        return service.grantableTree(current(request));
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
