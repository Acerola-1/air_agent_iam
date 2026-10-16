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
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
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
 * 人类 Bearer 会话 HTTP 入口（Controller 层，不访问数据库、不做权限裁决）。
 *
 * <p>挂载在 {@code /v1/auth}，令牌只在 {@code Authorization: Bearer <Sa-Token>} 头中出现，
 * 一律不写 cookie；浏览器后台的等价能力走 {@code /web-api/auth/**} 会话适配
 * （Cookie 中央会话 + Origin 同源防护），两条链路共用 {@link SessionService} 与同一套
 * "Redis 存活 + PG 主库权威"核验，不存在第二权威。
 *
 * <p>认证面区分（与 WebMvcConfiguration 的拦截器注册完全一致）：
 * <ul>
 *   <li>{@code POST /v1/auth/login} 与 {@code POST /v1/auth/logout} 被排除在
 *       {@link BearerAuthInterceptor} 之外，属公开端点，文档不声明安全方案；logout 自行从
 *       Authorization 头取令牌——缺少该头仍是 401，但令牌已撤销/过期/不存在时按幂等成功返回 204。</li>
 *   <li>其余端点均受拦截器保护，需 {@code humanBearer}；拦截器把已核验的
 *       {@link CurrentSession} 与原始令牌分别写入请求属性
 *       {@code CURRENT_SESSION_ATTRIBUTE} 与 {@code RAW_TOKEN_ATTRIBUTE}，
 *       本层只做取回与透传。</li>
 * </ul>
 *
 * <p>错误统一由 {@link com.airagent.iam.web.error.GlobalExceptionHandler} 转为错误信封；
 * 各操作只列出实际可达的状态码。受保护端点的响应由拦截器统一追加
 * {@code Cache-Control: no-store}（公开端点不经该拦截器），防止中间缓存留存权限快照。
 *
 * @author Acerola
 */
@Tag(name = "人类会话与身份", description = "登录、登出、身份、菜单、企业列表、切企业、续期与本人改密。"
        + "除 login/logout 外均需人类 Bearer")
@RestController
@RequestMapping("/v1/auth")
public class AuthController {

    /** 会话与身份权威服务（核验、CAS、撤销与审计都在其中）。 */
    private final SessionService sessionService;

    /** iam-admin 菜单目录，按当前实时有效权限裁剪。 */
    private final MenuCatalog menuCatalog;

    /**
     * 构造人类会话控制器。
     *
     * @param sessionService 会话权威业务服务
     * @param menuCatalog    菜单目录装配组件（仅读会话快照，不访问数据库）
     */
    public AuthController(SessionService sessionService, MenuCatalog menuCatalog) {
        this.sessionService = sessionService;
        this.menuCatalog = menuCatalog;
    }

    /**
     * 账号口令登录，成功后建立人类 Bearer 会话。
     *
     * @param request 登录请求；请求体缺失按 400 处理
     * @return 一次性下发原始访问令牌、令牌类型、空闲有效期（秒）与实时身份视图
     */
    @Operation(summary = "登录",
            description = "公开端点，无需 Authorization 头。按 realm+account 做固定窗口限流（默认 60 秒 10 次），"
                    + "命中返回 429；账号不存在与口令错误、账号停用一律返回同一句 401 消息，不区分以避免账号枚举。"
                    + "口令仅用于 BCrypt 比对，不写日志、不回显。响应令牌只在本次出现，服务端只存其摘要。",
            security = {})
    @ApiResponse(responseCode = "200", description = "登录成功，返回访问令牌与身份")
    @ApiResponse(responseCode = "400", description = "请求体缺失，或 account/password/realm/audience 不合法")
    @ApiResponse(responseCode = "401", description = "账号或口令错误（含账号停用，同一消息）")
    @ApiResponse(responseCode = "429", description = "登录限流命中，请稍后重试")
    @ApiResponse(responseCode = "503", description = "限流或会话依赖（Redis/PG）暂不可用，失败关闭")
    @PostMapping("/login")
    public LoginVO login(@RequestBody(required = false) LoginDTO request) {
        return sessionService.login(request);
    }

    /**
     * 退出当前会话。
     *
     * @param request 当前 HTTP 请求，仅用于取 {@code Authorization} 头中的原始令牌
     * @return 204 空响应体
     */
    @Operation(summary = "登出当前会话",
            description = "公开端点：本方法自行从 Authorization 头读取令牌，不经 Bearer 拦截器。"
                    + "撤销的是 PG 权威会话行，同事务登记 Redis 键清理并尽力即时删除。"
                    + "缺少 Authorization 头返回 401；令牌不存在、已撤销或已过期时按幂等成功返回 204，不报错。"
                    + "只影响本会话，同用户其它会话保持活跃（全退请用 logout-all）。",
            security = {})
    @ApiResponse(responseCode = "204", description = "已登出（含令牌本就无效的幂等情形）")
    @ApiResponse(responseCode = "401", description = "缺少 Authorization 头或令牌为空")
    @ApiResponse(responseCode = "403", description = "所属企业或成员关系已停用")
    @ApiResponse(responseCode = "503", description = "Redis/PG 依赖暂不可用")
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request) {
        sessionService.logout(BearerAuthInterceptor.bearerToken(request));
        return ResponseEntity.noContent().build();
    }

    /**
     * 退出该用户全部会话（含当前会话）。
     *
     * @param request 当前 HTTP 请求，用于取拦截器保存的原始令牌
     * @return 204 空响应体
     */
    @Operation(summary = "登出全部会话",
            description = "需要人类 Bearer。撤销该用户全部活跃会话（含本次调用的当前会话与 SSO 兑换出的子会话），"
                    + "并额外推进用户授权代次，使任何旧快照在下一次核验即被拒；被撤会话的 Redis 键经同事务 outbox 清理。"
                    + "与 logout 不同，令牌不可用时明确返回 401，不伪装成登出成功。",
            security = {@SecurityRequirement(name = "humanBearer")})
    @ApiResponse(responseCode = "204", description = "全部会话已撤销")
    @ApiResponse(responseCode = "401", description = "缺少/无效令牌，会话已撤销、过期或授权代次变旧，账号已停用")
    @ApiResponse(responseCode = "403", description = "所属企业或成员关系已停用")
    @ApiResponse(responseCode = "503", description = "Redis/PG 依赖暂不可用")
    @PostMapping("/logout-all")
    public ResponseEntity<Void> logoutAll(HttpServletRequest request) {
        sessionService.logoutAll((String) request.getAttribute(BearerAuthInterceptor.RAW_TOKEN_ATTRIBUTE));
        return ResponseEntity.noContent().build();
    }

    /**
     * 查询当前令牌的实时身份。
     *
     * @param request 当前 HTTP 请求，用于取拦截器保存的原始令牌
     * @return iam.identity.v1 身份视图
     */
    @Operation(summary = "查询当前身份",
            description = "需要人类 Bearer。每次调用都是一次 Redis 存活检查加一次 PG 主库单往返，"
                    + "无跨请求授权缓存，因此返回的是实时有效权限。非 iam-admin 受众不返回业务权限码"
                    + "（资源型权限尚未开通）；未选企业时 current_tenant 与 membership 为 null，"
                    + "并以 needs_tenant_selection 指示前端引导选择。",
            security = {@SecurityRequirement(name = "humanBearer")})
    @ApiResponse(responseCode = "200", description = "查询成功")
    @ApiResponse(responseCode = "401", description = "缺少/无效令牌，会话缺失、已撤销、过期或授权代次变旧，账号已停用")
    @ApiResponse(responseCode = "403", description = "所属企业或成员关系已停用")
    @ApiResponse(responseCode = "503", description = "Redis/PG 依赖暂不可用或身份快照解析失败")
    @GetMapping("/me")
    public IdentityVO me(HttpServletRequest request) {
        return sessionService.me((String) request.getAttribute(BearerAuthInterceptor.RAW_TOKEN_ATTRIBUTE));
    }

    /**
     * 取回 iam-admin 的可见菜单树。
     *
     * @param request 当前 HTTP 请求，用于取拦截器注入的会话快照
     * @return 菜单目录：{@code application} 标识与已按权限裁剪的 {@code items} 树
     */
    @Operation(summary = "查询后台菜单",
            description = "需要人类 Bearer。按拦截器注入的实时权限快照裁剪，平台超级管理员可见全部平台分组，"
                    + "企业分组仅在已选择可用企业时给出。菜单只是 UX 提示，"
                    + "每个后端端点仍独立裁决权限，不以前端可见性作为授权依据。",
            security = {@SecurityRequirement(name = "humanBearer")})
    @ApiResponse(responseCode = "200", description = "查询成功")
    @ApiResponse(responseCode = "401", description = "缺少/无效令牌，会话不可用或账号已停用")
    @ApiResponse(responseCode = "403", description = "所属企业或成员关系已停用")
    @ApiResponse(responseCode = "503", description = "Redis/PG 依赖暂不可用")
    @GetMapping("/menus")
    public Map<String, Object> menus(HttpServletRequest request) {
        CurrentSession current = (CurrentSession) request
                .getAttribute(BearerAuthInterceptor.CURRENT_SESSION_ATTRIBUTE);
        return menuCatalog.build(current.snapshot());
    }

    /**
     * 列出当前用户可切入的企业。
     *
     * @param request 当前 HTTP 请求，用于取拦截器保存的原始令牌
     * @return 按企业 code 升序的活跃企业列表
     */
    @Operation(summary = "查询可切换企业",
            description = "需要人类 Bearer。只返回成员关系活跃且企业活跃的记录，按 code 升序；"
                    + "停用的企业与被禁用的成员关系一律不出现，因此该列表也是"
                    + "「switch-tenant 可选目标」的唯一来源。is_owner 字段语义为是否持有活跃 tenant_admin 角色。",
            security = {@SecurityRequirement(name = "humanBearer")})
    @ApiResponse(responseCode = "200", description = "查询成功，可能为空列表")
    @ApiResponse(responseCode = "401", description = "缺少/无效令牌，会话不可用或账号已停用")
    @ApiResponse(responseCode = "403", description = "所属企业或成员关系已停用")
    @ApiResponse(responseCode = "503", description = "Redis/PG 依赖暂不可用")
    @GetMapping("/tenants")
    public List<TenantMembershipVO> tenants(HttpServletRequest request) {
        return sessionService.tenants((String) request.getAttribute(BearerAuthInterceptor.RAW_TOKEN_ATTRIBUTE));
    }

    /**
     * 切换会话的当前企业。
     *
     * @param request 当前 HTTP 请求，用于取拦截器保存的原始令牌
     * @param body    目标企业与期望的会话纪元基线；请求体缺失按 400 处理
     * @return 切换后的实时身份视图（context_version 已递增）
     */
    @Operation(summary = "切换当前企业",
            description = "需要人类 Bearer。对中央会话执行一次 CAS：会话持行锁，纪元基线与当前值不一致返回 409；"
                    + "目标企业非活跃或该用户非其活跃成员返回 403（数据库 P0012）。成功即 ctx_version +1，"
                    + "并由数据库触发器把新上下文与纪元原子传播到同一中央会话下的全部子会话（SSO 应用会话）。"
                    + "返回体为切换后重新加载的实时身份，调用方必须用它替换本地基线代次。",
            security = {@SecurityRequirement(name = "humanBearer")})
    @ApiResponse(responseCode = "200", description = "切换成功，返回新身份")
    @ApiResponse(responseCode = "400", description = "tenant_id 或 expected_ctx_version 缺失，或 tenant_id 非 UUID")
    @ApiResponse(responseCode = "401", description = "缺少/无效令牌，会话已撤销或过期，账号已停用")
    @ApiResponse(responseCode = "403", description = "目标企业不可用或成员关系无效")
    @ApiResponse(responseCode = "409", description = "上下文代次冲突，请重新拉取身份后重试")
    @ApiResponse(responseCode = "503", description = "Redis/PG 依赖暂不可用")
    @PostMapping("/switch-tenant")
    public IdentityVO switchTenant(HttpServletRequest request,
                                         @RequestBody(required = false) SwitchTenantDTO body) {
        return sessionService.switchTenant(
                (String) request.getAttribute(BearerAuthInterceptor.RAW_TOKEN_ATTRIBUTE), body);
    }

    /**
     * 续期当前会话的空闲窗口。
     *
     * @param request 当前 HTTP 请求，用于取拦截器保存的原始令牌
     * @param body    期望的会话纪元基线；请求体缺失按 400 处理
     * @return 续期后的绝对与空闲到期时刻（UTC ISO-8601 文本）
     */
    @Operation(summary = "续期会话",
            description = "需要人类 Bearer。空闲截止时间在数据库持锁后取"
                    + "「max(原空闲截止, 锁后时刻 + 续期步长)」再被绝对上限夹住："
                    + "单调不减、可安全重试，且永远无法延长绝对到期时刻"
                    + "（默认空闲 7 天、绝对 30 天，单位秒）。已撤销或已过期的会话不可复活，返回 401；"
                    + "纪元基线不一致返回 409。",
            security = {@SecurityRequirement(name = "humanBearer")})
    @ApiResponse(responseCode = "200", description = "续期成功，返回新的两个到期时刻")
    @ApiResponse(responseCode = "400", description = "expected_ctx_version 缺失")
    @ApiResponse(responseCode = "401", description = "缺少/无效令牌，会话已撤销或已过期（不可续期复活）")
    @ApiResponse(responseCode = "403", description = "所属企业或成员关系已停用")
    @ApiResponse(responseCode = "409", description = "上下文代次冲突")
    @ApiResponse(responseCode = "503", description = "Redis/PG 依赖暂不可用")
    @PostMapping("/renew")
    public SessionTimersVO renew(HttpServletRequest request,
                               @RequestBody(required = false) RenewDTO body) {
        return sessionService.renew(
                (String) request.getAttribute(BearerAuthInterceptor.RAW_TOKEN_ATTRIBUTE), body);
    }

    /**
     * 本人改密。
     *
     * @param request 当前 HTTP 请求，用于取拦截器保存的原始令牌
     * @param body    旧口令与新口令；请求体缺失按 400 处理
     * @return 204 空响应体，不回显任何口令信息
     */
    @Operation(summary = "修改本人口令",
            description = "需要人类 Bearer。旧口令与权威快照中的 BCrypt 摘要在服务端内存中比对，不匹配返回 401；"
                    + "新口令长度须为 8..256 字符（400），与旧口令相同返回 409。"
                    + "成功后该用户全部活跃会话（含本次调用的当前会话）被撤销并即时清理 Redis 键，"
                    + "旧令牌立刻失效，调用方必须引导重新登录。两个口令字段不回显、不入日志与审计。",
            security = {@SecurityRequirement(name = "humanBearer")})
    @ApiResponse(responseCode = "204", description = "改密成功，全部会话已撤销")
    @ApiResponse(responseCode = "400", description = "old_password/new_password 缺失或新口令长度不合法")
    @ApiResponse(responseCode = "401", description = "缺少/无效令牌，或旧口令不正确")
    @ApiResponse(responseCode = "403", description = "所属企业或成员关系已停用")
    @ApiResponse(responseCode = "409", description = "新口令与旧口令相同")
    @ApiResponse(responseCode = "503", description = "Redis/PG 依赖暂不可用")
    @PostMapping("/change-password")
    public ResponseEntity<Void> changePassword(HttpServletRequest request,
                                               @RequestBody(required = false) ChangePasswordDTO body) {
        sessionService.changePassword(
                (String) request.getAttribute(BearerAuthInterceptor.RAW_TOKEN_ATTRIBUTE), body);
        return ResponseEntity.noContent().build();
    }
}
