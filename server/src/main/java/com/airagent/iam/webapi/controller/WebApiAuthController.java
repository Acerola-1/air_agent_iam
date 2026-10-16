package com.airagent.iam.webapi.controller;

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
import com.airagent.iam.webapi.BrowserHandleRow;
import com.airagent.iam.webapi.BrowserSessionInterceptor;
import com.airagent.iam.webapi.MenuCatalog;
import com.airagent.iam.webapi.WebCookies;
import com.airagent.iam.webapi.dto.WebLoginDTO;
import com.airagent.iam.webapi.service.BrowserSessionService;
import com.airagent.iam.webapi.vo.WebLoginVO;
import com.airagent.iam.webapi.vo.WebRenewVO;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * {@code /web-api/auth} 浏览器会话端点（Controller 层，不访问数据库）。
 *
 * <p>鉴权面：浏览器会话 Cookie（{@code browserCookie}）——HttpOnly 句柄经
 * {@link BrowserSessionInterceptor} 解析为会话 id 并完成"Redis 存活 + PG 权威"双检；
 * 所有<em>写</em>操作另经 {@link com.airagent.iam.webapi.CsrfOriginInterceptor} 做
 * Origin 同源 + {@code X-CSRF-Token} 双提交检查。<em>人类访问令牌从不进入浏览器</em>：
 * 登录内部走 {@link SessionService#login} 取得 {@link LoginVO}，只取其中身份视图，
 * 原始令牌留在服务端，浏览器仅持有映射到会话 id 的不透明句柄。受众由本层固定为
 * {@code iam-admin}，不接受客户端传入。
 *
 * <p>公开端点：{@code /login} 在 {@link com.airagent.iam.config.WebMvcConfiguration} 中被
 * {@link BrowserSessionInterceptor} 排除（登录前无会话），但仍是写操作，需先经 CSRF/Origin；
 * CSRF 获取见 {@link BrowserCsrfController}。其余端点需有效会话。
 *
 * <p>协作关系：会话与身份权威全部委托 {@link SessionService}；句柄生命周期委托
 * {@link BrowserSessionService}；菜单委托 {@link MenuCatalog}；Cookie 下发委托
 * {@link WebCookies}。错误统一 {@link com.airagent.iam.web.error.ApiException}，经
 * GlobalExceptionHandler 转错误信封。
 *
 * @author Acerola
 */
@Tag(name = "浏览器会话与身份", description = "/web-api/auth 浏览器会话：登录/登出、身份与企业列表、菜单、切企业、续期与本人改密。"
        + "Cookie 句柄 + 写操作同源 CSRF；受众固定 iam-admin，人类令牌不进浏览器")
@RestController
@RequestMapping("/web-api/auth")
public class WebApiAuthController {

    /** 本适配层为浏览器管理台签发的会话受众，固定值，防止客户端伪造受众。 */
    private static final String ADMIN_AUDIENCE = "iam-admin";

    /** 中央会话权威服务。 */
    private final SessionService sessionService;
    /** 浏览器句柄与会话服务。 */
    private final BrowserSessionService browserSessions;
    /** 管理端菜单目录。 */
    private final MenuCatalog menuCatalog;
    /** 会话与 CSRF Cookie 下发。 */
    private final WebCookies cookies;

    /**
     * 构造浏览器会话控制器。
     *
     * @param sessionService  会话与身份权威服务
     * @param browserSessions 浏览器句柄生命周期服务
     * @param menuCatalog     菜单目录装配器
     * @param cookies         Cookie 装配工具
     */
    public WebApiAuthController(SessionService sessionService,
                                BrowserSessionService browserSessions,
                                MenuCatalog menuCatalog,
                                WebCookies cookies) {
        this.sessionService = sessionService;
        this.browserSessions = browserSessions;
        this.menuCatalog = menuCatalog;
        this.cookies = cookies;
    }

    /**
     * 账号口令登录并绑定浏览器句柄。
     *
     * @param request  当前 HTTP 请求；CsrfOriginInterceptor 已把 CSRF 校验过的匿名句柄放入
     *                 {@link BrowserSessionInterceptor#HANDLE_RAW_ATTRIBUTE}，作为轮换绑定的旧句柄
     * @param response 当前 HTTP 响应；写入轮换后的会话句柄与 CSRF Cookie
     * @param body     登录请求（账号/口令/可选域）；{@code null} 或缺 account/password 返回 400
     * @return {@link WebLoginVO}：安全身份视图与会话到期时刻；不回传原始访问令牌
     */
    @Operation(summary = "浏览器登录",
            description = "公开端点（BrowserSessionInterceptor 排除）：受众固定 iam-admin，realm 缺省 workforce。"
                    + "口令核验成功后以防会话固定方式把 CSRF 阶段签发的匿名句柄原子绑定到真实会话并轮换。"
                    + "作为写操作仍需通过 Origin 同源 + X-CSRF-Token 双提交（先 GET /csrf 取匿名句柄）",
            security = {})
    @ApiResponse(responseCode = "200", description = "登录成功，返回身份视图并下发 HttpOnly 会话句柄 Cookie")
    @ApiResponse(responseCode = "400", description = "请求体缺失或 account/password/realm 不合法")
    @ApiResponse(responseCode = "401", description = "账号或口令错误（含账号停用，同一消息避免枚举）")
    @ApiResponse(responseCode = "403", description = "Origin 不同源或 CSRF 校验失败")
    @ApiResponse(responseCode = "429", description = "登录限流命中")
    @ApiResponse(responseCode = "503", description = "限流或会话依赖故障、会话二次校验不一致")
    @PostMapping("/login")
    public WebLoginVO login(HttpServletRequest request, HttpServletResponse response,
                                  @RequestBody(required = false) WebLoginDTO body) {
        if (body == null || body.account() == null || body.password() == null) {
            throw com.airagent.iam.web.error.ApiException.badRequest("account 与 password 必填");
        }
        String realm = body.realm() == null || body.realm().isBlank() ? "workforce" : body.realm();
        LoginVO result = sessionService.login(
                new LoginDTO(body.account(), body.password(), realm, ADMIN_AUDIENCE));
        UUID sessionId = UUID.fromString(result.identity().session().id());

        String oldRawHandle = (String) request.getAttribute(BrowserSessionInterceptor.HANDLE_RAW_ATTRIBUTE);
        BrowserSessionService.IssuedHandle bound = browserSessions.bind(oldRawHandle, sessionId);
        cookies.issueSession(response, bound.rawHandle());
        cookies.issueCsrf(response, bound.csrfToken());
        return new WebLoginVO(result.identity(), result.identity().session().expiresAt());
    }

    /**
     * 退出当前会话。
     *
     * @param request  当前 HTTP 请求；读取已核验会话与句柄原始值
     * @param response 当前 HTTP 响应；即刻失效会话句柄与 CSRF Cookie
     * @return 204 空响应体
     */
    @Operation(summary = "退出当前浏览器会话",
            description = "需有效会话 Cookie；写操作需 Origin + X-CSRF-Token。撤销权威会话（原因 user.logout）并吊销句柄，"
                    + "中央会话退出经数据库触发器同步撤销同一中央会话下派生的应用子会话",
            security = {@SecurityRequirement(name = "browserCookie")})
    @ApiResponse(responseCode = "204", description = "登出成功（幂等）")
    @ApiResponse(responseCode = "401", description = "会话句柄缺失或已失效")
    @ApiResponse(responseCode = "403", description = "Origin/CSRF 校验失败")
    @ApiResponse(responseCode = "503", description = "Redis/PG 依赖故障")
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response) {
        CurrentSession current = current(request);
        String rawHandle = (String) request.getAttribute(BrowserSessionInterceptor.HANDLE_RAW_ATTRIBUTE);
        sessionService.logout(current);
        browserSessions.revoke(rawHandle);
        cookies.expireSession(response);
        cookies.expireCsrf(response);
        return ResponseEntity.noContent().build();
    }

    /**
     * 退出当前用户的全部会话（含当前会话）。
     *
     * @param request  当前 HTTP 请求；读取已核验会话与句柄原始值
     * @param response 当前 HTTP 响应；即刻失效本地 Cookie
     * @return 204 空响应体
     */
    @Operation(summary = "退出该用户全部会话",
            description = "需有效会话 Cookie；写操作需 Origin + X-CSRF-Token。数据库一次性置 revoked 并把用户授权代次 +1，"
                    + "同用户所有会话（含 SSO 派生子会话）即时失效",
            security = {@SecurityRequirement(name = "browserCookie")})
    @ApiResponse(responseCode = "204", description = "全部会话已撤销")
    @ApiResponse(responseCode = "401", description = "会话句柄缺失或已失效")
    @ApiResponse(responseCode = "403", description = "Origin/CSRF 校验失败")
    @ApiResponse(responseCode = "503", description = "Redis/PG 依赖故障")
    @PostMapping("/logout-all")
    public ResponseEntity<Void> logoutAll(HttpServletRequest request, HttpServletResponse response) {
        CurrentSession current = current(request);
        String rawHandle = (String) request.getAttribute(BrowserSessionInterceptor.HANDLE_RAW_ATTRIBUTE);
        sessionService.logoutAll(current);
        browserSessions.revoke(rawHandle);
        cookies.expireSession(response);
        cookies.expireCsrf(response);
        return ResponseEntity.noContent().build();
    }

    /**
     * 查询当前会话的实时身份视图。
     *
     * @param request 当前 HTTP 请求；读取已核验会话
     * @return 受众 {@code iam-admin} 的 {@link IdentityVO}
     */
    @Operation(summary = "查询当前身份",
            description = "需有效会话 Cookie；GET 属安全方法，不做 CSRF/Origin 检查。返回按 iam-admin 受众裁剪的实时身份视图",
            security = {@SecurityRequirement(name = "browserCookie")})
    @ApiResponse(responseCode = "200", description = "查询成功")
    @ApiResponse(responseCode = "401", description = "会话缺失/撤销/过期或授权代次变旧")
    @ApiResponse(responseCode = "403", description = "企业停用或成员关系停用")
    @ApiResponse(responseCode = "503", description = "Redis/PG 依赖故障")
    @GetMapping("/me")
    public IdentityVO me(HttpServletRequest request) {
        return sessionService.identityOf(current(request));
    }

    /**
     * 列出当前用户可切入的企业。
     *
     * @param request 当前 HTTP 请求；读取已核验会话
     * @return 按企业 code 升序的活跃企业列表；无可用企业时为空列表
     */
    @Operation(summary = "列出可切入的企业",
            description = "需有效会话 Cookie。企业列表由数据库在用户自身上下文（平台标志关闭）下按 RLS 裁决，"
                    + "仅返回活跃企业且当前用户为活跃成员者",
            security = {@SecurityRequirement(name = "browserCookie")})
    @ApiResponse(responseCode = "200", description = "查询成功（可能为空列表）")
    @ApiResponse(responseCode = "401", description = "会话不可用")
    @ApiResponse(responseCode = "403", description = "企业或成员关系已停用")
    @ApiResponse(responseCode = "503", description = "依赖故障")
    @GetMapping("/tenants")
    public List<TenantMembershipVO> tenants(HttpServletRequest request) {
        return sessionService.tenants(current(request));
    }

    /**
     * 按当前权限快照返回前端菜单树。
     *
     * @param request 当前 HTTP 请求；读取已核验会话的权威快照
     * @return {@link MenuCatalog} 装配的 {@code {application, items}} 结构；仅作 UX 提示，
     *         端点权限仍独立裁决
     */
    @Operation(summary = "获取前端菜单目录",
            description = "需有效会话 Cookie。按实时权限码给出可见菜单分组：平台分组对超管或持 platform:*:read 者开放，"
                    + "企业分组仅在已选企业时出现。切企业后需重新拉取以反映新上下文权限",
            security = {@SecurityRequirement(name = "browserCookie")})
    @ApiResponse(responseCode = "200", description = "查询成功")
    @ApiResponse(responseCode = "401", description = "会话不可用")
    @ApiResponse(responseCode = "403", description = "企业或成员关系已停用")
    @ApiResponse(responseCode = "503", description = "依赖故障")
    @GetMapping("/menus")
    public Map<String, Object> menus(HttpServletRequest request) {
        return menuCatalog.build(current(request).snapshot());
    }

    /**
     * 切换当前企业并返回切换后的身份视图。
     *
     * @param request 当前 HTTP 请求；读取已核验会话与句柄行（用于滑动 TTL）
     * @param body    目标企业与期望上下文代次；{@code null} 或缺字段返回 400
     * @return 切换后的实时 {@link IdentityVO}（{@code contextVersion} 已递增）
     */
    @Operation(summary = "切换当前企业",
            description = "需有效会话 Cookie；写操作需 Origin + X-CSRF-Token。对中央会话执行一次 ctx_version CAS，"
                    + "变更经 auth_sessions_synchronize_central 触发器原子传播到同一中央会话下的派生应用子会话；"
                    + "成功即推进纪元，前端须以返回体的新纪元作为后续续期/切企业基线",
            security = {@SecurityRequirement(name = "browserCookie")})
    @ApiResponse(responseCode = "200", description = "切换成功，返回刷新后的身份视图")
    @ApiResponse(responseCode = "400", description = "请求体/字段缺失或 tenant_id 非 UUID")
    @ApiResponse(responseCode = "401", description = "会话不可用")
    @ApiResponse(responseCode = "403", description = "目标企业不可用或非有效成员，或 CSRF 校验失败")
    @ApiResponse(responseCode = "409", description = "上下文代次冲突，请刷新身份后重试")
    @ApiResponse(responseCode = "503", description = "Redis/PG 依赖故障")
    @PostMapping("/switch-tenant")
    public IdentityVO switchTenant(HttpServletRequest request,
                                         @RequestBody(required = false) SwitchTenantDTO body) {
        CurrentSession current = current(request);
        sessionService.switchTenant(current, body);
        CurrentSession fresh = sessionService.requireCurrentBySessionId(current.sessionId());
        BrowserHandleRow row = (BrowserHandleRow) request
                .getAttribute(BrowserSessionInterceptor.HANDLE_ROW_ATTRIBUTE);
        browserSessions.touch(row);
        return sessionService.identityOf(fresh);
    }

    /**
     * 续期当前会话的空闲窗口并返回新时限与刷新后的身份视图。
     *
     * @param request 当前 HTTP 请求；读取已核验会话
     * @param body    期望上下文代次；{@code null} 或缺字段返回 400
     * @return {@link WebRenewVO}：绝对与空闲到期时刻加续期后身份视图
     */
    @Operation(summary = "续期会话空闲窗口",
            description = "需有效会话 Cookie；写操作需 Origin + X-CSRF-Token。数据库持锁后取 "
                    + "GREATEST(原空闲截止, 锁后时刻 + renewIdleSeconds) 并被绝对上限夹住——续期单调不减、可安全重试，"
                    + "绝不延长绝对到期；已撤销/过期会话一律拒绝（不存在复活）",
            security = {@SecurityRequirement(name = "browserCookie")})
    @ApiResponse(responseCode = "200", description = "续期成功")
    @ApiResponse(responseCode = "400", description = "expected_ctx_version 缺失")
    @ApiResponse(responseCode = "401", description = "会话不可用，或已撤销/过期而不可复活")
    @ApiResponse(responseCode = "403", description = "企业或成员关系停用，或 CSRF 校验失败")
    @ApiResponse(responseCode = "409", description = "上下文代次冲突")
    @ApiResponse(responseCode = "503", description = "Redis/PG 依赖故障")
    @PostMapping("/renew")
    public WebRenewVO renew(HttpServletRequest request,
                                  @RequestBody(required = false) RenewDTO body) {
        CurrentSession current = current(request);
        SessionTimersVO timers = sessionService.renew(current, body);
        CurrentSession fresh = sessionService.requireCurrentBySessionId(current.sessionId());
        return new WebRenewVO(timers.absoluteExpiresAt(), timers.idleExpiresAt(),
                sessionService.identityOf(fresh));
    }

    /**
     * 本人改密（改密即撤销该用户全部活跃会话）。
     *
     * @param request 当前 HTTP 请求；读取已核验会话
     * @param body    旧口令与新口令；{@code null} 或缺字段返回 400
     * @return 204 空响应体；改密后旧令牌全部失效，前端须引导重新登录
     */
    @Operation(summary = "本人修改口令",
            description = "需有效会话 Cookie；写操作需 Origin + X-CSRF-Token。先撤销该用户全部活跃会话"
                    + "（原因 user.password_change，含当前会话与派生子会话）再写新摘要，改密后旧令牌立即失效",
            security = {@SecurityRequirement(name = "browserCookie")})
    @ApiResponse(responseCode = "204", description = "改密成功，当前会话已被撤销")
    @ApiResponse(responseCode = "400", description = "字段缺失或新口令长度不合法")
    @ApiResponse(responseCode = "401", description = "旧口令不正确")
    @ApiResponse(responseCode = "403", description = "CSRF 校验失败")
    @ApiResponse(responseCode = "409", description = "新口令与旧口令相同")
    @ApiResponse(responseCode = "503", description = "Redis/PG 依赖故障")
    @PostMapping("/change-password")
    public ResponseEntity<Void> changePassword(HttpServletRequest request,
                                               @RequestBody(required = false) ChangePasswordDTO body) {
        sessionService.changePassword(current(request), body);
        return ResponseEntity.noContent().build();
    }

    /**
     * 取回 {@link BrowserSessionInterceptor} 注入的请求级会话快照。
     *
     * <p>与 Bearer 链路共用同一 attribute key；仅在受保护路径且核验通过时非空，
     * 未注入时返回 {@code null}，由服务层按未授权拒绝。
     *
     * @param request 当前 HTTP 请求
     * @return 已核验的 {@link CurrentSession}，可能为 {@code null}
     */
    private CurrentSession current(HttpServletRequest request) {
        return (CurrentSession) request.getAttribute(BearerAuthInterceptor.CURRENT_SESSION_ATTRIBUTE);
    }

    /**
     * 从 Cookie 数组按<em>精确名</em>取原始值（通用工具，当前未被本类调用）。
     *
     * @param requestCookies 请求 Cookie 数组；{@code null} 视为无 Cookie
     * @param name           目标 Cookie 名
     * @return 首个非空非空白同名 Cookie 的值；无匹配返回 {@code null}
     */
    private String findCookie(jakarta.servlet.http.Cookie[] requestCookies, String name) {
        if (requestCookies == null) {
            return null;
        }
        for (jakarta.servlet.http.Cookie cookie : requestCookies) {
            if (name.equals(cookie.getName()) && cookie.getValue() != null && !cookie.getValue().isBlank()) {
                return cookie.getValue();
            }
        }
        return null;
    }
}
