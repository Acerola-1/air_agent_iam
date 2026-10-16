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
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
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
 * 服务账号与凭据管理 HTTP 入口（Controller 层，不访问数据库）。
 *
 * <p>挂载在两条路径上，对应两个鉴权面（拦截器注册见
 * {@link com.airagent.iam.config.WebMvcConfiguration}）：
 * <ul>
 *   <li>{@code /v1/admin/service-accounts**} —— 人类 Bearer：经
 *       {@link BearerAuthInterceptor} 校验 {@code Authorization} 头携带的 Sa-Token；</li>
 *   <li>{@code /web-api/admin/service-accounts**} —— 浏览器会话：经 BrowserSessionInterceptor
 *       校验会话 Cookie，并由 CsrfOriginInterceptor 对写操作做同源防护。</li>
 * </ul>
 * 两面的能力与权限完全相同，只有凭据载体不同。
 *
 * <p>本层只做会话提取与参数透传：权限码 {@code platform:service:write} 的裁决、租户上下文、
 * 事务与审计全部在 {@link ServiceAccountService} 实现层完成。前端菜单/按钮的显隐只是提示，
 * 不能替代后端权限，因此每个操作都会重新裁决。
 *
 * <p>凭据边界：明文密钥只在 {@code POST /{id}/tokens} 的响应体中出现一次，服务端不留副本、
 * 无任何接口可再次读取；列表与详情只返回凭据元数据。未认证请求（拦截器判定）返回 401，
 * 其余错误统一由 GlobalExceptionHandler 转为错误信封（HTTP 状态见各操作的
 * {@code @ApiResponse}）。
 *
 * @author Acerola
 */
@Tag(name = "服务账号与凭据管理",
        description = "平台级服务账号的建档、分页查询、详情、停用/启用，以及凭据签发与吊销。"
                + "所有操作需平台权限 platform:service:write；人类 Bearer 与浏览器会话两条路径能力相同")
@RestController
@RequestMapping({"/v1/admin/service-accounts", "/web-api/admin/service-accounts"})
public class ServiceAccountAdminController {

    /** 服务账号业务服务。 */
    private final ServiceAccountService service;

    /**
     * 构造服务账号管理控制器。
     *
     * @param service 服务账号与凭据业务服务（权限裁决与事务在服务层）
     */
    public ServiceAccountAdminController(ServiceAccountService service) {
        this.service = service;
    }

    /**
     * keyset 分页拉取服务账号列表。
     *
     * @param tenantId 可选企业过滤（UUID 文本）；{@code null} 或空白表示不按企业过滤，非 UUID 返回 400；
     *                 企业不存在时不报错，只返回空页
     * @param limit    单页条数；{@code null} 时取默认 20，合法范围 1..200，越界返回 400
     * @param cursor   不透明游标（上一页末行 id 的 base64url 编码）；{@code null} 或空白表示从首页开始
     * @return 当前页 {@link PageVO}；无匹配数据时 {@code items} 为空列表，无后续数据时
     *         {@code nextCursor} 为 {@code null}
     * @param request 当前 HTTP 请求（会话快照由拦截器注入请求属性）
     */
    @Operation(summary = "分页列出服务账号",
            description = "需要 platform:service:write 权限。按 id 升序 keyset 分页，可选按企业过滤；"
                    + "平台上下文可见全部企业的服务账号。响应只含账号元数据，不含任何凭据摘要或明文。",
            security = {@SecurityRequirement(name = "humanBearer"), @SecurityRequirement(name = "browserCookie")})
    @ApiResponse(responseCode = "200", description = "查询成功（可能为空列表）")
    @ApiResponse(responseCode = "400", description = "limit 越界、cursor 不合法或 tenant_id 非 UUID")
    @ApiResponse(responseCode = "403", description = "缺少权限")
    @GetMapping
    public PageVO<ServiceAccountVO> list(HttpServletRequest request,
                                        @Parameter(description = "按企业 UUID 过滤；省略则返回全部可见账号")
                                        @RequestParam(value = "tenant_id", required = false) String tenantId,
                                        @Parameter(description = "单页条数 1..200，缺省 20")
                                        @RequestParam(value = "limit", required = false) Integer limit,
                                        @Parameter(description = "上一页 nextCursor 原样回传；首页省略")
                                        @RequestParam(value = "cursor", required = false) String cursor) {
        return service.list(current(request), tenantId, limit, cursor);
    }

    /**
     * 创建服务账号（不签发凭据）。
     *
     * <p>请求体可缺省（{@code required = false}），缺省由服务层判为 400。
     *
     * @param body 建档请求（账号名、显示名、所属企业、受众、有效期天数、权限码）
     * @return 新建账号视图；HTTP 状态为 200（本控制器未显式改写为 201），
     *         {@code status} 恒为 {@code active}、{@code revision} 恒为 1
     * @param request 当前 HTTP 请求（会话快照由拦截器注入请求属性）
     */
    @Operation(summary = "创建服务账号",
            description = "需要 platform:service:write 权限。账号名需为 sa- 前缀且全库唯一；"
                    + "目标企业必须处于 active 状态，否则 400。有效期 1..365 天（缺省 90 天）。"
                    + "权限码只能取企业域、非资源型且已启用的权限，未知或越界整体 400。"
                    + "本操作只建账号主体，不返回任何凭据：凭据需另行调用签发接口。",
            security = {@SecurityRequirement(name = "humanBearer"), @SecurityRequirement(name = "browserCookie")})
    @ApiResponse(responseCode = "200", description = "创建成功（返回账号视图，不含凭据）")
    @ApiResponse(responseCode = "400", description = "请求体缺失、account/name/tenant_id/expires_in_days 不合法、"
            + "受众或权限码不合法或目标企业未处于 active 状态")
    @ApiResponse(responseCode = "403", description = "缺少权限")
    @ApiResponse(responseCode = "409", description = "账号名唯一冲突，或违反数据库业务约束（如有效期硬顶、资源型权限边界）")
    @PostMapping
    public ServiceAccountVO create(HttpServletRequest request,
                                   @RequestBody(required = false) CreateServiceAccountDTO body) {
        return service.create(current(request), body);
    }

    /**
     * 按 id 查询服务账号详情（含凭据元数据列表）。
     *
     * @param id 服务账号 UUID 文本；非 UUID 返回 400
     * @return {@link ServiceAccountDetailVO}：账号视图 + 该账号全部凭据的元数据
     *         （按签发时间倒序，从未签发时为空列表；任何情况下都不含摘要与明文）
     * @param request 当前 HTTP 请求（会话快照由拦截器注入请求属性）
     */
    @Operation(summary = "查询服务账号详情",
            description = "需要 platform:service:write 权限。凭据列表经受控函数 iam_auth.list_service_tokens 读取"
                    + "（service_tokens 对请求角色默认拒绝直读），只返回 credential_id、状态与时间列，"
                    + "不含 token_digest 与明文密钥。",
            security = {@SecurityRequirement(name = "humanBearer"), @SecurityRequirement(name = "browserCookie")})
    @ApiResponse(responseCode = "200", description = "查询成功")
    @ApiResponse(responseCode = "400", description = "id 不是合法 UUID")
    @ApiResponse(responseCode = "403", description = "缺少权限")
    @ApiResponse(responseCode = "404", description = "服务账号不存在或不可见")
    @GetMapping("/{id}")
    public ServiceAccountDetailVO get(HttpServletRequest request,
                                      @Parameter(description = "服务账号 UUID") @PathVariable("id") String id) {
        return service.get(current(request), id);
    }

    /**
     * 停用或重新启用服务账号。
     *
     * @param id   服务账号 UUID 文本；非 UUID 返回 400
     * @param body 目标状态请求；{@code null} 或非法 status 返回 400
     * @return 变更后的账号视图（{@code revision} 较变更前 +1）
     * @param request 当前 HTTP 请求（会话快照由拦截器注入请求属性）
     */
    @Operation(summary = "停用或启用服务账号",
            description = "需要 platform:service:write 权限。status 仅接受 active/disabled（数据库另有 revoked 取值，"
                    + "但本接口不设置，永久吊销请逐个吊销凭据）。停用不删除既有凭据，"
                    + "但下次凭据核验即返回 account_disabled，属即时生效。"
                    + "每次成功调用都会把账号 revision +1，且不提供 expected_revision 乐观并发基线。",
            security = {@SecurityRequirement(name = "humanBearer"), @SecurityRequirement(name = "browserCookie")})
    @ApiResponse(responseCode = "200", description = "状态变更成功")
    @ApiResponse(responseCode = "400", description = "请求体缺失、status 非 active/disabled 或 id 非 UUID")
    @ApiResponse(responseCode = "403", description = "缺少权限")
    @ApiResponse(responseCode = "404", description = "服务账号不存在或不可见")
    @PatchMapping("/{id}")
    public ServiceAccountVO updateStatus(HttpServletRequest request,
                                         @Parameter(description = "服务账号 UUID") @PathVariable("id") String id,
                                         @RequestBody(required = false) UpdateServiceAccountDTO body) {
        return service.updateStatus(current(request), id, body);
    }

    /**
     * 为服务账号签发新凭据（轮换即再调用本接口）。
     *
     * <p>返回体中的明文密钥是服务端唯一一次披露，之后任何接口都无法再次取回。
     *
     * @param serviceAccountId 服务账号 UUID 文本；非 UUID 返回 400，不存在返回 404
     * @param body             重叠窗口请求；可为 {@code null}（等价零窗口：旧凭据立即撤销）
     * @return 凭据签发结果（含一次性明文密钥、到期时间与施加于旧凭据的重叠上界）
     * @param request 当前 HTTP 请求（会话快照由拦截器注入请求属性）
     */
    @Operation(summary = "签发服务账号凭据",
            description = "需要 platform:service:write 权限。新凭据有效期固定为签发时刻 +90 天，"
                    + "并被账号到期时间与 365 天硬顶截断，调用方不可指定。overlap_hours 为 0..24（小时），"
                    + "缺省或 0 表示零窗口：此前所有活跃凭据立即转为 revoked。窗口大于 0 时旧凭据保持 active，"
                    + "但 overlap_until 被写在旧凭据上、从本次轮换时刻起算，到期即判无效。"
                    + "库内只存 SHA-256 摘要，明文密钥仅在本次响应体中出现一次，不可再次读取。",
            security = {@SecurityRequirement(name = "humanBearer"), @SecurityRequirement(name = "browserCookie")})
    @ApiResponse(responseCode = "200", description = "签发成功（响应体含一次性明文密钥）")
    @ApiResponse(responseCode = "400", description = "service_account_id 非 UUID 或 overlap_hours 越界")
    @ApiResponse(responseCode = "401", description = "签发函数判定账号已停用/已到期或所属企业不可用")
    @ApiResponse(responseCode = "403", description = "缺少权限")
    @ApiResponse(responseCode = "404", description = "服务账号不存在")
    @ApiResponse(responseCode = "409", description = "违反凭据到期或重叠窗口的数据库约束，或凭据标识/摘要唯一冲突")
    @PostMapping("/{id}/tokens")
    public ServiceTokenIssuedVO issueToken(HttpServletRequest request,
                                           @Parameter(description = "服务账号 UUID")
                                           @PathVariable("id") String serviceAccountId,
                                           @RequestBody(required = false) CreateServiceTokenDTO body) {
        return service.issueToken(current(request), serviceAccountId, body);
    }

    /**
     * 吊销单个凭据。
     *
     * @param credentialId 凭据标识（{@code sak_} + 32 位小写十六进制）；格式不符返回 400
     * @return 204 空响应体；吊销为幂等操作，标识合法但不存在或已吊销时同样返回 204
     * @param request 当前 HTTP 请求（会话快照由拦截器注入请求属性）
     */
    @Operation(summary = "吊销服务账号凭据",
            description = "需要 platform:service:write 权限。经 iam_auth.revoke_service_token 将状态由 active 置为 "
                    + "revoked 并写入 revoked_at；已是 revoked 的凭据不再变更，也不校验标识是否存在（幂等，无 404）。"
                    + "吊销后凭据在下次核验即失效，不涉及会话存储删除：服务凭据核验每次读主库、无正向缓存。"
                    + "成功返回 204，不回显任何凭据信息。",
            security = {@SecurityRequirement(name = "humanBearer"), @SecurityRequirement(name = "browserCookie")})
    @ApiResponse(responseCode = "204", description = "吊销成功（含幂等重复调用）")
    @ApiResponse(responseCode = "400", description = "credential_id 格式不合法")
    @ApiResponse(responseCode = "403", description = "缺少权限")
    @PostMapping("/tokens/{credentialId}/revoke")
    public ResponseEntity<Void> revokeToken(HttpServletRequest request,
                                            @Parameter(description = "凭据标识，形如 sak_ 加 32 位小写十六进制")
                                            @PathVariable("credentialId") String credentialId) {
        service.revokeToken(current(request), credentialId);
        return ResponseEntity.noContent().build();
    }

    /**
     * 取回拦截器注入的请求级会话快照。
     *
     * <p>仅对受保护路径有效；快照已经过 Redis Sa-Token 与 PG 权威双重核验。
     * 若拦截器未注入（配置外路径），返回 {@code null}，由服务层按缺少权限拒绝（403）。
     *
     * @param request 当前 HTTP 请求
     * @return 已核验的 {@link CurrentSession}，可能为 {@code null}
     */
    private CurrentSession current(HttpServletRequest request) {
        return (CurrentSession) request.getAttribute(BearerAuthInterceptor.CURRENT_SESSION_ATTRIBUTE);
    }
}
