package com.airagent.iam.internal.controller;

import com.airagent.iam.internal.dto.IntrospectDTO;
import com.airagent.iam.internal.dto.RuntimeTicketDTO;
import com.airagent.iam.internal.dto.TenantStatusDTO;
import com.airagent.iam.internal.service.IntrospectionService;
import com.airagent.iam.internal.service.RuntimeTicketService;
import com.airagent.iam.internal.vo.RuntimeTicketVO;
import com.airagent.iam.internal.vo.TenantStatusVO;
import com.airagent.iam.security.internal.InternalClientInterceptor;
import com.airagent.iam.web.RequestIdFilter;
import com.airagent.iam.web.async.IdentityDeadlineExecutor;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.async.DeferredResult;

/**
 * 内部端点 HTTP 入口（Controller 层，不访问数据库、不做任何授权判定）。
 *
 * <p>分层位置：{@code /v1/internal} 是第三鉴权面——调用方是<b>已登记的内部客户端</b>
 * （realm {@code internal_client}），不是人类会话。本层只做凭据透传、请求体接收与
 * 异步派发；受众白名单、scope、限流、主体实时核验与票据签发全部在
 * {@link IntrospectionService} / {@link RuntimeTicketService} 的实现层完成。
 *
 * <p>双主体边界（不得混淆）：{@code Authorization} 头认证的是"调用服务"，请求体里的
 * {@code subject_token} 才是被核验的人类会话令牌或服务账号令牌；凭据错误是 401/403，
 * 主体无效则按契约返回 {@code active:false} 的 200，消费方不得把 HTTP 200 当业务成功。
 *
 * <p>认证与限流的执行位置：{@link InternalClientInterceptor} 未注册到本路径的拦截器链，
 * 凭据核验、scope 裁决与按客户端准入限流由本层在
 * {@link InternalClientInterceptor#authenticateAndAuthorize(String, String)} 中显式调用，
 * 并置于 {@link IdentityDeadlineExecutor} 的端到端预算之内（预算含认证耗时）。
 * 响应统一 {@code Cache-Control: no-store}（由 {@link RequestIdFilter} 全局写入）。
 *
 * <p>失败关闭：核验超时、后台容量耗尽、Redis/PG 依赖故障一律 503，绝不退化为放行。
 * 异常统一由 GlobalExceptionHandler 转为错误信封，各操作实际 HTTP 码见 {@code @ApiResponse}。
 *
 * @author Acerola
 */
@Tag(name = "内部身份核验与签票",
        description = "已登记内部客户端专用：主体令牌实时内省（含执行复查上下文与引用复查模式）与 rt-v1 运行短票据签发。"
                + "凭据认证的是调用服务，subject_token 是被核验主体，两个主体不可混用")
@RestController
@RequestMapping("/v1/internal")
public class InternalApiController {

    /** 主体实时核验用例入口（令牌内省与执行引用复查）。 */
    private final IntrospectionService introspectionService;
    /** rt-v1 运行票据签发用例入口。 */
    private final RuntimeTicketService runtimeTicketService;
    /** 内部客户端凭据核验 + scope 裁决 + 按客户端准入限流，在本层显式调用。 */
    private final InternalClientInterceptor clientAuthorization;
    /** 身份核验总预算执行器，把用例放入虚拟线程并保证超时失败关闭。 */
    private final IdentityDeadlineExecutor deadlineExecutor;

    /**
     * 构造内部端点控制器，全部依赖经 Spring 构造注入。
     *
     * @param introspectionService 主体实时核验服务（人类令牌、服务账号令牌、执行引用复查三种形态）
     * @param runtimeTicketService rt-v1 运行票据签发服务
     * @param clientAuthorization  内部客户端凭据核验 + scope 裁决 + 准入限流组件，在异步预算内显式调用
     * @param deadlineExecutor     身份核验总预算执行器（虚拟线程 + 有界并发，超时失败关闭）
     */
    public InternalApiController(IntrospectionService introspectionService,
                                 RuntimeTicketService runtimeTicketService,
                                 InternalClientInterceptor clientAuthorization, IdentityDeadlineExecutor deadlineExecutor) {
        this.introspectionService = introspectionService;
        this.runtimeTicketService = runtimeTicketService;
        this.clientAuthorization = clientAuthorization;
        this.deadlineExecutor = deadlineExecutor;
    }

    /**
     * 主体令牌实时核验 / 已核验执行上下文复查。
     *
     * <p>请求体两形态互斥（同时给出或同时缺失返回 400）：
     * <ul>
     *   <li>{@code subject_token} 形态——核验人类会话令牌或服务账号令牌，有效时返回
     *       身份视图（{@code iam.identity.v1} 或机器主体视图），无效时返回
     *       {@code active:false} 的 {@code iam.introspection.v1}；
     *       {@code include_execution_context=true} 时额外附带一次性登记的执行上下文
     *       {@code execution_context}（仅 runtime 受众可用）；</li>
     *   <li>{@code execution_context} 形态——凭先前登记的 {@code verification_ref} 复查
     *       原会话的实时权威状态，返回 {@code context_matches} 结论，不重新授予更大权限。</li>
     * </ul>
     *
     * @param request 当前 HTTP 请求，用于取 {@code Authorization} 凭据与请求起始时刻
     * @param body    核验请求；{@code null} 请求体返回 400
     * @return 异步结果，实际体为多态形态之一（身份视图 / inactive 信封 / 复查结论 /
     *         identity 与 execution_context 的合并对象），见 {@code @ApiResponse} 说明
     */
    @Operation(summary = "主体令牌内省（token 模式与执行引用复查模式）",
            description = "需要客户端 scope identity:introspect，且请求受众在该客户端的注册受众白名单内（否则 403）。"
                    + "每次调用都实时读取 PostgreSQL 主库权威快照（iam_auth.load_trusted_authority_snapshot），"
                    + "人类主体另加 Redis Sa-Token 存活性检查，跨请求不缓存任何正向授权结果。"
                    + "响应结构随形态变化，故 OpenAPI 无法给出固定 schema。",
            security = {@SecurityRequirement(name = "internalClient")})
    @ApiResponse(responseCode = "200", description = "核验完成——active 身份视图、inactive 信封（active:false）"
            + "或复查结论（active / context_matches）；inactive 不是错误，消费方须自行映射 401/403")
    @ApiResponse(responseCode = "400", description = "audience 缺失或空白；subject_token 与 execution_context 未做到二选一；"
            + "verification_ref 缺失；expected_revisions 四项未齐；UUID 文本不合法；"
            + "include_execution_context 被非 runtime 受众使用；服务账号携带 expected_context/执行上下文")
    @ApiResponse(responseCode = "401", description = "客户端凭据无效、编码不合法或客户端已停用；引用登记时会话已不存在/已撤销")
    @ApiResponse(responseCode = "403", description = "客户端缺少所需 scope、端点未注册、客户端未注册该受众、"
            + "主体令牌受众与请求受众不一致、服务账号未注册该受众")
    @ApiResponse(responseCode = "409", description = "expected_context 与会话当前企业/上下文代次不一致（失败关闭，不回新上下文）")
    @ApiResponse(responseCode = "429", description = "命中按客户端的准入限流（固定窗口，默认每窗口 internal-limit 次）")
    @ApiResponse(responseCode = "503", description = "核验总预算超时/容量耗尽，或 Redis、PostgreSQL 依赖不可用（失败关闭）")
    @PostMapping("/identity/introspect")
    public DeferredResult<Object> introspect(HttpServletRequest request,
                             @RequestBody(required = false) IntrospectDTO body) {
        String authorization = request.getHeader("Authorization");
        String uri = request.getRequestURI();
        return deadlineExecutor.execute(started(request), () -> introspectionService.introspect(
                clientAuthorization.authenticateAndAuthorize(authorization, uri), body));
    }

    /**
     * 签发 rt-v1 运行短票据（供下游运行时作为入口凭据使用）。
     *
     * <p>签发前对 {@code subject_token} 做与内省同一套实时权威核验（PG 快照 + Redis 存活）；
     * 只有人类会话令牌可换票，服务账号等机器令牌一律拒绝。票据有效期取
     * 配置 TTL（上界 60 秒）与会话 idle/absolute 最早到期时刻的较小值。
     *
     * @param request 当前 HTTP 请求，用于取 {@code Authorization} 凭据与请求起始时刻
     * @param body    签票请求；{@code null} 请求体返回 400
     * @return 异步结果，成功为 {@link RuntimeTicketVO}（票据、{@code Bearer}、UTC 到期文本、剩余秒数、受众、格式）
     */
    @Operation(summary = "签发 rt-v1 运行票据",
            description = "需要客户端 scope runtime-ticket:issue，且客户端已注册 langgraph-runtime 受众（否则 403）。"
                    + "受众必须恰为 langgraph-runtime；签发前实时核验主体，target_tenant_id 或 expected_ctx_version 与会话当前状态"
                    + "不一致返回 409。票据正文含 sid/uid/tid/mid/aud/iat/exp 与四项修订，外层信封含 kid；"
                    + "票据原文不进审计与日志，审计仅记录 audience、目标企业与 TTL 秒数。",
            security = {@SecurityRequirement(name = "internalClient")})
    @ApiResponse(responseCode = "200", description = "签发成功")
    @ApiResponse(responseCode = "400", description = "subject_token 缺失或空白；audience 非 langgraph-runtime；"
            + "target_tenant_id / expected_ctx_version 缺失；target_tenant_id 不是合法 UUID")
    @ApiResponse(responseCode = "401", description = "客户端凭据无效；主体会话不存在、已撤销或账号已停用")
    @ApiResponse(responseCode = "403", description = "客户端未注册 langgraph-runtime 受众；企业上下文不可用（企业停用、"
            + "成员关系停用或不存在）；会话尚未选择企业；会话剩余有效期不足以签票")
    @ApiResponse(responseCode = "409", description = "target_tenant_id 或 expected_ctx_version 与当前会话权威状态不一致")
    @ApiResponse(responseCode = "429", description = "命中按客户端的准入限流（固定窗口，默认每窗口 internal-limit 次）")
    @ApiResponse(responseCode = "503", description = "rt-v1 签名密钥（kid/secret）未配置，或核验总预算超时、依赖不可用")
    @PostMapping("/runtime-tickets")
    public DeferredResult<RuntimeTicketVO> issueRuntimeTicket(HttpServletRequest request,
                                                    @RequestBody(required = false) RuntimeTicketDTO body) {
        String authorization = request.getHeader("Authorization");
        String uri = request.getRequestURI();
        return deadlineExecutor.execute(started(request), () -> runtimeTicketService.issue(
                clientAuthorization.authenticateAndAuthorize(authorization, uri), body));
    }

    /** Trusted internal status lookup used for reconciliation gates; the result grants no access. */
    @Operation(summary = "查询 IAM 企业当前可用状态",
            description = "需要内部客户端 scope tenant:status:read；只返回指定 UUID 的实时 active 状态，不接受业务库引用投影作为授权依据。",
            security = {@SecurityRequirement(name = "internalClient")})
    @ApiResponse(responseCode = "200", description = "返回 iam.tenant-status.v1 实时状态")
    @ApiResponse(responseCode = "400", description = "请求体或 tenant_id 缺失")
    @ApiResponse(responseCode = "401", description = "内部客户端凭据无效")
    @ApiResponse(responseCode = "403", description = "客户端缺少 tenant:status:read scope")
    @ApiResponse(responseCode = "503", description = "IAM PostgreSQL 不可用")
    @PostMapping("/tenants/status")
    public DeferredResult<TenantStatusVO> tenantStatus(HttpServletRequest request,
            @RequestBody(required = false) TenantStatusDTO body) {
        if (body == null || body.tenantId() == null) {
            throw com.airagent.iam.web.error.ApiException.badRequest("tenant_id 必填");
        }
        String authorization = request.getHeader("Authorization");
        String uri = request.getRequestURI();
        return deadlineExecutor.execute(started(request), () -> {
            clientAuthorization.authenticateAndAuthorize(authorization, uri);
            boolean active = introspectionService.tenantIsActive(body.tenantId());
            return new TenantStatusVO("iam.tenant-status.v1", body.tenantId().toString(), active);
        });
    }

    /**
     * 取本次请求的起始时刻（纳秒单调时钟），用于计算剩余核验预算。
     *
     * <p>{@link RequestIdFilter} 在过滤链入口写入
     * {@link RequestIdFilter#STARTED_NANOS_ATTRIBUTE}；异步再派发或属性缺失时以当前时刻兜底，
     * 此时预算退化为完整窗口而非负值。
     *
     * @param request 当前 HTTP 请求
     * @return {@link System#nanoTime()} 口径的起始纳秒值（仅可用于求差，不是墙钟时间）
     */
    private long started(HttpServletRequest request) {
        Object value = request.getAttribute(RequestIdFilter.STARTED_NANOS_ATTRIBUTE);
        return value instanceof Long timestamp ? timestamp : System.nanoTime();
    }
}
