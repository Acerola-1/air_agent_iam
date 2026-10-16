package com.airagent.iam.webapi.sso.service.impl;

import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.auth.service.SessionService;
import com.airagent.iam.common.mapper.RequestContextMapper;
import com.airagent.iam.config.IamProperties;
import com.airagent.iam.security.internal.RateLimiter;
import com.airagent.iam.security.token.OpaqueTokens;
import com.airagent.iam.web.error.ApiException;
import com.airagent.iam.webapi.BrowserHandleRow;
import com.airagent.iam.webapi.sso.entity.SsoRegistrationDO;
import com.airagent.iam.webapi.sso.mapper.SsoMapper;
import com.airagent.iam.webapi.sso.service.SsoAuthorizeService;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Map;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * 中央 SSO 授权跳转的实现（Service 层，授权码/state 的<em>签发</em>侧）。
 *
 * <p>分层位置：{@link com.airagent.iam.webapi.sso.controller.SsoController} 的唯一下游；
 * 只经 {@link SsoMapper} 读写数据，且全部落在 SECURITY DEFINER 函数上
 * （{@code iam.sso_states}/{@code iam.sso_tickets} 开启 RLS 且无策略，无裸表 SQL）。
 *
 * <p>真实语义一句话：已登录的浏览器把一次性 {@code state} 交给中央，中央校验注册客户端后
 * 生成一次性 {@code ticket}，303 回到<em>精确</em>登记的回调并附带 {@code ticket} 与
 * {@code state} 原值；此后由消费方在服务端兑换，人类令牌全程不进 URL。
 *
 * <p>凭证与生命周期（本服务只登记、不消费；消费侧见
 * {@link com.airagent.iam.webapi.sso.service.impl.SsoExchangeServiceImpl}）：
 * <ul>
 *   <li>{@code state} 由消费方生成、原样回传，服务端只存其 SHA-256 摘要，TTL 取
 *       配置 {@code iam.sso.state-ttl-seconds}（缺省 600 秒）；</li>
 *   <li>{@code ticket} 由本方法以 {@link OpaqueTokens#newRawToken()} 生成，
 *       TTL 取 {@code iam.sso.ticket-ttl-seconds}（缺省 30 秒），行内直接绑定当前
 *       浏览器中央会话 id——它是"这个人类会话授权了这次兑换"的唯一凭据；</li>
 *   <li>两者各成一行、各自原子消费，登记在同一事务内完成并写一条
 *       {@code auth.sso_authorize} 审计；审计 detail 只含 client_id 与 redirect_uri，
 *       ticket 与 state 的原始值和摘要都不进审计。</li>
 * </ul>
 *
 * <p>时间与失败：到期时刻以 {@code OffsetDateTime.now(ZoneOffset.UTC)} 加 TTL 计算，
 * 落 {@code timestamptz} 列，比较由数据库按瞬时点完成，不受偏移量与本机时区影响。
 * 任何一步失败都抛 {@link ApiException} 走统一错误信封，<em>不</em>产生携带错误码的重定向；
 * 事务内异常（含审计失败）整体回滚，不会留下半个可用凭证。
 *
 * @author Acerola
 */
@Service
public class SsoAuthorizeServiceImpl implements SsoAuthorizeService {

    /** SSO 注册/状态/票据数据访问 */
    private final SsoMapper ssoMapper;
    /** 数据库请求上下文设置 */
    private final RequestContextMapper requestContextMapper;
    /** 编程式事务边界 */
    private final TransactionTemplate tx;
    /** 中央会话权威服务 */
    private final SessionService sessionService;
    /** iam.* 配置（state/ticket TTL、客户端注册表） */
    private final IamProperties props;
    /** 按客户端固定窗口限流 */
    private final RateLimiter rateLimiter;

    /**
     * 构造授权服务。
     *
     * @param ssoMapper            SSO 数据访问，state/ticket 的登记与客户端读取
     * @param requestContextMapper 事务内 RLS 上下文设置（同事务的审计写入需要它）
     * @param tx                   编程式事务边界，把两次登记与审计包成同一提交
     * @param sessionService       会话服务，仅用于以调用方事务写审计
     * @param props                {@code iam.*} 配置，取 {@code iam.sso} 的两段 TTL
     * @param rateLimiter          Redis 固定窗口限流，防止已登录会话反复批量签发 ticket
     */
    public SsoAuthorizeServiceImpl(SsoMapper ssoMapper, RequestContextMapper requestContextMapper, TransactionTemplate tx,
                               SessionService sessionService, IamProperties props,
                               RateLimiter rateLimiter) {
        this.ssoMapper = ssoMapper;
        this.requestContextMapper = requestContextMapper;
        this.tx = tx;
        this.sessionService = sessionService;
        this.props = props;
        this.rateLimiter = rateLimiter;
    }

    /**
     * {@inheritDoc}
     *
     * <p>实现顺序（每步都可能中断，且中断即不产生任何写入）：
     * <ol>
     *   <li>形状：三参数必填非空白，长度上界 client_id 128 / redirect_uri 512 / state 256，
     *       且 state 必须整体匹配 {@code \p{Graph}{1,256}}（禁空白与控制字符，便于安全拼接进 query）；</li>
     *   <li>注册：{@link SsoMapper#selectClient} 取行，缺行或 {@code status} 非 {@code active}
     *       返回同一句 400，未知客户端与已停用客户端不做区分；</li>
     *   <li>回调：{@code redirectUri.equals(callbackUrl)} 的<em>精确全串</em>比对，
     *       不做前缀、子域或通配匹配，因此 {@code .../callback} 不能替代 {@code .../callback/agent}；</li>
     *   <li>回环：{@link #assertLoopbackCallback} 强制本机回环 http；</li>
     *   <li>Origin：仅当头实际存在且非空白时判定，必须命中注册 {@code origins} 列表的精确元素；</li>
     *   <li>限流：按中央会话 id 计数，见下；</li>
     *   <li>登记与审计：单事务内 {@code setContext → saveState → saveTicket → audit}；</li>
     *   <li>拼接跳转：按 redirectUri 是否已含 {@code ?} 选分隔符，ticket 与 state 均 UTF-8 URL 编码。</li>
     * </ol>
     *
     * <p>限流口径：{@link RateLimiter#check} 以 {@link RateLimiter#SCOPE_INTERNAL} 域、
     * key {@code sso-start:<中央会话 id>} 计数，阈值取 {@code iam.rate-limit.internal-limit}
     * （缺省 600）每 {@code iam.rate-limit.window-seconds}（缺省 60 秒）一个固定窗口；
     * {@code iam.rate-limit.enabled=false} 时限流整体短路，Redis 连接失败按 503 失败关闭。
     */
    @Override
    public String authorize(CurrentSession current, BrowserHandleRow handle,
                            String clientId, String redirectUri, String state, String origin) {
        if (blank(clientId) || blank(redirectUri) || blank(state)) {
            throw ApiException.badRequest("client_id、redirect_uri、state 必填");
        }
        if (clientId.length() > 128 || redirectUri.length() > 512 || state.length() > 256
                || !state.matches("\\p{Graph}{1,256}")) {
            throw ApiException.badRequest("SSO 参数不合法");
        }
        SsoRegistrationDO client = ssoMapper.selectClient(clientId);
        if (client == null || !"active".equals(client.status())) {
            throw ApiException.badRequest("SSO 客户端不存在或已停用");
        }
        if (!redirectUri.equals(client.callbackUrl())) {
            throw ApiException.badRequest("redirect_uri 与注册回调不一致");
        }
        assertLoopbackCallback(redirectUri);
        if (origin != null && !origin.isBlank() && !client.origins().contains(origin)) {
            throw ApiException.forbidden("Origin 未注册到该 SSO 客户端");
        }

        rateLimiter.check(RateLimiter.SCOPE_INTERNAL, "sso-start:" + current.sessionId());

        String ticket = OpaqueTokens.newRawToken();
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        OffsetDateTime stateExpires = now.plusSeconds(props.sso().stateTtlSeconds());
        OffsetDateTime ticketExpires = now.plusSeconds(props.sso().ticketTtlSeconds());

        tx.executeWithoutResult(status -> {
            requestContextMapper.setContext(current.userId(), current.currentTenantId(),
                    current.currentTenantId() == null);
            ssoMapper.saveState(OpaqueTokens.digest(state), clientId, handle.digest(), redirectUri, stateExpires);
            ssoMapper.saveTicket(OpaqueTokens.digest(ticket), clientId, current.sessionId(), redirectUri, ticketExpires);
            sessionService.audit(current.currentTenantId(), current.userId(),
                    "auth.sso_authorize", "auth_session", current.sessionId().toString(),
                    Map.of("client_id", clientId, "redirect_uri", redirectUri));
        });

        String separator = redirectUri.contains("?") ? "&" : "?";
        return redirectUri + separator
                + "ticket=" + URLEncoder.encode(ticket, StandardCharsets.UTF_8)
                + "&state=" + URLEncoder.encode(state, StandardCharsets.UTF_8);
    }

    /**
     * 域名未定阶段的回调落地限制：只允许本机回环 http，禁止任意外部跳转。
     *
     * <p>三重合取条件全部满足才放行：scheme 为 {@code http}（大小写不敏感）、host 可解析且
     * 非空、host 命中 {@code 127.0.0.1} / {@code localhost} / {@code [::1]} /
     * {@code 0:0:0:0:0:0:0:1} 四个字面量之一（IPv6 字面量按 {@link URI#getHost()} 的带方括号形式比较）。
     * 端口不参与判定，因此回环上的任意端口都可作为回调宿主；真正的地址约束仍由上层的
     * 精确 {@code callback_url} 比对决定，本方法只是叠加一层"不外跳"的纵深防御。
     *
     * @param redirectUri 已通过注册精确匹配的回调地址；此处只做结构与宿主判定
     * @throws ApiException 400 地址无法按 URI 解析（{@code URI.create} 抛
     *                      {@link IllegalArgumentException}），或 scheme/宿主不满足回环 http 条件
     */
    private void assertLoopbackCallback(String redirectUri) {
        URI uri;
        try {
            uri = URI.create(redirectUri);
        } catch (IllegalArgumentException e) {
            throw ApiException.badRequest("redirect_uri 不合法");
        }
        String host = uri.getHost();
        boolean loopback = "127.0.0.1".equals(host) || "localhost".equals(host)
                || "[::1]".equals(host) || "0:0:0:0:0:0:0:1".equals(host);
        if (!"http".equalsIgnoreCase(uri.getScheme()) || !loopback || uri.getHost() == null) {
            throw ApiException.badRequest("仅允许注册的本机回环 http 回调");
        }
    }

    /**
     * 配置/参数空判定：{@code null} 与全空白都视为未提供。
     *
     * @param value 待判定的文本
     * @return 未提供或仅由空白组成返回 {@code true}
     */
    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }
}
