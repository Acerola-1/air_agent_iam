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
 * 中央 SSO 授权：注册客户端精确回调白名单 + state 服务端绑定 + 30 秒一次性 ticket。
 * ticket/state 原始值只出现在 303 跳转的一次性 query；人类 Bearer 不进 URL。
 */
@Service
public class SsoAuthorizeServiceImpl implements SsoAuthorizeService {

    private final SsoMapper ssoMapper;
    private final RequestContextMapper requestContextMapper;
    private final TransactionTemplate tx;
    private final SessionService sessionService;
    private final IamProperties props;
    private final RateLimiter rateLimiter;

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

    /** 域名未定阶段：回调只允许本机回环 http，禁止任意外部跳转。 */
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

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }
}
