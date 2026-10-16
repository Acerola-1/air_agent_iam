package com.airagent.iam.webapi.sso.service.impl;

import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.auth.service.SessionService;
import com.airagent.iam.auth.vo.LoginVO;
import com.airagent.iam.security.token.OpaqueTokens;
import com.airagent.iam.web.error.ApiException;
import com.airagent.iam.webapi.sso.SsoClientView;
import com.airagent.iam.webapi.sso.dto.SsoExchangeDTO;
import com.airagent.iam.webapi.sso.entity.SsoStateDO;
import com.airagent.iam.webapi.sso.mapper.SsoMapper;
import com.airagent.iam.webapi.sso.service.SsoExchangeService;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * 一次性 ticket 服务端兑换：ticket 与 state 均原子消费，绑定客户端与精确回调；
 * 兑换时重新执行 Redis + PG 权威核验，随后签发受众受限的独立应用会话。
 */
@Service
public class SsoExchangeServiceImpl implements SsoExchangeService {

    private final SsoMapper ssoMapper;
    private final TransactionTemplate tx;
    private final SessionService sessionService;

    public SsoExchangeServiceImpl(SsoMapper ssoMapper, TransactionTemplate tx,
                              SessionService sessionService) {
        this.ssoMapper = ssoMapper;
        this.tx = tx;
        this.sessionService = sessionService;
    }

    @Override
    public LoginVO exchange(SsoClientView client, SsoExchangeDTO req) {
        if (req == null || blank(req.ticket()) || blank(req.redirectUri()) || blank(req.state())) {
            throw ApiException.badRequest("ticket、redirect_uri、state 必填");
        }
        if (req.ticket().length() > 256 || req.state().length() > 256
                || req.redirectUri().length() > 512) {
            throw ApiException.badRequest("SSO 参数超长");
        }
        if (!client.callbackUrl().equals(req.redirectUri())) {
            throw ApiException.badRequest("redirect_uri 与注册回调不一致");
        }

        UUID sourceSessionId = tx.execute(status -> consumeGrant(client, req));
        if (sourceSessionId == null) {
            throw ApiException.unauthenticated("ticket 或 state 无效、已过期或已被使用");
        }
        CurrentSession source = sessionService.requireCurrentBySessionId(sourceSessionId);
        return sessionService.issueSsoSession(source, client.audience());
    }

    private UUID consumeGrant(SsoClientView client, SsoExchangeDTO req) {
        UUID sourceSessionId = ssoMapper.consumeTicket(OpaqueTokens.digest(req.ticket()),
                client.clientId(), req.redirectUri());
        if (sourceSessionId == null) {
            return null;
        }
        SsoStateDO state = ssoMapper.consumeState(OpaqueTokens.digest(req.state()));
        if (state == null) {
            return null;
        }
        if (!client.clientId().equals(state.clientId()) || !req.redirectUri().equals(state.redirectUri())) {
            throw ApiException.badRequest("state 与客户端或回调不匹配");
        }
        return sourceSessionId;
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }
}
