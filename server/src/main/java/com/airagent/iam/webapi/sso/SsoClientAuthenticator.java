package com.airagent.iam.webapi.sso;

import com.airagent.iam.security.token.OpaqueTokens;
import com.airagent.iam.web.error.ApiException;
import com.airagent.iam.web.error.PgErrorTranslator;
import com.airagent.iam.webapi.sso.mapper.SsoMapper;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Component;

/**
 * 合成 SSO BFF 客户端 Basic 核验（sso_clients，区别于 internal_clients）：
 * 只认证"发起兑换的应用"，ticket 才代表浏览器中的人类。不存在/错密钥/停用同一 401。
 */
@Component
public class SsoClientAuthenticator {

    private final SsoMapper clientMapper;

    public SsoClientAuthenticator(SsoMapper clientMapper) {
        this.clientMapper = clientMapper;
    }

    public SsoClientView authenticate(String authorizationHeader) {
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String credential = authorizationHeader.substring(7).trim();
            if (credential.isEmpty() || credential.length() > 256) {
                throw ApiException.unauthenticated("客户端凭据无效");
            }
            SsoClientView client = clientMapper.authenticateBearer(OpaqueTokens.digest(credential));
            if (client == null) {
                throw ApiException.unauthenticated("客户端凭据无效");
            }
            return client;
        }
        if (authorizationHeader == null || !authorizationHeader.startsWith("Basic ")) {
            throw ApiException.unauthenticated("SSO 兑换端点要求 Basic 客户端凭据");
        }
        String decoded;
        try {
            decoded = new String(Base64.getDecoder().decode(authorizationHeader.substring(6).trim()),
                    StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw ApiException.unauthenticated("Basic 凭据编码不合法");
        }
        int sep = decoded.indexOf(':');
        if (sep <= 0 || sep == decoded.length() - 1) {
            throw ApiException.unauthenticated("Basic 凭据须为 client_id:client_secret");
        }
        String clientId = decoded.substring(0, sep);
        String secret = decoded.substring(sep + 1);
        if (clientId.length() > 128 || secret.length() > 256) {
            throw ApiException.unauthenticated("Basic 凭据超长");
        }
        try {
            SsoClientView client = clientMapper.authenticate(clientId, OpaqueTokens.digest(secret));
            if (client == null) {
                throw ApiException.unauthenticated("客户端凭据无效");
            }
            return client;
        } catch (DataAccessException e) {
            String sqlState = PgErrorTranslator.deepest(e) == null ? null : PgErrorTranslator.deepest(e).getSQLState();
            if ("28000".equals(sqlState) || "28P01".equals(sqlState)) {
                throw ApiException.unauthenticated("SSO 客户端凭据无效或客户端已停用");
            }
            throw PgErrorTranslator.toApiException(e);
        }
    }

}
