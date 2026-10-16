package com.airagent.iam.security.internal;

import com.airagent.iam.security.internal.mapper.InternalClientMapper;
import com.airagent.iam.security.token.OpaqueTokens;
import com.airagent.iam.web.error.ApiException;
import com.airagent.iam.web.error.PgErrorTranslator;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Component;

/**
 * HTTP Basic（client_id:client_secret）→ 主库内部客户端核验。
 *
 * <p>双主体边界：Basic 只认证"调用服务"，请求体内 subject_token 才是被核验的用户/服务账号主体。
 * 密钥只以 sha256 摘要存储与比对，原始 secret 不进日志/审计/响应。
 */
@Component
public class InternalClientAuthenticator {

    private final InternalClientMapper clientMapper;

    public InternalClientAuthenticator(InternalClientMapper clientMapper) {
        this.clientMapper = clientMapper;
    }

    public InternalClient authenticate(String authorizationHeader) {
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String credential = authorizationHeader.substring(7).trim();
            if (credential.isEmpty() || credential.length() > 256) {
                throw ApiException.unauthenticated("客户端凭据无效");
            }
            InternalClient client = clientMapper.authenticateBearer(OpaqueTokens.digest(credential));
            if (client == null) {
                throw ApiException.unauthenticated("客户端凭据无效");
            }
            return client;
        }
        if (authorizationHeader == null || !authorizationHeader.startsWith("Basic ")) {
            throw ApiException.unauthenticated("内部端点要求 Basic 客户端凭据");
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
            InternalClient client = clientMapper.authenticate(clientId, OpaqueTokens.digest(secret));
            if (client == null) {
                throw ApiException.unauthenticated("客户端凭据无效");
            }
            return client;
        } catch (DataAccessException e) {
            String sqlState = PgErrorTranslator.deepest(e) == null ? null : PgErrorTranslator.deepest(e).getSQLState();
            if ("28000".equals(sqlState) || "28P01".equals(sqlState)) {
                // 不存在/错密钥/已停用同一响应，避免客户端枚举
                throw ApiException.unauthenticated("内部客户端凭据无效或客户端已停用");
            }
            throw PgErrorTranslator.toApiException(e);
        }
    }

}
