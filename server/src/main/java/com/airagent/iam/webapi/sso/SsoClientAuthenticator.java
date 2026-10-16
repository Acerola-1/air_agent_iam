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
 * SSO 客户端凭据核验器（认证组件，{@code /v1/internal/sso/exchange} 的唯一认证入口）。
 *
 * <p>分层位置：由 {@link SsoExchangeInterceptor} 在 Controller 之前调用，产出
 * {@link SsoClientView} 写入请求属性；Controller/Service 都只消费这个已认证结果，
 * 不再自行解析 {@code Authorization} 头。核验本身走 {@link SsoMapper} 的两个
 * SECURITY DEFINER 函数（{@code iam_auth.authenticate_sso_client} 见 V11，
 * {@code iam_auth.authenticate_sso_bearer} 见 V17），{@code iam.sso_clients} 开启 RLS 且无策略，
 * 因此本类既无裸表读权限、也拿不到 {@code secret_digest} 列。
 *
 * <p>认证<em>对象</em>的关键区分：这里认证的是"发起兑换的应用/消费方 BFF"，
 * <em>不是</em>浏览器里的人类。人类身份由一次性 ticket 代表，只有 ticket 被原子消费后
 * 才取回其绑定的中央会话。凭据体系也与其他内部端点互斥：本类只查 {@code iam.sso_clients}，
 * {@code /v1/internal/introspect} 等端点用的 {@code iam.internal_clients}
 * 由 {@link com.airagent.iam.security.internal.InternalClientAuthenticator} 核验，
 * 一套登记表里的凭据在另一套上必然失败。
 *
 * <p>密钥边界：客户端密钥明文只来自配置 {@code iam.sso.clients.*.secret}（环境变量注入、
 * 启动预置时长度下限 32），库内只存 {@link OpaqueTokens#digest(String)} 的 SHA-256 十六进制摘要；
 * 本类把收到的凭据先摘要再比对，明文既不落库也不写日志。所有失败路径（缺头、前缀不对、
 * Base64 非法、无冒号、字段空白或超长、id 不存在、密钥错误、客户端停用）都归并为
 * 同一句 401，避免客户端枚举与凭据类型探测。
 *
 * @author Acerola
 */
@Component
public class SsoClientAuthenticator {

    /** SSO 客户端注册表数据访问 */
    private final SsoMapper clientMapper;

    /**
     * 构造核验器。
     *
     * @param clientMapper SSO 客户端核验的数据访问，只提供摘要比对后的安全视图
     */
    public SsoClientAuthenticator(SsoMapper clientMapper) {
        this.clientMapper = clientMapper;
    }

    /**
     * 按 {@code Authorization} 头核验 SSO 客户端，两种形式二选一，Bearer 优先判定。
     *
     * <p><b>Bearer 形式</b>（{@code Authorization: Bearer <client_secret>}）：前缀为大小写敏感的
     * {@code "Bearer "}，其余部分先 {@code trim()}；空白或超过 256 字符直接 401。
     * 该凭据即客户端密钥本身，客户端身份由摘要<em>反查</em>得出，
     * 因此要求摘要在 {@code iam.sso_clients} 中唯一命中——多个客户端共用同一密钥时
     * 函数返回空集，谁都认证不过。
     *
     * <p><b>Basic 形式</b>（{@code Authorization: Basic base64(client_id:client_secret)}）：
     * 前缀必须是 {@code "Basic "}；Base64 用标准字母表解码（不含填充即报错），按 UTF-8 还原后
     * 以<em>第一个</em>冒号切分——冒号必须在中间位置，故 id 与密钥都不得为空、
     * 密钥可以含冒号。长度上界 id 128、密钥 256。核验函数在 id 不存在、密钥不符或
     * 状态非 {@code active} 时统一 {@code RAISE} SQLSTATE 28000。
     *
     * @param authorizationHeader 原始 {@code Authorization} 头；{@code null} 或既非 Bearer
     *                            也非 Basic 前缀都按"要求客户端凭据"拒绝
     * @return 已认证的 {@link SsoClientView}，携带精确回调与受众绑定，供兑换服务直接使用
     * @throws ApiException 401 任何凭据缺失、格式非法、超长或核验不通过的情形
     *                      （消息一致，不区分具体原因）；
     *                      非 28000/28P01 的数据库故障经
     *                      {@link PgErrorTranslator#toApiException(DataAccessException)} 翻译，
     *                      依赖类连接故障落到 503
     */
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
