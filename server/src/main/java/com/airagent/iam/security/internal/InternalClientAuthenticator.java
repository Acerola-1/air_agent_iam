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
 * 内部客户端凭据核验组件（安全层组件，非 HTTP 端点模型，不带 Swagger 注解）：
 * 把 {@code Authorization} 头里的 HTTP Basic（{@code client_id:client_secret}）或等价的
 * Bearer 形态凭据，换成主库实时核验后的 {@link InternalClient}。
 *
 * <p>双主体边界（不得混淆）：本头认证的是<b>调用服务</b>本身，请求体内的 {@code subject_token}
 * 才是被核验的人类会话令牌或服务账号令牌；两者走完全不同的表与函数，任何一侧的凭据都不能
 * 冒充另一侧。同类实现的注册客户端版本见
 * {@link com.airagent.iam.webapi.sso.SsoClientAuthenticator}（查 {@code iam.sso_clients}）。
 *
 * <p>凭据校验顺序（Bearer 分支）：前缀 {@code "Bearer "}（大小写敏感）→ 去空白后非空且
 * 长度不超过 256 字符 → {@code SHA-256(凭据原文)} → {@code iam_auth.authenticate_internal_bearer(digest)}。
 * Basic 分支：前缀 {@code "Basic "} → 标准 Base64 解码（非法编码 401）→ 按 UTF-8 还原文本 →
 * 以第一个 {@code :} 切分（秘密本身可含 {@code :}）→ client_id 非空且不超过 128 字符、
 * secret 非空且不超过 256 字符 → {@code SHA-256(secret)} →
 * {@code iam_auth.authenticate_internal_client(client_id, digest)}。长度上限是进入数据库前的
 * 形状护栏，与 {@code client_id} 的实际登记长度无关。
 *
 * <p>摘要比对发生在哪里：Java 侧<b>不做</b>任何密钥比对，只把原文换成十六进制 SHA-256 摘要后交给
 * PostgreSQL 的 {@code SECURITY DEFINER} 函数——Basic 路径在 plpgsql 内以
 * {@code secret_digest IS DISTINCT FROM p_secret_digest} 比对，Bearer 路径以
 * {@code WHERE c.secret_digest = p_digest} 等值查找。因此这里没有常量时间比较的实现，
 * 可被时序观测的只是"摘要是否相等"，密钥原文从不参与比较，也不进日志、审计与响应。
 * Bearer 路径还由函数强制摘要唯一（同摘要命中多行时返回 0 行），避免两个客户端共享凭据造成
 * 归属歧义。
 *
 * <p>失败折叠：不存在、密钥错误、状态非 {@code active} 三种情形在数据库内以同一 SQLSTATE 28000
 * 报错、在本组件以同一句话回复 401，调用方无法据此枚举客户端 id；长度/编码类问题同样是 401，
 * 消息只指出问题类别，不回显任何输入片段。
 *
 * @author Acerola
 */
@Component
public class InternalClientAuthenticator {

    /** 内部客户端核验与鉴权的 SQL 网关（每次调用都回主库，无缓存）。 */
    private final InternalClientMapper clientMapper;

    /**
     * 构造核验组件。
     *
     * @param clientMapper 内部客户端核验的数据访问，SQL 见
     *                     {@code mapper/security/internal/InternalClientMapper.xml}
     */
    public InternalClientAuthenticator(InternalClientMapper clientMapper) {
        this.clientMapper = clientMapper;
    }

    /**
     * 核验 {@code Authorization} 头并返回已认证的客户端。
     *
     * <p>兼容规则：{@code Basic} 是内部端点的原生形态；{@code Bearer} 分支为已登记客户端提供
     * "单一凭据串"的等价用法（同一秘密原文做摘要后查同一张表），前缀判定大小写敏感，
     * 因此 {@code bearer ...} 之类的写法会落到 Basic 判定并因前缀不符被拒。两条分支互斥，
     * 先 Bearer 后 Basic，不存在同一请求头被两种主体重复解释的路径。
     *
     * @param authorizationHeader 原始 {@code Authorization} 请求头；{@code null} 或既非
     *                            {@code "Bearer "} 也非 {@code "Basic "} 前缀一律 401
     * @return 已通过主库核验的客户端（状态恒为 {@code active}）
     * @throws ApiException 401 凭据缺失、前缀不符、Base64 编码非法、切分后 id 或 secret 为空、
     *                      超出长度上限、摘要未命中唯一 {@code active} 客户端，或数据库以 28000/28P01
     *                      表达的"不存在/密钥错/已停用"；
     *                      其余数据库故障（连接类 08*、57P01 等 SQLSTATE）经
     *                      {@link PgErrorTranslator#toApiException(DataAccessException)} 译为 503——
     *                      依赖不可用绝不降级为放行。Bearer 分支不捕获
     *                      {@code DataAccessException}（该函数以"无行"表达拒绝、不抛 SQLSTATE），
     *                      其连接类异常冒泡给全局异常处理器同样转 503
     */
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
