package com.airagent.iam.security.token;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * 不透明随机令牌的生成与摘要（安全层静态工具，不参与任何授权判定）。
 *
 * <p>分工：{@link #newRawToken()} 产出"只以原文形式出现在响应体/请求头/Cookie 一次"的凭据，
 * {@link #digest(String)} 产出它落库与作 Redis 键的表示。全链路只持久化摘要——
 * {@code iam.auth_sessions.token_digest}、{@code iam.internal_clients.secret_digest}、
 * 服务令牌与 SSO/浏览器句柄的摘要列，以及 Sa-Token 的 Redis 键（见
 * {@link com.airagent.iam.security.satoken.DigestStpLogic}）——原文不进数据库、不进日志、
 * 不进审计 detail，撤销与核验都以摘要为主键。
 *
 * <p>使用面：人类会话访问令牌（登录与 SSO 兑换）、内部/SSO 客户端的 Bearer 凭据原文、
 * 服务账号一次性 secret、SSO 的 {@code state} 与一次性 ticket、浏览器会话句柄及其绑定的
 * CSRF 值、合成 BFF 的会话标识。配置项 {@code sa-token.token-style} 对本服务不生效：
 * 所有令牌都在生成后显式传给 Sa-Token，不由框架自取样式。
 *
 * <p>摘要是普通散列而非口令存储：SHA-256 无盐、无工作因子，其安全性完全依赖输入的随机熵，
 * 因此只可用于本类生成的 32 字节随机令牌；口令必须走
 * {@link com.airagent.iam.security.password.PasswordHasher} 的 BCrypt，两者不可互换。
 *
 * @author Acerola
 */
public final class OpaqueTokens {

    /** 共享的强伪随机源（{@code SecureRandom} 默认实例，非 {@code getInstanceStrong()}），可多线程并发使用。 */
    private static final SecureRandom RANDOM = new SecureRandom();

    /** base64url 无填充编码器：输出不含 {@code =}，可直接作 Cookie/URL 安全的令牌字符集。 */
    private static final Base64.Encoder URL_ENCODER = Base64.getUrlEncoder().withoutPadding();

    /** 纯静态工具，禁止实例化。 */
    private OpaqueTokens() {
    }

    /**
     * 生成一枚新的不透明原始令牌。
     *
     * <p>形状：32 字节（256 位）随机数据经 base64url 无填充编码，恒为 43 个字符，
     * 字符集限于 {@code A-Za-z0-9-_}；熵即 256 位，等同于密钥强度，无需再去重或哈希预处理。
     *
     * @return 原始令牌文本，可直接下发给调用方；本方法不落任何存储，调用方负责只在响应中给出一次
     */
    public static String newRawToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return URL_ENCODER.encodeToString(bytes);
    }

    /**
     * 计算令牌的存储表示：UTF-8 字节上的 SHA-256，输出小写十六进制。
     *
     * <p>确定性映射，同一原文每次得到同一摘要，因此可用作唯一列的查找键
     * （{@code auth_sessions.token_digest} 唯一约束即依赖它）与 Redis 键片段；
     * 单向性保证摘要泄露不能反推原始令牌。
     *
     * @param rawToken 原始令牌或客户端凭据原文（非空）；本项目实际传入 43 字符的 base64url 令牌，
     *                 也接受运维预置的任意长度秘密原文——低熵输入会使摘要可被字典枚举，
     *                 调用方须保证来源随机性
     * @return 64 个字符的小写十六进制摘要，长度恒定为 64
     * @throws IllegalStateException JVM 未提供 SHA-256 实现（JDK 规范要求该算法必须存在，
     *                               出现即视为运行时环境损坏）
     */
    public static String digest(String rawToken) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha256.digest(rawToken.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
