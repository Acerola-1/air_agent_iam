package com.airagent.iam.security.password;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Component;

/**
 * 口令摘要组件（安全层组件，不带 Swagger 注解）：强度校验 + BCrypt 生成与比对。
 *
 * <p>分层位置：被登录、本人改密、管理员建档/重置、企业成员建档等写路径共用
 * （见 {@link com.airagent.iam.auth.service.impl.SessionServiceImpl} 与
 * {@link com.airagent.iam.admin.service.impl.UserAdminServiceImpl}）。明文口令只在调用栈内
 * 短暂存在，本组件不落盘、不打日志、不返回任何可反推原文的中间值；持久化列
 * {@code iam.users.password_hash} 对请求角色 iam_app 无直接读权限，只能由
 * SECURITY DEFINER 函数带出后用于内存比对。
 *
 * <p>算法固定：变体 {@code $2b$}、{@code log_rounds = 10}（即 2^10 轮密钥编排），
 * 每次 {@link #hash(String)} 都新取 16 字节随机盐，因此同一口令两次摘要不同——任何地方都
 * 不得用摘要相等来推断口令相等，比对只能走 {@link #matches(String, String)}。
 * 摘要文本形如 {@code $2b$10$<22 字符盐><31 字符摘要>}，共 60 字符。
 *
 * <p>强度规则的真实范围：{@link #validateStrength(String)} 只校验长度 8..256
 * （按 {@code String.length()} 的 UTF-16 计数），<b>不</b>检查字符类别、大小写、数字、符号、
 * 字典命中或重复字符，也没有历史口令比对。登录路径的长度护栏在调用方另行完成，取值与本方法一致。
 *
 * <p>72 字节截断：BCrypt 的密钥材料以 UTF-8 字节计，本组件在摘要与比对两侧都先把口令截断到
 * 前 72 个字节（第 72 字节之后的内容不参与运算，截断按字节而非字符，可能在多字节字符中间切断）。
 * 这与 Python {@code bcrypt} 的按字节截断口径一致，跨语言等价性由固定向量测试
 * （{@code CrossLanguageVectorTest#bcryptPythonVectorsVerifyInJava}，含 72/73 字节等价类）验证；
 * 截断也规避了底层 {@code BCrypt.hashpw} 对新口令超过 72 字节直接抛异常的行为。
 * 历史 {@code $2a$} / {@code $2y$} 摘要的校验由底层按盐串自身变体处理，本组件不改动其前缀。
 *
 * @author Acerola
 */
@Component
public class PasswordHasher {

    /** BCrypt 工作因子对数：2^10 轮，写库摘要与向量测试都以此为唯一取值。 */
    private static final int STRENGTH = 10;

    /** 生成的盐串前缀（版本标记），决定 OpenBSD 修正后的 {@code $2b$} 算法分支。 */
    private static final String VERSION = "$2b$";

    /** BCrypt 密钥材料上限（字节），超出部分在摘要与比对两侧同时丢弃。 */
    private static final int MAX_BCRYPT_BYTES = 72;

    /** 构造期一次性取得的强随机实例，供盐生成复用；进程内共享，线程安全由 JDK 实现保证。 */
    private final SecureRandom secureRandom;

    /**
     * 构造组件并向 JDK 申请 {@code getInstanceStrong()} 强随机实例。
     *
     * @throws IllegalStateException JDK 未提供强随机算法实例（此时 Spring 容器启动失败，
     *                               绝不退化为弱随机源）；该实例在熵源不足时可能阻塞构造过程
     */
    public PasswordHasher() {
        try {
            this.secureRandom = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("strong SecureRandom unavailable", e);
        }
    }

    /**
     * 管理建档/重置与登录一致的口令形状校验：仅长度 8–256 字符（bcrypt 仍按 72 字节截断参与运算）。
     *
     * <p>不含字符类别、复杂度或字典要求；需要更强的口令策略必须由调用方另行实现。
     *
     * @param rawPassword 明文口令；{@code null}、空串、长度小于 8 或大于 256 均判不合法
     * @throws com.airagent.iam.web.error.ApiException 400 长度越界（消息只给出长度区间，不回显口令）
     */
    public void validateStrength(String rawPassword) {
        if (rawPassword == null || rawPassword.length() < 8 || rawPassword.length() > 256) {
            throw com.airagent.iam.web.error.ApiException.badRequest("password 长度必须在 8 到 256 之间");
        }
    }

    /**
     * 生成新口令的 BCrypt 摘要，用于首次建档与改密写库。
     *
     * @param rawPassword 明文口令（调用方应先经 {@link #validateStrength} 把关）；
     *                    为空指针时由字符编码转换抛出运行时异常
     * @return {@code $2b$10$} 开头的 60 字符摘要；每次调用因随机盐而不同
     */
    public String hash(String rawPassword) {
        String salt = BCrypt.gensalt(VERSION, STRENGTH, secureRandom);
        return BCrypt.hashpw(truncate(rawPassword), salt);
    }

    /**
     * 比对明文口令与库中摘要，用于登录与本人改密的旧口令校验。
     *
     * <p>比对把两侧摘要文本交给 {@code MessageDigest.isEqual}（无提前返回），
     * 不因不匹配位置提前退出；口令侧同样按 72 字节截断，与 {@link #hash(String)} 口径一致。
     * 该方法对"摘要缺失/非法"与"口令错误"统一返回 {@code false}，调用方据此折叠为同一句
     * 认证失败，避免账号枚举。
     *
     * @param rawPassword  明文口令；{@code null} 直接判不匹配
     * @param storedHash   库中摘要；{@code null}、空白串或非法 BCrypt 格式一律判不匹配
     *                     （历史 {@code $2a$}/{@code $2y$} 前缀按其自身变体校验）
     * @return 匹配返回 {@code true}；任一入参缺失、格式非法或不匹配返回 {@code false}，不抛异常
     */
    public boolean matches(String rawPassword, String storedHash) {
        if (rawPassword == null || storedHash == null || storedHash.isBlank()) {
            return false;
        }
        try {
            return BCrypt.checkpw(truncate(rawPassword), storedHash);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * 按 UTF-8 字节取前 72 字节，作为 BCrypt 的实际密钥材料。
     *
     * @param rawPassword 明文口令，非空（由调用方保证）
     * @return 不超过 72 字节的字节数组；不足时即完整编码结果
     */
    private byte[] truncate(String rawPassword) {
        byte[] bytes = rawPassword.getBytes(StandardCharsets.UTF_8);
        if (bytes.length <= MAX_BCRYPT_BYTES) {
            return bytes;
        }
        byte[] truncated = new byte[MAX_BCRYPT_BYTES];
        System.arraycopy(bytes, 0, truncated, 0, MAX_BCRYPT_BYTES);
        return truncated;
    }
}
