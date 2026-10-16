package com.airagent.iam.security.internal;

import com.airagent.iam.config.IamProperties;
import com.airagent.iam.web.error.ApiException;
import java.time.Instant;
import java.util.List;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Component;

/**
 * Redis 固定窗口准入限流（安全层组件，不带 Swagger 注解）：登录按主体、内部端点按客户端计数。
 *
 * <p>定位：这是一个<b>计数器</b>，不是授权来源。它只做"这一窗口内允许多少次尝试"的裁决，
 * 不缓存任何正向授权结果，也不参与身份、scope、受众或会话有效性的判定——被限流放行的请求
 * 仍要走完整的凭据核验与主库权威快照。放在登录路径上是为了在 BCrypt 之前挡住廉价口令探测，
 * 放在内部端点上是为了约束单个客户端的调用速率。
 *
 * <p>键构形：{@code iam:rl:<scope>:<bucket>:<identity>}。其中 {@code scope} 为
 * {@link #SCOPE_LOGIN} 或 {@link #SCOPE_INTERNAL}；{@code bucket} 是
 * {@code Instant.now().getEpochSecond() / max(1, windowSeconds)}，即按 Unix 纪元对齐的
 * 固定窗口序号（窗口边界两侧最坏可各放行 limit 次，是固定窗口的固有特性，不做滑动修正）；
 * {@code identity} 由调用方给出口径：登录为 {@code realm:account}
 * （见 {@link com.airagent.iam.auth.service.impl.SessionServiceImpl}），内部端点为
 * {@code client_id}（见 {@link InternalClientInterceptor#authenticateAndAuthorize(String, String)}），
 * SSO 链路另加 {@code sso-exchange:} / {@code sso-start:} 前缀区分主体，避免与内部客户端
 * 落在同一计数键上。
 *
 * <p>计数语义：Lua 脚本对键做 {@code INCR}，仅当返回值首次为 1 时补一个 {@code EXPIRE}
 * （时长取窗口秒数），从而让窗口在首次访问后自动到期，无需清理任务。阈值比较在 Java 侧完成
 * （脚本不使用传入的 limit 参数）：计数<b>严格大于</b> limit 才拒绝，即恰好等于 limit 的那一次
 * 仍被放行。默认配置为窗口 60 秒、登录每主体 10 次、内部端点每客户端 600 次
 * （{@code iam.rate-limit.*}，均可由环境变量覆盖）。
 *
 * <p>依赖故障语义（以代码为准）：连接失败抛 {@link ApiException} 503，
 * 其余 Redis 异常冒泡给 {@code GlobalExceptionHandler}，同样落 503——限流依赖故障
 * 不退化为"无限尝试"。例外是脚本返回值取不到（{@code null}）时不判超限，本次请求照常放行，
 * 授权判定仍由数据库权威承担。总开关 {@code iam.rate-limit.enabled} 关闭时完全不接触 Redis。
 *
 * @author Acerola
 */
@Component
public class RateLimiter {

    /** 限流域：登录尝试，主体口径为 {@code realm:account}，阈值取 {@code iam.rate-limit.login-limit}。 */
    public static final String SCOPE_LOGIN = "login";

    /** 限流域：内部/机器端点，主体口径为客户端 id（或调用方加前缀的会话 id），阈值取 {@code iam.rate-limit.internal-limit}。 */
    public static final String SCOPE_INTERNAL = "internal";

    /**
     * 计数脚本：{@code INCR} 后若为首次（返回 1）则按 {@code ARGV[2]}（窗口秒数）设置过期。
     * {@code ARGV[1]} 传入的是阈值，脚本本身不使用它，阈值比较留在 Java 侧。
     * 过期时长用的是未经分桶除数那层 {@code max(1, ·)} 夹取的原始窗口值，故运维须保证
     * {@code iam.rate-limit.window-seconds} 不小于 1，否则键会被立即过期、计数不累积。
     */
    private static final DefaultRedisScript<Long> INCR_WINDOW = new DefaultRedisScript<>(
            "local c = redis.call('INCR', KEYS[1]); "
                    + "if c == 1 then redis.call('EXPIRE', KEYS[1], tonumber(ARGV[2])) end; "
                    + "return c;",
            Long.class);

    /** 字符串模板：键与计数值均按 UTF-8 字符串存取，与 Sa-Token 会话库共用连接但不共用键空间。 */
    private final StringRedisTemplate redis;

    /** {@code iam.*} 配置，本组件只读 {@code iam.rate-limit}（enabled / window-seconds / 两个 limit）。 */
    private final IamProperties props;

    /**
     * 构造限流器。
     *
     * @param redis Redis 字符串模板（{@code spring.data.redis.*} 自动装配，命令超时 1 秒）
     * @param props {@code iam.*} 配置记录，提供窗口长度与各域阈值
     */
    public RateLimiter(StringRedisTemplate redis, IamProperties props) {
        this.redis = redis;
        this.props = props;
    }

    /**
     * 对一次访问计数，超限即拒绝。
     *
     * <p>判定顺序：总开关 → 按域取阈值 → 阈值非正数视为该域全拒 → 构窗口键 →
     * Redis 计数 → 与阈值比较。整个调用只有一次 Redis 往返，不占用数据库连接。
     *
     * @param scope    限流域，仅接受 {@link #SCOPE_LOGIN} 与 {@link #SCOPE_INTERNAL}；非空且大小写敏感
     * @param identity 计数主体标识，参与键构形（不含空白与控制字符由调用方保证）；
     *                 相同取值落在同一窗口计数上，不同域之间因键含 {@code scope} 而互不影响
     * @throws ApiException 429 命中限流，或该域阈值配置为 0/负数（等价于对该域全拒）；
     *                      503 Redis 连接不可用（失败关闭，绝不因读不到计数而放行）
     * @throws IllegalArgumentException {@code scope} 不在已知两个域之内——属调用方编程错误，
     *                                  不映射为任何 HTTP 语义，最终以 500 结束
     */
    public void check(String scope, String identity) {
        if (props.rateLimit() == null || !props.rateLimit().enabled()) {
            return;
        }
        int limit = switch (scope) {
            case SCOPE_LOGIN -> props.rateLimit().loginLimit();
            case SCOPE_INTERNAL -> props.rateLimit().internalLimit();
            default -> throw new IllegalArgumentException("未知限流域: " + scope);
        };
        if (limit <= 0) {
            throw ApiException.rateLimited("请求过于频繁，请稍后再试");
        }
        long window = props.rateLimit().windowSeconds();
        long bucket = Instant.now().getEpochSecond() / Math.max(1, window);
        String key = "iam:rl:" + scope + ":" + bucket + ":" + identity;
        Long count;
        try {
            count = redis.execute(INCR_WINDOW, List.of(key), String.valueOf(limit), String.valueOf(window));
        } catch (RedisConnectionFailureException e) {
            throw ApiException.dependencyUnavailable("准入依赖暂不可用");
        }
        if (count != null && count > limit) {
            throw ApiException.rateLimited("请求过于频繁，请稍后再试");
        }
    }
}
