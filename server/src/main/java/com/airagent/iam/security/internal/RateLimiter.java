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
 * Redis 固定窗口限流（登录按主体、内部端点按客户端）。
 *
 * <p>Redis 不可用时失败关闭抛 503：限流依赖故障不得退化为"无限尝试"。
 * 不缓存任何正向授权结果；本组件只做准入计数。
 */
@Component
public class RateLimiter {

    public static final String SCOPE_LOGIN = "login";
    public static final String SCOPE_INTERNAL = "internal";

    private static final DefaultRedisScript<Long> INCR_WINDOW = new DefaultRedisScript<>(
            "local c = redis.call('INCR', KEYS[1]); "
                    + "if c == 1 then redis.call('EXPIRE', KEYS[1], tonumber(ARGV[2])) end; "
                    + "return c;",
            Long.class);

    private final StringRedisTemplate redis;
    private final IamProperties props;

    public RateLimiter(StringRedisTemplate redis, IamProperties props) {
        this.redis = redis;
        this.props = props;
    }

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
