package com.airagent.iam.health.service.impl;

import com.airagent.iam.config.IamProperties;
import com.airagent.iam.health.mapper.HealthMapper;
import com.airagent.iam.health.service.HealthService;
import com.airagent.iam.health.vo.HealthStatusVO;
import org.springframework.data.redis.core.RedisOperations;
import org.springframework.stereotype.Service;

/**
 * {@link HealthService} 实现：汇总 PostgreSQL 与 Redis 的真实探测结果（无缓存、无副作用）。
 *
 * <p>探测顺序与独立性：先 PostgreSQL（{@link #isPostgresAvailable()}）再 Redis
 * （{@link #isRedisAvailable()}），两次都执行、互不短路——因此 Redis 故障不会让
 * {@code postgres} 位变成未知，PG 故障也不会跳过 Redis 判定。两项判定彼此独立，
 * 结果只用于装配状态字符串，不互相覆盖。
 *
 * <p>整体口径：仅当两项同时可用才是 {@code ok}，任一不可用即 {@code degraded}。
 * 本方法<em>不抛异常、也不返回 503</em>：连接不可得、命令超时等任何运行时异常都在探测
 * 方法内被吸收成 {@code false}。这与业务面"依赖故障失败关闭返 503"
 * （GlobalExceptionHandler）刻意不同——健康端点要能区分"进程活着但依赖断了"与"进程没起来"。
 *
 * <p>超时不在本类设置，全部沿用连接层配置（application.yml）：PG 侧为 HikariCP
 * 获取连接 250ms、JDBC {@code connectTimeout=3}/{@code socketTimeout=10} 秒与服务端
 * {@code statement_timeout=300ms}；Redis 侧为 Lettuce 命令与连接超时各 1 秒、
 * 连接池等待 500ms。故单次健康检查的最坏耗时由这两条预算决定，两次探测串行执行。
 *
 * <p>输出边界：只回状态字符串、配置项 {@code iam.issuer} 的文本与两个布尔位；
 * 不回主机、端口、异常消息、堆栈、连接串或任何凭据。{@code redis=false} 只说明
 * 会话存活索引当前不可达（Sa-Token 存储），不代表数据丢失——权威状态始终在 PostgreSQL。
 * 本实现不采集也不返回版本号、启动时间或任何指标。
 *
 * @author Acerola
 */
@Service
public class HealthServiceImpl implements HealthService {

    /**
     * Redis 探测键。本服务从不写入该键，读取只为触发一次真实的 GET 往返；
     * 读到 {@code null}（键不存在）属正常结果，不构成故障。
     */
    private static final String HEALTH_PROBE_KEY = "iam:health:probe";
    /** 整体状态：PostgreSQL 与 Redis 同时可用。 */
    private static final String STATUS_OK = "ok";
    /** 整体状态：至少一项依赖不可用（HTTP 状态仍是 200）。 */
    private static final String STATUS_DEGRADED = "degraded";

    /** PostgreSQL 探测入口：在不触表的 {@code SELECT 1} 上验证连接池与数据库往返。 */
    private final HealthMapper healthMapper;
    /** Redis 操作模板（项目内即会话存储使用的模板）；本类只用它触发一次 GET。 */
    private final RedisOperations<String, Object> redisOperations;
    /** 配置绑定：健康响应里的 {@code issuer} 取自 {@code iam.issuer}，是配置文本而非凭据。 */
    private final IamProperties properties;

    /**
     * 构造实现，全部依赖经 Spring 构造注入。
     *
     * @param healthMapper     PostgreSQL 探测数据访问
     * @param redisOperations  Redis 操作模板（泛型 String/Object 的那份，与 Sa-Token 会话存储同源）
     * @param properties       {@code iam.*} 配置，仅用于回填 issuer
     */
    public HealthServiceImpl(HealthMapper healthMapper,
                             RedisOperations<String, Object> redisOperations,
                             IamProperties properties) {
        this.healthMapper = healthMapper;
        this.redisOperations = redisOperations;
        this.properties = properties;
    }

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：两次探测串行执行且都不抛异常，{@code status} 由两个布尔位的
     * "与"决定；issuer 原样回填配置项 {@code iam.issuer} 的文本（application.yml 当前
     * 配置为 {@code air-agent-iam}），不校验其有效性，也不参与状态判定。
     */
    @Override
    public HealthStatusVO getHealth() {
        boolean postgresAvailable = isPostgresAvailable();
        boolean redisAvailable = isRedisAvailable();
        String status = postgresAvailable && redisAvailable ? STATUS_OK : STATUS_DEGRADED;
        return new HealthStatusVO(status, properties.issuer(), postgresAvailable, redisAvailable);
    }

    /**
     * 探测 PostgreSQL：经请求数据源执行一次不触表的常量查询。
     *
     * <p>判定口径是"返回值等于 1"，任何异常（连接池取不到连接、语句或服务端超时、
     * 数据库报错）都视为不可用并被就地吞掉，绝不向上抛出，以免健康端点变成 503。
     *
     * @return 查询成功且返回 1 时为 {@code true}；抛出任一运行时异常时为 {@code false}
     */
    private boolean isPostgresAvailable() {
        try {
            return healthMapper.checkConnection() == 1;
        } catch (RuntimeException exception) {
            return false;
        }
    }

    /**
     * 探测 Redis：对 {@link #HEALTH_PROBE_KEY} 做一次 GET。
     *
     * <p>该键从不被本服务写入，返回值被丢弃、也不建键，因此"读到 null"完全正常；
     * 判定只看这次命令能否在 Lettuce 超时预算内正常完成。与业务链路共用同一份
     * Redis 操作模板，故探测结果反映的就是会话索引实际使用的连接面。
     *
     * @return 命令正常完成（含键不存在）时为 {@code true}；连接失败、超时或任何
     *         Redis 运行时异常时为 {@code false}
     */
    private boolean isRedisAvailable() {
        try {
            redisOperations.opsForValue().get(HEALTH_PROBE_KEY);
            return true;
        } catch (RuntimeException exception) {
            return false;
        }
    }
}
