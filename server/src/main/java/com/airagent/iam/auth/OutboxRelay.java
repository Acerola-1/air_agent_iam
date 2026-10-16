package com.airagent.iam.auth;

import com.airagent.iam.auth.entity.OutboxEventDO;
import com.airagent.iam.auth.mapper.InfrastructureMapper;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * outbox → Redis 失效键清理中继（后台调度组件，不在任何请求路径上）。
 *
 * <p>职责边界：PG 授权状态是唯一权威。会话撤销在业务事务内落 PG 并同事务写
 * {@code iam.outbox}，本组件只负责把"删除 Redis 中残留 Sa-Token 键"这件事最终做完——
 * Redis 故障期间拒绝路径仍以 PG 为准（撤销后的令牌在内省与核验时一律不放行），
 * 因此中继滞后只会让已撤销的键多留一会儿，不会造成放行。
 *
 * <p>投递语义为至少一次：{@code claim_due_outbox} 以 {@code FOR UPDATE SKIP LOCKED} 申领并
 * 在申领时把 attempts +1，单条投递失败按指数退避重排（最长约 16 秒），达到
 * {@link #MAX_ATTEMPTS} 后转 {@code dead}。Redis 的 DEL 天然幂等，重复投递不改变结果；
 * 本类不读业务表、不写审计，也不缓存任何正向授权结论。
 *
 * @author Acerola
 */
@Component
public class OutboxRelay {

    /** 投递与依赖异常的告警日志，只输出 id/kind/次数与异常类型，不含 payload 细节。 */
    private static final Logger LOGGER = LoggerFactory.getLogger(OutboxRelay.class);

    /** 单条事件的最大尝试次数，与 {@code iam_auth.requeue_outbox} 的 dead 判定共用。 */
    private static final int MAX_ATTEMPTS = 10;

    /** outbox 的申领、完成与重排入口。 */
    private final InfrastructureMapper infrastructureMapper;

    /** 用于删除 Sa-Token 键的字符串 Redis 模板。 */
    private final StringRedisTemplate redis;

    /** 解析事件 payload 的 jsonb 文本。 */
    private final ObjectMapper mapper;

    /**
     * 构造 outbox 中继。
     *
     * @param infrastructureMapper outbox 申领与状态更新的数据访问
     * @param redis                执行键删除的 Redis 客户端
     * @param mapper               payload 解析器
     */
    public OutboxRelay(InfrastructureMapper infrastructureMapper, StringRedisTemplate redis, ObjectMapper mapper) {
        this.infrastructureMapper = infrastructureMapper;
        this.redis = redis;
        this.mapper = mapper;
    }

    /**
     * 单轮中继：申领一批到期事件并逐条投递。
     *
     * <p>调度参数 {@code iam.outbox.relay-delay-ms}（缺省 1000 毫秒）为<b>上一轮执行完成后</b>
     * 的固定间隔，而非固定频率，因此慢轮次不会相互重叠。批次上限固定 16 条。
     *
     * <p>申领失败（PG 不可用）只告警并直接返回，本轮不做任何判断——不得在缓存层留下放行依据，
     * 下一轮自然重试。逐条投递异常在条目级捕获：单条失败仅重排该条，其余事件照常推进。
     */
    @Scheduled(fixedDelayString = "${iam.outbox.relay-delay-ms:1000}")
    public void relay() {
        List<OutboxEventDO> rows;
        try {
            rows = infrastructureMapper.claimOutbox(16);
        } catch (RuntimeException e) {
            // PG 不可用：下轮再试；不得在缓存层保留放行判断
            LOGGER.warn("outbox 申领失败（下轮重试）: {}", e.getClass().getSimpleName());
            return;
        }
        for (OutboxEventDO row : rows) {
            long id = row.id();
            String kind = row.kind();
            int attempts = row.attempts();
            try {
                dispatch(kind, row.payloadJson());
                infrastructureMapper.completeOutbox(id);
            } catch (RuntimeException e) {
                LOGGER.warn("outbox 投递失败 id={} kind={} attempts={} reason={}",
                        id, kind, attempts, e.getClass().getSimpleName());
                infrastructureMapper.requeueOutbox(id, MAX_ATTEMPTS);
            }
        }
    }

    /**
     * 投递一条事件：解析键名列表并同步删除 Redis 键。
     *
     * <p>只支持 {@code redis_delete_keys}，其它 kind 视为数据异常并抛出，交由调用方重排；
     * payload 为空键列表时视为已完成（无事可做）直接返回。删除后同步返回，
     * 保证下一次核验读到的是"键已消失"；返回值为空或抛异常都会触发 outbox 重放。
     *
     * @param kind        事件类型，当前仅 {@code redis_delete_keys}
     * @param payloadJson 事件 payload 文本，形如 {@code {"keys":["<Sa-Token 令牌 Redis 键名>"]}}
     * @throws IllegalArgumentException 未知事件类型
     * @throws IllegalStateException    payload 无法解析，或 Redis 删除返回空
     */
    private void dispatch(String kind, String payloadJson) {
        if (!"redis_delete_keys".equals(kind)) {
            throw new IllegalArgumentException("未知 outbox 类型: " + kind);
        }
        JsonNode payload;
        try {
            payload = mapper.readTree(payloadJson);
        } catch (Exception e) {
            throw new IllegalStateException("outbox payload 无法解析", e);
        }
        List<String> keys = new ArrayList<>();
        payload.path("keys").forEach(n -> keys.add(n.asText()));
        if (keys.isEmpty()) {
            return;
        }
        // 同步删除确保下一次读到即消失；失败抛出让 outbox 重放
        Long deleted = redis.delete(keys);
        if (deleted == null) {
            throw new IllegalStateException("Redis delete 返回空");
        }
        LOGGER.debug("outbox 清理 Redis 键 expected={} deleted={}", keys.size(), deleted);
    }
}
