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
 * outbox → Redis 失效键清理中继。
 *
 * <p>PG 授权状态是权威：Redis 故障期间拒绝路径仍以 PG 为准（撤销后 introspection 不放行），
 * 中继只负责最终清理 Redis 残留；单条失败按指数退避重放，超限标 dead。
 */
@Component
public class OutboxRelay {

    private static final Logger LOGGER = LoggerFactory.getLogger(OutboxRelay.class);
    private static final int MAX_ATTEMPTS = 10;

    private final InfrastructureMapper infrastructureMapper;
    private final StringRedisTemplate redis;
    private final ObjectMapper mapper;

    public OutboxRelay(InfrastructureMapper infrastructureMapper, StringRedisTemplate redis, ObjectMapper mapper) {
        this.infrastructureMapper = infrastructureMapper;
        this.redis = redis;
        this.mapper = mapper;
    }

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
