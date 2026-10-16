package com.airagent.iam.health.service.impl;

import com.airagent.iam.config.IamProperties;
import com.airagent.iam.health.mapper.HealthMapper;
import com.airagent.iam.health.service.HealthService;
import com.airagent.iam.health.vo.HealthStatusVO;
import org.springframework.data.redis.core.RedisOperations;
import org.springframework.stereotype.Service;

/**
 * 汇总真实依赖探测结果。
 */
@Service
public class HealthServiceImpl implements HealthService {

    private static final String HEALTH_PROBE_KEY = "iam:health:probe";
    private static final String STATUS_OK = "ok";
    private static final String STATUS_DEGRADED = "degraded";

    private final HealthMapper healthMapper;
    private final RedisOperations<String, Object> redisOperations;
    private final IamProperties properties;

    public HealthServiceImpl(HealthMapper healthMapper,
                             RedisOperations<String, Object> redisOperations,
                             IamProperties properties) {
        this.healthMapper = healthMapper;
        this.redisOperations = redisOperations;
        this.properties = properties;
    }

    @Override
    public HealthStatusVO getHealth() {
        boolean postgresAvailable = isPostgresAvailable();
        boolean redisAvailable = isRedisAvailable();
        String status = postgresAvailable && redisAvailable ? STATUS_OK : STATUS_DEGRADED;
        return new HealthStatusVO(status, properties.issuer(), postgresAvailable, redisAvailable);
    }

    private boolean isPostgresAvailable() {
        try {
            return healthMapper.checkConnection() == 1;
        } catch (RuntimeException exception) {
            return false;
        }
    }

    private boolean isRedisAvailable() {
        try {
            redisOperations.opsForValue().get(HEALTH_PROBE_KEY);
            return true;
        } catch (RuntimeException exception) {
            return false;
        }
    }
}
