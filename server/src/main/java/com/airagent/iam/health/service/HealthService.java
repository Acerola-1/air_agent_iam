package com.airagent.iam.health.service;

import com.airagent.iam.health.vo.HealthStatusVO;

/**
 * 提供当前依赖状态，不返回连接凭据。
 */
public interface HealthService {

    /**
     * 查询 PostgreSQL 与 Redis 的实际可用状态。
     *
     * @return 不包含秘密的依赖状态
     */
    HealthStatusVO getHealth();
}
