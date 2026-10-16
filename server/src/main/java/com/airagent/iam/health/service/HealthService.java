package com.airagent.iam.health.service;

import com.airagent.iam.health.vo.HealthStatusVO;

/**
 * 依赖健康状态查询接口（Service 层，只读，不返回连接凭据）。
 *
 * <p>调用场景：本机脚本、容器编排与验收流程轮询 {@code GET /healthz}，据此判断实例
 * 是否真正可用——身份服务的可用性同时依赖 PostgreSQL（权威状态）与 Redis（Sa-Token
 * 会话存活索引），两者缺一都会让业务面失败关闭。
 *
 * <p>边界：本接口不参与任何鉴权裁决，也不得被业务代码当作放行依据；每次调用都真实
 * 往返探测，不缓存、不写入。探测失败以布尔位表达，不向外抛异常。
 *
 * @author Acerola
 */
public interface HealthService {

    /**
     * 查询 PostgreSQL 与 Redis 的实际可用状态。
     *
     * @return 不包含秘密的依赖状态：两项均可用为 {@code ok}，任一不可用为 {@code degraded}；
     *         依赖故障不抛异常、也不改变调用方看到的 HTTP 状态
     */
    HealthStatusVO getHealth();
}
