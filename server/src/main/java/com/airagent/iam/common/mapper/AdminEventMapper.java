package com.airagent.iam.common.mapper;

import java.util.UUID;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/**
 * 管理线共用事件写入（Mapper 层，SQL 见 mapper/common/AdminEventMapper.xml）。
 *
 * <p>两个方法都是 SECURITY DEFINER 数据库函数的调用面，必须在业务变更的同一事务内
 * 使用：审计失败即业务回滚，事件不丢失。actor 形态在 SQL 中固定为 {@code human}，
 * 服务账号形态由其他调用方自行写入。
 *
 * @author Acerola
 */
@Mapper
public interface AdminEventMapper {

    /**
     * 经 {@code iam_auth.write_audit} 写入一条人类主体的审计日志。
     *
     * <p>detail 以 JSONB 落库；null 值已在调用方（AdminSupport.audit）剔除，
     * 约定不含任何秘密值。request_id 取自 MDC，与错误信封可互相追踪。
     *
     * @param tenantId   企业上下文；平台级操作传 {@code null}（RLS 按平台标记放行）
     * @param actorId    执行人用户 UUID
     * @param action     动作码，如 {@code admin.user.create}
     * @param targetType 目标资源类型，如 {@code user}
     * @param targetId   目标资源标识文本
     * @param detailJson 序列化后的 JSONB 文本；调用方保证合法 JSON
     * @param requestId  本次请求的 request_id（可为 {@code null}）
     * @return 数据库生成的审计行 id
     */
    long insertAudit(@Param("tenantId") UUID tenantId, @Param("actorId") UUID actorId,
                     @Param("action") String action, @Param("targetType") String targetType,
                     @Param("targetId") String targetId, @Param("detailJson") String detailJson,
                     @Param("requestId") String requestId);

    /**
     * 经 {@code iam_auth.enqueue_outbox} 登记 {@code redis_delete_keys} 清理事件（同事务）。
     *
     * <p>事件由 OutboxRelay 异步投递，至少一次语义；payload 中键构形必须与
     * DigestStpLogic 的 Sa-Token 键一致。
     *
     * @param payloadJson {@code {"keys":[...]}} 形态的 JSON 文本
     * @return 数据库生成的 outbox 事件 id
     */
    long enqueueRedisDeletes(@Param("payloadJson") String payloadJson);
}
