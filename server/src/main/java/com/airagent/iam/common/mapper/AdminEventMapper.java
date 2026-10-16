package com.airagent.iam.common.mapper;

import java.util.UUID;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/** 与业务变更同事务写入审计与清理事件。 */
@Mapper
public interface AdminEventMapper {

    long insertAudit(@Param("tenantId") UUID tenantId, @Param("actorId") UUID actorId,
                     @Param("action") String action, @Param("targetType") String targetType,
                     @Param("targetId") String targetId, @Param("detailJson") String detailJson,
                     @Param("requestId") String requestId);

    long enqueueRedisDeletes(@Param("payloadJson") String payloadJson);
}
