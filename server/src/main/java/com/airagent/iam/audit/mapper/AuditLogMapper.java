package com.airagent.iam.audit.mapper;

import com.airagent.iam.audit.entity.AuditLogDO;
import java.util.List;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/** 仅在已设置请求上下文的 Spring 事务内查询，租户边界由 RLS 强制。 */
@Mapper
public interface AuditLogMapper {

    List<AuditLogDO> selectPage(@Param("beforeId") Long beforeId,
                                @Param("actionPattern") String actionPattern,
                                @Param("fetchSize") int fetchSize);
}
