package com.airagent.iam.common.mapper;

import java.util.UUID;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/**
 * 设置当前 Spring 事务中的可信数据库请求上下文。
 */
@Mapper
public interface RequestContextMapper {

    /**
     * 在调用方事务内设置本地上下文，禁止作为授权来源。
     *
     * @param userId 已认证用户标识，可为空
     * @param tenantId 已认证当前企业标识，可为空
     * @param platform 是否为已经授权的平台操作
     * @return 数据库函数执行结果行数
     */
    int setContext(@Param("userId") UUID userId,
                   @Param("tenantId") UUID tenantId,
                   @Param("platform") boolean platform);
}
