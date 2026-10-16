package com.airagent.iam.security.internal.mapper;

import com.airagent.iam.security.internal.InternalClient;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/** InternalClientMapper 的类型化数据访问，SQL 由同名 XML 定义。 */
@Mapper
public interface InternalClientMapper {

    InternalClient authenticate(@Param("clientId") String clientId, @Param("digest") String digest);
    InternalClient authenticateBearer(@Param("digest") String digest);
}
