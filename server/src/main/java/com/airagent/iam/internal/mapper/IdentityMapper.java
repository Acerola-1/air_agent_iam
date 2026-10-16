package com.airagent.iam.internal.mapper;

import com.airagent.iam.internal.entity.IssuedVerificationRefDO;
import com.airagent.iam.internal.entity.VerificationRefDO;
import java.util.UUID;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/** IdentityMapper 的类型化数据访问，SQL 由同名 XML 定义。 */
@Mapper
public interface IdentityMapper {

    VerificationRefDO findReference(
            @Param("id") UUID id,
            @Param("clientId") String clientId,
            @Param("audience") String audience);

    String snapshotForSession(@Param("sessionId") UUID sessionId);

    int touchReference(@Param("id") UUID id);

    IssuedVerificationRefDO createReference(
            @Param("clientId") String clientId,
            @Param("audience") String audience,
            @Param("sessionId") UUID sessionId,
            @Param("userId") UUID userId,
            @Param("tenantId") UUID tenantId,
            @Param("revisionsJson") String revisionsJson,
            @Param("ttlSeconds") long ttlSeconds);

    String loadServiceIdentity(@Param("digest") String digest);
}
