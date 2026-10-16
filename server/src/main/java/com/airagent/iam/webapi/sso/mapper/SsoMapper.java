package com.airagent.iam.webapi.sso.mapper;

import com.airagent.iam.webapi.sso.SsoClientView;
import com.airagent.iam.webapi.sso.entity.SsoRegistrationDO;
import com.airagent.iam.webapi.sso.entity.SsoStateDO;
import java.time.OffsetDateTime;
import java.util.UUID;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/** SsoMapper 的类型化数据访问，SQL 由同名 XML 定义。 */
@Mapper
public interface SsoMapper {

    SsoClientView authenticate(@Param("clientId") String clientId, @Param("digest") String digest);

    SsoRegistrationDO selectClient(@Param("clientId") String clientId);

    int saveState(
            @Param("digest") String digest,
            @Param("clientId") String clientId,
            @Param("handleDigest") String handleDigest,
            @Param("callbackUrl") String callbackUrl,
            @Param("expiresAt") OffsetDateTime expiresAt);

    int saveTicket(
            @Param("digest") String digest,
            @Param("clientId") String clientId,
            @Param("sessionId") UUID sessionId,
            @Param("callbackUrl") String callbackUrl,
            @Param("expiresAt") OffsetDateTime expiresAt);

    UUID consumeTicket(
            @Param("digest") String digest,
            @Param("clientId") String clientId,
            @Param("callbackUrl") String callbackUrl);

    SsoStateDO consumeState(@Param("digest") String digest);
    SsoClientView authenticateBearer(@Param("digest") String digest);
}
