package com.airagent.iam.webapi.mapper;

import com.airagent.iam.webapi.BrowserHandleRow;
import java.time.OffsetDateTime;
import java.util.UUID;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/** BrowserHandleMapper 的类型化数据访问，SQL 由同名 XML 定义。 */
@Mapper
public interface BrowserHandleMapper {

    int open(
            @Param("digest") String digest,
            @Param("csrfToken") String csrfToken,
            @Param("expiresAt") OffsetDateTime expiresAt);

    int bind(
            @Param("oldDigest") String oldDigest,
            @Param("newDigest") String newDigest,
            @Param("sessionId") UUID sessionId,
            @Param("csrfToken") String csrfToken,
            @Param("expiresAt") OffsetDateTime expiresAt);

    BrowserHandleRow resolve(@Param("digest") String digest);

    int touch(@Param("digest") String digest, @Param("expiresAt") OffsetDateTime expiresAt);

    UUID revoke(@Param("digest") String digest);
}
