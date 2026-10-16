package com.airagent.iam.auth.mapper;

import com.airagent.iam.auth.entity.LoginUserDO;
import com.airagent.iam.auth.entity.SessionContextDO;
import com.airagent.iam.auth.entity.SessionTimerDO;
import com.airagent.iam.auth.vo.TenantMembershipVO;
import java.util.List;
import java.util.UUID;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/** SessionMapper 的类型化数据访问，SQL 由同名 XML 定义。 */
@Mapper
public interface SessionMapper {

    LoginUserDO findLogin(@Param("realm") String realm, @Param("account") String account);

    UUID createSession(
            @Param("userId") UUID userId,
            @Param("realm") String realm,
            @Param("audience") String audience,
            @Param("digest") String digest,
            @Param("idleSeconds") long idleSeconds,
            @Param("absoluteSeconds") long absoluteSeconds);

    UUID mintSsoSession(
            @Param("sourceId") UUID sourceId,
            @Param("audience") String audience,
            @Param("digest") String digest,
            @Param("idleSeconds") long idleSeconds,
            @Param("absoluteSeconds") long absoluteSeconds);

    String revokeSession(@Param("sessionId") UUID sessionId, @Param("reason") String reason);

    List<String> revokeUserSessions(@Param("userId") UUID userId, @Param("reason") String reason);

    List<TenantMembershipVO> selectTenants(@Param("userId") UUID userId);

    UUID switchContext(
            @Param("sessionId") UUID sessionId,
            @Param("tenantId") UUID tenantId,
            @Param("expectedVersion") long expectedVersion);

    SessionTimerDO renew(
            @Param("sessionId") UUID sessionId,
            @Param("expectedVersion") long expectedVersion,
            @Param("idleSeconds") long idleSeconds);

    long setPassword(@Param("userId") UUID userId, @Param("passwordHash") String passwordHash);

    String selectTokenDigest(@Param("sessionId") UUID sessionId);

    SessionContextDO findContext(@Param("digest") String digest);

    String loadSnapshotJson(@Param("digest") String digest);
}
