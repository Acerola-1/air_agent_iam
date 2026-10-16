package com.airagent.iam.serviceaccount.mapper;

import com.airagent.iam.serviceaccount.entity.IssuedTokenDO;
import com.airagent.iam.serviceaccount.entity.ServiceAccountDO;
import com.airagent.iam.serviceaccount.entity.ServiceTokenDO;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/** ServiceAccountMapper 的类型化数据访问，SQL 由同名 XML 定义。 */
@Mapper
public interface ServiceAccountMapper {

    ServiceAccountDO selectById(@Param("id") UUID id);

    ServiceAccountDO lockById(@Param("id") UUID id);

    UUID insert(
            @Param("account") String account,
            @Param("name") String name,
            @Param("tenantId") UUID tenantId,
            @Param("audiences") List<String> audiences,
            @Param("expiresAt") OffsetDateTime expiresAt,
            @Param("actorId") UUID actorId);

    int insertPermission(
            @Param("tenantId") UUID tenantId,
            @Param("id") UUID id,
            @Param("permissionId") UUID permissionId,
            @Param("actorId") UUID actorId);

    IssuedTokenDO issueToken(
            @Param("id") UUID id,
            @Param("credentialId") String credentialId,
            @Param("digest") String digest,
            @Param("expiresAt") OffsetDateTime expiresAt,
            @Param("overlapUntil") OffsetDateTime overlapUntil);

    int revokeToken(@Param("credentialId") String credentialId);

    List<ServiceAccountDO> selectPage(
            @Param("tenantId") UUID tenantId,
            @Param("afterId") UUID afterId,
            @Param("fetchSize") int fetchSize);

    List<ServiceTokenDO> selectTokens(@Param("id") UUID id);

    int updateStatus(@Param("id") UUID id, @Param("status") String status);

    List<String> selectPermissionCodes(@Param("id") UUID id);

    List<UUID> resolvePermissions(@Param("codes") List<String> codes);
}
