package com.airagent.iam.admin.mapper;

import com.airagent.iam.admin.entity.UserDO;
import java.util.List;
import java.util.UUID;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/** 平台账号管理数据访问。 */
@Mapper
public interface UserMapper {

    List<UserDO> selectPage(@Param("query") String query, @Param("afterId") UUID afterId,
                            @Param("fetchSize") int fetchSize);

    UserDO selectById(@Param("id") UUID id);

    UserDO selectForUpdate(@Param("id") UUID id);

    UUID insert(@Param("account") String account, @Param("displayName") String displayName,
                 @Param("passwordHash") String passwordHash);

    int updateDisplayName(@Param("id") UUID id, @Param("displayName") String displayName);

    int updateStatus(@Param("id") UUID id, @Param("status") String status);

    long setPassword(@Param("id") UUID id, @Param("passwordHash") String passwordHash);

    List<String> revokeSessions(@Param("id") UUID id, @Param("reason") String reason);

    List<UUID> selectPlatformRoleIds(@Param("codes") List<String> codes);

    int deletePlatformRoles(@Param("userId") UUID userId);

    int insertPlatformRole(@Param("userId") UUID userId, @Param("roleId") UUID roleId,
                            @Param("actorId") UUID actorId);

    List<String> selectPlatformRoleCodes(@Param("userId") UUID userId);
}
