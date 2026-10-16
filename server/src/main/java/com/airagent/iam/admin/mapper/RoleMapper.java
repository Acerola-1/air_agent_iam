package com.airagent.iam.admin.mapper;

import com.airagent.iam.admin.entity.PermissionDO;
import com.airagent.iam.admin.entity.RoleDO;
import java.util.List;
import java.util.UUID;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/** 角色和权限目录的数据访问，所有调用必须处于可信上下文事务。 */
@Mapper
public interface RoleMapper {

    List<RoleDO> selectPage(@Param("scope") String scope, @Param("afterId") UUID afterId,
                            @Param("fetchSize") int fetchSize);

    RoleDO selectById(@Param("id") UUID id);

    UUID insert(@Param("scope") String scope, @Param("tenantId") UUID tenantId,
                 @Param("code") String code, @Param("name") String name,
                 @Param("description") String description);

    int update(@Param("id") UUID id, @Param("name") String name,
                @Param("description") String description, @Param("status") String status);

    List<String> selectPermissionCodes(@Param("roleId") UUID roleId);

    List<PermissionDO> selectCatalog(@Param("includePlatform") boolean includePlatform);

    List<PermissionDO> selectGrantable(@Param("scope") String scope);

    List<PermissionDO> selectPermissionsByCodes(@Param("codes") List<String> codes);

    int deletePermissions(@Param("roleId") UUID roleId);

    int insertPermissions(@Param("roleId") UUID roleId, @Param("actorId") UUID actorId,
                           @Param("permissions") List<PermissionDO> permissions);
}
