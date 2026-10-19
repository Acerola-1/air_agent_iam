package com.airagent.iam.ops.mapper;

import com.airagent.iam.ops.entity.OpsBusinessResourceDO;
import com.airagent.iam.ops.entity.OpsEntitlementDO;
import com.airagent.iam.ops.entity.OpsLegacyPermissionDO;
import com.airagent.iam.ops.entity.OpsMembershipDO;
import com.airagent.iam.ops.entity.OpsPermissionDO;
import com.airagent.iam.ops.entity.OpsRoleDO;
import com.airagent.iam.ops.entity.OpsTenantDO;
import com.airagent.iam.ops.entity.OpsUserDO;
import java.util.List;
import java.util.UUID;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/**
 * 一次性运维命令的数据访问。所有方法由调用方事务包裹；写路径依赖数据库 RLS 与边界触发器。
 */
@Mapper
public interface OpsMapper {

    OpsUserDO selectUser(@Param("id") UUID id);

    OpsTenantDO selectTenant(@Param("id") UUID id);

    OpsTenantDO selectTenantForUpdate(@Param("id") UUID id);

    List<OpsTenantDO> selectActiveTenants();

    OpsMembershipDO selectMembership(@Param("tenantId") UUID tenantId,
                                     @Param("userId") UUID userId);

    OpsMembershipDO selectMembershipForUpdate(@Param("tenantId") UUID tenantId,
                                              @Param("userId") UUID userId);

    UUID insertMembership(@Param("tenantId") UUID tenantId,
                          @Param("userId") UUID userId,
                          @Param("createdBy") UUID createdBy);

    OpsRoleDO selectTenantRole(@Param("tenantId") UUID tenantId,
                               @Param("code") String code);

    OpsRoleDO selectTenantRoleForUpdate(@Param("tenantId") UUID tenantId,
                                        @Param("code") String code);

    UUID insertTenantRole(@Param("tenantId") UUID tenantId,
                          @Param("code") String code,
                          @Param("name") String name,
                          @Param("description") String description);

    OpsPermissionDO selectPermissionByCode(@Param("code") String code);

    List<OpsPermissionDO> selectPermissionsByCodes(@Param("codes") List<String> codes);

    List<OpsBusinessResourceDO> selectActiveBusinessResources();

    List<String> selectRolePermissionCodes(@Param("roleId") UUID roleId);

    int insertRolePermission(@Param("roleId") UUID roleId,
                             @Param("permissionId") UUID permissionId,
                             @Param("grantedBy") UUID grantedBy);

    int countMembershipRole(@Param("membershipId") UUID membershipId,
                            @Param("roleId") UUID roleId);

    int insertMembershipRole(@Param("tenantId") UUID tenantId,
                             @Param("membershipId") UUID membershipId,
                             @Param("roleId") UUID roleId,
                             @Param("grantedBy") UUID grantedBy);

    OpsEntitlementDO selectEntitlement(@Param("tenantId") UUID tenantId,
                                       @Param("resourceCode") String resourceCode);

    int activateEntitlement(@Param("tenantId") UUID tenantId,
                            @Param("resourceCode") String resourceCode,
                            @Param("updatedBy") UUID updatedBy);

    long selectTenantAuthRevision(@Param("tenantId") UUID tenantId);

    long selectMembershipRevision(@Param("membershipId") UUID membershipId);

    List<OpsLegacyPermissionDO> selectLegacyPermissions(@Param("codes") List<String> codes);

    int deleteRolePermissionsByPermission(@Param("permissionId") UUID permissionId);

    int deleteServiceAccountPermissionsByPermission(@Param("permissionId") UUID permissionId);

    int deletePermission(@Param("permissionId") UUID permissionId);

    List<String> selectExistingTables(@Param("names") List<String> names);
}
