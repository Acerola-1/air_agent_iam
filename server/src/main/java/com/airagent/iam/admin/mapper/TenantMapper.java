package com.airagent.iam.admin.mapper;

import com.airagent.iam.admin.entity.DepartmentDO;
import com.airagent.iam.admin.entity.MembershipDO;
import com.airagent.iam.admin.entity.TenantDO;
import com.airagent.iam.admin.entity.UserDO;
import java.util.List;
import java.util.UUID;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/** 企业、成员和部门的数据访问。 */
@Mapper
public interface TenantMapper {

    List<TenantDO> selectTenants(@Param("afterId") UUID afterId, @Param("fetchSize") int fetchSize);

    TenantDO selectTenant(@Param("id") UUID id);

    TenantDO lockTenant(@Param("id") UUID id);

    UUID insertTenant(@Param("code") String code, @Param("name") String name, @Param("actorId") UUID actorId);

    int updateTenant(@Param("id") UUID id, @Param("name") String name, @Param("status") String status);

    List<MembershipDO> selectMembers(
            @Param("tenantId") UUID tenantId,
            @Param("afterId") UUID afterId,
            @Param("fetchSize") int fetchSize);

    MembershipDO selectMembership(@Param("tenantId") UUID tenantId, @Param("id") UUID id);

    MembershipDO lockMembership(@Param("tenantId") UUID tenantId, @Param("id") UUID id);

    int countMembership(@Param("tenantId") UUID tenantId, @Param("userId") UUID userId);

    List<UUID> findUserIds(@Param("account") String account);

    UUID insertMembership(
            @Param("tenantId") UUID tenantId,
            @Param("userId") UUID userId,
            @Param("departmentId") UUID departmentId,
            @Param("actorId") UUID actorId);

    int insertMemberRole(
            @Param("tenantId") UUID tenantId,
            @Param("membershipId") UUID membershipId,
            @Param("roleId") UUID roleId,
            @Param("actorId") UUID actorId);

    int deleteMemberRoles(@Param("tenantId") UUID tenantId, @Param("membershipId") UUID membershipId);

    int updateMembership(
            @Param("tenantId") UUID tenantId,
            @Param("membershipId") UUID membershipId,
            @Param("departmentId") UUID departmentId,
            @Param("status") String status);

    int deleteMembership(@Param("tenantId") UUID tenantId, @Param("membershipId") UUID membershipId);

    List<DepartmentDO> selectDepartments(
            @Param("tenantId") UUID tenantId,
            @Param("afterId") UUID afterId,
            @Param("fetchSize") int fetchSize);

    DepartmentDO selectDepartment(@Param("id") UUID id);

    UUID insertDepartment(
            @Param("tenantId") UUID tenantId,
            @Param("parentId") UUID parentId,
            @Param("code") String code,
            @Param("name") String name);

    int updateDepartment(
            @Param("tenantId") UUID tenantId,
            @Param("id") UUID id,
            @Param("name") String name,
            @Param("replaceParent") boolean replaceParent,
            @Param("parentId") UUID parentId,
            @Param("status") String status);

    List<UUID> selectTenantRoleIds(@Param("tenantId") UUID tenantId, @Param("codes") List<String> codes);

    UserDO selectMemberUser(@Param("membershipId") UUID membershipId);

    List<String> selectMemberRoleCodes(@Param("membershipId") UUID membershipId);
}
