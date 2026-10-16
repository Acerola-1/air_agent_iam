package com.airagent.iam.admin.mapper;

import com.airagent.iam.admin.entity.TenantEntitlementDO;
import java.util.List;
import java.util.UUID;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/**
 * iam.tenant_entitlements 的数据访问接口。
 */
@Mapper
public interface EntitlementMapper {

    List<TenantEntitlementDO> selectByTenant(@Param("tenantId") UUID tenantId,
                                             @Param("afterResourceCode") String afterResourceCode,
                                             @Param("fetchSize") int fetchSize);

    TenantEntitlementDO selectOne(@Param("tenantId") UUID tenantId,
                                  @Param("resourceCode") String resourceCode);

    Long selectTenantAuthRevision(@Param("tenantId") UUID tenantId);

    /** 目标企业状态；不存在返回null。 */
    String selectTenantStatus(@Param("tenantId") UUID tenantId);

    /** 当前企业的资源启用与开通交集计数。 */
    int countAvailable(@Param("tenantId") UUID tenantId, @Param("resourceCode") String resourceCode);

    UUID selectTenantIdByCode(@Param("tenantCode") String tenantCode);

    int upsert(@Param("tenantId") UUID tenantId, @Param("resourceCode") String resourceCode,
               @Param("status") String status, @Param("updatedBy") UUID updatedBy,
               @Param("expectedRevision") long expectedRevision,
               @Param("expectedTenantRevision") long expectedTenantRevision);

    int insertIfAbsent(@Param("tenantId") UUID tenantId, @Param("resourceCode") String resourceCode,
                       @Param("status") String status, @Param("updatedBy") UUID updatedBy);

    List<String> selectActiveEntitledResources(@Param("tenantId") UUID tenantId);
}
