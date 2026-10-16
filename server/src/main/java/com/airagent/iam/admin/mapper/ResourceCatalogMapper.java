package com.airagent.iam.admin.mapper;

import com.airagent.iam.admin.entity.ResourceCatalogDO;
import com.airagent.iam.admin.entity.ResourcePermissionDO;
import java.util.List;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/**
 * iam.resource_catalog 与资源权限绑定的数据访问接口。
 */
@Mapper
public interface ResourceCatalogMapper {

    List<ResourceCatalogDO> selectPage(@Param("status") String status,
                                       @Param("afterSort") Integer afterSort,
                                       @Param("afterCode") String afterCode,
                                       @Param("fetchSize") int fetchSize);

    /** 按稳定资源编码分页，供企业开通投影使用。 */
    List<ResourceCatalogDO> selectCodePage(@Param("afterCode") String afterCode, @Param("fetchSize") int fetchSize);

    ResourceCatalogDO selectByCode(@Param("code") String code);

    List<ResourcePermissionDO> selectPermissionsByResource(@Param("resourceCode") String resourceCode);

    List<ResourcePermissionDO> selectPermissionsByCodes(@Param("codes") List<String> codes);

    int insert(@Param("code") String code, @Param("nameZh") String nameZh,
               @Param("sort") int sort, @Param("parentCode") String parentCode);

    int insertPermission(@Param("code") String code, @Param("nameZh") String nameZh,
                         @Param("resourceCode") String resourceCode,
                         @Param("grantableToTenants") boolean grantableToTenants);

    int update(@Param("code") String code, @Param("nameZh") String nameZh,
               @Param("sort") Integer sort, @Param("status") String status,
               @Param("expectedRevision") long expectedRevision);

    int countPermissionConflicts(@Param("codes") List<String> codes);

    int countResourceConflicts(@Param("code") String code);

    List<Integer> lockResourcesAndTenants(@Param("resourceCodes") List<String> resourceCodes,
                                          @Param("tenantIds") List<java.util.UUID> tenantIds);

    List<Integer> lockTenants(@Param("tenantIds") List<java.util.UUID> tenantIds);

    /** 授权写按目录编码取得统一行锁；调用方随后锁企业与目标主体。 */
    List<Integer> lockCatalog();

    /** 仅返回目标企业当前可下放的已启用权限；资源权限还需开通交集。 */
    List<ResourcePermissionDO> selectMachineOptions(@Param("tenantId") java.util.UUID tenantId);
}
