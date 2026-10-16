package com.airagent.iam.admin.service;

import com.airagent.iam.admin.dto.CreateResourceDTO;
import com.airagent.iam.admin.dto.ExpectedContextDTO;
import com.airagent.iam.admin.dto.UpdateEntitlementDTO;
import com.airagent.iam.admin.dto.UpdateResourceDTO;
import com.airagent.iam.admin.vo.EntitlementVO;
import com.airagent.iam.admin.vo.ResourceVO;
import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.common.vo.PageVO;

/**
 * 资源目录与企业开通管理服务。
 */
public interface ResourceAdminService {

    /** 仅平台服务账号管理者可读取指定企业的建档选项与修订。 */
    com.airagent.iam.admin.vo.ServiceResourceOptionsVO serviceResourceOptions(CurrentSession actor, String tenantId);

    PageVO<ResourceVO> listResources(CurrentSession actor, String status, Integer limit, String cursor);

    ResourceVO createResource(CurrentSession actor, CreateResourceDTO dto);

    ResourceVO updateResource(CurrentSession actor, String resourceCode, UpdateResourceDTO dto);

    PageVO<EntitlementVO> listTenantEntitlements(CurrentSession actor, String tenantId,
                                                 Integer limit, String cursor);

    EntitlementVO updateEntitlement(CurrentSession actor, String tenantId, String resourceCode,
                                    UpdateEntitlementDTO dto);

    PageVO<EntitlementVO> listCurrentTenantResources(CurrentSession actor, Integer limit, String cursor);
}
