package com.airagent.iam.audit.service;

import com.airagent.iam.audit.dto.AuditLogQueryDTO;
import com.airagent.iam.audit.vo.AuditLogVO;
import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.common.vo.PageVO;

/** 平台及企业审计查询业务。 */
public interface AuditService {

    PageVO<AuditLogVO> list(CurrentSession actor, AuditLogQueryDTO query);
}
