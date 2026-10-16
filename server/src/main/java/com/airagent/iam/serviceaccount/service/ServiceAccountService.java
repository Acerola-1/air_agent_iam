package com.airagent.iam.serviceaccount.service;

import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.common.vo.PageVO;
import com.airagent.iam.serviceaccount.dto.CreateServiceAccountDTO;
import com.airagent.iam.serviceaccount.dto.CreateServiceTokenDTO;
import com.airagent.iam.serviceaccount.dto.UpdateServiceAccountDTO;
import com.airagent.iam.serviceaccount.vo.ServiceAccountDetailVO;
import com.airagent.iam.serviceaccount.vo.ServiceAccountVO;
import com.airagent.iam.serviceaccount.vo.ServiceTokenIssuedVO;

/** 服务账号及凭据生命周期业务。 */
public interface ServiceAccountService {
    ServiceAccountVO create(CurrentSession actor, CreateServiceAccountDTO req);
    ServiceTokenIssuedVO issueToken(CurrentSession actor, String serviceAccountId, CreateServiceTokenDTO req);
    void revokeToken(CurrentSession actor, String credentialId);
    PageVO<ServiceAccountVO> list(CurrentSession actor, String tenantIdRaw, Integer limitRaw, String cursorRaw);
    ServiceAccountDetailVO get(CurrentSession actor, String idRaw);
    ServiceAccountVO updateStatus(CurrentSession actor, String idRaw, UpdateServiceAccountDTO req);
}
