package com.airagent.iam.auth.service;

import com.airagent.iam.auth.AuthoritySnapshot;
import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.auth.dto.ChangePasswordDTO;
import com.airagent.iam.auth.dto.LoginDTO;
import com.airagent.iam.auth.dto.RenewDTO;
import com.airagent.iam.auth.dto.SwitchTenantDTO;
import com.airagent.iam.auth.vo.IdentityVO;
import com.airagent.iam.auth.vo.LoginVO;
import com.airagent.iam.auth.vo.SessionTimersVO;
import com.airagent.iam.auth.vo.TenantMembershipVO;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** 登录、会话及身份权威业务。 */
public interface SessionService {
    LoginVO login(LoginDTO req);
    LoginVO issueSsoSession(CurrentSession source, String audience);
    void logout(String rawToken);
    void logout(CurrentSession current);
    void logoutAll(String rawToken);
    void logoutAll(CurrentSession current);
    IdentityVO me(String rawToken);
    IdentityVO identityOf(CurrentSession current);
    List<TenantMembershipVO> tenants(String rawToken);
    List<TenantMembershipVO> tenants(CurrentSession current);
    IdentityVO switchTenant(String rawToken, SwitchTenantDTO req);
    void switchTenant(CurrentSession current, SwitchTenantDTO req);
    SessionTimersVO renew(String rawToken, RenewDTO req);
    SessionTimersVO renew(CurrentSession current, RenewDTO req);
    void changePassword(String rawToken, ChangePasswordDTO req);
    void changePassword(CurrentSession current, ChangePasswordDTO req);
    AuthoritySnapshot requireSnapshot(String rawToken);
    CurrentSession requireCurrent(String rawToken);
    CurrentSession requireCurrentBySessionId(UUID sessionId);
    AuthoritySnapshot loadSnapshot(String digest);
    void audit(
            UUID tenantId,
            UUID actor,
            String action,
            String targetType,
            String targetId,
            Map<String, Object> detail);
}
