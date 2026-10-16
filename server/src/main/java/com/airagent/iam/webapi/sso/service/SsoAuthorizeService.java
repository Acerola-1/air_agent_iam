package com.airagent.iam.webapi.sso.service;

import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.webapi.BrowserHandleRow;

/** 浏览器身份业务接口。 */
public interface SsoAuthorizeService {
    String authorize(
            CurrentSession current,
            BrowserHandleRow handle,
            String clientId,
            String redirectUri,
            String state,
            String origin);
}
