package com.airagent.iam.webapi.sso.service;

import com.airagent.iam.auth.vo.LoginVO;
import com.airagent.iam.webapi.sso.SsoClientView;
import com.airagent.iam.webapi.sso.dto.SsoExchangeDTO;

/** 浏览器身份业务接口。 */
public interface SsoExchangeService {
    LoginVO exchange(SsoClientView client, SsoExchangeDTO req);
}
