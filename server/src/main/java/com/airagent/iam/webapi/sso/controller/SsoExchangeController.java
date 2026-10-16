package com.airagent.iam.webapi.sso.controller;

import com.airagent.iam.auth.vo.LoginVO;
import com.airagent.iam.webapi.sso.SsoClientView;
import com.airagent.iam.webapi.sso.SsoExchangeInterceptor;
import com.airagent.iam.webapi.sso.dto.SsoExchangeDTO;
import com.airagent.iam.webapi.sso.service.SsoExchangeService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * SSO 应用令牌兑换：sso_clients Basic 认证由 {@link SsoExchangeInterceptor} 处理；
 * access_token 只出现在本次服务端到服务端响应中，浏览器与 URL 均不可见。
 */
@RestController
public class SsoExchangeController {

    private final SsoExchangeService exchangeService;

    public SsoExchangeController(SsoExchangeService exchangeService) {
        this.exchangeService = exchangeService;
    }

    @PostMapping("/v1/internal/sso/exchange")
    public LoginVO exchange(HttpServletRequest request,
                                @RequestBody(required = false) SsoExchangeDTO body) {
        SsoClientView client = (SsoClientView) request
                .getAttribute(SsoExchangeInterceptor.SSO_CLIENT_ATTRIBUTE);
        return exchangeService.exchange(client, body);
    }
}
