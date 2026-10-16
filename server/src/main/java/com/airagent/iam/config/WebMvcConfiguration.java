package com.airagent.iam.config;

import com.airagent.iam.security.internal.InternalClientInterceptor;
import com.airagent.iam.web.BearerAuthInterceptor;
import com.airagent.iam.webapi.BrowserSessionInterceptor;
import com.airagent.iam.webapi.CsrfOriginInterceptor;
import com.airagent.iam.webapi.sso.SsoExchangeInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebMvcConfiguration implements WebMvcConfigurer {

    private final BearerAuthInterceptor bearerAuthInterceptor;
    private final InternalClientInterceptor internalClientInterceptor;
    private final CsrfOriginInterceptor csrfOriginInterceptor;
    private final BrowserSessionInterceptor browserSessionInterceptor;
    private final SsoExchangeInterceptor ssoExchangeInterceptor;

    public WebMvcConfiguration(BearerAuthInterceptor bearerAuthInterceptor,
                               InternalClientInterceptor internalClientInterceptor,
                               CsrfOriginInterceptor csrfOriginInterceptor,
                               BrowserSessionInterceptor browserSessionInterceptor,
                               SsoExchangeInterceptor ssoExchangeInterceptor) {
        this.bearerAuthInterceptor = bearerAuthInterceptor;
        this.internalClientInterceptor = internalClientInterceptor;
        this.csrfOriginInterceptor = csrfOriginInterceptor;
        this.browserSessionInterceptor = browserSessionInterceptor;
        this.ssoExchangeInterceptor = ssoExchangeInterceptor;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(bearerAuthInterceptor)
                .addPathPatterns("/v1/auth/**", "/v1/admin/**")
                .excludePathPatterns("/v1/auth/login", "/v1/auth/logout");
        registry.addInterceptor(ssoExchangeInterceptor)
                .addPathPatterns("/v1/internal/sso/exchange");

        registry.addInterceptor(csrfOriginInterceptor)
                .addPathPatterns("/web-api/**", "/v1/sso/authorize");
        registry.addInterceptor(browserSessionInterceptor)
                .addPathPatterns("/web-api/auth/**", "/web-api/admin/**", "/web-api/sso/start", "/v1/sso/authorize")
                .excludePathPatterns("/web-api/auth/csrf", "/web-api/auth/login");
    }
}
