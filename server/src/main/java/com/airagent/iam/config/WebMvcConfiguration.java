package com.airagent.iam.config;

import com.airagent.iam.security.internal.InternalClientInterceptor;
import com.airagent.iam.web.BearerAuthInterceptor;
import com.airagent.iam.webapi.BrowserSessionInterceptor;
import com.airagent.iam.webapi.CsrfOriginInterceptor;
import com.airagent.iam.webapi.sso.SsoExchangeInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * MVC 拦截器装配（Config 层）：定义本项目全部鉴权面的挂载范围。
 *
 * <p>路径与认证机制的对应关系（Swagger securityScheme 名以本装配为事实来源）：
 * <ul>
 *   <li>humanBearer —— {@code /v1/auth/**}、{@code /v1/admin/**} 经
 *       BearerAuthInterceptor（登录/登出除外）；</li>
 *   <li>browserCookie —— {@code /web-api/**} 与 {@code /v1/sso/authorize} 经
 *       CsrfOriginInterceptor（Origin/令牌防护），其中 auth/admin/sso-start/authorize
 *       再叠加 BrowserSessionInterceptor（csrf 获取与登录除外）；</li>
 *   <li>internalClient —— {@code /v1/internal/sso/exchange} 经
 *       SsoExchangeInterceptor；其余 {@code /v1/internal/**} 端点由控制器内部
 *       显式调用认证组件（当前装配下不经拦截器）。</li>
 * </ul>
 *
 * @author Acerola
 */
@Configuration
public class WebMvcConfiguration implements WebMvcConfigurer {

    /** 人类 Bearer 拦截器。 */
    private final BearerAuthInterceptor bearerAuthInterceptor;
    /** 内部客户端拦截器（当前未挂载路径）。 */
    private final InternalClientInterceptor internalClientInterceptor;
    /** CSRF/Origin 防护拦截器。 */
    private final CsrfOriginInterceptor csrfOriginInterceptor;
    /** 浏览器会话拦截器。 */
    private final BrowserSessionInterceptor browserSessionInterceptor;
    /** SSO 兑换认证拦截器。 */
    private final SsoExchangeInterceptor ssoExchangeInterceptor;

    /**
     * 注入五个鉴权拦截器实例（注册顺序见 addInterceptors）。
     *
     * @param bearerAuthInterceptor     人类 Bearer 会话拦截器
     * @param internalClientInterceptor 内部客户端拦截器（当前注册表未挂载路径，见疑点记录）
     * @param csrfOriginInterceptor     浏览器面 Origin/CSRF 防护拦截器
     * @param browserSessionInterceptor 浏览器中央会话拦截器
     * @param ssoExchangeInterceptor    SSO 兑换端点客户端认证拦截器
     */
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

    /**
     * 注册拦截器及路径匹配：Bearer 面先行，SSO 兑换独立挂载，浏览器面按
     * CSRF（全 /web-api/** 与 authorize）再会话（子集路径）的顺序叠加。
     * excludePathPatterns 中的登录/csrf 获取端点是唯一公开入口。
     *
     * @param registry Spring MVC 拦截器注册表
     */
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
