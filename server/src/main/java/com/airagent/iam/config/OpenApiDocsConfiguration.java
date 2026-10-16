package com.airagent.iam.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * OpenAPI 文档的静态定义（文档层，不参与任何鉴权判定）。
 *
 * <p>声明本项目实际存在的三种认证方式为文档 securityScheme，供各 Controller 的
 * {@code @SecurityRequirement} 引用。真实认证仍由拦截器链执行
 * （见 WebMvcConfiguration），此处声明仅描述现状：
 * <ul>
 *   <li>{@code humanBearer} —— 人类会话 Bearer：{@code Authorization: Bearer <Sa-Token>}，
 *       由 BearerAuthInterceptor 校验（Redis 存活 + PG 权威双检）；</li>
 *   <li>{@code browserCookie} —— 浏览器会话 Cookie（名称随环境为
 *       air_iam_dev_session 或 __Host-air_iam_session），由
 *       BrowserSessionInterceptor 校验；写操作另需通过 CsrfOriginInterceptor
 *       的同源检查；</li>
 *   <li>{@code internalClient} —— 登记的内部/SSO 客户端凭据：Bearer 客户端密钥，
 *       兼容 Basic（InternalClientAuthenticator 与 SsoClientAuthenticator）。</li>
 * </ul>
 *
 * @author Acerola
 */
@Configuration
public class OpenApiDocsConfiguration {

    /** 人类 Bearer 会话方案名。 */
    private static final String HUMAN_BEARER = "humanBearer";
    /** 浏览器会话 Cookie 方案名。 */
    private static final String BROWSER_COOKIE = "browserCookie";
    /** 内部/SSO 客户端凭据方案名。 */
    private static final String INTERNAL_CLIENT = "internalClient";

    /**
     * 构建文档元信息与认证方案声明。
     *
     * @return OpenAPI 模型；springdoc 据此在 /v3/api-docs 输出规范
     */
    @Bean
    public OpenAPI iamOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("Air Agent IAM")
                        .version("1.0.0")
                        .description("企业账号、组织与鉴权独立服务。/v1/admin 与 /v1/auth 为人类 Bearer 面；"
                                + "/web-api 为浏览器会话 Cookie + CSRF 面；/v1/internal 为登记客户端面。"
                                + "所有响应错误体为统一错误信封。"))
                .schemaRequirement(HUMAN_BEARER, new SecurityScheme()
                        .type(SecurityScheme.Type.HTTP)
                        .scheme("bearer")
                        .bearerFormat("opaque")
                        .description("人类会话令牌：Authorization: Bearer <Sa-Token>，经 Redis 存活与 PG 权威双重核验"))
                .schemaRequirement(BROWSER_COOKIE, new SecurityScheme()
                        .type(SecurityScheme.Type.APIKEY)
                        .in(SecurityScheme.In.COOKIE)
                        .name("air_iam_dev_session / __Host-air_iam_session")
                        .description("浏览器中央会话 Cookie；本服务仅监听回环，故开发态非 Secure；写操作还需通过 Origin 同源检查"))
                .schemaRequirement(INTERNAL_CLIENT, new SecurityScheme()
                        .type(SecurityScheme.Type.HTTP)
                        .scheme("bearer")
                        .bearerFormat("client-secret")
                        .description("登记内部客户端的 Bearer 凭据（兼容 Basic），由 InternalClientAuthenticator/SsoClientAuthenticator 校验"));
    }
}
