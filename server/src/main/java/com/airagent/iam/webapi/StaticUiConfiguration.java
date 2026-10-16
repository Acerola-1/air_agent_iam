package com.airagent.iam.webapi;

import com.airagent.iam.config.IamProperties;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.CacheControl;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * 生产同源静态托管配置（Configuration 层，仅登记资源映射，不访问数据库、不参与鉴权）。
 *
 * <p>分层位置：Vite 构建产物（{@code web/dist/}）由 Spring Boot 直接以同一 origin 提供，
 * 前端因此可用相对路径调用 {@code /web-api/**} 而无需 CORS。本配置<em>只登记具体前缀</em>
 * （{@code /assets/**}、{@code /demo/**} 与若干具名文件），不使用 {@code /**} 兜底——
 * 未匹配的 API 路径继续走 Spring MVC 默认逻辑保持 404/405，不会被资源处理器接管、
 * 也<em>不会</em>被 {@link com.airagent.iam.webapi.CsrfOriginInterceptor} 与
 * {@link com.airagent.iam.webapi.BrowserSessionInterceptor} 改写为 HTML 或 401；
 * SPA 页面路由由 {@link com.airagent.iam.webapi.controller.SpaController} 显式承接。
 *
 * <p>缓存策略：{@code /assets/**} 命中 Vite 内容哈希文件名，故设
 * {@code max-age=365d, public, immutable}；{@code /demo/**} 与具名入口文件
 * （{@code favicon.ico}、{@code favicon.svg}、{@code vite.svg}、{@code index.html}）
 * 一律 {@code no-cache}，保证重新构建即时生效。
 *
 * <p>静态位置解析：默认 {@code file:./web/dist/} 与 {@code classpath:/static/} 依序尝试，
 * 可经 {@code iam.web.static-locations}（逗号分隔）覆盖；{@code file:} 走文件系统、
 * {@code classpath:} 走类路径。
 *
 * @author Acerola
 */
@Configuration
public class StaticUiConfiguration implements WebMvcConfigurer {

    /** 未配置 {@code iam.web.static-locations} 时依序使用的静态根位置。 */
    private static final String[] DEFAULT_LOCATIONS = {
            "file:./web/dist/", "classpath:/static/"
    };

    /** iam.* 配置（静态资源位置）。 */
    private final IamProperties props;

    /**
     * 构造静态托管配置。
     *
     * @param props {@code iam.*} 配置；仅使用 {@code iam.web.static-locations}
     */
    public StaticUiConfiguration(IamProperties props) {
        this.props = props;
    }

    /**
     * 登记具体前缀的静态资源处理器（不使用 {@code /**} 兜底，理由见类级说明）。
     *
     * @param registry Spring MVC 资源处理器注册表
     */
    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        String[] locations = locations();

        registry.addResourceHandler("/assets/**")
                .addResourceLocations(prefix(locations, "assets/"))
                .setCacheControl(CacheControl.maxAge(365, TimeUnit.DAYS).cachePublic().immutable());

        registry.addResourceHandler("/demo/**")
                .addResourceLocations(prefix(locations, "demo/"))
                .setCacheControl(CacheControl.noCache());

        registry.addResourceHandler("/favicon.ico", "/favicon.svg", "/vite.svg", "/index.html")
                .addResourceLocations(locations)
                .setCacheControl(CacheControl.noCache());
    }

    /**
     * 补齐 demo 目录的"无斜杠 / 尾斜杠 → index.html"重定向，与 SPA 页面路由分离。
     *
     * <p>仅覆盖 {@code /demo/{key}} 与 {@code /demo/{key}/} 两种形态；资源文件本身命中
     * {@link #addResourceHandlers} 中 {@code /demo/**} 的处理器直接返回。
     *
     * @param registry Spring MVC 视图控制器注册表
     */
    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addRedirectViewController("/demo/{key}", "/demo/{key}/index.html");
        registry.addRedirectViewController("/demo/{key}/", "/demo/{key}/index.html");
    }

    /**
     * 解析 {@code iam.web.static-locations}：空/未配置则回落默认；否则按逗号切分并去空白。
     *
     * @return 至少一项的静态位置数组；每项保留原始协议前缀（{@code file:} 或 {@code classpath:}），
     *         末尾斜杠不做二次规整，由 {@link #prefix(String[], String)} 处理
     */
    private String[] locations() {
        String configured = props.web() == null ? null : props.web().staticLocations();
        if (configured == null || configured.isBlank()) {
            return DEFAULT_LOCATIONS;
        }
        return Arrays.stream(configured.split(","))
                .map(String::trim)
                .filter(s -> !s.isBlank())
                .toArray(String[]::new);
    }

    /**
     * 为每个静态根拼接子目录：末尾已有 {@code /} 时直接接续，否则补一个分隔符。
     *
     * @param locations 静态根数组
     * @param suffix    期望的子目录（含末尾 {@code /}，如 {@code assets/}）
     * @return 与入参同长的新数组
     */
    private String[] prefix(String[] locations, String suffix) {
        return Arrays.stream(locations)
                .map(base -> base.endsWith("/") ? base + suffix : base + "/" + suffix)
                .toArray(String[]::new);
    }
}
