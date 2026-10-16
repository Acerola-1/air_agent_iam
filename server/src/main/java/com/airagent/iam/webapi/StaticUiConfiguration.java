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
 * 生产同源静态托管：Vite 构建产物 web/dist 由 Spring Boot 直接提供。
 * 只登记具体静态资源路径，不使用 /** 兜底——未知 API 路径因此保持 404/405，
 * 不会被资源处理器和认证拦截器改写成 HTML 或 401；页面路由由 SpaController 显式承接。
 */
@Configuration
public class StaticUiConfiguration implements WebMvcConfigurer {

    private static final String[] DEFAULT_LOCATIONS = {
            "file:./web/dist/", "classpath:/static/"
    };

    private final IamProperties props;

    public StaticUiConfiguration(IamProperties props) {
        this.props = props;
    }

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

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addRedirectViewController("/demo/{key}", "/demo/{key}/index.html");
        registry.addRedirectViewController("/demo/{key}/", "/demo/{key}/index.html");
    }

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

    private String[] prefix(String[] locations, String suffix) {
        return Arrays.stream(locations)
                .map(base -> base.endsWith("/") ? base + suffix : base + "/" + suffix)
                .toArray(String[]::new);
    }
}
