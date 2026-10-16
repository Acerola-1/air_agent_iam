package com.airagent.iam.webapi.controller;

import com.airagent.iam.config.IamProperties;
import com.airagent.iam.web.error.ApiException;
import io.swagger.v3.oas.annotations.Operation;
import java.nio.file.Path;
import java.util.Arrays;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * SPA 页面导航入口（Controller 层，返回 {@code text/html}，不提供 JSON 业务契约）。
 *
 * <p>分层位置：显式白名单挂载 {@code /}、{@code /login}、{@code /profile}、{@code /admin}、
 * {@code /admin/**} 这几条 GET（Spring MVC 会自动同时响应 HEAD），一律返回同一份
 * Vite 构建的 {@code index.html}，由前端路由接管后续渲染。<em>刻意不使用</em>
 * {@code /**} 兜底——未知路径与 {@code /web-api}、{@code /v1} 前缀继续走各自的
 * JSON 404/405 语义，不会被改写成 HTML，也就不会与浏览器会话/CSRF 拦截器混淆。
 *
 * <p>协作关系：静态资源与 {@code /demo/**} 由 {@link com.airagent.iam.webapi.StaticUiConfiguration}
 * 承担；本类只负责"入口 HTML 的分发"。Cookie 名/安全属性由 {@link com.airagent.iam.webapi.WebCookies}
 * 定义，与本类无耦合。
 *
 * <p>构建缺失：解析顺序命中不到可读的 {@code index.html}（{@code web/dist/} 未构建）时
 * 抛 {@link ApiException#notFound(String)}，由 {@link com.airagent.iam.web.error.GlobalExceptionHandler}
 * 转标准 404 错误信封。
 *
 * @author Acerola
 */
@RestController
public class SpaController {

    /** 未配置 {@code iam.web.static-locations} 时依序尝试的静态根（末尾保留 {@code /}）。 */
    private static final String[] DEFAULT_LOCATIONS = {
            "file:./web/dist/", "classpath:/static/"
    };

    /** iam.* 配置（静态资源与开关）。 */
    private final IamProperties props;

    /**
     * 构造 SPA 入口路由。
     *
     * @param props {@code iam.*} 配置；仅使用 {@code iam.web.static-locations}
     */
    public SpaController(IamProperties props) {
        this.props = props;
    }

    /**
     * 返回 SPA 入口 {@code index.html}；非 REST API，无请求体，无路径参数。
     *
     * <p>本端点由 {@link #DEFAULT_LOCATIONS} 与 {@code iam.web.static-locations} 依序解析，
     * 首个可读的 {@code index.html} 命中即返回；响应带 {@code Cache-Control: no-cache}
     * 与 {@code Content-Type: text/html}，浏览器刷新即可拿到最新构建。此处不做认证与
     * CSRF 校验（{@link com.airagent.iam.config.WebMvcConfiguration} 中的拦截器仅
     * 挂载在 {@code /web-api/**} 与 {@code /v1/**} 前缀）。
     *
     * @return 200 + {@code index.html} 资源；若前端尚未构建则抛 404
     */
    @Operation(summary = "SPA 页面入口（HTML）",
            description = "非 REST API：返回 Vite 构建的 index.html，前端路由接管页面渲染；公开无需认证；"
                    + "只覆盖显式白名单路径，未知路径仍走 JSON 404/405")
    @GetMapping({"/", "/login", "/profile", "/admin", "/admin/**"})
    public ResponseEntity<Resource> index() {
        for (String location : locations()) {
            Resource candidate = resolve(location + "index.html");
            if (candidate != null && candidate.isReadable()) {
                return ResponseEntity.ok()
                        .header(HttpHeaders.CACHE_CONTROL, CacheControl.noCache().getHeaderValue())
                        .contentType(MediaType.TEXT_HTML)
                        .body(candidate);
            }
        }
        throw ApiException.notFound("管理前端尚未构建：请先在 web/ 执行构建");
    }

    /**
     * 按位置前缀解析资源：仅识别 {@code classpath:} 与 {@code file:} 两种协议。
     *
     * @param location 形如 {@code classpath:/static/index.html} 或 {@code file:./web/dist/index.html}
     * @return 存在的 {@link Resource}；不存在或前缀不识别返回 {@code null}
     */
    private Resource resolve(String location) {
        if (location.startsWith("classpath:")) {
            Resource resource = new ClassPathResource(location.substring("classpath:".length()));
            return resource.exists() ? resource : null;
        }
        if (location.startsWith("file:")) {
            Resource resource = new FileSystemResource(Path.of(location.substring("file:".length())));
            return resource.exists() ? resource : null;
        }
        return null;
    }

    /**
     * 解析 {@code iam.web.static-locations}：空/未配置则回落默认；每项末尾补齐 {@code /}
     * 以便与 {@code index.html} 直接字符串拼接。
     *
     * @return 至少一项的静态根数组，每项均以 {@code /} 结尾
     */
    private String[] locations() {
        String configured = props.web() == null ? null : props.web().staticLocations();
        if (configured == null || configured.isBlank()) {
            return DEFAULT_LOCATIONS;
        }
        return Arrays.stream(configured.split(","))
                .map(String::trim)
                .filter(s -> !s.isBlank())
                .map(s -> s.endsWith("/") ? s : s + "/")
                .toArray(String[]::new);
    }
}
