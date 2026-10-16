package com.airagent.iam.webapi.controller;

import com.airagent.iam.config.IamProperties;
import com.airagent.iam.web.error.ApiException;
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
 * SPA 页面导航路由（显式白名单）：仅这些 GET（含自动 HEAD）路径返回 index.html，
 * /web-api、/v1 与其他未知路径不进入此处，保持 JSON 404/405。
 */
@RestController
public class SpaController {

    private static final String[] DEFAULT_LOCATIONS = {
            "file:./web/dist/", "classpath:/static/"
    };

    private final IamProperties props;

    public SpaController(IamProperties props) {
        this.props = props;
    }

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
