package com.airagent.iam.health.controller;

import com.airagent.iam.health.service.HealthService;
import com.airagent.iam.health.vo.HealthStatusVO;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 依赖健康状态查询入口。
 */
@RestController
public class HealthController {

    private final HealthService healthService;

    public HealthController(HealthService healthService) {
        this.healthService = healthService;
    }

    @GetMapping("/healthz")
    public ResponseEntity<HealthStatusVO> getHealth() {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .body(healthService.getHealth());
    }
}
