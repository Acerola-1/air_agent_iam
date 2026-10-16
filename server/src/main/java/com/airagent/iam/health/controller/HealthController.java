package com.airagent.iam.health.controller;

import com.airagent.iam.health.service.HealthService;
import com.airagent.iam.health.vo.HealthStatusVO;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 依赖健康状态 HTTP 入口（Controller 层，公开端点，不访问数据库）。
 *
 * <p>分层位置：{@code GET /healthz} 由本类接收，实际探测在
 * {@link com.airagent.iam.health.service.HealthService} 内完成。该路径<em>不在</em>
 * {@link com.airagent.iam.config.WebMvcConfiguration} 注册的任何拦截器模式内
 * （既非 {@code /v1/**} 也非 {@code /web-api/**}），因此无需 Bearer、无需会话 Cookie、
 * 也不做 CSRF 与权限裁决——文档面同样不声明任何 security requirement。
 *
 * <p>用途与响应面：供本机脚本、容器编排与验收流程轮询，判断"进程已起来、依赖是否真的可达"。
 * 响应刻意最小化：只有整体状态、配置项 {@code iam.issuer} 的文本与两个依赖布尔位，
 * 不含主机端口、连接串、连接池水位、异常消息或任何凭据（见 {@link HealthStatusVO}）。
 *
 * <p>返回码语义：依赖故障时本端点仍返回 HTTP 200，仅把状态降为 {@code degraded}
 * （探测异常在服务层被吸收），就绪判定必须以响应体字段为准，而不是状态码。
 *
 * @author Acerola
 */
@Tag(name = "运维探针",
        description = "存活与依赖探测。公开端点，不需要任何凭据，也不返回任何凭据、连接信息或异常细节")
@RestController
public class HealthController {

    /** 健康检查聚合服务 */
    private final HealthService healthService;

    /**
     * 构造健康检查控制器。
     *
     * @param healthService 依赖探测服务（PostgreSQL 与 Redis 的实际可达性判定在其中完成）
     */
    public HealthController(HealthService healthService) {
        this.healthService = healthService;
    }

    /**
     * 返回当前依赖状态快照。
     *
     * <p>本方法<em>恒以 200 返回</em>：PostgreSQL 或 Redis 不可达时把对应布尔位置为
     * {@code false}、整体状态降为 {@code degraded}，不抛异常、不返回 503——这样探针才能
     * 区分"服务活着但依赖断了"与"进程没起来"（后者由连接失败本身暴露）。
     * 每次调用都会真实往返一次，没有缓存，轮询频率需由调用方自控。
     *
     * @return 200 与 {@link HealthStatusVO}；附带 {@code Cache-Control: no-store}，
     *         禁止浏览器与中间层缓存探测结果
     */
    @Operation(summary = "存活与依赖探测",
            description = "公开端点：无 Bearer、无 Cookie、无 CSRF，也不校验任何权限。"
                    + "以不触表的 SELECT 1 探测 PostgreSQL，以对固定键的一次 GET 探测 Redis。"
                    + "两项都可用时 status=ok，任一不可用时 status=degraded 且对应字段为 false，"
                    + "HTTP 状态码仍为 200。响应体只含 status、issuer、postgres、redis 四个字段，"
                    + "不暴露连接地址、端口、凭据、池指标或异常信息。")
    @ApiResponse(responseCode = "200",
            description = "探测已完成并返回状态；依赖故障体现在 status=degraded 与对应布尔字段，而非错误状态码")
    @GetMapping("/healthz")
    public ResponseEntity<HealthStatusVO> getHealth() {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .body(healthService.getHealth());
    }
}
