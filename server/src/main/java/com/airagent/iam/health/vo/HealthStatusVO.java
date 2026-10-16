package com.airagent.iam.health.vo;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * 健康检查公开视图（VO，{@code GET /healthz} 的响应体）。
 *
 * <p>形状刻意最小：只有整体状态、配置里的发行方标识与两个依赖布尔位，
 * 供本机脚本与容器编排按字段判断就绪（例如要求 {@code postgres} 与 {@code redis}
 * 同时为真）。经全局 SNAKE_CASE 序列化后字段名仍是这四个单词，无嵌套结构，
 * 因此也不受依赖故障影响而带上错误信封。
 *
 * <p>不出现的内容：连接串、主机与端口、连接池水位、异常消息或堆栈、
 * 版本号与启动时间，以及任何口令/令牌/密钥信息；{@code issuer} 只是配置里的
 * 服务标识文本，不属于凭据。
 *
 * @param status   当前整体状态：{@code ok} 表示两项依赖同时可用，
 *                 {@code degraded} 表示至少一项不可用（HTTP 状态仍为 200）
 * @param issuer   身份服务发行方标识，取自配置项 {@code iam.issuer}，非秘密、固定文本
 * @param postgres PostgreSQL 是否可用（连接池取到连接并完成一次常量查询）
 * @param redis    Redis 是否可用（一次 GET 往返正常完成，键不存在不算故障）
 * @author Acerola
 */
@Schema(description = "依赖健康状态视图。两项依赖都可用时 status=ok，否则 degraded；"
        + "依赖故障仍返回 HTTP 200，就绪判定以本对象的布尔字段为准。不含连接信息与凭据")
public record HealthStatusVO(

        @Schema(description = "整体状态：两项依赖都可用为 ok，任一不可用为 degraded。",
                requiredMode = Schema.RequiredMode.REQUIRED, allowableValues = {"ok", "degraded"},
                example = "ok")
        String status,

        @Schema(description = "身份服务发行方标识，取配置项 iam.issuer（非秘密文本，不随依赖状态变化）。",
                requiredMode = Schema.RequiredMode.REQUIRED, example = "air-agent-iam")
        String issuer,

        @Schema(description = "PostgreSQL 可用性：以 SELECT 1 探测请求数据源，连接不可得或超时即为 false。",
                requiredMode = Schema.RequiredMode.REQUIRED)
        boolean postgres,

        @Schema(description = "Redis 可用性：对固定探测键完成一次 GET 往返即为 true（键本身不存在，"
                + "读到空值不算故障）；false 仅表示会话存活索引暂不可达。",
                requiredMode = Schema.RequiredMode.REQUIRED)
        boolean redis) {
}
