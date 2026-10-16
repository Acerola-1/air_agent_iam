package com.airagent.iam.health.vo;

/**
 * 健康检查公开视图。
 *
 * @param status 当前整体状态
 * @param issuer 身份服务发行方
 * @param postgres PostgreSQL 是否可用
 * @param redis Redis 是否可用
 */
public record HealthStatusVO(String status, String issuer, boolean postgres, boolean redis) {
}
