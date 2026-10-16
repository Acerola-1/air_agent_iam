package com.airagent.iam.admin.entity;

import java.time.Instant;
import java.util.UUID;

/**
 * iam.resource_catalog 行的持久化视图（DO，资源目录）。
 */
public record ResourceCatalogDO(
        UUID id,
        String code,
        String nameZh,
        Integer sort,
        String status,
        String kind,
        String parentCode,
        Long revision,
        Instant createdAt
) {
}
