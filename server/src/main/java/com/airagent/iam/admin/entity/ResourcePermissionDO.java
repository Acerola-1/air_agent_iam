package com.airagent.iam.admin.entity;

import java.util.UUID;

/**
 * 资源权限绑定的持久化视图（DO）。
 *
 * @param id                   权限 UUID
 * @param code                 权限码，须以资源 code + ':' 为前缀
 * @param nameZh               中文名
 * @param scope                固定 tenant
 * @param grantableToTenants   是否可下放企业
 * @param resourceCode         所属资源编码
 * @param status               active/disabled
 */
public record ResourcePermissionDO(
        UUID id,
        String code,
        String nameZh,
        String scope,
        boolean grantableToTenants,
        String resourceCode,
        String status
) {
}
