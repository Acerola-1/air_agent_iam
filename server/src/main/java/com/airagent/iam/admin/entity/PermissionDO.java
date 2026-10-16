package com.airagent.iam.admin.entity;

import java.util.UUID;

/** 权限目录持久化数据。 */
public record PermissionDO(UUID id, String code, String nameZh, String scope,
                            String resourceCode, boolean grantableToTenants) {
}
