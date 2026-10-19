package com.airagent.iam.ops.entity;

import java.util.UUID;

/** 权限定义视图。 */
public record OpsPermissionDO(UUID id, String code, String resourceCode, String status) {
}
