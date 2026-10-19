package com.airagent.iam.ops.entity;

import java.util.UUID;

/** 企业独有角色视图。 */
public record OpsRoleDO(UUID id, String code, boolean builtin, String status) {
}
