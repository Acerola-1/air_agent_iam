package com.airagent.iam.ops.entity;

import java.util.UUID;

/** 旧 Agent MCP/Skill 权限定义及其实际关联计数。 */
public record OpsLegacyPermissionDO(UUID id, String code, String scope, String status,
                                    int roleEdges, int serviceAccountEdges) {
}
