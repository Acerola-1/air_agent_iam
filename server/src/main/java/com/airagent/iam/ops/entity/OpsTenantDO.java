package com.airagent.iam.ops.entity;

import java.util.UUID;

/** 运维命令读取的企业视图。 */
public record OpsTenantDO(UUID id, String code, String name, String status, long authRevision) {
}
