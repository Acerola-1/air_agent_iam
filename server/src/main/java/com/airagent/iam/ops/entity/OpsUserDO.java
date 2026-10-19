package com.airagent.iam.ops.entity;

import java.util.UUID;

/** 运维命令读取的最小账号视图（不含口令摘要）。 */
public record OpsUserDO(UUID id, String account, String displayName, String status) {
}
