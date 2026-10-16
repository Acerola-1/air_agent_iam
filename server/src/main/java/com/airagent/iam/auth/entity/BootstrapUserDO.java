package com.airagent.iam.auth.entity;

import java.util.UUID;

/** 数据库结果对象。 */
public record BootstrapUserDO(UUID userId, boolean wasCreated) {
}
