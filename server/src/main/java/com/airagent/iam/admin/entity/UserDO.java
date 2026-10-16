package com.airagent.iam.admin.entity;

import java.time.OffsetDateTime;
import java.util.UUID;

/** 账号持久化视图，管理查询不读取口令摘要。 */
public record UserDO(UUID id, String realm, String account, String displayName, String status,
                      long authRevision, OffsetDateTime createdAt) {
}
