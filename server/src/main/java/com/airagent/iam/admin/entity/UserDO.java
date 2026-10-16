package com.airagent.iam.admin.entity;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * iam.users 行的持久化视图（DO，仅 Mapper 使用，不直接对外）。
 *
 * <p>映射列刻意不含 {@code password_hash}：请求角色 iam_app 对该列无读取权限，
 * 任何管理查询都拿不到口令摘要。字段语义与列 CHECK 约束一致。
 *
 * @param id          主键，{@code gen_random_uuid()} 生成
 * @param realm       账号域；当前账号管理创建的均为 {@code workforce}，(realm, account) 全库唯一
 * @param account     登录账号，可打印 ASCII 3..64 字符
 * @param displayName 显示名，非空
 * @param status      账号状态，仅 {@code active} / {@code disabled}；停用即失去登录与活跃会话
 * @param authRevision 授权代次；口令或状态变更触发器 +1，撤销会话函数额外 +1，会话快照以此校验授权是否过期
 * @param createdAt   创建时间（timestamptz，数据库 now()）
 * @author Acerola
 */
public record UserDO(UUID id, String realm, String account, String displayName, String status,
                      long authRevision, OffsetDateTime createdAt) {
}
