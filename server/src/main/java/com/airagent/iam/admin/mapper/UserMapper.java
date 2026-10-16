package com.airagent.iam.admin.mapper;

import com.airagent.iam.admin.entity.UserDO;
import java.util.List;
import java.util.UUID;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/**
 * 平台账号管理数据访问（Mapper 层，SQL 见 mapper/admin/UserMapper.xml）。
 *
 * <p>运行在 iam_app 请求角色下：列级权限不含 {@code password_hash}，
 * 行可见性由 iam.users 的 RLS 策略决定——调用前必须在同一事务内通过
 * {@link com.airagent.iam.common.mapper.RequestContextMapper#setContext} 设置
 * {@code app.user_id / app.tenant_id / app.is_platform}，否则查询结果为空。
 * 授权相关查询关闭二级缓存、一级缓存为 STATEMENT。
 *
 * @author Acerola
 */
@Mapper
public interface UserMapper {

    /**
     * keyset 分页：按 id 升序取 {@code afterId} 之后的至多 {@code fetchSize} 行。
     *
     * <p>服务层以 fetchSize = limit+1 探测是否还有下一页。
     *
     * @param query     可选账号子串（大小写不敏感的 position 匹配）；{@code null} 不过滤
     * @param afterId   游标 id，仅返回 id 大于它的行；{@code null} 从头开始
     * @param fetchSize 实际取行数上限（含多取的一条探测行）
     * @return 按 id 升序的账号列表；无匹配时为空列表，不返回 {@code null}
     */
    List<UserDO> selectPage(@Param("query") String query, @Param("afterId") UUID afterId,
                            @Param("fetchSize") int fetchSize);

    /**
     * 按主键读取账号（无行锁）。
     *
     * @param id 用户 UUID
     * @return 账号行；不存在或 RLS 不可见时返回 {@code null}
     */
    UserDO selectById(@Param("id") UUID id);

    /**
     * 按主键读取账号并加行级排他锁（SELECT ... FOR UPDATE）。
     *
     * <p>必须在开启的事务内调用，锁随事务提交/回滚释放；写路径以它串行化
     * 同一账号上的并发修改与修订比对。
     *
     * @param id 用户 UUID
     * @return 已持锁的账号行；不存在或不可见时返回 {@code null}（此时未持锁）
     */
    UserDO selectForUpdate(@Param("id") UUID id);

    /**
     * 插入新账号，realm 固定 {@code workforce}，status 取表默认 active。
     *
     * @param account      登录账号（可打印 ASCII 3..64；同 realm 唯一，违反触发约束冲突）
     * @param displayName  显示名
     * @param passwordHash BCrypt 摘要（明文口令不进入本层）
     * @return 数据库生成的新账号 id
     */
    UUID insert(@Param("account") String account, @Param("displayName") String displayName,
                 @Param("passwordHash") String passwordHash);

    /**
     * 仅更新显示名；不触及授权列，因此不推进授权代次。
     *
     * @param id          用户 UUID
     * @param displayName 新显示名
     * @return 受影响行数；0 表示行不存在或 RLS 不可见
     */
    int updateDisplayName(@Param("id") UUID id, @Param("displayName") String displayName);

    /**
     * 更新账号状态（active/disabled）。
     *
     * <p>状态实际变化时由数据库触发器 {@code users_bump_auth_revision}
     * 将 auth_revision +1，使携带旧基线的会话被拒。
     *
     * @param id     用户 UUID
     * @param status 目标状态；调用方须先行校验仅取 active/disabled
     * @return 受影响行数；0 表示行不存在或不可见
     */
    int updateStatus(@Param("id") UUID id, @Param("status") String status);

    /**
     * 经 SECURITY DEFINER 函数 {@code iam_auth.set_user_password} 写入新口令摘要。
     *
     * <p>该角色无 password_hash 列直接写权限，必须走函数；口令变更由触发器
     * 推进授权代次。账号不存在时函数以 P0002 报错——调用方应先用
     * {@link #selectForUpdate} 确认存在性。
     *
     * @param id           用户 UUID
     * @param passwordHash BCrypt 摘要
     * @return 写入后的 auth_revision
     */
    long setPassword(@Param("id") UUID id, @Param("passwordHash") String passwordHash);

    /**
     * 经 {@code iam_auth.revoke_user_sessions} 撤销目标账号的会话。
     *
     * <p>函数将活跃会话置为 revoked（p_keep 传 {@code null} 表示全撤、含调用者
     * 关心的当前会话），返回被撤会话的 token 摘要，并额外将 auth_revision +1。
     * 调用方必须把返回摘要经 outbox 删除对应 Redis 会话键（见
     * {@link com.airagent.iam.admin.AdminSupport#enqueueRedisDeletes}）。
     *
     * @param id     用户 UUID
     * @param reason 撤销原因（写入审计列 revoke_reason，如 admin.password_reset）
     * @return 被撤销会话的 token 摘要列表；无活跃会话时为空列表
     */
    List<String> revokeSessions(@Param("id") UUID id, @Param("reason") String reason);

    /**
     * 按角色码解析活跃的 platform 域角色 id。
     *
     * @param codes 角色码列表（非空，调用方已消毒去重）
     * @return 命中的角色 id；数量少于 codes 表示存在未知或停用角色码
     */
    List<UUID> selectPlatformRoleIds(@Param("codes") List<String> codes);

    /**
     * 删除账号当前全部平台角色关联（配合 insertPlatformRole 实现全量替换）。
     *
     * @param userId 用户 UUID
     * @return 删除的关联行数
     */
    int deletePlatformRoles(@Param("userId") UUID userId);

    /**
     * 授予单个平台角色并记录授权人。
     *
     * @param userId  被授权用户 UUID
     * @param roleId  角色 UUID（须为活跃 platform 域角色）
     * @param actorId 执行授权的管理员 UUID，入 granted_by 审计列
     * @return 插入行数（恒为 1，冲突会抛异常）
     */
    int insertPlatformRole(@Param("userId") UUID userId, @Param("roleId") UUID roleId,
                            @Param("actorId") UUID actorId);

    /**
     * 读取账号当前平台角色码。
     *
     * @param userId 用户 UUID
     * @return 按 code 升序的角色码列表；无任何角色时为空列表
     */
    List<String> selectPlatformRoleCodes(@Param("userId") UUID userId);
}
