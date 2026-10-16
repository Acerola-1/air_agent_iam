package com.airagent.iam.admin.mapper;

import com.airagent.iam.admin.entity.PermissionDO;
import com.airagent.iam.admin.entity.RoleDO;
import java.util.List;
import java.util.UUID;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/**
 * 角色与权限目录的数据访问（Mapper 层，SQL 见 mapper/admin/RoleMapper.xml）。
 *
 * <p>运行在 iam_app 请求角色下：iam.roles 启用 RLS，可见集由请求上下文决定——调用前必须在
 * 同一事务内通过 {@link com.airagent.iam.common.mapper.RequestContextMapper#setContext} 设置
 * {@code app.user_id / app.tenant_id / app.is_platform}，否则查询结果为空。
 * 读取时企业为空的角色（平台角色与内置企业模板）对任何上下文都可见，租户自定义角色只在
 * 本企业上下文或平台上下文可见；写入时 WITH CHECK 要求 {@code scope='tenant'} 必须落在
 * 上下文企业、{@code scope='platform'} 必须是平台上下文且企业为空。
 * iam.permissions 未启用 RLS，是全局共享目录，任何上下文都能读全。
 *
 * <p>授权判定依赖权限码，因此全部查询关闭二级缓存（{@code useCache=false}），
 * 写语句额外 flushCache，一级缓存为 STATEMENT，杜绝跨请求读到过期权限集合。
 *
 * @author Acerola
 */
@Mapper
public interface RoleMapper {

    /**
     * keyset 分页：按 id 升序取 {@code afterId} 之后的至多 {@code fetchSize} 行角色。
     *
     * <p>企业列表显式限制当前企业或全局企业模板；RLS还允许身份装配读取同一用户其他成员企业，
     * 因而不能单独作为管理列表的当前企业过滤。服务层以 fetchSize = limit+1 探测下一页。
     *
     * @param scope     角色域过滤；仅 {@code platform} / {@code tenant} 有意义，{@code null} 不按域过滤
     * @param afterId   游标 id，仅返回 id 大于它的行；{@code null} 从头开始
     * @param fetchSize 实际取行数上限（含多取的一条探测行）
     * @param tenantId 企业列表的明确目标；平台全局列表为null
     * @return 按 id 升序的角色列表；无匹配时为空列表，不返回 {@code null}
     */
    List<RoleDO> selectPage(@Param("scope") String scope, @Param("afterId") UUID afterId,
                            @Param("fetchSize") int fetchSize, @Param("tenantId") UUID tenantId);

    /**
     * 按主键读取角色（无行锁）。
     *
     * @param id 角色 UUID
     * @return 角色行；不存在或 RLS 不可见时返回 {@code null}
     */
    RoleDO selectById(@Param("id") UUID id);

    /**
     * 插入自定义角色，{@code is_builtin} 固定 false，status 取表默认 active。
     *
     * <p>返回 id 由 {@code RETURNING} 取得，故声明为查询并强制 flushCache。
     * 唯一冲突（平台角色码全局唯一、企业角色码同企业唯一）以 23505 抛出，由调用方翻译为 409。
     *
     * @param scope       角色域，仅 {@code platform} / {@code tenant}；决定 RLS 写入校验
     * @param tenantId    归属企业；平台角色必须传 {@code null}，企业角色须等于上下文企业
     * @param code        角色码（3..64 位小写字母数字/_/-，调用方已校验）
     * @param name        角色显示名，非空
     * @param description 角色说明；{@code null} 入库为空串（列 NOT NULL）
     * @return 数据库生成的新角色 id
     */
    UUID insert(@Param("scope") String scope, @Param("tenantId") UUID tenantId,
                 @Param("code") String code, @Param("name") String name,
                 @Param("description") String description);

    /**
     * 局部更新角色的名称、说明与状态（三列均为 COALESCE 语义）。
     *
     * <p>状态实际变化时由触发器 {@code role_status_invalidate_authority} 推进所有引用该角色的
     * 账号 auth_revision 与成员 revision，使旧权限快照即刻失效；仅改名或改说明不推进。
     * 域、角色码与归属企业不在可更新列内——迁移作用域需另走数据订正。
     *
     * @param id          角色 UUID
     * @param name        新显示名；{@code null} 保持原值
     * @param description 新说明；{@code null} 保持原值（传空串可清空）
     * @param status      新状态；{@code null} 保持原值；调用方须先行校验仅取 active/disabled
     * @return 受影响行数；0 表示行不存在或 RLS 不可见
     */
    int update(@Param("id") UUID id, @Param("name") String name,
                @Param("description") String description, @Param("status") String status);

    /**
     * 读取角色当前持有的权限码，用于视图装配与“可授范围”子集校验。
     *
     * @param roleId 角色 UUID
     * @return 按 code 升序的权限码列表；角色无权限时为空列表，不返回 {@code null}
     */
    List<String> selectPermissionCodes(@Param("roleId") UUID roleId);

    /**
     * 权限目录（后台展示用）：仅非资源型权限，按 sort、code 升序。
     *
     * <p>本查询不过滤权限状态，因此停用的权限仍会出现在目录里（与
     * {@link #selectGrantable} 的口径不同）。资源型权限（resource_code 非空）在资源开通前
     * 一律不出现在目录与可授树中。
     *
     * @param includePlatform 是否包含平台域权限；{@code false} 时只返回 tenant 域，
     *                        供仅有企业读权限的主体使用
     * @return 权限目录行列表；无匹配时为空列表
     */
    List<PermissionDO> selectCatalog(@Param("includePlatform") boolean includePlatform);

    /**
     * 指定域的可授权限：活跃、非资源型，且企业域需 grantable_to_tenants 为真。
     *
     * <p>过滤条件为 {@code scope = ? AND resource_code IS NULL AND status = 'active'}，
     * 并额外要求平台域或可下放到企业；排序按 sort、code。调用方再按 actor 自身权限快照做二次裁剪。
     *
     * @param scope 权限域，仅 {@code platform} / {@code tenant}；其他取值返回空列表
     * @return 可授权限列表；无匹配时为空列表
     */
    List<PermissionDO> selectGrantable(@Param("scope") String scope);

    /**
     * 按权限码批量解析目录行，用于角色权限集合的写入前校验。
     *
     * <p>不过滤状态与域：命中数小于 codes 数量即表示存在未知码，调用方据此返回 400；
     * 停用权限、平台专属权限与资源型权限的可授性由调用方结合角色 scope 另行判定，
     * 数据库触发器 role_permissions_boundary 再兜底。
     *
     * @param codes 权限码列表，必须非空（空列表会生成非法的 IN 空集合）；调用方已消毒去重
     * @return 按 code 升序的目录行；未知码不出现在结果中
     */
    List<PermissionDO> selectPermissionsByCodes(@Param("codes") List<String> codes);

    /**
     * 删除角色当前全部权限关联（配合 {@link #insertPermissions} 实现全量替换）。
     *
     * @param roleId 角色 UUID
     * @return 删除的关联行数（无关联时为 0）
     */
    int deletePermissions(@Param("roleId") UUID roleId);

    /** 授权目标在资源/企业锁之后锁定。 */
    RoleDO lockById(@Param("id") UUID id);

    int deletePermission(@Param("roleId") UUID roleId, @Param("code") String code);

    int countActiveEntitlement(@Param("tenantId") UUID tenantId, @Param("resourceCode") String resourceCode);

    /**
     * 批量写入角色权限关联并记录授权人。
     *
     * <p>单条多值 INSERT，全成功或全失败；触发器 role_permissions_boundary 以 23514 拒绝
     * 越界授予（企业角色拿平台专属权限、资源型权限），role_permissions_invalidate_authority
     * 则推进引用该角色的账号与成员修订。
     *
     * @param roleId      角色 UUID
     * @param actorId     执行授权的管理员 UUID，入 granted_by 审计列
     * @param permissions 已解析的目录行集合，必须非空（空集合会生成非法 SQL）
     * @return 插入的关联行数
     */
    int insertPermissions(@Param("roleId") UUID roleId, @Param("actorId") UUID actorId,
                           @Param("permissions") List<PermissionDO> permissions);
}
