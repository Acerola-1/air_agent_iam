package com.airagent.iam.serviceaccount.mapper;

import com.airagent.iam.serviceaccount.entity.IssuedTokenDO;
import com.airagent.iam.serviceaccount.entity.ServiceAccountDO;
import com.airagent.iam.serviceaccount.entity.ServiceTokenDO;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/**
 * 服务账号与凭据数据访问（Mapper 层，SQL 见 {@code mapper/serviceaccount/ServiceAccountMapper.xml}）。
 *
 * <p>分层与场景：只服务于
 * {@link com.airagent.iam.serviceaccount.service.impl.ServiceAccountServiceImpl}
 * 的管理面（建档、查询、停用/启用、签发与吊销），不承担机器身份的令牌核验。
 *
 * <p>运行在请求角色 iam_app 下，两类表的可达性不同，必须先在同一事务内经
 * {@link com.airagent.iam.common.mapper.RequestContextMapper#setContext} 写入
 * {@code app.user_id / app.tenant_id / app.is_platform}，否则结果为空或被拒：
 * <ul>
 *   <li>{@code iam.service_accounts} 与 {@code iam.service_account_permissions} 为 FORCE RLS，
 *       策略放行“行企业即上下文企业”或“平台上下文”，本模块统一走平台上下文；</li>
 *   <li>{@code iam.service_tokens} 只启用 RLS 而没有放行策略，对 iam_app <b>默认拒绝直读</b>，
 *       因此签发、吊销与凭据列表都必须经 iam_auth 下的 SECURITY DEFINER 函数完成，
 *       函数内部自行重置平台上下文。摘要列 {@code token_digest} 与明文密钥都不在任何返回投影里。</li>
 * </ul>
 *
 * <p>读查询一律 {@code useCache=false}（关闭二级缓存）；取回生成值的写入语句
 * （{@code insert}、{@code issueToken}、{@code revokeToken}）另声明 {@code affectData} 与
 * {@code flushCache}，避免同一请求内读到过期授权。
 *
 * @author Acerola
 */
@Mapper
public interface ServiceAccountMapper {

    /**
     * 按主键读取服务账号（无行锁）。
     *
     * @param id 服务账号 UUID
     * @return 账号行；不存在或 RLS 不可见时返回 {@code null}
     */
    ServiceAccountDO selectById(@Param("id") UUID id);

    /**
     * 按主键读取服务账号并加行级排他锁（SELECT ... FOR UPDATE）。
     *
     * <p>必须在已开启的事务内调用，锁随提交/回滚释放。签发凭据以它串行化同一账号上的并发签发，
     * 保证凭据代次（已有最大值 +1）不重复。
     *
     * @param id 服务账号 UUID
     * @return 已持锁的账号行；不存在或不可见时返回 {@code null}（此时未持锁）
     */
    ServiceAccountDO lockById(@Param("id") UUID id);

    /**
     * 插入服务账号主体。
     *
     * <p>SQL 形态为 {@code INSERT ... RETURNING id}（写在 select 标签内以取回生成主键）。
     * {@code status} 固定 {@code 'active'}、{@code revision} 固定 1，{@code created_by} 记操作人；
     * {@code audiences} 经 TextArrayTypeHandler 写为 text[]（空列表即空数组，不写 {@code null}）。
     * 账号名全库唯一，重复触发约束冲突；有效期另受“不得晚于写入时刻 +365 天”的 CHECK 约束。
     *
     * @param account   服务账号标识（{@code sa-} 前缀，调用方已校验格式）
     * @param name      显示名，非空
     * @param tenantId  所属企业 UUID，须为已存在且 active 的企业
     * @param audiences 受众码列表；不可为 {@code null}，无受众时传空列表
     * @param expiresAt 账号到期时刻（UTC），由调用方按天数偏移算出
     * @param actorId   建档人用户 UUID，入 {@code created_by} 审计列
     * @return 数据库生成的新账号 UUID
     */
    UUID insert(@Param("account") String account, @Param("name") String name,
                @Param("tenantId") UUID tenantId, @Param("audiences") List<String> audiences,
                @Param("expiresAt") OffsetDateTime expiresAt, @Param("actorId") UUID actorId);

    /**
     * 为服务账号授予一条权限（一条语句只授一码，多码由服务层循环调用，同一事务内整体生效）。
     *
     * <p>{@code (service_account_id, permission_id)} 为主键，重复授予会冲突；
     * {@code (tenant_id, service_account_id)} 另受复合外键约束，故租户必须与账号所属企业一致。
     * 触发器 {@code service_permissions_boundary} 拒绝资源型权限（{@code resource_code} 非空），
     * 属服务层预筛之外的数据库兜底。
     *
     * @param tenantId     账号所属企业 UUID（与 {@code id} 对应的账号行一致）
     * @param id           服务账号 UUID
     * @param permissionId 已解析出的权限 UUID（调用方须先经 {@link #resolvePermissions} 校验）
     * @param actorId      执行人用户 UUID，入 {@code granted_by} 审计列
     * @return 插入行数（成功恒为 1，冲突抛异常）
     */
    int insertPermission(@Param("tenantId") UUID tenantId, @Param("id") UUID id,
                         @Param("permissionId") UUID permissionId, @Param("actorId") UUID actorId);

    /**
     * 经 SECURITY DEFINER 函数 {@code iam_auth.issue_service_token} 签发凭据。
     *
     * <p>函数以账号行锁开始，校验账号 active、未到期且所属企业 active，随后把重叠窗口
     * （或零窗口时的立即撤销）写在<b>该账号当前全部 active 旧凭据</b>上，最后插入新行：
     * 新行状态 active、代次为已有最大值 +1、{@code overlap_until} 固定为 {@code null}。
     * 数据库侧的硬约束为：到期不得晚于“账号到期与 now()+365 天”的较小者、
     * 重叠上界不得超过轮换时刻 +24 小时。校验失败分别以 28000 / 23514 抛出。
     *
     * @param id            服务账号 UUID（调用方应已用 {@link #lockById} 确认存在）
     * @param credentialId  对外凭据标识，形如 {@code sak_} 加 32 位十六进制，全库唯一
     * @param digest        明文密钥的 SHA-256 十六进制摘要；明文不经本层，也不落库
     * @param expiresAt     新凭据到期时刻（UTC），须晚于当前且不越过账号到期与 365 天硬顶
     * @param overlapUntil  施加于旧凭据的重叠上界（UTC）；{@code null} 表示零窗口，
     *                      旧凭据立即转为 revoked。非空时不得超过轮换时刻 +24 小时
     * @return 新凭据行的三列投影 {@link IssuedTokenDO}（代次、到期与其自身的窗口；
     *         该窗口字段按函数定义恒为 {@code null}）
     */
    IssuedTokenDO issueToken(@Param("id") UUID id, @Param("credentialId") String credentialId,
                             @Param("digest") String digest, @Param("expiresAt") OffsetDateTime expiresAt,
                             @Param("overlapUntil") OffsetDateTime overlapUntil);

    /**
     * 经 {@code iam_auth.revoke_service_token} 立即吊销单个凭据。
     *
     * <p>函数只更新状态为 active 的行（置 revoked 并写入 revoked_at），对已 revoked 或
     * 不存在的标识不做任何变更且不报错，故本操作幂等。函数返回 void，语句以
     * {@code SELECT 1 FROM 函数(...)} 形态执行，因此返回值<b>不表示</b>是否真的撤销了行，
     * 调用方不得据此判定存在性。
     *
     * @param credentialId 凭据标识（调用方已校验格式）
     * @return 恒为 1，仅表示函数执行完成；与受影响行数无关
     */
    int revokeToken(@Param("credentialId") String credentialId);

    /**
     * keyset 分页：按 id 升序取 {@code afterId} 之后的至多 {@code fetchSize} 行。
     *
     * <p>服务层以 fetchSize = limit+1 探测是否还有下一页。企业过滤只比对行的 {@code tenant_id}，
     * 不校验企业是否存在，未知企业只会得到空结果。
     *
     * @param tenantId  企业过滤 UUID；{@code null} 表示不按企业过滤（平台上下文可见全部企业）
     * @param afterId   游标 id，仅返回 id 严格大于它的行；{@code null} 从头开始
     * @param fetchSize 实际取行数上限（含多取的一条探测行），必须为正
     * @return 按 id 升序的账号列表；无匹配时为空列表，不返回 {@code null}
     */
    List<ServiceAccountDO> selectPage(@Param("tenantId") UUID tenantId, @Param("afterId") UUID afterId,
                                      @Param("fetchSize") int fetchSize);

    /**
     * 经 {@code iam_auth.list_service_tokens} 读取某账号的全部凭据元数据。
     *
     * <p>函数是凭据表唯一的读取通道（直读被 RLS 拒绝），返回列只有标识、代次、状态与时间，
     * 不含 {@code token_digest}，因此无法据此还原任何凭据内容。历史行（已 revoked、已过期）
     * 一并返回，供管理面展示轮换结果。
     *
     * @param id 服务账号 UUID
     * @return 按签发时间倒序、同刻按凭据标识升序的凭据元数据；从未签发时为空列表
     */
    List<ServiceTokenDO> selectTokens(@Param("id") UUID id);

    /**
     * 更新账号状态并推进账号修订号。
     *
     * <p>同一条 SQL 完成三件事：写 {@code status}；置 {@code disabled} 时以
     * {@code COALESCE(revoked_at, now())} 记录首次停用时刻、置 {@code active} 时清空该列；
     * {@code revision + 1}。WHERE 只按 id 过滤、不比较原状态，因此重复提交同一状态也会 +1。
     * 不改动任何凭据行：停用只让核验返回 account_disabled。
     *
     * @param id     服务账号 UUID
     * @param status 目标状态；调用方须先行校验仅取 active/disabled（数据库另允许的 revoked 不经本方法）
     * @return 受影响行数；0 表示行不存在或 RLS 不可见
     */
    int updateStatus(@Param("id") UUID id, @Param("status") String status);

    /**
     * 读取账号当前已授予的权限码。
     *
     * @param id 服务账号 UUID
     * @return 按权限码升序的列表；无任何授予时为空列表。已停用权限码仍会返回
     *         （关联行未被回收），核验函数会在运行时再按状态过滤
     */
    List<String> selectPermissionCodes(@Param("id") UUID id);

    /**
     * 把权限码解析为服务账号可授予的权限 id。
     *
     * <p>过滤条件为 {@code status='active'}、{@code resource_code IS NULL} 且
     * {@code scope='tenant'}：平台专属码、资源型码、未知与停用码一律不返回。
     * 命中数少于入参数量即表示存在越界项，调用方须整体拒绝（不部分授予）。
     *
     * @param codes 权限码列表，必须非空（空列表会生成非法的空 IN 集合）；调用方已消毒去重
     * @return 命中的权限 id；因 code 全库唯一，故与命中的入参一一对应、顺序不保证
     */
    List<UUID> resolvePermissions(@Param("codes") List<String> codes);
}
