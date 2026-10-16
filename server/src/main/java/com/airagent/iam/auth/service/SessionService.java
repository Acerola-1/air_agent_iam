package com.airagent.iam.auth.service;

import com.airagent.iam.auth.AuthoritySnapshot;
import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.auth.dto.ChangePasswordDTO;
import com.airagent.iam.auth.dto.LoginDTO;
import com.airagent.iam.auth.dto.RenewDTO;
import com.airagent.iam.auth.dto.SwitchTenantDTO;
import com.airagent.iam.auth.vo.IdentityVO;
import com.airagent.iam.auth.vo.LoginVO;
import com.airagent.iam.auth.vo.SessionTimersVO;
import com.airagent.iam.auth.vo.TenantMembershipVO;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * 人类会话与身份权威的业务接口（Service 层，auth 模块唯一对外契约）。
 *
 * <p>被三类调用方共用：{@code /v1/auth/**} 的 Bearer 控制器传原始令牌；
 * {@code /web-api/**} 浏览器适配层与 SSO 授权/兑换链路传已核验的
 * {@link CurrentSession} 或会话 id；{@code /v1/internal} introspection 复用
 * {@link #loadSnapshot(String)} 与 {@link #audit}。接口本身不区分认证方式，
 * 只区分"是否已完成双重核验"。
 *
 * <p>方法重载约定：以 {@code String rawToken} 为入参的重载会自己完成
 * "Redis Sa-Token 存活 + PG 主库权威快照"双重核验；以 {@link CurrentSession} 为入参的重载
 * 信任调用方已核验的快照，不再重复核验，用于同一请求内的二次调用与浏览器链路。
 *
 * <p>权威边界：PG 是会话与授权的唯一权威，Redis 只是 Sa-Token 存活索引——Redis 丢失或被暂停
 * 时，读取路径因依赖失败一律 503 失败关闭，绝不因"读不到"而放行；PG 侧的撤销/停用/代次推进
 * 则在下一次核验即时生效。会话状态变更、审计与 Redis 清理 outbox 在同一事务提交。
 *
 * <p>失败统一抛 {@link com.airagent.iam.web.error.ApiException}
 * （badRequest 400 / unauthenticated 401 / forbidden 403 / conflict 409 /
 * rateLimited 429 / dependencyUnavailable 503），依赖类异常由
 * {@link com.airagent.iam.web.error.GlobalExceptionHandler} 兜底转 503。
 *
 * @author Acerola
 */
public interface SessionService {

    /**
     * 账号口令登录：限流 → 口令核验 → 建 Redis 会话 → 建 PG 权威会话 → 回读快照校验。
     *
     * <p>限流按 {@code realm:account} 固定窗口计数且发生在 BCrypt 之前；不存在账号与错误口令
     * 返回完全相同的 401 消息，不区分二者以避免账号枚举。PG 建立失败会补偿删除刚建的 Redis 会话，
     * 绝不返回未可靠建立的会话。
     *
     * @param req 登录请求；{@code null} 视为请求体缺失
     * @return 一次性下发原始令牌、令牌类型、空闲有效期（秒）与实时身份视图
     * @throws com.airagent.iam.web.error.ApiException 400 请求体缺失或 account/password/realm/audience 不合法；
     *                                                401 账号或口令错误（含账号停用，同一消息）；
     *                                                429 登录限流命中；
     *                                                503 限流或会话依赖故障、会话建立二次校验不一致
     * @throws IllegalStateException 审计写入失败，事务整体回滚（Redis 会话已被补偿删除）
     */
    LoginVO login(LoginDTO req);

    /**
     * SSO 服务端兑换成功后，为同一人类签发受众绑定的独立应用会话。
     *
     * <p>新会话挂到源会话所属的中央会话下，复制其当前企业、上下文代次与三项授权基线，
     * 时限被中央会话剩余时间夹住；中央退出、切企业与续期由数据库触发器原子传播到该子会话。
     * 新令牌先建 Redis 会话再写 PG，PG 失败即补偿删除，Redis 残留由 outbox 兜底。
     *
     * @param source   已核验的浏览器中央会话快照；仅 {@code workforce} 域可用
     * @param audience 注册客户端声明的目标受众（{@code air-agent} / {@code knowledge} / {@code iam-admin}）
     * @return 新应用会话的登录结果，原始令牌只在本次服务端响应中出现一次
     * @throws com.airagent.iam.web.error.ApiException 403 源会话非 workforce 人类会话；
     *                                                401 源会话已撤销或过期（数据库 28000）；
     *                                                409 受众不合法（数据库 23514）；
     *                                                503 会话依赖故障
     */
    LoginVO issueSsoSession(CurrentSession source, String audience);

    /**
     * 按原始令牌退出当前会话。
     *
     * <p>核验不通过（缺令牌、已撤销、已过期、代次变旧）时按"已登出"处理并静默返回，
     * 使登出成为幂等操作；其余错误（如企业停用）与依赖故障照常抛出。
     *
     * @param rawToken 原始访问令牌；{@code null} 或空白视为未认证
     * @throws com.airagent.iam.web.error.ApiException 403 企业或成员关系已停用；
     *                                                503 Redis/PG 依赖故障
     */
    void logout(String rawToken);

    /**
     * 退出已核验的当前会话（浏览器链路复用）。
     *
     * <p>把该会话置为 revoked（原因 {@code user.logout}）、同事务登记 Redis 键删除 outbox 并写审计；
     * 提交后再尽力即时删除 Redis 键，删除失败不回滚——PG 撤销已足以让下一次核验拒绝该令牌。
     * 只影响本会话，同用户其它会话保持活跃。
     *
     * @param current 已核验的当前会话快照
     * @throws com.airagent.iam.web.error.ApiException 503 Redis/PG 依赖故障
     * @throws IllegalStateException 审计或 outbox 写入失败，事务整体回滚
     */
    void logout(CurrentSession current);

    /**
     * 按原始令牌退出该用户全部会话（含当前会话）。
     *
     * @param rawToken 原始访问令牌；{@code null} 或空白视为未认证
     * @throws com.airagent.iam.web.error.ApiException 401 令牌无效、会话已撤销/过期或授权代次变旧；
     *                                                403 企业或成员关系已停用；
     *                                                503 依赖故障
     */
    void logoutAll(String rawToken);

    /**
     * 撤销已核验会话所属用户的全部活跃会话（含当前会话）。
     *
     * <p>数据库函数 {@code revoke_user_sessions(p_keep = NULL)} 一次性置 revoked 并额外把
     * 用户授权代次 +1；被撤会话的 Redis 键删除与审计 {@code auth.logout_all}
     * （detail 记录撤销数量）同事务入 outbox。SSO 兑换出的子会话同样被撤销。
     *
     * @param current 已核验的当前会话快照
     * @throws com.airagent.iam.web.error.ApiException 503 Redis/PG 依赖故障
     * @throws IllegalStateException 审计或 outbox 写入失败，事务整体回滚
     */
    void logoutAll(CurrentSession current);

    /**
     * 查询当前令牌对应的实时身份视图。
     *
     * @param rawToken 原始访问令牌；{@code null} 或空白视为未认证
     * @return 受众按会话登录受众裁剪的 {@link IdentityVO}
     * @throws com.airagent.iam.web.error.ApiException 401 令牌无效、会话缺失/撤销/过期或代次变旧；
     *                                                403 企业或成员关系已停用；
     *                                                503 依赖故障或快照解析失败
     */
    IdentityVO me(String rawToken);

    /**
     * 由已核验快照直接装配身份视图，不再触发额外核验。
     *
     * @param current 已核验的当前会话快照
     * @return 与 {@link #me(String)} 同结构的 {@link IdentityVO}
     */
    IdentityVO identityOf(CurrentSession current);

    /**
     * 列出当前令牌所属用户可切入的企业。
     *
     * @param rawToken 原始访问令牌；{@code null} 或空白视为未认证
     * @return 按企业 code 升序的活跃企业列表；无可用企业时为空列表
     * @throws com.airagent.iam.web.error.ApiException 401 令牌/会话不可用；403 企业或成员关系已停用；
     *                                                503 依赖故障
     */
    List<TenantMembershipVO> tenants(String rawToken);

    /**
     * 列出已核验用户可切入的企业。
     *
     * <p>在事务内先把请求上下文设为该用户自身（平台标志关闭）——tenants 与
     * tenant_memberships 为 FORCE RLS，不设置上下文时结果恒为空。
     *
     * @param current 已核验的当前会话快照
     * @return 按企业 code 升序的活跃企业列表；无可用企业时为空列表
     * @throws com.airagent.iam.web.error.ApiException 503 依赖故障
     */
    List<TenantMembershipVO> tenants(CurrentSession current);

    /**
     * 切换当前企业并返回切换后的实时身份视图。
     *
     * <p>先核验令牌，再执行一次 CAS 切换，最后用新令牌重新加载快照——因此返回体的
     * {@code contextVersion} 已递增，前端必须以此后的值作为后续续期/切企业的基线。
     *
     * @param rawToken 原始访问令牌；{@code null} 或空白视为未认证
     * @param req      目标企业与期望上下文代次；{@code null} 视为字段缺失
     * @return 切换后的实时身份视图（企业、成员关系与权限码均已刷新）
     * @throws com.airagent.iam.web.error.ApiException 400 字段缺失或 tenant_id 非 UUID；
     *                                                401 令牌/会话不可用；
     *                                                403 目标企业不可用或非有效成员（数据库 P0012）；
     *                                                409 上下文代次冲突（数据库 P0010）；
     *                                                503 依赖故障
     */
    IdentityVO switchTenant(String rawToken, SwitchTenantDTO req);

    /**
     * 对已核验会话执行切企业 CAS，不返回身份视图。
     *
     * <p>成功即推进 {@code ctx_version} 并刷新企业/成员基线，变更经中央会话同步触发器
     * 传播到同一中央会话下的全部子会话；审计 {@code auth.switch_tenant} 同事务写入。
     *
     * @param current 已核验的当前会话快照
     * @param req     目标企业与期望上下文代次
     * @throws com.airagent.iam.web.error.ApiException 400 请求体/字段缺失或 tenant_id 非 UUID；
     *                                                403 目标企业不可用或非有效成员；
     *                                                409 上下文代次冲突；
     *                                                503 Redis/PG 依赖故障
     * @throws IllegalStateException 审计写入失败，事务整体回滚
     */
    void switchTenant(CurrentSession current, SwitchTenantDTO req);

    /**
     * 续期当前会话的空闲窗口并返回新的两个到期时刻。
     *
     * @param rawToken 原始访问令牌；{@code null} 或空白视为未认证
     * @param req      期望上下文代次；{@code null} 视为字段缺失
     * @return UTC ISO-8601 文本形式的绝对与空闲到期时刻
     * @throws com.airagent.iam.web.error.ApiException 400 expected_ctx_version 缺失；
     *                                                401 令牌/会话不可用，或会话已撤销/过期而不可复活
     *                                                （数据库 28000）；
     *                                                403 企业或成员关系已停用；
     *                                                409 上下文代次冲突（数据库 P0010）；
     *                                                503 Redis/PG 依赖故障
     * @throws IllegalStateException 审计写入失败，事务整体回滚
     */
    SessionTimersVO renew(String rawToken, RenewDTO req);

    /**
     * 对已核验会话执行续期。
     *
     * <p>数据库在持锁后取 {@code GREATEST(原空闲截止, 锁后时刻 + renewIdleSeconds)}，
     * 再被绝对上限夹住：因此续期单调不减、可安全重试，且永远无法延长绝对到期时刻。
     * 已过期或被撤销的会话一律拒绝，不存在"复活"路径。
     *
     * @param current 已核验的当前会话快照
     * @param req     期望上下文代次
     * @return 续期后的绝对与空闲到期时刻
     * @throws com.airagent.iam.web.error.ApiException 400 代次缺失；401 会话不存在或已撤销/过期；
     *                                                409 代次冲突；503 Redis/PG 依赖故障
     * @throws IllegalStateException 审计写入失败，事务整体回滚
     */
    SessionTimersVO renew(CurrentSession current, RenewDTO req);

    /**
     * 本人改密（Bearer 链路）。
     *
     * @param rawToken 原始访问令牌；{@code null} 或空白视为未认证
     * @param req      旧口令与新口令；{@code null} 视为字段缺失
     * @throws com.airagent.iam.web.error.ApiException 400 字段缺失或新口令长度不在 8..256；
     *                                                401 令牌/会话不可用或旧口令不正确；
     *                                                403 企业或成员关系已停用；
     *                                                409 新口令与旧口令相同；
     *                                                503 Redis/PG 依赖故障
     * @throws IllegalStateException 审计或 outbox 写入失败，事务整体回滚
     */
    void changePassword(String rawToken, ChangePasswordDTO req);

    /**
     * 对已核验会话执行本人改密。
     *
     * <p>旧口令与权威快照中的 BCrypt 摘要在服务端内存中比对（该摘要不出现在响应与日志）；
     * 相等的新旧口令在哈希之前即被拒绝。写入顺序为先撤销该用户全部活跃会话
     * （原因 {@code user.password_change}，含当前会话）再写新摘要——改密后旧令牌立即失效，
     * 调用方必须引导重新登录。被撤会话的 Redis 键删除同事务入 outbox，提交后再即时清理一次，
     * 即时清理失败不回滚事务。
     *
     * @param current 已核验的当前会话快照
     * @param req     旧口令与新口令
     * @throws com.airagent.iam.web.error.ApiException 400 字段缺失或新口令长度不合法；
     *                                                401 旧口令不正确；
     *                                                409 新旧口令相同；
     *                                                503 Redis/PG 依赖故障
     * @throws IllegalStateException 审计或 outbox 写入失败，事务整体回滚
     */
    void changePassword(CurrentSession current, ChangePasswordDTO req);

    /**
     * 双重核验并返回权威快照：先确认 Redis 中 Sa-Token 会话存活，再读 PG 主库快照并比对主体。
     *
     * <p>Redis 与 PG 的 login 主体不一致视为令牌错配，直接 401；快照不可用时按数据库给出的
     * 状态映射：{@code missing} / {@code invalid_or_revoked} / {@code account_disabled} → 401，
     * {@code tenant_suspended} / {@code membership_disabled} → 403。Redis 抛出的连接类异常
     * 不在这里吞掉，由全局处理器转 503（失败关闭）。
     *
     * @param rawToken 原始访问令牌；{@code null} 或空白视为未认证
     * @return 判定为 {@code ok} 的权威快照
     * @throws com.airagent.iam.web.error.ApiException 401 缺少令牌、Redis 会话不存在/已失效、
     *                                                主体不一致、会话缺失/撤销/过期、代次变旧或账号停用；
     *                                                403 企业停用或成员关系停用；
     *                                                503 快照解析失败
     */
    AuthoritySnapshot requireSnapshot(String rawToken);

    /**
     * 双重核验并返回请求作用域会话快照（拦截器与 {@code rawToken} 系重载的公共入口）。
     *
     * @param rawToken 原始访问令牌；{@code null} 或空白视为未认证
     * @return 已核验的 {@link CurrentSession}
     * @throws com.airagent.iam.web.error.ApiException 同 {@link #requireSnapshot(String)}
     */
    CurrentSession requireCurrent(String rawToken);

    /**
     * 浏览器 {@code /web-api} 链路的核验入口：句柄只映射到会话 id，原始令牌不经过浏览器。
     *
     * <p>服务端经 SECURITY DEFINER 函数按会话 id 取回令牌摘要，然后走与 Bearer 完全相同的
     * "Redis 存活 + PG 主库权威快照"双检，不引入第二套权威。
     *
     * @param sessionId 浏览器会话句柄绑定到的会话 id；{@code null} 视为未认证
     * @return 已核验的 {@link CurrentSession}
     * @throws com.airagent.iam.web.error.ApiException 401 句柄缺失、会话不存在、摘要无对应 Redis 会话
     *                                                或权威判定不可用；403 企业/成员关系停用；
     *                                                503 依赖故障
     */
    CurrentSession requireCurrentBySessionId(UUID sessionId);

    /**
     * 加载权威快照，不校验 Redis 存活性。
     *
     * <p>单次主库往返完成：数据库函数自行按摘要推导可信 RLS 上下文并在读取后恢复，
     * 因此调用方无需预先设置上下文。本方法只判定"PG 侧是否可用"，放行前仍需
     * {@link #requireSnapshot(String)} 那样的 Redis 核验。
     *
     * @param digest 令牌摘要（非原始令牌）
     * @return 权威快照，状态可能为不可用，由调用方判断
     * @throws com.airagent.iam.web.error.ApiException 503 jsonb 解析失败
     */
    AuthoritySnapshot loadSnapshot(String digest);

    /**
     * 以调用方事务写入一条 {@code actor_type = human} 的审计。
     *
     * <p>必须在业务变更所在事务内调用：审计失败会抛出使整个事务回滚，不存在"业务成功、审计丢失"。
     * 上下文（RLS 可见性）由调用方先行设置；平台级事件传 {@code tenantId = null}。
     *
     * @param tenantId   审计归属企业；{@code null} 表示平台级事件（受 audit_logs 的 FORCE RLS 约束，
     *                   需上下文为平台身份才可见）
     * @param actor      执行人用户 UUID
     * @param action     动作码，如 {@code auth.login} / {@code auth.logout} / {@code auth.switch_tenant}
     * @param targetType 目标类型，如 {@code auth_session} / {@code user}
     * @param targetId   目标标识文本
     * @param detail     结构化补充信息；{@code null} 按空对象处理。禁止放入口令、令牌、密钥等秘密
     * @throws IllegalStateException 序列化或写入失败，调用方事务随之整体回滚
     */
    void audit(
            UUID tenantId,
            UUID actor,
            String action,
            String targetType,
            String targetId,
            Map<String, Object> detail);
}
