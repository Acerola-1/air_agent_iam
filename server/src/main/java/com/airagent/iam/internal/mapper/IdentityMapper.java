package com.airagent.iam.internal.mapper;

import com.airagent.iam.internal.entity.IssuedKnowledgeDelegationDO;
import com.airagent.iam.internal.entity.IssuedVerificationRefDO;
import com.airagent.iam.internal.entity.KnowledgeDelegationDO;
import com.airagent.iam.internal.entity.VerificationRefDO;
import java.util.UUID;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/**
 * 内部主体核验与执行引用的数据访问（Mapper 层，SQL 见 mapper/internal/IdentityMapper.xml）。
 *
 * <p>运行在请求角色 {@code iam_app} 下：本接口<b>不写任何表名可见的业务 SQL</b>，全部语句
 * 是对 {@code iam_auth} schema 下 {@code SECURITY DEFINER} 函数的单次调用——执行引用表
 * {@code iam.verification_refs} 启用 RLS 且未向 {@code iam_app} 开放策略，服务账号与令牌明细
 * 同样只能通过 {@code load_service_identity} 取得。因此调用方无需、也不得预先设置
 * {@code app.user_id / app.tenant_id / app.is_platform} 上下文。
 *
 * <p>一致性口径：所有查询 {@code useCache=false}（关闭二级缓存）、写侧另加
 * {@code flushCache=true}，绝不复用上一请求的授权结果——每次核验都是一次主库往返。
 * 判定结论（{@code status}）一律由数据库给出，本层与 Service 都不做放行推断。
 *
 * @author Acerola
 */
@Mapper
public interface IdentityMapper {

    /**
     * 按引用 id 读取执行引用，作用域由客户端与受众共同界定。
     *
     * <p>函数在 {@code WHERE} 中同时要求 {@code client_id}、{@code audience} 匹配且
     * {@code valid_until > now()}：其他客户端即使拿到同一 UUID 也查不到（视为伪造），
     * 过期引用同理。命中即代表引用自身仍有效，主体实时性仍需服务层另读权威快照。
     *
     * @param id       引用 UUID；{@code null} 不会命中任何行
     * @param clientId 已认证内部客户端标识（精确匹配，不做大小写折叠）
     * @param audience 本次请求受众，须与引用登记时的受众一致
     * @return 引用行；不存在、不匹配或已过期时返回 {@code null}，不返回部分字段
     */
    VerificationRefDO findReference(
            @Param("id") UUID id,
            @Param("clientId") String clientId,
            @Param("audience") String audience);

    /**
     * 按会话 id 读取该会话当前的权威快照（复查模式使用）。
     *
     * <p>SQL 为 {@code load_trusted_authority_snapshot(session_token_digest(sessionId))} 的单次
     * 嵌套调用：先由会话 id 反查令牌摘要，再走与令牌摘要完全相同的权威判定路径
     * （会话状态、账号状态、时限、三项授权代次与企业/成员状态全部在 PG 内比较）。
     * 可信版函数自行从会话推导 RLS 上下文并在读取后恢复调用方事务上下文，因此不污染外层事务。
     *
     * @param sessionId 会话 UUID；不存在或摘要缺失时快照以 {@code {"status":"missing"}} 返回
     * @return 权威快照的 jsonb 文本，永不返回 {@code null}；调用方解析为
     *         {@link com.airagent.iam.auth.AuthoritySnapshot}
     */
    String snapshotForSession(@Param("sessionId") UUID sessionId);

    /**
     * 记录引用的最近一次复查时刻（{@code last_checked_at = now()}）。
     *
     * <p>不改变 {@code valid_until}，即"复查"不构成续期；引用失效上界始终由登记时的 TTL
     * 与原会话绝对上界决定。当前复查链路未调用本方法（引用可被重复复查，无需登记消费事实）。
     *
     * @param id 引用 UUID；不存在的 id 更新不到行
     * @return 固定为 1（函数无返回列，语句以 {@code SELECT 1} 表达执行成功）；不反映实际更新行数
     */
    int touchReference(@Param("id") UUID id);

    /**
     * 登记一条新的执行引用（令牌内省携带 {@code include_execution_context} 时调用）。
     *
     * <p>函数校验会话存在且为 {@code active}，否则以 SQLSTATE 28000 报错；
     * {@code valid_until} 取 {@code LEAST(now() + ttlSeconds, 会话 absolute_expires_at)}。
     * 每次调用都插入新行，同一会话可并存多条引用，旧引用不被消费或撤销——
     * 引用只是复查锚点，不是凭证。
     *
     * @param clientId     登记该引用的已认证客户端（后续仅同一客户端可查）
     * @param audience     登记时的受众，须与复查请求的受众一致
     * @param sessionId    原会话 UUID
     * @param userId       主体用户 UUID
     * @param tenantId     当前企业 UUID，可为 {@code null}（以 {@code jdbcType=OTHER} 传未指定类型参数）
     * @param revisionsJson 四项修订的 JSON 文本，入库时 {@code CAST(... AS jsonb)}；键为 SNAKE_CASE
     * @param ttlSeconds   引用上界秒数（配置 {@code iam.internal.verification-ref-ttl-seconds}，
     *                     默认 43200 秒），单位秒，非相对会话剩余时间的延长量
     * @return 新引用的 id 与失效时刻
     * @throws org.springframework.dao.DataAccessException 会话不存在或已撤销（SQLSTATE 28000），
     *         经 PgErrorTranslator 落为 401
     */
    IssuedVerificationRefDO createReference(
            @Param("clientId") String clientId,
            @Param("audience") String audience,
            @Param("sessionId") UUID sessionId,
            @Param("userId") UUID userId,
            @Param("tenantId") UUID tenantId,
            @Param("revisionsJson") String revisionsJson,
            @Param("ttlSeconds") long ttlSeconds);

    /**
     * 按令牌摘要读取服务账号（机器主体）身份与实时权限。
     *
     * <p>函数内部把请求上下文置为平台域，按摘要定位 {@code iam.service_tokens} 行，
     * 依次判：凭据不存在/已撤销/已过 {@code expires_at}/已过 {@code overlap_until} →
     * {@code invalid_or_revoked}；服务账号非 active 或已到期 → {@code account_disabled}；
     * 所属企业非 active → {@code tenant_suspended}。权限码仅取活跃且<b>非资源型</b>
     * （{@code resource_code IS NULL}）的授予，资源边界另由授予层与消费方默认拒绝。
     *
     * @param digest 令牌原文的 SHA-256 十六进制摘要（见
     *               {@link com.airagent.iam.security.token.OpaqueTokens#digest(String)}）；
     *               原始令牌不进入本层
     * @return 机器身份快照的 jsonb 文本，永不返回 {@code null}；无 {@code status = ok}
     *         时不含 {@code service_account} 等节点，由调用方按 {@code status} 分支
     */
    String loadServiceIdentity(@Param("digest") String digest);

    /** IAM authoritative tenant availability; does not grant tenant access. */
    boolean tenantIsActive(@Param("tenantId") UUID tenantId);

    /**
     * 以当前客户端自己名下的 runtime 执行引用登记一条知识只读委托。
     *
     * <p>数据库在同一函数内完成：引用归属/受众/期限、源会话 active、四项修订一致、
     * 企业成员关系、至少一项实时有效 {@code knowledge:lib:*:read}，并把有效期收敛到
     * 60 秒、源引用与会话绝对期限的最小值。任何一项不满足都以 SQLSTATE 28000/42501 拒绝。
     *
     * @param clientId    申请委托的 Agent 内部客户端
     * @param referenceId 源执行引用 UUID
     * @param operation   单一操作
     * @param tokenDigest 随机令牌的 SHA-256 摘要（只存摘要）
     * @param ttlSeconds  TTL（1..60）
     * @return 到期时刻与源身份快照
     */
    IssuedKnowledgeDelegationDO createKnowledgeDelegation(
            @Param("clientId") String clientId,
            @Param("referenceId") UUID referenceId,
            @Param("operation") String operation,
            @Param("tokenDigest") String tokenDigest,
            @Param("ttlSeconds") long ttlSeconds);

    /**
     * 按摘要读取仍有效（未过期、未撤销）的知识委托行。
     *
     * @param digest 令牌 SHA-256 摘要
     * @return 委托行；不存在/过期/撤销时返回 {@code null}
     */
    KnowledgeDelegationDO findKnowledgeDelegation(@Param("digest") String digest);

    /**
     * 记录委托的最近使用时刻（不续期）。
     *
     * @param id 委托行 id
     */
    int touchKnowledgeDelegation(@Param("id") UUID id);
}
