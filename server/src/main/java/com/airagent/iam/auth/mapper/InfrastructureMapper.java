package com.airagent.iam.auth.mapper;

import com.airagent.iam.auth.entity.BootstrapUserDO;
import com.airagent.iam.auth.entity.OutboxEventDO;
import com.airagent.iam.auth.entity.ProvisionResultDO;
import java.util.List;
import java.util.UUID;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/**
 * 启动引导与 outbox 中继的数据访问（Mapper 层，SQL 见 mapper/auth/InfrastructureMapper.xml）。
 *
 * <p>承载两类非请求路径的能力：应用启动时由 {@link com.airagent.iam.auth.BootstrapRunner}
 * 幂等预置超级管理员与内部/SSO 客户端；后台调度由
 * {@link com.airagent.iam.auth.OutboxRelay} 申领并投递 Redis 清理事件。两者都只经
 * {@code iam_auth.*} 的 SECURITY DEFINER 函数触碰无策略或 FORCE RLS 的表，
 * 因此不依赖请求上下文，也不在任何 HTTP 路径上暴露。
 *
 * <p>秘密边界：本层参数一律是 BCrypt 口令摘要或 SHA-256 令牌/密钥摘要，
 * 原始口令与客户端密钥不进入 SQL、日志或审计。
 *
 * @author Acerola
 */
@Mapper
public interface InfrastructureMapper {

    /**
     * 幂等引导超级管理员（{@code iam_auth.ensure_bootstrap_user}）。
     *
     * <p>函数内以 {@code realm = 'workforce' AND account = ?} 判定是否已存在：已存在则原样返回其
     * id 与 {@code false}，不重置口令、不改动角色；仅新建路径才插入账号、授予平台超管角色、
     * 登记 {@code iam.bootstrap_meta} 并写 {@code bootstrap.user.ensure} 审计
     * （函数内部临时提升为平台上下文以满足 audit_logs 的 FORCE RLS）。
     *
     * @param account      引导账号（可打印 ASCII 3..64，由调用方从配置读取）
     * @param displayName  显示名，非空
     * @param passwordHash BCrypt 摘要；已存在账号不会被它覆盖
     * @param roleId       平台超级管理员角色 UUID（与种子目录固定 id 一致）
     * @return 账号 id 与"本次是否新建"
     */
    BootstrapUserDO ensureUser(
            @Param("account") String account,
            @Param("displayName") String displayName,
            @Param("passwordHash") String passwordHash,
            @Param("roleId") UUID roleId);

    /**
     * 幂等预置/轮换本机合成 runtime 内部客户端（{@code iam_auth.ensure_internal_client}）。
     *
     * <p>名称、scope 与 audience 在 XML 中固定（{@code identity:introspect}、
     * {@code runtime-ticket:issue} 与 {@code langgraph-runtime}），不接受调用方传入。
     * 按 client_id 做 upsert：已存在会用本次摘要覆盖旧密钥并令 revision +1、状态复位为
     * {@code active}，因此每次带凭据的启动都是一次密钥轮换。
     *
     * @param clientId      客户端标识（配置 {@code iam.internal.runtime-client.id}）
     * @param secretDigest  客户端密钥的 SHA-256 摘要；原始密钥不落库
     * @return 本次是否新建，以及写入后的修订号
     */
    ProvisionResultDO ensureRuntimeClient(
            @Param("clientId") String clientId,
            @Param("secretDigest") String secretDigest);

    /**
     * 幂等预置合成 SSO 客户端（{@code iam_auth.ensure_sso_client}）。
     *
     * <p>与内部客户端不同：冲突时只同步名称、精确回调地址、Origin 白名单与受众，
     * 不覆盖既有密钥摘要。受众不在 {@code air-agent} / {@code knowledge} / {@code iam-admin}
     * 白名单内时函数以 SQLSTATE 23514 报错。sso_clients 为无策略表，iam_app 只能经该函数访问。
     *
     * @param clientId      客户端标识
     * @param name          客户端显示名
     * @param secretDigest  客户端密钥的 SHA-256 摘要；已存在客户端不会被它更新
     * @param callbackUrl   精确回调地址（不做前缀或通配匹配）
     * @param origins       允许的浏览器 Origin 精确白名单；{@code null} 或空表示不登记任何 Origin，
     *                      经数组类型处理器写入 text[] 列
     * @param audience      该客户端兑换应用会话时允许的受众
     * @return 本次是否新建（函数以 {@code xmax = 0} 判定）
     */
    boolean ensureSsoClient(
            @Param("clientId") String clientId,
            @Param("name") String name,
            @Param("secretDigest") String secretDigest,
            @Param("callbackUrl") String callbackUrl,
            @Param("origins") List<String> origins,
            @Param("audience") String audience);

    /**
     * 申领一批到期待投递的 outbox 事件（{@code iam_auth.claim_due_outbox}）。
     *
     * <p>筛选 {@code status = 'pending' AND available_at <= now()}，按 id 升序取
     * {@code batchSize} 条并用 {@code FOR UPDATE SKIP LOCKED} 避免多实例重复申领；
     * 同一条 UPDATE 内把 {@code attempts} +1，因此返回行的 attempts 已含本次。
     * 申领与投递不在同一事务，进程中途崩溃时该行仍是 pending，靠重投与 Redis 删除幂等兜底。
     *
     * @param batchSize 单轮上限（含），由中继按固定批次大小传入
     * @return 本轮申领到的事件；无到期事件时为空列表
     */
    List<OutboxEventDO> claimOutbox(@Param("batchSize") int batchSize);

    /**
     * 标记事件投递完成（{@code iam_auth.complete_outbox(id, false)}），状态置 {@code done}。
     *
     * @param id outbox 事件 id
     * @return 来自 {@code SELECT 1 FROM ...} 的常量 1（函数无结果集），表示调用完成，
     *         不代表实际更新行数；id 不存在或已终结时同样返回 1
     */
    int completeOutbox(@Param("id") long id);

    /**
     * 投递失败后重排事件（{@code iam_auth.requeue_outbox}）。
     *
     * <p>{@code attempts} 已达上限时置 {@code dead} 不再重投；否则回到 {@code pending} 并把
     * {@code available_at} 推到 {@code now + LEAST(30 秒, 1 秒 × 2^MIN(attempts,4))}，
     * 即最长约 16 秒的指数退避。
     *
     * @param id          outbox 事件 id
     * @param maxAttempts 重试次数上限，与事件当前 attempts 比较后决定 pending 或 dead
     * @return 来自 {@code SELECT 1 FROM ...} 的常量 1，语义同 {@link #completeOutbox(long)}
     */
    int requeueOutbox(@Param("id") long id, @Param("maxAttempts") int maxAttempts);
}
