package com.airagent.iam.auth.entity;

/**
 * 已申领待投递的 outbox 事件行（DO，仅
 * {@link com.airagent.iam.auth.mapper.InfrastructureMapper#claimOutbox} 使用，不对外）。
 *
 * <p>来源为 SECURITY DEFINER 函数 {@code iam_auth.claim_due_outbox(limit)}：它以
 * {@code status = 'pending' AND available_at <= now()} 按 id 升序取批，并用
 * {@code FOR UPDATE SKIP LOCKED} 保证并发中继实例互不重复申领；同一条 UPDATE 里把
 * {@code attempts} +1，因此本记录的 attempts 是"含本次"的已尝试次数。
 *
 * <p>投递语义为至少一次：状态变更与 outbox 登记在业务事务内同写，Redis 删除本身幂等，
 * 失败按指数退避重放，达到上限后由 {@code iam_auth.requeue_outbox} 置 {@code dead}。
 * outbox 表为 ENABLE RLS 无策略表，iam_app 只能经 iam_auth 函数访问。
 *
 * @param id          iam.outbox 主键（bigint IDENTITY），完成/重排按它定位
 * @param kind        事件类型，当前仅 {@code redis_delete_keys}（表 CHECK 另留
 *                    {@code redis_delete_pattern}，本服务暂无生产者）
 * @param payloadJson payload 列的 jsonb 文本，形如 {@code {"keys":["<Sa-Token 令牌 Redis 键名>"]}}，
 *                    键名由 {@code DigestStpLogic#keyByDigest} 按令牌摘要拼接；不含原始令牌
 * @param attempts    已尝试次数（申领时已自增），与中继的重试上限比较以决定是否转 dead
 * @author Acerola
 */
public record OutboxEventDO(long id, String kind, String payloadJson, int attempts) {
}
