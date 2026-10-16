package com.airagent.iam.auth.entity;

import java.time.OffsetDateTime;

/**
 * 续期后的会话截止时间行（DO，仅 {@link com.airagent.iam.auth.mapper.SessionMapper#renew} 使用，不对外）。
 *
 * <p>来源为 SECURITY DEFINER 函数 {@code iam_auth.renew_session(session_id, expected_ctx_version,
 * idle_seconds)} 的结果集（V13/V16）。数据库在持锁后以 {@code clock_timestamp()} 重新计算
 * 空闲截止时间，并保证单调：新值取 {@code GREATEST(原 idle_expires_at, now + idle_seconds)}
 * 后再被 {@code LEAST(..., absolute_expires_at)} 夹住，因此续期只会延后空闲上限、绝不越过绝对上限，
 * 也不会因旧事务晚提交而缩短会话。
 *
 * <p>函数同时返回的 {@code expires_at} 与 {@code idle_expires_at} 取值相同（会话有效性判定读
 * {@code expires_at}），Mapper 只映射本记录的两个字段。
 *
 * @param absoluteExpiresAt 绝对到期时刻，续期不改变（timestamptz，数据库时钟）
 * @param idleExpiresAt     续期后的空闲到期时刻，同时写入 {@code expires_at}（timestamptz，数据库时钟）
 * @author Acerola
 */
public record SessionTimerDO(OffsetDateTime absoluteExpiresAt, OffsetDateTime idleExpiresAt) {
}
