package com.airagent.iam.auth.entity;

/**
 * 内部客户端预置/轮换结果（DO，仅
 * {@link com.airagent.iam.auth.mapper.InfrastructureMapper#ensureRuntimeClient} 使用，不对外）。
 *
 * <p>来源为 SECURITY DEFINER 函数 {@code iam_auth.ensure_internal_client(client_id, name,
 * secret_digest, scopes, audiences)}（V7）。它按 {@code client_id} 做 upsert：
 * 首次插入 {@code revision = 1}；已存在则用本次摘要与固定 scope/audience 覆盖旧值，
 * 同时把 {@code revision} +1、状态复位为 {@code active} 并清空 {@code revoked_at}。
 * 因此每次带同一 client_id 的启动都是一次凭据轮换，而非"保持不变"。
 *
 * <p>登记的只有 SHA-256 摘要：原始密钥既不写库也不进日志。
 *
 * @param wasCreated 本次是否新建（函数内以"调用前是否已存在同 client_id"判定）
 * @param revision   写入后的内部客户端修订号；轮换会使其递增，供核验侧识别凭据版本
 * @author Acerola
 */
public record ProvisionResultDO(boolean wasCreated, long revision) {
}
