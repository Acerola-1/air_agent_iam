package com.airagent.iam.webapi.sso.entity;

/**
 * 一次性 {@code state} 被原子消费后回读的绑定信息（DO，仅 Mapper 使用，不直接对外）。
 *
 * <p>分层位置：{@link com.airagent.iam.webapi.sso.mapper.SsoMapper#consumeState} 的返回值。
 * 底层 SQL 为 {@code SELECT client_id, redirect_uri FROM iam_auth.sso_state_consume(#{digest})}
 * （见 {@code resources/mapper/webapi/sso/SsoMapper.xml}）。该 SECURITY DEFINER 函数对
 * {@code iam.sso_states} 执行<em>单语句</em> {@code UPDATE ... SET consumed_at = now()
 * WHERE state_digest = ? AND consumed_at IS NULL AND expires_at > now() RETURNING ...}：
 * 领取与置位同一原子完成，重放或已过期命中 0 行即返回 {@code null}，不存在"读到未消费行"的中间态。
 *
 * <p>消费边界：{@code state_digest} 为主键，存的是原始 state 的 SHA-256 十六进制摘要，
 * 原始 state 只出现在 303 回调 query 里、从不入库。行上的 {@code handle_digest}
 * 记录发起授权时绑定的浏览器会话句柄摘要（写入侧见 {@link com.airagent.iam.webapi.sso.mapper.SsoMapper#saveState}），
 * 但函数虽返回该列，XML 只映射两列，因此兑换阶段<em>不</em>校验句柄一致性——
 * 兑换凭的是 ticket 绑定的中央会话 id，而非句柄。
 *
 * @param clientId     发起授权时登记的客户端标识；兑换侧据此确认 state 属于本客户端
 * @param redirectUri  发起授权时登记的<em>精确</em>回调地址；兑换侧与请求体的
 *                     {@code redirect_uri} 做全串比对，不做前缀匹配
 * @author Acerola
 */
public record SsoStateDO(String clientId, String redirectUri) {
}
