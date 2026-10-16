package com.airagent.iam.security.rt;

import java.util.UUID;

/**
 * rt-v1 运行票据正文（安全层值对象，仅经 {@link RtV1Codec} 序列化，不作 HTTP 响应模型，无 Swagger 注解）。
 *
 * <p>它是"已核验人类会话的一次性短入口凭据"的载荷：由
 * {@link com.airagent.iam.internal.service.impl.RuntimeTicketServiceImpl} 在实时核验主库权威快照后装配，
 * 交给下游运行时（LangGraph runtime）作为受众绑定的入口凭据。票据不是授权快照——权限判定仍由
 * 消费方按 {@code crev/urev/trev/mrev} 与自身缓存的基线比对，或回源内省。
 *
 * <p>字段顺序固定为 {@code sid,uid,tid,mid,aud,iat,exp,crev,urev,trev,mrev}，
 * {@link RtV1Codec} 在其前追加 {@code typ}，序列化为紧凑 JSON 后与 Python 侧
 * {@code tools/rt-v1/rt_v1.py} 的 {@code BODY_ORDER} 逐字节一致——这是跨语言固定向量测试
 * 的前提，任何字段增删或换序都会改变签名输入，属契约变更。
 *
 * @param sid 会话 id，对应 {@code iam.auth_sessions.id}，消费方用它把票据绑定回具体登录
 * @param uid 用户 id，对应 {@code iam.users.id}
 * @param tid 当前企业 id，对应 {@code iam.tenants.id}；签发时该会话必须已选定企业上下文，
 *            否则不产生票据
 * @param mid 该用户在 {@code tid} 下的活跃成员关系 id，对应 {@code iam.tenant_memberships.id}
 * @param aud 受众，本项目实际只签发 {@code langgraph-runtime}；消费方按自身受众校验，不匹配即拒
 * @param iat 签发时刻，Unix 纪元秒（UTC，非本地时区）；核验侧要求 {@code iat <= now + 60}
 *            且 {@code iat <= exp}
 * @param exp 到期时刻，Unix 纪元秒；取签发时刻加 TTL 与会话 idle/绝对上界的最早者，
 *            且与 {@code iat} 的跨度不超过 60 秒
 * @param crev 会话上下文代次（{@code auth_sessions.ctx_version}），切企业时递增；
 *             核验侧要求大于等于 1，低于会话当前值即判旧
 * @param urev 用户授权代次（{@code users.auth_revision}），V3/V12 触发器在口令或账号状态变化、
 *             平台角色授予回收、角色权限内容或角色状态变化时 +1；可为 0
 * @param trev 企业授权代次（{@code tenants.auth_revision}），V3 触发器仅在企业状态变化时 +1；可为 0
 * @param mrev 成员关系代次（{@code tenant_memberships.revision}），V3/V12 触发器在成员状态或部门变化、
 *             成员角色授予回收、角色权限内容或角色状态变化时 +1；可为 0
 * @author Acerola
 */
public record RtV1Body(
        UUID sid,
        UUID uid,
        UUID tid,
        UUID mid,
        String aud,
        long iat,
        long exp,
        long crev,
        long urev,
        long trev,
        long mrev) {
}
