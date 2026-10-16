package com.airagent.iam.audit.entity;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * iam.audit_logs 行的持久化视图（DO，仅 Mapper 使用，不直接对外）。
 *
 * <p>分层位置：由 {@link com.airagent.iam.audit.mapper.AuditLogMapper#selectPage} 的
 * resultMap 按构造器顺序装配，再经
 * {@link com.airagent.iam.audit.service.impl.AuditServiceImpl} 转成对外视图。
 * 本类只出现在读路径——审计写入走 SECURITY DEFINER 函数
 * {@code iam_auth.write_audit}（调用面见
 * {@link com.airagent.iam.common.mapper.AdminEventMapper#insertAudit}），
 * Java 侧没有 INSERT/UPDATE/DELETE 的映射方法。
 *
 * <p>列语义与约束（V1 建表）：主键是数据库 identity 生成的 bigint，租户与操作者列
 * 均为<em>可空且不带外键</em>的 uuid，因此历史事件不会因主体被删而丢失，也不保证引用存在。
 *
 * <p>秘密边界（以实际写入方为据，非推测）：detail 由各写入方显式装配——管理线
 * {@link com.airagent.iam.admin.AdminSupport#audit}、会话线
 * {@link com.airagent.iam.auth.service.SessionService#audit}、服务账号线与内部签票线。
 * 已核对的键只有：account、display_name、code、name、status、roles、permissions、user_id、
 * via 与若干"是否变更"布尔位（管理线）；audience、realm、source_session_id、
 * target_tenant_id、expected_ctx_version、revoked_sessions 计数（会话线）；
 * service_account_id、credential_id、audiences、expires_in_days、expires_at（服务账号线）；
 * audience、target_tenant_id、ttl_seconds（内部签票线）。全部是标识、名称、枚举值、
 * 计数与时长，口令、令牌原文、密钥摘要与请求体原文都不在其中。空值键的处理略有差异：
 * 管理线与服务账号线在序列化前剔除值为 {@code null} 的键，会话线与内部签票线按传入
 * Map 原样序列化（现有调用点未传 null 值）。新增写入方必须遵守同一约定。
 *
 * @param id           审计行 id（{@code bigint GENERATED ALWAYS AS IDENTITY}，全局单调递增；
 *                     分页游标即它的十进制文本，读取按 id 降序 = 最新在前）
 * @param tenantId     事件归属企业 id；{@code null} 表示平台级事件（无外键约束，可空）。
 *                     租户口径的查询看不见 {@code null} 租户行
 * @param actorUserId  操作主体的账号 id（uuid，无外键约束）；可为 {@code null}，
 *                     表示该事件没有可归属的账号
 * @param actorType    主体形态，列 CHECK 允许 {@code human}、{@code service_account}、
 *                     {@code internal_client}、{@code bootstrap}、{@code anonymous}。
 *                     当前 Java 侧全部写入经同一个 Mapper 语句，该值被固定为 {@code human}；
 *                     {@code bootstrap} 由数据库引导函数写入，其余取值是预留位
 * @param action       动作码，形如 {@code admin.user.create}、{@code auth.login}、
 *                     {@code service_account.token_issue}；列为无格式约束的 text，值由写入方给出
 * @param targetType   目标对象类型，形如 {@code user}、{@code tenant_membership}、
 *                     {@code auth_session}；列 NOT NULL
 * @param targetId     目标对象标识文本（通常是 UUID 字符串）；列可空，故可为 {@code null}
 * @param detailJson   结构化补充信息的 JSONB 文本形态。SQL 以 {@code detail::text} 取回
 *                     （列 {@code NOT NULL DEFAULT '{}'::jsonb}），故本字段恒为非空的合法 JSON 文本，
 *                     无补充信息时为空对象文本；内容遵守上述秘密边界
 * @param requestId    请求 id，写入方取自行间日志上下文 MDC 的 {@code request_id}，
 *                     与错误信封可互相追踪；上下文无该键时为 {@code null}
 * @param createdAt    事件写入时间（timestamptz），取数据库 {@code now()}，不受应用进程时钟影响
 * @author Acerola
 */
public record AuditLogDO(long id, UUID tenantId, UUID actorUserId, String actorType,
                         String action, String targetType, String targetId, String detailJson,
                         String requestId, OffsetDateTime createdAt) {
}
