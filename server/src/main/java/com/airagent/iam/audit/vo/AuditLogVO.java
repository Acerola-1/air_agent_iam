package com.airagent.iam.audit.vo;

import io.swagger.v3.oas.annotations.media.Schema;
import tools.jackson.databind.JsonNode;

/**
 * 审计日志 HTTP 出参（VO，对外响应模型）。
 *
 * <p>由 {@link com.airagent.iam.audit.entity.AuditLogDO} 逐行装配：uuid 与时间转文本，
 * {@code detail} 由数据库 {@code detail::text} 还原为 JSON 树后原样输出，不做二次脱敏或改名。
 * 字段名经全局 SNAKE_CASE 序列化策略落为 {@code tenant_id}、{@code actor_user_id}、
 * {@code target_type}、{@code request_id}、{@code created_at} 等，与既有前端
 * {@code AuditView} 类型保持一致；本记录出现在 {@code PageVO} 的 {@code items} 数组中。
 *
 * <p>敏感面：detail 的键集合由各写入方决定（管理线、会话线、服务账号线、内部签票线），
 * 约定只含标识、名称、角色/权限码、状态、受众、原因与时长等非秘密值；
 * 口令、令牌与密钥摘要不进入 detail（键的逐项核对见
 * {@link com.airagent.iam.audit.entity.AuditLogDO}）。响应里的可见范围完全由权限码与
 * RLS 决定，本视图不承担过滤职责。
 *
 * @param id           审计行 id（bigint identity，全局单调）；分页游标即它的 base64url 文本
 * @param tenantId     事件归属企业的 UUID 文本；{@code null} 表示平台级事件，
 *                     只有平台口径的查询能看见这类行
 * @param actorUserId  操作主体的账号 UUID 文本；可为 {@code null}（无可归属账号的事件）
 * @param actorType    主体形态；列 CHECK 允许 {@code human}、{@code service_account}、
 *                     {@code internal_client}、{@code bootstrap}、{@code anonymous}，
 *                     当前 Java 写入路径固定为 {@code human}，{@code bootstrap} 由数据库引导函数写入
 * @param action       动作码，形如 {@code admin.user.create}、{@code auth.login}；
 *                     数据库列无格式约束，值按写入方原文返回
 * @param targetType   目标对象类型，形如 {@code user}、{@code tenant_membership}（列 NOT NULL）
 * @param targetId     目标对象标识文本（通常是 UUID 字符串）；可为 {@code null}
 * @param detail       结构化补充信息，JSONB 原文；无补充时为空对象，不含口令/令牌/密钥
 * @param requestId    请求 id，可用于与错误信封、应用日志互查；上下文缺失时为 {@code null}
 * @param createdAt    事件写入时间，UTC ISO-8601 文本（由数据库 now() 决定；java.time 默认格式
 *                     在秒为 0 时会省略该位，故不保证定长）
 * @author Acerola
 */
@Schema(description = "审计日志视图（只读，分页元素）。detail 为落库 JSONB 原文，"
        + "写入方约定不含口令、令牌与密钥摘要")
public record AuditLogVO(

        @Schema(description = "审计行 id（数据库 identity 生成的 bigint，全局单调递增）。"
                + "列表按它降序返回，下一页游标即本页末行 id 的 base64url 文本。",
                format = "int64", requiredMode = Schema.RequiredMode.REQUIRED, example = "123456")
        long id,

        @Schema(description = "事件归属企业 UUID 文本；null 表示平台级事件（仅平台审计口径可见）。",
                format = "uuid", nullable = true, example = "01930000-0000-4000-8000-000000000201")
        String tenantId,

        @Schema(description = "操作主体账号 UUID 文本；无可归属账号的事件为 null。",
                format = "uuid", nullable = true, example = "01930000-0000-4000-8000-000000000001")
        String actorUserId,

        @Schema(description = "主体形态。列约束允许五种取值；当前应用侧写入固定为 human，"
                + "bootstrap 由数据库引导函数产生，其余为预留。",
                requiredMode = Schema.RequiredMode.REQUIRED,
                allowableValues = {"human", "service_account", "internal_client", "bootstrap", "anonymous"})
        String actorType,

        @Schema(description = "动作码，例如 admin.user.create、auth.login、service_account.token_issue。",
                requiredMode = Schema.RequiredMode.REQUIRED, example = "admin.user.password_reset")
        String action,

        @Schema(description = "目标对象类型，例如 user、tenant、tenant_membership、department。",
                requiredMode = Schema.RequiredMode.REQUIRED, example = "user")
        String targetType,

        @Schema(description = "目标对象标识文本（通常是目标资源 UUID 字符串）；写入方未提供时为 null。",
                nullable = true, example = "01930000-0000-4000-8000-000000000107")
        String targetId,

        @Schema(description = "结构化补充信息，JSONB 原文（键随动作码变化，如 account、display_name、"
                + "status、roles、permissions、audience、ttl_seconds）。无补充时为空对象；"
                + "不含口令、令牌与密钥摘要。", type = "object", additionalProperties = Schema.AdditionalPropertiesValue.TRUE)
        JsonNode detail,

        @Schema(description = "请求 id，用于与错误信封及应用日志互查；无请求上下文时为 null。",
                nullable = true, example = "req-7f3c1a2b")
        String requestId,

        @Schema(description = "事件写入时间，UTC ISO-8601 文本（数据库时钟；秒为 0 时该位会被省略）。",
                format = "date-time", requiredMode = Schema.RequiredMode.REQUIRED,
                example = "2026-03-04T09:12:33.482117Z")
        String createdAt) {
}
