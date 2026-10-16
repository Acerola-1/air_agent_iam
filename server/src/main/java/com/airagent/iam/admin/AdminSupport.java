package com.airagent.iam.admin;

import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.common.mapper.AdminEventMapper;
import com.airagent.iam.common.mapper.RequestContextMapper;
import com.airagent.iam.web.error.ApiException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

/**
 * 管理线（Controller → Service → Mapper）共用的支撑组件，不属于任何单一业务域。
 *
 * <p>集中四件事：会话权限裁决（{@link #requirePermission}/{@link #requireAnyPermission}）、
 * PostgreSQL 请求上下文写入（{@link #setContext}，决定 RLS 与触发器的可见性口径）、
 * keyset 分页参数处理（{@link #clampLimit}/{@link #encodeCursor}/{@link #decodeCursor}）、
 * 同事务审计与 Redis 会话键删除投递（{@link #audit}/{@link #enqueueRedisDeletes}）。
 * 各 AdminServiceImpl 在自己的事务里调用本组件，因此这里不持有事务边界。
 *
 * <p>菜单/按钮不可替代这里的服务端裁决；权限来源始终是会话授权快照
 * （由 {@code iam_auth.load_authority_snapshot} 单轮装配），而不是请求头或请求体自报值。
 * 每次写操作都必须在调用方事务内显式 {@link #setContext} —— 上下文是事务级
 * （set_config 的 local 标志），提交或回滚后自动失效，跨事务复用不会残留。
 *
 * <p>失败语义：裁决不通过一律抛 {@link ApiException}，由 GlobalExceptionHandler 转错误信封；
 * 审计写入失败抛 {@link IllegalStateException} 使调用方事务整体回滚，绝不吞异常。
 *
 * @author Acerola
 */
@Component
public class AdminSupport {

    /** 分页缺省条数：请求未带 limit 时使用。 */
    public static final int DEFAULT_LIMIT = 20;
    /** 分页上限：同时是 {@link #clampLimit} 的合法上界，超过即 400。 */
    public static final int MAX_LIMIT = 200;

    /** 审计事件与 Redis 删除 outbox 的数据访问入口（同事务写入）。 */
    private final AdminEventMapper eventMapper;
    /** 审计 detail 与 outbox payload 的 JSON 序列化器。 */
    private final ObjectMapper mapper;
    /** 写入 PostgreSQL 请求上下文（app.user_id / app.tenant_id / app.is_platform）的入口。 */
    private final RequestContextMapper requestContextMapper;

    /**
     * 构造管理线支撑组件，全部依赖经 Spring 构造注入。
     *
     * @param eventMapper            审计与 outbox 写入
     * @param mapper                 JSON 序列化器（detail、待删键列表）
     * @param requestContextMapper   事务级请求上下文写入
     */
    public AdminSupport(AdminEventMapper eventMapper, ObjectMapper mapper,
                        RequestContextMapper requestContextMapper) {
        this.eventMapper = eventMapper;
        this.mapper = mapper;
        this.requestContextMapper = requestContextMapper;
    }

    /**
     * 要求会话权限快照中必须含有指定权限码。
     *
     * <p>不区分"未认证"与"无权限"：会话为 {@code null} 同样按 403 处理（未认证场景由拦截器
     * 在进入服务层之前返回 401）。权限码是账号的平台角色与企业角色的权限并集，非空即视为具备。
     *
     * @param session 当前会话快照，可为 {@code null}（此时按无权限拒绝）
     * @param code    要求的权限码，如 {@code platform:user:read}、{@code tenant:member:write}
     * @throws ApiException 403 当会话为空或权限快照不含该码（消息中带上缺失的权限码）
     */
    public void requirePermission(CurrentSession session, String code) {
        if (session == null || !session.snapshot().permissions().contains(code)) {
            throw ApiException.forbidden("缺少权限: " + code);
        }
    }

    /**
     * 要求会话具备给定权限码中的至少一个（或语义，命中即通过）。
     *
     * <p>用于读写权限分列的目录类接口。调用方须保证 codes 至少含一个元素，
     * 空数组时行为等价于"必然 403"。
     *
     * @param session 当前会话快照，可为 {@code null}（此时按未认证拒绝）
     * @param codes   候选权限码（可变参数），任一命中即通过
     * @throws ApiException 403 当会话为空，或所有候选码都不在权限快照中
     */
    public void requireAnyPermission(CurrentSession session, String... codes) {
        if (session == null) {
            throw ApiException.forbidden("未认证会话");
        }
        for (String code : codes) {
            if (session.snapshot().permissions().contains(code)) {
                return;
            }
        }
        throw ApiException.forbidden("缺少任一必需权限");
    }

    /**
     * 要求会话已选择企业上下文，并取回该企业 id。
     *
     * <p>企业管理（platform 线）可以在空租户上下文下执行，而企业内成员/部门/角色的写操作
     * 一律不允许在平台空上下文下直写租户行，因此必须先切企业再进事务。
     * 本方法只回读会话里的租户 id，不复核企业是否停用、成员关系是否仍有效
     * —— 这些由 RLS 与权威快照裁决。会话本身为 {@code null} 不在本方法防御范围内
     * （调用方应先完成权限裁决）。
     *
     * @param session 当前会话快照
     * @return 会话当前企业 id（非 {@code null}）
     * @throws ApiException 400 当会话未选择企业上下文（currentTenantId 为空）
     */
    public UUID requireCurrentTenant(CurrentSession session) {
        UUID tenantId = session.currentTenantId();
        if (tenantId == null) {
            throw ApiException.badRequest("请先选择企业上下文");
        }
        return tenantId;
    }

    /**
     * 写入 PostgreSQL 请求上下文（经 SECURITY DEFINER 函数 {@code iam_auth.set_request_context}）。
     *
     * <p>必须在调用方事务内的第一条业务 SQL 之前执行：三项参数分别落为
     * {@code app.user_id}、{@code app.tenant_id}、{@code app.is_platform}，
     * 后续所有行的可见性（RLS 策略）、触发器口径（如最后管理员保护）都以此为准。
     * 上下文为事务级，事务结束后自动消失，因此每个事务都要重新设置。
     *
     * @param userId   写入 {@code app.user_id} 的操作者账号 id；{@code null} 表示该键置空
     * @param tenantId 写入 {@code app.tenant_id} 的企业 id；平台口径通常传 {@code null}
     * @param platform {@code true} 打开平台口径（RLS 放行跨租户读、并允许写全局行），
     *                 {@code false} 收敛为租户口径（仅本租户可见可写）
     */
    public void setContext(UUID userId, UUID tenantId, boolean platform) {
        requestContextMapper.setContext(userId, tenantId, platform);
    }

    /**
     * 归一并校验分页条数。
     *
     * @param limit 请求里的 limit；{@code null} 表示未提供
     * @return 实际生效条数：未提供时为 {@link #DEFAULT_LIMIT}，否则原值（保证落在 1..{@link #MAX_LIMIT}）
     * @throws ApiException 400 当 limit 小于 1 或大于 200（不静默截断）
     */
    public int clampLimit(Integer limit) {
        if (limit == null) {
            return DEFAULT_LIMIT;
        }
        if (limit < 1 || limit > MAX_LIMIT) {
            throw ApiException.badRequest("limit 必须在 1 到 200 之间");
        }
        return limit;
    }

    /**
     * 生成 keyset 游标：base64url（无填充）编码上一页末行 id 的文本。
     *
     * <p>游标刻意不透明，不承载排序方向或偏移量语义，翻页只能靠服务端继续按 id 升序比对。
     *
     * @param lastId 本页最后一行的 id 文本（UUID 字符串）；不做非空校验，由调用方保证本页非空
     * @return 可直接放进响应的游标字符串
     */
    public String encodeCursor(String lastId) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(lastId.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * 解码 keyset 游标。
     *
     * @param cursor 请求里的游标原文；{@code null} 或空白表示从首页开始
     * @return 解码出的上一页末行 id 文本，首页为 {@code null}；返回值不保证是合法 UUID，
     *         由调用方经 {@link #parseUuid} 二次校验
     * @throws ApiException 400 当游标不是合法的 base64url 文本
     */
    public String decodeCursor(String cursor) {
        if (cursor == null || cursor.isBlank()) {
            return null;
        }
        try {
            return new String(Base64.getUrlDecoder().decode(cursor), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw ApiException.badRequest("cursor 不合法");
        }
    }

    /**
     * 解析路径/查询参数中的 UUID 文本。
     *
     * @param value 待解析文本，允许为 {@code null}（按不合法处理）
     * @param field 出错消息中引用的字段名（如 {@code user_id}、{@code tenant_id}）
     * @return 解析后的 UUID
     * @throws ApiException 400 当文本为 {@code null} 或不构成合法 UUID
     */
    public static UUID parseUuid(String value, String field) {
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException | NullPointerException e) {
            throw ApiException.badRequest(field + " 不是合法 UUID");
        }
    }

    /**
     * 角色/权限码列表消毒：去空白、去重、拒绝超长/非法字符。
     *
     * <p>合法码形如 {@code tenant:member:read}、{@code platform_super_admin}：以小写字母开头，
     * 总长 3..64，仅允许小写字母、数字与 {@code : _ -}。去重保留首次出现顺序，
     * 因此"重复同一个码"不会导致重复授予，也不会报错。
     *
     * @param codes 请求体里的原始码列表，可为 {@code null}
     * @return 消毒后的不可变列表；输入为 {@code null} 时返回空列表（等价"不授予任何码"）
     * @throws ApiException 400 当任一元素为 {@code null}、空白、超长或含非法字符（消息回显原值）
     */
    public static List<String> sanitizeCodes(java.util.List<String> codes) {
        if (codes == null) {
            return List.of();
        }
        java.util.List<String> result = new java.util.ArrayList<>();
        for (String code : codes) {
            if (code == null || code.isBlank() || code.length() > 64
                    || !code.matches("[a-z][a-z0-9:_-]{2,63}")) {
                throw ApiException.badRequest("角色/权限码不合法: " + code);
            }
            if (!result.contains(code)) {
                result.add(code);
            }
        }
        return result;
    }

    /**
     * 登记 Redis 键删除 outbox（同事务）。Sa-Token 键构形必须与 DigestStpLogic 一致：
     * Authorization:login:token:&lt;sha256-hex(rawToken)&gt;。
     *
     * <p>会话撤销的 SQL 侧只返回令牌摘要，Redis 不能在同一事务里安全删除，
     * 故先落 outbox，由消费端在事务提交后重放清理；入队失败会连带业务事务回滚。
     *
     * @param digests 被撤销会话的令牌摘要列表（sha256 十六进制小写文本）；
     *                {@code null} 元素不受支持，空列表按 no-op 处理（不产生 outbox 行）
     */
    public void enqueueRedisDeletes(List<String> digests) {
        if (digests.isEmpty()) {
            return;
        }
        List<String> keys = digests.stream().map(digest -> "Authorization:login:token:" + digest).toList();
        eventMapper.enqueueRedisDeletes(mapper.writeValueAsString(Map.of("keys", keys)));
    }

    /**
     * 写入审计日志（与调用方业务变更同事务，审计失败整体回滚）。
     *
     * <p>detail 只在 JSON 里留下非空值（null 值字段被剔除，避免把"未提供"与"置空"混为一谈），
     * key 顺序按传入的 Map 保留。请求 id 取自行间日志上下文 MDC 的 request_id，
     * 无该键时写 null。审计行的可见性受 iam.audit_logs 的 RLS 约束：租户内审计必须
     * 在对应企业上下文写入，平台级审计（tenantId 传 {@code null}）必须在平台上下文写入。
     *
     * @param tenantId   审计归属企业；{@code null} 表示平台级事件
     * @param actor      操作者账号 id（写入审计的 actor 列）
     * @param action     动作码，形如 {@code admin.user.create}、{@code admin.membership.delete}
     * @param targetType 目标对象类型，形如 {@code user}、{@code tenant}、{@code department}
     * @param targetId   目标对象 id 文本
     * @param detail     结构化补充信息；可为 {@code null}（落库为空对象），其中值为 {@code null}
     *                   的条目会被剔除。禁止放入口令、令牌等敏感片段
     * @throws IllegalStateException 当 detail 序列化或审计写入抛出任何运行时异常
     *                               （含 SQL 约束冲突等数据访问异常），以保证调用方事务回滚
     */
    public void audit(UUID tenantId, UUID actor, String action, String targetType, String targetId,
                     Map<String, Object> detail) {
        try {
            Map<String, Object> safeDetail = new LinkedHashMap<>(detail == null ? Map.of() : detail);
            safeDetail.values().removeIf(v -> v == null);
            eventMapper.insertAudit(tenantId, actor, action, targetType, targetId,
                    mapper.writeValueAsString(safeDetail), MDC.get("request_id"));
        } catch (RuntimeException e) {
            throw new IllegalStateException("审计写入失败（事务必须整体回滚）", e);
        }
    }
}
