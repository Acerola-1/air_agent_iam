package com.airagent.iam.audit.service.impl;

import com.airagent.iam.admin.AdminSupport;
import com.airagent.iam.audit.dto.AuditLogQueryDTO;
import com.airagent.iam.audit.entity.AuditLogDO;
import com.airagent.iam.audit.mapper.AuditLogMapper;
import com.airagent.iam.audit.service.AuditService;
import com.airagent.iam.audit.vo.AuditLogVO;
import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.common.mapper.RequestContextMapper;
import com.airagent.iam.common.vo.PageVO;
import com.airagent.iam.web.error.ApiException;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.ObjectMapper;

/**
 * {@link AuditService} 实现：审计日志的有界只读查询（权限码
 * {@code platform:audit:read} / {@code tenant:audit:read}）。
 *
 * <p>编排顺序（见 {@link #list}，全部落在同一个只读事务里）：会话权限裁决 → 判定平台或
 * 租户口径 → 页宽归一与游标解码 → 写入 PostgreSQL 请求上下文 → 多取一行的 keyset 查询 →
 * DO 到 VO 装配与游标生成。声明式 {@code @Transactional(readOnly = true)} 而非
 * {@link org.springframework.transaction.support.TransactionTemplate}，是因为上下文设置、
 * RLS 判定与查询必须共用同一条连接与同一个事务：上下文由事务级 {@code set_config} 承载，
 * 出了事务即失效，跨事务不复用。
 *
 * <p>可见性边界与 {@code iam.audit_logs} 的 RLS 策略一一对应，服务层的裁决只是决定
 * 用哪个口径去查询，不越过 RLS 放行任何行：
 * <ul>
 *   <li>持 {@code platform:audit:read} —— 平台口径（{@code app.is_platform=on}、租户上下文置空），
 *       可见全部审计行，包含 {@code tenant_id} 为 NULL 的平台级事件与其它租户的事件；</li>
 *   <li>仅持 {@code tenant:audit:read} —— 以会话当前企业为租户口径，只放行本企业行，
 *       平台级事件与其他租户事件一律不可见；会话未选择企业上下文时返回 400，
 *       不放宽为全库；</li>
 *   <li>两个码都持 —— 按平台口径处理（取更宽的一档），不做两口径结果合并。</li>
 * </ul>
 *
 * <p>查询面上界：单页至多 200 条（越界 400，不截断），无时间范围、操作者、目标对象或
 * 租户归属参数；动作码过滤是大小写敏感的 SQL LIKE 模式，服务端仅把 {@code *} 转为多字符
 * 通配符。审计写入由业务事务经 {@link AdminSupport#audit} 等入口同事务完成，本类只读。
 *
 * @author Acerola
 */
@Service
public class AuditServiceImpl implements AuditService {

    /** 平台审计读取权限码：持有即按平台口径查询，跨租户可见（含 NULL 租户的平台级事件）。 */
    private static final String PLATFORM_AUDIT_PERMISSION = "platform:audit:read";
    /** 企业审计读取权限码：仅在会话当前企业口径下可见本租户审计行。 */
    private static final String TENANT_AUDIT_PERMISSION = "tenant:audit:read";

    /** 审计行有界读取（SQL 见 mapper/audit/AuditLogMapper.xml，行可见性由 RLS 决定）。 */
    private final AuditLogMapper auditLogMapper;
    /** 事务级请求上下文写入：决定本次查询走平台口径还是租户口径。 */
    private final RequestContextMapper requestContextMapper;
    /** 管理线共用组件：权限裁决、页宽归一、游标编解码与租户上下文检查。 */
    private final AdminSupport support;
    /** JSON 序列化器：把数据库 {@code detail::text} 还原为可下发的 JSON 树。 */
    private final ObjectMapper objectMapper;

    /**
     * 构造实现，全部依赖经 Spring 构造注入。
     *
     * @param auditLogMapper        审计读取数据访问
     * @param requestContextMapper  PostgreSQL 请求上下文写入（RLS 口径的事实来源）
     * @param support               权限裁决、分页与游标的共用支撑组件
     * @param objectMapper          JSON 树装配用序列化器（Jackson 3）
     */
    public AuditServiceImpl(AuditLogMapper auditLogMapper, RequestContextMapper requestContextMapper,
                            AdminSupport support, ObjectMapper objectMapper) {
        this.auditLogMapper = auditLogMapper;
        this.requestContextMapper = requestContextMapper;
        this.support = support;
        this.objectMapper = objectMapper;
    }

    /**
     * {@inheritDoc}
     *
     * <p>实现细节：先用 {@link AdminSupport#requireAnyPermission} 做"或"语义裁决，
     * 再以权限快照里是否含平台码决定口径——平台线租户上下文传 {@code null}，
     * 企业线经 {@link AdminSupport#requireCurrentTenant} 取会话当前企业（为空即 400）。
     * 查询按 {@code limit + 1} 多取一行：只有确实多出一行才生成 {@code nextCursor}，
     * 游标取本页（裁剪后）最后一行的审计 id。空结果与到末页都返回 {@code null} 游标。
     * 动作过滤只在 {@code action} 为 {@code null} 时省略条件——空串会转成空 LIKE 模式，
     * 与"不过滤"不同；模式串除把 {@code *} 换成百分号外不做其它转义或大小写归一。
     */
    @Override
    @Transactional(readOnly = true)
    public PageVO<AuditLogVO> list(CurrentSession actor, AuditLogQueryDTO query) {
        support.requireAnyPermission(actor, PLATFORM_AUDIT_PERMISSION, TENANT_AUDIT_PERMISSION);
        boolean platform = actor.snapshot().permissions().contains(PLATFORM_AUDIT_PERMISSION);
        UUID tenantId = platform ? null : support.requireCurrentTenant(actor);
        int limit = support.clampLimit(query.limit());
        Long beforeId = parseCursor(query.cursor());
        String actionPattern = query.action() == null ? null : query.action().replace('*', '%');
        requestContextMapper.setContext(actor.userId(), tenantId, platform);
        List<AuditLogDO> rows = auditLogMapper.selectPage(beforeId, actionPattern, limit + 1);
        boolean hasMore = rows.size() > limit;
        List<AuditLogVO> items = rows.stream().limit(limit).map(this::toView).toList();
        String next = hasMore
                ? support.encodeCursor(Long.toString(items.getLast().id())) : null;
        return new PageVO<>(items, next);
    }

    /**
     * 把游标原文解码为审计行 id。
     *
     * <p>游标形态是上一页末行 id 十进制文本的 base64url（无填充）编码，编解码复用
     * {@link AdminSupport#decodeCursor}。本方法只校验能否解成正整数，不校验该 id 是否
     * 真实存在——指向已被清理或伪造 id 的游标只会让结果集自然为空，不报错。
     *
     * @param cursor 游标原文；{@code null} 或空白表示从最新一行开始
     * @return 审计行 id（严格大于 0）；首页返回 {@code null}
     * @throws ApiException 400 当游标不是合法 base64url、解码结果不是长整型十进制文本，
     *                      或数值不大于 0
     */
    private Long parseCursor(String cursor) {
        String decoded = support.decodeCursor(cursor);
        if (decoded == null) {
            return null;
        }
        try {
            long value = Long.parseLong(decoded);
            if (value <= 0) {
                throw ApiException.badRequest("cursor 不合法");
            }
            return value;
        } catch (NumberFormatException ex) {
            throw ApiException.badRequest("cursor 不合法");
        }
    }

    /**
     * DO 到 VO 的转换：uuid 与时间转文本，detail 由 JSONB 文本还原为 JSON 树。
     *
     * <p>SQL 侧以 {@code detail::text} 取回文本（避开 jsonb 类型处理器），这里用
     * {@link ObjectMapper#readTree(String)} 还原结构后原样下发。列定义
     * {@code NOT NULL DEFAULT '{}'::jsonb} 保证入参文本恒为合法 JSON，无补充信息时
     * 落成空对象；内容遵守写入方的"不含秘密"约定（见 {@link AuditLogDO}）。
     * 时间统一换算为零偏移（UTC）后用 java.time 默认格式输出。
     *
     * @param row 审计行持久化视图（来自 {@link AuditLogMapper#selectPage}，非 {@code null}）
     * @return 对外视图 {@link AuditLogVO}；{@code tenantId} 与 {@code actorUserId} 为空时
     *         保持 {@code null}（不转成空串）
     */
    private AuditLogVO toView(AuditLogDO row) {
        return new AuditLogVO(row.id(), row.tenantId() == null ? null : row.tenantId().toString(),
                row.actorUserId() == null ? null : row.actorUserId().toString(), row.actorType(),
                row.action(), row.targetType(), row.targetId(), objectMapper.readTree(row.detailJson()),
                row.requestId(), row.createdAt().withOffsetSameInstant(ZoneOffset.UTC).toString());
    }
}
