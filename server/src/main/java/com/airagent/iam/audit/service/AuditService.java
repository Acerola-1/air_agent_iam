package com.airagent.iam.audit.service;

import com.airagent.iam.audit.dto.AuditLogQueryDTO;
import com.airagent.iam.audit.vo.AuditLogVO;
import com.airagent.iam.auth.CurrentSession;
import com.airagent.iam.common.vo.PageVO;

/**
 * 审计日志查询业务接口（Service 层，只读，无写方法）。
 *
 * <p>覆盖平台与企业两套审计口径：调用方只交出已核验的会话与查询参数，
 * 由实现决定按平台还是租户口径设置 PostgreSQL 请求上下文，行可见性最终由
 * {@code iam.audit_logs} 的 RLS 策略裁决。权限码为
 * {@code platform:audit:read}（平台）或 {@code tenant:audit:read}（企业），二者具备其一即放行。
 *
 * <p>失败统一抛 {@link com.airagent.iam.web.error.ApiException}，由全局处理器映射 HTTP 状态；
 * 本接口不提供任何导出、统计或删除能力，以避免出现"读审计"之外的副作用面。
 *
 * @author Acerola
 */
public interface AuditService {

    /**
     * 分页列出 actor 可见的审计日志，按审计行 id 降序（最新在前）。
     *
     * @param actor 已通过"Redis 存活 + PG 权威快照"双检的会话；可为 {@code null}
     *              （拦截器未注入时实现按 403 拒绝，不放行）
     * @param query 查询参数（页宽、游标、动作码模式）；由 Controller 构造保证记录本身非空，
     *              其三个字段可为 {@code null}，越界值在记录构造期即已 400
     * @return 当前页 {@link PageVO}，元素为 {@link AuditLogVO}；无更多数据时
     *         {@code nextCursor} 为 {@code null}
     * @throws com.airagent.iam.web.error.ApiException 403 会话为空或两个审计权限码都不具备；
     *         400 游标无法解码或不大于 0，或仅持企业审计权限但会话未选择企业上下文
     */
    PageVO<AuditLogVO> list(CurrentSession actor, AuditLogQueryDTO query);
}
