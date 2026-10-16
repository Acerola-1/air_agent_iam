package com.airagent.iam.audit.mapper;

import com.airagent.iam.audit.entity.AuditLogDO;
import java.util.List;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/**
 * 审计日志读取数据访问（Mapper 层，SQL 见 mapper/audit/AuditLogMapper.xml）。
 *
 * <p>运行在请求角色 iam_app 下：{@code iam.audit_logs} 已 ENABLE + FORCE ROW LEVEL
 * SECURITY，唯一策略 {@code audit_tenant} 的 USING 条件是
 * {@code (tenant_id IS NOT NULL AND tenant_id = app.tenant_id) OR app.is_platform}。
 * 因此行可见性完全取决于同一事务内先写入的请求上下文
 * （{@link com.airagent.iam.common.mapper.RequestContextMapper#setContext}）：
 * 平台口径放行全部行（含 {@code tenant_id} 为 NULL 的平台级事件），
 * 租户口径只放行本企业行。上下文缺失时结果为空列表，而不是报错。
 *
 * <p>本接口只有读方法：审计写入走 SECURITY DEFINER 函数 {@code iam_auth.write_audit}
 * （见 {@link com.airagent.iam.common.mapper.AdminEventMapper#insertAudit}），
 * 应用侧不提供更新或删除审计的通路。查询语句 {@code useCache=false}，与全局
 * {@code cache-enabled=false} + 一级缓存 STATEMENT 一致，避免翻页读到缓存中的旧行。
 *
 * @author Acerola
 */
@Mapper
public interface AuditLogMapper {

    /**
     * keyset 分页：按 id 降序取 {@code beforeId} 之前的至多 {@code fetchSize} 行（最新在前）。
     *
     * <p>服务层以 {@code fetchSize = limit + 1} 多取一行来探测是否还有下一页。
     * 排序只依赖 bigint 主键 id，不按 {@code created_at} 排序，故并发写入的展示顺序
     * 以 identity 分配顺序为准；本查询的谓词与排序都不涉及时间列，表上的
     * {@code created_at DESC} 索引不会被它使用。
     *
     * @param beforeId      游标 id，仅返回 id 严格小于它的行；{@code null} 表示从最新一行开始
     * @param actionPattern SQL LIKE 模式（百分号为多字符通配、下划线为单字符通配），
     *                      大小写敏感且未做额外转义；{@code null} 表示不加动作过滤条件
     * @param fetchSize     实际取行数上限（含多取的一条探测行）；由调用方保证为正整数，
     *                      非正数会使 LIMIT 取到无意义值
     * @return 按 id 降序的审计行列表，元素为 {@link AuditLogDO}；无匹配时为空列表，
     *         不返回 {@code null}
     */
    List<AuditLogDO> selectPage(@Param("beforeId") Long beforeId,
                                @Param("actionPattern") String actionPattern,
                                @Param("fetchSize") int fetchSize);
}
