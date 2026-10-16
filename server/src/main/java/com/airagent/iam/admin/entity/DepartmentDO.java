package com.airagent.iam.admin.entity;

import java.util.UUID;

/**
 * iam.departments 行的持久化视图（DO，仅 Mapper 使用，不直接对外）。
 *
 * <p>分层：由 {@link com.airagent.iam.admin.mapper.TenantMapper} 的部门查询装配，
 * 服务层再转成 DepartmentVO 出参；映射列刻意不含 created_at / updated_at，
 * 更新时间由数据库触发器维护且不参与管理面契约。
 *
 * <p>场景与协作：企业组织树的节点，只在部门管理接口（list/create/update）中出现。
 * 行可见性受 iam.departments 的 RLS 约束，且 V15 起已收紧为
 * “仅 {@code tenant_id} 等于请求上下文的企业、或处于平台上下文”两个分支——
 * 跨企业的成员资格不再扩展部门读权限，因此非平台调用前必须把上下文切到本部门所属企业。
 *
 * <p>完整性由数据库兜底：同一企业内 code 唯一；{@code (tenant_id, parent_id)} 复合外键
 * 阻止跨租户挂父；{@code reject_department_cycle} 触发器阻止层级成环。
 * 部门表没有修订列，写接口的并发守卫使用会话上下文版本而非行版本号。
 *
 * @param id       主键，{@code gen_random_uuid()} 生成
 * @param tenantId 所属企业，NOT NULL；决定 RLS 可见范围与同租户复合外键边界
 * @param parentId 上级部门；{@code null} 表示顶级节点，非空时必须同属一个企业且不成环
 * @param code     部门编码，同企业内唯一，创建后不可修改
 * @param name     部门显示名，非空（长度由服务层校验）
 * @param status   部门状态，仅 {@code active} / {@code disabled}；停用不级联子部门或成员
 * @author Acerola
 */
public record DepartmentDO(UUID id, UUID tenantId, UUID parentId, String code, String name, String status) {
}
