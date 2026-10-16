package com.airagent.iam.admin.entity;

import java.util.UUID;

/**
 * iam.roles 行的持久化视图（DO，仅 Mapper 使用，不直接对外）。
 *
 * <p>分层：由 {@link com.airagent.iam.admin.mapper.RoleMapper} 装配，服务层再补权限码列表转成
 * RoleVO。映射列不含 created_at / updated_at；角色没有修订列，授权失效依赖触发器推进引用主体
 * （关联账号的 auth_revision、关联成员的 revision）。
 *
 * <p>场景与协作：一份角色定义横跨两个授权面——{@code scope} 为 {@code platform} 的角色写入
 * iam.user_roles，由平台线接口分配；{@code scope} 为 {@code tenant} 的角色写入
 * iam.membership_roles，由企业线接口分配，两套关系互不相通，
 * 由 {@code guard_role_assignment_boundary} 触发器硬性拦截跨域分配。
 *
 * <p>可见性与可写性由 RLS 决定：读取时内置角色（{@code tenant_id} 为空）对所有上下文可见，
 * 租户自定义角色只在同企业上下文或平台上下文可见；写入时 WITH CHECK 要求
 * {@code scope='tenant'} 必须落在请求上下文的企业、{@code scope='platform'} 必须是平台上下文且
 * 企业为空——因此企业管理员无法创建或改写平台角色。
 * 唯一性由两个部分索引保证：平台角色码全局唯一，企业角色码在同企业内唯一。
 *
 * @param id          主键，{@code gen_random_uuid()} 生成
 * @param code        角色码，作用域内唯一（平台域全局唯一、企业域按企业唯一），创建后不可修改
 * @param scope       角色域，仅 {@code platform} / {@code tenant}，决定授权面与所需权限码
 * @param tenantId    归属企业；平台角色恒为 {@code null}；企业角色为 {@code null} 时是内置全局模板
 *                    （种子数据即如此），非 {@code null} 时为本租户自定义角色
 * @param name        角色显示名，非空
 * @param description 角色说明，列 NOT NULL 且默认为空串（无权限含义）
 * @param builtin     是否内置角色（映射列 is_builtin）；内置角色经管理接口一律拒绝修改
 *                    （改名、改说明、停用、改权限集合均为 403）
 * @param status      角色状态，仅 {@code active} / {@code disabled}；停用后不再参与权限快照计算
 * @author Acerola
 */
public record RoleDO(UUID id, String code, String scope, UUID tenantId, String name,
                      String description, boolean builtin, String status) {
}
