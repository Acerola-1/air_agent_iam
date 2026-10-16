package com.airagent.iam.admin.entity;

import java.util.UUID;

/**
 * iam.tenant_memberships 行的持久化视图（DO，仅 Mapper 使用，不直接对外）。
 *
 * <p>分层：由 {@link com.airagent.iam.admin.mapper.TenantMapper} 的成员查询装配，服务层再结合
 * {@code iam_auth.member_user_brief} 与角色码转成 MemberVO。映射列不含 created_by / created_at /
 * updated_at，账号侧信息（realm、account 等）不在此行内，需另经关联查询取得。
 *
 * <p>场景与协作：一个账号与一个企业之间的成员关系，是租户内授权（iam.membership_roles）
 * 与部门挂靠的锚点。RLS 允许“本企业上下文”“本人是成员”“平台上下文”三个分支，
 * 因此本人可在未选企业时看到自己的成员资格行。
 * 同一企业内一个账号至多一条关系（唯一键约束）；{@code (tenant_id, department_id)} 复合外键
 * 禁止跨租户挂靠部门。
 *
 * <p>关联查询的空结果语义：成员视图依赖的两条关联查询在无数据时都返回空列表而非 null——
 * 角色码查询为空表示该成员暂无角色；账号摘要查询走 SECURITY DEFINER 函数，
 * 仅用于越过 iam.users 的行可见性（停用账号在纯企业上下文下不可见），
 * 函数不返回口令摘要列，账号行缺失时服务层按 404 处理。
 *
 * @param id           主键，{@code gen_random_uuid()} 生成
 * @param tenantId     所属企业，NOT NULL；企业域写操作恒以会话当前企业限定
 * @param userId       关联账号，NOT NULL；与 tenantId 组合唯一
 * @param departmentId 挂靠部门；{@code null} 表示不属于任何部门
 * @param status       成员状态，仅 {@code active} / {@code disabled}；停用使该账号在本企业的会话失效
 * @param revision     成员修订号，建档即为 1；状态或部门实际变化、角色增删、以及所关联角色的
 *                     权限或状态变化都由触发器 +1，会话以此校验租户内授权是否过期
 * @author Acerola
 */
public record MembershipDO(UUID id, UUID tenantId, UUID userId, UUID departmentId, String status, long revision) {
}
