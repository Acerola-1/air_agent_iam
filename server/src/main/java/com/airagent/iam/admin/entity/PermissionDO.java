package com.airagent.iam.admin.entity;

import java.util.UUID;

/**
 * iam.permissions 行的持久化视图（DO，权限目录，仅 Mapper 使用，不直接对外）。
 *
 * <p>分层：由 {@link com.airagent.iam.admin.mapper.RoleMapper} 的目录/可授/按码三类查询装配，
 * 服务层转成 PermissionVO 或 GrantableTreeVO 的叶子节点，并用于角色授权范围判定。
 * 映射列不含 status 与 sort：目录顺序由 SQL 的 {@code ORDER BY sort, code} 决定，
 * 而权限的启用/停用状态不进入 Java 侧判断——目录查询与按码查询都不过滤 status，
 * 只有可授权限查询额外要求 {@code status = 'active'}，因此停用权限仍可能出现在权限目录里。
 *
 * <p>场景与协作：权限码是服务端裁决的唯一依据（菜单/按钮不构成授权）。
 * 该表未启用 RLS，iam_app 可全量读取，属于全局共享目录；写路径只由迁移种子负责，
 * 管理接口不修改目录本身，只修改角色与权限的关联关系。
 *
 * <p>可授边界由两列共同决定：{@code resourceCode} 非空即资源型权限，在资源开通能力落地前
 * 由触发器硬拒授予；{@code grantableToTenants} 决定该权限能否进入企业角色的权限集合，
 * 服务层先给出 409 语义，数据库 role_permissions_boundary 触发器再兜底。
 *
 * @param id                主键，种子数据使用固定合成 UUID 以保证迁移幂等
 * @param code              权限码，全库唯一，形如 {@code platform:user:read} / {@code tenant:member:write}
 * @param nameZh            中文显示名，仅供后台界面展示
 * @param scope             权限域，仅 {@code platform} / {@code tenant}
 * @param resourceCode      绑定的资源编码；{@code null} 表示普通功能权限，非空即资源型权限（当前不可授予）
 * @param grantableToTenants 是否可分配给企业角色；平台专属权限为 {@code false}
 * @author Acerola
 */
public record PermissionDO(UUID id, String code, String nameZh, String scope,
                            String resourceCode, boolean grantableToTenants) {
}
