package com.airagent.iam.auth.entity;

import java.util.UUID;

/**
 * 引导账号写入结果（DO，仅
 * {@link com.airagent.iam.auth.mapper.InfrastructureMapper#ensureUser} 使用，不对外）。
 *
 * <p>来源为 SECURITY DEFINER 函数 {@code iam_auth.ensure_bootstrap_user(account, display_name,
 * password_hash, super_admin_role_id)}（V4/V5）。幂等判定发生在数据库内且只看
 * {@code realm = 'workforce' AND account = ?} 是否已有行——不是"整库为空"判定：账号已存在时
 * 直接返回其 id 与 {@code wasCreated = false}，既不重置口令也不改动既有角色与授权。
 *
 * <p>仅新建路径会授予平台超管角色、登记 {@code iam.bootstrap_meta} 并写
 * {@code bootstrap.user.ensure} 审计（函数内部显式提升为平台上下文以满足 audit_logs 的 FORCE RLS）。
 *
 * @param userId      引导账号 id：新建时为新生成的行，已存在时为既有行
 * @param wasCreated  本次调用是否真实创建了账号；{@code false} 表示命中同名既有账号、未做任何变更
 * @author Acerola
 */
public record BootstrapUserDO(UUID userId, boolean wasCreated) {
}
