package com.airagent.iam.admin.entity;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * iam.tenants 行的持久化视图（DO，仅 Mapper 使用，不直接对外）。
 *
 * <p>分层：由 {@link com.airagent.iam.admin.mapper.TenantMapper} 装配，服务层转成 TenantVO。
 * 映射列不含 created_by / updated_at：建档人只作为写入审计列存在，不出现在管理契约里。
 *
 * <p>场景与协作：企业是租户隔离的根，会话快照的 currentTenantId、部门与成员行的 tenant_id、
 * 请求上下文的 {@code app.tenant_id} 都指向本表主键。RLS 的读取分支允许
 * “目标企业即上下文企业”“平台上下文”“本人是该企业的活跃成员”三种情况；
 * 写入分支（WITH CHECK）只允许平台上下文，因此企业建档与状态变更都是平台线专属能力。
 *
 * <p>修订语义：{@code authRevision} 初值为 1，只在企业状态实际变化时由
 * {@code tenants_bump_auth_revision} 触发器 +1（改名不推进）。登录/切企业时该值被记入会话基线，
 * 权威核验发现当前值更大即判为租户停用或授权过期；它同时也是企业写接口的乐观并发基线。
 * 状态取值与账号、部门不同：企业只有停用（suspended），没有 disabled。
 *
 * @param id           主键，{@code gen_random_uuid()} 生成
 * @param code         企业编码，全库唯一，创建后不可修改
 * @param name         企业显示名，非空（长度由服务层校验）
 * @param status       企业状态，仅 {@code active} / {@code suspended}；停用使该企业下的活跃会话失效
 * @param authRevision 企业授权代次，初值 1；仅状态变化时 +1，会话基线与写接口修订比对都用它
 * @param createdAt    创建时间（timestamptz，数据库 now()）
 * @author Acerola
 */
public record TenantDO(UUID id, String code, String name, String status, long authRevision, OffsetDateTime createdAt) {
}
