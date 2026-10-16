-- I1a 企业资源开通：约束、种子、触发器改造、有效权限求交与修订推进。
-- 已执行迁移不改，本文件从实际 head（V19）之后追加。

-- ===========================================================================
-- 1. tenant:resource:grant 种子（企业资源授权管理资格）
-- ===========================================================================

INSERT INTO iam.permissions (id, code, name_zh, scope, grantable_to_tenants, resource_code, sort) VALUES
  ('01930000-0000-4000-8000-000000000211','tenant:resource:grant','企业资源授权管理','tenant',true,NULL,211)
ON CONFLICT (id) DO NOTHING;

INSERT INTO iam.role_permissions (role_id, permission_id)
SELECT r.id, p.id
  FROM iam.roles r JOIN iam.permissions p ON p.code = 'tenant:resource:grant'
 WHERE r.code = 'tenant_admin' AND r.scope = 'tenant' AND r.tenant_id IS NULL
ON CONFLICT DO NOTHING;

-- ===========================================================================
-- 2. 资源 code / 权限绑定约束
-- ===========================================================================

-- 资源 code 形如 knowledge:lib:air：冒号分段小写 ASCII，每段 [a-z][a-z0-9_-]*，至少两段
ALTER TABLE iam.resource_catalog
    ADD CONSTRAINT resource_catalog_code_format CHECK (
        code ~ '^[a-z][a-z0-9_-]*(:[a-z][a-z0-9_-]*)+$'
    );

-- 权限 code 必须以所属资源 code 为前缀（resource_code 非空时）
ALTER TABLE iam.permissions
    ADD CONSTRAINT permissions_resource_prefix CHECK (
        resource_code IS NULL OR code LIKE resource_code || ':%'
    );

-- 权限与资源关联外键（resource_code 可空）
ALTER TABLE iam.permissions
    ADD CONSTRAINT permissions_resource_fk
    FOREIGN KEY (resource_code) REFERENCES iam.resource_catalog(code);

-- 索引：有效权限求交 join 路径
CREATE INDEX IF NOT EXISTS idx_permissions_resource_code ON iam.permissions(resource_code) WHERE resource_code IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_tenant_entitlements_status ON iam.tenant_entitlements(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_resource_catalog_status ON iam.resource_catalog(status);

-- ===========================================================================
-- 3. 授权边界触发器改造：按目标企业、目录、开通、可下放性检查
-- ===========================================================================

CREATE OR REPLACE FUNCTION iam.guard_role_assignment_boundary() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    v_scope text; v_grantable boolean; v_resource text; v_tenant uuid;
    v_perm_status text; v_resource_status text; v_entitled boolean;
    v_role_tenant uuid;
BEGIN
    IF TG_TABLE_NAME = 'user_roles' THEN
        SELECT scope INTO v_scope FROM iam.roles WHERE id = NEW.role_id;
        IF v_scope IS DISTINCT FROM 'platform' THEN
            RAISE EXCEPTION '仅平台角色可分配到用户' USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;

    IF TG_TABLE_NAME = 'membership_roles' THEN
        SELECT scope, tenant_id INTO v_scope, v_tenant FROM iam.roles WHERE id = NEW.role_id;
        IF v_scope IS DISTINCT FROM 'tenant' THEN
            RAISE EXCEPTION '企业成员仅可分配企业角色' USING ERRCODE = 'check_violation';
        END IF;
        IF v_tenant IS NOT NULL AND v_tenant IS DISTINCT FROM NEW.tenant_id THEN
            RAISE EXCEPTION '企业角色不属于该企业' USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;

    -- role_permissions
    SELECT r.scope, r.tenant_id, p.grantable_to_tenants, p.resource_code, p.status
      INTO v_scope, v_role_tenant, v_grantable, v_resource, v_perm_status
      FROM iam.roles r JOIN iam.permissions p ON p.id = NEW.permission_id
     WHERE r.id = NEW.role_id;

    IF v_scope = 'tenant' AND NOT v_grantable THEN
        RAISE EXCEPTION '企业角色不可分配平台专属权限' USING ERRCODE = 'check_violation';
    END IF;

    IF v_resource IS NOT NULL THEN
        -- 资源码仅允许写入明确 tenant_id 的企业独有角色
        IF v_scope IS DISTINCT FROM 'tenant' OR v_role_tenant IS NULL THEN
            RAISE EXCEPTION '资源型权限仅可授予企业独有角色' USING ERRCODE = 'check_violation';
        END IF;
        IF NOT v_grantable THEN
            RAISE EXCEPTION '资源型权限必须可下放企业' USING ERRCODE = 'check_violation';
        END IF;
        IF v_perm_status IS DISTINCT FROM 'active' THEN
            RAISE EXCEPTION '权限已停用' USING ERRCODE = 'check_violation';
        END IF;
        SELECT status INTO v_resource_status FROM iam.resource_catalog WHERE code = v_resource;
        IF NOT FOUND OR v_resource_status IS DISTINCT FROM 'active' THEN
            RAISE EXCEPTION '资源不存在或已停用' USING ERRCODE = 'check_violation';
        END IF;
        SELECT EXISTS (
            SELECT 1 FROM iam.tenant_entitlements
             WHERE tenant_id = v_role_tenant AND resource_code = v_resource AND status = 'active'
        ) INTO v_entitled;
        IF NOT v_entitled THEN
            RAISE EXCEPTION '企业未开通该资源' USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION iam.guard_service_permission_boundary() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    v_resource text; v_grantable boolean; v_perm_status text;
    v_resource_status text; v_entitled boolean; v_sa_tenant uuid;
BEGIN
    SELECT p.resource_code, p.grantable_to_tenants, p.status
      INTO v_resource, v_grantable, v_perm_status
      FROM iam.permissions p WHERE p.id = NEW.permission_id;

    IF v_resource IS NULL THEN
        RETURN NEW;
    END IF;

    -- 资源码仅允许绑定明确 tenant 的服务账号
    SELECT tenant_id INTO v_sa_tenant FROM iam.service_accounts WHERE id = NEW.service_account_id;
    IF v_sa_tenant IS NULL THEN
        RAISE EXCEPTION '资源型权限服务账号必须绑定企业' USING ERRCODE = 'check_violation';
    END IF;
    IF NOT v_grantable THEN
        RAISE EXCEPTION '资源型权限必须可下放企业' USING ERRCODE = 'check_violation';
    END IF;
    IF v_perm_status IS DISTINCT FROM 'active' THEN
        RAISE EXCEPTION '权限已停用' USING ERRCODE = 'check_violation';
    END IF;
    SELECT status INTO v_resource_status FROM iam.resource_catalog WHERE code = v_resource;
    IF NOT FOUND OR v_resource_status IS DISTINCT FROM 'active' THEN
        RAISE EXCEPTION '资源不存在或已停用' USING ERRCODE = 'check_violation';
    END IF;
    SELECT EXISTS (
        SELECT 1 FROM iam.tenant_entitlements
         WHERE tenant_id = v_sa_tenant AND resource_code = v_resource AND status = 'active'
    ) INTO v_entitled;
    IF NOT v_entitled THEN
        RAISE EXCEPTION '企业未开通该资源' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

-- ===========================================================================
-- 4. 修订推进：开通/回收、目录停用/恢复
-- ===========================================================================

CREATE OR REPLACE FUNCTION iam.bump_tenant_revision_on_entitlement() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
DECLARE
    v_platform text := current_setting('app.is_platform', true);
BEGIN
    PERFORM set_config('app.is_platform', 'on', true);
    IF TG_OP = 'INSERT' THEN
        IF NEW.status = 'active' THEN
            UPDATE iam.tenants SET auth_revision = auth_revision + 1 WHERE id = NEW.tenant_id;
        END IF;
    ELSIF TG_OP = 'UPDATE' THEN
        IF NEW.status IS DISTINCT FROM OLD.status THEN
            UPDATE iam.tenants SET auth_revision = auth_revision + 1 WHERE id = NEW.tenant_id;
        END IF;
    END IF;
    PERFORM set_config('app.is_platform', COALESCE(v_platform, 'off'), true);
    RETURN COALESCE(NEW, OLD);
END;
$$;
DROP TRIGGER IF EXISTS entitlements_bump_revision ON iam.tenant_entitlements;
CREATE TRIGGER entitlements_bump_revision
    AFTER INSERT OR UPDATE OF status ON iam.tenant_entitlements
    FOR EACH ROW EXECUTE FUNCTION iam.bump_tenant_revision_on_entitlement();

CREATE OR REPLACE FUNCTION iam.bump_tenants_on_resource_status() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
DECLARE
    v_platform text := current_setting('app.is_platform', true);
BEGIN
    IF NEW.status IS NOT DISTINCT FROM OLD.status THEN
        RETURN NEW;
    END IF;
    PERFORM set_config('app.is_platform', 'on', true);
    -- 目录安全状态改变推进所有受影响（active 开通）企业的修订
    UPDATE iam.tenants t SET auth_revision = auth_revision + 1
     WHERE t.id IN (
        SELECT te.tenant_id FROM iam.tenant_entitlements te
         WHERE te.resource_code = NEW.code AND te.status = 'active'
     );
    PERFORM set_config('app.is_platform', COALESCE(v_platform, 'off'), true);
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS resource_catalog_bump_tenants ON iam.resource_catalog;
CREATE TRIGGER resource_catalog_bump_tenants
    AFTER UPDATE OF status ON iam.resource_catalog
    FOR EACH ROW EXECUTE FUNCTION iam.bump_tenants_on_resource_status();

-- ===========================================================================
-- 5. 有效权限求交：load_authority_snapshot / load_service_identity
-- ===========================================================================

-- 人类权威快照：资源权限须同时满足 目录启用 + 企业 active 开通
CREATE OR REPLACE FUNCTION iam_auth.load_authority_snapshot(p_digest text)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
DECLARE
    v_sess iam.auth_sessions%ROWTYPE;
    v_user iam.users%ROWTYPE;
    v_tenant iam.tenants%ROWTYPE;
    v_mem iam.tenant_memberships%ROWTYPE;
    v_status text := 'ok';
    v_proles jsonb; v_troles jsonb; v_perms jsonb;
    v_any_mem boolean;
BEGIN
    SELECT * INTO v_sess FROM iam.auth_sessions WHERE token_digest = p_digest;
    IF NOT FOUND THEN
        RETURN jsonb_build_object('status', 'missing');
    END IF;
    IF v_sess.status <> 'active' THEN
        v_status := 'invalid_or_revoked';
    END IF;
    SELECT * INTO v_user FROM iam.users WHERE id = v_sess.user_id;
    IF NOT FOUND OR v_user.status <> 'active' THEN
        v_status := 'account_disabled';
    ELSIF v_user.auth_revision > v_sess.base_user_revision THEN
        v_status := 'invalid_or_revoked';
    END IF;
    IF now() >= v_sess.absolute_expires_at OR now() >= v_sess.expires_at THEN
        v_status := 'invalid_or_revoked';
    END IF;

    IF v_sess.current_tenant_id IS NOT NULL THEN
        SELECT * INTO v_tenant FROM iam.tenants WHERE id = v_sess.current_tenant_id;
        SELECT * INTO v_mem FROM iam.tenant_memberships
         WHERE tenant_id = v_sess.current_tenant_id AND user_id = v_sess.user_id;
        IF NOT FOUND OR v_mem.status <> 'active' THEN
            IF v_status = 'ok' THEN v_status := 'membership_disabled'; END IF;
        ELSIF v_mem.revision > v_sess.base_membership_revision THEN
            v_status := 'invalid_or_revoked';
        END IF;
        IF NOT FOUND OR v_tenant.status IS DISTINCT FROM 'active' THEN
            IF v_status = 'ok' THEN v_status := 'tenant_suspended'; END IF;
        ELSIF v_tenant.auth_revision > v_sess.base_tenant_revision THEN
            v_status := 'invalid_or_revoked';
        END IF;
    END IF;

    SELECT EXISTS (
        SELECT 1 FROM iam.tenant_memberships m JOIN iam.tenants t ON t.id = m.tenant_id
         WHERE m.user_id = v_sess.user_id AND m.status = 'active' AND t.status = 'active'
    ) INTO v_any_mem;

    SELECT COALESCE(jsonb_agg(jsonb_build_object('code', r.code, 'name', r.name)), '[]'::jsonb)
      INTO v_proles
      FROM iam.user_roles ur JOIN iam.roles r ON r.id = ur.role_id
     WHERE ur.user_id = v_sess.user_id AND r.scope = 'platform' AND r.status = 'active';

    IF v_mem.id IS NOT NULL AND v_mem.status = 'active' THEN
        SELECT COALESCE(jsonb_agg(jsonb_build_object('code', r.code, 'name', r.name)), '[]'::jsonb)
          INTO v_troles
          FROM iam.membership_roles mr JOIN iam.roles r ON r.id = mr.role_id
         WHERE mr.membership_id = v_mem.id AND r.scope = 'tenant' AND r.status = 'active';
    ELSE
        v_troles := '[]'::jsonb;
    END IF;

    -- 权限并集，资源权限须 求交（主体有效 + 明确授予 + 权限启用 + 目录启用 + 企业 active 开通）
    SELECT COALESCE(jsonb_agg(DISTINCT p.code), '[]'::jsonb)
      INTO v_perms
      FROM (
        SELECT p.code
          FROM iam.user_roles ur
          JOIN iam.roles r ON r.id = ur.role_id AND r.status = 'active'
          JOIN iam.role_permissions rp ON rp.role_id = ur.role_id
          JOIN iam.permissions p ON p.id = rp.permission_id
         WHERE ur.user_id = v_sess.user_id AND p.status = 'active'
           AND (p.resource_code IS NULL
                OR (v_sess.current_tenant_id IS NOT NULL
                    AND EXISTS (
                        SELECT 1 FROM iam.tenant_entitlements te
                          JOIN iam.resource_catalog rc ON rc.code = te.resource_code
                         WHERE te.tenant_id = v_sess.current_tenant_id
                           AND te.resource_code = p.resource_code
                           AND te.status = 'active'
                           AND rc.status = 'active')))
        UNION
        SELECT p.code
          FROM iam.membership_roles mr
          JOIN iam.roles r ON r.id = mr.role_id AND r.status = 'active'
          JOIN iam.role_permissions rp ON rp.role_id = mr.role_id
          JOIN iam.permissions p ON p.id = rp.permission_id
         WHERE mr.membership_id = v_mem.id AND p.status = 'active'
           AND (p.resource_code IS NULL
                OR (v_sess.current_tenant_id IS NOT NULL
                    AND EXISTS (
                        SELECT 1 FROM iam.tenant_entitlements te
                          JOIN iam.resource_catalog rc ON rc.code = te.resource_code
                         WHERE te.tenant_id = v_sess.current_tenant_id
                           AND te.resource_code = p.resource_code
                           AND te.status = 'active'
                           AND rc.status = 'active')))
      ) p;

    RETURN jsonb_build_object(
        'status', v_status,
        'session', to_jsonb(v_sess),
        'user', to_jsonb(v_user),
        'tenant', CASE WHEN v_tenant.id IS NULL THEN NULL ELSE to_jsonb(v_tenant) END,
        'membership', CASE WHEN v_mem.id IS NULL THEN NULL ELSE to_jsonb(v_mem) END,
        'platform_roles', v_proles,
        'tenant_roles', v_troles,
        'permissions', v_perms,
        'has_any_membership', COALESCE(v_any_mem, false),
        'revisions', jsonb_build_object(
            'user_auth_revision', v_user.auth_revision,
            'tenant_auth_revision', COALESCE(v_tenant.auth_revision, 0),
            'membership_revision', COALESCE(v_mem.revision, 0),
            'session_ctx_version', v_sess.ctx_version
        )
    );
END;
$$;

-- 机器身份：资源权限同样求交，不再一律排除 resource_code
CREATE OR REPLACE FUNCTION iam_auth.load_service_identity(p_digest text)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
DECLARE
    v_tok iam.service_tokens%ROWTYPE;
    v_sa iam.service_accounts%ROWTYPE;
    v_tenant iam.tenants%ROWTYPE;
    v_perms jsonb;
    v_status text := 'ok';
BEGIN
    PERFORM iam_auth.set_request_context(NULL, NULL, true);

    SELECT * INTO v_tok FROM iam.service_tokens WHERE token_digest = p_digest;
    IF NOT FOUND OR v_tok.status <> 'active' OR now() >= v_tok.expires_at
       OR (v_tok.overlap_until IS NOT NULL AND clock_timestamp() >= v_tok.overlap_until) THEN
        RETURN jsonb_build_object('status', 'invalid_or_revoked');
    END IF;

    SELECT * INTO v_sa FROM iam.service_accounts WHERE id = v_tok.service_account_id;
    IF NOT FOUND OR v_sa.status <> 'active' OR now() >= v_sa.expires_at THEN
        v_status := 'account_disabled';
    END IF;

    SELECT * INTO v_tenant FROM iam.tenants WHERE id = v_sa.tenant_id;
    IF NOT FOUND OR v_tenant.status IS DISTINCT FROM 'active' THEN
        IF v_status = 'ok' THEN v_status := 'tenant_suspended'; END IF;
    END IF;

    SELECT COALESCE(jsonb_agg(DISTINCT p.code), '[]'::jsonb)
      INTO v_perms
      FROM iam.service_account_permissions sap
      JOIN iam.permissions p ON p.id = sap.permission_id
     WHERE sap.service_account_id = v_sa.id
       AND p.status = 'active'
       AND (p.resource_code IS NULL
            OR (v_sa.tenant_id IS NOT NULL
                AND EXISTS (
                    SELECT 1 FROM iam.tenant_entitlements te
                      JOIN iam.resource_catalog rc ON rc.code = te.resource_code
                     WHERE te.tenant_id = v_sa.tenant_id
                       AND te.resource_code = p.resource_code
                       AND te.status = 'active'
                       AND rc.status = 'active')));

    RETURN jsonb_build_object(
        'status', v_status,
        'service_account', CASE WHEN v_sa.id IS NULL THEN NULL ELSE to_jsonb(v_sa) END,
        'tenant', CASE WHEN v_tenant.id IS NULL THEN NULL ELSE to_jsonb(v_tenant) END,
        'credential', jsonb_build_object(
            'id', v_tok.credential_id,
            'revision', v_tok.credential_revision,
            'expires_at', v_tok.expires_at,
            'overlap_until', v_tok.overlap_until
        ),
        'permissions', v_perms
    );
END;
$$;

-- ===========================================================================
-- 6. 资源目录 RLS：平台写、授权用户读
-- ===========================================================================

ALTER TABLE iam.resource_catalog ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS resource_catalog_read ON iam.resource_catalog;
CREATE POLICY resource_catalog_read ON iam.resource_catalog
    FOR SELECT USING (iam.ctx_uuid('app.user_id') IS NOT NULL OR iam.ctx_platform());
DROP POLICY IF EXISTS resource_catalog_write ON iam.resource_catalog;
CREATE POLICY resource_catalog_write ON iam.resource_catalog
    FOR ALL WITH CHECK (iam.ctx_platform());

-- tenant_entitlements：企业仅读自身，写仅平台（覆盖原策略以明确不能自开通）
DROP POLICY IF EXISTS entitlements_tenant ON iam.tenant_entitlements;
CREATE POLICY entitlements_tenant ON iam.tenant_entitlements
    USING (tenant_id = iam.ctx_uuid('app.tenant_id') OR iam.ctx_platform())
    WITH CHECK (iam.ctx_platform());

-- ===========================================================================
-- 7. 统一锁序辅助函数：资源行（code 排序）→ 企业行（UUID 排序）
-- ===========================================================================

CREATE OR REPLACE FUNCTION iam.lock_resources_and_tenants(p_resource_codes text[], p_tenant_ids uuid[])
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
BEGIN
    PERFORM 1 FROM iam.resource_catalog WHERE code = ANY(p_resource_codes) ORDER BY code FOR UPDATE;
    PERFORM 1 FROM iam.tenants WHERE id = ANY(p_tenant_ids) ORDER BY id FOR UPDATE;
END;
$$;
REVOKE ALL ON FUNCTION iam.lock_resources_and_tenants(text[], uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.lock_resources_and_tenants(text[], uuid[]) TO iam_app;
