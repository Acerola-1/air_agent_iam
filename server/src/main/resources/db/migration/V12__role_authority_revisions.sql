-- 角色授权变化必须推进引用中的权威修订；已有迁移保持不变。
CREATE OR REPLACE FUNCTION iam.invalidate_role_authority() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
DECLARE
    v_role uuid;
    v_platform text := current_setting('app.is_platform', true);
BEGIN
    IF TG_TABLE_NAME = 'roles' THEN
        IF NEW.status IS NOT DISTINCT FROM OLD.status THEN RETURN NEW; END IF;
        v_role := NEW.id;
    ELSE
        v_role := COALESCE(NEW.role_id, OLD.role_id);
    END IF;
    -- 内置角色可跨企业关联。触发器内部提升仅用于推进关联主体修订，随后恢复请求上下文。
    PERFORM set_config('app.is_platform', 'on', true);
    UPDATE iam.users SET auth_revision = auth_revision + 1
     WHERE id IN (SELECT user_id FROM iam.user_roles WHERE role_id = v_role);
    UPDATE iam.tenant_memberships SET revision = revision + 1
     WHERE id IN (SELECT membership_id FROM iam.membership_roles WHERE role_id = v_role);
    PERFORM set_config('app.is_platform', COALESCE(v_platform, 'off'), true);
    RETURN COALESCE(NEW, OLD);
END;
$$;
CREATE TRIGGER role_permissions_invalidate_authority
    AFTER INSERT OR UPDATE OR DELETE ON iam.role_permissions
    FOR EACH ROW EXECUTE FUNCTION iam.invalidate_role_authority();
CREATE TRIGGER role_status_invalidate_authority
    AFTER UPDATE OF status ON iam.roles
    FOR EACH ROW EXECUTE FUNCTION iam.invalidate_role_authority();

CREATE OR REPLACE FUNCTION iam.bump_user_revision_for_roles() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
BEGIN
    UPDATE iam.users SET auth_revision = auth_revision + 1
     WHERE id = COALESCE(NEW.user_id, OLD.user_id);
    RETURN COALESCE(NEW, OLD);
END;
$$;
CREATE TRIGGER user_roles_bump_revision AFTER INSERT OR DELETE ON iam.user_roles
    FOR EACH ROW EXECUTE FUNCTION iam.bump_user_revision_for_roles();

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

    SELECT COALESCE(jsonb_agg(DISTINCT p.code), '[]'::jsonb)
      INTO v_perms
      FROM (
        SELECT p.code
          FROM iam.user_roles ur
          JOIN iam.roles r ON r.id = ur.role_id AND r.status = 'active'
          JOIN iam.role_permissions rp ON rp.role_id = ur.role_id
          JOIN iam.permissions p ON p.id = rp.permission_id
         WHERE ur.user_id = v_sess.user_id AND p.status = 'active'
        UNION
        SELECT p.code
          FROM iam.membership_roles mr
          JOIN iam.roles r ON r.id = mr.role_id AND r.status = 'active'
          JOIN iam.role_permissions rp ON rp.role_id = mr.role_id
          JOIN iam.permissions p ON p.id = rp.permission_id
         WHERE mr.membership_id = v_mem.id AND p.status = 'active'
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
