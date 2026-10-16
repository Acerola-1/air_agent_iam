-- I1 第3组：会话修订基线、修订推进触发器、iam_auth 权威网关函数。
-- 约定：iam_app 不直接 UPDATE auth_sessions/users 的权威状态（无上下文时 RLS 拒绝），
-- 所有会话状态机变更经本文件中的 SECURITY DEFINER 函数完成；审计/outbox 与状态变更同事务。

-- ===========================================================================
-- 会话修订基线（登录/切企业时快照；权威核验时与当前值比较）
-- ===========================================================================
ALTER TABLE iam.auth_sessions
    ADD COLUMN base_user_revision       bigint NOT NULL DEFAULT 0,
    ADD COLUMN base_tenant_revision     bigint NOT NULL DEFAULT 0,
    ADD COLUMN base_membership_revision bigint NOT NULL DEFAULT 0;

-- ===========================================================================
-- 修订推进触发器
-- ===========================================================================

-- 口令哈希或账号状态变化 → 用户授权代次 +1
CREATE OR REPLACE FUNCTION iam.bump_user_auth_revision() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.password_hash IS DISTINCT FROM OLD.password_hash
       OR NEW.status IS DISTINCT FROM OLD.status THEN
        NEW.auth_revision := OLD.auth_revision + 1;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER users_bump_auth_revision BEFORE UPDATE ON iam.users
    FOR EACH ROW EXECUTE FUNCTION iam.bump_user_auth_revision();

-- 企业状态变化 → 企业授权代次 +1
CREATE OR REPLACE FUNCTION iam.bump_tenant_auth_revision() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.status IS DISTINCT FROM OLD.status THEN
        NEW.auth_revision := OLD.auth_revision + 1;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER tenants_bump_auth_revision BEFORE UPDATE ON iam.tenants
    FOR EACH ROW EXECUTE FUNCTION iam.bump_tenant_auth_revision();

-- 成员状态/部门变化 → 成员代次 +1
CREATE OR REPLACE FUNCTION iam.bump_membership_revision() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.status IS DISTINCT FROM OLD.status
       OR NEW.department_id IS DISTINCT FROM OLD.department_id THEN
        NEW.revision := OLD.revision + 1;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER memberships_bump_revision BEFORE UPDATE ON iam.tenant_memberships
    FOR EACH ROW EXECUTE FUNCTION iam.bump_membership_revision();

-- 成员角色授予/撤销 → 成员代次 +1（旧会话下一次核验即失效）
CREATE OR REPLACE FUNCTION iam.bump_membership_revision_for_roles() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE v_membership uuid;
BEGIN
    v_membership := COALESCE(NEW.membership_id, OLD.membership_id);
    UPDATE iam.tenant_memberships
       SET revision = revision + 1
     WHERE id = v_membership;
    RETURN COALESCE(NEW, OLD);
END;
$$;
CREATE TRIGGER membership_roles_bump_revision AFTER INSERT OR DELETE ON iam.membership_roles
    FOR EACH ROW EXECUTE FUNCTION iam.bump_membership_revision_for_roles();

-- ===========================================================================
-- 会话状态机函数
-- ===========================================================================

-- 建立会话（登录在同事务内调用；过期窗口由应用层按秒传入）
CREATE OR REPLACE FUNCTION iam_auth.create_session(
    p_user uuid, p_realm text, p_audience text, p_digest text,
    p_idle_seconds bigint, p_absolute_seconds bigint
) RETURNS iam.auth_sessions
LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
DECLARE v_row iam.auth_sessions%ROWTYPE; v_base bigint;
BEGIN
    SELECT auth_revision INTO v_base FROM iam.users WHERE id = p_user;
    IF NOT FOUND THEN
        RAISE EXCEPTION '用户不存在' USING ERRCODE = '28000';
    END IF;
    INSERT INTO iam.auth_sessions (
        user_id, realm, login_audience, token_digest,
        current_tenant_id, ctx_version, status,
        expires_at, idle_expires_at, absolute_expires_at, base_user_revision
    ) VALUES (
        p_user, p_realm, p_audience, p_digest,
        NULL, 1, 'active',
        now() + make_interval(secs => LEAST(p_idle_seconds, p_absolute_seconds)),
        now() + make_interval(secs => LEAST(p_idle_seconds, p_absolute_seconds)),
        now() + make_interval(secs => p_absolute_seconds),
        v_base
    ) RETURNING * INTO v_row;
    RETURN v_row;
END;
$$;

-- 撤销单个会话；返回被撤销会话的 token 摘要（供同事务登记 Redis 清理 outbox）
CREATE OR REPLACE FUNCTION iam_auth.revoke_session(p_session uuid, p_reason text)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
DECLARE v_digest text;
BEGIN
    UPDATE iam.auth_sessions
       SET status = 'revoked', revoked_at = now(), revoke_reason = p_reason
     WHERE id = p_session AND status = 'active'
    RETURNING token_digest INTO v_digest;
    RETURN v_digest;
END;
$$;

-- 撤销某用户全部（或除当前外全部）会话并推进用户授权代次；返回撤销摘要列表
CREATE OR REPLACE FUNCTION iam_auth.revoke_user_sessions(
    p_user uuid, p_keep uuid, p_reason text
) RETURNS TABLE(digest text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
BEGIN
    RETURN QUERY
    UPDATE iam.auth_sessions s
       SET status = 'revoked', revoked_at = now(), revoke_reason = p_reason
     WHERE s.user_id = p_user
       AND s.status = 'active'
       AND (p_keep IS NULL OR s.id <> p_keep)
    RETURNING s.token_digest;
    UPDATE iam.users SET auth_revision = auth_revision + 1 WHERE id = p_user;
END;
$$;

-- CAS 切企业：行锁 + expected_ctx_version 比较 + 成员/企业校验 + 快照刷新
CREATE OR REPLACE FUNCTION iam_auth.switch_session_context(
    p_session uuid, p_tenant uuid, p_expected bigint
) RETURNS iam.auth_sessions
LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
DECLARE
    v_sess iam.auth_sessions%ROWTYPE;
    v_tenant iam.tenants%ROWTYPE;
    v_mem iam.tenant_memberships%ROWTYPE;
BEGIN
    SELECT * INTO v_sess FROM iam.auth_sessions WHERE id = p_session FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION '会话不存在' USING ERRCODE = '28000';
    END IF;
    IF v_sess.status <> 'active'
       OR now() >= v_sess.absolute_expires_at
       OR now() >= v_sess.expires_at THEN
        RAISE EXCEPTION '会话已撤销或过期' USING ERRCODE = '28000';
    END IF;
    IF v_sess.ctx_version <> p_expected THEN
        RAISE EXCEPTION '上下文版本冲突 expected=% actual=%', p_expected, v_sess.ctx_version
            USING ERRCODE = 'P0010';
    END IF;
    SELECT * INTO v_tenant FROM iam.tenants WHERE id = p_tenant;
    IF NOT FOUND OR v_tenant.status <> 'active' THEN
        RAISE EXCEPTION '目标企业不存在或已停用' USING ERRCODE = 'P0012';
    END IF;
    SELECT * INTO v_mem FROM iam.tenant_memberships
     WHERE tenant_id = p_tenant AND user_id = v_sess.user_id AND status = 'active';
    IF NOT FOUND THEN
        RAISE EXCEPTION '用户不是该企业有效成员' USING ERRCODE = 'P0012';
    END IF;

    UPDATE iam.auth_sessions
       SET current_tenant_id = p_tenant,
           ctx_version = ctx_version + 1,
           base_tenant_revision = v_tenant.auth_revision,
           base_membership_revision = v_mem.revision,
           last_used_at = now()
     WHERE id = p_session
    RETURNING * INTO v_sess;
    RETURN v_sess;
END;
$$;

-- 显式空闲续期：只延空闲不越绝对上限；过期/撤销/版本不符一律拒绝（不可复活）
CREATE OR REPLACE FUNCTION iam_auth.renew_session(
    p_session uuid, p_expected bigint, p_idle_seconds bigint
) RETURNS TABLE(absolute_expires_at timestamptz, idle_expires_at timestamptz, expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
DECLARE
    v_sess iam.auth_sessions%ROWTYPE;
    v_new_idle timestamptz;
BEGIN
    SELECT * INTO v_sess FROM iam.auth_sessions WHERE id = p_session FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION '会话不存在' USING ERRCODE = '28000';
    END IF;
    IF v_sess.status <> 'active'
       OR now() >= v_sess.absolute_expires_at
       OR now() >= v_sess.expires_at THEN
        RAISE EXCEPTION '会话已撤销或过期，不能续期' USING ERRCODE = '28000';
    END IF;
    IF v_sess.ctx_version <> p_expected THEN
        RAISE EXCEPTION '上下文版本冲突 expected=% actual=%', p_expected, v_sess.ctx_version
            USING ERRCODE = 'P0010';
    END IF;
    v_new_idle := LEAST(now() + make_interval(secs => p_idle_seconds), v_sess.absolute_expires_at);
    UPDATE iam.auth_sessions
       SET idle_expires_at = v_new_idle, expires_at = v_new_idle, last_used_at = now()
     WHERE id = p_session;
    RETURN QUERY SELECT v_sess.absolute_expires_at, v_new_idle, v_new_idle;
END;
$$;

-- 修改口令：触发器推进 auth_revision；RETURNING 新代次供调用方对齐当前会话基线
CREATE OR REPLACE FUNCTION iam_auth.set_user_password(p_user uuid, p_hash text)
RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
DECLARE v_rev bigint;
BEGIN
    UPDATE iam.users SET password_hash = p_hash WHERE id = p_user RETURNING auth_revision INTO v_rev;
    IF NOT FOUND THEN
        RAISE EXCEPTION '用户不存在' USING ERRCODE = 'P0002';
    END IF;
    RETURN v_rev;
END;
$$;

-- 当前会话对齐新的用户授权代次（改密后当前会话保留，其余会话因基线变旧被拒）
CREATE OR REPLACE FUNCTION iam_auth.align_session_user_revision(p_session uuid, p_revision bigint)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
BEGIN
    UPDATE iam.auth_sessions SET base_user_revision = p_revision WHERE id = p_session;
END;
$$;

-- 权威快照：一次主库往返取得会话判定所需的全部状态（无跨请求正向授权缓存）
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
          JOIN iam.role_permissions rp ON rp.role_id = ur.role_id
          JOIN iam.permissions p ON p.id = rp.permission_id
         WHERE ur.user_id = v_sess.user_id AND p.status = 'active'
        UNION
        SELECT p.code
          FROM iam.membership_roles mr
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

GRANT EXECUTE ON FUNCTION
    iam_auth.create_session(uuid, text, text, text, bigint, bigint),
    iam_auth.revoke_session(uuid, text),
    iam_auth.revoke_user_sessions(uuid, uuid, text),
    iam_auth.switch_session_context(uuid, uuid, bigint),
    iam_auth.renew_session(uuid, bigint, bigint),
    iam_auth.set_user_password(uuid, text),
    iam_auth.align_session_user_revision(uuid, bigint),
    iam_auth.load_authority_snapshot(text)
TO iam_app;
