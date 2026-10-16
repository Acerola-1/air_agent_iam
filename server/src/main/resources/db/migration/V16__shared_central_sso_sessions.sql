-- 应用凭据绑定同一个中央权威会话；中央退出、上下文切换和续期原子传播。
ALTER TABLE iam.auth_sessions ADD COLUMN central_session_id uuid REFERENCES iam.auth_sessions(id);
CREATE INDEX idx_auth_sessions_central ON iam.auth_sessions(central_session_id)
    WHERE central_session_id IS NOT NULL;

CREATE OR REPLACE FUNCTION iam_auth.synchronize_central_session() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
BEGIN
    IF NEW.central_session_id IS NULL THEN
        UPDATE iam.auth_sessions child
           SET current_tenant_id = NEW.current_tenant_id, ctx_version = NEW.ctx_version,
               base_user_revision = NEW.base_user_revision,
               base_tenant_revision = NEW.base_tenant_revision,
               base_membership_revision = NEW.base_membership_revision,
               status = CASE WHEN NEW.status = 'revoked' THEN 'revoked' ELSE child.status END,
               revoked_at = CASE WHEN NEW.status = 'revoked' THEN NEW.revoked_at ELSE child.revoked_at END,
               revoke_reason = CASE WHEN NEW.status = 'revoked' THEN NEW.revoke_reason ELSE child.revoke_reason END,
               expires_at = LEAST(child.absolute_expires_at, NEW.expires_at),
               idle_expires_at = LEAST(child.absolute_expires_at, NEW.idle_expires_at)
         WHERE child.central_session_id = NEW.id;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER auth_sessions_synchronize_central AFTER UPDATE ON iam.auth_sessions
    FOR EACH ROW EXECUTE FUNCTION iam_auth.synchronize_central_session();

CREATE OR REPLACE FUNCTION iam_auth.mint_sso_session(
    p_source   uuid,
    p_audience text,
    p_digest   text,
    p_idle_seconds     bigint,
    p_absolute_seconds bigint
) RETURNS iam.auth_sessions
LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
DECLARE
    v_src iam.auth_sessions%ROWTYPE;
    v_row iam.auth_sessions%ROWTYPE;
BEGIN
    IF p_audience NOT IN ('air-agent','knowledge','iam-admin') THEN
        RAISE EXCEPTION 'SSO 会话受众不合法 %', p_audience USING ERRCODE = '23514';
    END IF;
    SELECT * INTO v_src FROM iam.auth_sessions
     WHERE id = (SELECT COALESCE(central_session_id, id) FROM iam.auth_sessions WHERE id = p_source)
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION '源会话不存在' USING ERRCODE = '28000';
    END IF;
    IF v_src.status <> 'active'
       OR now() >= v_src.absolute_expires_at
       OR now() >= v_src.expires_at THEN
        RAISE EXCEPTION '源会话已撤销或过期' USING ERRCODE = '28000';
    END IF;

    INSERT INTO iam.auth_sessions (
        central_session_id, user_id, realm, login_audience, token_digest,
        current_tenant_id, ctx_version, status,
        expires_at, idle_expires_at, absolute_expires_at,
        base_user_revision, base_tenant_revision, base_membership_revision
    ) VALUES (
        v_src.id, v_src.user_id, v_src.realm, p_audience, p_digest,
        v_src.current_tenant_id, v_src.ctx_version, 'active',
        LEAST(v_src.expires_at, now() + make_interval(secs => LEAST(p_idle_seconds, p_absolute_seconds))),
        LEAST(v_src.expires_at, now() + make_interval(secs => LEAST(p_idle_seconds, p_absolute_seconds))),
        LEAST(v_src.absolute_expires_at, now() + make_interval(secs => p_absolute_seconds)),
        v_src.base_user_revision, v_src.base_tenant_revision, v_src.base_membership_revision
    ) RETURNING * INTO v_row;
    RETURN v_row;
END;
$$;

CREATE OR REPLACE FUNCTION iam_auth.switch_session_context(
    p_session uuid, p_tenant uuid, p_expected bigint
) RETURNS iam.auth_sessions
LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
DECLARE
    v_sess iam.auth_sessions%ROWTYPE;
    v_tenant iam.tenants%ROWTYPE;
    v_mem iam.tenant_memberships%ROWTYPE;
BEGIN
    SELECT * INTO v_sess FROM iam.auth_sessions
     WHERE id = (SELECT COALESCE(central_session_id, id) FROM iam.auth_sessions WHERE id = p_session)
     FOR UPDATE;
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
     WHERE id = v_sess.id
    RETURNING * INTO v_sess;
    RETURN v_sess;
END;
$$;

CREATE OR REPLACE FUNCTION iam_auth.renew_session(
    p_session uuid, p_expected bigint, p_idle_seconds bigint
) RETURNS TABLE(absolute_expires_at timestamptz, idle_expires_at timestamptz, expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
DECLARE
    v_sess iam.auth_sessions%ROWTYPE;
    v_new_idle timestamptz;
BEGIN
    SELECT * INTO v_sess FROM iam.auth_sessions
     WHERE id = (SELECT COALESCE(central_session_id, id) FROM iam.auth_sessions WHERE id = p_session)
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION '会话不存在' USING ERRCODE = '28000';
    END IF;
    IF v_sess.status <> 'active'
       OR clock_timestamp() >= v_sess.absolute_expires_at
       OR clock_timestamp() >= v_sess.expires_at THEN
        RAISE EXCEPTION '会话已撤销或过期，不能续期' USING ERRCODE = '28000';
    END IF;
    IF v_sess.ctx_version <> p_expected THEN
        RAISE EXCEPTION '上下文版本冲突 expected=% actual=%', p_expected, v_sess.ctx_version
            USING ERRCODE = 'P0010';
    END IF;
    v_new_idle := LEAST(GREATEST(v_sess.idle_expires_at,
                              clock_timestamp() + make_interval(secs => p_idle_seconds)),
                        v_sess.absolute_expires_at);
    UPDATE iam.auth_sessions
       SET idle_expires_at = v_new_idle, expires_at = v_new_idle, last_used_at = clock_timestamp()
     WHERE id = v_sess.id;
    RETURN QUERY SELECT v_sess.absolute_expires_at, v_new_idle, v_new_idle;
END;
$$;
