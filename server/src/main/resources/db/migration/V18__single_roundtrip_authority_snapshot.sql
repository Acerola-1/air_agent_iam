-- 单次往返从会话自身推导可信 RLS 上下文，读取后恢复调用方事务上下文。
CREATE OR REPLACE FUNCTION iam_auth.load_trusted_authority_snapshot(p_digest text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
DECLARE
    v_session iam.auth_sessions%ROWTYPE;
    v_result jsonb;
    v_user text := current_setting('app.user_id', true);
    v_tenant text := current_setting('app.tenant_id', true);
    v_platform text := current_setting('app.is_platform', true);
BEGIN
    SELECT * INTO v_session FROM iam.auth_sessions WHERE token_digest = p_digest;
    IF NOT FOUND THEN
        RETURN jsonb_build_object('status', 'missing');
    END IF;
    PERFORM iam_auth.set_request_context(v_session.user_id, v_session.current_tenant_id,
                                        v_session.current_tenant_id IS NULL);
    v_result := iam_auth.load_authority_snapshot(p_digest);
    PERFORM set_config('app.user_id', COALESCE(v_user, ''), true);
    PERFORM set_config('app.tenant_id', COALESCE(v_tenant, ''), true);
    PERFORM set_config('app.is_platform', COALESCE(v_platform, 'off'), true);
    RETURN v_result;
END;
$$;
REVOKE ALL ON FUNCTION iam_auth.load_trusted_authority_snapshot(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam_auth.load_trusted_authority_snapshot(text) TO iam_app;
