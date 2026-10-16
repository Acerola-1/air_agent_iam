-- I1 第3组修复：bootstrap 引导发生在请求上下文之外，而 audit_logs 为 FORCE RLS，
-- 平台级（tenant_id IS NULL）审计行要求 app.is_platform=on。
-- 在引导事务内显式设置平台上下文（set_config local=true，不跨事务泄漏）。
-- 普通请求的审计上下文仍由服务端按已认证主体显式设置，write_audit 不自行提权（保持失败关闭）。

CREATE OR REPLACE FUNCTION iam_auth.ensure_bootstrap_user(
    p_account text, p_display_name text, p_password_hash text, p_super_admin_role_id uuid
) RETURNS TABLE(user_id uuid, was_created boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
DECLARE v_id uuid;
BEGIN
    SELECT u.id INTO v_id FROM iam.users u
     WHERE u.realm = 'workforce' AND u.account = p_account;
    IF FOUND THEN
        RETURN QUERY SELECT v_id, false;
        RETURN;
    END IF;

    INSERT INTO iam.users(account, display_name, password_hash)
    VALUES (p_account, p_display_name, p_password_hash)
    RETURNING id INTO v_id;

    INSERT INTO iam.user_roles(user_id, role_id, granted_by)
    VALUES (v_id, p_super_admin_role_id, v_id)
    ON CONFLICT DO NOTHING;

    INSERT INTO iam.bootstrap_meta(key, value)
    VALUES ('bootstrap', jsonb_build_object(
        'user_id', v_id, 'account', p_account, 'created_at', now()))
    ON CONFLICT (key) DO NOTHING;

    PERFORM iam_auth.set_request_context(v_id, NULL, true);
    PERFORM iam_auth.write_audit(NULL, v_id, 'bootstrap', 'bootstrap.user.ensure',
                                 'user', v_id::text,
                                 jsonb_build_object('account', p_account, 'created', true), NULL);
    RETURN QUERY SELECT v_id, true;
END;
$$;

GRANT EXECUTE ON FUNCTION iam_auth.ensure_bootstrap_user(text, text, text, uuid) TO iam_app;
