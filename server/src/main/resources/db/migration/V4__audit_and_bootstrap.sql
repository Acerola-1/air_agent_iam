-- I1 第3组：审计同事务写入网关 + 显式 bootstrap 用户幂等引导。

CREATE OR REPLACE FUNCTION iam_auth.write_audit(
    p_tenant uuid, p_actor uuid, p_actor_type text,
    p_action text, p_target_type text, p_target_id text,
    p_detail jsonb, p_request_id text
) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
DECLARE v_id bigint;
BEGIN
    INSERT INTO iam.audit_logs(
        tenant_id, actor_user_id, actor_type, action, target_type, target_id, detail, request_id
    ) VALUES (
        p_tenant, p_actor, p_actor_type, p_action, p_target_type,
        p_target_id, COALESCE(p_detail, '{}'::jsonb), p_request_id
    ) RETURNING id INTO v_id;
    RETURN v_id;
END;
$$;

-- 仅空库/账号不存在时创建 bootstrap 超级管理员；重复执行不重置口令、不改既有授权。
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

    PERFORM iam_auth.write_audit(NULL, v_id, 'bootstrap', 'bootstrap.user.ensure',
                                 'user', v_id::text,
                                 jsonb_build_object('account', p_account, 'created', true), NULL);
    RETURN QUERY SELECT v_id, true;
END;
$$;

GRANT EXECUTE ON FUNCTION
    iam_auth.write_audit(uuid, uuid, text, text, text, text, jsonb, text),
    iam_auth.ensure_bootstrap_user(text, text, text, uuid)
TO iam_app;
