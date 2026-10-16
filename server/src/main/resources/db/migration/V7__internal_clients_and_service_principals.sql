-- I1 第4组：内部客户端认证、verification_ref 执行复查登记、服务账号令牌与机器身份。
-- 约定：内部客户端密钥与服务令牌只存 sha256 摘要；所有核验每次读主库，无正向授权 TTL 缓存。
-- 服务账号/权限/企业为 FORCE RLS，机器函数内部显式置平台上下文后再读，函数外 iam_app 仍不可直读。

-- ===========================================================================
-- 服务令牌凭据修订（轮换即 +1；契约 C15 机器身份字段）
-- ===========================================================================
ALTER TABLE iam.service_tokens
    ADD COLUMN credential_revision bigint NOT NULL DEFAULT 1;

-- 轮换重叠窗口硬约束：overlap_until 不得超过签发后 24 小时，且不得晚于本令牌到期
ALTER TABLE iam.service_tokens
    ADD CONSTRAINT service_tokens_overlap_window_ck
    CHECK (overlap_until IS NULL
           OR (overlap_until <= issued_at + interval '24 hours'
               AND overlap_until <= expires_at));

-- service_accounts 无 updated_at 列，V1 的通用触发器循环误挂（同 V6 对 auth_sessions 的修复）
DROP TRIGGER IF EXISTS service_accounts_touch ON iam.service_accounts;

-- ===========================================================================
-- 内部客户端认证
-- ===========================================================================

-- 每次主库核验客户端身份；client_id/secret_digest 任一不符或非 active 一律 28000（不区分不存在与错密钥）
CREATE OR REPLACE FUNCTION iam_auth.authenticate_internal_client(
    p_client_id text, p_secret_digest text
) RETURNS iam.internal_clients
LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
DECLARE v_row iam.internal_clients%ROWTYPE;
BEGIN
    SELECT * INTO v_row FROM iam.internal_clients WHERE client_id = p_client_id;
    IF NOT FOUND
       OR v_row.secret_digest IS DISTINCT FROM p_secret_digest
       OR v_row.status <> 'active' THEN
        RAISE EXCEPTION '内部客户端凭据无效或已停用' USING ERRCODE = '28000';
    END IF;
    RETURN v_row;
END;
$$;

-- 启动幂等预置/轮换内部客户端密钥（仅平台引导路径可写无 policy 表）
CREATE OR REPLACE FUNCTION iam_auth.ensure_internal_client(
    p_client_id text, p_name text, p_secret_digest text,
    p_scopes text[], p_audiences text[]
) RETURNS TABLE(was_created boolean, revision bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
DECLARE v_exists boolean;
BEGIN
    SELECT EXISTS (SELECT 1 FROM iam.internal_clients WHERE client_id = p_client_id)
      INTO v_exists;
    INSERT INTO iam.internal_clients(client_id, name, secret_digest, scopes, audiences)
    VALUES (p_client_id, p_name, p_secret_digest, p_scopes, p_audiences)
    ON CONFLICT (client_id) DO UPDATE
       SET secret_digest = EXCLUDED.secret_digest,
           scopes = EXCLUDED.scopes,
           audiences = EXCLUDED.audiences,
           name = EXCLUDED.name,
           revision = iam.internal_clients.revision + 1,
           status = 'active',
           revoked_at = NULL;
    SELECT iam.internal_clients.revision INTO revision
      FROM iam.internal_clients WHERE client_id = p_client_id;
    RETURN QUERY SELECT NOT v_exists, revision;
END;
$$;

-- ===========================================================================
-- verification_ref：长运行执行复查引用（非授权票据）
-- ===========================================================================

-- 首次核验产生引用；valid_until 由 TTL 与原会话绝对上界取小，TTL 不可延长身份
CREATE OR REPLACE FUNCTION iam_auth.create_verification_ref(
    p_client text, p_audience text, p_session uuid, p_user uuid, p_tenant uuid,
    p_revisions jsonb, p_ttl_seconds bigint
) RETURNS TABLE(id uuid, valid_until timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
DECLARE
    v_sess iam.auth_sessions%ROWTYPE;
    v_valid timestamptz;
    v_id uuid;
BEGIN
    SELECT * INTO v_sess FROM iam.auth_sessions WHERE auth_sessions.id = p_session;
    IF NOT FOUND OR v_sess.status <> 'active' THEN
        RAISE EXCEPTION '会话不存在或已撤销' USING ERRCODE = '28000';
    END IF;
    v_valid := LEAST(now() + make_interval(secs => p_ttl_seconds),
                     v_sess.absolute_expires_at);
    INSERT INTO iam.verification_refs(
        client_id, audience, session_id, user_id, tenant_id, revisions, valid_until
    ) VALUES (p_client, p_audience, p_session, p_user, p_tenant, p_revisions, v_valid)
    RETURNING verification_refs.id INTO v_id;
    RETURN QUERY SELECT v_id, v_valid;
END;
$$;

-- 引用必须同时匹配客户端与受众，且自身未过期；主体实时性由调用方在快照中复查
CREATE OR REPLACE FUNCTION iam_auth.find_verification_ref(
    p_id uuid, p_client text, p_audience text
) RETURNS SETOF iam.verification_refs
LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
BEGIN
    RETURN QUERY
    SELECT r.* FROM iam.verification_refs r
     WHERE r.id = p_id
       AND r.client_id = p_client
       AND r.audience = p_audience
       AND r.valid_until > now();
END;
$$;

CREATE OR REPLACE FUNCTION iam_auth.touch_verification_ref(p_id uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
BEGIN
    UPDATE iam.verification_refs SET last_checked_at = now() WHERE id = p_id;
END;
$$;

-- ===========================================================================
-- 服务账号令牌
-- ===========================================================================

-- 签发新令牌。强制：服务账号/企业 active；到期不晚于服务账号到期与 now()+365d（硬顶）；
-- 重叠窗口不超过 24h；原始秘密只以摘要入库。
CREATE OR REPLACE FUNCTION iam_auth.issue_service_token(
    p_service_account uuid, p_credential_id text, p_token_digest text,
    p_expires_at timestamptz, p_overlap_until timestamptz
) RETURNS iam.service_tokens
LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
DECLARE
    v_sa iam.service_accounts%ROWTYPE;
    v_tenant iam.tenants%ROWTYPE;
    v_row iam.service_tokens%ROWTYPE;
    v_rev bigint;
BEGIN
    PERFORM iam_auth.set_request_context(NULL, NULL, true);

    SELECT * INTO v_sa FROM iam.service_accounts WHERE id = p_service_account;
    IF NOT FOUND THEN
        RAISE EXCEPTION '服务账号不存在' USING ERRCODE = '28000';
    END IF;
    IF v_sa.status <> 'active' THEN
        RAISE EXCEPTION '服务账号已停用或撤销' USING ERRCODE = '28000';
    END IF;
    IF now() >= v_sa.expires_at THEN
        RAISE EXCEPTION '服务账号已到期' USING ERRCODE = '28000';
    END IF;
    SELECT * INTO v_tenant FROM iam.tenants WHERE id = v_sa.tenant_id;
    IF NOT FOUND OR v_tenant.status <> 'active' THEN
        RAISE EXCEPTION '服务账号所属企业不可用' USING ERRCODE = '28000';
    END IF;

    IF p_expires_at <= now() THEN
        RAISE EXCEPTION '凭据到期时间必须晚于当前' USING ERRCODE = '23514';
    END IF;
    IF p_expires_at > LEAST(v_sa.expires_at, now() + interval '365 days') THEN
        RAISE EXCEPTION '凭据到期不得晚于服务账号到期与 365 天硬顶' USING ERRCODE = '23514';
    END IF;
    IF p_overlap_until IS NOT NULL AND p_overlap_until > now() + interval '24 hours' THEN
        RAISE EXCEPTION '轮换重叠窗口不得超过 24 小时' USING ERRCODE = '23514';
    END IF;

    SELECT COALESCE(MAX(credential_revision), 0) + 1 INTO v_rev
      FROM iam.service_tokens WHERE service_account_id = p_service_account;

    INSERT INTO iam.service_tokens(
        service_account_id, credential_id, token_digest, status,
        expires_at, overlap_until, credential_revision
    ) VALUES (p_service_account, p_credential_id, p_token_digest, 'active',
              p_expires_at, p_overlap_until, v_rev)
    RETURNING * INTO v_row;
    RETURN v_row;
END;
$$;

-- 立即撤销单个凭据
CREATE OR REPLACE FUNCTION iam_auth.revoke_service_token(p_credential_id text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
BEGIN
    PERFORM iam_auth.set_request_context(NULL, NULL, true);
    UPDATE iam.service_tokens
       SET status = 'revoked', revoked_at = now()
     WHERE credential_id = p_credential_id AND status = 'active';
END;
$$;

-- 机器身份权威加载。状态优先级：凭据缺失/撤销/过期 → invalid_or_revoked；
-- 服务账号停用/到期 → account_disabled；企业停用 → tenant_suspended。
-- 有效权限 = 主体已授 ∩ 启用权限 ∩ 非资源型（资源型在 I1a 开通前默认拒绝，不做字符串猜测）。
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
    IF NOT FOUND OR v_tok.status <> 'active' OR now() >= v_tok.expires_at THEN
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
       AND p.resource_code IS NULL;

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

-- verification_ref 复查：引用只存 session id（不存摘要），经此包装回到同一权威快照路径
CREATE OR REPLACE FUNCTION iam_auth.load_authority_snapshot_for_session(p_session uuid)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
DECLARE v_digest text;
BEGIN
    SELECT token_digest INTO v_digest FROM iam.auth_sessions WHERE id = p_session;
    IF v_digest IS NULL THEN
        RETURN jsonb_build_object('status', 'missing');
    END IF;
    RETURN iam_auth.load_authority_snapshot(v_digest);
END;
$$;

GRANT EXECUTE ON FUNCTION
    iam_auth.authenticate_internal_client(text, text),
    iam_auth.ensure_internal_client(text, text, text, text[], text[]),
    iam_auth.load_authority_snapshot_for_session(uuid),
    iam_auth.create_verification_ref(text, text, uuid, uuid, uuid, jsonb, bigint),
    iam_auth.find_verification_ref(uuid, text, text),
    iam_auth.touch_verification_ref(uuid),
    iam_auth.issue_service_token(uuid, text, text, timestamptz, timestamptz),
    iam_auth.revoke_service_token(text),
    iam_auth.load_service_identity(text)
TO iam_app;
