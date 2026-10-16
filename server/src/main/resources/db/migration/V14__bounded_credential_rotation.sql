-- 轮换时在旧凭据上保存重叠截止时间，默认立即撤销；新凭据不受旧凭据窗口截断。
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

    SELECT * INTO v_sa FROM iam.service_accounts WHERE id = p_service_account FOR UPDATE;
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

    UPDATE iam.service_tokens
       SET overlap_until = LEAST(expires_at, COALESCE(p_overlap_until, clock_timestamp())),
           status = CASE WHEN p_overlap_until IS NULL THEN 'revoked' ELSE status END,
           revoked_at = CASE WHEN p_overlap_until IS NULL THEN clock_timestamp() ELSE revoked_at END
     WHERE service_account_id = p_service_account AND status = 'active';

    SELECT COALESCE(MAX(credential_revision), 0) + 1 INTO v_rev
      FROM iam.service_tokens WHERE service_account_id = p_service_account;

    INSERT INTO iam.service_tokens(
        service_account_id, credential_id, token_digest, status,
        expires_at, overlap_until, credential_revision
    ) VALUES (p_service_account, p_credential_id, p_token_digest, 'active',
              p_expires_at, NULL, v_rev)
    RETURNING * INTO v_row;
    RETURN v_row;
END;
$$;

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
