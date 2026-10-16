-- 重叠上界从轮换时刻计算，而不是从旧凭据最初签发时刻计算。
ALTER TABLE iam.service_tokens ADD COLUMN rotated_at timestamptz;
UPDATE iam.service_tokens SET rotated_at = issued_at WHERE overlap_until IS NOT NULL;
ALTER TABLE iam.service_tokens DROP CONSTRAINT service_tokens_overlap_window_ck;
ALTER TABLE iam.service_tokens ADD CONSTRAINT service_tokens_overlap_window_ck
    CHECK (overlap_until IS NULL OR (rotated_at IS NOT NULL
           AND overlap_until <= rotated_at + interval '24 hours' AND overlap_until <= expires_at));

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
    IF p_overlap_until IS NOT NULL AND p_overlap_until > clock_timestamp() + interval '24 hours' THEN
        RAISE EXCEPTION '轮换重叠窗口不得超过 24 小时' USING ERRCODE = '23514';
    END IF;

    UPDATE iam.service_tokens
       SET rotated_at = clock_timestamp(),
           overlap_until = LEAST(expires_at, COALESCE(p_overlap_until, clock_timestamp())),
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
