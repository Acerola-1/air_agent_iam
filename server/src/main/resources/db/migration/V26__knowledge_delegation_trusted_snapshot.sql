-- 修复：知识委托签发必须走可信权威快照包装，不能直接调用内部函数。
--
-- `iam_auth.load_authority_snapshot` 依赖调用方事务内的 `air_agent` 上下文；
-- 委托签发发生在内部客户端请求中，没有该上下文，直接调用会把有效成员关系读成
-- membership_disabled。`load_trusted_authority_snapshot` 会由源会话推导并恢复上下文。

CREATE OR REPLACE FUNCTION iam_auth.create_knowledge_delegation(
    p_client text,
    p_ref uuid,
    p_operation text,
    p_token_digest text,
    p_ttl_seconds bigint
) RETURNS TABLE(
    expires_at timestamptz,
    user_id uuid,
    session_id uuid,
    tenant_id uuid,
    membership_id uuid,
    context_version bigint,
    revisions jsonb
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
DECLARE
    v_ref iam.verification_refs%ROWTYPE;
    v_sess iam.auth_sessions%ROWTYPE;
    v_snapshot jsonb;
    v_status text;
    v_mem text;
    v_tenant text;
    v_rev jsonb;
    v_valid timestamptz;
    v_id uuid;
BEGIN
    IF p_operation IS NULL OR p_operation NOT IN
       ('query', 'record:read', 'source:read', 'document:read') THEN
        RAISE EXCEPTION '不支持的 knowledge 委托 operation' USING ERRCODE = '22023';
    END IF;
    IF p_token_digest IS NULL OR p_token_digest !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION '委托摘要格式非法' USING ERRCODE = '22023';
    END IF;
    IF p_ttl_seconds IS NULL OR p_ttl_seconds < 1 OR p_ttl_seconds > 60 THEN
        RAISE EXCEPTION '委托 TTL 必须在 1..60 秒' USING ERRCODE = '22023';
    END IF;

    SELECT * INTO v_ref
      FROM iam.verification_refs r
     WHERE r.id = p_ref
       AND r.client_id = p_client
       AND r.audience = 'langgraph-runtime'
       AND r.valid_until > now();
    IF NOT FOUND THEN
        RAISE EXCEPTION '执行引用不存在、不属于该客户端或已过期' USING ERRCODE = '28000';
    END IF;

    SELECT * INTO v_sess FROM iam.auth_sessions WHERE id = v_ref.session_id;
    IF NOT FOUND OR v_sess.status <> 'active' THEN
        RAISE EXCEPTION '源会话不存在或已撤销' USING ERRCODE = '28000';
    END IF;

    -- 可信包装：从源会话推导 RLS 上下文并在读取后恢复，不污染外层事务。
    v_snapshot := iam_auth.load_trusted_authority_snapshot(v_sess.token_digest);
    v_status := v_snapshot ->> 'status';
    IF v_status IS DISTINCT FROM 'ok' THEN
        RAISE EXCEPTION '源会话当前不可用' USING ERRCODE = '28000';
    END IF;

    v_tenant := v_snapshot #>> '{tenant,id}';
    v_mem := v_snapshot #>> '{membership,id}';
    v_rev := v_snapshot -> 'revisions';

    IF v_tenant IS NULL OR v_tenant::uuid IS DISTINCT FROM v_ref.tenant_id THEN
        RAISE EXCEPTION '源会话企业上下文已变更' USING ERRCODE = '28000';
    END IF;
    IF v_mem IS NULL THEN
        RAISE EXCEPTION '源会话缺少有效企业成员关系' USING ERRCODE = '28000';
    END IF;
    IF (v_rev ->> 'user_auth_revision')::bigint
           IS DISTINCT FROM (v_ref.revisions ->> 'user_auth_revision')::bigint
       OR (v_rev ->> 'tenant_auth_revision')::bigint
           IS DISTINCT FROM (v_ref.revisions ->> 'tenant_auth_revision')::bigint
       OR (v_rev ->> 'membership_revision')::bigint
           IS DISTINCT FROM (v_ref.revisions ->> 'membership_revision')::bigint
       OR (v_rev ->> 'session_ctx_version')::bigint
           IS DISTINCT FROM (v_ref.revisions ->> 'session_ctx_version')::bigint THEN
        RAISE EXCEPTION '源会话授权修订已变化' USING ERRCODE = '28000';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM jsonb_array_elements_text(v_snapshot -> 'permissions') AS p(code)
         WHERE p.code ~ '^knowledge:lib:[a-z][a-z0-9_-]{1,31}:read$'
    ) THEN
        RAISE EXCEPTION '当前企业没有有效知识库读取权限' USING ERRCODE = '42501';
    END IF;

    v_valid := LEAST(
        now() + make_interval(secs => p_ttl_seconds),
        v_ref.valid_until,
        v_sess.absolute_expires_at
    );
    IF v_valid <= now() THEN
        RAISE EXCEPTION '源会话剩余有效期不足' USING ERRCODE = '28000';
    END IF;

    INSERT INTO iam.knowledge_delegations(
        token_digest, issuing_client_id, user_id, session_id, tenant_id,
        membership_id, operation, context_version, revisions, expires_at
    ) VALUES (
        p_token_digest, p_client, v_ref.user_id, v_ref.session_id, v_ref.tenant_id,
        v_mem::uuid, p_operation, (v_rev ->> 'session_ctx_version')::bigint, v_rev, v_valid
    )
    RETURNING knowledge_delegations.id INTO v_id;

    PERFORM iam_auth.touch_verification_ref(v_ref.id);

    RETURN QUERY SELECT v_valid, v_ref.user_id, v_ref.session_id, v_ref.tenant_id,
                        v_mem::uuid, (v_rev ->> 'session_ctx_version')::bigint, v_rev;
END;
$$;

REVOKE ALL ON FUNCTION iam_auth.create_knowledge_delegation(text, uuid, text, text, bigint)
FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam_auth.create_knowledge_delegation(text, uuid, text, text, bigint)
TO iam_app;
