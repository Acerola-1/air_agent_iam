-- 三图共享知识检索：短期、只读、单 operation 的用户委托。
--
-- 设计约束（见 Agent 仓 openspec/changes/add-shared-knowledge-retrieval-tool/contracts.md）：
--   * 只能由持有本人有效 verification_ref 的 Agent 内部客户端申请；
--   * 目标受众固定 knowledge，源受众固定 langgraph-runtime；
--   * 只保存 256 位随机令牌的 SHA-256 摘要，原始令牌只在签发响应中出现一次；
--   * TTL 最长 60 秒，且不超过源引用与会话绝对到期；
--   * operation 只能取 query / record:read / source:read / document:read；
--   * 每次内省重新读取源会话、四项修订、企业与有效知识权限，不依赖签发时快照。

CREATE TABLE iam.knowledge_delegations (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    token_digest      text NOT NULL UNIQUE,
    issuing_client_id text NOT NULL,
    user_id           uuid NOT NULL,
    session_id        uuid NOT NULL REFERENCES iam.auth_sessions(id),
    tenant_id         uuid NOT NULL,
    membership_id     uuid NOT NULL,
    operation         text NOT NULL CHECK (
        operation IN ('query', 'record:read', 'source:read', 'document:read')
    ),
    context_version   bigint NOT NULL,
    revisions         jsonb NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    expires_at        timestamptz NOT NULL,
    last_used_at      timestamptz,
    revoked_at        timestamptz,
    CONSTRAINT knowledge_delegations_ttl_ck
        CHECK (expires_at > created_at AND expires_at <= created_at + interval '60 seconds')
);

CREATE INDEX idx_knowledge_delegations_session
    ON iam.knowledge_delegations(session_id);
CREATE INDEX idx_knowledge_delegations_expiry
    ON iam.knowledge_delegations(expires_at);

-- 无 policy：iam_app 只能经下方 SECURITY DEFINER 函数访问（表属主为迁移角色，
-- 与 verification_refs 同一口径；不启用 FORCE，避免属主执行函数时被自身 RLS 阻断）。
ALTER TABLE iam.knowledge_delegations ENABLE ROW LEVEL SECURITY;

-- ---------------------------------------------------------------------------
-- 签发：以源执行引用登记一条只读委托
-- ---------------------------------------------------------------------------

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

    v_snapshot := iam_auth.load_authority_snapshot(v_sess.token_digest);
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

    -- 至少一项实时有效的知识库读权限；细粒度资料映射由 RAG 再裁决。
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

-- ---------------------------------------------------------------------------
-- 内省：按摘要读取未过期的委托行（有效性由 Java 层以实时快照复核）
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION iam_auth.find_knowledge_delegation(p_digest text)
RETURNS SETOF iam.knowledge_delegations
LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
BEGIN
    RETURN QUERY
    SELECT d.* FROM iam.knowledge_delegations d
     WHERE d.token_digest = p_digest
       AND d.expires_at > now()
       AND d.revoked_at IS NULL;
END;
$$;

CREATE OR REPLACE FUNCTION iam_auth.touch_knowledge_delegation(p_id uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
BEGIN
    UPDATE iam.knowledge_delegations SET last_used_at = now() WHERE id = p_id;
END;
$$;

-- 只清理已过期且超过保留窗口的摘要行；由运维/测试显式调用，不自动删除活动行。
CREATE OR REPLACE FUNCTION iam_auth.purge_expired_knowledge_delegations(p_retention_hours bigint)
RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
DECLARE v_count bigint;
BEGIN
    IF p_retention_hours IS NULL OR p_retention_hours < 1 THEN
        RAISE EXCEPTION '保留时长必须 >= 1 小时' USING ERRCODE = '22023';
    END IF;
    DELETE FROM iam.knowledge_delegations
     WHERE expires_at < now() - make_interval(hours => p_retention_hours);
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$;

REVOKE ALL ON FUNCTION
    iam_auth.create_knowledge_delegation(text, uuid, text, text, bigint),
    iam_auth.find_knowledge_delegation(text),
    iam_auth.touch_knowledge_delegation(uuid),
    iam_auth.purge_expired_knowledge_delegations(bigint)
FROM PUBLIC;

GRANT EXECUTE ON FUNCTION
    iam_auth.create_knowledge_delegation(text, uuid, text, text, bigint),
    iam_auth.find_knowledge_delegation(text),
    iam_auth.touch_knowledge_delegation(uuid),
    iam_auth.purge_expired_knowledge_delegations(bigint)
TO iam_app;
