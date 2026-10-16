-- I1 第5组：服务账号详情需要凭据元数据列表。
-- service_tokens 对 iam_app 仅 ENABLE RLS 且无 policy（默认拒绝直读），
-- 与核验/签发路径一致，统一经 iam_auth 受控函数读取；返回内容不含 token_digest/原始秘密。

CREATE OR REPLACE FUNCTION iam_auth.list_service_tokens(p_service_account uuid)
RETURNS TABLE(
    credential_id text,
    credential_revision bigint,
    status text,
    issued_at timestamptz,
    expires_at timestamptz,
    overlap_until timestamptz,
    revoked_at timestamptz
)
LANGUAGE sql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
    SELECT st.credential_id,
           st.credential_revision,
           st.status,
           st.issued_at,
           st.expires_at,
           st.overlap_until,
           st.revoked_at
      FROM iam.service_tokens st
     WHERE st.service_account_id = p_service_account
     ORDER BY st.issued_at DESC, st.credential_id ASC
$$;

GRANT EXECUTE ON FUNCTION iam_auth.list_service_tokens(uuid) TO iam_app;
