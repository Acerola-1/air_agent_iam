-- I1 第6组：合成 SSO 客户端预置/核验函数与跨端会话签发。
-- sso_clients 为 ENABLE RLS 无 policy 表，iam_app 只能经 iam_auth SECURITY DEFINER
-- 函数单行键控访问；客户端密钥只存 sha256 摘要，原始值不进日志/审计/响应。

-- 注册客户端允许为浏览器兑换到的应用会话受众；与登录白名单一致，不产生新受众通道。
ALTER TABLE iam.sso_clients ADD COLUMN IF NOT EXISTS audience text NOT NULL DEFAULT 'air-agent';
ALTER TABLE iam.sso_clients DROP CONSTRAINT IF EXISTS sso_clients_audience_check;
ALTER TABLE iam.sso_clients
    ADD CONSTRAINT sso_clients_audience_check CHECK (audience IN ('air-agent','knowledge','iam-admin'));

-- 幂等预置：首次插入写摘要；已存在只同步名称/精确回调/Origin/受众，不覆盖既有密钥。
CREATE OR REPLACE FUNCTION iam_auth.ensure_sso_client(
    p_client_id     text,
    p_name          text,
    p_secret_digest text,
    p_callback_url  text,
    p_origins       text[],
    p_audience      text
) RETURNS TABLE(was_created boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
BEGIN
    IF p_audience NOT IN ('air-agent','knowledge','iam-admin') THEN
        RAISE EXCEPTION 'SSO 客户端受众不合法 %', p_audience USING ERRCODE = '23514';
    END IF;
    RETURN QUERY
    INSERT INTO iam.sso_clients(client_id, name, secret_digest, callback_url, origins, audience, status)
    VALUES (p_client_id, p_name, p_secret_digest, p_callback_url, p_origins, p_audience, 'active')
    ON CONFLICT (client_id) DO UPDATE
       SET name = EXCLUDED.name,
           callback_url = EXCLUDED.callback_url,
           origins = EXCLUDED.origins,
           audience = EXCLUDED.audience
    RETURNING (xmax = 0) AS was_created;
END;
$$;

-- 兑换端点核验调用方：不存在/错密钥/停用统一 28000，由应用层映射为同一 401，避免客户端枚举。
CREATE OR REPLACE FUNCTION iam_auth.authenticate_sso_client(p_client_id text, p_secret_digest text)
RETURNS TABLE(
    client_id    text,
    name         text,
    callback_url text,
    origins      text[],
    audience     text,
    status       text
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
BEGIN
    RETURN QUERY
    SELECT c.client_id, c.name, c.callback_url, c.origins, c.audience, c.status
      FROM iam.sso_clients c
     WHERE c.client_id = p_client_id
       AND c.secret_digest = p_secret_digest
       AND c.status = 'active';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'SSO 客户端凭据无效或已停用' USING ERRCODE = '28000';
    END IF;
END;
$$;

-- 兑换成功后为同一人类签发独立应用会话：复制中央会话当前企业与上下文版本及四修订基线，
-- 新随机令牌摘要；源会话必须仍 active 且未过绝对期限。撤销/停用以 users/tenants/
-- memberships 修订在每次权威核验时即时生效；全局登出按 user_id 一并撤销新会话。
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
    SELECT * INTO v_src FROM iam.auth_sessions WHERE id = p_source FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION '源会话不存在' USING ERRCODE = '28000';
    END IF;
    IF v_src.status <> 'active'
       OR now() >= v_src.absolute_expires_at
       OR now() >= v_src.expires_at THEN
        RAISE EXCEPTION '源会话已撤销或过期' USING ERRCODE = '28000';
    END IF;

    INSERT INTO iam.auth_sessions (
        user_id, realm, login_audience, token_digest,
        current_tenant_id, ctx_version, status,
        expires_at, idle_expires_at, absolute_expires_at,
        base_user_revision, base_tenant_revision, base_membership_revision
    ) VALUES (
        v_src.user_id, v_src.realm, p_audience, p_digest,
        v_src.current_tenant_id, v_src.ctx_version, 'active',
        now() + make_interval(secs => LEAST(p_idle_seconds, p_absolute_seconds)),
        now() + make_interval(secs => LEAST(p_idle_seconds, p_absolute_seconds)),
        now() + make_interval(secs => p_absolute_seconds),
        v_src.base_user_revision, v_src.base_tenant_revision, v_src.base_membership_revision
    ) RETURNING * INTO v_row;
    RETURN v_row;
END;
$$;

GRANT EXECUTE ON FUNCTION
    iam_auth.ensure_sso_client(text, text, text, text, text[], text),
    iam_auth.authenticate_sso_client(text, text),
    iam_auth.mint_sso_session(uuid, text, text, bigint, bigint)
TO iam_app;
