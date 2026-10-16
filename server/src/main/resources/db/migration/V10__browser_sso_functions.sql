-- I1 第6组：浏览器会话句柄（/web-api）与合成 SSO 的受控数据访问。
-- browser_handles / sso_* 已 ENABLE RLS 且无 policy（默认拒绝 iam_app 直读直写），
-- 全部访问收敛到 iam_auth SECURITY DEFINER 函数；函数只做单行键控操作，
-- 不返回任何原始人类会话令牌（auth_sessions.token_digest 仅经 session_token_digest
-- 供服务端完成"句柄→会话→权威快照"解析，不进响应/日志）。

-- ---------------------------------------------------------------- 浏览器句柄

CREATE OR REPLACE FUNCTION iam_auth.browser_handle_open(
    p_handle_digest text,
    p_csrf_token    text,
    p_expires_at    timestamptz
) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
    INSERT INTO iam.browser_handles(handle_digest, session_id, csrf_token, expires_at)
    VALUES (p_handle_digest, NULL, p_csrf_token, p_expires_at)
$$;

CREATE OR REPLACE FUNCTION iam_auth.browser_handle_get(p_handle_digest text)
RETURNS TABLE(
    handle_digest    text,
    session_id       uuid,
    csrf_token       text,
    authenticated_at timestamptz,
    expires_at       timestamptz,
    revoked_at       timestamptz
)
LANGUAGE sql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
    SELECT h.handle_digest, h.session_id, h.csrf_token,
           h.authenticated_at, h.expires_at, h.revoked_at
      FROM iam.browser_handles h
     WHERE h.handle_digest = p_handle_digest
$$;

-- 登录成功后会话固定（session fixation 防护）：旧匿名句柄立即吊销，
-- 新随机句柄绑定真实会话与新 CSRF；由应用在同一数据库事务边界内连续调用。
CREATE OR REPLACE FUNCTION iam_auth.browser_handle_bind(
    p_old_digest    text,
    p_new_digest    text,
    p_session_id    uuid,
    p_csrf_token    text,
    p_expires_at    timestamptz
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
BEGIN
    IF p_old_digest IS NOT NULL THEN
        UPDATE iam.browser_handles
           SET revoked_at = now()
         WHERE handle_digest = p_old_digest AND revoked_at IS NULL;
    END IF;
    INSERT INTO iam.browser_handles(handle_digest, session_id, csrf_token,
                                    authenticated_at, expires_at)
    VALUES (p_new_digest, p_session_id, p_csrf_token, now(), p_expires_at);
END;
$$;

CREATE OR REPLACE FUNCTION iam_auth.browser_handle_revoke(p_handle_digest text)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
DECLARE
    v_session uuid;
BEGIN
    UPDATE iam.browser_handles
       SET revoked_at = now()
     WHERE handle_digest = p_handle_digest AND revoked_at IS NULL
    RETURNING session_id INTO v_session;
    RETURN v_session;
END;
$$;

CREATE OR REPLACE FUNCTION iam_auth.browser_handle_touch(
    p_handle_digest text,
    p_expires_at    timestamptz
) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
    UPDATE iam.browser_handles
       SET expires_at = p_expires_at
     WHERE handle_digest = p_handle_digest AND revoked_at IS NULL
$$;

-- 句柄→会话令牌摘要：仅服务端权威解析链路使用，绝不暴露到 /web-api 响应。
CREATE OR REPLACE FUNCTION iam_auth.session_token_digest(p_session_id uuid)
RETURNS text
LANGUAGE sql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
    SELECT token_digest FROM iam.auth_sessions WHERE id = p_session_id
$$;

GRANT EXECUTE ON FUNCTION
    iam_auth.browser_handle_open(text, text, timestamptz),
    iam_auth.browser_handle_get(text),
    iam_auth.browser_handle_bind(text, text, uuid, text, timestamptz),
    iam_auth.browser_handle_revoke(text),
    iam_auth.browser_handle_touch(text, timestamptz),
    iam_auth.session_token_digest(uuid)
TO iam_app;

-- ---------------------------------------------------------------- SSO（合成客户端）

CREATE OR REPLACE FUNCTION iam_auth.sso_client_get(p_client_id text)
RETURNS TABLE(
    client_id     text,
    name          text,
    secret_digest text,
    callback_url  text,
    origins       text[],
    status        text
)
LANGUAGE sql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
    SELECT c.client_id, c.name, c.secret_digest, c.callback_url, c.origins, c.status
      FROM iam.sso_clients c
     WHERE c.client_id = p_client_id
$$;

-- state 一次性消费：仅当未消费且未过期时原子置位，并发/重放第二个事务命中 0 行。
CREATE OR REPLACE FUNCTION iam_auth.sso_state_consume(p_state_digest text)
RETURNS TABLE(
    client_id    text,
    handle_digest text,
    redirect_uri text
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
BEGIN
    RETURN QUERY
    UPDATE iam.sso_states s
       SET consumed_at = now()
     WHERE s.state_digest = p_state_digest
       AND s.consumed_at IS NULL
       AND s.expires_at > now()
    RETURNING s.client_id, s.handle_digest, s.redirect_uri;
END;
$$;

CREATE OR REPLACE FUNCTION iam_auth.sso_state_save(
    p_state_digest  text,
    p_client_id     text,
    p_handle_digest text,
    p_redirect_uri  text,
    p_expires_at    timestamptz
) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
    INSERT INTO iam.sso_states(state_digest, client_id, handle_digest, redirect_uri, expires_at)
    VALUES (p_state_digest, p_client_id, p_handle_digest, p_redirect_uri, p_expires_at)
$$;

-- ticket 30 秒一次性消费：绑定 client 与精确回调，重放/过期返回 0 行。
CREATE OR REPLACE FUNCTION iam_auth.sso_ticket_consume(
    p_ticket_digest text,
    p_client_id     text,
    p_redirect_uri  text
)
RETURNS TABLE(
    session_id uuid
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
BEGIN
    RETURN QUERY
    UPDATE iam.sso_tickets t
       SET consumed_at = now()
     WHERE t.ticket_digest = p_ticket_digest
       AND t.client_id = p_client_id
       AND t.redirect_uri = p_redirect_uri
       AND t.consumed_at IS NULL
       AND t.expires_at > now()
    RETURNING t.session_id;
END;
$$;

CREATE OR REPLACE FUNCTION iam_auth.sso_ticket_save(
    p_ticket_digest text,
    p_client_id     text,
    p_session_id    uuid,
    p_redirect_uri  text,
    p_expires_at    timestamptz
) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
    INSERT INTO iam.sso_tickets(ticket_digest, client_id, session_id, redirect_uri, expires_at)
    VALUES (p_ticket_digest, p_client_id, p_session_id, p_redirect_uri, p_expires_at)
$$;

GRANT EXECUTE ON FUNCTION
    iam_auth.sso_client_get(text),
    iam_auth.sso_state_consume(text),
    iam_auth.sso_state_save(text, text, text, text, timestamptz),
    iam_auth.sso_ticket_consume(text, text, text),
    iam_auth.sso_ticket_save(text, text, uuid, text, timestamptz)
TO iam_app;
