-- 使用锁后实时时间并保持空闲截止时间单调，防止旧事务晚提交缩短会话。
CREATE OR REPLACE FUNCTION iam_auth.renew_session(
    p_session uuid, p_expected bigint, p_idle_seconds bigint
) RETURNS TABLE(absolute_expires_at timestamptz, idle_expires_at timestamptz, expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
DECLARE
    v_sess iam.auth_sessions%ROWTYPE;
    v_new_idle timestamptz;
BEGIN
    SELECT * INTO v_sess FROM iam.auth_sessions WHERE id = p_session FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION '会话不存在' USING ERRCODE = '28000';
    END IF;
    IF v_sess.status <> 'active'
       OR clock_timestamp() >= v_sess.absolute_expires_at
       OR clock_timestamp() >= v_sess.expires_at THEN
        RAISE EXCEPTION '会话已撤销或过期，不能续期' USING ERRCODE = '28000';
    END IF;
    IF v_sess.ctx_version <> p_expected THEN
        RAISE EXCEPTION '上下文版本冲突 expected=% actual=%', p_expected, v_sess.ctx_version
            USING ERRCODE = 'P0010';
    END IF;
    v_new_idle := LEAST(GREATEST(v_sess.idle_expires_at,
                              clock_timestamp() + make_interval(secs => p_idle_seconds)),
                        v_sess.absolute_expires_at);
    UPDATE iam.auth_sessions
       SET idle_expires_at = v_new_idle, expires_at = v_new_idle, last_used_at = clock_timestamp()
     WHERE id = p_session;
    RETURN QUERY SELECT v_sess.absolute_expires_at, v_new_idle, v_new_idle;
END;
$$;
