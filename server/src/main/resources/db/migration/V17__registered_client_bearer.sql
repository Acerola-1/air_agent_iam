-- 冻结契约中的内部 Bearer 凭据与人类 subject_token 分型；仅查对应客户端登记表。
CREATE OR REPLACE FUNCTION iam_auth.authenticate_internal_bearer(p_digest text)
RETURNS TABLE(client_id text, name text, scopes text[], audiences text[], status text)
LANGUAGE sql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
    SELECT c.client_id, c.name, c.scopes, c.audiences, c.status
      FROM iam.internal_clients c
     WHERE c.secret_digest = p_digest AND c.status = 'active'
       AND (SELECT count(*) FROM iam.internal_clients x WHERE x.secret_digest = p_digest) = 1
$$;
CREATE OR REPLACE FUNCTION iam_auth.authenticate_sso_bearer(p_digest text)
RETURNS TABLE(client_id text, name text, callback_url text, origins text[], audience text, status text)
LANGUAGE sql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
    SELECT c.client_id, c.name, c.callback_url, c.origins, c.audience, c.status
      FROM iam.sso_clients c
     WHERE c.secret_digest = p_digest AND c.status = 'active'
       AND (SELECT count(*) FROM iam.sso_clients x WHERE x.secret_digest = p_digest) = 1
$$;
REVOKE ALL ON FUNCTION iam_auth.authenticate_internal_bearer(text),
    iam_auth.authenticate_sso_bearer(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam_auth.authenticate_internal_bearer(text),
    iam_auth.authenticate_sso_bearer(text) TO iam_app;
