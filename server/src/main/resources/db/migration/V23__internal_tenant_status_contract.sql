CREATE OR REPLACE FUNCTION iam_auth.tenant_is_active(p_tenant_id uuid)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = iam, pg_temp
AS $$
DECLARE
    v_user text := current_setting('app.user_id', true);
    v_tenant text := current_setting('app.tenant_id', true);
    v_platform text := current_setting('app.is_platform', true);
    v_active boolean;
BEGIN
    PERFORM iam_auth.set_request_context(NULL, NULL, true);
    SELECT EXISTS (
        SELECT 1 FROM iam.tenants t
         WHERE t.id = p_tenant_id AND t.status = 'active'
    ) INTO v_active;
    PERFORM set_config('app.user_id', coalesce(v_user, ''), true);
    PERFORM set_config('app.tenant_id', coalesce(v_tenant, ''), true);
    PERFORM set_config('app.is_platform', coalesce(v_platform, 'off'), true);
    RETURN v_active;
EXCEPTION WHEN OTHERS THEN
    PERFORM set_config('app.user_id', coalesce(v_user, ''), true);
    PERFORM set_config('app.tenant_id', coalesce(v_tenant, ''), true);
    PERFORM set_config('app.is_platform', coalesce(v_platform, 'off'), true);
    RAISE;
END;
$$;

REVOKE ALL ON FUNCTION iam_auth.tenant_is_active(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam_auth.tenant_is_active(uuid) TO iam_app;
