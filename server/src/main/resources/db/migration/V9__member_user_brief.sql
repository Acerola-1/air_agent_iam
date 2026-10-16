-- I1 第5组：成员视图的用户摘要受控读取。
-- 成员停用后 users_policy 的“同租户活跃成员”可见分支失效，企业管理员（非平台上下文）
-- 直读 users 会取不到行，管理端成员列表/详情因此无法展示停用成员。
-- 经成员键读取：调用授权仍由服务层（成员必须属于会话当前企业）+ memberships RLS 把关，
-- SECURITY DEFINER 仅用于越过 users 行可见性，函数不返回 password_hash 等敏感列。

CREATE OR REPLACE FUNCTION iam_auth.member_user_brief(p_membership uuid)
RETURNS TABLE(
    user_id uuid,
    realm text,
    account text,
    display_name text,
    status text,
    auth_revision bigint,
    created_at timestamptz
)
LANGUAGE sql SECURITY DEFINER SET search_path = iam, pg_temp AS $$
    SELECT u.id, u.realm, u.account, u.display_name, u.status, u.auth_revision, u.created_at
      FROM iam.users u
      JOIN iam.tenant_memberships m ON m.user_id = u.id
     WHERE m.id = p_membership
$$;

GRANT EXECUTE ON FUNCTION iam_auth.member_user_brief(uuid) TO iam_app;
