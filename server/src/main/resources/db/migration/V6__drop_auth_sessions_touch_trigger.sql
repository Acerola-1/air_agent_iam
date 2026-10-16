-- I1 第3组修复：V1 的通用 set_updated_at 触发器循环误挂到 auth_sessions，
-- 而该表只有 last_used_at（无 updated_at 列），导致任何会话状态机 UPDATE 都失败。
-- 会话时间由 iam_auth 会话函数显式维护（last_used_at/revoked_at），不需要该触发器。

DROP TRIGGER IF EXISTS auth_sessions_touch ON iam.auth_sessions;
