#!/usr/bin/env bash
# 浏览器验收夹具（C29 切企业 A→B→A）：给指定用户在两个指定租户建立 tenant_admin 成员关系。
# 背景：平台/企业授权可授分离，平台管理员不能直接授予企业角色；企业首位管理员只能在开通流程落库。
# 本脚本仅用于本任务自有的隔离 iam 库（iam-pg17），确定性、幂等、可清理：
#   ./scripts/seed-browser-fixture.sh <user_account> <tenant_code_a> <tenant_code_b>
#   ./scripts/seed-browser-fixture.sh --cleanup <user_account> <tenant_code_a> <tenant_code_b>
# 仅插入 tenant_memberships / membership_roles，不触碰既有用户与租户主体。
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; . ./.env.local; set +a

MODE="seed"
if [ "${1:-}" = "--cleanup" ]; then MODE="cleanup"; shift; fi
ACC="${1:?}"; CODE_A="${2:?}"; CODE_B="${3:?}"

CB="$(command -v container || command -v docker)"

"$CB" exec -i iam-pg17 psql -U "$IAM_PG_MIGRATE_USER" -d "$IAM_PG_DB" -v ON_ERROR_STOP=1 -v acc="$ACC" -v ca="$CODE_A" -v cb="$CODE_B" -v mode="$MODE" <<'SQL'
BEGIN;
SELECT iam_auth.set_request_context(NULL,NULL,true);
SELECT set_config('iam_fixture.acc', :'acc', false), set_config('iam_fixture.ca', :'ca', false),
       set_config('iam_fixture.cb', :'cb', false), set_config('iam_fixture.mode', :'mode', false);

DO $$
DECLARE v_acc text := current_setting('iam_fixture.acc');
        v_ca  text := current_setting('iam_fixture.ca');
        v_cb  text := current_setting('iam_fixture.cb');
        v_mode text := current_setting('iam_fixture.mode');
        r record;
BEGIN
  IF v_mode = 'cleanup' THEN
    DELETE FROM iam.membership_roles mr
    USING iam.tenant_memberships m
    WHERE mr.membership_id = m.id AND m.user_id = (SELECT id FROM iam.users WHERE account = v_acc)
      AND m.tenant_id IN (SELECT id FROM iam.tenants WHERE code IN (v_ca, v_cb));
    DELETE FROM iam.tenant_memberships
    WHERE user_id = (SELECT id FROM iam.users WHERE account = v_acc)
      AND tenant_id IN (SELECT id FROM iam.tenants WHERE code IN (v_ca, v_cb));
  ELSE
    FOR r IN
      SELECT t.id AS tenant_id, u.id AS user_id
      FROM iam.tenants t CROSS JOIN iam.users u
      WHERE u.account = v_acc AND t.code IN (v_ca, v_cb)
    LOOP
      INSERT INTO iam.tenant_memberships(id, tenant_id, user_id, created_by)
      VALUES (gen_random_uuid(), r.tenant_id, r.user_id, r.user_id)
      ON CONFLICT (tenant_id, user_id) DO NOTHING;

      INSERT INTO iam.membership_roles(tenant_id, membership_id, role_id, granted_by)
      SELECT r.tenant_id, m.id, ro.id, r.user_id
      FROM iam.tenant_memberships m
      JOIN iam.roles ro ON ro.scope = 'tenant' AND ro.code = 'tenant_admin'
      WHERE m.tenant_id = r.tenant_id AND m.user_id = r.user_id
      ON CONFLICT DO NOTHING;
    END LOOP;
  END IF;
END $$;
COMMIT;
SQL
