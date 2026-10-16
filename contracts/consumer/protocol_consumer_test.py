#!/usr/bin/env python3
"""IAM 协议消费者测试器（无外部服务依赖，纯契约）。

验收点：
- C04 身份载荷：正向样本通过 JSON Schema 2020-12；缺字段/错类型反例被拒。
- C12 消费方契约：aud 枚举、主体分型、inactive 信封不泄漏身份、revision 必须整数。
- 跨字段语义：session.ctx_version == context_version == revisions.session_ctx_version。
- 请求体：login/switch/renew/introspect/runtime-ticket/sso-exchange 正反样本。
- OpenAPI 3.1 文档自身可被 openapi-spec-validator 解析通过。

退出码：全过 0，任一失败 1。
"""
from __future__ import annotations

import json
import pathlib
import sys

import jsonschema
from jsonschema import Draft202012Validator
from openapi_spec_validator import validate as validate_openapi
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schemas"
SAMPLE_DIR = ROOT / "samples"
OPENAPI_PATH = ROOT / "openapi" / "iam-identity-v1.openapi.yaml"

SECRET_KEYS = {
    "password", "old_password", "new_password", "password_hash",
    "token", "access_token", "refresh_token", "subject_token",
    "ticket", "cookie", "secret", "client_secret",
}

failures: list[str] = []
passes: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        passes.append(f"PASS {name}")
    else:
        failures.append(f"FAIL {name}: {detail}")


def load_json(path: pathlib.Path):
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def load_schema(name: str):
    schema = load_json(SCHEMA_DIR / name)
    Draft202012Validator.check_schema(schema)
    return schema


FORMAT_CHECKER = jsonschema.FormatChecker()


def schema_errors(validator, instance) -> list[str]:
    return [
        f"{list(err.absolute_path) or '<root>'}: {err.message}"
        for err in sorted(validator.iter_errors(instance), key=str)
    ]


def semantic_identity_invariants(name: str, payload) -> list[str]:
    """Schema 表达不了的跨字段一致性；返回错误描述列表（空=通过）。"""
    errs: list[str] = []
    ctx = payload.get("context_version")
    sess_ctx = (payload.get("session") or {}).get("ctx_version")
    rev_ctx = (payload.get("revisions") or {}).get("session_ctx_version")
    if not (ctx == sess_ctx == rev_ctx):
        errs.append(f"ctx triple differ: context_version={ctx} session.ctx_version={sess_ctx} revisions.session_ctx_version={rev_ctx}")
    secret_hits: list[str] = []
    def collect_secret(node, path="$") -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in SECRET_KEYS:
                    secret_hits.append(f"{path}.{key}")
                else:
                    collect_secret(value, f"{path}.{key}")
        elif isinstance(node, list):
            for idx, item in enumerate(node):
                collect_secret(item, f"{path}[{idx}]")
    collect_secret(payload)
    if secret_hits:
        errs.append(f"secret fields present: {secret_hits}")
    if payload.get("needs_tenant_selection") and not (
        payload.get("current_tenant") is None and payload.get("membership") is None
    ):
        errs.append("needs_tenant_selection=true 时 current_tenant/membership 必须为 null")
    if payload.get("context_usable") and payload.get("current_tenant") and payload.get("membership"):
        if payload["membership"]["tenant_id"] != payload["current_tenant"]["id"]:
            errs.append("membership.tenant_id 与 current_tenant.id 不一致")
    return errs


def main() -> int:
    identity_schema = load_schema("identity.schema.json")
    inactive_schema = load_schema("introspection-inactive.schema.json")
    requests_schema = load_schema("requests.schema.json")
    error_schema = load_schema("error.schema.json")
    Draft202012Validator(error_schema)

    identity_validator = Draft202012Validator(identity_schema, format_checker=FORMAT_CHECKER)
    inactive_validator = Draft202012Validator(inactive_schema, format_checker=FORMAT_CHECKER)

    # ---- 身份正样本 ----
    for path in sorted((SAMPLE_DIR / "identity" / "valid").glob("*.json")):
        payload = load_json(path)
        validator = inactive_validator if path.name.startswith("inactive-") else identity_validator
        errs = schema_errors(validator, payload)
        check(f"identity-valid/{path.name}", not errs, "; ".join(errs))
        if not errs and path.name.startswith("inactive-"):
            leaked = [k for k in ("user", "session", "permissions", "revisions") if k in payload]
            check(f"identity-valid/{path.name}/no-leak", not leaked, f"leak keys={leaked}")
        elif not errs:
            sem = semantic_identity_invariants(path.name, payload)
            check(f"identity-valid/{path.name}/semantic", not sem, "; ".join(sem))

    # ---- 身份反例 ----
    semantic_only = {"ctx-version-mismatch-session.json", "context-version-mismatch.json"}
    for path in sorted((SAMPLE_DIR / "identity" / "invalid").glob("*.json")):
        payload = load_json(path)
        validator = inactive_validator if path.name.startswith("inactive-") else identity_validator
        errs = schema_errors(validator, payload)
        expect_schema_fail = path.name not in semantic_only
        if expect_schema_fail:
            check(f"identity-invalid/{path.name}/rejected", bool(errs), "schema 未拒绝该反例")
        else:
            check(f"identity-invalid/{path.name}/schema-pass", not errs, "; ".join(errs))
            if not errs:
                # 语义层必须拒绝
                sem = semantic_identity_invariants(path.name, payload)
                check(
                    f"identity-invalid/{path.name}/semantic-rejected",
                    bool(sem),
                    "schema 通过但跨字段语义未识别差异",
                )

    # ---- 请求体正反样本 ----
    request_defs = requests_schema["$defs"]
    for path in sorted((SAMPLE_DIR / "request").glob("*.json")):
        payload = load_json(path)
        is_invalid = ".invalid." in path.name
        # 文件名前缀映射到 $def
        if path.name.startswith("login"):
            def_name = "login"
        elif path.name.startswith("switch-tenant"):
            def_name = "switch_tenant"
        elif path.name.startswith("renew"):
            def_name = "renew"
        elif path.name.startswith("introspect"):
            def_name = "introspect"
        elif path.name.startswith("runtime-ticket"):
            def_name = "runtime_ticket"
        elif path.name.startswith("sso-exchange"):
            def_name = "sso_exchange"
        validator = Draft202012Validator(request_defs[def_name], format_checker=FORMAT_CHECKER)
        errs = schema_errors(validator, payload)
        if is_invalid:
            check(f"request-invalid/{path.name}/rejected", bool(errs), "; ".join(errs))
        else:
            check(f"request-valid/{path.name}/accepted", not errs, "; ".join(errs))

    # ---- 额外 C12 断言：inactive 信封不允许携带 active 身份细节 ----
    inactive_bad = load_json(SAMPLE_DIR / "identity" / "invalid" / "inactive-with-identity-leak.json")
    errs = schema_errors(inactive_validator, inactive_bad)
    check("c12/inactive-envelope-no-identity", bool(errs), "inactive 信封泄漏身份未被 schema 拦截")

    # ---- OpenAPI 3.1 文档自校验 ----
    with OPENAPI_PATH.open(encoding="utf-8") as fh:
        spec = yaml.safe_load(fh)
    try:
        validate_openapi(spec)
        check("openapi/3.1/spec-valid", True)
    except Exception as exc:  # noqa: BLE001
        check("openapi/3.1/spec-valid", False, f"{type(exc).__name__}: {exc}")

    # ---- 关键端点必须出现在 OpenAPI 中 ----
    required_paths = [
        "/v1/auth/login", "/v1/auth/logout", "/v1/auth/logout-all", "/v1/auth/me",
        "/v1/auth/tenants", "/v1/auth/switch-tenant", "/v1/auth/change-password",
        "/v1/auth/renew", "/v1/auth/menus",
        "/v1/internal/identity/introspect", "/v1/internal/runtime-tickets",
        "/v1/internal/sso/exchange", "/v1/sso/authorize",
        "/web-api/csrf", "/web-api/auth/login", "/web-api/auth/me",
        "/web-api/sso/start", "/web-api/sso/callback",
    ]
    missing = [p for p in required_paths if p not in spec.get("paths", {})]
    check("openapi/required-paths", not missing, f"缺失路径: {missing}")

    for line in passes:
        print(line)
    for line in failures:
        print(line, file=sys.stderr)
    print(f"\n{len(passes)} passed, {len(failures)} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
