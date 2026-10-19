#!/usr/bin/env python3
"""通过正常登录与切企业读回 root 的实时 Agent 业务许可。

只读：登录、列出本人企业、逐个切换、读取 /v1/auth/me；不写数据库、不修改口令。
口令只从环境变量 IAM_ROOT_PASSWORD 或交互式 getpass 读取，不写入输出、日志或证据文件。
输出仅包含企业、权限码、修订与缺失项，不含 access_token。

用法：
  IAM_ROOT_PASSWORD='...' python3 scripts/verify-root-entitlements.py \
      --output docs/reviews/evidence/run/.../formal-root-readback.json

必需：现有 root 的可用口令（IAM 当前登录策略要求 8..256 字符）。
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import urllib.error
import urllib.request

REQUIRED = [
    "agent:business:basic-qa:use",
    "agent:business:data-analysis:use",
    "agent:business:intelligent-tracing:use",
    "agent:operations:read",
    "agent:metrics:read",
    "agent:content:read",
]


def call(base: str, method: str, path: str, body=None, token: str | None = None):
    data = None if body is None else json.dumps(body).encode("utf-8")
    request = urllib.request.Request(base + path, data=data, method=method)
    request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as exc:
        payload = exc.read().decode("utf-8", "replace")
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError:
            parsed = {"raw": payload[:500]}
        return exc.code, parsed


def emit(output: dict, path: str | None) -> None:
    text = json.dumps(output, ensure_ascii=False, indent=2)
    print(text)
    if path:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:19100")
    parser.add_argument("--account", default=os.environ.get("IAM_ROOT_ACCOUNT", "root"))
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    password = os.environ.get("IAM_ROOT_PASSWORD")
    if not password:
        password = getpass.getpass("root 口令（不落盘）：")
    if not password:
        print("缺少口令，拒绝继续", file=sys.stderr)
        return 2

    status, login = call(args.base_url, "POST", "/v1/auth/login", {
        "account": args.account,
        "password": password,
        "realm": "workforce",
        "audience": "iam-admin",
    })
    if status != 200:
        emit({
            "ok": False,
            "stage": "login",
            "status": status,
            "error": login,
            "note": "若为 password 不合法，说明现有短口令不满足 IAM 登录 8..256 字符策略；"
                    "本脚本不会修改口令。",
        }, args.output)
        return 2

    token = login["access_token"]
    identity = login["identity"]
    status, tenants = call(args.base_url, "GET", "/v1/auth/tenants", token=token)
    if status != 200:
        emit({"ok": False, "stage": "tenants", "status": status, "error": tenants}, args.output)
        return 2

    results = []
    ctx = identity["session"]["ctx_version"]
    for item in tenants:
        if item.get("member_status") != "active" or item.get("status") != "active":
            continue
        status, switched = call(args.base_url, "POST", "/v1/auth/switch-tenant", {
            "tenant_id": item["tenant_id"],
            "expected_ctx_version": ctx,
        }, token=token)
        if status != 200:
            results.append({"tenant": item.get("code"), "status": status, "switched": False,
                            "ok": False})
            continue
        ctx = switched["session"]["ctx_version"]
        status, me = call(args.base_url, "GET", "/v1/auth/me", token=token)
        if status != 200:
            results.append({"tenant": item.get("code"), "status": status, "me": False})
            continue
        permissions = sorted(set(me.get("permissions", [])))
        missing = [code for code in REQUIRED if code not in permissions]
        results.append({
            "tenant": item.get("code"),
            "tenant_id": item.get("tenant_id"),
            "permissions": permissions,
            "missing": missing,
            "revisions": me.get("revisions"),
            "ok": not missing,
        })

    ok = bool(results) and all(row.get("ok") for row in results)
    output = {
        "ok": ok,
        "account": args.account,
        "required_permissions": REQUIRED,
        "tenants": results,
        "note": "仅正常登录/切企业/me 读回；未修改口令或会话时效，输出不含令牌。",
    }
    emit(output, args.output)
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
