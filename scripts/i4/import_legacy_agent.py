#!/usr/bin/env python3
"""将旧 Agent 身份平移到 IAM，保持 UUID、有效口令摘要和显式授权。

仅用于受控维护迁移。默认只读，执行必须提供 --execute；连接串从环境读取，
不复制旧会话，也不按同名账号自动合并。旧摘要无法用于 BCrypt 时原样保留其
不可登录性质，不生成默认密码。源库只读；目标所有新增行在一个事务内提交。
"""

from __future__ import annotations

import argparse
import json
import os
from typing import Any

import psycopg
from psycopg import sql
from psycopg.rows import dict_row

TABLES = (
    "users",
    "tenants",
    "departments",
    "tenant_memberships",
    "permissions",
    "roles",
    "role_permissions",
    "user_roles",
    "membership_roles",
)
KEYS = {
    "role_permissions": ("role_id", "permission_id"),
    "user_roles": ("user_id", "role_id"),
    "membership_roles": ("membership_id", "role_id"),
}


def read_source(conn: psycopg.Connection) -> dict[str, list[dict[str, Any]]]:
    """读取一致的旧身份快照，不修改源数据。"""
    conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
    return {
        table: conn.execute(
            sql.SQL("SELECT * FROM public.{}").format(sql.Identifier(table))
        ).fetchall()
        for table in TABLES
    }


def translated(table: str, row: dict[str, Any]) -> dict[str, Any]:
    """仅转换两套已知 schema 的字段，不赋予新的管理权限。"""
    if table == "users":
        return {
            "id": row["id"],
            "realm": "workforce",
            "account": row["account"],
            "display_name": row["display_name"],
            "password_hash": row["password_hash"],
            "status": "active" if row["is_active"] else "disabled",
            "auth_revision": row["auth_revision"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
    if table == "tenants":
        return {
            key: row[key]
            for key in (
                "id",
                "code",
                "name",
                "status",
                "auth_revision",
                "created_at",
                "updated_at",
            )
        }
    if table == "departments":
        return {
            "id": row["id"],
            "tenant_id": row["tenant_id"],
            "parent_id": None,
            "code": row["dept_code"],
            "name": row["name"],
            "status": "active",
            "created_at": row["created_at"],
            "updated_at": row["created_at"],
        }
    if table == "tenant_memberships":
        return {
            key: row[key]
            for key in (
                "id",
                "tenant_id",
                "user_id",
                "department_id",
                "status",
                "revision",
                "created_at",
                "updated_at",
            )
        }
    if table == "permissions":
        return {
            "id": row["id"],
            "code": row["code"],
            "name_zh": row["name"],
            "scope": "tenant" if row["grantable_to_tenants"] else "platform",
            "grantable_to_tenants": row["grantable_to_tenants"],
            "resource_code": None,
            "status": "active" if row["is_active"] else "disabled",
            "sort": row["sort"],
            "created_at": row["created_at"],
        }
    if table == "roles":
        return {
            "id": row["id"],
            "code": row["code"],
            "scope": row["scope"],
            "tenant_id": row["tenant_id"],
            "name": row["name"],
            "description": row["description"] or "",
            "is_builtin": row["is_system"],
            "status": "active",
            "created_at": row["created_at"],
            "updated_at": row["created_at"],
        }
    return dict(row)


def validate(target: psycopg.Connection, source: dict) -> dict[str, list[dict]]:
    """写入前阻断 UUID、账号、企业编码、角色与权限编码的冲突。"""
    changes: dict[str, list[dict]] = {}
    for table in TABLES:
        desired = [translated(table, row) for row in source[table]]
        existing = target.execute(
            sql.SQL("SELECT * FROM iam.{}").format(sql.Identifier(table))
        ).fetchall()
        keys = KEYS.get(table, ("id",))
        by_key = {tuple(row[k] for k in keys): row for row in existing}
        fresh = []
        for row in desired:
            key = tuple(row[k] for k in keys)
            prior = by_key.get(key)
            if prior:
                comparable = {
                    "users": ("realm", "account"),
                    "tenants": ("code",),
                    "roles": ("scope", "tenant_id", "code"),
                    "permissions": ("code",),
                    "tenant_memberships": ("tenant_id", "user_id"),
                    "departments": ("tenant_id", "code"),
                }.get(table, keys)
                if any(prior[k] != row[k] for k in comparable):
                    raise ValueError(f"{table}: UUID/关系绑定冲突，拒绝自动合并")
                continue
            if table == "users" and any(
                x["realm"] == "workforce" and x["account"] == row["account"]
                for x in existing
            ):
                raise ValueError("users: 同名不同UUID，需显式对账")
            if table in ("tenants", "permissions") and any(
                x["code"] == row["code"] for x in existing
            ):
                raise ValueError(f"{table}: 编码不同UUID，需显式对账")
            if table == "roles" and any(
                x["scope"] == row["scope"]
                and x["tenant_id"] == row["tenant_id"]
                and x["code"] == row["code"]
                for x in existing
            ):
                raise ValueError("roles: 同作用域角色编码冲突")
            fresh.append(row)
        changes[table] = fresh
    return changes


def migrate(source_dsn: str, authority_dsn: str, *, execute: bool = False) -> dict:
    """先全量验证；仅显式执行时在单一 IAM 事务内插入缺失行。"""
    with psycopg.connect(source_dsn, row_factory=dict_row) as source_conn:
        source = read_source(source_conn)
        with psycopg.connect(authority_dsn, row_factory=dict_row) as target:
            target.execute("SELECT iam_auth.set_request_context(NULL,NULL,true)")
            changes = validate(target, source)
            report = {
                "execute": execute,
                "source_counts": {k: len(v) for k, v in source.items()},
                "insert_counts": {k: len(v) for k, v in changes.items()},
                "copies_sessions": False,
                "same_name_merge": False,
            }
            if not execute:
                target.rollback()
                return report
            target.execute("SELECT pg_advisory_xact_lock(169721, 4004)")
            # Revalidate inside the serialized writer transaction.
            changes = validate(target, source)
            for table in TABLES:
                for row in changes[table]:
                    columns = list(row)
                    target.execute(
                        sql.SQL("INSERT INTO iam.{} ({}) VALUES ({})").format(
                            sql.Identifier(table),
                            sql.SQL(",").join(map(sql.Identifier, columns)),
                            sql.SQL(",").join(sql.Placeholder() for _ in columns),
                        ),
                        [row[key] for key in columns],
                    )
            for row in source["departments"]:
                if row["parent_id"] is not None:
                    target.execute(
                        "UPDATE iam.departments SET parent_id=%s WHERE id=%s AND tenant_id=%s",
                        (row["parent_id"], row["id"], row["tenant_id"]),
                    )
            # Source is read-only and a failure rolls back every IAM insertion.
            target.commit()
            report["committed"] = True
            return report


def main() -> int:
    """命令行入口：只输出计数和非秘密原因。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    try:
        report = migrate(
            os.environ["I4_LEGACY_AGENT_DSN"],
            os.environ["I4_AUTHORITY_DSN"],
            execute=args.execute,
        )
    except (KeyError, ValueError, psycopg.Error) as exc:
        # Database exception details can contain credential material; never echo them.
        print(
            json.dumps(
                {
                    "error_type": type(exc).__name__,
                    "committed": False,
                    "error": str(exc)
                    if isinstance(exc, ValueError)
                    else "配置或数据库验证失败",
                },
                ensure_ascii=False,
            )
        )
        return 2
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
