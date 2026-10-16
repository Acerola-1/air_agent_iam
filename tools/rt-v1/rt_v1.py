#!/usr/bin/env python3
"""rt-v1 运行票据跨语言固定向量工具（Python 侧）。

票据线性格式（与原 Python 消费端一致，非 JWT）：
  base64url({"kid": kid, "p": {"typ": "rt-v1", ...claims}}).base64url(HMAC_SHA256(第一段原文))

generate  生成正向与反向篡改向量 -> out/rt-v1-py-vectors.json
verify    校验 Java 侧票据文件（每行一个票据 + 期望结论）
复跑：
  tools/.venv/bin/python tools/rt-v1/rt_v1.py generate
  tools/.venv/bin/python tools/rt-v1/rt_v1.py verify server/target/rt-v1-java-tokens.json
"""
import base64
import hashlib
import hmac
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "tools" / "rt-v1" / "out"

VECTOR_KID = "vector-1"
VECTOR_SECRET_HEX = "aa" * 32
BODY_ORDER = ["sid", "uid", "tid", "mid", "aud", "iat", "exp", "crev", "urev", "trev", "mrev"]
BODY = {
    "sid": "22222222-2222-4222-8222-222222222222",
    "uid": "11111111-1111-4111-8111-111111111111",
    "tid": "33333333-3333-4333-8333-333333333333",
    "mid": "44444444-4444-4444-8444-444444444444",
    "aud": "langgraph-runtime",
    "iat": 1760400000,
    "exp": 1760400060,
    "crev": 7,
    "urev": 0,
    "trev": 5,
    "mrev": 3,
}


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def _reject_duplicates(pairs):
    seen = set()
    for k, v in pairs:
        if k in seen:
            raise ValueError(f"duplicate field: {k}")
        seen.add(k)
    return dict(pairs)


def _compact(body: dict) -> bytes:
    ordered = {k: body[k] for k in BODY_ORDER}
    extra = set(body) - set(BODY_ORDER)
    if extra:
        raise ValueError(f"unknown fields: {sorted(extra)}")
    return json.dumps(ordered, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def sign(body: dict, kid: str, secret: bytes) -> str:
    payload = {"typ": "rt-v1", **json.loads(_compact(body))}
    encoded = b64url(json.dumps({"kid": kid, "p": payload}, ensure_ascii=False,
                               separators=(",", ":")).encode("utf-8"))
    sig = b64url(hmac.new(secret, encoded.encode("ascii"), hashlib.sha256).digest())
    return f"{encoded}.{sig}"


def verify(ticket: str, kid: str, secret: bytes, expected_aud: str | None = None,
           now: int | None = None) -> tuple[bool, str, dict | None]:
    try:
        parts = ticket.split(".")
        if len(parts) != 2:
            return False, "malformed", None
        body_text, sig_text = parts
        expected_sig = hmac.new(secret, body_text.encode("ascii"), hashlib.sha256).digest()
        if not hmac.compare_digest(b64url_decode(sig_text), expected_sig):
            return False, "bad_signature", None
        envelope = json.loads(b64url_decode(body_text), object_pairs_hook=_reject_duplicates)
        if set(envelope) != {"kid", "p"} or envelope["kid"] != kid:
            return False, "bad_kid", None
        payload = envelope["p"]
        if payload.get("typ") != "rt-v1" or set(payload) != set(BODY_ORDER) | {"typ"}:
            return False, "bad_fields", None
        body = {k: payload[k] for k in BODY_ORDER}
        if expected_aud is not None and body["aud"] != expected_aud:
            return False, "bad_audience", None
        current = int(time.time()) if now is None else now
        if not isinstance(body["iat"], int) or not isinstance(body["exp"], int):
            return False, "bad_time_type", None
        if current >= body["exp"]:
            return False, "expired", None
        if body["iat"] > body["exp"]:
            return False, "iat_after_exp", None
        for k in ("crev", "urev", "trev", "mrev"):
            if not isinstance(body[k], int) or isinstance(body[k], bool) or body[k] < 0:
                return False, f"bad_revision_{k}", None
        if body["crev"] < 1:
            return False, "crev_below_one", None
        return True, "ok", body
    except (ValueError, KeyError, json.JSONDecodeError):
        return False, "malformed", None


def generate() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    secret = bytes.fromhex(VECTOR_SECRET_HEX)
    good = sign(BODY, VECTOR_KID, secret)
    other_secret = bytes.fromhex("bb" * 32)
    tampered_body = dict(BODY, aud="knowledge")
    tampered = sign(tampered_body, VECTOR_KID, secret)
    wrong_kid = sign(BODY, "other-kid", secret)
    expired_body = dict(BODY, iat=100, exp=160)
    expired = sign(expired_body, VECTOR_KID, secret)
    bad_sig_signed = sign(BODY, VECTOR_KID, other_secret)
    mutated = good[:-2] + ("aa" if good[-2:] != "aa" else "bb")
    doc = {
        "format": "rt-v1",
        "signature": "HMAC-SHA256 over original base64url envelope text",
        "kid": VECTOR_KID,
        "secret_hex": VECTOR_SECRET_HEX,
        "audience": "langgraph-runtime",
        "ttl_seconds": 60,
        "body": BODY,
        "vectors": [
            {"name": "valid", "ticket": good, "expect": "ok", "now": BODY["iat"] + 10},
            {"name": "wrong-audience", "ticket": tampered, "expect": "bad_audience", "now": BODY["iat"] + 10},
            {"name": "wrong-kid", "ticket": wrong_kid, "expect": "bad_kid", "now": BODY["iat"] + 10},
            {"name": "expired", "ticket": expired, "expect": "expired", "now": 1000},
            {"name": "wrong-secret-signature", "ticket": bad_sig_signed, "expect": "bad_signature", "now": BODY["iat"] + 10},
            {"name": "mutated-signature", "ticket": mutated, "expect": "bad_signature", "now": BODY["iat"] + 10},
        ],
    }
    target = OUT / "rt-v1-py-vectors.json"
    target.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    for v in doc["vectors"]:
        ok, reason, _ = verify(v["ticket"], VECTOR_KID, secret, "langgraph-runtime", v["now"])
        flag = "OK" if reason == v["expect"] else "MISMATCH"
        print(f"PY  {v['name']:<26} -> {reason} [{flag}]")
    print(f"written: {target}")
    return 0


def verify_java(path: str) -> int:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    secret = bytes.fromhex(doc["secret_hex"])
    failures = 0
    for v in doc["vectors"]:
        ok, reason, body = verify(v["ticket"], doc["kid"], secret, doc.get("audience"), v["now"])
        good = reason == v["expect"]
        if not good:
            failures += 1
        print(f"JAVA {v['name']:<26} -> {reason} [{'OK' if good else 'MISMATCH'}]")
    print(f"java tickets: checked={len(doc['vectors'])} failures={failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "generate":
        sys.exit(generate())
    if len(sys.argv) == 3 and sys.argv[1] == "verify":
        sys.exit(verify_java(sys.argv[2]))
    print(__doc__)
    sys.exit(2)
