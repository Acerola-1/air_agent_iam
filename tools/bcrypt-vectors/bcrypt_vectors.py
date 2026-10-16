#!/usr/bin/env python3
"""bcrypt $2b$ 跨语言固定向量工具（Python 侧）。

generate    用固定 salt 生成 Python $2b$ 向量 -> out/bcrypt-py-vectors.json
verify-java 校验 Java 侧生成的向量（正确口令通过、错误口令拒绝）
向量内容只含合成口令与哈希；复跑命令：
  tools/.venv/bin/python tools/bcrypt-vectors/bcrypt_vectors.py generate
  tools/.venv/bin/python tools/bcrypt-vectors/bcrypt_vectors.py verify-java server/target/bcrypt-java-vectors.json
"""
import json
import sys
from pathlib import Path

import bcrypt

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "tools" / "bcrypt-vectors" / "out"

SALTS = [
    b"$2b$10$86sNiWmwUpB13rh3OdKpu.",
    b"$2b$10$0Tfl.emyuQWnpCetJnoatO",
    b"$2b$10$F5FvLyFAffHynQlpRCnXw.",
    b"$2b$10$pox8JuGaxP4oIuZitufC2u",
    b"$2b$10$M3HW8pCZHfkRxVMwm2.epu",
    b"$2b$10$hKSQGF9aioTd5imd/XfU3e",
]

P72 = "a" * 72
CASES = [
    ("ascii", "memberA-2026-synthetic"),
    ("chinese", "中文口令-空气知识库-2026"),
    ("multibyte-mixed", "pässwörd-日本語-🔑-Σ"),
    ("exactly-72-bytes", P72),
    ("73-bytes-truncated-to-72", P72 + "b"),
    ("empty", ""),
]
WRONG = ["wrong-password", "中文口令-空气知识库-2027", P72[:71] + "x"]
EQUIVALENT_AFTER_72 = [P72, P72 + "b", P72 + "c"]


def entries():
    for (name, password), salt in zip(CASES, SALTS):
        raw = password.encode("utf-8")
        yield {
            "name": name,
            "password_utf8_hex": raw.hex(),
            "password_length_bytes": len(raw),
            "hash": bcrypt.hashpw(raw, salt).decode("ascii"),
        }


def generate() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    doc = {
        "algorithm": "bcrypt",
        "variant": "$2b$",
        "rounds": 10,
        "encoding": "utf-8",
        "note": "73-bytes 向量用于确认 bcrypt 72 字节截断语义在两侧一致",
        "cases": list(entries()),
        "wrong_passwords_utf8_hex": [w.encode("utf-8").hex() for w in WRONG],
    }
    target = OUT / "bcrypt-py-vectors.json"
    target.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    for c in doc["cases"]:
        print(f"PY  {c['name']:<24} {c['hash']}")
    print(f"written: {target}")
    return 0


def verify_java(path: str) -> int:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    expected = {name: pwd for name, pwd in CASES}
    failures = 0
    checked = 0
    for case in doc["cases"]:
        name = case["name"]
        if name not in expected:
            print(f"FAIL unknown case {name}")
            failures += 1
            continue
        h = case["hash"].encode("ascii")
        ok = bcrypt.checkpw(expected[name].encode("utf-8"), h)
        checked += 1
        if not ok:
            print(f"FAIL correct password rejected: {name}")
            failures += 1
        for wrong in WRONG:
            if bcrypt.checkpw(wrong.encode("utf-8"), h):
                print(f"FAIL wrong password accepted: {name}")
                failures += 1
        if name in ("exactly-72-bytes", "73-bytes-truncated-to-72"):
            for equivalent in EQUIVALENT_AFTER_72:
                if not bcrypt.checkpw(equivalent.encode("utf-8"), h):
                    print(f"FAIL 72-byte truncation equivalence broken: {name}")
                    failures += 1
    print(f"java vectors: checked={checked} failures={failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "generate":
        sys.exit(generate())
    if len(sys.argv) == 3 and sys.argv[1] == "verify-java":
        sys.exit(verify_java(sys.argv[2]))
    print(__doc__)
    sys.exit(2)
