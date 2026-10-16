#!/usr/bin/env python3
"""C25 暖连接 introspection 性能采集：100 样本×3轮，并发 1/10/30。

每个工作线程持有一条到回环服务的 keep-alive HTTP/1.1 连接（暖连接）。
只记录状态码/耗时/active 计数；不打印令牌与凭据。
"""
import argparse
import base64
import http.client
import json
import statistics
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

TARGET_PATH = "/v1/internal/identity/introspect"


def pct(sorted_vals, q):
    if not sorted_vals:
        return 0.0
    k = (len(sorted_vals) - 1) * q
    f = int(k)
    c = min(f + 1, len(sorted_vals) - 1)
    if f == c:
        return sorted_vals[f]
    return sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f)


class Worker:
    def __init__(self, host, port, auth_header, body):
        self.conn = http.client.HTTPConnection(host, port, timeout=10)
        self.auth = auth_header
        self.body = body
        self.lock = threading.Lock()

    def once(self):
        t0 = time.perf_counter_ns()
        try:
            with self.lock:
                self.conn.request(
                    "POST", TARGET_PATH, body=self.body,
                    headers={"Authorization": self.auth,
                             "Content-Type": "application/json"})
                resp = self.conn.getresponse()
                raw = resp.read()
                code = resp.status
            active = False
            try:
                active = json.loads(raw).get("active") is True
            except Exception:
                pass
            return (time.perf_counter_ns() - t0) / 1_000_000.0, code, active, None
        except Exception as e:
            try:
                self.conn.close()
                self.conn = http.client.HTTPConnection(
                    self.conn.host, self.conn.port, timeout=10)
            except Exception:
                pass
            return (time.perf_counter_ns() - t0) / 1_000_000.0, 0, False, type(e).__name__


def burst(workers, n):
    """在给定工作线程集合上发 n 个请求，尽量均匀分配，记录每条延迟。"""
    lat, codes, actives, errors = [], 0, 0, []
    idx = 0

    def task(i):
        return workers[i % len(workers)].once()

    with ThreadPoolExecutor(max_workers=len(workers)) as ex:
        for ms, code, active, err in ex.map(task, range(n)):
            lat.append(ms)
            if code != 200:
                codes += 1
            if active:
                actives += 1
            if err:
                errors.append(err)
    lat.sort()
    return {
        "n": n, "non_200": codes, "active": actives,
        "p50": round(pct(lat, 0.50), 3),
        "p95": round(pct(lat, 0.95), 3),
        "p99": round(pct(lat, 0.99), 3),
        "mean": round(statistics.fmean(lat), 3),
        "max": round(max(lat), 3),
        "errors": sorted(set(errors)),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:19100")
    ap.add_argument("--client-id", required=True)
    ap.add_argument("--secret", required=True)
    ap.add_argument("--token", required=True)
    ap.add_argument("--audience", default="iam-admin")
    ap.add_argument("--samples", type=int, default=100)
    ap.add_argument("--rounds", type=int, default=3)
    args = ap.parse_args()

    host_port = args.base.replace("http://", "").split("/")[0]
    host, port = host_port.split(":")
    port = int(port)
    auth = "Basic " + base64.b64encode(
        f"{args.client_id}:{args.secret}".encode()).decode()
    body = json.dumps({"subject_token": args.token,
                       "audience": args.audience})

    results = {"base": args.base, "samples": args.samples,
               "rounds": args.rounds, "runs": []}
    print(f"目标 {args.base}{TARGET_PATH}  暖连接 keep-alive HTTP/1.1  "
          f"样本/轮={args.samples} 轮={args.rounds}")
    print(f"{'并发':>4} {'轮':>2} {'非200':>6} {'active':>7} "
          f"{'P50ms':>8} {'P95ms':>8} {'P99ms':>8} {'均值':>8} {'最大':>8}")

    for conc in (1, 10, 30):
        workers = [Worker(host, port, auth, body) for _ in range(conc)]
        warm = burst(workers, max(30, conc))
        if warm["non_200"]:
            print(f"预热失败: {warm}", file=sys.stderr)
            sys.exit(2)
        for r in range(1, args.rounds + 1):
            stat = burst(workers, args.samples)
            results["runs"].append({"concurrency": conc, "round": r, **stat})
            print(f"{conc:>4} {r:>2} {stat['non_200']:>6} {stat['active']:>7} "
                  f"{stat['p50']:>8} {stat['p95']:>8} {stat['p99']:>8} "
                  f"{stat['mean']:>8} {stat['max']:>8}")
        for w in workers:
            w.conn.close()

    # 汇总
    for conc in (1, 10, 30):
        rs = [r for r in results["runs"] if r["concurrency"] == conc]
        allp = [x for r in rs for x in (r["p50"],)]  # 占位，避免误读
        p50s = [r["p50"] for r in rs]
        p95s = [r["p95"] for r in rs]
        p99s = [r["p99"] for r in rs]
        print(f"汇总 c={conc}: P50 范围 {min(p50s)}–{max(p50s)}ms  "
              f"P95 范围 {min(p95s)}–{max(p95s)}ms  "
              f"P99 范围 {min(p99s)}–{max(p99s)}ms  "
              f"核验次数={sum(r['n'] for r in rs)}")
    print("JSON_RESULT " + json.dumps(results, ensure_ascii=False))


if __name__ == "__main__":
    main()
