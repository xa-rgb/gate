#!/usr/bin/env python3
"""把最近 N 轮的检测结果合并成一份，并逐个回测剔除已失效的节点。

数据来源：
- 本轮：check.yml 的 Pages 产物（data.json）
- 历史：已发布站点的 history/round-1.json、history/round-2.json

产物沿用上游 vpngate.py 的 build_outputs / build_nodes_text / write_outputs，
所以 data.json 的 schema、nodes.txt 的行格式与上游完全一致，前端不用改。

环境变量：
  CHECK_WORKER   必填，形如 https://check.xxx/check?sstp=vpn:vpn@
  ARTIFACT_DIR   本轮产物目录（默认 _art）
  OUT_DIR        输出目录（默认 _merged）
  SITE_URL       已发布站点根（默认 https://xa-rgb.github.io/gate）
  MERGE_ROUNDS   合并几轮（默认 3）
  VERIFY_CONC    回测并发（默认 24）
"""
from __future__ import annotations

import dataclasses
import json
import os
import shutil
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests


def _find_root() -> Path:
    """本脚本与 vpngate.py 同目录，或在其任意上级目录里。"""
    here = Path(__file__).resolve().parent
    for cand in [here, *here.parents]:
        if (cand / "vpngate.py").exists():
            return cand
    raise SystemExit("找不到 vpngate.py，无法复用上游产物格式")


ROOT = _find_root()
sys.path.insert(0, str(ROOT))
import vpngate  # noqa: E402  上游模块，产物格式以它为准

WORKER = os.environ.get("CHECK_WORKER", "").strip()
ART = Path(os.environ.get("ARTIFACT_DIR", "_art"))
ROUNDS_DIR = Path(os.environ.get("ROUNDS_DIR", "_rounds"))
OUT = Path(os.environ.get("OUT_DIR", "_merged"))
SITE = os.environ.get("SITE_URL", "https://xa-rgb.github.io/gate").rstrip("/")
ROUNDS = max(2, int(os.environ.get("MERGE_ROUNDS", "3")))
CONC = int(os.environ.get("VERIFY_CONC", "24"))
MAX_RES = int(os.environ.get("MAX_RESIDENTIAL_PER_COUNTRY", "40"))
MAX_DC = int(os.environ.get("MAX_DATACENTER_PER_COUNTRY", "15"))


def log(section: str, msg: str) -> None:
    print(f"[{section}] {msg}", flush=True)


def load_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def nodes_by_endpoint(data: dict | None) -> dict[str, dict]:
    """取出某轮里所有成功的节点，按 host:port 去重。"""
    out: dict[str, dict] = {}
    if not data:
        return out
    for group in (data.get("countries") or {}).values():
        for node in group.get("nodes") or []:
            if not node.get("success"):
                continue
            host, port = node.get("host"), node.get("port")
            if not host or not port:
                continue
            out[f"{host}:{port}"] = node
    return out


def fetch_round(index: int) -> dict | None:
    """取第 index 轮（1 = 上一个成功轮）。

    优先读工作流提前下载好的 artifact（确定性最高，不受 Pages CDN 传播延迟影响），
    取不到才退回已发布站点上的 history 快照。
    """
    art = ROUNDS_DIR / str(index)
    if art.exists():
        path = next(art.rglob("data.json"), None)
        if path:
            data = load_json(path)
            if data:
                log("历史", f"round-{index} 取自 artifact（{sum(len(g.get('nodes') or []) for g in data.get('countries', {}).values())} 个节点）")
                return data
    # 加时间戳绕过 Pages 的 CDN 缓存，否则可能拿到上一轮的内容
    url = f"{SITE}/history/round-{index}.json?t={int(time.time())}"
    try:
        resp = requests.get(url, timeout=25, headers={"cache-control": "no-cache"})
        if resp.status_code == 200:
            return resp.json()
        log("历史", f"round-{index} 不可用（HTTP {resp.status_code}），按空轮处理")
    except Exception as exc:  # noqa: BLE001
        log("历史", f"round-{index} 拉取失败（{type(exc).__name__}），按空轮处理")
    return None


def verify(item: tuple[str, dict], session: requests.Session) -> dict | None:
    """回测一个节点；通过则返回 gate 的 node 结构，否则 None。"""
    endpoint, prev = item
    try:
        resp = session.get(f"{WORKER}{endpoint}", timeout=30)
        payload = resp.json()
    except Exception:  # noqa: BLE001
        return None
    if not payload.get("success"):
        return None

    exit_raw = payload.get("exit") or {}
    asn = exit_raw.get("asn") or {}
    org = str(asn.get("org") or asn.get("name") or "")
    residential = vpngate.classify_network(org, exit_raw.get("is_datacenter"))
    cc = (exit_raw.get("country_code") or prev.get("country_code") or "").upper()
    host, port = endpoint.rsplit(":", 1)
    return {
        "host": host,
        "port": int(port),
        "ip": prev.get("ip"),
        "country": exit_raw.get("country") or prev.get("country"),
        "country_code": cc,
        "ping": prev.get("ping"),
        "score": prev.get("score"),
        "protocol": "sstp",
        "link": f"sstp://vpn:vpn@{endpoint}",
        "status": "success",
        "success": True,
        "latency_ms": payload.get("responseTime"),
        "colo": payload.get("colo"),
        "residential": residential,
        "exit": {
            "ip": exit_raw.get("ip"),
            "country": exit_raw.get("country"),
            "country_code": cc,
            "city": exit_raw.get("city"),
            "continent": exit_raw.get("continent"),
            "asn": asn.get("asn"),
            "org": org,
            "is_datacenter": exit_raw.get("is_datacenter"),
        },
    }


def main() -> None:
    if not WORKER:
        raise SystemExit("未设置 CHECK_WORKER")

    started = time.time()

    # 本轮产物（来自 workflow artifact，确定性最高）
    current_path = next(ART.rglob("data.json"), None)
    if current_path is None:
        raise SystemExit(f"在 {ART} 里没找到 data.json（artifact 是否下载成功？）")
    current = load_json(current_path)
    if not current:
        raise SystemExit("本轮 data.json 解析失败")
    src_dir = current_path.parent  # artifact 解包后的站点根

    rounds: list[dict | None] = [current] + [fetch_round(i) for i in range(1, ROUNDS)]
    pools = [nodes_by_endpoint(r) for r in rounds]
    log("合并", "各轮成功率：" + " / ".join(str(len(p)) for p in pools))

    merged: dict[str, dict] = {}
    for pool in pools:
        for endpoint, node in pool.items():
            merged.setdefault(endpoint, node)
    log("合并", f"去重后候选 {len(merged)} 个（来自最近 {ROUNDS} 轮）")

    # 逐个回测，剔除已失效
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(pool_connections=CONC, pool_maxsize=CONC)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=CONC) as pool:
        for node in pool.map(lambda it: verify(it, session), merged.items()):
            if node:
                results.append(node)

    dropped = len(merged) - len(results)
    log("回测", f"通过 {len(results)}，剔除失效 {dropped}")
    if not results:
        raise SystemExit("回测后没有任何存活节点，本次不发布")

    # 用上游函数生成产物
    cfg = dataclasses.replace(
        vpngate.Config.load(),
        public_dir=str(OUT),
        max_residential_per_country=MAX_RES,
        max_datacenter_per_country=MAX_DC,
    )
    data = vpngate.build_outputs(
        results=results,
        raw_count=len(merged),
        sstp_count=len(merged),
        source=f"merged: last {ROUNDS} rounds, re-verified",
        worker_host=str(cfg.worker_base).split("/")[2] if "//" in str(cfg.worker_base) else "unknown",
        duration_s=time.time() - started,
        timed_out=0,
    )

    # 统计口径修正：checked=候选总数，failed=被剔除的失效数
    data["stats"]["checked"] = len(merged)
    data["stats"]["failed"] = dropped

    if OUT.exists():
        shutil.rmtree(OUT)
    # 站点根直接铺平到 OUT（不外挂一层 public/），再让上游函数覆盖三件产物
    shutil.copytree(src_dir, OUT)
    _, _, _, nodes_text = vpngate.write_outputs(data, cfg, list(cfg.edge_hosts))
    lines = [ln for ln in nodes_text.splitlines() if ln.strip()]

    # 轮换历史快照：下一轮的 round-1 就是本轮，round-2 就是上一轮的 round-1
    hist = OUT / "history"
    hist.mkdir(exist_ok=True)
    (hist / "round-1.json").write_text(
        json.dumps(current, ensure_ascii=False, separators=(",", ":")), encoding="utf-8"
    )
    if rounds[1]:
        (hist / "round-2.json").write_text(
            json.dumps(rounds[1], ensure_ascii=False, separators=(",", ":")), encoding="utf-8"
        )

    stats = data["stats"]
    log("产物", f"nodes.txt {len(lines)} 行 / 国家 {stats['countries']} / 住宅 {stats['residential_est']} / 机房 {stats['datacenter_est']}")
    log("产物", f"输出目录 {OUT}")

    summary = os.environ.get("GITHUB_STEP_SUMMARY", "").strip()
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write("### 三轮并集结果\n\n")
            fh.write(f"- 各轮成功数：{' / '.join(str(len(p)) for p in pools)}\n")
            fh.write(f"- 去重候选：{len(merged)}，回测通过 **{len(results)}**，剔除 {dropped}\n")
            fh.write(f"- 发布：nodes.txt **{len(lines)} 行**，{stats['countries']} 个国家/地区\n")


if __name__ == "__main__":
    main()
