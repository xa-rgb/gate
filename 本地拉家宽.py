#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""本地拉家宽 —— 从你自己的域名取源 / 取结果，在本机实测「到底哪些家宽 IP 我能连上」。

为什么要在本地跑：
  · 站上那份清单是 GitHub 的海外 runner 判的、也是海外测的；海外能连 ≠ 大陆能连。
    实测大陆移动侧命中率只有四成左右，高位端口更低。
  · raw.githubusercontent.com 在国内是 SNI 阻断的，本地根本拿不到那些源。
    所以：判定交给海外流水线正确，**可达性交给本机**，而源和结果都走你自己的域名。

两种取数方式（默认全开，三条通道合并去重）：
  ① 直连原始源   —— 776771 在国内能直连；GitHub 的 raw 有时能连有时被断
  ② 域名镜像源   —— 直连失败时走 https://<你的域名>/src/ ，海外流水线每轮存下来的原文
  ③ 站上结果     —— https://<你的域名>/proxyip/all.txt ，已经判定过家宽/机房的成品

  python 本地拉家宽.py                    # 三条通道全用，最全
  python 本地拉家宽.py --result-only      # 只用站上结果，最快（约 30 秒）
  python 本地拉家宽.py --res-only         # 输出只留家宽
  python 本地拉家宽.py --no-direct        # 不试直连，直接走域名（网络差时更快）
  python 本地拉家宽.py --src marina-aqua,inconigto   # 只跑指定源

结果推回链接（可选）：
  set GH_TOKEN=xxx   然后  python 本地拉家宽.py --push
  推完约 1 分钟，手机/别的设备就能用 https://<你的域名>/local/all.txt
"""
from __future__ import annotations

import argparse
import base64
import csv
import io
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

BASE = os.environ.get("GATE_BASE", "https://gate.96857462.xyz").rstrip("/")
UA = {"User-Agent": "local-residential-gate/2.0"}
STD_PORTS = (443, 8443)
LINE_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})(?:#(.*))?$")
CSV_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\s*,\s*(\d{1,5})\s*,\s*([A-Za-z]{0,2})\s*,\s*(.*)$")

# ---- 家宽判定词表：与 aggregate_proxyip.py 保持同步 ----
DC_HINTS = (
    "oracle", "amazon", "aws", "google", "microsoft", "azure", "digitalocean", "linode",
    "vultr", "ovh", "hetzner", "contabo", "cloudflare", "tencent", "alibaba", "aliyun",
    "huawei", "ucloud", "leaseweb", "m247", "psychz", "colocrossing", "choopa", "hostinger",
    "hosthatch", "kamatera", "ionos", "godaddy", "namecheap", "hosting", "host", "vps",
    "cloud", "colo", "datacenter", "data center", "data-center", "dedicated", "server",
    "backbone", "transit", "cdn", "ip-ptr", "hosted-by", "senko", "waicore", "delis",
    "nktelecom", "global connectivity", "anarchy lab", "baykov", "golden hightech", "idc",
    "solutions", "technologies", "webhorizon", "quicksrv", "fdcservers", "cgi global",
    "capdecision", "ibcs", "veesp", "bytevirt", "sebek", "timeweb", "my-vm", "smartnet",
    "cogent", "zayo", "hurricane electric", "telia carrier", "carrier", "lumen",
    "ntt america", "pccw global", "global crossing", "level3", "level 3",
)
HOME_HINTS = (
    "dynamic", "dhcp", "pppoe", "ppp", "adsl", "vdsl", "ftth", "fiber", "fibre",
    "broadband", "cable", "residential", "home", ".pool", "hinet", "hi-net", "fixed",
    "chunghwa", "kbro", "seednet", "tbc", "netvigator", "hkbn", "hgc", "i-cable",
    "korea telecom", "kt corp", "sk broadband", "lg u+", "sk telecom", "dlive", "sejong",
    "kddi", "softbank", "biglobe", "plala", "ocn", "so-net", "j:com", "nuro", "commufa",
    "comcast", "verizon", "at&t", "charter", "spectrum", "cox", "centurylink", "frontier",
    "windstream", "mediacom", "suddenlink", "altice", "optimum", "fios",
    "bell canada", "telus", "rogers", "shaw", "videotron", "cogeco",
    "bt ", "virgin media", "sky broadband", "talktalk", "plusnet",
    "deutsche telekom", "vodafone", "1&1", "unitymedia", "kabel", "netcologne", "m-net",
    "orange", "free sas", "sfr", "bouygues", "kpn", "ziggo", "xs4all", "telfort",
    "telefonica", "telecom italia", "fastweb", "proximus", "telenet", "telia", "elisa",
    "telenor", "swisscom", "sunrise", "cosmote", "ote ", "upc", "liberty global",
    "vectra", "inea", "multimedia polska", "netia", "orange polska", "t-mobile",
    "telstra", "optus", "tpg", "iinet", "spark nz", "2degrees", "vocus",
    "singtel", "starhub", "m1 limited", "myrepublic", "viewqwest",
)


def log(msg: str = "") -> None:
    print(msg, flush=True)


def http_get(url: str, timeout: int = 40) -> str:
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def fetch_text(url: str, tries: int = 3) -> str:
    last = None
    for i in range(tries):
        try:
            return http_get(url)
        except Exception as exc:  # noqa: BLE001
            last = exc
            time.sleep(1.2 * (i + 1))
    raise RuntimeError(f"{type(last).__name__}: {last}")


# ---------------------------------------------------------------------------
# 筛选（本地版，与海外流水线同一套口径）
# ---------------------------------------------------------------------------
def is_home_by_isp(text: str) -> bool:
    """有正面证据才算家宽：先排机房品牌词，再要命中家用线路/运营商特征。"""
    t = (text or "").lower()
    if not t:
        return False
    if any(k in t for k in DC_HINTS):
        return False
    return any(k in t for k in HOME_HINTS)


def cn_reachable(tag: str) -> bool:
    m = re.search(r"-V[46]-(.*)$", tag)
    if not m:
        return False
    segs = m.group(1).split("-")
    return "CN" in segs or "CNH" in segs


def keep_xiaobei_res(remark: str) -> bool:
    up = remark.upper()
    if "-RES" not in up and "-MOB" not in up:
        return False
    return cn_reachable(up)


# ---------------------------------------------------------------------------
# 解析
# ---------------------------------------------------------------------------
def row(ip: str, port: str, region: str, kind: str, remark: str, src: str) -> dict:
    return {"ip": ip, "port": int(port), "endpoint": f"{ip}:{port}",
            "region": region or "未知", "kind": kind, "remark": remark, "src": src}


def parse_list_text(text: str, src: str, kind_hint: str = "") -> list[dict]:
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = LINE_RE.match(line)
        if not m:
            continue
        remark = (m.group(3) or "").strip()
        parts = remark.split("-")
        region = parts[0] if parts else ""
        kind = "家宽" if "家宽" in remark else ("机房" if "机房" in remark else kind_hint)
        out.append(row(m.group(1), m.group(2), region, kind or "未知", remark, src))
    return out


def parse_csv_text(text: str, src: str) -> list[dict]:
    out = []
    for r in csv.reader(io.StringIO(text)):
        if len(r) < 4:
            continue
        ip, port, cc, isp = r[0].strip(), r[1].strip(), r[2].strip().upper(), ",".join(r[3:]).strip()
        if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", ip):
            continue
        try:
            p = int(port)
        except ValueError:
            continue
        out.append(row(ip, str(p), cc, "家宽" if is_home_by_isp(isp) else "机房",
                       f"{cc}-{isp}", src))
    return out


# ---------------------------------------------------------------------------
# 取源：直连原始源优先，连不上就走域名镜像；站上已判定的结果也一并并进来
# ---------------------------------------------------------------------------
RAW = "https://raw.githubusercontent.com"
SRC_PLAN = [
    # (名字, 原始直连地址, 解析方式, 过滤)
    ("gfw-radar", "https://776771.xyz/all.txt", "list", None),
    ("xiaobei-res", f"{RAW}/Xiaobei09/proxyip/main/data/valid/all_premium.txt", "list", None),
    ("xiaobei-full", f"{RAW}/Xiaobei09/proxyip/main/data/valid/all.txt", "list", keep_xiaobei_res),
    ("marina-aqua", f"{RAW}/MarinaAqua/ProxyIP/refs/heads/main/ProxyList.txt", "csv", "isp"),
    ("inconigto", f"{RAW}/InconigtoVPN/ProxyIP/refs/heads/main/proxyList.txt", "csv", "isp"),
]


def load_region_map() -> dict[str, str]:
    try:
        meta = json.loads(fetch_text(f"{BASE}/proxyip/index.json"))
        return {v.get("name", ""): k for k, v in (meta.get("regions") or {}).items() if v.get("name")}
    except Exception:  # noqa: BLE001
        return {}


def fetch_dual(name: str, direct: str, use_direct: bool, use_mirror: bool) -> tuple[str, str] | None:
    """先直连原始源，失败再走域名镜像。返回 (正文, 实际来源标签)。"""
    if use_direct:
        try:
            return http_get(direct, timeout=25), "直连"
        except Exception as exc:  # noqa: BLE001
            short = type(exc).__name__
            if isinstance(exc, urllib.error.HTTPError):
                short = f"HTTP {exc.code}"
            log(f"      直连失败（{short}），改走域名镜像")
    if use_mirror:
        for url in (f"{BASE}/src/{name}.txt", f"{BASE}/src/{name}.txt?t={int(time.time())}"):
            try:
                return http_get(url, timeout=40), "域名镜像"
            except Exception:  # noqa: BLE001
                continue
    return None


def gather_all(use_direct: bool, use_mirror: bool, use_result: bool,
               only_src: list[str] | None = None,
               use_sources: bool = True) -> list[dict]:
    """把三条通道都拉下来合并去重：站上结果 > 原始源（直连/镜像）。

    kind 的优先级：站上结果里已经判定过，最可信；源里的按本地口径现判。
    """
    merged: dict[str, dict] = {}

    def absorb(rows: list[dict], prefer_existing: bool) -> int:
        new = 0
        for r in rows:
            old = merged.get(r["endpoint"])
            if old is None:
                merged[r["endpoint"]] = r
                new += 1
            elif prefer_existing and old["kind"] == "未知" and r["kind"] != "未知":
                old["kind"] = r["kind"]
        return new

    # 通道 1：站上已判定结果（家宽优先）
    if use_result:
        try:
            text = fetch_text(f"{BASE}/proxyip/all.txt", tries=2)
            rows = parse_list_text(text, "站点结果")
            n = absorb(rows, prefer_existing=False)
            log(f"  [结果] 站点已判定清单      {len(rows):6d} 行，新增 {n:6d}")
        except Exception as exc:  # noqa: BLE001
            log(f"  [结果] 站点清单取不到（{type(exc).__name__}），跳过")

    # 通道 2：原始源，直连优先、镜像兜底
    for name, direct, fmt, keep in (SRC_PLAN if use_sources else []):
        if only_src and name not in only_src:
            continue
        got = fetch_dual(name, direct, use_direct, use_mirror)
        if not got:
            log(f"  [源]   {name:14s} 直连和镜像都拿不到，跳过")
            continue
        text, via = got
        raw_rows = parse_csv_text(text, name) if fmt == "csv" else parse_list_text(text, name)
        if keep == "isp":
            kept = [r for r in raw_rows if r["kind"] == "家宽"]
        elif keep is not None:
            kept = [r for r in raw_rows if keep(r["remark"])]
        else:
            kept = raw_rows
        n = absorb(kept, prefer_existing=True)
        log(f"  [源]   {name:14s} 原文 {len(raw_rows):6d} 行 -> 筛出 {len(kept):5d}，新增 {n:5d}  ({via})")

    log(f"  合并去重后候选 {len(merged)}")
    return list(merged.values())


# ---------------------------------------------------------------------------
# 实测
# ---------------------------------------------------------------------------
def tcp_probe(r: dict, timeout: float, tries: int) -> dict:
    best = None
    for _ in range(tries):
        t0 = time.time()
        s = None
        try:
            s = socket.create_connection((r["ip"], r["port"]), timeout=timeout)
            rtt = round((time.time() - t0) * 1000)
            best = rtt if best is None else min(best, rtt)
        except Exception:  # noqa: BLE001
            pass
        finally:
            if s is not None:
                try:
                    s.close()
                except Exception:  # noqa: BLE001
                    pass
    out = dict(r)
    out["rtt"] = best
    return out


def probe_all(rows: list[dict], conc: int, timeout: float, tries: int) -> list[dict]:
    total, done, t0 = len(rows), 0, time.time()
    out = []
    with ThreadPoolExecutor(max_workers=conc) as pool:
        for r in pool.map(lambda x: tcp_probe(x, timeout, tries), rows):
            out.append(r)
            done += 1
            if done % 200 == 0 or done == total:
                ok = sum(1 for x in out if x["rtt"] is not None)
                log(f"  测 {done}/{total}  可连 {ok}  {time.time() - t0:.0f}s")
    return out


# ---------------------------------------------------------------------------
# 输出 / 推送
# ---------------------------------------------------------------------------
def fmt(rows: list[dict]) -> str:
    return "\n".join(f"{r['endpoint']}#{r['remark']}-{r['rtt']}ms" for r in rows) + ("\n" if rows else "")


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def push_github(outdir: Path, repo: str, token: str, prefix: str = "local") -> None:
    """把结果写进仓库 local/ 目录。工作流会把它并进站点，于是有自己的域名可用。
    只推顶层几个文件——61 个地区文件每次都提交太吵，需要时本地重新跑一遍就有。"""
    api = f"https://api.github.com/repos/{repo}/contents"
    hdr = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}

    def put(remote: str, content: bytes) -> None:
        sha = None
        try:
            with urllib.request.urlopen(urllib.request.Request(f"{api}/{remote}", headers=hdr), timeout=30) as r:
                sha = json.loads(r.read().decode()).get("sha")
        except urllib.error.HTTPError as e:
            if e.code != 404:
                raise
        body = {"message": f"data: 本机实测家宽 {datetime.now():%Y-%m-%d %H:%M}",
                "content": base64.b64encode(content).decode(), "branch": "main"}
        if sha:
            body["sha"] = sha
        req = urllib.request.Request(f"{api}/{remote}", data=json.dumps(body).encode(),
                                     headers={**hdr, "Content-Type": "application/json"}, method="PUT")
        with urllib.request.urlopen(req, timeout=60) as r:
            log(f"  [推送] {remote}  HTTP {r.status}")

    for p in sorted(outdir.iterdir()):
        if p.is_file():
            put(f"{prefix}/{p.name}", p.read_bytes())


# ---------------------------------------------------------------------------
def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="从自己的域名+原始源取数据，在本机实测家宽")
    ap.add_argument("--no-direct", action="store_true", help="不直连原始源，只用域名镜像")
    ap.add_argument("--no-mirror", action="store_true", help="不用域名镜像，只直连原始源")
    ap.add_argument("--no-result", action="store_true", help="不并入站上已判定的结果")
    ap.add_argument("--result-only", action="store_true", help="只用站上已判定的结果（最快）")
    ap.add_argument("--src", default="", help="只跑指定源，逗号分隔：gfw-radar,xiaobei-res,xiaobei-full,marina-aqua,inconigto")
    ap.add_argument("--res-only", action="store_true", help="输出只留家宽")
    ap.add_argument("--std-ports", action="store_true", help="只测 443/8443")
    ap.add_argument("--max-rtt", type=int, default=800, help="RTT 上限毫秒，0=不限（默认 800）")
    ap.add_argument("--conc", type=int, default=48, help="并发（默认 48）")
    ap.add_argument("--timeout", type=float, default=4.0, help="单次连接超时秒（默认 4）")
    ap.add_argument("--tries", type=int, default=3, help="每条重试次数（默认 3）")
    ap.add_argument("--out", default="", help="输出目录")
    ap.add_argument("--push", action="store_true", help="推回仓库 local/（需 GH_TOKEN）")
    ap.add_argument("--repo", default="xa-rgb/gate", help="推送目标仓库")
    a = ap.parse_args(argv)

    only_src = [s.strip() for s in a.src.split(",") if s.strip()] or None
    log(f"== 第 1 步：取数据（直连原始源 {'关' if a.no_direct or a.result_only else '开'} / "
        f"域名镜像 {'关' if a.no_mirror else '开'} / 站上结果 {'关' if a.no_result else '开'}）")
    rows = gather_all(use_direct=not a.no_direct and not a.result_only,
                      use_mirror=not a.no_mirror and not a.result_only,
                      use_result=not a.no_result,
                      only_src=only_src,
                      use_sources=not a.result_only)

    if not rows:
        log("一条都没拉到：先确认域名能打开，以及站点上是否已有对应文件")
        return 1

    if a.std_ports:
        before = len(rows)
        rows = [r for r in rows if r["port"] in STD_PORTS]
        log(f"  只留 443/8443：{before} -> {len(rows)}")
    if not rows:
        log("过滤后为空")
        return 1

    log(f"\n== 第 2 步：本机 TCP 实测 {len(rows)} 条（并发 {a.conc}，每条 {a.tries} 次）")
    rows = probe_all(rows, a.conc, a.timeout, a.tries)

    alive = [r for r in rows if r["rtt"] is not None]
    kept = [r for r in alive if (not a.max_rtt or r["rtt"] <= a.max_rtt)]
    slow, dead = len(alive) - len(kept), len(rows) - len(alive)
    if a.res_only:
        before = len(kept)
        kept = [r for r in kept if r["kind"] == "家宽"]
        log(f"  只留家宽：{before} -> {len(kept)}")
    log(f"\n== 结果：可连 {len(alive)}/{len(rows)}；保留 {len(kept)}（丢慢 {slow}、丢不通 {dead}）")

    kept.sort(key=lambda r: (r["kind"] != "家宽", r["rtt"]))
    res = [r for r in kept if r["kind"] == "家宽"]

    rmap = load_region_map()
    by_region: dict[str, list[dict]] = {}
    for r in kept:
        by_region.setdefault(r["region"] or "未知", []).append(r)
    log("  地区：" + " ".join(f"{k}{len(v)}"
                          for k, v in sorted(by_region.items(), key=lambda kv: -len(kv[1]))[:12]))

    outdir = Path(a.out) if a.out else Path(__file__).resolve().parent / f"本地家宽-{datetime.now():%Y%m%d-%H%M}"
    head = (f"# 本机实测可用 {datetime.now():%Y-%m-%d %H:%M}  "
            f"共 {len(kept)} 条（家宽 {len(res)} / 机房 {len(kept) - len(res)}）  "
            f"丢不通 {dead} 丢慢 {slow}\n")
    write(outdir / "all.txt", head + fmt(kept))
    write(outdir / "residential.txt", head + fmt(res))
    for name, lst in by_region.items():
        slug = rmap.get(name) or re.sub(r"[^A-Za-z0-9]", "", name) or "unknown"
        write(outdir / "by-region" / f"{slug}.txt", head + fmt(lst))
    with open(outdir / "detail.csv", "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["endpoint", "ip", "port", "region", "kind", "rtt_ms", "remark", "src"])
        for r in kept:
            w.writerow([r["endpoint"], r["ip"], r["port"], r["region"], r["kind"], r["rtt"],
                        r["remark"], r["src"]])

    rtts = sorted(r["rtt"] for r in kept)
    if rtts:
        log(f"  RTT：最快 {rtts[0]}ms  中位 {rtts[len(rtts) // 2]}ms  最慢 {rtts[-1]}ms")
    # 端口分档：高位端口在家用宽带上命中极低（实测 341 条高位只活 1 条），单独列出来
    buckets = {"443": 0, "8443": 0, "其他<10000": 0, ">=10000": 0}
    for r in kept:
        p = r["port"]
        buckets["443" if p == 443 else "8443" if p == 8443 else ">=10000" if p >= 10000 else "其他<10000"] += 1
    log("  端口分档：" + "  ".join(f"{k} {v}" for k, v in buckets.items()))
    log(f"\n== 产物：{outdir}")
    log(f"   all.txt {len(kept)} 行 / residential.txt {len(res)} 行 / by-region {len(by_region)} 个地区")

    if a.push:
        token = os.environ.get("GH_TOKEN", "").strip()
        if not token:
            for cand in (Path(__file__).resolve().parent / ".ghtoken",
                         Path(__file__).resolve().parent.parent / "gate-deploy" / ".ghtoken"):
                if cand.exists():
                    token = cand.read_text(encoding="utf-8").strip()
                    break
        if not token:
            log("\n  [推送跳过] 没 token：设 GH_TOKEN，或把 token 放到脚本同目录 .ghtoken")
            return 0
        log(f"\n== 第 3 步：推回 {a.repo} 的 local/")
        try:
            push_github(outdir, a.repo, token)
            log(f"  约 1 分钟后可用：{BASE}/local/all.txt")
        except Exception as exc:  # noqa: BLE001
            log(f"  [推送失败] {type(exc).__name__}: {exc}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        log("\n已中断")
        sys.exit(130)
