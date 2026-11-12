#!/usr/bin/env python3
"""把多个 ProxyIP 库聚合进来，判真家宽、按地区拆分、出合并订阅。

数据源（多源合并，去重后统一复核）：
  1. 776771.xyz（GFW Radar）        https://776771.xyz/all.txt
  2. Xiaobei09/proxyip 的 -RES- 池   data/valid/all_premium.txt（上游已筛"真实住宅"，但我们仍自己重判）
  3. Xiaobei09/proxyip 全池          data/valid/all.txt（1.7 万条，本地只留「-RES/-MOB 且带 -CN 标记」
                                    即上游实测大陆可达的住宅/移动出口；premium 只是它的前 10%，全池能多捞 1400 多条）
  4. MarinaAqua/ProxyIP              ProxyList.txt（2.7 万行 CSV：ip,port,CC,ISP，用 ISP 列首筛家宽）
  5. InconigtoVPN/ProxyIP            proxyList.txt（1.8 万行，同格式）

判定口径（自己重判，不轻信上游标签）：
1. 机房品牌词先拦：ip-api 的 hosting 标记对小主机商经常失灵（它们把自己注册成 ISP），
   所以再用 Oracle / AWS / DigitalOcean / Leaseweb / VPS 商名等关键词硬拦一层
2. 家宽只认正面证据：PTR 或 ISP/ASN 文本命中家用线路命名习惯（hinet/dynamic/pppoe/fixed…）
   或家用运营商名（Chunghwa、KPN、Ziggo、Comcast、AT&T…）
3. TCP 实测 —— 连不上的直接不发

不做「没被标成机房就算家宽」的兜底：实测那样会把注册成 ISP 的 VPS 商全收进来，
标 1098 条家宽里只有 201 条是真的，这个坑已经在 2026-11-11 踩过并修掉。

产物（写进 OUT_DIR/proxyip/）：
  all.txt           全部有效节点，家宽优先
  residential.txt   只要真家宽
  mobile.txt        移动网络里的真家宽（上游 -MOB 且通过家宽判定），为 0 就不出
  <cc>.txt          按国家/地区拆（hk/tw/jp/kr/sg/us/de/nl…），家宽优先
  index.json        统计、来源明细与链接清单
  index.html        上面这些的网页版
另外若 OUT_DIR/nodes.txt 存在，会额外生成 OUT_DIR/mix.txt = SSTP 节点 + 真家宽 ProxyIP。

环境变量：
  OUT_DIR        输出站点根（默认 _merged）
  SITE_URL       兜底用（所有上游都拉不到时读本站上一版）
  PROXYIP_SRC    本地文件路径，逗号分隔；给了就不联网拉上游（调试用）
  VERIFY_CONC    TCP 并发（默认 60）
  PTR_CONC       PTR 并发（默认 30）
  INCLUDE_CN     '1' 才保留中国大陆的 IP（默认剔除，因为我们只要海外出口）
  MAX_CANDIDATES 候选上限（默认 6000），超了按「住宅优先 + uptime 高」截断，防止 CI 超时
"""
from __future__ import annotations

import collections
import json
import os
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import requests

OUT = Path(os.environ.get("OUT_DIR", "_merged"))
SITE = os.environ.get("SITE_URL", "https://xa-rgb.github.io/gate").rstrip("/")
SRC_OVERRIDE = os.environ.get("PROXYIP_SRC", "").strip()
VERIFY_CONC = int(os.environ.get("VERIFY_CONC", "60"))
PTR_CONC = int(os.environ.get("PTR_CONC", "30"))
INCLUDE_CN = os.environ.get("INCLUDE_CN", "") == "1"
MAX_CANDIDATES = int(os.environ.get("MAX_CANDIDATES", "6000"))
MIRROR_DIR = os.environ.get("MIRROR_DIR", "").strip()

RAW = "https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/valid"


def cn_reachable(tag: str) -> bool:
    """上游用 V4/V6 之后的 CN / CNH 段标记「大陆实测可达」，必须只在这段里找，
    否则会把 `🇭🇰HK←CN-电信` 这种「出口地是 CN」误判成可达标记。"""
    m = re.search(r"-V[46]-(.*)$", tag)
    if not m:
        return False
    segs = m.group(1).split("-")
    return "CN" in segs or "CNH" in segs


def keep_cn_res(remark: str) -> bool:
    """全池只收：上游标 residential / mobile，且带大陆可达标记。"""
    up = remark.upper()
    if "-RES" not in up and "-MOB" not in up:
        return False
    return cn_reachable(up)


def keep_csv_res(isp: str) -> bool:
    """CSV 源带 ISP 列，先用名字粗筛（省掉 ip-api 额度），过筛的才进后续核验。
    ISP 列本身有错标（实测把 Azure 段标成 1&1），所以后面还要 ip-api + PTR 复核。"""
    return classify({"isp": isp, "hosting": False}, "")[0] == "家宽"


SOURCES = [
    {"name": "gfw-radar", "url": "https://776771.xyz/all.txt", "fmt": "list"},
    {"name": "xiaobei-res", "url": f"{RAW}/all_premium.txt", "fmt": "list"},
    {"name": "xiaobei-full", "url": f"{RAW}/all.txt", "fmt": "list", "keep": keep_cn_res},
    # 两个 CSV 源（ip,port,CC,ISP）合计 4.5 万行；首筛靠 ISP 列，能捞出 370+ 条 ISP 名像家宽的
    {"name": "marina-aqua",
     "url": "https://raw.githubusercontent.com/MarinaAqua/ProxyIP/refs/heads/main/ProxyList.txt",
     "fmt": "csv", "keep": keep_csv_res},
    {"name": "inconigto",
     "url": "https://raw.githubusercontent.com/InconigtoVPN/ProxyIP/refs/heads/main/proxyList.txt",
     "fmt": "csv", "keep": keep_csv_res},
]
LINE_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})(?:#(.*))?$")
CSV_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\s*,\s*(\d{1,5})\s*,\s*([A-Za-z]{0,2})\s*,\s*(.*)$")
UPTIME_RE = re.compile(r"-U(\d{1,3})")
# 之前只看是不是 443，CSV 源带上来一堆高位端口，8443 得同等待遇
PREFERRED_PORTS = (443, 8443)

# 出现即判机房（优先级最高）。ip-api 的 hosting 标记对小主机商经常失灵，
# 它们把自己注册成 ISP，所以必须再加一层「机房品牌词」硬拦。
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
    # 骨干网/批发转售，不是家用线路（Telia 本身是运营商，但 Telia Carrier 是骨干）
    "cogent", "zayo", "hurricane electric", "telia carrier", "carrier", "lumen",
    "ntt america", "pccw global", "global crossing", "level3", "level 3",
)
# 正面证据：家用宽带线路的命名习惯 + 各地区典型家用运营商。
# 只认这些，不认「没被标成机房」——否则那些注册成 ISP 的 VPS 商会被误收。
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

COUNTRY_ZH = {
    "HK": "香港", "TW": "台湾", "JP": "日本", "KR": "韩国", "SG": "新加坡",
    "US": "美国", "GB": "英国", "DE": "德国", "FR": "法国", "CA": "加拿大",
    "AU": "澳大利亚", "NL": "荷兰", "RU": "俄罗斯", "VN": "越南", "TH": "泰国",
    "MY": "马来西亚", "PH": "菲律宾", "IN": "印度", "ID": "印尼", "IT": "意大利",
    "ES": "西班牙", "SE": "瑞典", "CH": "瑞士", "BR": "巴西", "AE": "阿联酋",
    "TR": "土耳其", "PL": "波兰", "FI": "芬兰", "NO": "挪威", "DK": "丹麦",
    "IE": "爱尔兰", "AT": "奥地利", "BE": "比利时", "CZ": "捷克", "LV": "拉脱维亚",
    "HR": "克罗地亚", "RO": "罗马尼亚", "UA": "乌克兰", "ZA": "南非", "MX": "墨西哥",
    "AR": "阿根廷", "CL": "智利", "NZ": "新西兰", "PT": "葡萄牙", "GR": "希腊",
    "DO": "多米尼加", "KZ": "哈萨克斯坦", "GE": "格鲁吉亚", "BD": "孟加拉",
    "MU": "毛里求斯", "BG": "保加利亚", "MD": "摩尔多瓦", "AM": "亚美尼亚",
    "EE": "爱沙尼亚", "CY": "塞浦路斯", "CN": "中国大陆",
}


def log(section: str, msg: str) -> None:
    print(f"[{section}] {msg}", flush=True)


_MIRRORED: dict[str, dict] = {}


def mirror(text: str, source: str, url: str) -> None:
    """把拉到的原文存一份到站点 /src/，好让本地工具直接取。
    因为 raw.githubusercontent.com 在国内是 SNI 阻断的，本地拿不到源；而自己的域名能直连。"""
    _MIRRORED[source] = {"file": f"{source}.txt", "url": url, "bytes": len(text)}
    if not MIRROR_DIR:
        return
    try:
        p = Path(MIRROR_DIR) / f"{source}.txt"
        p.parent.mkdir(parents=True, exist_ok=True)
        head = (f"# source: {url}\n"
                f"# fetched: {datetime.now(timezone.utc):%Y-%m-%dT%H:%M:%SZ}  bytes: {len(text)}\n")
        p.write_text(head + text, encoding="utf-8", newline="\n")
        log("镜像", f"{source:14s} -> {p.name}（{len(text) // 1024} KB）")
    except Exception as exc:  # noqa: BLE001
        log("镜像", f"{source} 写失败（{type(exc).__name__}）")


# ---------------------------------------------------------------------------
# 抓取与解析
# ---------------------------------------------------------------------------
def parse_list(text: str, source: str, keep=None) -> list[dict]:
    out = []
    skipped = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = LINE_RE.match(line)
        if not m:
            continue
        remark = (m.group(3) or "").strip()
        if keep is not None and not keep(remark):
            skipped += 1
            continue
        up = remark.upper()
        mu = UPTIME_RE.search(up)
        out.append({
            "endpoint": f"{m.group(1)}:{m.group(2)}",
            "ip": m.group(1),
            "port": int(m.group(2)),
            "remark": remark,
            "source": source,
            "res_hint": "-RES" in up,
            "mob_hint": "-MOB" in up,
            "uptime": int(mu.group(1)) if mu else -1,
        })
    if keep is not None:
        log("源", f"{source:12} 按「住宅/移动 + 大陆可达」过滤，丢弃 {skipped} 条")
    return out


def parse_csv_list(text: str, source: str, keep=None) -> list[dict]:
    """CSV 源：`ip,port,CC,ISP`。keep 收的是 ISP 列，不是备注。"""
    out = []
    skipped = 0
    for raw in text.splitlines():
        m = CSV_RE.match(raw.strip())
        if not m:
            continue
        ip, port, cc, isp = m.group(1), m.group(2), m.group(3).upper(), m.group(4).strip()
        if keep is not None and not keep(isp):
            skipped += 1
            continue
        out.append({
            "endpoint": f"{ip}:{port}",
            "ip": ip,
            "port": int(port),
            "remark": f"{cc}-{isp}",
            "source": source,
            "res_hint": True,      # 已按 ISP 名过筛
            "mob_hint": False,
            "uptime": -1,
        })
    if keep is not None:
        log("源", f"{source:12} 按 ISP 名筛家宽，丢弃 {skipped} 条")
    return out


def read_one(url: str, source: str, keep=None, fmt: str = "list") -> list[dict]:
    for attempt in (1, 2):
        try:
            if not url.startswith("http"):
                text = Path(url.replace("file://", "")).read_text(encoding="utf-8")
            else:
                resp = requests.get(url, timeout=60, headers={"user-agent": "gate-aggregator"})
                resp.raise_for_status()
                text = resp.text
            mirror(text, source, url)
            rows = parse_csv_list(text, source, keep) if fmt == "csv" else parse_list(text, source, keep)
            if rows:
                res = sum(1 for r in rows if r["res_hint"])
                mob = sum(1 for r in rows if r["mob_hint"])
                log("源", f"{source:12} {url.split('/')[-1]:20} → {len(rows):4} 条（RES {res} / MOB {mob}）")
                return rows
            log("源", f"{source} 解析出 0 条")
            return []
        except Exception as exc:  # noqa: BLE001
            log("源", f"{source} 第 {attempt} 次失败（{type(exc).__name__}）")
            time.sleep(2)
    return []


def fetch_sources() -> list[dict]:
    if SRC_OVERRIDE:
        targets = [{"name": f"local-{i + 1}", "url": p.strip(), "fmt": "list"}
                   for i, p in enumerate(SRC_OVERRIDE.split(",")) if p.strip()]
    else:
        targets = SOURCES
    rows: list[dict] = []
    for cfg in targets:
        rows.extend(read_one(cfg["url"], cfg["name"], cfg.get("keep"), cfg.get("fmt", "list")))

    # 全部上游都失败时，退回本站上一版
    if not rows:
        log("源", "所有上游均失败，尝试本站上一版兜底")
        rows = read_one(f"{SITE}/proxyip/all.txt?t={int(time.time())}", "self-fallback")

    merged: dict[str, dict] = {}
    for r in rows:
        prev = merged.get(r["endpoint"])
        if prev is None:
            merged[r["endpoint"]] = r
        else:
            prev["res_hint"] = prev["res_hint"] or r["res_hint"]
            prev["mob_hint"] = prev["mob_hint"] or r["mob_hint"]
            prev["uptime"] = max(prev["uptime"], r["uptime"])
            if r["source"] not in prev["source"]:
                prev["source"] = f"{prev['source']}+{r['source']}"
    log("合并", f"原始 {len(rows)} 条 → 去重 {len(merged)} 条")

    final = list(merged.values())
    if len(final) > MAX_CANDIDATES:
        # 上游暴涨时的兜底：住宅优先、uptime 高的先测，保证 CI 时长可控
        final.sort(key=lambda r: (not r["res_hint"], -r["uptime"]))
        log("合并", f"候选 {len(final)} 条超上限 {MAX_CANDIDATES}，按住宅/uptime 截断")
        final = final[:MAX_CANDIDATES]
    return final


# ---------------------------------------------------------------------------
# 归属、反查、连通性
# ---------------------------------------------------------------------------
def enrich_geo(rows: list[dict]) -> dict[str, dict]:
    fields = "status,country,countryCode,city,isp,org,as,hosting,mobile"
    geo: dict[str, dict] = {}
    ips = list({r["ip"] for r in rows})
    total = (len(ips) + 99) // 100
    for i in range(0, len(ips), 100):
        chunk = ips[i:i + 100]
        for attempt in (1, 2, 3):
            try:
                resp = requests.post("http://ip-api.com/batch", params={"fields": fields},
                                     json=chunk, timeout=45)
                data = resp.json()
                if not isinstance(data, list):  # 额度用尽时返回的是 {"message": ...}
                    raise RuntimeError(str(data)[:80])
                for ip, item in zip(chunk, data):
                    geo[ip] = item if isinstance(item, dict) else {}
                log("归属", f"批次 {i // 100 + 1}/{total}: {len(data)} 条")
                break
            except Exception as exc:  # noqa: BLE001
                if attempt == 3:
                    log("归属", f"批次 {i // 100 + 1} 三次失败（{type(exc).__name__}），该批按未知处理")
                else:
                    time.sleep(15)  # 免费额度 15 批/分钟，撞限流就歇一轮
        if i + 100 < len(ips):
            time.sleep(4.5)
    return geo


def lookup_ptr(ip: str) -> str:
    rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    try:
        resp = requests.get("https://dns.alidns.com/resolve",
                            params={"name": rev, "type": "PTR"}, timeout=8)
        for ans in (resp.json().get("Answer") or []):
            if ans.get("type") == 12:
                return str(ans.get("data", "")).rstrip(".").lower()
    except Exception:  # noqa: BLE001
        pass
    return ""


def enrich_ptr(ips: list[str]) -> dict[str, str]:
    """只对「还没被判成机房」的 IP 做反查，省一大半请求。"""
    with ThreadPoolExecutor(max_workers=PTR_CONC) as pool:
        res = list(pool.map(lambda ip: (ip, lookup_ptr(ip)), ips))
    got = sum(1 for _, v in res if v)
    log("PTR", f"反查 {len(res)} 个，有记录 {got} 个")
    return dict(res)


def tcp_ok(row: dict, timeout: float = 3.0) -> bool:
    sock = socket.socket()
    sock.settimeout(timeout)
    try:
        sock.connect((row["ip"], row["port"]))
        return True
    except Exception:  # noqa: BLE001
        return False
    finally:
        sock.close()


def verify(rows: list[dict]) -> list[dict]:
    with ThreadPoolExecutor(max_workers=VERIFY_CONC) as pool:
        flags = list(pool.map(tcp_ok, rows))
    alive = [r for r, ok in zip(rows, flags) if ok]
    log("连通", f"TCP 可达 {len(alive)}/{len(rows)}")
    return alive


def classify(geo: dict, ptr: str) -> tuple[str, str]:
    """返回 (类型, 证据)。类型只有 '家宽' / '机房'。

    判家宽必须有「正面证据」：PTR 或 ISP/ASN 文本命中家用线路特征。
    不做「没被判成机房就当家宽」的兜底——实测那会把注册成 ISP 的 VPS 商
    （SIA VEESP / ByteVirt / SEBEK 之类）全收进来，标 1098 条家宽里只有 201 条是真的。
    """
    blob = " ".join(str(geo.get(k) or "") for k in ("isp", "org", "as")).lower() + " " + ptr
    if geo.get("hosting") is True:
        return "机房", "ip-api 标记机房"
    hit_dc = next((t for t in DC_HINTS if t in blob), "")
    if hit_dc:
        return "机房", f"机房品牌词:{hit_dc}"
    for token in HOME_HINTS:
        if token in blob:
            where = "PTR" if token in ptr else "ISP"
            return "家宽", f"{where}:{token}"
    return "机房", "无家宽证据"


# ---------------------------------------------------------------------------
# 输出
# ---------------------------------------------------------------------------
def fmt_lines(nodes: list[dict], cc_filter: str | None = None) -> str:
    """备注：国家-家宽|机房-NN-城市。编号按「国家+类型」各自从 01 起，便于对照分地区文件。"""
    counters: dict[tuple[str, str], int] = collections.defaultdict(int)
    out = []
    for n in nodes:
        if cc_filter and n["cc"] != cc_filter:
            continue
        kind = n["kind"]
        key = (n["cc"], kind)
        counters[key] += 1
        remark = f"{n['country_zh']}-{kind}-{counters[key]:02d}"
        if n.get("city"):
            remark += f"-{n['city']}"
        out.append(f"{n['endpoint']}#{remark}")
    return "\n".join(out) + ("\n" if out else "")


def build_index_html(meta: dict) -> str:
    rows = []
    for slug, info in meta["regions"].items():
        rows.append(
            f'<tr><td><a href="/proxyip/{slug}.txt">/proxyip/{slug}.txt</a></td>'
            f'<td>{info["name"]}</td><td>{info["lines"]}</td>'
            f'<td>{info["residential"]}</td></tr>'
        )
    srcs = "".join(
        f'<tr><td>{s["name"]}</td><td>{s["lines"]}</td><td>{s["residential"]}</td></tr>'
        for s in meta["sources"]
    )
    return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ProxyIP 聚合 · 真家宽分地区</title>
<style>
:root{{--bg:#f6f7f9;--card:#fff;--ink:#1a1d21;--dim:#6b7280;--line:#e5e7eb;--acc:#2563eb}}
*{{box-sizing:border-box}}
body{{margin:0;padding:32px 20px;background:var(--bg);color:var(--ink);
font:15px/1.7 -apple-system,"Segoe UI","Microsoft YaHei",sans-serif}}
.wrap{{max-width:780px;margin:0 auto}}
h1{{font-size:20px;font-weight:600;margin:0 0 6px}}
.sub{{color:var(--dim);font-size:13px;margin-bottom:22px}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:10px;
padding:18px 20px;margin-bottom:16px}}
h2{{font-size:14px;font-weight:600;margin:0 0 12px;color:var(--dim);letter-spacing:.04em}}
a{{color:var(--acc);text-decoration:none;font-family:ui-monospace,Consolas,monospace;font-size:13px}}
a:hover{{text-decoration:underline}}
ul{{margin:0;padding-left:18px}}li{{margin:6px 0}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th,td{{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line)}}
th{{color:var(--dim);font-weight:500}}td:nth-child(n+3){{text-align:right;font-variant-numeric:tabular-nums}}
.note{{color:var(--dim);font-size:12.5px;margin-top:10px}}
</style></head><body><div class="wrap">
<h1>ProxyIP 聚合（含真家宽分地区）</h1>
<div class="sub">更新于 {meta["generated_at"]} ｜ 去重候选 {meta["candidates"]} 条 →
存活 {meta["alive"]} 条（家宽 {meta["residential"]} / 机房 {meta["datacenter"]} / 移动 {meta["mobile"]}）</div>

<div class="card"><h2>订阅链接</h2><ul>
<li><a href="/nodes.txt">/nodes.txt</a> — 原 SSTP 节点（不变）</li>
<li><a href="/mix.txt">/mix.txt</a> — <strong>合并版</strong>：SSTP 节点 + 真家宽 ProxyIP</li>
<li><a href="/proxyip/residential.txt">/proxyip/residential.txt</a> — 只真家宽</li>
<li><a href="/proxyip/mobile.txt">/proxyip/mobile.txt</a> — 移动网络出口（家宽/蜂窝）</li>
<li><a href="/proxyip/all.txt">/proxyip/all.txt</a> — 全部（家宽优先，含机房）</li>
</ul></div>

<div class="card"><h2>分地区</h2><table>
<tr><th>链接</th><th>地区</th><th>条数</th><th>其中家宽</th></tr>
{"".join(rows)}
</table></div>

<div class="card"><h2>来源</h2><table>
<tr><th>源</th><th>存活</th><th>其中家宽</th></tr>
{srcs}
</table></div>

<div class="card"><h2>判定口径</h2>
<div class="note"><strong>家宽必须有正面证据</strong>：反向解析域名或 ISP/ASN 名称命中家用线路特征
（hinet / dynamic / pppoe / fixed / broadband 这类命名，或 Chunghwa、KPN、Ziggo、Comcast、AT&amp;T、Vodafone 等家用运营商）；
只要出现 Oracle / AWS / DigitalOcean / Leaseweb / 各类 VPS 商等机房品牌词，或 ip-api 标记为机房，一律归机房。
<em>不做「没被标成机房就算家宽」的兜底</em>——实测那样做会把注册成 ISP 的小 VPS 商全收进来。
全部条目发布前都做过 TCP 连通性实测，连不上的已剔除。上游标称 RES 的准确率为
{meta["upstream_res_agreement"]}（我们只认能证实的那部分）。机房 IP 更适合跑流量，家宽 IP 更适合过风控，按需取用。</div></div>
</div></body></html>
"""


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def main() -> None:
    started = time.time()
    rows = fetch_sources()
    if not rows:
        log("结果", "上游与本站兜底都拿不到数据，本次跳过（保留上一版页面不动）")
        return

    # 源镜像清单：本地工具靠它知道 /src/ 下有哪些原文可取
    if MIRROR_DIR and _MIRRORED:
        write(Path(MIRROR_DIR) / "index.json", json.dumps({
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "note": "原始源的镜像，供本地工具直接取（raw.githubusercontent 在国内被阻断）",
            "files": _MIRRORED,
        }, ensure_ascii=False, indent=2))

    geo = enrich_geo(rows)
    alive = verify(rows)

    # 只对「没被判成机房」的做 PTR，省请求
    need_ptr = [r["ip"] for r in alive if (geo.get(r["ip"]) or {}).get("hosting") is not True]
    ptr = enrich_ptr(need_ptr)

    nodes = []
    for r in alive:
        g = geo.get(r["ip"]) or {}
        cc = (g.get("countryCode") or "").upper() or "??"
        if cc == "CN" and not INCLUDE_CN:
            continue
        kind, evidence = classify(g, ptr.get(r["ip"], ""))
        nodes.append({
            "endpoint": r["endpoint"],
            "ip": r["ip"],
            "port": r["port"],
            "cc": cc,
            "country": g.get("country") or "",
            "country_zh": COUNTRY_ZH.get(cc, g.get("country") or cc),
            "city": (g.get("city") or "").strip(),
            "isp": g.get("isp") or "",
            "asn": g.get("as") or "",
            "ptr": ptr.get(r["ip"], ""),
            "kind": kind,
            "evidence": evidence,
            "mob": r["mob_hint"] or bool(g.get("mobile")),
            "source": r["source"],
            "res_hint": r["res_hint"],
        })

    if not nodes:
        log("结果", "过滤后没有可用节点，本次跳过")
        return

    # 家宽优先 → 地区按节点数降序 → 同国内 443/8443 优先 → IP 稳定排序
    by_cc = collections.Counter(n["cc"] for n in nodes)
    nodes.sort(key=lambda n: (n["kind"] != "家宽", -by_cc[n["cc"]], n["cc"],
                              n["port"] not in PREFERRED_PORTS, n["ip"]))

    res = [n for n in nodes if n["kind"] == "家宽"]
    # 上游 -MOB 标签同样不可靠（会把荷兰的 VPS 也标成移动），必须和「已确认家宽」取交集
    mob = [n for n in nodes if n["mob"] and n["kind"] == "家宽"]
    base = OUT / "proxyip"
    write(base / "all.txt", fmt_lines(nodes))
    write(base / "residential.txt", fmt_lines(res))
    if mob:
        write(base / "mobile.txt", fmt_lines(mob))
        log("产物", f"mobile.txt = 移动网络里的真家宽 {len(mob)} 条")

    region_links = {}
    for cc in sorted(by_cc, key=lambda c: -by_cc[c]):
        if cc == "??":
            continue
        slug = cc.lower()
        text = fmt_lines(nodes, cc)
        write(base / f"{slug}.txt", text)
        region_links[slug] = {
            "code": cc,
            "name": COUNTRY_ZH.get(cc, cc),
            "total": by_cc[cc],
            "residential": sum(1 for n in nodes if n["cc"] == cc and n["kind"] == "家宽"),
            "lines": len([x for x in text.splitlines() if x.strip()]),
        }

    src_stat: dict[str, dict] = {}
    for n in nodes:
        for s in n["source"].split("+"):
            st = src_stat.setdefault(s, {"name": s, "lines": 0, "residential": 0})
            st["lines"] += 1
            if n["kind"] == "家宽":
                st["residential"] += 1

    hinted = [n for n in nodes if n["res_hint"]]
    agree = sum(1 for n in hinted if n["kind"] == "家宽")
    ev_stat = collections.Counter(
        (n["evidence"].split(":")[0] if n["kind"] == "家宽" else "机房")
        for n in nodes
    )

    meta = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "candidates": len(rows),
        "alive": len(nodes),
        "residential": len(res),
        "datacenter": len(nodes) - len(res),
        "mobile": len(mob),
        "sources": sorted(src_stat.values(), key=lambda s: -s["lines"]),
        "upstream_res_agreement": f"{agree}/{len(hinted)}" if hinted else "n/a",
        "evidence": dict(ev_stat),
        "regions": region_links,
        "duration_s": round(time.time() - started, 1),
    }
    write(base / "index.json", json.dumps(meta, ensure_ascii=False, indent=2))
    write(base / "index.html", build_index_html(meta))

    # 合并版：SSTP 节点 + 真家宽 ProxyIP（edgetunnel 两种行都吃）
    nodes_txt = OUT / "nodes.txt"
    if nodes_txt.exists():
        sstp = [ln for ln in nodes_txt.read_text(encoding="utf-8").splitlines() if ln.strip()]
        write(OUT / "mix.txt", "\n".join(sstp) + ("\n" if sstp else "") + fmt_lines(res))
        log("产物", f"mix.txt = SSTP {len(sstp)} 行 + 家宽 {len(res)} 行")

    log("产物", f"全部 {len(nodes)} 条（家宽 {len(res)} / 机房 {len(nodes) - len(res)}），"
                f"地区 {len(region_links)} 个，用时 {time.time() - started:.0f}s")
    if hinted:
        log("校验", f"上游标 RES {len(hinted)} 条，我们判为家宽 {agree} 条"
                    f"（不一致 {len(hinted) - agree} 条）")
    log("产物", f"输出目录 {base}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        # 聚合是加分项，失败不能拖垮整条发布链路
        print(f"::warning::ProxyIP 聚合失败：{type(exc).__name__}: {exc}", flush=True)
        sys.exit(0)
