#!/usr/bin/env python3
"""把 776771.xyz（GFW Radar）的 ProxyIP 库聚合进来，判真家宽、按地区拆分、出合并订阅。

判定口径（三套独立来源交叉，不轻信上游标签）：
1. ip-api.com 的 hosting 标记 —— true 即机房/云主机
2. AliDNS DoH 反查 PTR —— netvigator / ctinets / dynamic-ip 这类是家用宽带；
   imsbiz / business / cloud / vps 这类是商用线或机房，要从「家宽」里踢掉
3. TCP 443 实测 —— 连不上的直接不发

产物（写进 OUT_DIR/proxyip/）：
  all.txt           全部有效节点，家宽优先
  residential.txt   只要真家宽
  <cc>.txt          按国家/地区拆（hk/tw/jp/kr/sg/us…），家宽优先
  index.json        统计与链接清单
另外若 OUT_DIR/nodes.txt 存在，会额外生成 OUT_DIR/mix.txt = SSTP 节点 + 真家宽 ProxyIP。

环境变量：
  OUT_DIR        输出站点根（默认 _merged）
  SITE_URL       兜底用（上游拉不到时读本站上一版）
  PROXYIP_SRC    本地/自定义源，给了就不联网拉 776771（调试用）
  VERIFY_CONC    TCP 并发（默认 60）
  PTR_CONC       PTR 并发（默认 20）
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
SRC = os.environ.get("PROXYIP_SRC", "").strip()
VERIFY_CONC = int(os.environ.get("VERIFY_CONC", "60"))
PTR_CONC = int(os.environ.get("PTR_CONC", "20"))

UPSTREAM = "https://776771.xyz/all.txt"
LINE_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})(?:#(.*))?$")

# PTR 里出现这些词 = 商用线/机房，不能算家宽
BIZ_HINTS = (
    "imsbiz", "business", "biz.", "corp", "datacenter", "data-center", "idc",
    "cloud", "vps", "server", "hosting", "colo", "cdn", "dedicated",
)
# 出现这些词基本可确认为家用宽带
HOME_HINTS = (
    "dynamic", "dhcp", "ppp", "broadband", "netvigator", "ctinets", "hsd1",
    "cable", "fiber", "adsl", "vdsl", "residential", "home",
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
}


def log(section: str, msg: str) -> None:
    print(f"[{section}] {msg}", flush=True)


# ---------------------------------------------------------------------------
# 抓取与解析
# ---------------------------------------------------------------------------
def parse_list(text: str) -> list[dict]:
    out, seen = [], set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = LINE_RE.match(line)
        if not m:
            continue
        key = f"{m.group(1)}:{m.group(2)}"
        if key in seen:
            continue
        seen.add(key)
        out.append({"endpoint": key, "ip": m.group(1), "port": int(m.group(2)),
                    "remark": (m.group(3) or "").strip()})
    return out


def fetch_source() -> list[dict]:
    urls = [SRC] if SRC else [UPSTREAM, f"{SITE}/proxyip/all.txt?t={int(time.time())}"]
    for url in urls:
        for attempt in range(1, 3):
            try:
                if url.startswith("file://") or (SRC and not url.startswith("http")):
                    text = Path(url.replace("file://", "")).read_text(encoding="utf-8")
                else:
                    resp = requests.get(url, timeout=30, headers={"user-agent": "gate-aggregator"})
                    resp.raise_for_status()
                    text = resp.text
                rows = parse_list(text)
                if rows:
                    log("源", f"{url} → {len(rows)} 条")
                    return rows
                log("源", f"{url} 解析出 0 条，换下一个")
                break
            except Exception as exc:  # noqa: BLE001
                log("源", f"{url} 第 {attempt} 次失败（{type(exc).__name__}）")
                time.sleep(2)
    return []


# ---------------------------------------------------------------------------
# 归属与家宽判定
# ---------------------------------------------------------------------------
def enrich_geo(rows: list[dict]) -> dict[str, dict]:
    fields = "status,country,countryCode,city,isp,org,as,hosting,mobile"
    geo: dict[str, dict] = {}
    ips = [r["ip"] for r in rows]
    for i in range(0, len(ips), 100):
        chunk = ips[i:i + 100]
        try:
            resp = requests.post("http://ip-api.com/batch", params={"fields": fields},
                                 json=chunk, timeout=45)
            data = resp.json()
            for ip, item in zip(chunk, data):
                geo[ip] = item if isinstance(item, dict) else {}
            log("归属", f"批次 {i // 100 + 1}: {len(data)} 条")
        except Exception as exc:  # noqa: BLE001
            log("归属", f"批次 {i // 100 + 1} 失败（{type(exc).__name__}），该批按未知处理")
        if i + 100 < len(ips):
            time.sleep(4)  # 免费额度 15 批/分钟
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


def enrich_ptr(rows: list[dict]) -> dict[str, str]:
    with ThreadPoolExecutor(max_workers=PTR_CONC) as pool:
        res = list(pool.map(lambda r: (r["ip"], lookup_ptr(r["ip"])), rows))
    got = sum(1 for _, v in res if v)
    log("PTR", f"有反查记录 {got}/{len(res)}")
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


def classify(row: dict, geo: dict, ptr: str) -> str:
    """返回 '家宽' 或 '机房'。"""
    hosting = geo.get("hosting")
    if hosting is True:
        return "机房"
    if any(h in ptr for h in BIZ_HINTS):
        return "机房"
    if hosting is False:
        # PTR 明说是家用宽带 → 家宽；没 PTR 也按家宽算（库里 hosting=false 的多为住宅/商用线）
        return "家宽"
    # 归属查不到时，只能靠 PTR
    return "家宽" if any(h in ptr for h in HOME_HINTS) else "机房"


# ---------------------------------------------------------------------------
# 输出
# ---------------------------------------------------------------------------
def fmt_lines(nodes: list[dict], cc_filter: str | None = None) -> str:
    """备注格式：国家-家宽|机房-NN-城市。编号按「国家+类型」各自从 01 起，便于对照分地区文件。"""
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
    return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ProxyIP 聚合 · 真家宽分地区</title>
<style>
:root{{--bg:#f6f7f9;--card:#fff;--ink:#1a1d21;--dim:#6b7280;--line:#e5e7eb;--acc:#2563eb}}
*{{box-sizing:border-box}}
body{{margin:0;padding:32px 20px;background:var(--bg);color:var(--ink);
font:15px/1.7 -apple-system,"Segoe UI","Microsoft YaHei",sans-serif}}
.wrap{{max-width:760px;margin:0 auto}}
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
code{{background:#eef1f5;padding:1px 5px;border-radius:4px;font-size:12.5px}}
</style></head><body><div class="wrap">
<h1>ProxyIP 聚合（含真家宽分地区）</h1>
<div class="sub">更新于 {meta["generated_at"]} ｜ 上游候选 {meta["candidates"]} 条 →
存活 {meta["alive"]} 条（家宽 {meta["residential"]} / 机房 {meta["datacenter"]}）</div>

<div class="card"><h2>订阅链接</h2><ul>
<li><a href="/nodes.txt">/nodes.txt</a> — 原 SSTP 节点（不变）</li>
<li><a href="/mix.txt">/mix.txt</a> — <strong>合并版</strong>：SSTP 节点 + 真家宽 ProxyIP</li>
<li><a href="/proxyip/residential.txt">/proxyip/residential.txt</a> — 只真家宽</li>
<li><a href="/proxyip/all.txt">/proxyip/all.txt</a> — 全部（家宽优先，含机房）</li>
</ul></div>

<div class="card"><h2>分地区</h2><table>
<tr><th>链接</th><th>地区</th><th>条数</th><th>其中家宽</th></tr>
{"".join(rows)}
</table></div>

<div class="card"><h2>判定口径</h2>
<div class="note">家宽 = ip-api 机房标记为否 <em>且</em> 反查域名不属于 imsbiz/business/cloud/vps 等商用线；
全部条目在发布前都做过 TCP 连通性实测，连不上的已剔除。机房 IP 更适合跑流量，
家宽 IP 更适合过风控，按需取用。</div></div>
</div></body></html>
"""


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def main() -> None:
    started = time.time()
    rows = fetch_source()
    if not rows:
        log("结果", "上游与本站兜底都拿不到数据，本次跳过（保留上一版页面不动）")
        return

    geo = enrich_geo(rows)
    ptr = enrich_ptr(rows)
    alive = verify(rows)

    nodes = []
    for r in alive:
        g = geo.get(r["ip"]) or {}
        cc = (g.get("countryCode") or "").upper() or "??"
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
            "kind": classify(r, g, ptr.get(r["ip"], "")),
        })

    # 家宽优先 → 地区按节点数降序 → 同国内 443 优先 → IP 稳定排序
    by_cc = collections.Counter(n["cc"] for n in nodes)
    nodes.sort(key=lambda n: (n["kind"] != "家宽", -by_cc[n["cc"]], n["cc"],
                              n["port"] != 443, n["ip"]))

    res = [n for n in nodes if n["kind"] == "家宽"]
    base = OUT / "proxyip"
    write(base / "all.txt", fmt_lines(nodes))
    write(base / "residential.txt", fmt_lines(res))

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

    meta = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "upstream": UPSTREAM,
        "candidates": len(rows),
        "alive": len(nodes),
        "residential": len(res),
        "datacenter": len(nodes) - len(res),
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
    log("产物", f"输出目录 {base}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        # 聚合是加分项，失败不能拖垮整条发布链路
        print(f"::warning::ProxyIP 聚合失败：{type(exc).__name__}: {exc}", flush=True)
        sys.exit(0)
