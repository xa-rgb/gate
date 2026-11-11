#!/usr/bin/env python3
"""把多个 ProxyIP 库聚合进来，判真家宽、按地区拆分、出合并订阅。

数据源（多源合并，去重后统一复核）：
  1. 776771.xyz（GFW Radar）        https://776771.xyz/all.txt
  2. Xiaobei09/proxyip 的 -RES- 池   data/valid/all_premium.txt（上游已筛"真实住宅"，但我们仍自己重判）

判定口径（三套独立来源交叉，不轻信上游标签）：
1. ip-api.com 的 hosting 标记 —— true 即机房/云主机
2. AliDNS DoH 反查 PTR —— netvigator / ctinets / dynamic-ip 这类是家用宽带；
   imsbiz / business / cloud / vps 这类是商用线或机房，要从「家宽」里踢掉
3. TCP 实测 —— 连不上的直接不发

产物（写进 OUT_DIR/proxyip/）：
  all.txt           全部有效节点，家宽优先
  residential.txt   只要真家宽
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

RAW = "https://raw.githubusercontent.com/Xiaobei09/proxyip/main/data/valid"
SOURCES = [
    ("gfw-radar", "https://776771.xyz/all.txt"),
    ("xiaobei-res", f"{RAW}/all_premium.txt"),
]
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
    "DO": "多米尼加", "KZ": "哈萨克斯坦", "GE": "格鲁吉亚", "BD": "孟加拉",
    "MU": "毛里求斯", "BG": "保加利亚", "MD": "摩尔多瓦", "AM": "亚美尼亚",
    "EE": "爱沙尼亚", "CY": "塞浦路斯", "CN": "中国大陆",
}


def log(section: str, msg: str) -> None:
    print(f"[{section}] {msg}", flush=True)


# ---------------------------------------------------------------------------
# 抓取与解析
# ---------------------------------------------------------------------------
def parse_list(text: str, source: str) -> list[dict]:
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = LINE_RE.match(line)
        if not m:
            continue
        remark = (m.group(3) or "").strip()
        out.append({
            "endpoint": f"{m.group(1)}:{m.group(2)}",
            "ip": m.group(1),
            "port": int(m.group(2)),
            "remark": remark,
            "source": source,
            "res_hint": "-RES" in remark.upper(),
        })
    return out


def read_one(url: str, source: str) -> list[dict]:
    for attempt in (1, 2):
        try:
            if not url.startswith("http"):
                text = Path(url.replace("file://", "")).read_text(encoding="utf-8")
            else:
                resp = requests.get(url, timeout=40, headers={"user-agent": "gate-aggregator"})
                resp.raise_for_status()
                text = resp.text
            rows = parse_list(text, source)
            if rows:
                res = sum(1 for r in rows if r["res_hint"])
                log("源", f"{source:12} {url.split('/')[-1]:20} → {len(rows):4} 条（标 RES {res}）")
                return rows
            log("源", f"{source} 解析出 0 条")
            return []
        except Exception as exc:  # noqa: BLE001
            log("源", f"{source} 第 {attempt} 次失败（{type(exc).__name__}）")
            time.sleep(2)
    return []


def fetch_sources() -> list[dict]:
    targets = ([(f"local-{i + 1}", p.strip()) for i, p in enumerate(SRC_OVERRIDE.split(",")) if p.strip()]
               if SRC_OVERRIDE else SOURCES)
    rows: list[dict] = []
    for name, url in targets:
        rows.extend(read_one(url, name))

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
            if r["source"] not in prev["source"]:
                prev["source"] = f"{prev['source']}+{r['source']}"
    log("合并", f"原始 {len(rows)} 条 → 去重 {len(merged)} 条")
    return list(merged.values())


# ---------------------------------------------------------------------------
# 归属、反查、连通性
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


def classify(geo: dict, ptr: str) -> str:
    """返回 '家宽' 或 '机房'。"""
    if geo.get("hosting") is True:
        return "机房"
    if any(h in ptr for h in BIZ_HINTS):
        return "机房"
    if geo.get("hosting") is False:
        return "家宽"
    return "家宽" if any(h in ptr for h in HOME_HINTS) else "机房"


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

<div class="card"><h2>来源</h2><table>
<tr><th>源</th><th>存活</th><th>其中家宽</th></tr>
{srcs}
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
    rows = fetch_sources()
    if not rows:
        log("结果", "上游与本站兜底都拿不到数据，本次跳过（保留上一版页面不动）")
        return

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
            "kind": classify(g, ptr.get(r["ip"], "")),
            "source": r["source"],
            "res_hint": r["res_hint"],
        })

    if not nodes:
        log("结果", "过滤后没有可用节点，本次跳过")
        return

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

    src_stat: dict[str, dict] = {}
    for n in nodes:
        for s in n["source"].split("+"):
            st = src_stat.setdefault(s, {"name": s, "lines": 0, "residential": 0})
            st["lines"] += 1
            if n["kind"] == "家宽":
                st["residential"] += 1

    hinted = [n for n in nodes if n["res_hint"]]
    agree = sum(1 for n in hinted if n["kind"] == "家宽")

    meta = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "candidates": len(rows),
        "alive": len(nodes),
        "residential": len(res),
        "datacenter": len(nodes) - len(res),
        "sources": sorted(src_stat.values(), key=lambda s: -s["lines"]),
        "upstream_res_agreement": f"{agree}/{len(hinted)}" if hinted else "n/a",
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
