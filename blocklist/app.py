import os
import re
import ipaddress
import time
from collections import defaultdict
from typing import Dict, Set, List, Tuple, Any

import requests
import yaml
from fastapi import FastAPI, Query
from fastapi.responses import PlainTextResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

app = FastAPI(title="blocklist-compiler")

CONFIG_DIR = os.getenv("BLOCKLIST_CONF_DIR", "conf")
LISTS_PATH = os.path.join(CONFIG_DIR, "lists.yaml")
WHITELIST_PATH = os.path.join(CONFIG_DIR, "whitelist.yaml")

MIKROTIK_LIST_NAME = os.getenv("MIKROTIK_LIST_NAME", "blacklist")
GLOBAL_COMMENT = os.getenv("GLOBAL_COMMENT", "compiled-blocklist")

AGGREGATE_THRESHOLD = int(os.getenv("AGGREGATE_THRESHOLD", "50"))
FETCH_TIMEOUT = int(os.getenv("FETCH_TIMEOUT", "20"))
CACHE_TTL = int(os.getenv("CACHE_TTL", "600"))

_custom_cache: Dict[Tuple[str, str, Tuple[int, ...], Tuple[str, ...]], Dict[str, object]] = {}


def _normalize_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v != 0
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "y", "on")
    return False


def load_sources_from_yaml() -> List[dict]:
    try:
        with open(LISTS_PATH, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except FileNotFoundError:
        print(f"[WARN] lists.yaml not found at {LISTS_PATH}, no sources loaded.")
        return []
    except Exception as e:
        print(f"[WARN] Failed to load lists.yaml ({LISTS_PATH}): {e}")
        return []

    if not isinstance(data, dict) or "sources" not in data:
        print(f"[WARN] lists.yaml has no 'sources' key or wrong structure.")
        return []

    raw_sources = data.get("sources", [])
    if not isinstance(raw_sources, list):
        print("[WARN] lists.yaml 'sources' is not a list.")
        return []

    sources: List[dict] = []
    next_id = 1
    for src in raw_sources:
        if not isinstance(src, dict):
            continue

        sid = src.get("id")
        if not isinstance(sid, int):
            sid = next_id
            next_id += 1
        else:
            next_id = max(next_id, sid + 1)

        name = (src.get("name") or f"source-{sid}").strip()
        url = (src.get("url") or "").strip()
        if not url:
            print(f"[WARN] Source id={sid} has empty URL, skipped.")
            continue

        is_active = _normalize_bool(src.get("is_active", True))
        delimiter = src.get("delimiter", "\n")
        cidr_mode = src.get("cidr_mode", "32")
        timeout_hours = int(src.get("timeout_hours", 2))
        comment = (src.get("comment") or name or GLOBAL_COMMENT).strip() or GLOBAL_COMMENT

        sources.append(
            {
                "id": int(sid),
                "name": name,
                "url": url,
                "is_active": is_active,
                "delimiter": delimiter,
                "cidr_mode": cidr_mode,
                "timeout_hours": timeout_hours,
                "comment": comment,
            }
        )

    print(f"[INFO] Loaded {len(sources)} sources from {LISTS_PATH}")
    return sources


ALL_SOURCES: List[dict] = load_sources_from_yaml()


def get_active_sources() -> List[dict]:
    return [s for s in ALL_SOURCES if _normalize_bool(s.get("is_active", True))]


def load_yaml_whitelist() -> List[ipaddress.IPv4Network]:
    nets: List[ipaddress.IPv4Network] = []
    try:
        with open(WHITELIST_PATH, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except FileNotFoundError:
        print(f"[INFO] No whitelist.yaml found at {WHITELIST_PATH}, skipping.")
        return []
    except Exception as e:
        print(f"[WARN] Failed to load whitelist.yaml ({WHITELIST_PATH}): {e}")
        return []

    cidrs: List[str] = []
    if isinstance(data, dict) and "whitelist" in data and isinstance(data["whitelist"], list):
        cidrs = data["whitelist"]
    elif isinstance(data, list):
        cidrs = data
    else:
        print(f"[WARN] whitelist.yaml format not recognised at {WHITELIST_PATH}")
        return []

    for entry in cidrs:
        if not isinstance(entry, str):
            continue
        entry = entry.strip()
        if not entry:
            continue
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            print(f"[WARN] Invalid YAML whitelist CIDR skipped: {entry}")
            continue

        if not isinstance(net, ipaddress.IPv4Network):
            print(f"[WARN] IPv6 whitelist not supported (skipped): {entry}")
            continue

        nets.append(net)

    print(f"[INFO] Loaded {len(nets)} IPv4 networks from whitelist.yaml.")
    return nets


YAML_WHITELIST_NETS: List[ipaddress.IPv4Network] = load_yaml_whitelist()


def fetch_list(url: str) -> str:
    try:
        timeout = FETCH_TIMEOUT
        if timeout <= 0:
            timeout = 5
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()
        return resp.text
    except Exception as e:
        print(f"[WARN] Source skipped (timeout or error): {url} -> {e}")
        return ""


def extract_ipv4s_from_text(text: str, delimiter: str | None) -> List[ipaddress.IPv4Address]:
    ips: List[ipaddress.IPv4Address] = []
    if not delimiter:
        delimiter = "\n"

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        token = line
        if delimiter:
            parts = line.split(delimiter, 1)
            token = parts[0].strip()

        if not token:
            continue

        try:
            ip = ipaddress.IPv4Address(token)
            ips.append(ip)
            continue
        except ValueError:
            pass

        try:
            iface = ipaddress.IPv4Interface(token)
            ips.append(iface.ip)
            continue
        except ValueError:
            pass

    return ips


def normalize_list_name(raw: str | None) -> str:
    if not raw:
        return MIKROTIK_LIST_NAME
    raw = raw.strip()
    if not raw:
        return MIKROTIK_LIST_NAME
    cleaned = re.sub(r"[^A-Za-z0-9_\-]", "_", raw)
    if not cleaned:
        return MIKROTIK_LIST_NAME
    return cleaned[:63]


def parse_timeout(raw: str | None) -> str:
    DEFAULT_TIMEOUT = "02:00:00"
    MAX_SECONDS = 3 * 24 * 3600

    if raw is None or not raw.strip():
        return DEFAULT_TIMEOUT

    txt = raw.strip()

    days = 0
    h = m = s = 0

    mobj = re.match(r"^(\d+)d\s*(\d{1,2}):(\d{2}):(\d{2})$", txt)
    if mobj:
        days = int(mobj.group(1))
        h = int(mobj.group(2))
        m = int(mobj.group(3))
        s = int(mobj.group(4))
    else:
        mobj = re.match(r"^(\d{1,2}):(\d{2}):(\d{2})$", txt)
        if not mobj:
            raise ValueError("Invalid timeout format")
        h = int(mobj.group(1))
        m = int(mobj.group(2))
        s = int(mobj.group(3))

    total = days * 86400 + h * 3600 + m * 60 + s
    if total <= 0 or total > MAX_SECONDS:
        raise ValueError("Timeout exceeds maximum (3d) or is zero")

    days, rem = divmod(total, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)

    if days:
        return f"{days}d {h:02d}:{m:02d}:{s:02d}"
    else:
        return f"{h:02d}:{m:02d}:{s:02d}"


def make_error_script() -> str:
    return ':log error "Custom blocklist link is wrong, please check online !"' + "\n"


def compile_custom_blocklist(
    list_name: str,
    timeout: str,
    source_ids: List[int],
    whitelist_nets: List[ipaddress.IPv4Network],
) -> str:
    if not source_ids:
        raise ValueError("No sources selected")

    sources = get_active_sources()
    src_by_id = {int(s["id"]): s for s in sources}
    selected = []
    for sid in source_ids:
        if sid in src_by_id:
            selected.append(src_by_id[sid])
    if not selected:
        raise ValueError("Unknown sources")

    wl_nets = whitelist_nets or []

    all_ips: Set[ipaddress.IPv4Address] = set()
    explicit_nets24: Set[ipaddress.IPv4Network] = set()
    explicit_nets24_comment: Dict[ipaddress.IPv4Network, str] = {}
    ip_first_comment: Dict[ipaddress.IPv4Address, str] = {}

    for src in selected:
        url = src["url"]
        delim = src.get("delimiter") or "\n"
        cidr_mode = src.get("cidr_mode") or "32"
        source_comment = (src.get("name") or src.get("comment") or GLOBAL_COMMENT).strip() or GLOBAL_COMMENT

        text = fetch_list(url)
        if not text:
            continue

        ips = extract_ipv4s_from_text(text, delim)

        if cidr_mode == "24":
            for ip in ips:
                if any(ip in net for net in wl_nets):
                    continue
                net = ipaddress.IPv4Network(f"{ip.exploded}/24", strict=False)
                if net not in explicit_nets24:
                    explicit_nets24.add(net)
                    explicit_nets24_comment[net] = source_comment
        else:
            for ip in ips:
                if any(ip in net for net in wl_nets):
                    continue
                if ip not in all_ips:
                    all_ips.add(ip)
                    ip_first_comment.setdefault(ip, source_comment)

    per_net24: Dict[ipaddress.IPv4Network, Set[ipaddress.IPv4Address]] = defaultdict(set)
    for ip in all_ips:
        net24 = ipaddress.IPv4Network(f"{ip.exploded}/24", strict=False)
        per_net24[net24].add(ip)

    aggregated_nets24: Set[ipaddress.IPv4Network] = set()
    aggregated_ips: Set[ipaddress.IPv4Address] = set()
    aggregated_nets24_comment: Dict[ipaddress.IPv4Network, str] = {}

    for net, ips_set in per_net24.items():
        if len(ips_set) >= AGGREGATE_THRESHOLD:
            aggregated_nets24.add(net)
            aggregated_ips.update(ips_set)
            first_ip = next(iter(ips_set))
            aggregated_nets24_comment[net] = ip_first_comment.get(first_ip, GLOBAL_COMMENT)

    remaining_ips: Set[ipaddress.IPv4Address] = set()
    for ip in all_ips:
        ip_net24 = ipaddress.IPv4Network(f"{ip.exploded}/24", strict=False)
        if ip_net24 in explicit_nets24:
            continue
        if ip_net24 in aggregated_nets24:
            continue
        remaining_ips.add(ip)

    final_nets24: Set[ipaddress.IPv4Network] = set(explicit_nets24) | set(aggregated_nets24)

    lines: List[str] = []
    lines.append("/ip firewall address-list")
    lines.append(f'remove [find list="{list_name}"]')

    for net in sorted(final_nets24, key=lambda n: (int(n.network_address), n.prefixlen)):
        if net in explicit_nets24_comment:
            comment = explicit_nets24_comment[net]
        else:
            comment = aggregated_nets24_comment.get(net, GLOBAL_COMMENT)
        lines.append(
            f'add list={list_name} address={net.with_prefixlen} comment="{comment}" timeout={timeout}'
        )

    for ip in sorted(remaining_ips, key=int):
        comment = ip_first_comment.get(ip, GLOBAL_COMMENT)
        lines.append(
            f'add list={list_name} address={ip.exploded} comment="{comment}" timeout={timeout}'
        )

    return "\n".join(lines) + "\n"


def get_custom_script_cached(
    list_name: str,
    timeout: str,
    source_ids: List[int],
    whitelist_nets: List[ipaddress.IPv4Network],
) -> str:
    key = (
        list_name,
        timeout,
        tuple(sorted(source_ids)),
        tuple(sorted(str(net) for net in whitelist_nets)),
    )
    now = time.time()
    entry = _custom_cache.get(key)
    if entry and now - float(entry.get("ts", 0.0)) <= CACHE_TTL:
        return entry["data"]

    script = compile_custom_blocklist(list_name, timeout, source_ids, whitelist_nets)
    _custom_cache[key] = {"ts": now, "data": script}
    return script


app.mount("/html", StaticFiles(directory="html"), name="html")

DEFAULT_INDEX_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>WIFX Blocklist</title>
</head>
<body>
<header>
  <h1>WIFX Blocklist</h1>
</header>
<main>
  {{SOURCES}}
</main>
</body>
</html>
"""


def render_index_html() -> str:
    sources = get_active_sources()
    parts: List[str] = []

    parts.append("<h2>Available blocklists</h2>")
    parts.append("<p>Select the sources you want to include, then generate your custom URL.</p>")
    parts.append('<section class="builder">')
    parts.append('<div class="builder-form">')
    parts.append('<label>Address-list name (MikroTik): <input id="list-name" type="text" placeholder="blacklist"></label><br>')
    parts.append('<label>Timeout (HH:MM:SS or Xd HH:MM:SS, max 3d): <input id="timeout" type="text" placeholder="02:00:00"></label><br>')
    parts.append('<label>Whitelist CIDR (one per line):<br><textarea id="whitelist" rows="4" cols="40" placeholder="203.0.113.0/24\n198.51.100.0/23"></textarea></label>')
    parts.append("</div>")
    parts.append('<div class="builder-sources">')
    parts.append("<h3>Sources</h3>")
    parts.append("<ul>")
    for src in sources:
        sid = int(src["id"])
        name = src["name"] or f"source-{sid}"
        url = src["url"]
        parts.append(
            f'<li><label><input type="checkbox" class="src-checkbox" value="{sid}" /> '
            f"{name}</label><br><code>{url}</code></li>"
        )
    parts.append("</ul>")
    parts.append("</div>")
    parts.append('<div class="builder-actions">')
    parts.append('<button type="button" id="generate-btn">Generate custom URL</button>')
    parts.append("</div>")
    parts.append("</section>")

    parts.append('<div class="builder-output">')
    parts.append('<h3>Generated URL</h3>')
    parts.append('<input type="text" id="generated-url" readonly style="width:100%;" placeholder="Will appear here..." />')
    parts.append('<button type="button" id="copy-url">Copy URL</button>')
    parts.append("</div>")

    sources_html = "\n".join(parts)

    template = DEFAULT_INDEX_TEMPLATE
    try:
        with open("html/index.html", "r", encoding="utf-8") as f:
            template = f.read()
    except FileNotFoundError:
        pass

    return template.replace("{{SOURCES}}", sources_html)


@app.get("/health", response_class=PlainTextResponse)
def health():
    return "ok\n"


@app.get("/", response_class=HTMLResponse)
def index():
    html = render_index_html()
    return HTMLResponse(content=html)


def _parse_whitelist_params(wl_params: List[str]) -> List[ipaddress.IPv4Network]:
    nets: List[ipaddress.IPv4Network] = []
    for entry in wl_params:
        entry = entry.strip()
        if not entry:
            continue
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            raise ValueError(f"Invalid whitelist CIDR: {entry}")
        if not isinstance(net, ipaddress.IPv4Network):
            raise ValueError(f"Whitelist IPv6 not supported: {entry}")
        nets.append(net)
    return nets


@app.get("/custom.rsc", response_class=PlainTextResponse)
def custom_rsc(
    list_param: str | None = Query(None, alias="list"),
    timeout_param: str | None = Query(None, alias="timeout"),
    src: List[int] = Query([], alias="src"),
    wl: List[str] = Query([], alias="wl"),
):
    try:
        list_name = normalize_list_name(list_param)
        timeout = parse_timeout(timeout_param)
        if not src:
            raise ValueError("No sources selected")

        wl_nets_query = _parse_whitelist_params(wl)

        all_wl_nets: List[ipaddress.IPv4Network] = []
        all_wl_nets.extend(YAML_WHITELIST_NETS)
        all_wl_nets.extend(wl_nets_query)

        script = get_custom_script_cached(list_name, timeout, src, all_wl_nets)
        return PlainTextResponse(content=script, media_type="text/plain; charset=utf-8")
    except Exception as e:
        print(f"[custom.rsc] error: {e}")
        err_script = make_error_script()
        return PlainTextResponse(content=err_script, media_type="text/plain; charset=utf-8")


@app.get("/mikrotik.rsc", response_class=PlainTextResponse)
def mikrotik_rsc():
    return all_rsc()


@app.get("/all.rsc", response_class=PlainTextResponse)
def all_rsc():
    try:
        sources = get_active_sources()
        if not sources:
            raise ValueError("No active sources configured")
        all_ids = [int(s) for s in {int(x["id"]) for x in sources}]
        list_name = MIKROTIK_LIST_NAME
        timeout = parse_timeout(None)

        script = get_custom_script_cached(list_name, timeout, all_ids, YAML_WHITELIST_NETS)
        return PlainTextResponse(content=script, media_type="text/plain; charset=utf-8")
    except Exception as e:
        print(f"[all.rsc] error: {e}")
        err_script = make_error_script()
        return PlainTextResponse(content=err_script, media_type="text/plain; charset=utf-8")
