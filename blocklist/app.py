import os
import re
import ipaddress
import time
from collections import defaultdict
from typing import Dict, Set, List

import requests
import mysql.connector
from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

app = FastAPI(title="blocklist-compiler")

# --- Config via env ---------------------------------------------------------

DB_HOST = os.getenv("DB_HOST", "mariadb")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_NAME = os.getenv("DB_NAME", "blocklist")
DB_USER = os.getenv("DB_USER", "blocklist")
DB_PASS = os.getenv("DB_PASS", "blocklist")

MIKROTIK_LIST_NAME = os.getenv("MIKROTIK_LIST_NAME", "blacklist")
GLOBAL_COMMENT = os.getenv("GLOBAL_COMMENT", "compiled-blocklist")

AGGREGATE_THRESHOLD = int(os.getenv("AGGREGATE_THRESHOLD", "50"))
FETCH_TIMEOUT = int(os.getenv("FETCH_TIMEOUT", "20"))
CACHE_TTL = int(os.getenv("CACHE_TTL", "600"))  # secondes, 600 = 10 min
WHITELIST_PATH = os.getenv("WHITELIST_PATH", "/etc/conf/whitelist.txt")

# --- Cache en mémoire -------------------------------------------------------

_all_cache: Dict[str, object] = {
    "ts": 0.0,
    "data": "",
    "whitelist_mtime": None,
}

_per_source_cache: Dict[str, Dict[str, object]] = {}  # slug -> {ts, data}

_whitelist_state: Dict[str, object] = {
    "mtime": None,
    "nets": set(),
}


def get_whitelist_networks() -> tuple[Set[ipaddress.IPv4Network], float | None]:
    """Charge les réseaux IPv4 de la whitelist depuis WHITELIST_PATH.

    Le fichier est rechargé automatiquement en cas de modification (mtime)."""
    global _whitelist_state
    path = WHITELIST_PATH
    try:
        st = os.stat(path)
    except FileNotFoundError:
        _whitelist_state["mtime"] = None
        _whitelist_state["nets"] = set()
        return _whitelist_state["nets"], _whitelist_state["mtime"]
    mtime = st.st_mtime
    if _whitelist_state["mtime"] != mtime:
        nets: Set[ipaddress.IPv4Network] = set()
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        net = ipaddress.ip_network(line, strict=False)
                    except ValueError:
                        # Ligne invalide, on ignore
                        continue
                    # On ne garde que de l'IPv4, la génération actuelle est IPv4-only
                    if isinstance(net, ipaddress.IPv4Network):
                        nets.add(net)
        except OSError:
            nets = set()
        _whitelist_state["mtime"] = mtime
        _whitelist_state["nets"] = nets
    return _whitelist_state["nets"], _whitelist_state["mtime"]  # type: ignore[return-value]


# --- Helpers généraux -------------------------------------------------------

def slugify(name: str) -> str:
    s = name.strip().lower()
    s = re.sub(r"\s+", "-", s)
    s = re.sub(r"[^a-z0-9\-]+", "", s)
    return s


def get_db():
    return mysql.connector.connect(
        host=DB_HOST,
        port=DB_PORT,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASS,
    )


def get_active_sources():
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute(
        """
        SELECT id, name, url, is_active, delimiter, cidr_mode,
               timeout_hours, comment
        FROM bl_sources
        WHERE is_active = 1
        ORDER BY id
        """
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows


def fetch_list(url: str) -> str:
    resp = requests.get(url, timeout=FETCH_TIMEOUT)
    resp.raise_for_status()
    return resp.text


def extract_ipv4s_from_text(text: str, delimiter: str | None) -> List[ipaddress.IPv4Address]:
    """Extrait des IPv4 en prenant le token avant delimiter (si fourni)."""
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

        # IP simple
        try:
            ip = ipaddress.IPv4Address(token)
            ips.append(ip)
            continue
        except ValueError:
            pass

        # IP/CIDR
        try:
            iface = ipaddress.IPv4Interface(token)
            ips.append(iface.ip)
            continue
        except ValueError:
            pass

    return ips


# --- Compilation globale (toutes sources actives) ---------------------------

def compile_blocklist_all() -> str:
    """Compile une liste globale avec déduplication entre toutes les sources."""
    sources = get_active_sources()
    if not sources:
        raise HTTPException(status_code=500, detail="No active sources configured")

    whitelist_nets, _ = get_whitelist_networks()

    all_ips: Set[ipaddress.IPv4Address] = set()
    explicit_nets24: Set[ipaddress.IPv4Network] = set()
    explicit_nets24_comment: Dict[ipaddress.IPv4Network, str] = {}
    ip_first_comment: Dict[ipaddress.IPv4Address, str] = {}

    for src in sources:
        url = src["url"]
        delim = src.get("delimiter") or "\n"
        cidr_mode = src.get("cidr_mode") or "32"
        source_comment = (src.get("name") or src.get("comment") or GLOBAL_COMMENT).strip() or GLOBAL_COMMENT

        text = fetch_list(url)
        ips = extract_ipv4s_from_text(text, delim)

        if cidr_mode == "24":
            for ip in ips:
                # IP dans la whitelist -> on ignore
                if any(ip in net for net in whitelist_nets):
                    continue
                net = ipaddress.IPv4Network(f"{ip.exploded}/24", strict=False)
                if net not in explicit_nets24:
                    explicit_nets24.add(net)
                    explicit_nets24_comment[net] = source_comment
        else:
            for ip in ips:
                # IP dans la whitelist -> on ignore
                if any(ip in net for net in whitelist_nets):
                    continue
                if ip not in all_ips:
                    all_ips.add(ip)
                    ip_first_comment.setdefault(ip, source_comment)

    # Agrégation en /24 pour IP /32
    per_net24: Dict[ipaddress.IPv4Network, Set[ipaddress.IPv4Address]] = defaultdict(set)
    for ip in all_ips:
        net24 = ipaddress.IPv4Network(f"{ip.exploded}/24", strict=False)
        per_net24[net24].add(ip)

    aggregated_nets24: Set[ipaddress.IPv4Network] = set()
    aggregated_ips: Set[ipaddress.IPv4Address] = set()
    aggregated_nets24_comment: Dict[ipaddress.IPv4Network, str] = {}

    for net, ips in per_net24.items():
        if len(ips) >= AGGREGATE_THRESHOLD:
            aggregated_nets24.add(net)
            aggregated_ips.update(ips)
            first_ip = next(iter(ips))
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
    lines.append(f'remove [find list="{MIKROTIK_LIST_NAME}"]')

    # /24
    for net in sorted(final_nets24, key=lambda n: (int(n.network_address), n.prefixlen)):
        if net in explicit_nets24_comment:
            comment = explicit_nets24_comment[net]
        else:
            comment = aggregated_nets24_comment.get(net, GLOBAL_COMMENT)
        lines.append(
            f'add list={MIKROTIK_LIST_NAME} address={net.with_prefixlen} '
            f'comment="{comment}" timeout=02:00:00'
        )

    # /32
    for ip in sorted(remaining_ips, key=int):
        comment = ip_first_comment.get(ip, GLOBAL_COMMENT)
        lines.append(
            f'add list={MIKROTIK_LIST_NAME} address={ip.exploded} '
            f'comment="{comment}" timeout=02:00:00'
        )

    return "\n".join(lines) + "\n"


def get_all_script_cached() -> str:
    now = time.time()
    # On invalide le cache si la whitelist change (mtime) ou si le TTL est dépassé
    _, wl_mtime = get_whitelist_networks()
    cached_mtime = _all_cache.get("whitelist_mtime")
    if (
        not _all_cache.get("data")
        or now - float(_all_cache.get("ts", 0.0)) > CACHE_TTL
        or cached_mtime != wl_mtime
    ):
        script = compile_blocklist_all()
        _all_cache["data"] = script
        _all_cache["ts"] = now
        _all_cache["whitelist_mtime"] = wl_mtime
    return _all_cache["data"]  # type: ignore[return-value]


# --- Compilation par source individuelle ------------------------------------

def compile_blocklist_for_source(src: dict) -> str:
    """Compile une liste pour UNE seule source (dédup + agrégation dans cette source)."""
    url = src["url"]
    delim = src.get("delimiter") or "\n"
    cidr_mode = src.get("cidr_mode") or "32"
    source_comment = (src.get("name") or src.get("comment") or GLOBAL_COMMENT).strip() or GLOBAL_COMMENT

    whitelist_nets, _ = get_whitelist_networks()

    text = fetch_list(url)
    ips = extract_ipv4s_from_text(text, delim)

    all_ips: Set[ipaddress.IPv4Address] = set()
    explicit_nets24: Set[ipaddress.IPv4Network] = set()

    if cidr_mode == "24":
        for ip in ips:
            # IP dans la whitelist -> on ignore
            if any(ip in net for net in whitelist_nets):
                continue
            net = ipaddress.IPv4Network(f"{ip.exploded}/24", strict=False)
            explicit_nets24.add(net)
    else:
        for ip in ips:
            # IP dans la whitelist -> on ignore
            if any(ip in net for net in whitelist_nets):
                continue
            all_ips.add(ip)

    per_net24: Dict[ipaddress.IPv4Network, Set[ipaddress.IPv4Address]] = defaultdict(set)
    for ip in all_ips:
        net24 = ipaddress.IPv4Network(f"{ip.exploded}/24", strict=False)
        per_net24[net24].add(ip)

    aggregated_nets24: Set[ipaddress.IPv4Network] = set()
    aggregated_ips: Set[ipaddress.IPv4Address] = set()

    for net, ips_set in per_net24.items():
        if len(ips_set) >= AGGREGATE_THRESHOLD:
            aggregated_nets24.add(net)
            aggregated_ips.update(ips_set)

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
    lines.append(f'remove [find list="{MIKROTIK_LIST_NAME}"]')

    for net in sorted(final_nets24, key=lambda n: (int(n.network_address), n.prefixlen)):
        lines.append(
            f'add list={MIKROTIK_LIST_NAME} address={net.with_prefixlen} '
            f'comment="{source_comment}" timeout=02:00:00'
        )

    for ip in sorted(remaining_ips, key=int):
        lines.append(
            f'add list={MIKROTIK_LIST_NAME} address={ip.exploded} '
            f'comment="{source_comment}" timeout=02:00:00'
        )

    return "\n".join(lines) + "\n"


def get_source_script_cached(src: dict) -> str:
    slug = slugify(src["name"] or f"source-{src['id']}")
    now = time.time()
    _, wl_mtime = get_whitelist_networks()
    entry = _per_source_cache.get(slug)

    if (
        not entry
        or now - float(entry.get("ts", 0.0)) > CACHE_TTL
        or entry.get("whitelist_mtime") != wl_mtime
    ):
        script = compile_blocklist_for_source(src)
        _per_source_cache[slug] = {"ts": now, "data": script, "whitelist_mtime": wl_mtime}
        return script
    return entry["data"]  # type: ignore[return-value]


# --- HTML / static ----------------------------------------------------------

# On sert /html/logo.png & co
app.mount("/html", StaticFiles(directory="html"), name="html")

DEFAULT_INDEX_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>WIFX Blocklist</title>
  <style>
    body { margin:0; font-family: -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; background:#f5f6f8; }
    header { background:#0747a6; color:#fff; padding:8px 16px; display:flex; align-items:center; }
    header img { height:28px; margin-right:12px; }
    header .title { font-size:18px; font-weight:600; }
    main { max-width:900px; margin:24px auto; background:#fff; padding:24px 28px; border-radius:6px; box-shadow:0 1px 3px rgba(9,30,66,0.13); }
    h1 { margin-top:0; font-size:22px; color:#172b4d; }
    p { color:#42526e; }
    ul { padding-left:20px; }
    li { margin:4px 0; }
    code { background:#f4f5f7; padding:2px 4px; border-radius:3px; font-size:90%; }
    footer { text-align:center; padding:16px; font-size:12px; color:#6b778c; }
    footer a { color:#0747a6; text-decoration:none; }
  </style>
</head>
<body>
<header>
  <img src="/html/logo.png" alt="WIFX">
  <div class="title">WIFX Blocklist Service</div>
</header>
<main>
  <h1>Blocklists Mikrotik</h1>
  <p>List of <code>.rsc</code> prêtes à être importées dansready for RouterOS.</p>

  {{SOURCES}}

</main>
<footer>
  &copy; WIFX SA - <a href="https://www.wifx.net" target="_blank" rel="noopener">www.wifx.net</a>
</footer>
</body>
</html>
"""


def render_index_html() -> str:
    sources = get_active_sources()
    parts: List[str] = []
    parts.append("<h2>Listes disponibles</h2>")
    parts.append("<ul>")
    parts.append('<li><a href="/all.rsc">all.rsc</a> – liste globale (toutes sources actives)</li>')

    for src in sources:
        name = src["name"] or f"source-{src['id']}"
        slug = slugify(name)
        parts.append(
            f'<li><a href="/all-{slug}.rsc">all-{slug}.rsc</a> – {name} '
            f'(<code>{src["url"]}</code>)</li>'
        )

    parts.append("</ul>")
    sources_html = "\n".join(parts)

    template = DEFAULT_INDEX_TEMPLATE
    try:
        # Si tu crées html/index.html, on l'utilise à la place
        with open("html/index.html", "r", encoding="utf-8") as f:
            template = f.read()
    except FileNotFoundError:
        pass

    return template.replace("{{SOURCES}}", sources_html)


# --- Endpoints --------------------------------------------------------------

@app.get("/health", response_class=PlainTextResponse)
def health():
    return "ok\n"


@app.get("/", response_class=HTMLResponse)
def index():
    html = render_index_html()
    return HTMLResponse(content=html)


@app.get("/mikrotik.rsc", response_class=PlainTextResponse)
def mikrotik_rsc():
    """Ancien endpoint, alias de /all.rsc."""
    script = get_all_script_cached()
    return PlainTextResponse(content=script, media_type="text/plain; charset=utf-8")


@app.get("/all.rsc", response_class=PlainTextResponse)
def all_rsc():
    """Liste globale compilée (toutes sources actives)."""
    script = get_all_script_cached()
    return PlainTextResponse(content=script, media_type="text/plain; charset=utf-8")


@app.get("/all-{slug}.rsc", response_class=PlainTextResponse)
def per_source_rsc(slug: str):
    """Liste compilée pour une source unique, identifiée par son slug basé sur name."""
    sources = get_active_sources()
    src_match = None
    for src in sources:
        if slugify(src["name"] or f"source-{src['id']}") == slug.lower():
            src_match = src
            break

    if not src_match:
        raise HTTPException(status_code=404, detail="Unknown source")

    script = get_source_script_cached(src_match)
    return PlainTextResponse(content=script, media_type="text/plain; charset=utf-8")
