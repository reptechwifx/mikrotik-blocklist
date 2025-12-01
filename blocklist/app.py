import os
import ipaddress
from collections import defaultdict
from typing import Dict, Set, List

import requests
import mysql.connector
from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse

app = FastAPI(title="blocklist-compiler")

# --- Config via env ---------------------------------------------------------

DB_HOST = os.getenv("DB_HOST", "mariadb")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_NAME = os.getenv("DB_NAME", "blocklist")
DB_USER = os.getenv("DB_USER", "blocklist")
DB_PASS = os.getenv("DB_PASS", "blocklist")

# Nom de la liste Mikrotik + commentaire global par défaut
MIKROTIK_LIST_NAME = os.getenv("MIKROTIK_LIST_NAME", "blacklist")
GLOBAL_COMMENT = os.getenv("GLOBAL_COMMENT", "compiled-blocklist")

# Seuil de regroupement en /24
AGGREGATE_THRESHOLD = int(os.getenv("AGGREGATE_THRESHOLD", "50"))

# Timeout HTTP pour les listes
FETCH_TIMEOUT = int(os.getenv("FETCH_TIMEOUT", "20"))


# --- Helpers DB -------------------------------------------------------------

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


# --- Parsing des listes -----------------------------------------------------

def fetch_list(url: str) -> str:
    resp = requests.get(url, timeout=FETCH_TIMEOUT)
    resp.raise_for_status()
    return resp.text


def extract_ipv4s_from_text(text: str, delimiter: str | None) -> List[ipaddress.IPv4Address]:
    """Extrait des IPv4 en se basant sur le token avant le delimiter (si fourni).
    On est volontairement pragmatique : si le token est du genre '1.2.3.4/32',
    on essaie aussi de le parser.
    """
    ips: List[ipaddress.IPv4Address] = []
    if not delimiter:
        delimiter = "\n"

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        token = line
        if delimiter:
            # Ne découper qu'une fois
            parts = line.split(delimiter, 1)
            token = parts[0].strip()

        if not token:
            continue

        # Essayer IP simple
        try:
            ip = ipaddress.IPv4Address(token)
            ips.append(ip)
            continue
        except ValueError:
            pass

        # Essayer IP/CIDR
        try:
            iface = ipaddress.IPv4Interface(token)
            ips.append(iface.ip)
            continue
        except ValueError:
            pass

        # Sinon on ignore la ligne
    return ips


# --- Logique de compilation -------------------------------------------------

def compile_blocklist() -> str:
    sources = get_active_sources()
    if not sources:
        raise HTTPException(status_code=500, detail="No active sources configured")

    # IP /32 collectées (pour les modes '32' et 'auto')
    all_ips: Set[ipaddress.IPv4Address] = set()

    # /24 explicites demandés par les sources (cidr_mode='24')
    explicit_nets24: Set[ipaddress.IPv4Network] = set()
    explicit_nets24_comment: Dict[ipaddress.IPv4Network, str] = {}

    # Comment préféré pour une IP /32 (première source rencontrée)
    ip_first_comment: Dict[ipaddress.IPv4Address, str] = {}

    for src in sources:
        url = src["url"]
        delim = src.get("delimiter") or "\n"
        cidr_mode = src.get("cidr_mode") or "32"
        # Comment “source” : on privilégie name, sinon comment, sinon GLOBAL_COMMENT
        source_comment = (src.get("name") or src.get("comment") or GLOBAL_COMMENT).strip() or GLOBAL_COMMENT

        try:
            text = fetch_list(url)
        except Exception as e:
            # On remonte l'erreur, à toi de voir si tu veux continuer partiellement
            raise HTTPException(
                status_code=502,
                detail=f"Failed to fetch {url}: {e}"
            )

        ips = extract_ipv4s_from_text(text, delim)

        if cidr_mode == "24":
            # Chaque IP -> /24 explicite avec commentaire de la source
            for ip in ips:
                net = ipaddress.IPv4Network(f"{ip.exploded}/24", strict=False)
                if net not in explicit_nets24:
                    explicit_nets24.add(net)
                    explicit_nets24_comment[net] = source_comment
        else:
            # '32' ou 'auto' -> IP /32
            for ip in ips:
                if ip not in all_ips:
                    all_ips.add(ip)
                    ip_first_comment.setdefault(ip, source_comment)

    # Agrégation en /24 pour les IP /32 ('auto' et '32')
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
            # commentaire = celui de la première IP du /24
            first_ip = next(iter(ips))
            aggregated_nets24_comment[net] = ip_first_comment.get(first_ip, GLOBAL_COMMENT)

    # IP finales = toutes les IP /32 non couvertes par un /24 explicite ou agrégé
    remaining_ips: Set[ipaddress.IPv4Address] = set()
    for ip in all_ips:
        ip_net24 = ipaddress.IPv4Network(f"{ip.exploded}/24", strict=False)
        if ip_net24 in explicit_nets24:
            continue
        if ip_net24 in aggregated_nets24:
            continue
        remaining_ips.add(ip)

    # /24 finaux = /24 explicites + /24 agrégés
    final_nets24: Set[ipaddress.IPv4Network] = set(explicit_nets24) | set(aggregated_nets24)

    # Génération du script RouterOS
    lines: List[str] = []
    lines.append("/ip firewall address-list")
    # On supprime toutes les entrées de cette liste (peu importe le commentaire)
    lines.append(f'remove [find list="{MIKROTIK_LIST_NAME}"]')

    # /24 d'abord (triés pour stabilité)
    for net in sorted(final_nets24, key=lambda n: (int(n.network_address), n.prefixlen)):
        if net in explicit_nets24_comment:
            comment = explicit_nets24_comment[net]
        else:
            comment = aggregated_nets24_comment.get(net, GLOBAL_COMMENT)
        lines.append(
            f'add list={MIKROTIK_LIST_NAME} address={net.with_prefixlen} '
            f'comment="{comment}" timeout=02:00:00'
        )

    # puis les /32 restants
    for ip in sorted(remaining_ips, key=int):
        comment = ip_first_comment.get(ip, GLOBAL_COMMENT)
        lines.append(
            f'add list={MIKROTIK_LIST_NAME} address={ip.exploded} '
            f'comment="{comment}" timeout=02:00:00'
        )

    return "\n".join(lines) + "\n"


# --- Endpoints --------------------------------------------------------------

@app.get("/health", response_class=PlainTextResponse)
def health():
    return "ok\n"


@app.get("/mikrotik.rsc", response_class=PlainTextResponse)
def mikrotik_rsc():
    """
    Endpoint principal : retourne un script .rsc à faire fetch/import
    sur le Mikrotik.
    """
    script = compile_blocklist()
    return PlainTextResponse(content=script, media_type="text/plain; charset=utf-8")
