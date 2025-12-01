# WIFX Blocklist Compiler

## Overview

WIFX Blocklist Compiler is a lightweight service that aggregates multiple external blocklists, deduplicates entries, optionally aggregates them into /24 subnets, and generates MikroTik-ready `.rsc` files. The service offers a clean HTML interface with WIFX branding, a MariaDB backend for configuration, and a caching layer for efficient performance.

## Features

- Aggregate multiple blocklists from external sources  
- IPv4 deduplication across all sources  
- Automatic /24 subnet aggregation when large numbers of IPs fall within the same block  
- Per-source blocklist generation  
- MikroTik-compatible `.rsc` output  
- FastAPI backend with HTTP endpoints  
- MariaDB configuration storage  
- phpMyAdmin configuration UI  
- HTML homepage with WIFX logo  
- Traefik-compatible routing  
- In-memory caching to reduce backend load  

---

## Architecture

```
External Blocklists → Blocklist Compiler (FastAPI) → .rsc Output → MikroTik RouterOS
                                 ↑
                        MariaDB + phpMyAdmin
```

---

# Installation

## Directory Structure

```
blocklist/
 ├── docker-compose.yml
 ├── app.py
 ├── requirements.txt
 ├── html/
 │    ├── index.html       (optional custom homepage)
 │    └── logo.png         (WIFX logo)
 ├── sql/
 │    ├── 00-schema.sql
 │    └── 01-seed.sql
```

---

# Database Initialization

You can initialize the database using phpMyAdmin.

## Step-by-step Instructions

1. Open  
   **https://service.tld/phpmyadmin**

2. Log in with your MariaDB credentials (blocklist / blocklist)

3. Select the database:  
   **blocklist**

4. Import schema:

   - Go to **Import**
   - Select `sql/00-schema.sql`
   - Click **Execute**

5. Import seed data:

   - Import `sql/01-seed.sql`
   - Click **Execute**

Your table `bl_sources` is now populated with default sources.

---

# Docker Compose Example

Below is an example `docker-compose.yml` that includes MariaDB, phpMyAdmin, and the blocklist compiler service:

```yaml
version: '3.4'
services:

  mariadb:
    image: mariadb:10.11
    environment:
      MARIADB_ROOT_PASSWORD: "blocklistroot$"
      MARIADB_DATABASE: "blocklist"
      MARIADB_USER: "blocklist"
      MARIADB_PASSWORD: "blocklist"
    volumes:
      - ${VOLPATH}/${PREFIX}/db:/var/lib/mysql
      - ${VOLPATH}/${PREFIX}/sql:/docker-entrypoint-initdb.d:ro
    networks:
      - blocklist
    restart: unless-stopped

  phpmyadmin:
    image: phpmyadmin
    environment:
      PMA_HOST: "mariadb"
      PMA_ABSOLUTE_URI: "https://serivce.tld/phpmyadmin/"
    networks:
      - blocklist
      - proxy
    labels:
      - "traefik.enable=true"
      - "traefik.http.services.${PREFIX}-phpmyadmin.loadbalancer.server.port=80"
      - "traefik.http.routers.${PREFIX}-phpmyadmin.rule=Host(`blocklist.service.tld`) && PathPrefix(`/phpmyadmin`)"
      - "traefik.http.routers.${PREFIX}-phpmyadmin.entrypoints=websecure"
      - "traefik.http.routers.${PREFIX}-phpmyadmin.tls=true"

  blocklist:
    image: registry.wifx.net/technical/blocklist-wifx:main
    environment:
      DB_HOST: "mariadb"
      DB_PORT: "3306"
      DB_NAME: "blocklist"
      DB_USER: "blocklist"
      DB_PASS: "blocklist"

      MIKROTIK_LIST_NAME: "blacklist"
      GLOBAL_COMMENT: "compiled-blocklist"
      AGGREGATE_THRESHOLD: "50"
      CACHE_TTL: "600"

    networks:
      - blocklist
      - proxy

    labels:
      - "traefik.enable=true"
      - "traefik.http.services.${PREFIX}.loadbalancer.server.port=80"
      - "traefik.http.routers.${PREFIX}.rule=Host(`blocklist.service.tld`)"
      - "traefik.http.routers.${PREFIX}.entrypoints=websecure"
      - "traefik.http.routers.${PREFIX}.tls=true"
```

---

# MikroTik Integration

## Create RAM Disk (only once)

```
/disk add type=tmpfs tmpfs-max-size=10M slot=tmpfs1
```

## Download & Import the Compiled Blocklist

```
/tool fetch url="https://blocklist.wifx.net/all.rsc" dst-path="tmpfs1/blocklist.rsc"
/import file-name="tmpfs1/blocklist.rsc"
```

## Automate with Scheduler

```
/system scheduler add name=update_blocklist interval=10m on-event=":local ramdisk \"tmpfs1\"; :if ([:len [/disk find where name=$ramdisk]] = 0) do={ /disk add type=tmpfs tmpfs-max-size=10M slot=$ramdisk; :delay 1s; }; /tool fetch url=\"https://blocklist.wifx.net/all.rsc\" dst-path=\"$ramdisk/blocklist.rsc\"; /import file-name=\"$ramdisk/blocklist.rsc\"; "
```

---

# Endpoints

| URL | Description |
|-----|-------------|
| `/` | HTML interface with logo |
| `/all.rsc` | Global compiled blocklist |
| `/all-<name>.rsc` | Per-source blocklist |
| `/mikrotik.rsc` | Legacy alias of `/all.rsc` |
| `/health` | Health check |

---

# Aggregation Logic

Each source defines a **cidr_mode**:

### `32`
Store each IP as `/32`.

### `24`
Convert each IP into its `/24` subnet.

### `auto`
- Load IPs as `/32`  
- If **≥ 50** IPs belong to the same `/24`, they are replaced by a single `/24` entry.

Threshold can be configured:

```
AGGREGATE_THRESHOLD=50
```

---

# Caching

To avoid regenerating lists on every request:

- Global blocklists cached for **10 minutes**
- Per-source blocklists cached individually

Configure with:

```
CACHE_TTL=600
```

---

# Custom HTML Page

Place a file at:

```
html/index.html
```

It will override the built‑in template.

Static assets (including logo):

```
html/logo.png
```

The service automatically exposes `/html/logo.png`.

---

# License

Internal WIFX Usage Only.
