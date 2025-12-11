# Mikrotik Blocklist

FastAPI service that aggregates multiple public IPv4 blocklists, applies a global YAML-based whitelist, and generates ready-to-import MikroTik `/ip firewall address-list` scripts.

The generator is designed to:
- Fetch and normalize multiple external feeds
- Optionally aggregate noisy /32 into /24 (with a threshold)
- Apply a global YAML whitelist
- Expose ready-to-use `.rsc` scripts for MikroTik RouterOS v7

---

## Configuration

The service uses a configuration directory mounted as a volume inside the container.

### Directory layout

At runtime:

- `/app/conf` – **runtime configuration directory** (mounted volume)
  - `lists.yaml` – defines external sources
  - `whitelist.yaml` – defines global IPv4 whitelist CIDRs
- `/app/conf-dist` – **built-in defaults** shipped in the image  
  (`lists.yaml` and `whitelist.yaml` used only on first start to seed `/app/conf`)

On container startup:

1. If `/app/conf/lists.yaml` **does not exist**, it is copied from `/app/conf-dist/lists.yaml`.
2. If `/app/conf/whitelist.yaml` **does not exist**, it is copied from `/app/conf-dist/whitelist.yaml`.
3. If the files existent already in the mounted volume, they are **left untouched**.

You are expected to edit the files in your mounted `./conf/` directory on the host.

---

### `lists.yaml` – blocklist sources

Example:

```yaml
sources:
  - id: 1
    name: "DShield"
    url: "https://www.dshield.org/block.txt"
    is_active: true
    delimiter: "\t"
    cidr_mode: "24"
    timeout_hours: 2
    comment: "DShield"

  - id: 2
    name: "BlockList.de"
    url: "https://lists.blocklist.de/lists/all.txt"
    is_active: true
    delimiter: "\n"
    cidr_mode: "auto"
    timeout_hours: 2
    comment: "BlockList.de"
```

---

### `whitelist.yaml` – global whitelist

```yaml
whitelist:
  - "172.16.0.0/12"
  - "192.168.0.0/16"
  - "10.0.0.0/8"
  - "100.64.0.0/10"
```

Rules:
- Only IPv4 CIDRs are supported.
- YAML whitelist **always applies first**.
- Web UI whitelist (`wl=` parameters) is applied *in addition*.

---

## Environment variables

| Variable | Description | Default |
|---------|-------------|---------|
| `MIKROTIK_LIST_NAME` | Name of generated address-list | blacklist |
| `GLOBAL_COMMENT` | Default comment used in `/add` entries | compiled-blocklist |
| `AGGREGATE_THRESHOLD` | /24 aggregation threshold | 50 |
| `CACHE_TTL` | Cache duration for compiled scripts (sec) | 600 |
| `BLOCKLIST_CONF_DIR` | Directory containing lists.yaml & whitelist.yaml | /app/conf |

---

## Docker

Build:

```bash
docker build -t mikrotik-blocklist .
```

Run:

```bash
docker run --rm   -p 8000:8000   -e BLOCKLIST_CONF_DIR=/app/conf   -v "$(pwd)/conf:/app/conf"   mikrotik-blocklist
```

At first run, the container will seed configuration files.

---

## Example `docker-compose.yaml`

```yaml
version: "3.8"

services:
  blocklist:
    image: reptechwifx/mikrotik-blocklist:latest
    container_name: mikrotik-blocklist

    environment:
      MIKROTIK_LIST_NAME: "blacklist"
      GLOBAL_COMMENT: "compiled-blocklist"
      AGGREGATE_THRESHOLD: "50"
      CACHE_TTL: "600"
      BLOCKLIST_CONF_DIR: "/app/conf"

    ports:
      - "8000:8000"

    volumes:
      - ./conf:/app/conf
```

---

## Endpoints

### `/health`
Returns `"ok"`.

### `/`
Web interface with:
- list of sources
- source selection
- whitelist override
- script generator

### `/all.rsc`
Generates script including all active sources and YAML whitelist.

### `/custom.rsc`
Example:

```
/custom.rsc?src=1&src=2&list=blacklist&timeout=02:00:00&wl=203.0.113.0/24
```

### `/mikrotik.rsc`
Alias for `/all.rsc`.

---

## MikroTik Example

```rsc
/tool fetch url="https://blocklist.example.com/all.rsc" dst-path=blocklist.rsc
/import blocklist.rsc
```

You may schedule hourly refresh:

```rsc
/system scheduler
add name=blocklist-refresh interval=1h on-event="/tool fetch url=https://blocklist.example.com/all.rsc dst-path=blocklist.rsc; /import blocklist.rsc"
```

---
