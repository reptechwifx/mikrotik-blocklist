# Mikrotik Blocklist

FastAPI service that aggregates multiple public blocklists, applies a global YAML-based whitelist, and generates ready-to-import MikroTik `/ip firewall address-list` scripts.

## Configuration

Configuration lives in the `conf` directory, mounted as a volume:

- `conf/lists.yaml` – defines the external sources
- `conf/whitelist.yaml` – defines global IPv4 whitelist CIDRs

On container start, if these files are missing in `/app/conf`, they are seeded from `/app/conf-dist`.

## Docker

```bash
docker build -t mikrotik-blocklist .

docker run --rm -p 8000:8000   -v $(pwd)/conf:/app/conf   mikrotik-blocklist
```

## Endpoints

- `GET /` – simple HTML page with source list and custom URL builder
- `GET /all.rsc` – compiled script with all active sources
- `GET /custom.rsc?src=1&src=2&list=blacklist&timeout=02:00:00&wl=203.0.113.0/24`

The returned content is MikroTik RouterOS script, safe to use with `fetch` + `:import`.
