#!/usr/bin/env sh
set -e

APP_DIR="/app"
CONF_DIR="${APP_DIR}/conf"
CONF_DIST_DIR="${APP_DIR}/conf-dist"

mkdir -p "${CONF_DIR}"

if [ -f "${CONF_DIST_DIR}/lists.yaml" ] && [ ! -f "${CONF_DIR}/lists.yaml" ]; then
  echo "[entrypoint] Seeding conf/lists.yaml"
  cp "${CONF_DIST_DIR}/lists.yaml" "${CONF_DIR}/lists.yaml"
fi

if [ -f "${CONF_DIST_DIR}/whitelist.yaml" ] && [ ! -f "${CONF_DIR}/whitelist.yaml" ]; then
  echo "[entrypoint] Seeding conf/whitelist.yaml"
  cp "${CONF_DIST_DIR}/whitelist.yaml" "${CONF_DIR}/whitelist.yaml"
fi

exec "$@"
