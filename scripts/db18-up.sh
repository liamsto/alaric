#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/docker-compose.postgres18.yml"

cd "$ROOT_DIR"
docker compose -f "$COMPOSE_FILE" up -d postgres18

echo "Waiting for postgres18 healthcheck..."
until [ "$(docker inspect -f '{{.State.Health.Status}}' alaric-postgres18 2>/dev/null || true)" = "healthy" ]; do
  sleep 1
done

echo "postgres18 is healthy"
echo "DATABASE_URL=postgres://alaric:alaric@127.0.0.1:55432/alaric"
