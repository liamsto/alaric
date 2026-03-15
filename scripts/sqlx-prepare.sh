#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

"$ROOT_DIR/scripts/db18-up.sh"

export DATABASE_URL="postgres://alaric:alaric@127.0.0.1:55432/alaric"

cargo sqlx database create
cargo sqlx migrate run --source lib/migrations
cargo sqlx prepare --workspace -- --workspace

echo "Prepared .sqlx metadata with DATABASE_URL=$DATABASE_URL"
