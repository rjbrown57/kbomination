#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

database="${KBOMINATION_SAMPLE_DB:-.data/kbomination-sample.duckdb}"
mkdir -p "$(dirname "$database")"

mise exec -- go run ./cmd/kbomination --db "$database" import \
  --manifest testdata/sample/manifest.json

echo "Sample database ready: $database"
