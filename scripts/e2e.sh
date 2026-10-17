#!/usr/bin/env bash
set -euo pipefail

cluster="kbomination-e2e"
config="$(mktemp)"
cleanup() {
  kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
  rm -f "$config"
}
trap cleanup EXIT

kind create cluster --name "$cluster" --kubeconfig "$config" --wait 120s
go run ./cmd/kbomination contexts --kubeconfig "$config" --context-regex '^kind-kbomination-e2e$'
go run ./cmd/kbomination collect --kubeconfig "$config" --context-regex '^kind-kbomination-e2e$' --output .data/e2e-kboms
go run ./cmd/kbomination import --manifest "$(find .data/e2e-kboms -name manifest.json -type f | sort | tail -n 1)" --db .data/e2e.duckdb
