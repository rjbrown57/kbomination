#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

cluster="${KIND_CLUSTER_NAME:-kbomination-demo}"
database="${KBOMINATION_DB:-.data/kbomination-demo.duckdb}"

if [[ ! "$cluster" =~ ^[a-z0-9][a-z0-9.-]*$ ]]; then
  echo "KIND_CLUSTER_NAME must contain only lowercase letters, digits, dots, and hyphens." >&2
  exit 2
fi

if kind get clusters | grep -Fxq "$cluster"; then
  echo "Reusing kind cluster '$cluster'."
  kind export kubeconfig --name "$cluster"
else
  echo "Creating kind cluster '$cluster'."
  kind create cluster --name "$cluster" --wait 120s
fi

context="kind-$cluster"
echo "Collecting kube-system inventory from '$context' into '$database'."
mise exec -- go run ./cmd/kbomination collect \
  --context-regex "^${context}$" \
  --namespaces kube-system \
  --ingest \
  --db "$database"

echo "Starting kbomination at http://127.0.0.1:8080 (Ctrl-C to stop)."
exec mise exec -- go run ./cmd/kbomination serve --db "$database"
