# kbomination

<p align="center">
  <img src="docs/images/kbomination-logo.png" alt="Pen-and-ink abominable snowman holding a blue Kubernetes emblem" width="360">
</p>

Collect Kubernetes Bill of Materials from local kubeconfig contexts, retain each collection in DuckDB, and explore fleet inventory from a local web UI.

## Prerequisites

Install [mise](https://mise.jdx.dev/). Go, Node, Trivy, kind, and kubectl are pinned in `mise.toml` and run through mise. On a fresh checkout, trust the local mise configuration and install the pinned tools, then run:

```sh
mise trust
mise install
mise run setup
mise run build
```

DuckDB uses its supported Go driver and therefore requires the C toolchain available on the host.

## Use

Kubernetes access uses the standard kubeconfig loading rules and credential plugins. Trivy needs list access to the API resources it collects. The selected kubeconfig and credentials stay local. The current kubeconfig context is never changed.

Preview matching contexts:

```sh
mise exec -- go run ./cmd/kbomination contexts --context-regex '^(prod|staging)-'
```

Collect all matching contexts (all namespaces by default):

```sh
mise exec -- go run ./cmd/kbomination collect \
  --kubeconfig ~/.kube/config \
  --context-regex '^prod-' \
  --output kboms
```

Limit collection to namespaces and ingest the results into the default database:

```sh
mise exec -- go run ./cmd/kbomination collect \
  --context-regex '^prod-' \
  --namespaces kube-system,platform \
  --ingest
```

Each collection writes a timestamped directory containing CycloneDX KBOM files and a manifest with the original kubeconfig source, context, timestamp, Trivy version, and collection scope. To import it later, run `kbomination import --manifest <directory>/manifest.json`. A standalone KBOM can be imported with `--source`, `--context`, and `--collected-at`.

Start the local server:

```sh
mise exec -- go run ./cmd/kbomination serve --listen 127.0.0.1:8080
```

Open <http://127.0.0.1:8080>. The database defaults to `.data/kbomination.duckdb`; choose another with `--db`. Use only one process to open the database for writing. While the server is open, send collection results to it with `collect --ingest --server http://127.0.0.1:8080` or `import --manifest … --server http://127.0.0.1:8080`.

Create collection profiles in the UI for on-demand runs or schedules. Schedules use five-field cron expressions in UTC and run only while the local server is open. Missed runs are skipped. Collections run at most two contexts at once, default to a 15-minute timeout per context, and report partial fleet failures independently. A namespace-limited collection is stored as a separate scope and does not replace the all-namespace view. The server marks interrupted runs after a restart.

## Inventory and queries

The UI offers filters for cluster, snapshot, namespace, category, component, version, and collection scope. It shows only information present in Trivy's KBOM; unavailable resource metadata appears as unknown. Historical snapshots remain available.

The SQL workspace supports a single read-only `SELECT` query against application-owned inventory and history views. For example:

```sql
SELECT cluster_name, name, version
FROM latest_inventory
WHERE contains(lower(name), 'coredns')
ORDER BY cluster_name, version;
```

Queries have a 30-second deadline and a 10,000-row result limit. Functions are allowlisted, and external table and file access, extensions, settings changes, and writes are rejected.

## Development

```sh
mise run dev:web   # Vite frontend on 127.0.0.1:5173; /api proxies to :8080
mise run dev       # local Go API, scheduler, and production frontend
mise run build
mise run test
mise run e2e       # disposable local kind cluster
mise run testenv   # persistent kind demo cluster, sample collection, and local UI
```

`mise run testenv` creates or reuses `kbomination-demo`, collects `kube-system` into `.data/kbomination-demo.duckdb`, and runs the local UI in the foreground. Stop it with Ctrl-C; the cluster and database remain for the next run. Override the cluster or database with `KIND_CLUSTER_NAME` and `KBOMINATION_DB`.

For API details, see [docs/openapi.yaml](docs/openapi.yaml).
