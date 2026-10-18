# kbomination

<p align="center">
  <img src="docs/images/kbomination-logo.png" alt="Pen-and-ink abominable snowman holding a blue Kubernetes emblem" width="360">
</p>

Collect Kubernetes Bill of Materials from local kubeconfig contexts, retain each collection in DuckDB, and explore fleet inventory from a local web UI.

## Use

Kubernetes access uses the standard kubeconfig loading rules and credential plugins. Trivy needs list access to the API resources it collects. The selected kubeconfig and credentials stay local. The current kubeconfig context is never changed. Cluster identity is the kubeconfig cluster entry name. Context names select access credentials; matching contexts for the same cluster are collected once, using the first matching context alphabetically. Changing the kubeconfig path or access context does not create another cluster in the database.

Imports use `cluster.name` as the cluster identity regardless of source. Older manifests containing `kubeconfig_name` are normalized on input. If an older manifest uses context aliases as names, set the actual cluster names before importing; `import --manifest … --cluster NAME` can override a single-cluster manifest. Previously stored context-named history is not automatically merged because its real cluster cannot be inferred safely.

Preview matching contexts:

```sh
kbomination contexts --context-regex '^(prod|staging)-'
```

Collect all matching contexts (all namespaces by default):

```sh
kbomination collect \
  --kubeconfig ~/.kube/config \
  --context-regex '^prod-' \
  --output kboms
```

Limit collection to namespaces and ingest the results into the default database:

```sh
kbomination collect \
  --context-regex '^prod-' \
  --namespaces kube-system,platform \
  --ingest
```

Each collection writes a timestamped directory containing CycloneDX KBOM files and a manifest with the cluster name, collection source, timestamp, Trivy version, and collection scope. To import it later, run `kbomination import --manifest <directory>/manifest.json`. A standalone KBOM can be imported with `--cluster` and `--collected-at` (`--source` optionally records provenance).

Start the local server:

```sh
kbomination serve --listen 127.0.0.1:8080
```

Open <http://127.0.0.1:8080>. The database defaults to `.data/kbomination.duckdb`; choose another with `--db`. Use only one process to open the database for writing. While the server is open, send collection results to it with `collect --ingest --server http://127.0.0.1:8080` or `import --manifest … --server http://127.0.0.1:8080`.

Create collection profiles in the UI for on-demand runs or schedules. Schedules use five-field cron expressions in UTC and run only while the local server is open. Missed runs are skipped. Collections run at most two clusters at once, default to a 15-minute timeout per cluster, and report partial fleet failures independently. A namespace-limited collection is stored as a separate scope and does not replace the all-namespace view. The server marks interrupted runs after a restart.

## Run with Docker Compose

For a named local HTTPS endpoint with Caddy and a trusted mkcert certificate:

```sh
mise run local:up
```

Open <https://kbomination.localhost:8443>. See [local deployment instructions](local/README.md) for prerequisites, port conflicts, and lifecycle commands.

For direct HTTP access:

With Docker Engine and Compose (or Docker Desktop), run:

```sh
docker compose up --build -d --wait
```

Open <http://127.0.0.1:8080>. 

Compose mounts `${HOME}/.kube` read-only at `/kube` and sets `KUBECONFIG=/kube/config`. The source directory must already exist. Override the directory or host port when starting Compose:

```sh
KBOMINATION_KUBE_DIR=/absolute/path/to/kube-directory KBOMINATION_PORT=8081 \
  docker compose up --build -d --wait
```

The standalone volume name differs from Compose's project-prefixed volume. Run one server per database volume.

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

### MCP client

The optional stdio MCP process calls the running local API and does not open DuckDB itself:

```sh
kbomination mcp --server http://127.0.0.1:8080
```

Configure your MCP client to launch this command with its stdin/stdout connected to the process. It exposes read-only cluster, component, snapshot, run, schema, and guarded SQL tools. Keep MCP client access scoped like direct access to the local UI.

## Development

### Host prerequisites

Install [mise](https://mise.jdx.dev/). Go, Node, Trivy, kind, kubectl, Helm, and GoReleaser are pinned in `mise.toml` and run through mise. On a fresh checkout, trust the local mise configuration and install the pinned tools, then run:

```sh
mise trust
mise install
mise run setup
mise run build
```

### Mise tools

```sh
mise run dev:web   # Vite frontend on 127.0.0.1:5173; /api proxies to :8080
mise run dev       # local Go API, scheduler, and production frontend
mise run build
mise run test
mise run e2e       # disposable local kind cluster
mise run testenv   # persistent kind demo cluster, sample collection, and local UI
mise run sample-db # import checked-in sample KBOMs into a local database
```

`mise run testenv` creates or reuses `kbomination-demo`, collects `kube-system` into `.data/kbomination-demo.duckdb`, and runs the local UI in the foreground. Stop it with Ctrl-C; the cluster and database remain for the next run. Override the cluster or database with `KIND_CLUSTER_NAME` and `KBOMINATION_DB`.

`mise run sample-db` creates `.data/kbomination-sample.duckdb` from the checked-in sample KBOMs without contacting a Kubernetes cluster. The import is repeatable; set `KBOMINATION_SAMPLE_DB` to choose a different database path. Start the UI against it with `go run ./cmd/kbomination serve --db .data/kbomination-sample.duckdb`.

For API details, see [docs/openapi.yaml](docs/openapi.yaml).

## Local version

Run kbomination locally behind Caddy with a trusted HTTPS certificate at <https://kbomination.localhost:8443>. Install Docker Engine with Compose (or Docker Desktop) and [mkcert](https://github.com/FiloSottile/mkcert) (`brew install mkcert` on macOS), then run from the repository root:

```sh
mise run local:up
```

This generates certificates in `local/certs`, installs mkcert’s local CA into your host trust store, pulls the published GHCR image, and starts the services. Port 8443 allows this deployment to run alongside Cartographer on port 443. Override it with `KBOMINATION_HTTPS_PORT=9443 mise run local:up` and use that port in browser and CLI URLs.

### Load data

Build the current CLI with `mise run build`, then collect using your host kubeconfig and ingest through the running server:

```sh
./bin/kbomination collect \
  --context-regex '^kind-' \
  --ingest \
  --server https://kbomination.localhost:8443
```

Adjust the context regex for your clusters. To load an existing collection without collecting again:

```sh
./bin/kbomination import \
  --manifest kboms/<collection-directory>/manifest.json \
  --server https://kbomination.localhost:8443
```

The server stores data in a persistent Docker volume that survives `local:down`. Send imports through `--server` while it is running so only the server writes to DuckDB. This volume is separate from host `.data` databases and the root HTTP Compose deployment.

UI collection profiles use `${HOME}/.kube`, mounted read-only into the container. Override the source with `KBOMINATION_KUBE_DIR=/absolute/path/to/kube-directory mise run local:up`; credential plugins and external credential files must also be available inside the container. Host CLI collection uses your host’s kubeconfig and credentials.

### Manage the deployment

```sh
mise run local:logs     # Follow service logs
mise run local:ps       # Show service status
mise run local:contexts # List contexts available inside the container
mise run local:pull     # Pull the latest application image from GHCR
mise run local:certs    # Generate local certificates
mise run local:down     # Stop services and retain data
```

For certificate renewal and additional deployment details, see [local/README.md](local/README.md).
