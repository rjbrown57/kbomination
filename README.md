# kbomination

<p align="center">
  <img src="docs/images/kbomination-logo.png" alt="Pen-and-ink abominable snowman holding a blue Kubernetes emblem" width="360">
</p>

Collect Kubernetes Bill of Materials from local kubeconfig contexts, retain each collection in DuckDB, and explore fleet inventory from a local web UI.

## Use

Kubernetes access uses the standard kubeconfig loading rules and credential plugins. Trivy needs list access to the API resources it collects.

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

### Collection controls

The CLI and the Collections profile editor support the same Trivy settings. Defaults preserve the lightweight inventory collection: all kinds, image scanning skipped, and node collection disabled.

| CLI flags | Default / behavior |
| --- | --- |
| `--exclude-namespaces` | No exclusions; cannot overlap `--namespaces` |
| `--include-kinds`, `--exclude-kinds` | No restrictions; comma-separated Kubernetes kinds |
| `--qps`, `--burst` | 5 API requests/second and burst 10, per collector |
| `--scan-images` | False; opt into image downloads and scanning |
| `--parallel` | 5 scan workers per Trivy process; 0 selects automatically |
| `--image-src` | `docker,containerd,podman,remote`, in priority order |
| `--cache-dir`, `--cacert` | Trivy's default cache directory; no extra PEM CA file |
| `--db-repository`, `--java-db-repository` | Trivy 0.76.0 defaults: Google mirror then GHCR; ordered comma-separated OCI repositories |
| `--skip-db-update`, `--skip-java-db-update` | False; enabling requires preprovisioned databases |
| `--offline-scan` | False; disables dependency-identification API requests, not Kubernetes or registry access |

For example:

```sh
kbomination collect --context-regex '^prod-' \
  --exclude-namespaces sandbox --include-kinds deployment,daemonset \
  --qps 3 --burst 6 --scan-images --image-src remote --parallel 2 --ingest
```

Image scanning increases work and may produce artifacts exceeding the existing 64 MiB import limit. Scan parallelism does not change the two-cluster collection limit. Paths belong to the collector process: host CLI paths are local; UI and scheduled collections use server/container paths. Credentials continue to come from kubeconfig plugins, registry authentication, and credential environment variables. Trivy configuration files and non-credential `TRIVY_*` environment settings are ignored; configure collection behavior through these flags or profiles. The permitted Trivy credential variables are `TRIVY_USERNAME`, `TRIVY_PASSWORD`, `TRIVY_REGISTRY_TOKEN`, `TRIVY_TOKEN`, and `TRIVY_GITHUB_TOKEN`; other process environment variables remain available.

Snapshots retain normalized `collection_options` and a readable coverage description. Namespace/kind filters, image scanning, and offline dependency identification when images are scanned define separate inventory scopes. Throttling, source priority, cache paths, CA paths, and database settings are recorded but do not split scopes. Default coverage retains the existing `all` / `namespaces:…` scope keys; other coverage uses stable `coverage:v1:…` keys. The overview shows default-coverage snapshots only. Historical settings that were not recorded are labeled accordingly.

New collections write version-2 manifests. Imports accept versions 1 and 2; manifest coverage cannot be overridden with CLI flags. Standalone imports accept `--namespaces`, `--exclude-namespaces`, `--include-kinds`, `--exclude-kinds`, `--scan-images`, and `--offline-scan` to declare coverage. Without coverage flags their additional settings remain unrecorded.

Opening an existing database upgrades its schema to version 3 without changing existing snapshot IDs or scope keys. Backups now use version 2 and include collection settings; restore accepts versions 1 and 2. Older binaries cannot open the upgraded database or consume the new manifest/backup versions.

### Inventory and queries

The UI offers filters for cluster, snapshot, namespace, category, component, version, and collection scope. It shows only information present in Trivy's KBOM; unavailable resource metadata appears as unknown. Historical snapshots remain available.

The Components page collapses matching package identities by name and shows a count for each group. Expand a name to browse its identities, inspect details, and follow links to clusters. Counts reflect the active filters across recorded snapshots; both groups and their entries are paginated.

The SQL workspace supports a single read-only `SELECT` query against application-owned inventory and history views. For example:

```sql
SELECT cluster_name, name, version
FROM latest_inventory
WHERE contains(lower(name), 'coredns')
ORDER BY cluster_name, version;
```

Queries have a 30-second deadline and a 10,000-row result limit. Functions are allowlisted, and external table and file access, extensions, settings changes, and writes are rejected.

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

For detailed instructions on the local HTTPS deployment, loading data, kubeconfig access, and deployment commands, see [docs/local.md](docs/local.md).
