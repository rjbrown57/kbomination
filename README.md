# kbomination

<p align="center">
  <img src="docs/images/kbomination-logo.png" alt="Pen-and-ink abominable snowman holding a blue Kubernetes emblem" width="360">
</p>

Collect Kubernetes Bill of Materials from local kubeconfig contexts, retain each collection in DuckDB, and explore fleet inventory from a local web UI.

## Run with Docker Compose

With Docker Engine and Compose (or Docker Desktop), run:

```sh
docker compose up --build -d --wait
```

If you use mise, these helpers wrap the same Compose commands:

```sh
mise run compose:up        # build, start, and wait until healthy
mise run compose:build     # build the image without starting it
mise run compose:ps        # show service status
mise run compose:logs      # follow logs (Ctrl-C to stop following)
mise run compose:contexts  # list contexts in the running container
mise run compose:down      # stop and retain the database volume
```

The helpers accept the same `KBOMINATION_KUBE_DIR` and `KBOMINATION_PORT` environment overrides shown below.

Open <http://127.0.0.1:8080>. The image builds the frontend and Go application and includes mise and pinned Trivy; host Go, Node, and mise installations are not needed for container collection. The process runs as a non-root user. Compose publishes the service only on host loopback. The API has no authentication: keep this localhost port binding, even though the container explicitly enables `--allow-non-loopback` to listen on its own network interface.

Compose mounts `${HOME}/.kube` read-only at `/kube` and sets `KUBECONFIG=/kube/config`. The source directory must already exist. Override the directory or host port when starting Compose:

```sh
KBOMINATION_KUBE_DIR=/absolute/path/to/kube-directory KBOMINATION_PORT=8081 \
  docker compose up --build -d --wait
```

Preview contexts with `docker compose exec kbomination kbomination contexts`. In UI collection profiles, leave the kubeconfig path empty to use the default, or enter a **container path**, such as `/kube/work-config`. On-demand and scheduled collections run inside the container. The mounted files are never modified by kbomination.

DuckDB lives in the `kbomination-data` named volume. `docker compose down` stops the service and retains the data; `docker compose down --volumes` deletes it. View logs with `docker compose logs -f`. The server must remain the only database writer: for CLI collection while it is running, use:

```sh
docker compose exec kbomination kbomination collect --context-regex '^prod-' \
  --output /data/kboms --ingest --server http://127.0.0.1:8080
```

### Kubeconfig and credential compatibility

- Embedded certificates and tokens work without additional tools. Relative certificate/key paths under the mounted directory continue to work. Absolute host paths and references outside that directory need extra read-only mounts at matching container paths, or a separate container-specific kubeconfig. Do not mount your entire home directory.
- On native Linux, the image's user is UID 1000. If your kubeconfig is private to another UID, set Compose `user` to your UID/GID in an override and give that user writable `HOME`, mise cache/state directories, and the data volume. Keep credential files private rather than making them world-readable.
- Kubeconfig `exec` plugins (AWS CLI, GKE auth plugin, kubelogin, etc.) must be installed as **Linux binaries** in a derived image and be on its `PATH`, or at the exact configured executable path. The base image does not bundle cloud-provider CLIs. Mount only the provider's required credential files and configure its environment using a local Compose override. Authentication caches that refresh need a separate writable location; `/kube` remains read-only. Complete interactive login before relying on background schedules.
- For multiple kubeconfigs, add explicit mounts and override the container's `KUBECONFIG` with a colon-separated list of container paths. Host `KUBECONFIG` is not automatically forwarded.
- Cluster API addresses must be reachable from the container. `127.0.0.1` in a kubeconfig points back to the container, not your host. Docker Desktop provides `host.docker.internal`; native Linux may need a `host-gateway` mapping. The endpoint must also be listening on a reachable interface and its TLS certificate must match the configured server name. For kind, a local override can attach the service to the kind network and use a separately generated internal kubeconfig. Keep TLS verification enabled and leave your original kubeconfig unchanged.

### Credentials stored in a host keyring

A kubeconfig mount does not expose macOS Keychain or another host keyring to Linux containers. Use the host collector with its normal credential plugin and keyring, sending results to the container server:

```sh
mise exec -- go run ./cmd/kbomination collect \
  --kubeconfig ~/.kube/config --context-regex '^prod-' \
  --ingest --server http://127.0.0.1:8080
```

This fallback requires the host prerequisites below; adjust the server port if overridden. Only collected inventory is sent to the server. Launch or schedule these collections on the host. The container's UI and scheduler cannot invoke the host collector; they require credentials usable inside the container. No keyring forwarding or host credential broker is provided.

Cluster identity currently includes the absolute kubeconfig source path. Host and container paths therefore produce separate inventory identities for the same context. Use one collection mode consistently for each cluster to preserve a continuous history.

For a standalone Docker invocation, build with `docker build -t kbomination:local .`, then run:

```sh
docker run --rm --init --name kbomination \
  -p 127.0.0.1:8080:8080 \
  --mount "type=bind,source=$HOME/.kube,target=/kube,readonly" \
  --mount type=volume,source=kbomination-data,target=/data \
  -e KUBECONFIG=/kube/config \
  kbomination:local serve --listen 0.0.0.0:8080 --allow-non-loopback \
  --db /data/kbomination.duckdb
```

The standalone volume name differs from Compose's project-prefixed volume. Run one server per database volume.

## Host prerequisites

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
