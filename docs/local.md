# Local version

Run kbomination locally behind Caddy with a trusted HTTPS certificate at <https://kbomination.localhost:8443>. Install Docker Engine with Compose (or Docker Desktop) and [mkcert](https://github.com/FiloSottile/mkcert) (`brew install mkcert` on macOS), then run from the repository root:

```sh
mise run local:up
```

This generates certificates in `local/certs`, installs mkcert’s local CA into your host trust store, pulls the published GHCR image, and starts the services. Port 8443 allows this deployment to run alongside Cartographer on port 443. Override it with `KBOMINATION_HTTPS_PORT=9443 mise run local:up` and use that port in browser and CLI URLs.

## Load data

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

## Manage the deployment

```sh
mise run local:logs     # Follow service logs
mise run local:ps       # Show service status
mise run local:contexts # List contexts available inside the container
mise run local:pull     # Pull the latest application image from GHCR
mise run local:certs    # Generate local certificates
mise run local:down     # Stop services and retain data
```

For certificate renewal and additional deployment details, see [local/README.md](../local/README.md).
