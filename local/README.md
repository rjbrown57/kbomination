# kbomination local HTTPS

This follows Cartographer’s local deployment pattern with Caddy and mkcert.
Install Docker Engine with Compose (or Docker Desktop) and [mkcert](https://github.com/FiloSottile/mkcert) (`brew install mkcert` on macOS), then run from the repository root:

```sh
mise run local:up
```

Open <https://kbomination.localhost:8443>. The command installs mkcert’s local CA into your host trust store, generates certificates in `local/certs`, builds kbomination, and waits for startup. Certificates and private keys are ignored by Git. To renew a certificate, remove the two generated PEM files and rerun `mise run local:certs`, then `docker compose -f local/compose.yaml restart caddy`.

Caddy binds to loopback on port 8443 and forwards to kbomination on the private Compose network. The `.localhost` name resolves to loopback on modern systems without editing `/etc/hosts`. Caddy preserves the request Host for the API’s same-origin checks.

Port 8443 allows Cartographer to keep using port 443. To choose another port:

```sh
KBOMINATION_HTTPS_PORT=9443 mise run local:up
```

Then open <https://kbomination.localhost:9443>. Use the selected port for CLI calls; the default is `kbomination mcp --server https://kbomination.localhost:8443`.

Kubeconfig is mounted read-only from `${HOME}/.kube` to `/kube`. Override it with `KBOMINATION_KUBE_DIR=/absolute/path/to/kube-directory mise run local:up`. The directory must exist; credential plugins and any external credential files must also be available inside the container.

The `kbomination-local` Compose project stores DuckDB in its own named volume. It is separate from the root HTTP Compose deployment and does not migrate existing data. Run only one writer per database volume. Stop services without deleting data with:

```sh
mise run local:down
```

Follow logs with `mise run local:logs`, inspect services with `mise run local:ps`, and pull the latest published application image with `mise run local:pull`. The original HTTP deployment remains available with `docker compose up --build -d --wait` from the repository root.
