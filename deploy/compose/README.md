# Buzz Docker Compose deployment

This is the single-node/VPS deployment bundle. It is intentionally separate from
the root `docker-compose.yml`, which remains local development infrastructure.

## Quick start

```bash
cd deploy/compose
cp .env.example .env
$EDITOR .env       # replace every CHANGE_ME value
./run.sh start
```

For a public VPS with automatic Let's Encrypt certificates:

```bash
cd deploy/compose
BUZZ_COMPOSE_TLS=true ./run.sh start
```

For a Cloudflare Tunnel or another TLS-terminating proxy whose origin is
`http://127.0.0.1:3000`, enable the stateless NIP-AB pairing sidecar:

```bash
# Set this in .env:
BUZZ_PAIRING_RELAY_URL=wss://buzz.example.com/pair

./run.sh start
```

The pairing overlay puts a local Caddy origin on port 3000. It proxies `/pair`
to `buzz-pair-relay` and all other requests to the main relay, so no tunnel or
DNS change is required. `run.sh` automatically enables the overlay whenever
`BUZZ_PAIRING_RELAY_URL` is set in `.env`; `BUZZ_COMPOSE_PAIRING=true` is
available as an explicit override.

## Always-on agents

The optional Remote Runner supervises hardened agent containers independently
of Desktop. It controls the host Docker socket and is therefore a trusted,
root-equivalent service intended for a single owner.

Enable it in `.env`:

```bash
BUZZ_RUNNER_ENABLED=true
BUZZ_IMAGE=buzz-relay:runner-local
BUZZ_RUNNER_IMAGE=buzz-runner:local
BUZZ_RUNNER_AGENT_IMAGE=buzz-agent:local
BUZZ_RUNNER_RUNTIMES={"buzz-agent":"buzz-agent:local"}
```

Build the runner-capable relay and runtime images, then start the stack:

```bash
./run.sh runner-build
./run.sh start
./run.sh runner-pair
```

Pairing is completed from Buzz Desktop under **Settings → Remote runners**.
Confirm the six-digit SAS on both screens. The owner key remains on Desktop;
the server persists only its own runner identity, encrypted deployment
secrets, and agent workspaces under `/var/lib/buzz-runner`.

The bootstrap script should eventually replace manual `.env` editing for normal
users. It is responsible for generating stable secrets and, optionally, an owner
keypair.

## Production notes

- Requires Docker Compose v2.24.4 or newer; the TLS override uses Compose's
  `!reset` tag to remove the direct relay port when Caddy terminates HTTPS.
- Default `BUZZ_IMAGE` tracks `ghcr.io/block/buzz:main` for early testing. Pin it to `ghcr.io/block/buzz:sha-<7>` or a semver release tag for production once available.
- Keep `BUZZ_RELAY_PRIVATE_KEY`, `BUZZ_GIT_HOOK_HMAC_SECRET`, database/Redis,
  and S3 secrets stable across restarts.
- `RELAY_OWNER_PUBKEY` is intentionally not prefixed with `BUZZ_`; it must be a
  64-character hex Nostr pubkey when closed relay mode is enabled.
- `BUZZ_AUTO_MIGRATE` is opt-in. Set `BUZZ_AUTO_MIGRATE=true` or run
  `buzz-admin migrate` before starting the relay when bootstrapping a fresh
  database. Auto-migration requires an image that includes embedded SQLx
  migrations.
- The stack uses Postgres, Redis, MinIO, and a git data volume because
  those are real Buzz dependencies today. Minimal mode can simplify this later.

Run `./run.sh backup-hint` for the backup checklist.

## Validation

Before sharing an install link publicly, verify a fresh install with:

```bash
cd deploy/compose
cp .env.example .env
$EDITOR .env
./run.sh config
./run.sh start
curl -fsS "http://127.0.0.1:$(grep -E '^BUZZ_HTTP_PORT=' .env | cut -d= -f2-)/_liveness"
./run.sh status
```
