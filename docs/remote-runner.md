# Operating a remote Buzz runner

The Buzz runner is an always-on, single-owner supervisor for Docker-hosted
agents. It controls the host Docker socket and is therefore a trusted,
root-equivalent component. Do not run an untrusted runner image or share a
runner between owners.

The agent containers do not receive the Docker socket. They run with a
read-only root filesystem, all Linux capabilities dropped,
`no-new-privileges`, an isolated persistent workspace, a private tmpfs, and
operator-configured CPU and memory limits.

## Host preparation

The runner uses two host paths:

- `/var/lib/buzz-runner` for its identity, SQLite database, encrypted secrets,
  workspaces, and retired workspaces;
- `/run/buzz-runner` for temporary `0400` secret files. On normal Linux hosts,
  `/run` is tmpfs.

Create and protect them before starting Compose:

```bash
sudo install -d -m 0700 /var/lib/buzz-runner /run/buzz-runner
docker compose --profile runner-build build buzz-agent-image buzz-runner
```

Set `BUZZ_RELAY_URL` to the main relay. The pair command persists the
confirmed owner's public key in runner state; `BUZZ_RUNNER_OWNER_PUBKEY` is an
optional unattended-provisioning override. The owner secret key never belongs
on the server.

The runtime allowlist is a JSON object:

```bash
export BUZZ_RUNNER_RUNTIMES='{
  "buzz-agent": "buzz-agent:local",
  "goose": "registry.example/approved-goose@sha256:..."
}'
```

IDs must match Desktop's canonical Rust runtime catalog. Values are
operator-controlled images; deployment events cannot provide an image or
command.

## Pairing

Start the one-time pairing display:

```bash
docker compose exec buzz-runner buzz-runner pair \
  --relay wss://buzz.example
```

Paste the URI into **Settings → Remote runners → Pair**, verify the six-digit
SAS, and confirm. Desktop publishes the owner-signed active registration.
Paste Desktop's displayed owner public key into the runner prompt and confirm
the matching SAS there. The runner thereafter authenticates with its own key
and that registration coordinate. Revocation immediately closes its relay
session.

## Lifecycle and recovery

The runner reconciles after startup, reconnect, desired-state changes,
container exits, and every 15 seconds. Relay outages do not stop healthy agent
containers. A clean harness exit is latched as `stopped_by_agent` for its
current generation and survives runner or host restart. Desktop Start/Restart
publishes a new generation.

Delete removes the container and runtime secrets immediately, then moves the
workspace below `/var/lib/buzz-runner/retired`. Purge is deliberately separate:

```bash
docker compose exec buzz-runner buzz-runner purge <agent-pubkey>
```
