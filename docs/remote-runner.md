# Operating a remote Buzz runner

The Buzz runner is an always-on, single-owner supervisor for Docker-hosted
agents. It controls the host Docker socket and is therefore a trusted,
root-equivalent component. Do not run an untrusted runner image or share a
runner between owners.

The agent containers do not receive the Docker socket. They run with a
read-only root filesystem, all Linux capabilities dropped,
`no-new-privileges`, an isolated persistent workspace, a private tmpfs, and
operator-configured CPU and memory limits.

## Local end-to-end development

The repository includes an isolated convenience harness for testing the full
relay → runner → Docker agent → Desktop path without changing the normal Buzz
development database:

```bash
just remote-runner-dev up
just remote-runner-dev pair
just remote-runner-dev status
```

`up` starts a dedicated Postgres and Redis, builds the current branch's relay,
runner, and Sprig runtime image, then launches the relay, runner, and Desktop in
the background. It chooses a LAN-reachable relay URL so both Desktop and the
Docker agent can use the same Nostr community host.

Useful follow-up commands:

```bash
just remote-runner-dev logs runner --follow
just remote-runner-dev desktop
just remote-runner-dev down
just remote-runner-dev reset --yes
```

`down` preserves the isolated database, runner identity, encrypted secrets, and
workspaces so restart behavior can be tested. `reset --yes` permanently removes
only resources marked as belonging to this harness. Run
`just remote-runner-dev --help` for port, host, image, and state-directory
overrides.

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
