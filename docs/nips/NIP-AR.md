# NIP-AR: Remote Always-On Agent Runners

`draft` `optional`

NIP-AR defines a relay-mediated control plane for running Buzz-managed agents
on an always-on host. The runner has its own Nostr key and is paired to exactly
one owner. An owner may pair several runners and a runner may host several
agents.

## Vocabulary

- **Agent**: a Buzz identity and behavioral configuration.
- **Runner**: a paired remote execution host.
- **Deployment**: the binding between one agent and one runner.
- **Runtime**: an allowlisted ACP harness image.
- **Desired state**: owner-authored `running`, `stopped`, or `deleted`.
- **Actual state**: runner-observed container state.

The relay is the only control-plane transport. Runners do not expose a Buzz
HTTP API.

## Event kinds

| Kind | Author | Lifetime | Purpose |
|---|---|---|---|
| `30178` | owner | parameterized replaceable | runner registration or revocation |
| `30179` | owner | parameterized replaceable | encrypted deployment desired state |
| `30180` | runner | parameterized replaceable | encrypted runner capability/status |
| `30181` | runner | parameterized replaceable | encrypted deployment actual state |
| `24201` | owner or runner | ephemeral | encrypted provisioning, acknowledgement, heartbeat |

All five kinds carry NIP-44 v2 ciphertext. A relay MUST reject a payload that
does not fit the NIP-44 v2 envelope. Raw credentials MUST NOT appear in tags,
durable event content, status payloads, or registration payloads.

## Coordinates and tags

All public keys are lower-case 64-character hex strings.

Runner registration is keyed by the runner:

```json
[
  ["d", "<runner-pubkey>"],
  ["p", "<runner-pubkey>"],
  ["runner", "<runner-pubkey>"],
  ["status", "active"]
]
```

`status` is exactly `active` or `revoked`. Registration content is encrypted
to the runner. Replacing an active registration with `revoked` immediately
invalidates runner authorization, including an already-open connection.

A deployment coordinate is:

```text
<runner-pubkey>:<agent-pubkey>
```

Desired-state events use that coordinate as `d`, address the runner with `p`,
and repeat both components in `runner` and `agent` tags. Deployment status
uses the same coordinate and addresses the owner with `p`.

Runner status uses `d=<runner-pubkey>`, `p=<owner-pubkey>`, and a matching
`runner` tag.

Ephemeral frames use `p=<recipient-pubkey>`, a `runner` tag, an optional
`agent` tag, and one of:

```json
["frame", "secrets_put"]
["frame", "purge_workspace"]
["frame", "acknowledgement"]
["frame", "heartbeat"]
```

## Pairing

Pairing reuses NIP-AB transport and SAS confirmation with the custom payload
type `buzz.runner.pair.v1`. The runner CLI displays a one-time URI and SAS.
Desktop and runner both confirm the SAS. The exchange transfers:

1. the runner public key and protocol version;
2. the owner public key;
3. an owner-signed active kind `30178` registration.

The owner's secret key is never transferred. A runner MUST refuse a
registration whose signature, author, `d`, `p`, `runner`, or `status` tags do
not match the confirmed pairing transcript.

## Authentication and relay authorization

The runner authenticates with NIP-42 using its own key. Its auth event includes
an `a` tag referencing the active registration coordinate:

```text
30178:<owner-pubkey>:<runner-pubkey>
```

The relay resolves the latest registration head for that owner and runner. A
restricted runner session may:

- read kind `30179` events whose `p` and `runner` tags equal its public key;
- receive kind `24201` events whose `p` equals its public key and whose
  `runner` tag equals its public key;
- publish kinds `30180`, `30181`, and `24201` addressed only to its registered
  owner.

It receives no channel, membership-management, repository, moderation, relay
administration, or owner authority. Revocation is checked on every runner read
and write, not only at connection authentication.

Owner reads are restricted to events they authored or runner events whose
`p` tag equals the authenticated owner. ID-only, COUNT, search, and mixed-kind
filters MUST enforce the same result-level rules.

## Encrypted payloads

Every payload includes `protocol_version: 1`.

Kind `30179` includes:

- `generation` (positive, monotonically increasing);
- `desired_state`;
- `runtime_id`;
- `relay_url`;
- `workspace_policy`;
- `secret_revision`;
- non-secret runtime configuration.

It never includes image names, arbitrary commands, agent keys, auth tags,
provider credentials, or a fully materialized environment.

Kind `30180` includes runner version, observation time, agent count, retired
workspace agent IDs, and the available runtime IDs with resolved image digests.
Runtime IDs are identifiers, not executable input.

Kind `30181` includes desired generation, observed generation, actual state,
resolved image digest, and an optional redacted error.

`secrets_put` frames contain the agent key, auth tag, and materialized runtime
environment. The runner persists an encrypted blob and acknowledges the
revision before starting the agent. The maximum serialized secret object is
49,152 bytes. Logs and error messages MUST redact it.

`purge_workspace` contains only the retired agent public key. It is
owner-to-runner, encrypted, ephemeral, and acknowledged before Desktop reports
the purge complete.

## Generations and lifecycle

Only a newer owner generation changes a deployment's intended revision.
Configuration edits may publish a pending generation, but an active agent is
not silently restarted in version 1. Owner Start or Restart publishes a new
`running` generation and clears the clean-stop latch.

The runner reconciles on startup, relay reconnect, deployment change,
container exit, and a periodic safety sweep. A clean harness exit following
owner `!shutdown` becomes `stopped_by_agent` and is latched for that generation.
Runner and host restarts MUST NOT resurrect it. A new generation clears the
latch.

`deleted` stops and removes the container, deletes runtime secrets
immediately, and moves the workspace into the retired area. Purging a retired
workspace is a separate, explicit owner operation acknowledged by the runner.

Runner or relay outages do not stop an already healthy agent container. The
agent harness reconnects to the relay independently and runner reconciliation
resumes after connectivity returns.

## Runtime security requirements

A runner is a trusted, root-equivalent, single-owner component because it
controls the Docker socket. Agent containers are not trusted and MUST:

- have no Docker socket and no privileged mode;
- drop all capabilities and set `no-new-privileges`;
- use a read-only root filesystem;
- receive only writable workspace and temporary mounts;
- receive secrets from `0400` files mounted read-only from host tmpfs;
- use operator-configured CPU and memory limits;
- carry runner, owner, agent, generation, runtime ID, and image digest labels.

The operator maps runtime IDs to allowlisted images. The runner resolves and
records immutable digests and rejects unknown IDs, arbitrary images, and
arbitrary commands. Desktop intersects advertised IDs with its canonical Rust
runtime catalog; the runner advertisement never defines harness capabilities
or environment mappings.

## Discovery

Supporting relays advertise:

```json
{
  "buzz": {
    "remote_runner_protocol": 1
  }
}
```

Clients hide runner management against a relay that omits this value or
advertises an unsupported version. Local agents and legacy backend providers
remain unchanged.
