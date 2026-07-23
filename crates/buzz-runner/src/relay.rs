//! Relay-connected runner control loop.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use buzz_core::kind::{KIND_RUNNER_DEPLOYMENT, KIND_RUNNER_FRAME};
use buzz_core::runner::{
    decrypt_runner_payload, encrypt_runner_payload, DeploymentStatusPayload, RunnerFrame,
    RunnerRuntime, RunnerStatusPayload, RUNNER_AGENT_TAG, RUNNER_PROTOCOL_VERSION, RUNNER_TAG,
};
use buzz_sdk::{build_runner_deployment_status, build_runner_frame, build_runner_status};
use buzz_ws_client::{NostrWsConnection, RelayMessage, WsClientError};
use nostr::{Event, Keys, PublicKey, Tag};
use serde_json::json;
use tracing::{info, warn};

use crate::config::RunnerConfig;
use crate::docker::ContainerEngine;
use crate::reconcile::Reconciler;
use crate::store::Store;

/// Run the reconnecting relay control plane forever.
pub async fn run_control_loop<E: ContainerEngine>(
    relay_url: &str,
    owner: PublicKey,
    keys: &Keys,
    store: &Store,
    engine: &E,
    config: &RunnerConfig,
) -> Result<(), String> {
    let mut backoff = 1u64;
    loop {
        match run_connected(relay_url, owner, keys, store, engine, config).await {
            Ok(()) => backoff = 1,
            Err(error) => {
                warn!(error, backoff, "runner relay connection ended");
                tokio::time::sleep(Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(60);
            }
        }
    }
}

async fn run_connected<E: ContainerEngine>(
    relay_url: &str,
    owner: PublicKey,
    keys: &Keys,
    store: &Store,
    engine: &E,
    config: &RunnerConfig,
) -> Result<(), String> {
    let runner_hex = keys.public_key().to_hex();
    let owner_hex = owner.to_hex();
    let registration_coordinate = format!("30178:{owner_hex}:{runner_hex}");
    let registration_tag =
        Tag::parse(["a", &registration_coordinate]).map_err(|error| error.to_string())?;
    let mut connection = NostrWsConnection::connect(relay_url)
        .await
        .map_err(|error| error.to_string())?;
    connection
        .authenticate(keys, Some(&registration_tag))
        .await
        .map_err(|error| error.to_string())?;
    connection
        .send_raw(&json!([
            "REQ",
            "runner-control",
            {
                "kinds": [KIND_RUNNER_DEPLOYMENT, KIND_RUNNER_FRAME],
                "#p": [runner_hex]
            }
        ]))
        .await
        .map_err(|error| error.to_string())?;
    info!("runner control-plane subscription active");

    let reconciler = Reconciler::new(store, engine, config, &owner_hex, &runner_hex);
    sync_runtime_catalog(store, engine, config).await?;
    reconciler.reconcile_all(now()).await?;
    publish_all_statuses(&mut connection, owner, keys, store).await?;

    let mut sweep = tokio::time::interval(Duration::from_secs(15));
    loop {
        tokio::select! {
            message = connection.next_event(Duration::from_secs(30)) => {
                match message {
                    Ok(RelayMessage::Event { event, .. }) => {
                        process_event(&mut connection, owner, keys, store, &event).await?;
                        reconciler.reconcile_all(now()).await?;
                        publish_all_statuses(&mut connection, owner, keys, store).await?;
                    }
                    Ok(RelayMessage::Closed { message, .. }) => {
                        return Err(format!("runner subscription closed: {message}"));
                    }
                    Ok(_) => {}
                    Err(WsClientError::Timeout) => {}
                    Err(error) => return Err(error.to_string()),
                }
            }
            _ = sweep.tick() => {
                reconciler.reconcile_all(now()).await?;
                publish_all_statuses(&mut connection, owner, keys, store).await?;
            }
        }
    }
}

async fn process_event(
    connection: &mut NostrWsConnection,
    owner: PublicKey,
    keys: &Keys,
    store: &Store,
    event: &Event,
) -> Result<(), String> {
    if event.pubkey != owner {
        return Err("received runner control event from a non-owner author".into());
    }
    match event.kind.as_u16() as u32 {
        KIND_RUNNER_DEPLOYMENT => {
            let agent = single_tag(event, RUNNER_AGENT_TAG)?;
            let runner = single_tag(event, RUNNER_TAG)?;
            if runner != keys.public_key().to_hex() {
                return Err("deployment runner tag does not match this runner".into());
            }
            let desired = decrypt_runner_payload(keys, event).map_err(|error| error.to_string())?;
            store.upsert_desired(agent, &desired)?;
        }
        KIND_RUNNER_FRAME => {
            let frame: RunnerFrame =
                decrypt_runner_payload(keys, event).map_err(|error| error.to_string())?;
            match frame {
                RunnerFrame::SecretsPut {
                    agent_pubkey,
                    generation,
                    secret_revision,
                    secrets,
                } => {
                    ensure_frame_agent(event, &agent_pubkey, "secrets_put")?;
                    let desired = store
                        .deployments()?
                        .into_iter()
                        .find(|deployment| deployment.agent_pubkey == agent_pubkey)
                        .ok_or_else(|| {
                            "secrets_put references an unknown deployment".to_string()
                        })?;
                    if desired.desired.generation != generation
                        || desired.desired.secret_revision != secret_revision
                    {
                        return Err("secrets_put generation or revision is stale".into());
                    }
                    store.put_secrets(&agent_pubkey, secret_revision, &secrets)?;
                    send_ack(
                        connection,
                        owner,
                        keys,
                        Some(agent_pubkey),
                        "secrets_put",
                        Some(generation),
                        Some(secret_revision),
                    )
                    .await?;
                }
                RunnerFrame::PurgeWorkspace { agent_pubkey } => {
                    ensure_frame_agent(event, &agent_pubkey, "purge_workspace")?;
                    purge_retired_workspace(store, &agent_pubkey)?;
                    send_ack(
                        connection,
                        owner,
                        keys,
                        Some(agent_pubkey),
                        "purge_workspace",
                        None,
                        None,
                    )
                    .await?;
                }
                RunnerFrame::Acknowledgement { .. } | RunnerFrame::Heartbeat { .. } => {}
            }
        }
        _ => {}
    }
    Ok(())
}

async fn send_ack(
    connection: &mut NostrWsConnection,
    owner: PublicKey,
    keys: &Keys,
    agent_pubkey: Option<String>,
    operation: &str,
    generation: Option<u64>,
    secret_revision: Option<u64>,
) -> Result<(), String> {
    let ack = RunnerFrame::Acknowledgement {
        agent_pubkey: agent_pubkey.clone(),
        operation: operation.into(),
        generation,
        secret_revision,
    };
    let content = encrypt_runner_payload(keys, &owner, &ack).map_err(|error| error.to_string())?;
    let event = build_runner_frame(
        &owner.to_hex(),
        &keys.public_key().to_hex(),
        agent_pubkey.as_deref(),
        "acknowledgement",
        &content,
    )
    .map_err(|error| error.to_string())?
    .sign_with_keys(keys)
    .map_err(|error| error.to_string())?;
    send_accepted(connection, event).await
}

fn purge_retired_workspace(store: &Store, agent_pubkey: &str) -> Result<(), String> {
    let retired = store
        .retired_workspaces()?
        .into_iter()
        .find(|(agent, _)| agent == agent_pubkey)
        .ok_or_else(|| "no retired workspace exists for that agent".to_string())?;
    if retired.1.exists() {
        std::fs::remove_dir_all(&retired.1)
            .map_err(|error| format!("purge retired workspace: {error}"))?;
    }
    store.remove_retired_workspace(agent_pubkey)
}

async fn sync_runtime_catalog<E: ContainerEngine>(
    store: &Store,
    engine: &E,
    config: &RunnerConfig,
) -> Result<(), String> {
    let mut resolved = Vec::new();
    for runtime in config.runtimes.values() {
        match engine.resolve_image(&runtime.image).await {
            Ok(image) => resolved.push((
                runtime.runtime_id.clone(),
                runtime.image.clone(),
                image.digest,
            )),
            Err(error) => {
                warn!(
                    runtime_id = runtime.runtime_id,
                    error, "runtime image is unavailable"
                );
            }
        }
    }
    store.replace_runtime_catalog(&resolved)
}

async fn publish_all_statuses(
    connection: &mut NostrWsConnection,
    owner: PublicKey,
    keys: &Keys,
    store: &Store,
) -> Result<(), String> {
    let deployments = store.deployments()?;
    let runtimes = store
        .runtime_catalog()?
        .into_iter()
        .map(|(runtime_id, image_digest)| RunnerRuntime {
            id: runtime_id,
            image_digest: Some(image_digest),
        })
        .collect();
    let status = RunnerStatusPayload {
        protocol_version: RUNNER_PROTOCOL_VERSION,
        runner_version: env!("CARGO_PKG_VERSION").into(),
        observed_at: now(),
        runtimes,
        agent_count: deployments
            .iter()
            .filter(|deployment| {
                deployment.desired.desired_state
                    != buzz_core::runner::DeploymentDesiredState::Deleted
            })
            .count()
            .try_into()
            .unwrap_or(u32::MAX),
        retired_workspaces: store
            .retired_workspaces()?
            .into_iter()
            .map(|(agent_pubkey, _)| agent_pubkey)
            .collect(),
    };
    let content =
        encrypt_runner_payload(keys, &owner, &status).map_err(|error| error.to_string())?;
    let event = build_runner_status(&owner.to_hex(), &keys.public_key().to_hex(), &content)
        .map_err(|error| error.to_string())?
        .sign_with_keys(keys)
        .map_err(|error| error.to_string())?;
    send_accepted(connection, event).await?;

    for deployment in deployments {
        let payload = DeploymentStatusPayload {
            protocol_version: RUNNER_PROTOCOL_VERSION,
            desired_generation: deployment.desired.generation,
            observed_generation: deployment.observed_generation,
            state: deployment.actual_state,
            last_error: deployment.last_error,
            image_digest: deployment.image_digest,
        };
        let content =
            encrypt_runner_payload(keys, &owner, &payload).map_err(|error| error.to_string())?;
        let event = build_runner_deployment_status(
            &owner.to_hex(),
            &keys.public_key().to_hex(),
            &deployment.agent_pubkey,
            &content,
        )
        .map_err(|error| error.to_string())?
        .sign_with_keys(keys)
        .map_err(|error| error.to_string())?;
        send_accepted(connection, event).await?;
    }

    let heartbeat = RunnerFrame::Heartbeat { observed_at: now() };
    let content =
        encrypt_runner_payload(keys, &owner, &heartbeat).map_err(|error| error.to_string())?;
    let event = build_runner_frame(
        &owner.to_hex(),
        &keys.public_key().to_hex(),
        None,
        "heartbeat",
        &content,
    )
    .map_err(|error| error.to_string())?
    .sign_with_keys(keys)
    .map_err(|error| error.to_string())?;
    send_accepted(connection, event).await
}

async fn send_accepted(connection: &mut NostrWsConnection, event: Event) -> Result<(), String> {
    let response = connection
        .send_event(event)
        .await
        .map_err(|error| error.to_string())?;
    if !response.accepted {
        return Err(format!("relay rejected runner event: {}", response.message));
    }
    Ok(())
}

fn single_tag<'a>(event: &'a Event, name: &str) -> Result<&'a str, String> {
    let mut values = event.tags.iter().filter_map(|tag| {
        let values = tag.as_slice();
        (values.first().map(String::as_str) == Some(name))
            .then(|| values.get(1).map(String::as_str))
            .flatten()
    });
    let value = values
        .next()
        .ok_or_else(|| format!("runner event is missing {name} tag"))?;
    if values.next().is_some() {
        return Err(format!("runner event has duplicate {name} tags"));
    }
    Ok(value)
}

fn ensure_frame_agent(event: &Event, encrypted_agent: &str, operation: &str) -> Result<(), String> {
    if single_tag(event, RUNNER_AGENT_TAG)? != encrypted_agent {
        return Err(format!(
            "{operation} encrypted agent does not match its public route"
        ));
    }
    Ok(())
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use nostr::{EventBuilder, Keys, Kind, Tag};

    use super::*;

    #[test]
    fn encrypted_frame_agent_must_match_public_route() {
        let author = Keys::generate();
        let routed_agent = Keys::generate().public_key().to_hex();
        let event = EventBuilder::new(Kind::Custom(KIND_RUNNER_FRAME as u16), "encrypted")
            .tags([
                Tag::parse([RUNNER_AGENT_TAG, &routed_agent]).expect("agent tag"),
                Tag::public_key(Keys::generate().public_key()),
            ])
            .sign_with_keys(&author)
            .expect("sign");

        assert!(ensure_frame_agent(&event, &routed_agent, "secrets_put").is_ok());
        assert!(ensure_frame_agent(
            &event,
            &Keys::generate().public_key().to_hex(),
            "secrets_put"
        )
        .is_err());
    }
}
