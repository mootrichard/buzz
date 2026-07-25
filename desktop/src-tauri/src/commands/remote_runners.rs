use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use buzz_core_pkg::kind::{KIND_RUNNER_DEPLOYMENT_STATUS, KIND_RUNNER_STATUS};
use buzz_core_pkg::runner::{
    decrypt_runner_payload, encrypt_runner_payload, DeploymentDesiredPayload,
    DeploymentDesiredState, DeploymentSecrets, DeploymentStatusPayload, RunnerFrame,
    RunnerRegistrationPayload, RunnerRegistrationState, RunnerStatusPayload, WorkspacePolicy,
    RUNNER_PROTOCOL_VERSION,
};
use nostr::{Event, PublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Manager, State};
use url::Url;

use crate::{
    app_state::AppState,
    managed_agents::{
        build_managed_agent_summary, known_acp_runtime, load_managed_agents, load_personas,
        BackendKind, ManagedAgentRecord, ManagedAgentSummary,
    },
    relay::{
        query_relay, relay_api_base_url_with_override, relay_ws_url_with_override, submit_event,
    },
};

const RUNNER_STORE_FILE: &str = "remote-runners.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteRunner {
    pub runner_pubkey: String,
    pub name: String,
    pub relay_url: String,
    pub protocol_version: u16,
    pub runner_version: Option<String>,
    pub online: bool,
    pub last_seen: Option<u64>,
    pub runtimes: Vec<String>,
    pub agent_count: u32,
    #[serde(default)]
    pub retired_workspaces: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteDeploymentState {
    pub agent_pubkey: String,
    pub runner_pubkey: String,
    pub desired_generation: u64,
    pub observed_generation: u64,
    pub deployment_state: String,
    pub last_runner_error: Option<String>,
    #[serde(default)]
    pub configuration_revision: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct RemoteRunnerStore {
    #[serde(default)]
    runners: Vec<RemoteRunner>,
    #[serde(default)]
    deployments: Vec<RemoteDeploymentState>,
}

fn store_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("failed to resolve app data dir: {error}"))?
        .join("agents");
    fs::create_dir_all(&dir).map_err(|error| format!("failed to create agents dir: {error}"))?;
    Ok(dir.join(RUNNER_STORE_FILE))
}

fn load_store(app: &AppHandle) -> Result<RemoteRunnerStore, String> {
    let path = store_path(app)?;
    if !path.exists() {
        return Ok(RemoteRunnerStore::default());
    }
    let bytes = fs::read(&path).map_err(|error| format!("read remote runners: {error}"))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("parse remote runners: {error}"))
}

fn save_store(app: &AppHandle, store: &RemoteRunnerStore) -> Result<(), String> {
    let path = store_path(app)?;
    let temp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(store)
        .map_err(|error| format!("encode remote runners: {error}"))?;
    fs::write(&temp, bytes).map_err(|error| format!("write remote runners: {error}"))?;
    fs::rename(&temp, &path).map_err(|error| format!("replace remote runners: {error}"))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn single_tag(event: &Event, name: &str) -> Option<String> {
    event.tags.iter().find_map(|tag| {
        let parts = tag.as_slice();
        (parts.first().map(String::as_str) == Some(name))
            .then(|| parts.get(1).cloned())
            .flatten()
    })
}

fn parse_pairing_uri(uri: &str) -> Result<(String, String, u16, String), String> {
    let url = Url::parse(uri).map_err(|error| format!("invalid runner pairing URI: {error}"))?;
    if url.scheme() != "buzz" || url.host_str() != Some("runner-pair") {
        return Err("pairing URI must start with buzz://runner-pair".into());
    }
    let values = url.query_pairs().collect::<BTreeMap<_, _>>();
    let relay = values
        .get("relay")
        .map(ToString::to_string)
        .ok_or("pairing URI is missing relay")?;
    let runner = values
        .get("runner")
        .map(ToString::to_string)
        .ok_or("pairing URI is missing runner")?;
    PublicKey::from_hex(&runner).map_err(|_| "runner public key is invalid".to_string())?;
    let version = values
        .get("v")
        .ok_or("pairing URI is missing protocol version")?
        .parse::<u16>()
        .map_err(|_| "runner protocol version is invalid".to_string())?;
    if version != RUNNER_PROTOCOL_VERSION {
        return Err(format!(
            "runner protocol {version} is incompatible with Desktop protocol {RUNNER_PROTOCOL_VERSION}"
        ));
    }
    let nonce = values
        .get("nonce")
        .map(ToString::to_string)
        .ok_or("pairing URI is missing nonce")?;
    let nonce_bytes = hex::decode(&nonce).map_err(|_| "pairing nonce is invalid".to_string())?;
    if nonce_bytes.len() != 32 {
        return Err("pairing nonce must be 32 bytes".into());
    }
    Ok((relay, runner, version, nonce))
}

fn pairing_sas(nonce_hex: &str) -> Result<String, String> {
    let nonce = hex::decode(nonce_hex).map_err(|_| "pairing nonce is invalid".to_string())?;
    let digest = Sha256::digest(nonce);
    let value = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % 1_000_000;
    Ok(format!("{value:06}"))
}

#[tauri::command]
pub fn inspect_remote_runner_pairing_uri(uri: String) -> Result<String, String> {
    let (_, _, _, nonce) = parse_pairing_uri(&uri)?;
    pairing_sas(&nonce)
}

async fn remote_runner_protocol_version(state: &AppState) -> Result<Option<u16>, String> {
    let response = state
        .http_client
        .get(relay_api_base_url_with_override(state))
        .header("Accept", "application/nostr+json")
        .send()
        .await
        .map_err(|_| "relay unreachable: could not load relay metadata".to_string())?;
    if !response.status().is_success() {
        return Ok(None);
    }
    let body = response
        .json::<serde_json::Value>()
        .await
        .map_err(|error| format!("invalid relay metadata: {error}"))?;
    Ok(body
        .get("buzz")
        .and_then(|buzz| buzz.get("remote_runner_protocol"))
        .and_then(serde_json::Value::as_u64)
        .and_then(|version| u16::try_from(version).ok()))
}

#[tauri::command]
pub async fn get_remote_runner_protocol_version(
    state: State<'_, AppState>,
) -> Result<Option<u16>, String> {
    remote_runner_protocol_version(&state).await
}

#[tauri::command]
pub async fn pair_remote_runner(
    uri: String,
    confirmed_sas: String,
    name: Option<String>,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<RemoteRunner, String> {
    let (relay_url, runner_pubkey, protocol_version, nonce) = parse_pairing_uri(&uri)?;
    if relay_url.trim_end_matches('/') != relay_ws_url_with_override(&state).trim_end_matches('/') {
        return Err("runner pairing URI targets a different relay than this workspace".into());
    }
    let expected_sas = pairing_sas(&nonce)?;
    if confirmed_sas != expected_sas {
        return Err("SAS mismatch; runner was not paired".into());
    }
    let runner_key =
        PublicKey::from_hex(&runner_pubkey).map_err(|_| "invalid runner public key".to_string())?;
    let runner_name = name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("Remote runner")
        .to_string();
    let keys = state.signing_keys()?;
    let payload = RunnerRegistrationPayload {
        protocol_version,
        name: runner_name.clone(),
    };
    let encrypted =
        encrypt_runner_payload(&keys, &runner_key, &payload).map_err(|error| error.to_string())?;
    let builder = buzz_sdk_pkg::build_runner_registration(
        &runner_pubkey,
        RunnerRegistrationState::Active,
        &encrypted,
    )
    .map_err(|error| error.to_string())?;
    let result = submit_event(builder, &state).await?;
    if !result.accepted {
        return Err(format!(
            "relay rejected runner registration: {}",
            result.message
        ));
    }

    let runner = RemoteRunner {
        runner_pubkey: runner_pubkey.clone(),
        name: runner_name,
        relay_url,
        protocol_version,
        runner_version: None,
        online: false,
        last_seen: None,
        runtimes: Vec::new(),
        agent_count: 0,
        retired_workspaces: Vec::new(),
    };
    let mut store = load_store(&app)?;
    store
        .runners
        .retain(|entry| entry.runner_pubkey != runner_pubkey);
    store.runners.push(runner.clone());
    save_store(&app, &store)?;
    Ok(runner)
}

#[tauri::command]
pub async fn revoke_remote_runner(
    runner_pubkey: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let runner_key =
        PublicKey::from_hex(&runner_pubkey).map_err(|_| "invalid runner public key".to_string())?;
    let keys = state.signing_keys()?;
    let payload = RunnerRegistrationPayload {
        protocol_version: RUNNER_PROTOCOL_VERSION,
        name: "revoked".into(),
    };
    let encrypted =
        encrypt_runner_payload(&keys, &runner_key, &payload).map_err(|error| error.to_string())?;
    let builder = buzz_sdk_pkg::build_runner_registration(
        &runner_pubkey,
        RunnerRegistrationState::Revoked,
        &encrypted,
    )
    .map_err(|error| error.to_string())?;
    let result = submit_event(builder, &state).await?;
    if !result.accepted {
        return Err(format!(
            "relay rejected runner revocation: {}",
            result.message
        ));
    }
    let mut store = load_store(&app)?;
    store
        .runners
        .retain(|entry| entry.runner_pubkey != runner_pubkey);
    save_store(&app, &store)
}

#[tauri::command]
pub async fn list_remote_runners(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<Vec<RemoteRunner>, String> {
    if remote_runner_protocol_version(&state).await?.is_none() {
        return Ok(Vec::new());
    }
    refresh_remote_runner_statuses(&app, &state).await?;
    Ok(load_store(&app)?.runners)
}

pub(crate) async fn refresh_remote_runner_statuses(
    app: &AppHandle,
    state: &AppState,
) -> Result<(), String> {
    let mut store = load_store(app)?;
    let owner = state.signing_keys()?;
    let owner_hex = owner.public_key().to_hex();
    let runner_pubkeys = store
        .runners
        .iter()
        .map(|runner| runner.runner_pubkey.clone())
        .collect::<Vec<_>>();
    if !runner_pubkeys.is_empty() {
        let events = query_relay(
            state,
            &[
                serde_json::json!({
                    "kinds": [KIND_RUNNER_STATUS],
                    "authors": runner_pubkeys,
                    "#p": [owner_hex],
                    "limit": 256
                }),
                serde_json::json!({
                    "kinds": [KIND_RUNNER_DEPLOYMENT_STATUS],
                    "#p": [owner.public_key().to_hex()],
                    "limit": 1024
                }),
            ],
        )
        .await?;
        apply_status_events(&mut store, &owner, events);
        save_store(app, &store)?;
    }
    Ok(())
}

fn apply_status_events(store: &mut RemoteRunnerStore, owner: &nostr::Keys, events: Vec<Event>) {
    let current = now();
    for event in events {
        if event.kind.as_u16() as u32 == KIND_RUNNER_STATUS {
            if let Ok(payload) = decrypt_runner_payload::<RunnerStatusPayload>(owner, &event) {
                if let Some(runner) = store
                    .runners
                    .iter_mut()
                    .find(|runner| runner.runner_pubkey == event.pubkey.to_hex())
                {
                    runner.runner_version = Some(payload.runner_version);
                    runner.last_seen = Some(payload.observed_at);
                    runner.online = current.saturating_sub(payload.observed_at) <= 45;
                    runner.runtimes = payload
                        .runtimes
                        .into_iter()
                        .map(|runtime| runtime.id)
                        .collect();
                    runner.agent_count = payload.agent_count;
                    runner.retired_workspaces = payload.retired_workspaces;
                }
            }
        } else if event.kind.as_u16() as u32 == KIND_RUNNER_DEPLOYMENT_STATUS {
            let Some(agent_pubkey) = single_tag(&event, "agent") else {
                continue;
            };
            let Ok(payload) = decrypt_runner_payload::<DeploymentStatusPayload>(owner, &event)
            else {
                continue;
            };
            let state = RemoteDeploymentState {
                agent_pubkey: agent_pubkey.clone(),
                runner_pubkey: event.pubkey.to_hex(),
                desired_generation: payload.desired_generation,
                observed_generation: payload.observed_generation,
                deployment_state: serde_json::to_value(payload.state)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_string))
                    .unwrap_or_else(|| "error".into()),
                last_runner_error: payload.last_error,
                configuration_revision: store
                    .deployments
                    .iter()
                    .find(|entry| entry.agent_pubkey == agent_pubkey)
                    .map(|entry| entry.configuration_revision.clone())
                    .unwrap_or_default(),
            };
            store
                .deployments
                .retain(|entry| entry.agent_pubkey != agent_pubkey);
            store.deployments.push(state);
        }
    }
}

pub(crate) fn deployment_state(
    app: &AppHandle,
    agent_pubkey: &str,
) -> Option<RemoteDeploymentState> {
    load_store(app)
        .ok()?
        .deployments
        .into_iter()
        .find(|entry| entry.agent_pubkey == agent_pubkey)
}

fn next_generation(app: &AppHandle, agent_pubkey: &str) -> u64 {
    deployment_state(app, agent_pubkey).map_or_else(
        || now().max(1),
        |state| state.desired_generation.saturating_add(1),
    )
}

fn apply_remote_runtime_environment(
    environment: &mut BTreeMap<String, String>,
    mcp_command: Option<&str>,
    mcp_hooks: bool,
) {
    environment.insert(
        "BUZZ_ACP_MCP_COMMAND".into(),
        mcp_command.unwrap_or_default().to_string(),
    );
    if mcp_hooks {
        environment.insert("MCP_HOOK_SERVERS".into(), "*".into());
    }
}

pub(crate) async fn publish_remote_deployment(
    app: &AppHandle,
    state: &AppState,
    record: &ManagedAgentRecord,
    desired_state: DeploymentDesiredState,
) -> Result<(), String> {
    let BackendKind::Runner { runner_pubkey } = &record.backend else {
        return Err("agent is not assigned to a runner".into());
    };
    let runner =
        PublicKey::from_hex(runner_pubkey).map_err(|_| "invalid runner public key".to_string())?;
    let effective_command = crate::managed_agents::record_agent_command(
        record,
        &load_personas(app).unwrap_or_default(),
    );
    let runtime = known_acp_runtime(&effective_command)
        .ok_or_else(|| "agent harness is not in the Rust runtime catalog".to_string())?;
    let paired_runner = load_store(app)?
        .runners
        .into_iter()
        .find(|entry| entry.runner_pubkey == *runner_pubkey)
        .ok_or_else(|| "runner is not paired".to_string())?;
    if desired_state == DeploymentDesiredState::Running
        && !paired_runner.runtimes.iter().any(|id| id == runtime.id)
    {
        return Err(format!(
            "runner {} does not advertise runtime {}",
            paired_runner.name, runtime.id
        ));
    }
    let generation = next_generation(app, &record.pubkey);
    let secret_revision = generation;
    let owner = state.signing_keys()?;
    let desired = DeploymentDesiredPayload {
        protocol_version: RUNNER_PROTOCOL_VERSION,
        generation,
        desired_state,
        runtime_id: runtime.id.to_string(),
        relay_url: relay_ws_url_with_override(state),
        workspace_policy: WorkspacePolicy::Persistent,
        secret_revision,
        config: BTreeMap::new(),
    };
    desired.validate().map_err(|error| error.to_string())?;
    let encrypted =
        encrypt_runner_payload(&owner, &runner, &desired).map_err(|error| error.to_string())?;
    let builder = buzz_sdk_pkg::build_runner_deployment(runner_pubkey, &record.pubkey, &encrypted)
        .map_err(|error| error.to_string())?;
    let result = submit_event(builder, state).await?;
    if !result.accepted {
        return Err(format!("relay rejected deployment: {}", result.message));
    }

    if desired_state == DeploymentDesiredState::Running {
        let personas = load_personas(app).unwrap_or_default();
        let global = crate::managed_agents::load_global_agent_config(app).unwrap_or_default();
        let mut environment = crate::managed_agents::resolve_effective_agent_env(
            record,
            &personas,
            Some(runtime),
            &global,
        )
        .env;
        environment.insert("BUZZ_RELAY_URL".into(), relay_ws_url_with_override(state));
        environment.insert("BUZZ_ACP_AGENT_COMMAND".into(), effective_command.clone());
        environment.insert(
            "BUZZ_ACP_AGENT_ARGS".into(),
            crate::managed_agents::normalize_agent_args(
                &effective_command,
                record.agent_args.clone(),
            )
            .join(","),
        );
        environment.insert("BUZZ_ACP_AGENTS".into(), record.parallelism.to_string());
        environment.insert("BUZZ_ACP_MULTIPLE_EVENT_HANDLING".into(), "steer".into());
        environment.insert("BUZZ_ACP_DEDUP".into(), "queue".into());
        environment.insert("BUZZ_ACP_RELAY_OBSERVER".into(), "true".into());
        apply_remote_runtime_environment(&mut environment, runtime.mcp_command, runtime.mcp_hooks);
        if let Some(prompt) = crate::managed_agents::spawn_hash::effective_spawn_prompt(record) {
            environment.insert("BUZZ_ACP_SYSTEM_PROMPT".into(), prompt);
        }
        if let Some(idle) = record.idle_timeout_seconds {
            environment.insert("BUZZ_ACP_IDLE_TIMEOUT".into(), idle.to_string());
        }
        if let Some(maximum) = record.max_turn_duration_seconds {
            environment.insert("BUZZ_ACP_MAX_TURN_DURATION".into(), maximum.to_string());
        }
        let owner_pubkey = owner.public_key().to_hex();
        let (gate_set, _) =
            crate::managed_agents::build_respond_to_env(record, Some(&owner_pubkey))?;
        environment.extend(
            gate_set
                .into_iter()
                .map(|(key, value)| (key.to_string(), value)),
        );
        let secrets = DeploymentSecrets {
            agent_private_key: record.private_key_nsec.clone(),
            auth_tag: record.auth_tag.clone().unwrap_or_default(),
            environment,
        };
        let frame = RunnerFrame::SecretsPut {
            agent_pubkey: record.pubkey.clone(),
            generation,
            secret_revision,
            secrets,
        };
        frame.validate().map_err(|error| error.to_string())?;
        let encrypted =
            encrypt_runner_payload(&owner, &runner, &frame).map_err(|error| error.to_string())?;
        let builder = buzz_sdk_pkg::build_runner_frame(
            runner_pubkey,
            runner_pubkey,
            Some(&record.pubkey),
            "secrets_put",
            &encrypted,
        )
        .map_err(|error| error.to_string())?;
        let result = submit_event(builder, state).await?;
        if !result.accepted {
            return Err(format!(
                "relay rejected secret provisioning: {}",
                result.message
            ));
        }
    }

    let mut store = load_store(app)?;
    store
        .deployments
        .retain(|entry| entry.agent_pubkey != record.pubkey);
    store.deployments.push(RemoteDeploymentState {
        agent_pubkey: record.pubkey.clone(),
        runner_pubkey: runner_pubkey.clone(),
        desired_generation: generation,
        observed_generation: 0,
        deployment_state: match desired_state {
            DeploymentDesiredState::Running => "waiting_for_secrets",
            DeploymentDesiredState::Stopped => "stopped_by_owner",
            DeploymentDesiredState::Deleted => "deleting",
        }
        .into(),
        last_runner_error: None,
        configuration_revision: remote_configuration_revision(record, app),
    });
    save_store(app, &store)
}

pub(crate) async fn deploy_new_remote_agent(
    app: &AppHandle,
    state: &AppState,
    agent_pubkey: &str,
) -> Result<(), String> {
    let record = {
        let _guard = state
            .managed_agents_store_lock
            .lock()
            .map_err(|error| error.to_string())?;
        load_managed_agents(app)?
            .into_iter()
            .find(|record| record.pubkey == agent_pubkey)
            .ok_or_else(|| "agent disappeared".to_string())?
    };
    publish_remote_deployment(app, state, &record, DeploymentDesiredState::Running).await
}

async fn try_change_remote_agent_state(
    app: &AppHandle,
    state: &AppState,
    agent_pubkey: &str,
    desired_state: DeploymentDesiredState,
) -> Result<Option<ManagedAgentSummary>, String> {
    let record = {
        let _guard = state
            .managed_agents_store_lock
            .lock()
            .map_err(|error| error.to_string())?;
        load_managed_agents(app)?
            .into_iter()
            .find(|record| record.pubkey == agent_pubkey)
            .filter(|record| matches!(record.backend, BackendKind::Runner { .. }))
    };
    let Some(record) = record else {
        return Ok(None);
    };
    publish_remote_deployment(app, state, &record, desired_state).await?;
    let _guard = state
        .managed_agents_store_lock
        .lock()
        .map_err(|error| error.to_string())?;
    let records = load_managed_agents(app)?;
    let runtimes = state
        .managed_agent_processes
        .lock()
        .map_err(|error| error.to_string())?;
    let updated = records
        .iter()
        .find(|entry| entry.pubkey == agent_pubkey)
        .ok_or_else(|| format!("agent {agent_pubkey} not found"))?;
    let personas = load_personas(app).unwrap_or_default();
    build_managed_agent_summary(app, updated, &runtimes, &personas).map(Some)
}

pub(crate) async fn try_start_remote_agent(
    app: &AppHandle,
    state: &AppState,
    agent_pubkey: &str,
) -> Result<Option<ManagedAgentSummary>, String> {
    try_change_remote_agent_state(app, state, agent_pubkey, DeploymentDesiredState::Running).await
}

pub(crate) async fn try_stop_remote_agent(
    app: &AppHandle,
    state: &AppState,
    agent_pubkey: &str,
) -> Result<Option<ManagedAgentSummary>, String> {
    try_change_remote_agent_state(app, state, agent_pubkey, DeploymentDesiredState::Stopped).await
}

pub(crate) async fn prepare_remote_agent_delete(
    app: &AppHandle,
    state: &AppState,
    agent_pubkey: &str,
    force: bool,
) -> Result<(), String> {
    let record = {
        let _guard = state
            .managed_agents_store_lock
            .lock()
            .map_err(|error| error.to_string())?;
        load_managed_agents(app)?
            .into_iter()
            .find(|record| record.pubkey == agent_pubkey)
            .filter(|record| matches!(record.backend, BackendKind::Runner { .. }))
    };
    let Some(record) = record else {
        return Ok(());
    };
    let deletion = async {
        publish_remote_deployment(app, state, &record, DeploymentDesiredState::Deleted).await?;
        for _ in 0..20 {
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            refresh_remote_runner_statuses(app, state).await?;
            if deployment_state(app, agent_pubkey)
                .is_some_and(|status| status.deployment_state == "deleted")
            {
                return Ok(());
            }
        }
        Err("timed out waiting for the runner's deleted status".to_string())
    }
    .await;
    if let Err(error) = deletion {
        if !force {
            return Err(format!(
                "runner did not acknowledge deletion; retry or confirm forced local deletion: {error}"
            ));
        }
        eprintln!(
            "buzz-desktop: forced local deletion orphaned runner deployment {agent_pubkey}: {error}"
        );
    }
    Ok(())
}

fn remote_configuration_revision(record: &ManagedAgentRecord, app: &AppHandle) -> String {
    let personas = load_personas(app).unwrap_or_default();
    let effective_command = crate::managed_agents::record_agent_command(record, &personas);
    let value = serde_json::json!({
        "agent_command": effective_command,
        "agent_args": record.agent_args,
        "env_vars": record.env_vars,
        "system_prompt": record.system_prompt,
        "model": record.model,
        "provider": record.provider,
        "idle_timeout_seconds": record.idle_timeout_seconds,
        "max_turn_duration_seconds": record.max_turn_duration_seconds,
        "parallelism": record.parallelism,
        "respond_to": record.respond_to,
        "respond_to_allowlist": record.respond_to_allowlist,
    });
    let encoded = serde_json::to_vec(&value).unwrap_or_default();
    hex::encode(Sha256::digest(encoded))
}

pub(crate) fn remote_restart_required(app: &AppHandle, record: &ManagedAgentRecord) -> bool {
    matches!(record.backend, BackendKind::Runner { .. })
        && deployment_state(app, &record.pubkey).is_some_and(|deployment| {
            !deployment.configuration_revision.is_empty()
                && deployment.configuration_revision != remote_configuration_revision(record, app)
        })
}

pub(crate) type RemoteSummary = (
    Option<String>,
    Option<u64>,
    Option<u64>,
    Option<String>,
    Option<String>,
);

pub(crate) fn remote_summary(app: &AppHandle, record: &ManagedAgentRecord) -> RemoteSummary {
    let runner_id = match &record.backend {
        BackendKind::Runner { runner_pubkey } => Some(runner_pubkey.clone()),
        _ => None,
    };
    let store = load_store(app).ok();
    let runner_online = runner_id.as_ref().and_then(|id| {
        store
            .as_ref()?
            .runners
            .iter()
            .find(|runner| runner.runner_pubkey == *id)
            .map(|runner| runner.online)
    });
    let status = store.as_ref().and_then(|store| {
        store
            .deployments
            .iter()
            .find(|entry| entry.agent_pubkey == record.pubkey)
            .cloned()
    });
    (
        runner_id,
        status.as_ref().map(|value| value.desired_generation),
        status.as_ref().map(|value| value.observed_generation),
        if runner_online == Some(false) {
            Some("runner_offline".into())
        } else {
            status.as_ref().map(|value| value.deployment_state.clone())
        },
        status.and_then(|value| value.last_runner_error),
    )
}

#[tauri::command]
pub async fn purge_remote_runner_workspace(
    runner_pubkey: String,
    agent_pubkey: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let runner =
        PublicKey::from_hex(&runner_pubkey).map_err(|_| "invalid runner public key".to_string())?;
    let owner = state.signing_keys()?;
    let frame = RunnerFrame::PurgeWorkspace {
        agent_pubkey: agent_pubkey.clone(),
    };
    let encrypted =
        encrypt_runner_payload(&owner, &runner, &frame).map_err(|error| error.to_string())?;
    let builder = buzz_sdk_pkg::build_runner_frame(
        &runner_pubkey,
        &runner_pubkey,
        Some(&agent_pubkey),
        "purge_workspace",
        &encrypted,
    )
    .map_err(|error| error.to_string())?;
    let result = submit_event(builder, &state).await?;
    if !result.accepted {
        return Err(format!(
            "relay rejected workspace purge: {}",
            result.message
        ));
    }
    for _ in 0..20 {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        refresh_remote_runner_statuses(&app, &state).await?;
        let purged = load_store(&app)?
            .runners
            .into_iter()
            .find(|runner| runner.runner_pubkey == runner_pubkey)
            .is_some_and(|runner| !runner.retired_workspaces.contains(&agent_pubkey));
        if purged {
            return Ok(());
        }
    }
    Err("timed out waiting for the runner's purge acknowledgement".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_uri_sas_matches_runner_derivation() {
        let nonce = "11".repeat(32);
        let uri = format!(
            "buzz://runner-pair?relay=wss%3A%2F%2Frelay.example&runner={}&v=1&nonce={nonce}",
            "22".repeat(32)
        );
        let (_, _, version, parsed_nonce) = parse_pairing_uri(&uri).expect("valid URI");
        assert_eq!(version, RUNNER_PROTOCOL_VERSION);
        assert_eq!(pairing_sas(&parsed_nonce).expect("sas").len(), 6);
    }

    #[test]
    fn remote_runtime_environment_includes_mcp_wiring() {
        let mut environment = BTreeMap::new();

        apply_remote_runtime_environment(&mut environment, Some("buzz-dev-mcp"), true);

        assert_eq!(
            environment.get("BUZZ_ACP_MCP_COMMAND").map(String::as_str),
            Some("buzz-dev-mcp")
        );
        assert_eq!(
            environment.get("MCP_HOOK_SERVERS").map(String::as_str),
            Some("*")
        );
    }
}
