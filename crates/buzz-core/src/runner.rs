//! NIP-AR remote runner protocol types.
//!
//! Durable runner events expose only routing metadata in tags. Their JSON
//! payloads, and every ephemeral provisioning frame, are NIP-44 encrypted.

use std::collections::BTreeMap;
use std::fmt;

use nostr::{Event, Keys, PublicKey};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;

use crate::observer::{
    content_looks_like_nip44, decrypt_observer_payload, encrypt_observer_payload,
    ObserverPayloadError, OBSERVER_MAX_PLAINTEXT_LEN,
};

/// Current NIP-AR wire protocol version.
pub const RUNNER_PROTOCOL_VERSION: u16 = 1;
/// Public tag containing a runner public key.
pub const RUNNER_TAG: &str = "runner";
/// Public tag containing an agent public key.
pub const RUNNER_AGENT_TAG: &str = "agent";
/// Public registration routing tag.
pub const RUNNER_REGISTRATION_TAG: &str = "status";
/// Active runner registration tag value.
pub const RUNNER_REGISTRATION_ACTIVE: &str = "active";
/// Revoked runner registration tag value.
pub const RUNNER_REGISTRATION_REVOKED: &str = "revoked";
/// Maximum serialized provisioning secret payload.
pub const RUNNER_SECRET_MAX_PLAINTEXT_LEN: usize = 49_152;

/// Owner-authored runner registration state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunnerRegistrationState {
    /// Runner may authenticate and participate in NIP-AR.
    Active,
    /// Runner access is revoked immediately.
    Revoked,
}

impl RunnerRegistrationState {
    /// Return the canonical public routing tag value.
    pub const fn as_tag_value(self) -> &'static str {
        match self {
            Self::Active => RUNNER_REGISTRATION_ACTIVE,
            Self::Revoked => RUNNER_REGISTRATION_REVOKED,
        }
    }
}

/// Desired deployment lifecycle state authored by the owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentDesiredState {
    /// Reconcile the deployment to an active container.
    Running,
    /// Reconcile the deployment to a stopped container.
    Stopped,
    /// Remove runtime material and retire its workspace.
    Deleted,
}

/// Runner-observed deployment state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentActualState {
    /// A newer secret revision must be provisioned.
    WaitingForSecrets,
    /// The allowlisted image is being pulled.
    PullingImage,
    /// The agent container is being created or started.
    Starting,
    /// The agent container is running.
    Running,
    /// The owner requested a stop.
    StoppedByOwner,
    /// The agent exited cleanly after `!shutdown`.
    StoppedByAgent,
    /// Repeated failures exceeded the restart budget.
    CrashLoop,
    /// The runtime ID is not in the operator allowlist.
    IncompatibleRuntime,
    /// Runtime resources are removed and the workspace is retired.
    Deleted,
    /// The runner encountered an unclassified error.
    Error,
}

/// Publicly routable registration metadata encrypted to the runner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunnerRegistrationPayload {
    /// NIP-AR protocol version.
    pub protocol_version: u16,
    /// Human-readable owner-assigned runner name.
    pub name: String,
}

/// Workspace materialization policy for a deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspacePolicy {
    /// Keep the workspace across stops and runner restarts.
    Persistent,
}

/// Non-secret desired configuration for one deployment generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentDesiredPayload {
    /// NIP-AR protocol version.
    pub protocol_version: u16,
    /// Monotonically increasing desired generation.
    pub generation: u64,
    /// Owner-authored lifecycle state.
    pub desired_state: DeploymentDesiredState,
    /// Runtime catalog ID, never an image or command.
    pub runtime_id: String,
    /// Relay URL injected into the harness.
    pub relay_url: String,
    /// Workspace persistence policy.
    pub workspace_policy: WorkspacePolicy,
    /// Revision expected through an ephemeral `secrets_put` frame.
    pub secret_revision: u64,
    /// Non-secret runtime configuration values.
    #[serde(default)]
    pub config: BTreeMap<String, String>,
}

impl DeploymentDesiredPayload {
    /// Validate constraints that cannot be represented by Rust's types.
    pub fn validate(&self) -> Result<(), RunnerPayloadError> {
        if self.protocol_version != RUNNER_PROTOCOL_VERSION {
            return Err(RunnerPayloadError::InvalidPayload(format!(
                "unsupported protocol version {}",
                self.protocol_version
            )));
        }
        if self.generation == 0 {
            return Err(RunnerPayloadError::InvalidPayload(
                "generation must be greater than zero".into(),
            ));
        }
        if self.runtime_id.trim().is_empty() {
            return Err(RunnerPayloadError::InvalidPayload(
                "runtime_id must not be empty".into(),
            ));
        }
        if !self.relay_url.starts_with("ws://") && !self.relay_url.starts_with("wss://") {
            return Err(RunnerPayloadError::InvalidPayload(
                "relay_url must use ws:// or wss://".into(),
            ));
        }
        Ok(())
    }
}

/// Runtime offered by an operator-configured runner allowlist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunnerRuntime {
    /// Stable runtime catalog ID.
    pub id: String,
    /// Resolved immutable image digest, when available.
    pub image_digest: Option<String>,
}

/// Runner capability and health head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunnerStatusPayload {
    /// NIP-AR protocol version.
    pub protocol_version: u16,
    /// Runner software version.
    pub runner_version: String,
    /// Unix timestamp in seconds.
    pub observed_at: u64,
    /// Runtime IDs currently available on this runner.
    pub runtimes: Vec<RunnerRuntime>,
    /// Number of non-deleted deployments known to the runner.
    pub agent_count: u32,
    /// Agent public keys with workspaces awaiting explicit purge.
    #[serde(default)]
    pub retired_workspaces: Vec<String>,
}

/// Per-agent runner reconciliation status head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentStatusPayload {
    /// NIP-AR protocol version.
    pub protocol_version: u16,
    /// Latest desired generation observed by the runner.
    pub desired_generation: u64,
    /// Generation represented by the actual container state.
    pub observed_generation: u64,
    /// Runner-observed state.
    pub state: DeploymentActualState,
    /// Actionable redacted error text, if any.
    pub last_error: Option<String>,
    /// Resolved immutable image digest, if a runtime was resolved.
    pub image_digest: Option<String>,
}

/// Secret material delivered only in an ephemeral encrypted frame.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentSecrets {
    /// Agent Nostr private key.
    pub agent_private_key: String,
    /// Agent relay authorization tag.
    pub auth_tag: String,
    /// Fully materialized harness environment.
    pub environment: BTreeMap<String, String>,
}

impl fmt::Debug for DeploymentSecrets {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeploymentSecrets")
            .field("agent_private_key", &"[REDACTED]")
            .field("auth_tag", &"[REDACTED]")
            .field("environment", &"[REDACTED]")
            .finish()
    }
}

/// Ephemeral encrypted runner provisioning and liveness frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RunnerFrame {
    /// Owner-to-runner secret provisioning.
    SecretsPut {
        /// Agent public key.
        agent_pubkey: String,
        /// Desired deployment generation.
        generation: u64,
        /// Secret revision being installed.
        secret_revision: u64,
        /// Runtime secrets.
        secrets: DeploymentSecrets,
    },
    /// Owner request to permanently delete a retired workspace.
    PurgeWorkspace {
        /// Agent whose retired workspace should be removed.
        agent_pubkey: String,
    },
    /// Runner-to-owner acknowledgement.
    Acknowledgement {
        /// Agent public key, absent for runner-level acknowledgements.
        agent_pubkey: Option<String>,
        /// Acknowledged operation.
        operation: String,
        /// Acknowledged generation.
        generation: Option<u64>,
        /// Acknowledged secret revision.
        secret_revision: Option<u64>,
    },
    /// Runner-to-owner liveness heartbeat.
    Heartbeat {
        /// Unix timestamp in seconds.
        observed_at: u64,
    },
}

impl RunnerFrame {
    /// Validate secret and generation limits before encryption.
    pub fn validate(&self) -> Result<(), RunnerPayloadError> {
        if let Self::SecretsPut {
            generation,
            secret_revision,
            secrets,
            ..
        } = self
        {
            if *generation == 0 || *secret_revision == 0 {
                return Err(RunnerPayloadError::InvalidPayload(
                    "generation and secret_revision must be greater than zero".into(),
                ));
            }
            let size = serde_json::to_vec(secrets)?.len();
            if size > RUNNER_SECRET_MAX_PLAINTEXT_LEN {
                return Err(RunnerPayloadError::SecretPayloadTooLarge {
                    max: RUNNER_SECRET_MAX_PLAINTEXT_LEN,
                    got: size,
                });
            }
        }
        Ok(())
    }
}

/// Errors produced by NIP-AR payload operations.
#[derive(Debug, Error)]
pub enum RunnerPayloadError {
    /// Shared NIP-44 payload helper failed.
    #[error(transparent)]
    Payload(#[from] ObserverPayloadError),
    /// JSON serialization failed while validating a payload.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// A payload field violates the protocol.
    #[error("invalid runner payload: {0}")]
    InvalidPayload(String),
    /// Provisioned secrets exceed the dedicated size limit.
    #[error("runner secret payload exceeds {max} bytes (got {got})")]
    SecretPayloadTooLarge {
        /// Maximum accepted serialized bytes.
        max: usize,
        /// Actual serialized bytes.
        got: usize,
    },
}

/// Return the stable deployment coordinate `<runner-pubkey>:<agent-pubkey>`.
pub fn deployment_coordinate(runner_pubkey: &str, agent_pubkey: &str) -> String {
    format!(
        "{}:{}",
        runner_pubkey.to_ascii_lowercase(),
        agent_pubkey.to_ascii_lowercase()
    )
}

/// Return true when content fits the required NIP-44 envelope.
pub fn runner_content_looks_encrypted(content: &str) -> bool {
    content_looks_like_nip44(content)
}

/// Serialize and encrypt a NIP-AR payload.
pub fn encrypt_runner_payload<T: Serialize>(
    sender_keys: &Keys,
    recipient: &PublicKey,
    payload: &T,
) -> Result<String, RunnerPayloadError> {
    Ok(encrypt_observer_payload(sender_keys, recipient, payload)?)
}

/// Decrypt and deserialize a NIP-AR event payload.
pub fn decrypt_runner_payload<T: DeserializeOwned>(
    recipient_keys: &Keys,
    event: &Event,
) -> Result<T, RunnerPayloadError> {
    Ok(decrypt_observer_payload(recipient_keys, event)?)
}

/// Return the maximum common encrypted plaintext envelope.
pub const fn runner_max_plaintext_len() -> usize {
    OBSERVER_MAX_PLAINTEXT_LEN
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::{EventBuilder, Kind, Tag};

    #[test]
    fn desired_payload_rejects_zero_generation_and_arbitrary_relay_scheme() {
        let mut payload = DeploymentDesiredPayload {
            protocol_version: RUNNER_PROTOCOL_VERSION,
            generation: 0,
            desired_state: DeploymentDesiredState::Running,
            runtime_id: "sprig".into(),
            relay_url: "https://relay.example".into(),
            workspace_policy: WorkspacePolicy::Persistent,
            secret_revision: 1,
            config: BTreeMap::new(),
        };
        assert!(payload.validate().is_err());
        payload.generation = 1;
        assert!(payload.validate().is_err());
        payload.relay_url = "wss://relay.example".into();
        assert!(payload.validate().is_ok());
    }

    #[test]
    fn runner_payload_round_trips_with_nip44() {
        let owner = Keys::generate();
        let runner = Keys::generate();
        let payload = RunnerStatusPayload {
            protocol_version: RUNNER_PROTOCOL_VERSION,
            runner_version: "0.1.0".into(),
            observed_at: 42,
            runtimes: vec![RunnerRuntime {
                id: "sprig".into(),
                image_digest: Some("sha256:abc".into()),
            }],
            agent_count: 1,
            retired_workspaces: Vec::new(),
        };
        let content =
            encrypt_runner_payload(&runner, &owner.public_key(), &payload).expect("encrypt");
        assert!(runner_content_looks_encrypted(&content));
        let event = EventBuilder::new(
            Kind::Custom(crate::kind::KIND_RUNNER_STATUS as u16),
            content,
        )
        .tags([Tag::public_key(owner.public_key())])
        .sign_with_keys(&runner)
        .expect("sign");
        let decrypted: RunnerStatusPayload =
            decrypt_runner_payload(&owner, &event).expect("decrypt");
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn secrets_are_redacted_and_size_limited() {
        let frame = RunnerFrame::SecretsPut {
            agent_pubkey: "a".repeat(64),
            generation: 1,
            secret_revision: 1,
            secrets: DeploymentSecrets {
                agent_private_key: "nsec-secret".into(),
                auth_tag: "auth-secret".into(),
                environment: BTreeMap::from([(
                    "BIG".into(),
                    "x".repeat(RUNNER_SECRET_MAX_PLAINTEXT_LEN),
                )]),
            },
        };
        let rendered = format!("{frame:?}");
        assert!(!rendered.contains("nsec-secret"));
        assert!(!rendered.contains("auth-secret"));
        assert!(matches!(
            frame.validate(),
            Err(RunnerPayloadError::SecretPayloadTooLarge { .. })
        ));
    }

    #[test]
    fn deployment_coordinate_is_stable_and_lowercase() {
        assert_eq!(
            deployment_coordinate(&"A".repeat(64), &"B".repeat(64)),
            format!("{}:{}", "a".repeat(64), "b".repeat(64))
        );
    }
}
