//! Runner configuration and runtime allowlist.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// One operator-approved runtime image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeImage {
    /// Canonical Desktop runtime catalog ID.
    pub runtime_id: String,
    /// Operator-selected image reference.
    pub image: String,
}

/// Process configuration for one runner.
#[derive(Debug, Clone)]
pub struct RunnerConfig {
    /// Persistent runner state root.
    pub state_dir: PathBuf,
    /// Host tmpfs directory used for materialized secret files.
    pub runtime_secrets_dir: PathBuf,
    /// Persistent workspace root.
    pub workspace_dir: PathBuf,
    /// Retired workspace root.
    pub retired_workspace_dir: PathBuf,
    /// CPU limit for each agent container.
    pub cpu_limit: String,
    /// Memory limit for each agent container.
    pub memory_limit: String,
    /// Runtime-ID-to-image operator allowlist.
    pub runtimes: BTreeMap<String, RuntimeImage>,
}

impl RunnerConfig {
    /// Load configuration from environment variables.
    pub fn from_env() -> Result<Self, String> {
        let state_dir = env_path("BUZZ_RUNNER_STATE_DIR", "/var/lib/buzz-runner");
        let runtime_secrets_dir = env_path("BUZZ_RUNNER_SECRETS_DIR", "/run/buzz-runner");
        let workspace_dir = env_path(
            "BUZZ_RUNNER_WORKSPACE_DIR",
            "/var/lib/buzz-runner/workspaces",
        );
        let retired_workspace_dir =
            env_path("BUZZ_RUNNER_RETIRED_DIR", "/var/lib/buzz-runner/retired");
        let cpu_limit = std::env::var("BUZZ_RUNNER_AGENT_CPUS").unwrap_or_else(|_| "2".into());
        let memory_limit =
            std::env::var("BUZZ_RUNNER_AGENT_MEMORY").unwrap_or_else(|_| "4g".into());
        let raw = std::env::var("BUZZ_RUNNER_RUNTIMES")
            .unwrap_or_else(|_| r#"{"buzz-agent":"ghcr.io/block/buzz-agent:latest"}"#.into());
        let images: BTreeMap<String, String> = serde_json::from_str(&raw)
            .map_err(|error| format!("BUZZ_RUNNER_RUNTIMES must be a JSON object: {error}"))?;
        if images.is_empty() {
            return Err("BUZZ_RUNNER_RUNTIMES must allow at least one runtime".into());
        }
        let runtimes = images
            .into_iter()
            .map(|(runtime_id, image)| {
                if runtime_id.trim().is_empty() || image.trim().is_empty() {
                    return Err("runtime IDs and images must not be empty".to_string());
                }
                Ok((runtime_id.clone(), RuntimeImage { runtime_id, image }))
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            state_dir,
            runtime_secrets_dir,
            workspace_dir,
            retired_workspace_dir,
            cpu_limit,
            memory_limit,
            runtimes,
        })
    }
}

fn env_path(name: &str, default: &str) -> PathBuf {
    std::env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(default))
}
