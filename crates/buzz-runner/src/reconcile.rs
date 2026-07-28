//! Desired/actual-state reconciliation.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use buzz_core::runner::{DeploymentActualState, DeploymentDesiredState, DeploymentSecrets};

use crate::config::RunnerConfig;
use crate::docker::{ContainerEngine, ContainerSpec, ContainerState};
use crate::store::{DeploymentRecord, Store};

/// Failures before a deployment enters `crash_loop`.
pub const CRASH_LOOP_THRESHOLD: u32 = 5;

/// Bounded exponential retry delay.
pub const fn restart_backoff_seconds(failure_count: u32) -> u64 {
    let candidate = failure_count.saturating_sub(1);
    let exponent = if candidate > 8 { 8 } else { candidate };
    let delay = 1u64 << exponent;
    if delay > 300 {
        300
    } else {
        delay
    }
}

/// Reconciles persisted desired state with Docker.
pub struct Reconciler<'a, E: ContainerEngine> {
    store: &'a Store,
    engine: &'a E,
    config: &'a RunnerConfig,
    owner_pubkey: &'a str,
    runner_pubkey: &'a str,
}

impl<'a, E: ContainerEngine> Reconciler<'a, E> {
    /// Create a reconciler.
    pub fn new(
        store: &'a Store,
        engine: &'a E,
        config: &'a RunnerConfig,
        owner_pubkey: &'a str,
        runner_pubkey: &'a str,
    ) -> Self {
        Self {
            store,
            engine,
            config,
            owner_pubkey,
            runner_pubkey,
        }
    }

    /// Reconcile every persisted deployment.
    pub async fn reconcile_all(&self, now: u64) -> Result<(), String> {
        for deployment in self.store.deployments()? {
            if let Err(error) = self.reconcile_one(&deployment, now).await {
                self.store.set_actual(
                    &deployment.agent_pubkey,
                    deployment.observed_generation,
                    DeploymentActualState::Error,
                    Some(&redact_error(&error)),
                    None,
                )?;
            }
        }
        Ok(())
    }

    async fn reconcile_one(&self, deployment: &DeploymentRecord, now: u64) -> Result<(), String> {
        let name = container_name(&deployment.agent_pubkey);
        match deployment.desired.desired_state {
            DeploymentDesiredState::Deleted => {
                self.engine.stop(&name).await?;
                self.engine.remove(&name).await?;
                remove_materialized_secrets(
                    &self.config.runtime_secrets_dir,
                    &deployment.agent_pubkey,
                )?;
                self.store.delete_secrets(&deployment.agent_pubkey)?;
                let retired = retire_workspace(
                    &self.config.workspace_dir,
                    &self.config.retired_workspace_dir,
                    &deployment.agent_pubkey,
                    now,
                )?;
                if let Some(path) = retired {
                    self.store
                        .retire_workspace(&deployment.agent_pubkey, &path)?;
                }
                self.store.set_actual(
                    &deployment.agent_pubkey,
                    deployment.desired.generation,
                    DeploymentActualState::Deleted,
                    None,
                    deployment.image_digest.as_deref(),
                )
            }
            DeploymentDesiredState::Stopped => {
                self.engine.stop(&name).await?;
                remove_materialized_secrets(
                    &self.config.runtime_secrets_dir,
                    &deployment.agent_pubkey,
                )?;
                self.store.set_actual(
                    &deployment.agent_pubkey,
                    deployment.desired.generation,
                    DeploymentActualState::StoppedByOwner,
                    None,
                    deployment.image_digest.as_deref(),
                )
            }
            DeploymentDesiredState::Running => self.reconcile_running(deployment, &name, now).await,
        }
    }

    async fn reconcile_running(
        &self,
        deployment: &DeploymentRecord,
        name: &str,
        now: u64,
    ) -> Result<(), String> {
        if deployment.stop_latch_generation == Some(deployment.desired.generation) {
            return self.store.set_actual(
                &deployment.agent_pubkey,
                deployment.desired.generation,
                DeploymentActualState::StoppedByAgent,
                None,
                deployment.image_digest.as_deref(),
            );
        }

        let Some(runtime) = self.config.runtimes.get(&deployment.desired.runtime_id) else {
            return self.store.set_actual(
                &deployment.agent_pubkey,
                deployment.observed_generation,
                DeploymentActualState::IncompatibleRuntime,
                Some("runtime ID is not enabled by this runner"),
                None,
            );
        };

        if deployment.installed_secret_revision != Some(deployment.desired.secret_revision) {
            return self.store.set_actual(
                &deployment.agent_pubkey,
                deployment.observed_generation,
                DeploymentActualState::WaitingForSecrets,
                None,
                deployment.image_digest.as_deref(),
            );
        }

        let state = self.engine.inspect(name).await?;
        if state == ContainerState::Running
            && deployment.observed_generation == deployment.desired.generation
        {
            return self.store.set_actual(
                &deployment.agent_pubkey,
                deployment.desired.generation,
                DeploymentActualState::Running,
                None,
                deployment.image_digest.as_deref(),
            );
        }

        if state == ContainerState::Running {
            self.engine.stop(name).await?;
            self.engine.remove(name).await?;
        }

        match state {
            ContainerState::Exited(0)
                if deployment.observed_generation == deployment.desired.generation =>
            {
                remove_materialized_secrets(
                    &self.config.runtime_secrets_dir,
                    &deployment.agent_pubkey,
                )?;
                return self
                    .store
                    .latch_clean_stop(&deployment.agent_pubkey, deployment.desired.generation);
            }
            ContainerState::Exited(code) => {
                let failures = self.store.record_failure(
                    &deployment.agent_pubkey,
                    now,
                    &format!("agent container exited with code {code}"),
                )?;
                if failures >= CRASH_LOOP_THRESHOLD {
                    remove_materialized_secrets(
                        &self.config.runtime_secrets_dir,
                        &deployment.agent_pubkey,
                    )?;
                    return self.store.set_actual(
                        &deployment.agent_pubkey,
                        deployment.desired.generation,
                        DeploymentActualState::CrashLoop,
                        Some("agent container repeatedly crashed"),
                        deployment.image_digest.as_deref(),
                    );
                }
                if deployment.last_failure_at.is_some_and(|last| {
                    now < last.saturating_add(restart_backoff_seconds(failures))
                }) {
                    return Ok(());
                }
                self.engine.remove(name).await?;
            }
            ContainerState::Missing | ContainerState::Running => {}
        }

        self.store.set_actual(
            &deployment.agent_pubkey,
            deployment.observed_generation,
            DeploymentActualState::PullingImage,
            None,
            deployment.image_digest.as_deref(),
        )?;
        let resolved_image = self.engine.resolve_image(&runtime.image).await?;
        let digest = resolved_image.digest;
        let secrets = self
            .store
            .load_secrets(&deployment.agent_pubkey)?
            .ok_or_else(|| "installed secret revision has no encrypted blob".to_string())?;
        let secret_dir = materialize_secrets(
            &self.config.runtime_secrets_dir,
            &deployment.agent_pubkey,
            &secrets,
        )?;
        let workspace = self.config.workspace_dir.join(&deployment.agent_pubkey);
        fs::create_dir_all(&workspace)
            .map_err(|error| format!("create agent workspace: {error}"))?;
        assign_to_agent_user(&workspace)?;
        let labels = BTreeMap::from([
            ("com.buzz.runner".into(), self.runner_pubkey.into()),
            ("com.buzz.owner".into(), self.owner_pubkey.into()),
            ("com.buzz.agent".into(), deployment.agent_pubkey.clone()),
            (
                "com.buzz.deployment-generation".into(),
                deployment.desired.generation.to_string(),
            ),
            (
                "com.buzz.runtime-id".into(),
                deployment.desired.runtime_id.clone(),
            ),
            ("com.buzz.image-digest".into(), digest.clone()),
        ]);
        let spec = ContainerSpec {
            name: name.into(),
            image: runtime.image.clone(),
            image_digest: digest.clone(),
            immutable_image: resolved_image.reference,
            workspace_dir: workspace,
            secrets_dir: secret_dir,
            cpu_limit: self.config.cpu_limit.clone(),
            memory_limit: self.config.memory_limit.clone(),
            labels,
        };
        self.store.set_actual(
            &deployment.agent_pubkey,
            deployment.desired.generation,
            DeploymentActualState::Starting,
            None,
            Some(&digest),
        )?;
        self.engine.create(&spec).await?;
        self.engine.start(name).await?;
        self.store.set_actual(
            &deployment.agent_pubkey,
            deployment.desired.generation,
            DeploymentActualState::Running,
            None,
            Some(&digest),
        )
    }
}

fn container_name(agent_pubkey: &str) -> String {
    let prefix = agent_pubkey.get(..16).unwrap_or(agent_pubkey);
    format!("buzz-agent-{prefix}")
}

fn valid_environment_name(name: &str) -> bool {
    let mut characters = name.chars();
    characters
        .next()
        .is_some_and(|first| first == '_' || first.is_ascii_uppercase())
        && characters.all(|character| {
            character == '_' || character.is_ascii_uppercase() || character.is_ascii_digit()
        })
}

fn materialize_secrets(
    root: &Path,
    agent_pubkey: &str,
    secrets: &DeploymentSecrets,
) -> Result<PathBuf, String> {
    let directory = root.join(agent_pubkey);
    if directory.exists() {
        fs::remove_dir_all(&directory)
            .map_err(|error| format!("replace materialized secret directory: {error}"))?;
    }
    fs::create_dir_all(&directory)
        .map_err(|error| format!("create materialized secret directory: {error}"))?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("secure materialized secret directory: {error}"))?;
    assign_to_agent_user(&directory)?;
    let mut values = secrets.environment.clone();
    values.insert("BUZZ_PRIVATE_KEY".into(), secrets.agent_private_key.clone());
    values.insert("BUZZ_AUTH_TAG".into(), secrets.auth_tag.clone());
    for (name, value) in values {
        if !valid_environment_name(&name) {
            remove_materialized_secrets(root, agent_pubkey)?;
            return Err("secret environment contains an invalid variable name".into());
        }
        let path = directory.join(&name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .open(&path)
            .map_err(|error| format!("create materialized secret file: {error}"))?;
        file.write_all(value.as_bytes())
            .and_then(|_| file.sync_all())
            .map_err(|error| format!("persist materialized secret file: {error}"))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400))
            .map_err(|error| format!("secure materialized secret file: {error}"))?;
        assign_to_agent_user(&path)?;
    }
    Ok(directory)
}

fn assign_to_agent_user(path: &Path) -> Result<(), String> {
    let current_uid = std::process::Command::new("id")
        .arg("-u")
        .output()
        .map_err(|error| format!("inspect runner uid: {error}"))?;
    if String::from_utf8_lossy(&current_uid.stdout).trim() != "0" {
        return Ok(());
    }
    let result = std::process::Command::new("chown")
        .args(["1000:1000"])
        .arg(path)
        .status()
        .map_err(|error| format!("assign agent path ownership: {error}"))?;
    if !result.success() {
        return Err("assign agent path ownership failed".into());
    }
    Ok(())
}

fn remove_materialized_secrets(root: &Path, agent_pubkey: &str) -> Result<(), String> {
    let directory = root.join(agent_pubkey);
    if directory.exists() {
        fs::remove_dir_all(directory)
            .map_err(|error| format!("remove materialized deployment secrets: {error}"))?;
    }
    Ok(())
}

fn retire_workspace(
    workspace_root: &Path,
    retired_root: &Path,
    agent_pubkey: &str,
    now: u64,
) -> Result<Option<PathBuf>, String> {
    let source = workspace_root.join(agent_pubkey);
    if !source.exists() {
        return Ok(None);
    }
    fs::create_dir_all(retired_root)
        .map_err(|error| format!("create retired workspace directory: {error}"))?;
    let destination = retired_root.join(format!("{agent_pubkey}-{now}"));
    fs::rename(&source, &destination)
        .map_err(|error| format!("retire agent workspace: {error}"))?;
    Ok(Some(destination))
}

fn redact_error(error: &str) -> String {
    let mut redacted = error.replace("nsec1", "[REDACTED]");
    if redacted.len() > 512 {
        redacted.truncate(512);
    }
    redacted
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use buzz_core::runner::{
        DeploymentDesiredPayload, DeploymentDesiredState, WorkspacePolicy, RUNNER_PROTOCOL_VERSION,
    };

    use crate::config::RuntimeImage;

    use super::*;

    #[derive(Default)]
    struct FakeEngine {
        state: Mutex<ContainerState>,
        created: Mutex<Vec<ContainerSpec>>,
    }

    #[async_trait]
    impl ContainerEngine for FakeEngine {
        async fn resolve_image(&self, image: &str) -> Result<crate::docker::ResolvedImage, String> {
            Ok(crate::docker::ResolvedImage {
                reference: format!("{image}@sha256:resolved"),
                digest: "sha256:resolved".into(),
            })
        }
        async fn inspect(&self, _name: &str) -> Result<ContainerState, String> {
            self.state
                .lock()
                .map(|state| *state)
                .map_err(|_| "fake lock poisoned".into())
        }
        async fn create(&self, spec: &ContainerSpec) -> Result<(), String> {
            self.created
                .lock()
                .map_err(|_| "fake lock poisoned".to_string())?
                .push(spec.clone());
            Ok(())
        }
        async fn start(&self, _name: &str) -> Result<(), String> {
            *self
                .state
                .lock()
                .map_err(|_| "fake lock poisoned".to_string())? = ContainerState::Running;
            Ok(())
        }
        async fn stop(&self, _name: &str) -> Result<(), String> {
            *self
                .state
                .lock()
                .map_err(|_| "fake lock poisoned".to_string())? = ContainerState::Exited(0);
            Ok(())
        }
        async fn remove(&self, _name: &str) -> Result<(), String> {
            *self
                .state
                .lock()
                .map_err(|_| "fake lock poisoned".to_string())? = ContainerState::Missing;
            Ok(())
        }
    }

    fn test_config(root: &Path) -> RunnerConfig {
        RunnerConfig {
            state_dir: root.join("state"),
            runtime_secrets_dir: root.join("run"),
            workspace_dir: root.join("workspaces"),
            retired_workspace_dir: root.join("retired"),
            cpu_limit: "2".into(),
            memory_limit: "4g".into(),
            runtimes: BTreeMap::from([(
                "buzz-agent".into(),
                RuntimeImage {
                    runtime_id: "buzz-agent".into(),
                    image: "example/buzz-agent:latest".into(),
                },
            )]),
        }
    }

    fn desired(state: DeploymentDesiredState, generation: u64) -> DeploymentDesiredPayload {
        DeploymentDesiredPayload {
            protocol_version: RUNNER_PROTOCOL_VERSION,
            generation,
            desired_state: state,
            runtime_id: "buzz-agent".into(),
            relay_url: "wss://relay.example".into(),
            workspace_policy: WorkspacePolicy::Persistent,
            secret_revision: generation,
            config: BTreeMap::new(),
        }
    }

    fn secrets() -> DeploymentSecrets {
        DeploymentSecrets {
            agent_private_key: "secret".into(),
            auth_tag: "auth".into(),
            environment: BTreeMap::from([("BUZZ_RELAY_URL".into(), "wss://relay.example".into())]),
        }
    }

    #[tokio::test]
    async fn creates_hardened_allowlisted_container_and_materializes_0400_secrets() {
        let temp = tempfile::tempdir().expect("temp");
        let config = test_config(temp.path());
        let store = Store::open(&config.state_dir).expect("store");
        let agent = "a".repeat(64);
        store
            .upsert_desired(&agent, &desired(DeploymentDesiredState::Running, 1))
            .expect("desired");
        store
            .put_secrets(&agent, 1, 1, &secrets())
            .expect("secrets");
        let engine = FakeEngine::default();
        Reconciler::new(&store, &engine, &config, &"b".repeat(64), &"c".repeat(64))
            .reconcile_all(100)
            .await
            .expect("reconcile");

        let created = engine.created.lock().expect("created");
        assert_eq!(created.len(), 1);
        assert_eq!(created[0].cpu_limit, "2");
        assert_eq!(created[0].memory_limit, "4g");
        let mode = fs::metadata(
            config
                .runtime_secrets_dir
                .join(&agent)
                .join("BUZZ_PRIVATE_KEY"),
        )
        .expect("secret metadata")
        .permissions()
        .mode()
            & 0o777;
        assert_eq!(mode, 0o400);
    }

    #[tokio::test]
    async fn clean_exit_latches_and_new_generation_clears_by_mismatch() {
        let temp = tempfile::tempdir().expect("temp");
        let config = test_config(temp.path());
        let store = Store::open(&config.state_dir).expect("store");
        let agent = "a".repeat(64);
        store
            .upsert_desired(&agent, &desired(DeploymentDesiredState::Running, 1))
            .expect("desired");
        store
            .put_secrets(&agent, 1, 1, &secrets())
            .expect("secrets");
        store
            .set_actual(&agent, 1, DeploymentActualState::Running, None, None)
            .expect("running");
        let engine = FakeEngine::default();
        *engine.state.lock().expect("state") = ContainerState::Exited(0);
        let owner_pubkey = "b".repeat(64);
        let runner_pubkey = "c".repeat(64);
        let reconciler = Reconciler::new(&store, &engine, &config, &owner_pubkey, &runner_pubkey);
        reconciler.reconcile_all(100).await.expect("reconcile");
        assert_eq!(
            store.deployments().expect("records")[0].stop_latch_generation,
            Some(1)
        );

        store
            .upsert_desired(&agent, &desired(DeploymentDesiredState::Running, 2))
            .expect("new generation");
        store
            .put_secrets(&agent, 2, 2, &secrets())
            .expect("secrets");
        *engine.state.lock().expect("state") = ContainerState::Missing;
        reconciler.reconcile_all(101).await.expect("restart");
        assert_eq!(
            store.deployments().expect("records")[0].actual_state,
            DeploymentActualState::Running
        );
    }

    #[test]
    fn backoff_is_bounded() {
        assert_eq!(restart_backoff_seconds(1), 1);
        assert_eq!(restart_backoff_seconds(4), 8);
        assert_eq!(restart_backoff_seconds(100), 256);
    }
}
