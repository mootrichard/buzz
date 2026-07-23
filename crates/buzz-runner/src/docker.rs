//! Hardened Docker container abstraction.

use std::collections::BTreeMap;
use std::path::PathBuf;

use async_trait::async_trait;
use tokio::process::Command;

/// Desired immutable container attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerSpec {
    /// Deterministic container name.
    pub name: String,
    /// Allowlisted image reference.
    pub image: String,
    /// Resolved immutable digest.
    pub image_digest: String,
    /// Immutable image reference passed to Docker (`repo@digest` or local image ID).
    pub immutable_image: String,
    /// Persistent workspace directory.
    pub workspace_dir: PathBuf,
    /// Read-only secret directory.
    pub secrets_dir: PathBuf,
    /// CPU limit.
    pub cpu_limit: String,
    /// Memory limit.
    pub memory_limit: String,
    /// Audit labels.
    pub labels: BTreeMap<String, String>,
}

/// Observed Docker state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ContainerState {
    /// No matching container exists.
    #[default]
    Missing,
    /// Container is running.
    Running,
    /// Container exited with this process exit code.
    Exited(i32),
}

/// Immutable result of resolving an operator-allowlisted image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedImage {
    /// Docker reference used for container creation.
    pub reference: String,
    /// Content digest or local image ID recorded in status and labels.
    pub digest: String,
}

/// Operations used by the reconciler.
#[async_trait]
pub trait ContainerEngine: Send + Sync {
    /// Resolve an allowlisted image reference to an immutable digest.
    async fn resolve_image(&self, image: &str) -> Result<ResolvedImage, String>;
    /// Inspect a named container.
    async fn inspect(&self, name: &str) -> Result<ContainerState, String>;
    /// Create a container with the exact hardened specification.
    async fn create(&self, spec: &ContainerSpec) -> Result<(), String>;
    /// Start an existing container.
    async fn start(&self, name: &str) -> Result<(), String>;
    /// Stop a container if present.
    async fn stop(&self, name: &str) -> Result<(), String>;
    /// Remove a container if present.
    async fn remove(&self, name: &str) -> Result<(), String>;
}

/// Docker CLI implementation.
#[derive(Debug, Default)]
pub struct DockerCli;

impl DockerCli {
    async fn run(args: &[String]) -> Result<String, String> {
        let output = Command::new("docker")
            .args(args)
            .output()
            .await
            .map_err(|error| format!("failed to execute docker: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "docker command failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    async fn inspect_repo_digest(image: &str) -> Result<String, String> {
        Self::run(&[
            "image".into(),
            "inspect".into(),
            "--format".into(),
            "{{index .RepoDigests 0}}".into(),
            image.into(),
        ])
        .await
    }
}

#[async_trait]
impl ContainerEngine for DockerCli {
    async fn resolve_image(&self, image: &str) -> Result<ResolvedImage, String> {
        let repo_digest = match Self::inspect_repo_digest(image).await {
            Ok(value) => value,
            Err(_) => {
                Self::run(&["pull".into(), image.into()]).await?;
                Self::inspect_repo_digest(image).await?
            }
        };
        if let Some((_, digest)) = repo_digest.split_once('@') {
            if digest.starts_with("sha256:") {
                let digest = digest.to_string();
                return Ok(ResolvedImage {
                    reference: repo_digest,
                    digest,
                });
            }
        }
        let image_id = Self::run(&[
            "image".into(),
            "inspect".into(),
            "--format".into(),
            "{{.Id}}".into(),
            image.into(),
        ])
        .await?;
        if !image_id.starts_with("sha256:") {
            return Err(format!(
                "image {image} did not resolve to immutable content"
            ));
        }
        Ok(ResolvedImage {
            reference: image_id.clone(),
            digest: image_id,
        })
    }

    async fn inspect(&self, name: &str) -> Result<ContainerState, String> {
        let output = Command::new("docker")
            .args([
                "inspect",
                "--format",
                "{{.State.Status}} {{.State.ExitCode}}",
                name,
            ])
            .output()
            .await
            .map_err(|error| format!("failed to execute docker inspect: {error}"))?;
        if !output.status.success() {
            return Ok(ContainerState::Missing);
        }
        let value = String::from_utf8_lossy(&output.stdout);
        let mut parts = value.split_whitespace();
        match parts.next() {
            Some("running") => Ok(ContainerState::Running),
            Some("exited") => {
                let code = parts
                    .next()
                    .and_then(|value| value.parse::<i32>().ok())
                    .unwrap_or(-1);
                Ok(ContainerState::Exited(code))
            }
            Some(_) | None => Ok(ContainerState::Missing),
        }
    }

    async fn create(&self, spec: &ContainerSpec) -> Result<(), String> {
        let mut args = vec![
            "create".into(),
            "--name".into(),
            spec.name.clone(),
            "--restart".into(),
            "on-failure:3".into(),
            "--read-only".into(),
            "--cap-drop".into(),
            "ALL".into(),
            "--security-opt".into(),
            "no-new-privileges:true".into(),
            "--cpus".into(),
            spec.cpu_limit.clone(),
            "--memory".into(),
            spec.memory_limit.clone(),
            "--tmpfs".into(),
            "/tmp:rw,noexec,nosuid,size=256m".into(),
            "--mount".into(),
            format!(
                "type=bind,src={},dst=/workspace",
                spec.workspace_dir.display()
            ),
            "--mount".into(),
            format!(
                "type=bind,src={},dst=/run/buzz-secrets,readonly",
                spec.secrets_dir.display()
            ),
            "--workdir".into(),
            "/workspace".into(),
        ];
        for (key, value) in &spec.labels {
            args.push("--label".into());
            args.push(format!("{key}={value}"));
        }
        args.push(spec.immutable_image.clone());
        Self::run(&args).await.map(|_| ())
    }

    async fn start(&self, name: &str) -> Result<(), String> {
        Self::run(&["start".into(), name.into()]).await.map(|_| ())
    }

    async fn stop(&self, name: &str) -> Result<(), String> {
        let state = self.inspect(name).await?;
        if state == ContainerState::Missing {
            return Ok(());
        }
        Self::run(&["stop".into(), "--time".into(), "20".into(), name.into()])
            .await
            .map(|_| ())
    }

    async fn remove(&self, name: &str) -> Result<(), String> {
        if self.inspect(name).await? == ContainerState::Missing {
            return Ok(());
        }
        Self::run(&["rm".into(), "-f".into(), name.into()])
            .await
            .map(|_| ())
    }
}
