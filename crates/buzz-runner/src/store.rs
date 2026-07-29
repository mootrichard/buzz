//! SQLite state and encrypted secret persistence.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use buzz_core::runner::{DeploymentActualState, DeploymentDesiredPayload, DeploymentSecrets};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension};
use zeroize::Zeroizing;

use crate::fs_security::{create_new_private, set_private_mode};

/// Persistent deployment record used by reconciliation.
#[derive(Debug, Clone)]
pub struct DeploymentRecord {
    /// Agent public key.
    pub agent_pubkey: String,
    /// Latest desired payload.
    pub desired: DeploymentDesiredPayload,
    /// Last generation reflected in actual state.
    pub observed_generation: u64,
    /// Last actual state.
    pub actual_state: DeploymentActualState,
    /// Clean-stop generation latch.
    pub stop_latch_generation: Option<u64>,
    /// Installed secret revision.
    pub installed_secret_revision: Option<u64>,
    /// Consecutive crash count.
    pub failure_count: u32,
    /// Last failure Unix timestamp.
    pub last_failure_at: Option<u64>,
    /// Redacted runner error.
    pub last_error: Option<String>,
    /// Resolved image digest.
    pub image_digest: Option<String>,
}

/// Runner SQLite store.
pub struct Store {
    connection: Connection,
    master_key: Zeroizing<[u8; 32]>,
}

impl Store {
    /// Open or initialize the store below `state_dir`.
    pub fn open(state_dir: &Path) -> Result<Self, String> {
        fs::create_dir_all(state_dir)
            .map_err(|error| format!("create runner state directory: {error}"))?;
        let master_key = load_or_create_master_key(&state_dir.join("master.key"))?;
        let connection = Connection::open(state_dir.join("runner.sqlite"))
            .map_err(|error| format!("open runner SQLite: {error}"))?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA foreign_keys=ON;
                 CREATE TABLE IF NOT EXISTS settings (
                   key TEXT PRIMARY KEY,
                   value TEXT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS deployments (
                   agent_pubkey TEXT PRIMARY KEY,
                   desired_json TEXT NOT NULL,
                   observed_generation INTEGER NOT NULL DEFAULT 0,
                   actual_state TEXT NOT NULL DEFAULT 'waiting_for_secrets',
                   stop_latch_generation INTEGER,
                   installed_secret_revision INTEGER,
                   secret_nonce BLOB,
                   secret_ciphertext BLOB,
                   failure_count INTEGER NOT NULL DEFAULT 0,
                   last_failure_at INTEGER,
                   last_error TEXT,
                   image_digest TEXT,
                   updated_at INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS retired_workspaces (
                   agent_pubkey TEXT PRIMARY KEY,
                   path TEXT NOT NULL,
                   retired_at INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS runtime_catalog (
                   runtime_id TEXT PRIMARY KEY,
                   image TEXT NOT NULL,
                   image_digest TEXT,
                   updated_at INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS pending_provisioning (
                   agent_pubkey TEXT PRIMARY KEY,
                   generation INTEGER NOT NULL,
                   secret_revision INTEGER NOT NULL,
                   secret_nonce BLOB NOT NULL,
                   secret_ciphertext BLOB NOT NULL,
                   updated_at INTEGER NOT NULL
                 );",
            )
            .map_err(|error| format!("initialize runner SQLite: {error}"))?;
        Ok(Self {
            connection,
            master_key,
        })
    }

    /// Store a runner setting.
    pub fn set_setting(&self, key: &str, value: &str) -> Result<(), String> {
        self.connection
            .execute(
                "INSERT INTO settings(key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                params![key, value],
            )
            .map_err(|error| format!("write runner setting: {error}"))?;
        Ok(())
    }

    /// Read a runner setting.
    pub fn setting(&self, key: &str) -> Result<Option<String>, String> {
        self.connection
            .query_row(
                "SELECT value FROM settings WHERE key=?1",
                params![key],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| format!("read runner setting: {error}"))
    }

    /// Replace the advertised runtime catalog with resolved immutable images.
    pub fn replace_runtime_catalog(
        &self,
        runtimes: &[(String, String, String)],
    ) -> Result<(), String> {
        self.connection
            .execute("DELETE FROM runtime_catalog", [])
            .map_err(|error| format!("clear runtime catalog: {error}"))?;
        for (runtime_id, image, image_digest) in runtimes {
            self.connection
                .execute(
                    "INSERT INTO runtime_catalog(runtime_id, image, image_digest, updated_at)
                     VALUES (?1, ?2, ?3, unixepoch())",
                    params![runtime_id, image, image_digest],
                )
                .map_err(|error| format!("write runtime catalog: {error}"))?;
        }
        Ok(())
    }

    /// Read runtime IDs and immutable digests safe to advertise to Desktop.
    pub fn runtime_catalog(&self) -> Result<Vec<(String, String)>, String> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT runtime_id, image_digest FROM runtime_catalog
                 WHERE image_digest IS NOT NULL ORDER BY runtime_id",
            )
            .map_err(|error| format!("prepare runtime catalog query: {error}"))?;
        let rows = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|error| format!("query runtime catalog: {error}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("decode runtime catalog: {error}"))
    }

    /// Persist the latest desired deployment generation.
    pub fn upsert_desired(
        &self,
        agent_pubkey: &str,
        desired: &DeploymentDesiredPayload,
    ) -> Result<bool, String> {
        desired.validate().map_err(|error| error.to_string())?;
        let existing_generation: Option<u64> = self
            .connection
            .query_row(
                "SELECT json_extract(desired_json, '$.generation')
                 FROM deployments WHERE agent_pubkey=?1",
                params![agent_pubkey],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| format!("read desired generation: {error}"))?;
        if existing_generation.is_some_and(|generation| generation >= desired.generation) {
            if existing_generation == Some(desired.generation) {
                self.promote_pending_secrets(agent_pubkey, desired)?;
            }
            return Ok(false);
        }
        let desired_json = serde_json::to_string(desired)
            .map_err(|error| format!("serialize desired deployment: {error}"))?;
        self.connection
            .execute(
                "INSERT INTO deployments(agent_pubkey, desired_json, updated_at)
                 VALUES (?1, ?2, unixepoch())
                 ON CONFLICT(agent_pubkey) DO UPDATE SET
                   desired_json=excluded.desired_json,
                   failure_count=0,
                   last_failure_at=NULL,
                   last_error=NULL,
                   updated_at=excluded.updated_at",
                params![agent_pubkey, desired_json],
            )
            .map_err(|error| format!("write desired deployment: {error}"))?;
        self.promote_pending_secrets(agent_pubkey, desired)?;
        Ok(true)
    }

    /// Persist an encrypted secret revision, staging it when desired state has
    /// not arrived yet.
    pub fn put_secrets(
        &self,
        agent_pubkey: &str,
        generation: u64,
        revision: u64,
        secrets: &DeploymentSecrets,
    ) -> Result<(), String> {
        let plaintext = Zeroizing::new(
            serde_json::to_vec(secrets)
                .map_err(|error| format!("serialize deployment secrets: {error}"))?,
        );
        if plaintext.len() > buzz_core::runner::RUNNER_SECRET_MAX_PLAINTEXT_LEN {
            return Err("deployment secret payload exceeds protocol limit".into());
        }
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let cipher = XChaCha20Poly1305::new((&*self.master_key).into());
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce), plaintext.as_slice())
            .map_err(|_| "encrypt deployment secrets".to_string())?;
        let desired: Option<(u64, u64)> = self
            .connection
            .query_row(
                "SELECT json_extract(desired_json, '$.generation'),
                        json_extract(desired_json, '$.secret_revision')
                 FROM deployments WHERE agent_pubkey=?1",
                params![agent_pubkey],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| format!("read desired secret coordinate: {error}"))?;

        if let Some((desired_generation, desired_revision)) = desired {
            if desired_generation == generation && desired_revision == revision {
                self.connection
                    .execute(
                        "UPDATE deployments SET installed_secret_revision=?2,
                           secret_nonce=?3, secret_ciphertext=?4, updated_at=unixepoch()
                         WHERE agent_pubkey=?1",
                        params![agent_pubkey, revision, nonce.as_slice(), ciphertext],
                    )
                    .map_err(|error| format!("write encrypted deployment secrets: {error}"))?;
                self.connection
                    .execute(
                        "DELETE FROM pending_provisioning WHERE agent_pubkey=?1",
                        params![agent_pubkey],
                    )
                    .map_err(|error| format!("clear pending deployment secrets: {error}"))?;
                return Ok(());
            }
            if desired_generation >= generation {
                return Err("secrets_put generation or revision is stale".into());
            }
        }

        let changed = self
            .connection
            .execute(
                "INSERT INTO pending_provisioning(
                   agent_pubkey, generation, secret_revision, secret_nonce,
                   secret_ciphertext, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, unixepoch())
                 ON CONFLICT(agent_pubkey) DO UPDATE SET
                   generation=excluded.generation,
                   secret_revision=excluded.secret_revision,
                   secret_nonce=excluded.secret_nonce,
                   secret_ciphertext=excluded.secret_ciphertext,
                   updated_at=excluded.updated_at
                 WHERE pending_provisioning.generation <= excluded.generation",
                params![
                    agent_pubkey,
                    generation,
                    revision,
                    nonce.as_slice(),
                    ciphertext
                ],
            )
            .map_err(|error| format!("stage encrypted deployment secrets: {error}"))?;
        if changed != 1 {
            return Err("secrets_put generation is stale".into());
        }
        Ok(())
    }

    fn promote_pending_secrets(
        &self,
        agent_pubkey: &str,
        desired: &DeploymentDesiredPayload,
    ) -> Result<(), String> {
        let pending: Option<(u64, u64, Vec<u8>, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT generation, secret_revision, secret_nonce, secret_ciphertext
                 FROM pending_provisioning WHERE agent_pubkey=?1",
                params![agent_pubkey],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(|error| format!("read pending deployment secrets: {error}"))?;
        let Some((generation, revision, nonce, ciphertext)) = pending else {
            return Ok(());
        };
        if generation == desired.generation && revision == desired.secret_revision {
            self.connection
                .execute(
                    "UPDATE deployments SET installed_secret_revision=?2,
                       secret_nonce=?3, secret_ciphertext=?4, updated_at=unixepoch()
                     WHERE agent_pubkey=?1",
                    params![agent_pubkey, revision, nonce, ciphertext],
                )
                .map_err(|error| format!("promote pending deployment secrets: {error}"))?;
        }
        if generation <= desired.generation {
            self.connection
                .execute(
                    "DELETE FROM pending_provisioning WHERE agent_pubkey=?1",
                    params![agent_pubkey],
                )
                .map_err(|error| format!("clear pending deployment secrets: {error}"))?;
        }
        Ok(())
    }

    /// Decrypt the installed deployment secrets.
    pub fn load_secrets(&self, agent_pubkey: &str) -> Result<Option<DeploymentSecrets>, String> {
        let encrypted: Option<(Vec<u8>, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT secret_nonce, secret_ciphertext FROM deployments
                 WHERE agent_pubkey=?1 AND secret_nonce IS NOT NULL
                   AND secret_ciphertext IS NOT NULL",
                params![agent_pubkey],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| format!("read encrypted deployment secrets: {error}"))?;
        let Some((nonce, ciphertext)) = encrypted else {
            return Ok(None);
        };
        if nonce.len() != 24 {
            return Err("encrypted secret nonce has invalid length".into());
        }
        let cipher = XChaCha20Poly1305::new((&*self.master_key).into());
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(XNonce::from_slice(&nonce), ciphertext.as_slice())
                .map_err(|_| "decrypt deployment secrets".to_string())?,
        );
        serde_json::from_slice(&plaintext)
            .map(Some)
            .map_err(|error| format!("decode deployment secrets: {error}"))
    }

    /// Remove encrypted secrets immediately.
    pub fn delete_secrets(&self, agent_pubkey: &str) -> Result<(), String> {
        self.connection
            .execute(
                "UPDATE deployments SET installed_secret_revision=NULL,
                   secret_nonce=NULL, secret_ciphertext=NULL, updated_at=unixepoch()
                 WHERE agent_pubkey=?1",
                params![agent_pubkey],
            )
            .map_err(|error| format!("delete deployment secrets: {error}"))?;
        self.connection
            .execute(
                "DELETE FROM pending_provisioning WHERE agent_pubkey=?1",
                params![agent_pubkey],
            )
            .map_err(|error| format!("delete pending deployment secrets: {error}"))?;
        Ok(())
    }

    /// Return all desired deployments.
    pub fn deployments(&self) -> Result<Vec<DeploymentRecord>, String> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT agent_pubkey, desired_json, observed_generation,
                        actual_state, stop_latch_generation,
                        installed_secret_revision, failure_count,
                        last_failure_at, last_error, image_digest
                 FROM deployments ORDER BY agent_pubkey",
            )
            .map_err(|error| format!("prepare deployment query: {error}"))?;
        let rows = statement
            .query_map([], |row| {
                let desired_json: String = row.get(1)?;
                let desired = serde_json::from_str(&desired_json).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        desired_json.len(),
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?;
                let actual_raw: String = row.get(3)?;
                let actual_state =
                    serde_json::from_str(&format!("\"{actual_raw}\"")).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            actual_raw.len(),
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?;
                Ok(DeploymentRecord {
                    agent_pubkey: row.get(0)?,
                    desired,
                    observed_generation: row.get(2)?,
                    actual_state,
                    stop_latch_generation: row.get(4)?,
                    installed_secret_revision: row.get(5)?,
                    failure_count: row.get(6)?,
                    last_failure_at: row.get(7)?,
                    last_error: row.get(8)?,
                    image_digest: row.get(9)?,
                })
            })
            .map_err(|error| format!("query deployments: {error}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("decode deployment record: {error}"))
    }

    /// Update observed reconciliation state.
    pub fn set_actual(
        &self,
        agent_pubkey: &str,
        generation: u64,
        state: DeploymentActualState,
        error: Option<&str>,
        image_digest: Option<&str>,
    ) -> Result<(), String> {
        let state =
            serde_json::to_string(&state).map_err(|serialize_error| serialize_error.to_string())?;
        let state = state.trim_matches('"');
        self.connection
            .execute(
                "UPDATE deployments SET observed_generation=?2, actual_state=?3,
                   last_error=?4, image_digest=COALESCE(?5, image_digest),
                   updated_at=unixepoch() WHERE agent_pubkey=?1",
                params![agent_pubkey, generation, state, error, image_digest],
            )
            .map_err(|db_error| format!("update actual deployment state: {db_error}"))?;
        Ok(())
    }

    /// Persist a clean-stop latch for this generation.
    pub fn latch_clean_stop(&self, agent_pubkey: &str, generation: u64) -> Result<(), String> {
        self.connection
            .execute(
                "UPDATE deployments SET stop_latch_generation=?2,
                   actual_state='stopped_by_agent', observed_generation=?2,
                   updated_at=unixepoch() WHERE agent_pubkey=?1",
                params![agent_pubkey, generation],
            )
            .map_err(|error| format!("persist clean-stop latch: {error}"))?;
        Ok(())
    }

    /// Increment and return the crash count.
    pub fn record_failure(&self, agent_pubkey: &str, now: u64, error: &str) -> Result<u32, String> {
        self.connection
            .execute(
                "UPDATE deployments SET failure_count=failure_count+1,
                   last_failure_at=?2, last_error=?3, updated_at=unixepoch()
                 WHERE agent_pubkey=?1",
                params![agent_pubkey, now, error],
            )
            .map_err(|db_error| format!("record deployment failure: {db_error}"))?;
        self.connection
            .query_row(
                "SELECT failure_count FROM deployments WHERE agent_pubkey=?1",
                params![agent_pubkey],
                |row| row.get(0),
            )
            .map_err(|db_error| format!("read deployment failure count: {db_error}"))
    }

    /// Record a retired workspace path.
    pub fn retire_workspace(&self, agent_pubkey: &str, path: &Path) -> Result<(), String> {
        self.connection
            .execute(
                "INSERT INTO retired_workspaces(agent_pubkey, path, retired_at)
                 VALUES (?1, ?2, unixepoch())
                 ON CONFLICT(agent_pubkey) DO UPDATE SET
                   path=excluded.path, retired_at=excluded.retired_at",
                params![agent_pubkey, path.to_string_lossy()],
            )
            .map_err(|error| format!("record retired workspace: {error}"))?;
        Ok(())
    }

    /// List retired workspace paths.
    pub fn retired_workspaces(&self) -> Result<Vec<(String, PathBuf)>, String> {
        let mut statement = self
            .connection
            .prepare("SELECT agent_pubkey, path FROM retired_workspaces ORDER BY retired_at DESC")
            .map_err(|error| format!("prepare retired workspace query: {error}"))?;
        let rows = statement
            .query_map([], |row| {
                let agent: String = row.get(0)?;
                let path: String = row.get(1)?;
                Ok((agent, PathBuf::from(path)))
            })
            .map_err(|error| format!("query retired workspaces: {error}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("decode retired workspace: {error}"))
    }

    /// Forget a purged retired workspace.
    pub fn remove_retired_workspace(&self, agent_pubkey: &str) -> Result<(), String> {
        self.connection
            .execute(
                "DELETE FROM retired_workspaces WHERE agent_pubkey=?1",
                params![agent_pubkey],
            )
            .map_err(|error| format!("remove retired workspace record: {error}"))?;
        Ok(())
    }
}

fn load_or_create_master_key(path: &Path) -> Result<Zeroizing<[u8; 32]>, String> {
    if path.exists() {
        set_private_mode(path, 0o600)
            .map_err(|error| format!("secure runner master key permissions: {error}"))?;
        let mut bytes = Zeroizing::new(Vec::new());
        File::open(path)
            .and_then(|mut file| file.read_to_end(&mut bytes))
            .map_err(|error| format!("read runner master key: {error}"))?;
        let key: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| "runner master key must be exactly 32 bytes".to_string())?;
        return Ok(Zeroizing::new(key));
    }

    let mut key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *key);
    let mut file = create_new_private(path, 0o600)
        .map_err(|error| format!("create runner master key: {error}"))?;
    file.write_all(&*key)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("persist runner master key: {error}"))?;
    set_private_mode(path, 0o600)
        .map_err(|error| format!("secure runner master key permissions: {error}"))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use buzz_core::runner::{DeploymentDesiredState, WorkspacePolicy, RUNNER_PROTOCOL_VERSION};

    use super::*;

    fn desired(generation: u64) -> DeploymentDesiredPayload {
        DeploymentDesiredPayload {
            protocol_version: RUNNER_PROTOCOL_VERSION,
            generation,
            desired_state: DeploymentDesiredState::Running,
            runtime_id: "buzz-agent".into(),
            relay_url: "wss://relay.example".into(),
            workspace_policy: WorkspacePolicy::Persistent,
            secret_revision: generation,
            config: BTreeMap::new(),
        }
    }

    #[test]
    fn persists_generations_latches_and_encrypted_secrets() {
        let temp = tempfile::tempdir().expect("temp");
        let store = Store::open(temp.path()).expect("store");
        assert!(store
            .upsert_desired(&"a".repeat(64), &desired(1))
            .expect("upsert"));
        assert!(!store
            .upsert_desired(&"a".repeat(64), &desired(1))
            .expect("stale"));

        let secrets = DeploymentSecrets {
            agent_private_key: "secret-key".into(),
            auth_tag: "secret-auth".into(),
            environment: BTreeMap::from([("TOKEN".into(), "secret-token".into())]),
        };
        store
            .put_secrets(&"a".repeat(64), 1, 1, &secrets)
            .expect("put secrets");
        assert_eq!(
            store.load_secrets(&"a".repeat(64)).expect("load"),
            Some(secrets)
        );
        let database_bytes = fs::read(temp.path().join("runner.sqlite")).expect("db bytes");
        let database_text = String::from_utf8_lossy(&database_bytes);
        assert!(!database_text.contains("secret-key"));
        assert!(!database_text.contains("secret-token"));

        store.latch_clean_stop(&"a".repeat(64), 1).expect("latch");
        let record = store.deployments().expect("records").remove(0);
        assert_eq!(record.stop_latch_generation, Some(1));
        assert_eq!(record.actual_state, DeploymentActualState::StoppedByAgent);
    }

    #[test]
    fn secrets_received_before_desired_state_are_promoted_when_generation_arrives() {
        let temp = tempfile::tempdir().expect("temp");
        let store = Store::open(temp.path()).expect("store");
        let agent = "b".repeat(64);
        let secrets = DeploymentSecrets {
            agent_private_key: "secret-key".into(),
            auth_tag: "secret-auth".into(),
            environment: BTreeMap::from([("TOKEN".into(), "secret-token".into())]),
        };

        store
            .put_secrets(&agent, 7, 7, &secrets)
            .expect("stage out-of-order secrets");
        assert_eq!(
            store.load_secrets(&agent).expect("load before desired"),
            None
        );
        drop(store);
        let store = Store::open(temp.path()).expect("reopen store");

        store
            .upsert_desired(&agent, &desired(7))
            .expect("persist desired");

        assert_eq!(
            store.load_secrets(&agent).expect("load promoted secrets"),
            Some(secrets)
        );
        let record = store.deployments().expect("records").remove(0);
        assert_eq!(record.installed_secret_revision, Some(7));
    }

    #[test]
    #[cfg(unix)]
    fn master_key_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().expect("temp");
        Store::open(temp.path()).expect("store");
        let mode = fs::metadata(temp.path().join("master.key"))
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn runtime_catalog_replaces_stale_entries_and_keeps_digests() {
        let temp = tempfile::tempdir().expect("temp");
        let store = Store::open(temp.path()).expect("store");
        store
            .replace_runtime_catalog(&[(
                "buzz-agent".into(),
                "buzz-agent:local".into(),
                "sha256:first".into(),
            )])
            .expect("first catalog");
        store
            .replace_runtime_catalog(&[(
                "goose".into(),
                "example/goose:stable".into(),
                "sha256:second".into(),
            )])
            .expect("replacement catalog");
        assert_eq!(
            store.runtime_catalog().expect("catalog"),
            vec![("goose".into(), "sha256:second".into())]
        );
    }
}
