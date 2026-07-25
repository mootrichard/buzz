#![deny(unsafe_code)]

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use buzz_core::runner::RUNNER_PROTOCOL_VERSION;
use buzz_runner::config::RunnerConfig;
use buzz_runner::docker::DockerCli;
use buzz_runner::relay::run_control_loop;
use buzz_runner::store::Store;
use clap::{Parser, Subcommand};
use nostr::{Keys, PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use tracing_subscriber::EnvFilter;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "buzz-runner", about = "Buzz remote always-on agent runner")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the relay-connected reconciliation supervisor.
    Run {
        /// Relay WebSocket URL.
        #[arg(long, env = "BUZZ_RELAY_URL")]
        relay: String,
        /// Paired owner public key.
        #[arg(long, env = "BUZZ_RUNNER_OWNER_PUBKEY")]
        owner_pubkey: Option<String>,
    },
    /// Display a one-time pairing URI and SAS.
    Pair {
        /// Main Buzz relay URL.
        #[arg(long, env = "BUZZ_RELAY_URL")]
        relay: String,
    },
    /// Permanently purge one retired workspace.
    Purge {
        /// Agent public key whose retired workspace should be purged.
        agent_pubkey: String,
    },
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("buzz-runner: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    // Both aws-lc-rs and ring are compiled in transitively, so rustls cannot
    // choose a process-level provider automatically when the runner first
    // connects to a wss:// relay.
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| "failed to install rustls crypto provider".to_string())?;
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();
    let config = RunnerConfig::from_env()?;
    fs::create_dir_all(&config.state_dir)
        .map_err(|error| format!("create runner state: {error}"))?;
    let keys = load_or_create_runner_keys(&config.state_dir.join("runner.key"))?;
    let store = Store::open(&config.state_dir)?;

    match Cli::parse().command {
        Some(Command::Pair { relay }) => pair(&relay, &keys, &store),
        Some(Command::Purge { agent_pubkey }) => purge(&store, &agent_pubkey),
        Some(Command::Run {
            relay,
            owner_pubkey,
        }) => {
            let owner_pubkey = wait_for_owner(&store, owner_pubkey).await?;
            let owner = PublicKey::from_hex(&owner_pubkey)
                .map_err(|_| "owner pubkey must be 64-character hex".to_string())?;
            store.set_setting("owner_pubkey", &owner.to_hex())?;
            run_control_loop(&relay, owner, &keys, &store, &DockerCli, &config).await
        }
        None => Err("choose one of: run, pair, purge".into()),
    }
}

async fn wait_for_owner(store: &Store, configured: Option<String>) -> Result<String, String> {
    if let Some(owner) = configured.filter(|value| !value.trim().is_empty()) {
        return Ok(owner);
    }
    loop {
        if let Some(owner) = store.setting("owner_pubkey")? {
            if !owner.trim().is_empty() {
                return Ok(owner);
            }
        }
        tracing::info!(
            "runner is waiting to be paired; run `buzz-runner pair` with this state volume \
             (Compose: `docker compose exec buzz-runner buzz-runner pair`)"
        );
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

fn pair(relay: &str, keys: &Keys, store: &Store) -> Result<(), String> {
    let mut nonce = [0u8; 32];
    let random = Keys::generate();
    nonce.copy_from_slice(random.secret_key().as_secret_bytes());
    let digest = Sha256::digest(nonce);
    let sas_number = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % 1_000_000;
    let nonce_hex = hex::encode(nonce);
    let uri = format!(
        "buzz://runner-pair?relay={}&runner={}&v={}&nonce={}",
        percent_encode(relay),
        keys.public_key().to_hex(),
        RUNNER_PROTOCOL_VERSION,
        nonce_hex
    );
    println!("Pairing URI (one-time):\n{uri}");
    println!("SAS: {sas_number:06}");
    println!("Confirm this SAS in Buzz Desktop. The owner secret key is never transferred.");
    print!("After Desktop confirms the SAS, paste the owner public key it displays: ");
    std::io::stdout()
        .flush()
        .map_err(|error| format!("flush pairing prompt: {error}"))?;
    let mut owner_pubkey = String::new();
    std::io::stdin()
        .read_line(&mut owner_pubkey)
        .map_err(|error| format!("read owner public key: {error}"))?;
    let owner_pubkey = owner_pubkey.trim();
    let owner = PublicKey::from_hex(owner_pubkey)
        .map_err(|_| "owner public key must be 64-character hex".to_string())?;
    print!("Do both screens show SAS {sas_number:06}? [y/N]: ");
    std::io::stdout()
        .flush()
        .map_err(|error| format!("flush SAS prompt: {error}"))?;
    let mut confirmation = String::new();
    std::io::stdin()
        .read_line(&mut confirmation)
        .map_err(|error| format!("read SAS confirmation: {error}"))?;
    if !matches!(
        confirmation.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ) {
        return Err("pairing cancelled; SAS was not confirmed on both sides".into());
    }
    store.set_setting("owner_pubkey", &owner.to_hex())?;
    println!("Runner paired. The supervisor will connect automatically.");
    Ok(())
}

fn percent_encode(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
                vec![byte as char]
            } else {
                format!("%{byte:02X}").chars().collect()
            }
        })
        .collect()
}

fn purge(store: &Store, agent_pubkey: &str) -> Result<(), String> {
    let retired = store
        .retired_workspaces()?
        .into_iter()
        .find(|(agent, _)| agent == agent_pubkey)
        .ok_or_else(|| "no retired workspace exists for that agent".to_string())?;
    if retired.1.exists() {
        fs::remove_dir_all(&retired.1)
            .map_err(|error| format!("purge retired workspace: {error}"))?;
    }
    store.remove_retired_workspace(agent_pubkey)?;
    println!("Purged retired workspace for {agent_pubkey}");
    Ok(())
}

fn load_or_create_runner_keys(path: &Path) -> Result<Keys, String> {
    if path.exists() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("secure runner identity permissions: {error}"))?;
        let mut secret = Zeroizing::new(String::new());
        OpenOptions::new()
            .read(true)
            .open(path)
            .and_then(|mut file| file.read_to_string(&mut secret))
            .map_err(|error| format!("read runner identity: {error}"))?;
        let key = SecretKey::from_hex(secret.trim())
            .map_err(|_| "runner identity file is invalid".to_string())?;
        return Ok(Keys::new(key));
    }
    let keys = Keys::generate();
    let secret_hex = Zeroizing::new(hex::encode(keys.secret_key().as_secret_bytes()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("create runner identity: {error}"))?;
    file.write_all(secret_hex.as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("persist runner identity: {error}"))?;
    Ok(keys)
}
