//! NIP-AR runner protocol validation and registration lookup.

use buzz_core::kind::{
    event_kind_u32, KIND_RUNNER_DEPLOYMENT, KIND_RUNNER_DEPLOYMENT_STATUS, KIND_RUNNER_FRAME,
    KIND_RUNNER_REGISTRATION, KIND_RUNNER_STATUS,
};
use buzz_core::runner::{
    deployment_coordinate, runner_content_looks_encrypted, RunnerRegistrationState,
    RUNNER_AGENT_TAG, RUNNER_REGISTRATION_ACTIVE, RUNNER_REGISTRATION_REVOKED,
    RUNNER_REGISTRATION_TAG, RUNNER_TAG,
};
use buzz_core::CommunityId;
use buzz_db::{Db, EventQuery};
use nostr::{Event, PublicKey};

/// Validated routing information for a NIP-AR event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunnerEventRoute {
    /// Owner-authored registration head.
    Registration {
        /// Registered runner.
        runner: PublicKey,
        /// Registration state.
        state: RunnerRegistrationState,
    },
    /// Owner-authored desired deployment.
    Deployment {
        /// Target runner.
        runner: PublicKey,
        /// Target agent.
        agent: PublicKey,
    },
    /// Runner-authored status head.
    RunnerStatus {
        /// Registered owner recipient.
        owner: PublicKey,
        /// Authoring runner.
        runner: PublicKey,
    },
    /// Runner-authored per-agent status head.
    DeploymentStatus {
        /// Registered owner recipient.
        owner: PublicKey,
        /// Authoring runner.
        runner: PublicKey,
        /// Target agent.
        agent: PublicKey,
    },
    /// Encrypted ephemeral frame.
    Frame {
        /// Recipient.
        recipient: PublicKey,
        /// Paired runner.
        runner: PublicKey,
        /// Optional deployment agent.
        agent: Option<PublicKey>,
        /// Frame routing value.
        frame: String,
    },
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
        .ok_or_else(|| format!("invalid: runner event requires one {name} tag"))?;
    if values.next().is_some() {
        return Err(format!(
            "invalid: runner event requires exactly one {name} tag"
        ));
    }
    Ok(value)
}

fn optional_single_tag<'a>(event: &'a Event, name: &str) -> Result<Option<&'a str>, String> {
    let mut values = event.tags.iter().filter_map(|tag| {
        let values = tag.as_slice();
        (values.first().map(String::as_str) == Some(name))
            .then(|| values.get(1).map(String::as_str))
            .flatten()
    });
    let value = values.next();
    if values.next().is_some() {
        return Err(format!(
            "invalid: runner event allows at most one {name} tag"
        ));
    }
    Ok(value)
}

fn pubkey_tag(event: &Event, name: &str) -> Result<PublicKey, String> {
    PublicKey::from_hex(single_tag(event, name)?)
        .map_err(|_| format!("invalid: runner {name} tag must be a hex pubkey"))
}

fn coordinate_matches(event: &Event, runner: &PublicKey, agent: &PublicKey) -> Result<(), String> {
    let expected = deployment_coordinate(&runner.to_hex(), &agent.to_hex());
    if single_tag(event, "d")? != expected {
        return Err("invalid: deployment d tag does not match runner and agent".into());
    }
    Ok(())
}

/// Validate the public envelope of a NIP-AR event.
pub fn validate_runner_event(event: &Event) -> Result<RunnerEventRoute, String> {
    if !runner_content_looks_encrypted(&event.content) {
        return Err("invalid: runner content must be NIP-44 encrypted".into());
    }

    match event_kind_u32(event) {
        KIND_RUNNER_REGISTRATION => {
            let runner = pubkey_tag(event, RUNNER_TAG)?;
            if pubkey_tag(event, "p")? != runner || single_tag(event, "d")? != runner.to_hex() {
                return Err("invalid: registration d, p, and runner tags must match".into());
            }
            let state = match single_tag(event, RUNNER_REGISTRATION_TAG)? {
                RUNNER_REGISTRATION_ACTIVE => RunnerRegistrationState::Active,
                RUNNER_REGISTRATION_REVOKED => RunnerRegistrationState::Revoked,
                _ => return Err("invalid: registration status must be active or revoked".into()),
            };
            Ok(RunnerEventRoute::Registration { runner, state })
        }
        KIND_RUNNER_DEPLOYMENT => {
            let runner = pubkey_tag(event, RUNNER_TAG)?;
            let agent = pubkey_tag(event, RUNNER_AGENT_TAG)?;
            if pubkey_tag(event, "p")? != runner {
                return Err("invalid: deployment p and runner tags must match".into());
            }
            coordinate_matches(event, &runner, &agent)?;
            Ok(RunnerEventRoute::Deployment { runner, agent })
        }
        KIND_RUNNER_STATUS => {
            let owner = pubkey_tag(event, "p")?;
            let runner = pubkey_tag(event, RUNNER_TAG)?;
            if runner != event.pubkey || single_tag(event, "d")? != runner.to_hex() {
                return Err("invalid: runner status author, d, and runner tags must match".into());
            }
            Ok(RunnerEventRoute::RunnerStatus { owner, runner })
        }
        KIND_RUNNER_DEPLOYMENT_STATUS => {
            let owner = pubkey_tag(event, "p")?;
            let runner = pubkey_tag(event, RUNNER_TAG)?;
            let agent = pubkey_tag(event, RUNNER_AGENT_TAG)?;
            if runner != event.pubkey {
                return Err("invalid: deployment status must be authored by its runner".into());
            }
            coordinate_matches(event, &runner, &agent)?;
            Ok(RunnerEventRoute::DeploymentStatus {
                owner,
                runner,
                agent,
            })
        }
        KIND_RUNNER_FRAME => {
            let recipient = pubkey_tag(event, "p")?;
            let runner = pubkey_tag(event, RUNNER_TAG)?;
            let agent = optional_single_tag(event, RUNNER_AGENT_TAG)?
                .map(PublicKey::from_hex)
                .transpose()
                .map_err(|_| "invalid: runner agent tag must be a hex pubkey".to_string())?;
            let frame = single_tag(event, "frame")?;
            if !matches!(
                frame,
                "secrets_put" | "purge_workspace" | "acknowledgement" | "heartbeat"
            ) {
                return Err("invalid: unknown runner frame".into());
            }
            match frame {
                "secrets_put" | "purge_workspace" if agent.is_none() => {
                    return Err("invalid: deployment runner frame requires an agent tag".into());
                }
                "heartbeat" if agent.is_some() => {
                    return Err("invalid: runner heartbeat must not contain an agent tag".into());
                }
                _ => {}
            }
            Ok(RunnerEventRoute::Frame {
                recipient,
                runner,
                agent,
                frame: frame.to_string(),
            })
        }
        _ => Err("invalid: not a NIP-AR event kind".into()),
    }
}

/// Extract the owner from a NIP-42 registration reference.
///
/// The auth event must contain exactly one
/// `a=30178:<owner-pubkey>:<runner-pubkey>` tag.
pub fn runner_owner_from_auth_event(
    auth_event: &Event,
    runner: &PublicKey,
) -> Result<Option<PublicKey>, String> {
    let Some(value) = optional_single_tag(auth_event, "a")? else {
        return Ok(None);
    };
    let mut parts = value.split(':');
    let kind = parts.next();
    let owner = parts.next();
    let referenced_runner = parts.next();
    if parts.next().is_some()
        || kind != Some("30178")
        || referenced_runner != Some(runner.to_hex().as_str())
    {
        return Err("invalid: malformed runner registration reference".into());
    }
    owner
        .ok_or_else(|| "invalid: missing runner owner".to_string())
        .and_then(|value| {
            PublicKey::from_hex(value).map_err(|_| "invalid: malformed runner owner".to_string())
        })
        .map(Some)
}

/// Return whether the latest owner-authored registration is active and valid.
pub async fn registration_is_active(
    db: &Db,
    community: CommunityId,
    owner: &PublicKey,
    runner: &PublicKey,
) -> Result<bool, String> {
    let mut query = EventQuery::for_community(community);
    query.kinds = Some(vec![KIND_RUNNER_REGISTRATION as i32]);
    query.pubkey = Some(owner.to_bytes().to_vec());
    query.d_tag = Some(runner.to_hex());
    query.global_only = true;
    query.limit = Some(1);
    let event = db
        .query_events(&query)
        .await
        .map_err(|error| format!("registration lookup failed: {error}"))?
        .into_iter()
        .next();
    Ok(matches!(
        event
            .as_ref()
            .map(|stored| validate_runner_event(&stored.event)),
        Some(Ok(RunnerEventRoute::Registration {
            runner: registered,
            state: RunnerRegistrationState::Active,
        })) if registered == *runner
    ))
}

/// Validate a runner event and verify the active registration binding.
pub async fn authorize_runner_event(
    db: &Db,
    community: CommunityId,
    event: &Event,
) -> Result<RunnerEventRoute, String> {
    let route = validate_runner_event(event)?;
    let binding = match &route {
        RunnerEventRoute::Registration { runner, .. } => {
            if *runner == event.pubkey {
                return Err("invalid: a runner cannot register itself".into());
            }
            None
        }
        RunnerEventRoute::Deployment { runner, .. } => Some((event.pubkey, *runner)),
        RunnerEventRoute::RunnerStatus { owner, runner }
        | RunnerEventRoute::DeploymentStatus { owner, runner, .. } => Some((*owner, *runner)),
        RunnerEventRoute::Frame {
            recipient,
            runner,
            frame,
            ..
        } => {
            if event.pubkey == *runner && *recipient != *runner {
                if !matches!(frame.as_str(), "acknowledgement" | "heartbeat") {
                    return Err("invalid: runner-to-owner frame operation is not allowed".into());
                }
                Some((*recipient, *runner))
            } else if *recipient == *runner && event.pubkey != *runner {
                if !matches!(frame.as_str(), "secrets_put" | "purge_workspace") {
                    return Err("invalid: owner-to-runner frame operation is not allowed".into());
                }
                Some((event.pubkey, *runner))
            } else {
                return Err(
                    "invalid: runner frame must be between a runner and its registered owner"
                        .into(),
                );
            }
        }
    };
    if let Some((owner, runner)) = binding {
        if !registration_is_active(db, community, &owner, &runner).await? {
            return Err("restricted: runner registration is not active".into());
        }
    }
    Ok(route)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::{EventBuilder, Keys, Kind, Tag};

    fn encrypted() -> String {
        "A".repeat(buzz_core::observer::NIP44_MIN_CONTENT_LEN)
    }

    #[test]
    fn rejects_plaintext_and_mismatched_coordinates() {
        let owner = Keys::generate();
        let runner = Keys::generate();
        let agent = Keys::generate();
        let event = EventBuilder::new(Kind::Custom(KIND_RUNNER_DEPLOYMENT as u16), "plain")
            .tags([
                Tag::parse(["d", "wrong"]).expect("d"),
                Tag::public_key(runner.public_key()),
                Tag::parse([RUNNER_TAG, &runner.public_key().to_hex()]).expect("runner"),
                Tag::parse([RUNNER_AGENT_TAG, &agent.public_key().to_hex()]).expect("agent"),
            ])
            .sign_with_keys(&owner)
            .expect("sign");
        assert!(validate_runner_event(&event).is_err());

        let event = EventBuilder::new(Kind::Custom(KIND_RUNNER_DEPLOYMENT as u16), encrypted())
            .tags([
                Tag::parse(["d", "wrong"]).expect("d"),
                Tag::public_key(runner.public_key()),
                Tag::parse([RUNNER_TAG, &runner.public_key().to_hex()]).expect("runner"),
                Tag::parse([RUNNER_AGENT_TAG, &agent.public_key().to_hex()]).expect("agent"),
            ])
            .sign_with_keys(&owner)
            .expect("sign");
        assert!(validate_runner_event(&event).is_err());
    }

    #[test]
    fn auth_reference_binds_owner_and_runner() {
        let owner = Keys::generate();
        let runner = Keys::generate();
        let coordinate = format!(
            "30178:{}:{}",
            owner.public_key().to_hex(),
            runner.public_key().to_hex()
        );
        let event = EventBuilder::new(Kind::Custom(22242), "")
            .tags([Tag::parse(["a", &coordinate]).expect("a")])
            .sign_with_keys(&runner)
            .expect("sign");
        assert_eq!(
            runner_owner_from_auth_event(&event, &runner.public_key()).expect("parse"),
            Some(owner.public_key())
        );
    }

    #[test]
    fn deployment_frames_require_a_matching_public_route_shape() {
        let owner = Keys::generate();
        let runner = Keys::generate();
        let encrypted = encrypted();
        let missing_agent = EventBuilder::new(Kind::Custom(KIND_RUNNER_FRAME as u16), &encrypted)
            .tags([
                Tag::public_key(runner.public_key()),
                Tag::parse([RUNNER_TAG, &runner.public_key().to_hex()]).expect("runner"),
                Tag::parse(["frame", "secrets_put"]).expect("frame"),
            ])
            .sign_with_keys(&owner)
            .expect("sign");
        assert!(validate_runner_event(&missing_agent).is_err());

        let heartbeat_with_agent =
            EventBuilder::new(Kind::Custom(KIND_RUNNER_FRAME as u16), encrypted)
                .tags([
                    Tag::public_key(owner.public_key()),
                    Tag::parse([RUNNER_TAG, &runner.public_key().to_hex()]).expect("runner"),
                    Tag::parse([RUNNER_AGENT_TAG, &Keys::generate().public_key().to_hex()])
                        .expect("agent"),
                    Tag::parse(["frame", "heartbeat"]).expect("frame"),
                ])
                .sign_with_keys(&runner)
                .expect("sign");
        assert!(validate_runner_event(&heartbeat_with_agent).is_err());
    }
}
