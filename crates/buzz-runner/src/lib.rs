#![deny(unsafe_code)]
#![warn(missing_docs)]
//! Durable, single-owner Docker supervisor for Buzz agents.

/// Runtime configuration and allowlist parsing.
pub mod config;
/// Docker engine abstraction and hardened container specification.
pub mod docker;
/// Fail-closed filesystem helpers for private runner state.
pub mod fs_security;
/// Desired/actual-state reconciliation.
pub mod reconcile;
/// Relay control-plane loop.
pub mod relay;
/// SQLite state and encrypted secret storage.
pub mod store;
