//! # Admin
//!
//! Role-based access control helpers.  The contract has two privileged roles:
//!
//! | Role          | Storage key       | Capabilities                              |
//! |---------------|-------------------|-------------------------------------------|
//! | `admin`       | `StorageKey::Admin`       | Propose/accept admin transfer, rotate relay signer, pause/unpause, upgrade; also permitted to drive status transitions |
//! | `relay_signer`| `StorageKey::RelaySigner` | Register callbacks, drive status transitions |
//!
//! Both roles are initialised once and can be rotated by the admin.

use soroban_sdk::{Address, Env};

use crate::storage::StorageClient;
use crate::types::ContractError;

/// Hard-coded lower bound for the admin-configurable idempotency-key TTL, in
/// ledgers.  Roughly one hour at ~5s per ledger.  Values below this are
/// rejected at configuration time so the dedup window cannot be tuned into
/// something dangerously short.
pub const MIN_IDEMPOTENCY_TTL_LEDGERS: u32 = 720;

/// Hard-coded upper bound for the admin-configurable idempotency-key TTL, in
/// ledgers.  Roughly seven days at ~5s per ledger.  Values above this are
/// rejected at configuration time so temporary-storage rent cannot be tuned
/// into something wastefully long.
pub const MAX_IDEMPOTENCY_TTL_LEDGERS: u32 = 120_960;

/// Hard-coded lower bound for the admin-configurable archival retention
/// period, in ledgers.  Roughly one day at ~5s per ledger.  Values below this
/// are rejected at configuration time so a terminal-state transaction cannot
/// be evicted before off-chain indexers have had a reasonable window to
/// capture its full detail.
pub const MIN_ARCHIVAL_RETENTION_LEDGERS: u32 = 17_280;

/// Hard-coded upper bound for the admin-configurable archival retention
/// period, in ledgers.  Roughly ten years at ~5s per ledger.  Values above
/// this are rejected at configuration time so the retention period cannot be
/// tuned into something effectively unbounded.
pub const MAX_ARCHIVAL_RETENTION_LEDGERS: u32 = 63_072_000;

pub struct AdminClient;

impl AdminClient {
    /// Require the calling transaction to be authorised by the current admin.
    ///
    /// Returns `Err(ContractError::Unauthorised)` when auth fails.
    pub fn require_admin(env: &Env) -> Result<Address, ContractError> {
        let admin = StorageClient::get_admin(env)?;
        admin.require_auth();
        Ok(admin)
    }

    /// Assert that `caller` is either the admin or the trusted relay signer.
    ///
    /// Used by status-transition methods which are callable by both roles.
    pub fn assert_is_relay_or_admin(env: &Env, caller: &Address) -> Result<(), ContractError> {
        let admin = StorageClient::get_admin(env)?;
        let relay = StorageClient::get_relay_signer(env)?;
        if caller != &admin && caller != &relay {
            return Err(ContractError::Unauthorised);
        }
        caller.require_auth();
        Ok(())
    }

    /// Assert that `caller` is specifically the relay signer (not the admin).
    ///
    /// Used by `register_callback` — only the relay may ingest callbacks.
    #[allow(dead_code)]
    pub fn require_relay_signer(env: &Env, caller: &Address) -> Result<(), ContractError> {
        let relay = StorageClient::get_relay_signer(env)?;
        if caller != &relay {
            return Err(ContractError::NotRelaySigner);
        }
        caller.require_auth();
        Ok(())
    }

    /// Validate a proposed idempotency-key TTL (in ledgers) against the
    /// hard-coded `MIN_IDEMPOTENCY_TTL_LEDGERS` / `MAX_IDEMPOTENCY_TTL_LEDGERS`
    /// bounds.
    ///
    /// Returns `Err(ContractError::InvalidIdempotencyTtl)` when the value is
    /// out of bounds, so misconfiguration is rejected at configuration time
    /// rather than silently applied.
    pub fn validate_idempotency_ttl(ttl_ledgers: u32) -> Result<(), ContractError> {
        if ttl_ledgers < MIN_IDEMPOTENCY_TTL_LEDGERS
            || ttl_ledgers > MAX_IDEMPOTENCY_TTL_LEDGERS
        {
            return Err(ContractError::InvalidIdempotencyTtl);
        }
        Ok(())
    }

    /// Validate a proposed archival retention period (in ledgers) against the
    /// hard-coded `MIN_ARCHIVAL_RETENTION_LEDGERS` /
    /// `MAX_ARCHIVAL_RETENTION_LEDGERS` bounds.
    ///
    /// Returns `Err(ContractError::InvalidArchivalRetention)` when the value is
    /// out of bounds, so misconfiguration is rejected at configuration time
    /// rather than silently applied.
    pub fn validate_archival_retention(retention_ledgers: u32) -> Result<(), ContractError> {
        if retention_ledgers < MIN_ARCHIVAL_RETENTION_LEDGERS
            || retention_ledgers > MAX_ARCHIVAL_RETENTION_LEDGERS
        {
            return Err(ContractError::InvalidArchivalRetention);
        }
        Ok(())
    }
}
