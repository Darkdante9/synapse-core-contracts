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

/// Ledgers a signer approval stays valid for (~8 minutes at ~5s/ledger).
pub const RELAY_APPROVAL_WINDOW_LEDGERS: u32 = 100;

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

    /// Check `nonce` against `addr`'s next expected nonce and increment it.
    ///
    /// Nonces are strictly sequential per address: only the exact next value
    /// is accepted (no gaps, no reuse). Any other value fails with
    /// [`ContractError::InvalidNonce`].
    pub fn consume_nonce(env: &Env, addr: &Address, nonce: u64) -> Result<(), ContractError> {
        let expected = StorageClient::get_nonce(env, addr);
        if nonce != expected {
            return Err(ContractError::InvalidNonce);
        }
        StorageClient::set_nonce(env, addr, expected + 1);
        Ok(())
    }

    /// Assert that `caller` is either the admin or the trusted relay signer.
    ///
    /// Used by status-transition methods which are callable by both roles.
    pub fn assert_is_relay_or_admin(env: &Env, caller: &Address) -> Result<(), ContractError> {
        let admin = StorageClient::get_admin(env)?;
        if caller == &admin {
            caller.require_auth();
            return Ok(());
        }
        let set = StorageClient::get_relay_signer_set(env)?;
        if !set.signers.contains(caller) {
            return Err(ContractError::Unauthorised);
        }
        Self::require_relay_quorum(env, Some(caller))
    }

    /// Like [`Self::assert_is_relay_or_admin`], but honours a per-transaction
    /// signer binding: when `assigned` is `Some`, the caller must be that
    /// signer (or the admin) rather than the global relay signer.
    pub fn assert_can_drive_tx(
        env: &Env,
        caller: &Address,
        assigned: &Option<Address>,
    ) -> Result<(), ContractError> {
        match assigned {
            None => Self::assert_is_relay_or_admin(env, caller),
            Some(signer) => {
                let admin = StorageClient::get_admin(env)?;
                if caller != &admin && caller != signer {
                    return Err(ContractError::Unauthorised);
                }
                caller.require_auth();
                Ok(())
            }
        }
    }

    /// Assert that `caller` is specifically the relay signer (not the admin).
    ///
    /// Used by `register_callback` — only the relay may ingest callbacks.
    pub fn require_relay_signer(env: &Env, caller: &Address) -> Result<(), ContractError> {
        let set = StorageClient::get_relay_signer_set(env)?;
        if !set.signers.contains(caller) {
            return Err(ContractError::NotRelaySigner);
        }
        Self::require_relay_quorum(env, Some(caller))
    }

    /// Require `threshold`-of-`signers` authorisation (multi-invocation quorum).
    ///
    /// `caller` (if given) counts as one authorised signer via `require_auth`;
    /// every other signer must have registered a fresh approval through
    /// `approve_relay_call` within [`RELAY_APPROVAL_WINDOW_LEDGERS`]. With a
    /// single-signer set and no caller (legacy `register_callback`), that
    /// signer's own auth is required directly. Approvals are consumed.
    pub fn require_relay_quorum(env: &Env, caller: Option<&Address>) -> Result<(), ContractError> {
        let set = StorageClient::get_relay_signer_set(env)?;
        match caller {
            Some(c) => c.require_auth(),
            None if set.signers.len() == 1 => {
                set.signers.get(0).ok_or(ContractError::NotInitialised)?.require_auth();
                return Ok(());
            }
            None => {}
        }
        let now = env.ledger().sequence();
        let mut count = 0u32;
        for s in set.signers.iter() {
            let is_caller = caller == Some(&s);
            let approved = StorageClient::get_relay_approval(env, &s)
                .map(|l| now.saturating_sub(l) <= RELAY_APPROVAL_WINDOW_LEDGERS)
                .unwrap_or(false);
            if is_caller || approved {
                count += 1;
            }
        }
        if count < set.threshold {
            return Err(ContractError::QuorumNotMet);
        }
        for s in set.signers.iter() {
            StorageClient::clear_relay_approval(env, &s);
        }
        Ok(())
    }

    /// Reject `signer` with [`ContractError::SignerQuarantined`] when its last
    /// heartbeat is older than the configured window.
    ///
    /// A signer that has never heartbeated, or a window of `0`, is never
    /// quarantined (backward compatible). Staleness is strict: a signer is
    /// quarantined only when `now - last_heartbeat > window`.
    pub fn assert_not_quarantined(env: &Env, signer: &Address) -> Result<(), ContractError> {
        let window = StorageClient::get_heartbeat_window(env);
        if window == 0 {
            return Ok(());
        }
        if let Some(last) = StorageClient::get_last_heartbeat(env, signer) {
            if env.ledger().timestamp().saturating_sub(last) > window {
                return Err(ContractError::SignerQuarantined);
            }
        }
        Ok(())
    }

    /// Assert that `caller` holds `scope`, then require its auth.
    ///
    /// The admin and relay signer implicitly hold all scopes. Any other caller
    /// lacking the scope gets the same [`ContractError::Unauthorised`] as an
    /// unknown address, so error output does not reveal which addresses hold
    /// other scopes.
    pub fn require_scope(
        env: &Env,
        caller: &Address,
        scope: crate::types::RoleScope,
    ) -> Result<(), ContractError> {
        let admin = StorageClient::get_admin(env)?;
        let relay = StorageClient::get_relay_signer(env)?;
        if caller != &admin
            && caller != &relay
            && !StorageClient::get_scopes(env, caller).contains(scope)
        {
            return Err(ContractError::Unauthorised);
        }
        caller.require_auth();
        Ok(())
    }
}
