//! # Storage
//!
//! All ledger read/write operations are centralised here, keeping handler and
//! service logic free of raw `env.storage()` calls.
//!
//! ## Storage tiers used
//!
//! | Data                  | Tier       | Rationale                                  |
//! |-----------------------|------------|--------------------------------------------|
//! | Admin, relay signer   | `persistent` | Must survive archive/restore cycles      |
//! | Transactions          | `persistent` | Long-lived; needed for audit trail       |
//! | Idempotency keys      | `temporary`  | Admin-tunable TTL; evicted by the ledger |
//! | Initialised flag      | `instance`   | Lives with the contract instance         |

use soroban_sdk::{Address, Env, String};

use crate::types::{ContractError, StorageKey, Transaction};

/// Default TTL in ledgers applied to idempotency keys (~24 hours at ~5s/ledger).
///
/// 24 * 3600 / 5 = 17_280 ledgers.  We round up to 18_000 for safety.
pub const DEFAULT_IDEMPOTENCY_TTL_LEDGERS: u32 = 18_000;

/// Hard-coded lower bound for the admin-tunable idempotency-key TTL.
///
/// ~1 hour at ~5s/ledger (3600 / 5 = 720).  Anything shorter risks evicting
/// keys before the off-chain retry window has elapsed, defeating deduplication.
pub const MIN_IDEMPOTENCY_TTL_LEDGERS: u32 = 720;

/// Hard-coded upper bound for the admin-tunable idempotency-key TTL.
///
/// ~7 days at ~5s/ledger (7 * 24 * 3600 / 5 = 120_960).  Anything longer
/// wastes temporary-storage rent on keys that can no longer be replayed.
pub const MAX_IDEMPOTENCY_TTL_LEDGERS: u32 = 120_960;

/// Minimum TTL we require on transaction records before extending.
const TRANSACTION_MIN_TTL_LEDGERS: u32 = 100_000; // ~1 week

/// Default archival retention period in ledgers (~30 days at ~5s/ledger).
///
/// Terminal-state transactions younger than this are rejected by
/// [`StorageClient::archive_transaction`], giving off-chain indexers a
/// generous window to capture full detail before eviction.
pub const DEFAULT_ARCHIVE_RETENTION_LEDGERS: u32 = 518_400;

pub struct StorageClient;

impl StorageClient {
    // ── Initialisation flag ───────────────────────────────────────────────────

    /// Returns `true` if [`crate::SynapseCoreContract::initialize`] has been called.
    pub fn is_initialised(env: &Env) -> bool {
        env.storage().instance().has(&StorageKey::Initialised)
    }

    /// Persist the initialised flag.  Called exactly once during `initialize()`.
    pub fn set_initialised(env: &Env) {
        env.storage()
            .instance()
            .set(&StorageKey::Initialised, &true);
    }

    // ── Pause / circuit breaker ───────────────────────────────────────────────

    /// Returns `true` when the emergency-pause flag is engaged.
    ///
    /// Defaults to `false` when the flag has never been written, so a freshly
    /// initialised contract is always unpaused.
    pub fn is_paused(env: &Env) -> bool {
        env.storage()
            .instance()
            .get(&StorageKey::Paused)
            .unwrap_or(false)
    }

    /// Persist the emergency-pause flag.
    pub fn set_paused(env: &Env, paused: bool) {
        env.storage().instance().set(&StorageKey::Paused, &paused);
    }

    // ── Admin ─────────────────────────────────────────────────────────────────

    /// Read the current admin address from persistent storage.
    pub fn get_admin(env: &Env) -> Result<Address, ContractError> {
        env.storage()
            .persistent()
            .get(&StorageKey::Admin)
            .ok_or(ContractError::NotInitialised)
    }

    /// Persist an admin address.
    pub fn set_admin(env: &Env, admin: &Address) {
        env.storage().persistent().set(&StorageKey::Admin, admin);
    }

    // ── Relay signer ──────────────────────────────────────────────────────────

    /// Read the trusted relay signer address.
    pub fn get_relay_signer(env: &Env) -> Result<Address, ContractError> {
        env.storage()
            .persistent()
            .get(&StorageKey::RelaySigner)
            .ok_or(ContractError::NotInitialised)
    }

    /// Persist the relay signer address.
    pub fn set_relay_signer(env: &Env, signer: &Address) {
        env.storage()
            .persistent()
            .set(&StorageKey::RelaySigner, signer);
    }

    // ── Admin transfer (two-step) ─────────────────────────────────────────────

    /// Read the pending admin nominee, if a transfer is in progress.
    pub fn get_pending_admin(env: &Env) -> Option<Address> {
        env.storage().persistent().get(&StorageKey::PendingAdmin)
    }

    /// Persist the pending admin nominee, overwriting any existing proposal.
    pub fn set_pending_admin(env: &Env, nominee: &Address) {
        env.storage()
            .persistent()
            .set(&StorageKey::PendingAdmin, nominee);
    }

    /// Clear the pending admin nominee after a transfer is accepted.
    pub fn clear_pending_admin(env: &Env) {
        env.storage().persistent().remove(&StorageKey::PendingAdmin);
    }

    // ── Schema version ────────────────────────────────────────────────────────

    /// Read the on-chain storage schema version.
    pub fn get_schema_version(env: &Env) -> Result<u32, ContractError> {
        env.storage()
            .persistent()
            .get(&StorageKey::SchemaVersion)
            .ok_or(ContractError::NotInitialised)
    }

    /// Persist the storage schema version. Called once during `initialize()`.
    pub fn set_schema_version(env: &Env, version: u32) {
        env.storage()
            .persistent()
            .set(&StorageKey::SchemaVersion, &version);
    }

    // ── Idempotency TTL parameter ─────────────────────────────────────────────

    /// Read the admin-configured idempotency-key TTL in ledgers.
    ///
    /// Falls back to [`DEFAULT_IDEMPOTENCY_TTL_LEDGERS`] when the parameter has
    /// never been set, so a freshly initialised contract keeps the historical
    /// ~24-hour window without requiring an explicit configuration call.
    pub fn get_idempotency_ttl(env: &Env) -> u32 {
        env.storage()
            .instance()
            .get(&StorageKey::IdempotencyTtl)
            .unwrap_or(DEFAULT_IDEMPOTENCY_TTL_LEDGERS)
    }

    /// Persist the admin-configured idempotency-key TTL in ledgers.
    ///
    /// The caller is responsible for validating `ttl` against
    /// [`MIN_IDEMPOTENCY_TTL_LEDGERS`] / [`MAX_IDEMPOTENCY_TTL_LEDGERS`] before
    /// invoking this; out-of-bounds values are rejected at configuration time.
    pub fn set_idempotency_ttl(env: &Env, ttl: u32) {
        env.storage()
            .instance()
            .set(&StorageKey::IdempotencyTtl, &ttl);
    }

    // ── Archival retention parameter ──────────────────────────────────────────

    /// Read the admin-configured archival retention period in ledgers.
    ///
    /// Falls back to [`DEFAULT_ARCHIVE_RETENTION_LEDGERS`] when the parameter
    /// has never been set, so a freshly initialised contract keeps a sensible
    /// ~30-day window without requiring an explicit configuration call.
    pub fn get_archive_retention(env: &Env) -> u32 {
        env.storage()
            .instance()
            .get(&StorageKey::ArchiveRetention)
            .unwrap_or(DEFAULT_ARCHIVE_RETENTION_LEDGERS)
    }

    /// Persist the admin-configured archival retention period in ledgers.
    pub fn set_archive_retention(env: &Env, retention: u32) {
        env.storage()
            .instance()
            .set(&StorageKey::ArchiveRetention, &retention);
    }

    // ── Transactions ──────────────────────────────────────────────────────────

    /// Returns `true` if a transaction record already exists for `tx_id`.
    ///
    /// Existence-only check — unlike [`Self::get_transaction`] it does not
    /// extend TTL, since it is used purely as a pre-write guard against
    /// `transaction_id` reuse (see `register_callback`'s duplicate-tx-id
    /// check, THREAT_MODEL.md finding F-07).
    pub fn transaction_exists(env: &Env, tx_id: &String) -> bool {
        env.storage()
            .persistent()
            .has(&StorageKey::Transaction(tx_id.clone()))
    }

    /// Read a [`Transaction`] by its ID.
    ///
    /// Extends the ledger TTL on each access so active records are never evicted.
    pub fn get_transaction(env: &Env, tx_id: &String) -> Result<Transaction, ContractError> {
        let key = StorageKey::Transaction(tx_id.clone());
        let tx = env
            .storage()
            .persistent()
            .get::<StorageKey, Transaction>(&key)
            .ok_or(ContractError::TransactionNotFound)?;
        env.storage().persistent().extend_ttl(
            &key,
            TRANSACTION_MIN_TTL_LEDGERS,
            TRANSACTION_MIN_TTL_LEDGERS,
        );
        Ok(tx)
    }

    /// Persist (insert or update) a [`Transaction`].
    pub fn save_transaction(env: &Env, tx: &Transaction) {
        let key = StorageKey::Transaction(tx.id.clone());
        env.storage().persistent().set(&key, tx);
        env.storage().persistent().extend_ttl(
            &key,
            TRANSACTION_MIN_TTL_LEDGERS,
            TRANSACTION_MIN_TTL_LEDGERS,
        );
    }

    /// Evict a [`Transaction`] record from active persistent storage.
    ///
    /// This is the explicit-eviction half of the archival mechanism: the
    /// caller (see `SynapseCoreContract::archive_transaction`) is responsible
    /// for having validated terminal state and retention eligibility, and for
    /// emitting `EventTransactionArchived` with the full record so off-chain
    /// indexers retain the audit trail.  After this call the transaction is no
    /// longer returned by active-state queries such as
    /// `get_transactions_by_status`.
    pub fn remove_transaction(env: &Env, tx_id: &String) {
        env.storage()
            .persistent()
            .remove(&StorageKey::Transaction(tx_id.clone()));
    }
}
