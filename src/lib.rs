#![no_std]

//! # Synapse Core — On-Chain Contract
//!
//! Phase 1 of the Synapse Bridge ecosystem.
//!
//! This contract mirrors the off-chain `synapse-core` Rust service, providing an
//! **on-chain transaction registry** that:
//!
//! 1. Accepts callback registrations from the Stellar Anchor Platform (via the
//!    off-chain relay), storing each deposit event with status `Pending`.
//! 2. Guards against duplicate delivery with an idempotency key ledger.
//! 3. Drives the transaction through its lifecycle:
//!    `Pending → Processing → Completed | Failed`
//! 4. Emits structured events at every state transition so Phase 2 (Swap Engine)
//!    and Phase 3 (Cross-Chain Bridge) can subscribe and act.
//!
//! ## Module layout
//!
//! ```text
//! lib.rs          ← you are here (contract entry-point)
//! types.rs        ← Transaction, TransactionStatus, CallbackPayload, errors
//! storage.rs      ← all ledger read/write helpers
//! events.rs       ← typed event emission
//! validation.rs   ← input guards (account format, asset code, amount bounds)
//! admin.rs        ← admin / owner management
//! ```

mod admin;
mod events;
mod storage;
mod types;
mod validation;

#[cfg(test)]
mod test_pause;
#[cfg(test)]
    AdminRateLimitConfig, CallbackPayload, ContractError, PendingRelaySigner, RelaySignerSet,
    RoleScope, Transaction, TransactionStatus, UnpauseRoles, MAX_BATCH_SIZE, SCHEMA_VERSION,
#[cfg(test)]
mod tests;

use soroban_sdk::{contract, contractimpl, Address, BytesN, Env, String, Vec};

use crate::admin::AdminClient;
use crate::events::EventEmitter;
use crate::storage::StorageClient;
use crate::types::{
    AdminRateLimitConfig, CallbackPayload, ContractError, PendingRelaySigner, RelaySignerSet, RoleScope, Transaction, TransactionStatus,
    UnpauseRoles, MAX_BATCH_SIZE, MAX_PAGE_LIMIT, MAX_RETRIES, DEFAULT_RELAY_SIGNER_DELAY_LEDGERS, SCHEMA_VERSION,
};
use crate::validation::Validator;

// ─── Idempotency-key TTL bounds ──────────────────────────────────────────────

/// Minimum permitted idempotency-key TTL, in ledgers (~1 hour at 5s/ledger).
///
/// A shorter window risks accepting a genuine replay as a fresh callback,
/// defeating the temporary-tier dedup guard.
pub const MIN_IDEMPOTENCY_TTL_LEDGERS: u32 = 720;

/// Maximum permitted idempotency-key TTL, in ledgers (~7 days at 5s/ledger).
///
/// A longer window wastes temporary-storage rent on keys whose replay risk has
/// long since passed (see `COST_MODEL.md`).
pub const MAX_IDEMPOTENCY_TTL_LEDGERS: u32 = 120_960;

/// Default idempotency-key TTL, in ledgers (~24h at 5s/ledger).
///
/// Mirrors the off-chain Redis deduplication TTL documented in `README.md`.
pub const DEFAULT_IDEMPOTENCY_TTL_LEDGERS: u32 = 17_280;

/// Maximum number of transaction records a single [`SynapseCoreContract::bump_transaction_ttl_batch`]
/// call may extend. Bounds the per-call resource footprint so a maintenance
/// pass cannot exceed Soroban's per-transaction CPU/ledger-entry limits.
const MAX_TTL_BUMP_BATCH: u32 = 50;

// ─── Public contract interface ───────────────────────────────────────────────

#[contract]
pub struct SynapseCoreContract;

#[contractimpl]
impl SynapseCoreContract {
    // ── Initialisation ────────────────────────────────────────────────────────

    /// Initialise the contract; can only be called once.
    ///
    /// * `admin`        — Address that may call privileged methods.
    /// * `relay_signer` — Address of the trusted off-chain relay that forwards
    ///                    Anchor Platform callbacks on-chain.
    pub fn initialize(
        env: Env,
        admin: Address,
        relay_signer: Address,
    ) -> Result<(), ContractError> {
        if StorageClient::is_initialised(&env) {
            return Err(ContractError::AlreadyInitialised);
        }
        StorageClient::set_admin(&env, &admin);
        StorageClient::set_relay_signer(&env, &relay_signer);
        // Start unpaused so a freshly deployed contract accepts callbacks.
        StorageClient::set_paused(&env, false);
        StorageClient::set_schema_version(&env, SCHEMA_VERSION);
        // Seed the idempotency-key TTL with the documented ~24h default.
        StorageClient::set_idempotency_ttl(&env, DEFAULT_IDEMPOTENCY_TTL_LEDGERS);
        StorageClient::set_initialised(&env);
        EventEmitter::initialised(&env, &admin, &relay_signer);
        Ok(())
    }

    // ── Admin: idempotency-key TTL ────────────────────────────────────────────

    /// Set the idempotency-key TTL, in ledgers.
    ///
    /// Only the admin may call this. `ttl_ledgers` must fall within
    /// [`MIN_IDEMPOTENCY_TTL_LEDGERS`]..=[`MAX_IDEMPOTENCY_TTL_LEDGERS`];
    /// out-of-bounds values are rejected with
    /// [`ContractError::InvalidIdempotencyTtl`] so the window cannot be
    /// misconfigured into something dangerously short or wastefully long.
    ///
    /// The new value applies to idempotency keys written **going forward only**;
    /// keys already written retain the TTL they were created with and are not
    /// retroactively extended or shortened.
    ///
    /// Emits [`events::IdempotencyTtlChanged`].
    pub fn set_idempotency_ttl(
        env: Env,
        caller: Address,
        ttl_ledgers: u32,
    ) -> Result<(), ContractError> {
        AdminClient::assert_is_admin(&env, &caller)?;

        if ttl_ledgers < MIN_IDEMPOTENCY_TTL_LEDGERS
            || ttl_ledgers > MAX_IDEMPOTENCY_TTL_LEDGERS
        {
            return Err(ContractError::InvalidIdempotencyTtl);
        }

        let old_ttl = StorageClient::get_idempotency_ttl(&env);
        StorageClient::set_idempotency_ttl(&env, ttl_ledgers);
        EventEmitter::idempotency_ttl_changed(&env, old_ttl, ttl_ledgers);

        Ok(())
    }

    /// Return the currently configured idempotency-key TTL, in ledgers.
    pub fn get_idempotency_ttl(env: Env) -> u32 {
        StorageClient::get_idempotency_ttl(&env)
    }

    // ── Callback ingestion (Phase 1 core) ─────────────────────────────────────

    /// Register a new anchor callback, persisting a [`Transaction`] with status
    /// [`TransactionStatus::Pending`].
    ///
    /// Called by the trusted `relay_signer` after the off-chain `synapse-core`
    /// service validates and deduplicates the raw Anchor Platform webhook.
    ///
    /// # Idempotency
    /// If `payload.idempotency_key` has been seen before within the retention
    /// window the call returns `Ok(existing_tx_id)` without writing — matching
    /// the Redis idempotency behaviour of the off-chain service.
    ///
    /// The idempotency key alone is not a durable enough guard: it lives in
    /// *temporary* storage with an admin-configurable TTL (default ~24h), so a
    /// late replay with a fresh `idempotency_key` but the same `transaction_id`
    /// would otherwise pass the check above and reach the write below. To
    /// prevent that write from silently overwriting an existing (possibly
    /// `Completed`/`Failed`) record, `transaction_id` reuse is also rejected
    /// independently of idempotency-key state (THREAT_MODEL.md finding F-07).
    ///
    /// # Events
    /// Emits [`events::TransactionRegistered`] on first write.
    pub fn register_callback(env: Env, payload: CallbackPayload) -> Result<String, ContractError> {
        // Circuit breaker: while the emergency pause is engaged we fail closed
        // and reject all new callback ingestion outright. This check is first so
        // ingestion is blocked regardless of caller. Read-only queries and
        // draining of already-registered work are intentionally left unguarded
        // (see the module docs on `pause`).
        if StorageClient::is_paused(&env) {
            return Err(ContractError::ContractPaused);
        }

        // Only the trusted relay signer may forward Anchor Platform callbacks.
        AdminClient::require_relay_quorum(&env, None)?;

        // Anchor allowlist: an empty allowlist means "all anchors" (backward
        // compatible default, weaker; tighten post-deployment). The anchor
        // identity is the payload's `asset_issuer`.
        let allowed = StorageClient::get_relay_anchors(&env, &relay);
        if !allowed.is_empty() && !allowed.contains(&payload.asset_issuer) {
            return Err(ContractError::AnchorNotAllowed);
        }

        // Quarantine: a signer with a stale heartbeat cannot take new intake.
        // Existing Pending/Processing work stays processable.
        AdminClient::assert_not_quarantined(&env, &relay)?;

        Validator::validate_payload(&env, &payload)?;

        // Idempotency: a replayed key returns the original tx id without a
        // second write, mirroring the off-chain Redis idempotency behaviour.
        if StorageClient::get_idempotency_key(&env, &payload.idempotency_key).is_some() {
            return Ok(payload.transaction_id.clone());
        }

        // Second-line guard (F-07): the idempotency key's TTL is much shorter
        // than a transaction record's, so a late replay past that window must
        // still not be allowed to overwrite an existing record under the same
        // transaction_id.
        if StorageClient::transaction_exists(&env, &payload.transaction_id) {
            return Err(ContractError::DuplicateRequest);
        }

        // Backpressure: bound this signer's outstanding Pending backlog.
        if let Some(cap) = StorageClient::get_max_pending_per_signer(&env) {
            if StorageClient::get_pending_count(&env, &relay) >= cap {
                return Err(ContractError::OutstandingCapExceeded);
            }
        }

        let ledger = env.ledger().sequence();
        let tx = Transaction {
            id: payload.transaction_id.clone(),
            stellar_account: payload.stellar_account.clone(),
            amount: payload.amount,
            asset_code: payload.asset_code.clone(),
            asset_issuer: payload.asset_issuer.clone(),
            status: TransactionStatus::Pending,
            created_at_ledger: ledger,
            updated_at_ledger: ledger,
            anchor_transaction_id: payload.anchor_transaction_id.clone(),
            callback_type: payload.callback_type.clone(),
            callback_status: payload.callback_status.clone(),
            stellar_tx_hash: String::from_str(&env, ""),
            failure_reason: String::from_str(&env, ""),
            registered_at: env.ledger().timestamp(),
            settled_amount: None,
            assigned_signer: None,
            tags: Vec::new(&env),
            retry_count: 0,
        };

        StorageClient::save_transaction(&env, &tx);
        // Use the admin-configured TTL for the temporary-tier idempotency key.
        StorageClient::set_idempotency_key(
            &env,
            &payload.idempotency_key,
            StorageClient::get_idempotency_ttl(&env),
        );
        StorageClient::append_history(&env, &tx.id, TransactionStatus::Pending, &relay);
        StorageClient::inc_pending(&env, &relay, &tx.id);
        EventEmitter::transaction_registered(&env, &tx);

        Ok(tx.id)
    }

    // ── Storage maintenance ───────────────────────────────────────────────────

    /// Extend the persistent-storage TTL of a single transaction record.
    ///
    /// Persistent entries are subject to ledger rent and are archived once
    /// their TTL lapses. Records that remain operationally relevant (e.g. still
    /// `Disputed`, or high-value transactions worth retaining for a longer audit
    /// trail) can be kept live by periodically invoking this entry point from an
    /// off-chain maintenance job (see `DEPLOYMENT.md`).
    ///
    /// Uses Soroban's native `extend_ttl` ledger primitive directly rather than
    /// reimplementing TTL bookkeeping in contract storage.
    ///
    /// # Authorisation
    /// Restricted to the configured `admin` or `relay_signer`.
    ///
    /// # Errors
    /// * [`ContractError::TransactionNotFound`] — no record exists for `tx_id`.
    pub fn bump_transaction_ttl(
        env: Env,
        tx_id: String,
        caller: Address,
    ) -> Result<(), ContractError> {
        AdminClient::assert_is_relay_or_admin(&env, &caller)?;

        // Fail cleanly on a nonexistent record rather than extending the TTL of
        // an empty ledger entry.
        if !StorageClient::transaction_exists(&env, &tx_id) {
            return Err(ContractError::TransactionNotFound);
        }

        StorageClient::extend_transaction_ttl(&env, &tx_id);
        Ok(())
    }

    /// Extend the persistent-storage TTL of many transaction records in one pass.
    ///
    /// Intended for a scheduled off-chain maintenance job that walks a batch of
    /// still-relevant records (see `DEPLOYMENT.md`). The number of records
    /// processed per call is bounded by [`MAX_TTL_BUMP_BATCH`]; passing more
    /// than that returns [`ContractError::BatchTooLarge`] so the caller must
    /// chunk its work explicitly rather than have the batch silently truncated.
    ///
    /// Returns the number of records whose TTL was extended. If any `tx_id` in
    /// the batch does not exist the call fails with
    /// [`ContractError::TransactionNotFound`] and no partial state is committed,
    /// so the caller can retry the corrected batch.
    ///
    /// # Authorisation
    /// Restricted to the configured `admin` or `relay_signer`.
    pub fn bump_transaction_ttl_batch(
        env: Env,
        tx_ids: Vec<String>,
        caller: Address,
    ) -> Result<u32, ContractError> {
        AdminClient::assert_is_relay_or_admin(&env, &caller)?;

        let count = tx_ids.len();
        if count > MAX_TTL_BUMP_BATCH {
            return Err(ContractError::BatchTooLarge);
        }

        // Validate the whole batch before mutating anything so a bad entry
        // cannot leave the batch half-applied.
        for tx_id in tx_ids.iter() {
            if !StorageClient::transaction_exists(&env, &tx_id) {
                return Err(ContractError::TransactionNotFound);
            }
        }

        for tx_id in tx_ids.iter() {
            StorageClient::extend_transaction_ttl(&env, &tx_id);
        }

        Ok(count)
    }

    /// Register up to [`MAX_BATCH_SIZE`] callbacks atomically.
    ///
    /// Relay signer only. Every payload is validated, and checked against
    /// on-chain and in-batch duplicate `transaction_id`s, *before* any storage
    /// write; any failure aborts the whole call with no partial writes.
    /// An empty or oversized batch is rejected with
    /// [`ContractError::InvalidBatchSize`].
    ///
    /// # Events
    /// Emits [`events::EventTransactionRegistered`] per payload followed by one
    /// [`events::EventBatchProcessed`].
    pub fn batch_register_callback(
        env: Env,
        payloads: Vec<CallbackPayload>,
        caller: Address,
    ) -> Result<u32, ContractError> {
        if StorageClient::is_paused(&env) {
            return Err(ContractError::ContractPaused);
        }
        AdminClient::require_relay_signer(&env, &caller)?;
        caller.require_auth();

        let n = payloads.len();
        if n == 0 || n > MAX_BATCH_SIZE {
            return Err(ContractError::InvalidBatchSize);
        }

        // Pass 1: validate everything; no writes.
        for i in 0..n {
            let p = payloads.get_unchecked(i);
            Validator::validate_payload(&env, &p)?;
            if StorageClient::transaction_exists(&env, &p.transaction_id) {
                return Err(ContractError::DuplicateRequest);
            }
            for j in 0..i {
                if payloads.get_unchecked(j).transaction_id == p.transaction_id {
                    return Err(ContractError::DuplicateRequest);
                }
            }
        }

        // Pass 2: write.
        let ledger = env.ledger().sequence();
        for p in payloads.iter() {
            let tx = Transaction {
                id: p.transaction_id.clone(),
                stellar_account: p.stellar_account.clone(),
                amount: p.amount,
                asset_code: p.asset_code.clone(),
                asset_issuer: p.asset_issuer.clone(),
                status: TransactionStatus::Pending,
                created_at_ledger: ledger,
                updated_at_ledger: ledger,
                anchor_transaction_id: p.anchor_transaction_id.clone(),
                callback_type: p.callback_type.clone(),
                callback_status: p.callback_status.clone(),
                stellar_tx_hash: String::from_str(&env, ""),
                failure_reason: String::from_str(&env, ""),
                retry_count: 0,
            };
            StorageClient::save_transaction(&env, &tx);
            StorageClient::set_idempotency_key(&env, &p.idempotency_key);
            EventEmitter::transaction_registered(&env, &tx);
        }
        EventEmitter::batch_processed(&env, n, &caller);

        Ok(n)
    }
    }

    // ── Status transitions ────────────────────────────────────────────────────

    /// Mark a `Pending` transaction as `Processing`.
    ///
    /// Called by the relay when the off-chain processor picks up the job.
    /// Enforces the state machine: only `Pending → Processing` is valid here.
    pub fn start_processing(env: Env, tx_id: String, caller: Address) -> Result<(), ContractError> {
        AdminClient::require_scope(&env, &caller, RoleScope::StartProcessing)?;

        let mut tx = StorageClient::get_transaction(&env, &tx_id)?;
        if tx.status != TransactionStatus::Pending {
            return Err(ContractError::InvalidStatusTransition);
        }
        let old_status = tx.status.clone();
        tx.status = TransactionStatus::Processing;
        tx.updated_at_ledger = env.ledger().sequence();

        StorageClient::save_transaction(&env, &tx);
        StorageClient::append_history(&env, &tx_id, TransactionStatus::Processing, &caller);
        StorageClient::dec_pending(&env, &tx_id);
        EventEmitter::status_changed(&env, &tx_id, old_status, TransactionStatus::Processing);

        Ok(())
    }

    /// Mark a `Processing` transaction as `Completed` after on-chain verification.
    ///
    /// `stellar_tx_hash` — the Stellar transaction hash confirming the deposit
    ///                     was settled on Horizon. Stored for auditability.
    pub fn complete_transaction(
        env: Env,
        tx_id: String,
        stellar_tx_hash: String,
        caller: Address,
    ) -> Result<(), ContractError> {
        AdminClient::require_scope(&env, &caller, RoleScope::CompleteTransaction)?;
        Validator::validate_stellar_tx_hash(&env, &stellar_tx_hash)?;

        let mut tx = StorageClient::get_transaction(&env, &tx_id)?;
        AdminClient::assert_can_drive_tx(&env, &caller, &tx.assigned_signer)?;
        if tx.status != TransactionStatus::Processing {
            return Err(ContractError::InvalidStatusTransition);
        }
        let old_status = tx.status.clone();
        tx.status = TransactionStatus::Completed;
        tx.stellar_tx_hash = stellar_tx_hash;
        tx.updated_at_ledger = env.ledger().sequence();

        StorageClient::save_transaction(&env, &tx);
        StorageClient::append_history(&env, &tx_id, TransactionStatus::Completed, &caller);
        EventEmitter::status_changed(&env, &tx_id, old_status, TransactionStatus::Completed);
        EventEmitter::transaction_completed(&env, &tx_id, &stellar_tx_hash);
        // Additive phase-router hook: only when a route is configured.
        if let Some(next_phase) = StorageClient::get_forward_route(&env, &tx_id) {
            if next_phase != 0 {
                EventEmitter::forwarding_intent(&env, &tx_id, next_phase);
            }
        }

        Ok(())
    }

    /// Mark a `Processing` transaction as `Failed`, recording the reason.
    pub fn fail_transaction(
        env: Env,
        tx_id: String,
        reason: String,
        caller: Address,
    ) -> Result<(), ContractError> {
        AdminClient::assert_is_relay_or_admin(&env, &caller)?;

        let mut tx = StorageClient::get_transaction(&env, &tx_id)?;
        if tx.status != TransactionStatus::Processing {
            return Err(ContractError::InvalidStatusTransition);
        }
        let old_status = tx.status.clone();
        tx.status = TransactionStatus::Failed;
        tx.failure_reason = reason;
        tx.updated_at_ledger = env.ledger().sequence();

        StorageClient::save_transaction(&env, &tx);
        EventEmitter::status_changed(&env, &tx_id, old_status, TransactionStatus::Failed);

        Ok(())
    }

    // ── Read-only queries ─────────────────────────────────────────────────────

    /// Fetch a transaction by id.
    pub fn get_transaction(env: Env, tx_id: String) -> Result<Transaction, ContractError> {
        StorageClient::get_transaction(&env, &tx_id)
    }

    /// Return the current schema version stored at initialisation.
    pub fn schema_version(env: Env) -> u32 {
        StorageClient::get_schema_version(&env)
    }

    /// Return whether the emergency pause is currently engaged.
    pub fn is_paused(env: Env) -> bool {
        StorageClient::is_paused(&env)
    }

    // ── Admin: pause / unpause ────────────────────────────────────────────────

    /// Engage the emergency pause (admin only).
    pub fn pause(env: Env, caller: Address) -> Result<(), ContractError> {
        AdminClient::assert_is_admin(&env, &caller)?;
        StorageClient::set_paused(&env, true);
        EventEmitter::paused(&env, &caller);
        Ok(())
    }

    /// Disengage the emergency pause (admin only).
    pub fn unpause(env: Env, caller: Address) -> Result<(), ContractError> {
        AdminClient::assert_is_admin(&env, &caller)?;
        StorageClient::set_paused(&env, false);
        EventEmitter::unpaused(&env, &caller);
        Ok(())
    }

    // ── Admin: relay signer rotation ──────────────────────────────────────────

    /// Rotate the trusted relay signer (admin only).
    pub fn set_relay_signer(
        env: Env,
        caller: Address,
        new_relay_signer: Address,
    ) -> Result<(), ContractError> {
        AdminClient::assert_is_admin(&env, &caller)?;
        StorageClient::set_relay_signer(&env, &new_relay_signer);
        EventEmitter::relay_signer_changed(&env, &new_relay_signer);
        Ok(())
    }

    // ── Admin: ownership transfer ─────────────────────────────────────────────

    /// Transfer admin ownership to `new_admin` (admin only).
    pub fn transfer_admin(
        env: Env,
        caller: Address,
        new_admin: Address,
    ) -> Result<(), ContractError> {
        AdminClient::assert_is_admin(&env, &caller)?;
        StorageClient::set_admin(&env, &new_admin);
        EventEmitter::admin_transferred(&env, &caller, &new_admin);
        Ok(())
    }
}
