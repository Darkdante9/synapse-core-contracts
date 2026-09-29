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
mod test_recovery;
#[cfg(test)]
mod tests;

use soroban_sdk::{contract, contractimpl, Address, BytesN, Env, String, Vec};

use crate::admin::AdminClient;
use crate::events::EventEmitter;
use crate::storage::StorageClient;
use crate::types::{
    CallbackPayload, ContractError, PendingRelaySigner, RelaySignerSet, Transaction, TransactionStatus, MAX_BATCH_SIZE, MAX_PAGE_LIMIT, MAX_RETRIES, DEFAULT_RELAY_SIGNER_DELAY_LEDGERS, SCHEMA_VERSION,
};
use crate::validation::Validator;

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
        StorageClient::set_initialised(&env);
        EventEmitter::initialised(&env, &admin, &relay_signer);
        Ok(())
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
    /// *temporary* storage with a ~24h TTL, so a late replay with a fresh
    /// `idempotency_key` but the same `transaction_id` would otherwise pass
    /// the check above and reach the write below. To prevent that write from
    /// silently overwriting an existing (possibly `Completed`/`Failed`)
    /// record, `transaction_id` reuse is also rejected independently of
    /// idempotency-key state (THREAT_MODEL.md finding F-07).
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
        StorageClient::set_idempotency_key(&env, &payload.idempotency_key);
        StorageClient::append_history(&env, &tx.id, TransactionStatus::Pending, &relay);
        StorageClient::inc_pending(&env, &relay, &tx.id);
        EventEmitter::transaction_registered(&env, &tx);

        Ok(tx.id)
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

    // ── Status transitions ────────────────────────────────────────────────────

    /// Mark a `Pending` transaction as `Processing`.
    ///
    /// Called by the relay when the off-chain processor picks up the job.
    /// Enforces the state machine: only `Pending → Processing` is valid here.
    pub fn start_processing(env: Env, tx_id: String, caller: Address) -> Result<(), ContractError> {
        AdminClient::assert_is_relay_or_admin(&env, &caller)?;

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
        Validator::validate_stellar_tx_hash(&stellar_tx_hash)?;

        let mut tx = StorageClient::get_transaction(&env, &tx_id)?;
        AdminClient::assert_can_drive_tx(&env, &caller, &tx.assigned_signer)?;
        if tx.status != TransactionStatus::Processing {
            return Err(ContractError::InvalidStatusTransition);
        }
        let old_status = tx.status.clone();
        tx.status = TransactionStatus::Completed;
        tx.stellar_tx_hash = stellar_tx_hash.clone();
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

    /// Mark a `Processing` transaction as `Completed` with a settled amount
    /// strictly between zero and the originally registered amount.
    ///
    /// Purely a recording mechanism: the shortfall is not refunded or fee'd
    /// here. `complete_transaction` remains the full-amount path.
    ///
    /// # Events
    /// Emits [`events::EventStatusChanged`] then
    /// [`events::EventTransactionPartiallyCompleted`].
    pub fn partial_complete_transaction(
        env: Env,
        tx_id: String,
        settled_amount: i128,
        stellar_tx_hash: String,
        caller: Address,
    ) -> Result<(), ContractError> {
        Validator::validate_stellar_tx_hash(&stellar_tx_hash)?;

        let mut tx = StorageClient::get_transaction(&env, &tx_id)?;
        AdminClient::assert_can_drive_tx(&env, &caller, &tx.assigned_signer)?;
        if tx.status != TransactionStatus::Processing {
            return Err(ContractError::InvalidStatusTransition);
        }
        Validator::validate_settled_amount(settled_amount, tx.amount)?;
        let old_status = tx.status.clone();
        tx.status = TransactionStatus::Completed;
        tx.stellar_tx_hash = stellar_tx_hash.clone();
        tx.settled_amount = Some(settled_amount);
        tx.updated_at_ledger = env.ledger().sequence();

        StorageClient::save_transaction(&env, &tx);
        EventEmitter::status_changed(&env, &tx_id, old_status, TransactionStatus::Completed);
        EventEmitter::transaction_partially_completed(
            &env,
            &tx_id,
            tx.amount,
            settled_amount,
            &stellar_tx_hash,
        );
        Ok(())
    }

    /// Approve a standby relay signer that in-flight transactions may be
    /// reassigned to. Admin-gated.
    ///
    /// TODO: superseded by the N-of-M relay-signer set once that lands.
    pub fn set_standby_signer(env: Env, signer: Address) -> Result<(), ContractError> {
        AdminClient::require_admin(&env)?;
        StorageClient::set_standby_signer(&env, &signer);
        EventEmitter::standby_signer_set(&env, &signer);
        Ok(())
    }

    /// Rebind one in-flight (`Pending`/`Processing`) transaction's
    /// authorization to `new_signer`. Admin-gated recovery path for a revoked
    /// or compromised signer; does not touch global relay-signer state.
    ///
    /// `new_signer` must be the current relay signer or the admin-approved
    /// standby (TODO: gate on the signer set once it exists).
    ///
    /// # Errors
    /// - [`ContractError::InvalidStatusTransition`] if the transaction is terminal.
    /// - [`ContractError::SignerNotTrusted`] if `new_signer` is not trusted.
    ///
    /// # Events
    /// Emits [`events::EventTransactionReassigned`].
    pub fn reassign_relay_signer_for_transaction(
        env: Env,
        tx_id: String,
        new_signer: Address,
        caller: Address,
    ) -> Result<(), ContractError> {
        let admin = StorageClient::get_admin(&env)?;
        if caller != admin {
            return Err(ContractError::Unauthorised);
        }
        caller.require_auth();

        let mut tx = StorageClient::get_transaction(&env, &tx_id)?;
        if tx.status != TransactionStatus::Pending && tx.status != TransactionStatus::Processing {
            return Err(ContractError::InvalidStatusTransition);
        }
        let relay = StorageClient::get_relay_signer(&env)?;
        let standby = StorageClient::get_standby_signer(&env);
        if new_signer != relay && standby.as_ref() != Some(&new_signer) {
            return Err(ContractError::SignerNotTrusted);
        }
        let old_signer = tx.assigned_signer.clone().unwrap_or(relay);
        tx.assigned_signer = Some(new_signer.clone());
        tx.updated_at_ledger = env.ledger().sequence();

        StorageClient::save_transaction(&env, &tx);
        EventEmitter::transaction_reassigned(&env, &tx_id, &old_signer, &new_signer);
        Ok(())
    }

    /// Append an operational tag to a transaction. Admin or relay signer.
    ///
    /// Append-only; count and per-tag length are capped in `validation.rs`.
    ///
    /// # Errors
    /// - [`ContractError::TransactionNotFound`] for an unknown `tx_id`.
    /// - [`ContractError::TooManyTags`] once the per-transaction cap is hit.
    /// - [`ContractError::StringTooLong`] / [`ContractError::EmptyTag`] for a bad tag.
    ///
    /// # Events
    /// Emits [`events::EventTransactionTagged`].
    pub fn add_transaction_tag(
        env: Env,
        tx_id: String,
        tag: String,
        caller: Address,
    ) -> Result<(), ContractError> {
        AdminClient::assert_is_relay_or_admin(&env, &caller)?;
        let mut tx = StorageClient::get_transaction(&env, &tx_id)?;
        Validator::validate_tag(&tag, tx.tags.len())?;
        tx.tags.push_back(tag.clone());

        StorageClient::save_transaction(&env, &tx);
        EventEmitter::transaction_tagged(&env, &tx_id, &tag, tx.tags.len());
        Ok(())
    }

    /// Mark a `Pending` or `Processing` transaction as `Failed`.
    ///
    /// `reason` — short human-readable failure code (e.g. "horizon_timeout",
    ///            "invalid_account", "circuit_open").
    pub fn fail_transaction(
        env: Env,
        tx_id: String,
        reason: String,
        caller: Address,
    ) -> Result<(), ContractError> {
        AdminClient::assert_is_relay_or_admin(&env, &caller)?;
        Validator::validate_failure_reason(&reason)?;

        let mut tx = StorageClient::get_transaction(&env, &tx_id)?;
        if tx.status != TransactionStatus::Pending && tx.status != TransactionStatus::Processing {
            return Err(ContractError::InvalidStatusTransition);
        }
        let old_status = tx.status.clone();
        tx.status = TransactionStatus::Failed;
        tx.failure_reason = reason.clone();
        tx.updated_at_ledger = env.ledger().sequence();

        StorageClient::save_transaction(&env, &tx);
        StorageClient::append_history(&env, &tx_id, TransactionStatus::Failed, &caller);
        if old_status == TransactionStatus::Pending {
            StorageClient::dec_pending(&env, &tx_id);
        }
        EventEmitter::status_changed(&env, &tx_id, old_status, TransactionStatus::Failed);
        EventEmitter::transaction_failed(&env, &tx_id, &reason);

        Ok(())
    }

    /// **Break-glass admin recovery** (not a routine operation): link
    /// `duplicate_tx_id` to its canonical original after a replay slipped
    /// through as a separate `transaction_id`.
    ///
    /// The duplicate is never deleted: its data stays queryable, it gets a
    /// `MergedInto(canonical_tx_id)` marker (see [`Self::get_merged_into`]),
    /// and its record is moved to `Failed` with `failure_reason = "merged"`
    /// so `get_transaction` cannot pass for an active record. `reason` is
    /// the evidence-backed justification and is carried in the event.
    ///
    /// # Errors
    /// - [`ContractError::MergeSelf`] if both ids are equal.
    /// - [`ContractError::AlreadyMerged`] if either side is already merged.
    /// - [`ContractError::DuplicateSettled`] if the duplicate is `Completed`.
    /// - [`ContractError::TransactionNotFound`] if either record is missing.
    ///
    /// # Events
    /// Emits [`events::EventTransactionsMerged`].
    pub fn merge_duplicate_transactions(
        env: Env,
        canonical_tx_id: String,
        duplicate_tx_id: String,
        caller: Address,
        reason: String,
    ) -> Result<(), ContractError> {
        let admin = AdminClient::require_admin(&env)?;
        if caller != admin {
            return Err(ContractError::Unauthorised);
        }
        if canonical_tx_id == duplicate_tx_id {
            return Err(ContractError::MergeSelf);
        }
        Validator::validate_failure_reason(&reason)?;
        StorageClient::get_transaction(&env, &canonical_tx_id)?;
        let mut dup = StorageClient::get_transaction(&env, &duplicate_tx_id)?;
        if StorageClient::get_merged_into(&env, &duplicate_tx_id).is_some()
            || StorageClient::get_merged_into(&env, &canonical_tx_id).is_some()
        {
            return Err(ContractError::AlreadyMerged);
        }
        if dup.status == TransactionStatus::Completed {
            return Err(ContractError::DuplicateSettled);
        }
        dup.status = TransactionStatus::Failed;
        dup.failure_reason = String::from_str(&env, "merged");
        dup.updated_at_ledger = env.ledger().sequence();
        StorageClient::save_transaction(&env, &dup);
        StorageClient::set_merged_into(&env, &duplicate_tx_id, &canonical_tx_id);
        EventEmitter::transactions_merged(&env, &canonical_tx_id, &duplicate_tx_id, &admin, &reason);
        Ok(())
    }

    /// Configure the phase-router forwarding route for `tx_id`. Admin-gated.
    ///
    /// `next_phase == 0` clears the route (the default: no forwarding).
    /// When set, `complete_transaction` emits `EventForwardingIntent` after
    /// the `status`/`done` events. Never performs a cross-contract call.
    pub fn set_forwarding_route(
        env: Env,
        tx_id: String,
        next_phase: u32,
    ) -> Result<(), ContractError> {
        AdminClient::require_admin(&env)?;
        StorageClient::set_forward_route(
            &env,
            &tx_id,
            if next_phase == 0 { None } else { Some(next_phase) },
        );
        Ok(())
    }

    /// Return the configured forwarding `next_phase` for `tx_id`, or `None`.
    pub fn get_forwarding_route(env: Env, tx_id: String) -> Option<u32> {
        StorageClient::get_forward_route(&env, &tx_id)
    }

    // ── Disputes ──────────────────────────────────────────────────────────────

    /// Freeze a `Completed` transaction pending review.
    ///
    /// Disputed is an overlay flag; the stored status stays `Completed` so
    /// nothing is lost. Callable by the relay signer or admin.
    ///
    /// # Errors
    /// - [`ContractError::InvalidStatusTransition`] if not `Completed`.
    /// - [`ContractError::AlreadyDisputed`] if already disputed.
    pub fn dispute_transaction(
        env: Env,
        tx_id: String,
        caller: Address,
    ) -> Result<(), ContractError> {
        AdminClient::assert_is_relay_or_admin(&env, &caller)?;
        let tx = StorageClient::get_transaction(&env, &tx_id)?;
        if tx.status != TransactionStatus::Completed {
            return Err(ContractError::InvalidStatusTransition);
        }
        if StorageClient::is_disputed(&env, &tx_id) {
            return Err(ContractError::AlreadyDisputed);
        }
        StorageClient::set_disputed(&env, &tx_id, true);
        Ok(())
    }

    /// Resolve a dispute. **Admin only** — unlike every other lifecycle
    /// action this is deliberately NOT relay-signer-eligible.
    ///
    /// If `upheld`, the transaction moves `Completed -> Failed` with reason
    /// `dispute_upheld`; otherwise the flag is cleared and the transaction
    /// is exactly as it was (`Completed`).
    pub fn resolve_dispute(env: Env, tx_id: String, upheld: bool) -> Result<(), ContractError> {
        let admin = AdminClient::require_admin(&env)?;
        let mut tx = StorageClient::get_transaction(&env, &tx_id)?;
        if !StorageClient::is_disputed(&env, &tx_id) {
            return Err(ContractError::NotDisputed);
        }
        StorageClient::set_disputed(&env, &tx_id, false);
        if upheld {
            let old_status = tx.status.clone();
            tx.status = TransactionStatus::Failed;
            tx.failure_reason = String::from_str(&env, "dispute_upheld");
            tx.updated_at_ledger = env.ledger().sequence();
            StorageClient::save_transaction(&env, &tx);
            StorageClient::append_history(&env, &tx_id, TransactionStatus::Failed, &admin);
            EventEmitter::status_changed(&env, &tx_id, old_status, TransactionStatus::Failed);
        }
        Ok(())
    }

    /// Whether `tx_id` is currently under dispute.
    pub fn is_disputed(env: Env, tx_id: String) -> bool {
        StorageClient::is_disputed(&env, &tx_id)
    }

    /// Set the maximum age (seconds) a `Pending` transaction may reach before
    /// anyone can expire it. Admin-gated. `0` is rejected as invalid.
    pub fn set_expiry_window(env: Env, seconds: u64) -> Result<(), ContractError> {
        AdminClient::require_admin(&env)?;
        if seconds == 0 {
            return Err(ContractError::InvalidAmount);
        }
        StorageClient::set_expiry_window(&env, seconds);
        EventEmitter::expiry_window_set(&env, seconds);
        Ok(())
    }

    /// Return the configured `Pending` expiry window in seconds, if any.
    pub fn expiry_window(env: Env) -> Option<u64> {
        StorageClient::get_expiry_window(&env)
    }

    /// Move a stale `Pending` transaction to terminal `Expired`.
    ///
    /// Deliberately **permissionless** (no auth): expiry is a pure function of
    /// ledger time versus the admin-configured window, so anyone may trigger
    /// it and no privileged off-chain scheduler is needed. Only `Pending`
    /// transactions can expire; `Processing` implies active relay engagement.
    ///
    /// # Errors
    /// - [`ContractError::ExpiryNotConfigured`] if no window is set.
    /// - [`ContractError::InvalidStatusTransition`] if not `Pending`.
    /// - [`ContractError::ExpiryNotElapsed`] if `now < registered_at + window`.
    pub fn expire_transaction(env: Env, tx_id: String) -> Result<(), ContractError> {
        let window =
            StorageClient::get_expiry_window(&env).ok_or(ContractError::ExpiryNotConfigured)?;
        let mut tx = StorageClient::get_transaction(&env, &tx_id)?;
        if tx.status != TransactionStatus::Pending {
            return Err(ContractError::InvalidStatusTransition);
        }
        let deadline = tx.registered_at.saturating_add(window);
        if env.ledger().timestamp() < deadline {
            return Err(ContractError::ExpiryNotElapsed);
        }
        let old_status = tx.status.clone();
        tx.status = TransactionStatus::Expired;
        tx.updated_at_ledger = env.ledger().sequence();

        StorageClient::save_transaction(&env, &tx);
        EventEmitter::status_changed(&env, &tx_id, old_status, TransactionStatus::Expired);
        EventEmitter::transaction_expired(&env, &tx_id, tx.registered_at);

        Ok(())
    }

    /// Cancel a `Pending` or `Processing` transaction (terminal `Cancelled`).
    ///
    /// Callable only by the admin or the relay signer. `Completed` and
    /// `Failed` records are rejected with [`ContractError::CannotCancel`];
    /// an already-`Cancelled` record with [`ContractError::AlreadyCancelled`].
    ///
    /// # Events
    /// Emits [`events::EventStatusChanged`] and
    /// [`events::EventTransactionCancelled`].
    pub fn cancel_transaction(
        env: Env,
        tx_id: String,
        reason: String,
        caller: Address,
    ) -> Result<(), ContractError> {
        AdminClient::assert_is_relay_or_admin(&env, &caller)?;
        Validator::validate_failure_reason(&reason)?;

        let mut tx = StorageClient::get_transaction(&env, &tx_id)?;
        match tx.status {
            TransactionStatus::Pending | TransactionStatus::Processing => {}
            TransactionStatus::Cancelled => return Err(ContractError::AlreadyCancelled),
            _ => return Err(ContractError::CannotCancel),
        }
        let old_status = tx.status.clone();
        tx.status = TransactionStatus::Cancelled;
        tx.failure_reason = reason.clone();
        tx.updated_at_ledger = env.ledger().sequence();

        StorageClient::save_transaction(&env, &tx);
        EventEmitter::status_changed(&env, &tx_id, old_status, TransactionStatus::Cancelled);
        EventEmitter::transaction_cancelled(&env, &tx_id, &reason, &caller);

        Ok(())
    }

    /// Move a `Failed` transaction back to `Pending` for reprocessing.
    ///
    /// Relay or admin only. Each call increments [`Transaction::retry_count`];
    /// once it reaches [`MAX_RETRIES`] further calls fail with
    /// [`ContractError::RetryLimitExceeded`]. The counter lives on the
    /// persistent record, so it survives contract upgrades.
    ///
    /// # Events
    /// Emits [`events::EventStatusChanged`] and
    /// [`events::EventTransactionRetried`].
    pub fn retry_transaction(env: Env, tx_id: String, caller: Address) -> Result<(), ContractError> {
        AdminClient::assert_is_relay_or_admin(&env, &caller)?;

        let mut tx = StorageClient::get_transaction(&env, &tx_id)?;
        if tx.status != TransactionStatus::Failed {
            return Err(ContractError::InvalidStatusTransition);
        }
        if tx.retry_count >= MAX_RETRIES {
            return Err(ContractError::RetryLimitExceeded);
        }
        tx.retry_count += 1;
        tx.status = TransactionStatus::Pending;
        tx.failure_reason = String::from_str(&env, "");
        tx.updated_at_ledger = env.ledger().sequence();

        StorageClient::save_transaction(&env, &tx);
        EventEmitter::status_changed(
            &env,
            &tx_id,
            TransactionStatus::Failed,
            TransactionStatus::Pending,
        );
        EventEmitter::transaction_retried(&env, &tx_id, tx.retry_count);

        Ok(())
    }
    }

    // ── Read-only queries ─────────────────────────────────────────────────────

    /// Return the [`Transaction`] for the given `tx_id`, or
    /// [`ContractError::TransactionNotFound`].
    pub fn get_transaction(env: Env, tx_id: String) -> Result<Transaction, ContractError> {
        // Read-only: intentionally NOT gated by the pause flag — pausing must
        // never brick reads.
        StorageClient::get_transaction(&env, &tx_id)
    }

    /// Return a page of transaction IDs currently in `status`, in
    /// registration-into-status order.
    ///
    /// * `cursor` — zero-based offset; pass `0` for the first page, then the
    ///   previous `cursor + returned.len()`. An empty page means the end.
    /// * `limit`  — page size, `1..=MAX_PAGE_LIMIT` (else
    ///   [`ContractError::InvalidPageLimit`]).
    ///
    /// Read-only and not gated by the pause flag.
    pub fn get_transactions_by_status(
        env: Env,
        status: TransactionStatus,
        cursor: u32,
        limit: u32,
    ) -> Result<Vec<String>, ContractError> {
        if limit == 0 || limit > MAX_PAGE_LIMIT {
            return Err(ContractError::InvalidPageLimit);
        }
        Ok(StorageClient::get_ids_by_status(&env, &status, cursor, limit))
    }

    /// Return the current [`TransactionStatus`] without fetching the full record.
    pub fn get_status(env: Env, tx_id: String) -> Result<TransactionStatus, ContractError> {
        StorageClient::get_transaction(&env, &tx_id).map(|tx| tx.status)
    }

    /// Return the canonical tx id `tx_id` was merged into by
    /// [`Self::merge_duplicate_transactions`], or `None` if not merged.
    pub fn get_merged_into(env: Env, tx_id: String) -> Option<String> {
        StorageClient::get_merged_into(&env, &tx_id)
    }

    /// Return the append-only transition history of `tx_id`, oldest first.
    ///
    /// Holds at most [`types::MAX_HISTORY_LEN`] entries (oldest evicted first).
    /// Transactions registered before this feature have no history.
    pub fn get_transaction_history(env: Env, tx_id: String) -> Vec<TransitionRecord> {
        StorageClient::get_history(&env, &tx_id)
    }
    }

    /// Check whether an idempotency key has already been processed.
    pub fn is_duplicate(env: Env, idempotency_key: String) -> bool {
        StorageClient::get_idempotency_key(&env, &idempotency_key).is_some()
    }

    /// Return the current admin address, or [`ContractError::NotInitialised`].
    ///
    /// Read-only: lets off-chain monitoring and deployment tooling verify the
    /// on-chain admin against the value recorded in `contract-ids.json`
    /// without needing to trust that record alone.
    pub fn admin(env: Env) -> Result<Address, ContractError> {
        StorageClient::get_admin(&env)
    }

    /// Return the current trusted relay signer address, or
    /// [`ContractError::NotInitialised`].
    pub fn relay_signer(env: Env) -> Result<Address, ContractError> {
        StorageClient::get_relay_signer(&env)
    }

    /// Return the current on-chain storage schema version, or
    /// [`ContractError::NotInitialised`]. The value `upgrade()` requires
    /// callers to pass as `expected_schema_version`.
    pub fn schema_version(env: Env) -> Result<u32, ContractError> {
        StorageClient::get_schema_version(&env)
    }

    /// Return the pending admin nominee, if an admin transfer is in
    /// progress. `None` once accepted or if none was ever proposed.
    pub fn pending_admin(env: Env) -> Option<Address> {
        StorageClient::get_pending_admin(&env)
    }

    // ── Admin (two-step transfer) ────────────────────────────────────────────

    /// Nominate `new_admin` as the next admin.  Requires existing admin auth.
    ///
    /// The transfer does not take effect here — it only completes once
    /// `new_admin` itself calls [`Self::accept_admin`], proving it controls
    /// the corresponding key. A single call from the current admin can no
    /// longer finalise a transfer on its own (THREAT_MODEL.md finding F-03),
    /// which also rules out the classic mis-typed-address failure mode: a
    /// wrong address can never accept, so the current admin simply stays in
    /// control and can propose again.
    ///
    /// Rejects nominating the contract's own address (F-02) — see
    /// [`Validator::validate_admin_nominee`] for why that is the only
    /// "invalid address" Soroban lets this check for on-chain.
    ///
    /// # Events
    /// Emits [`events::EventAdminTransferProposed`].
    pub fn propose_admin(env: Env, new_admin: Address) -> Result<(), ContractError> {
        let current_admin = AdminClient::require_admin(&env)?;
        Validator::validate_admin_nominee(&env, &new_admin)?;
        StorageClient::set_pending_admin(&env, &new_admin);
        EventEmitter::admin_transfer_proposed(&env, &current_admin, &new_admin);
        Ok(())
    }

    /// Complete a pending admin transfer nominated via [`Self::propose_admin`].
    ///
    /// `caller` must be the pending nominee; the call requires `caller`'s own
    /// auth, which is what proves key control and finalises the transfer.
    ///
    /// # Errors
    /// - [`ContractError::NoPendingAdminTransfer`] if no transfer is pending.
    /// - [`ContractError::Unauthorised`] if `caller` is not the pending nominee.
    ///
    /// # Events
    /// Emits [`events::EventAdminTransferred`].
    pub fn accept_admin(env: Env, caller: Address) -> Result<(), ContractError> {
        let pending =
            StorageClient::get_pending_admin(&env).ok_or(ContractError::NoPendingAdminTransfer)?;
        if caller != pending {
            return Err(ContractError::Unauthorised);
        }
        caller.require_auth();

        let old_admin = StorageClient::get_admin(&env)?;
        StorageClient::set_admin(&env, &caller);
        StorageClient::clear_pending_admin(&env);
        EventEmitter::admin_transferred(&env, &old_admin, &caller);
        Ok(())
    }

    /// Set the maximum outstanding `Pending` transactions any single relay
    /// signer may hold. Admin-gated. `register_callback` fails with
    /// [`ContractError::OutstandingCapExceeded`] once a signer is at the cap.
    /// Lowering the cap never affects already-registered transactions.
    pub fn set_max_outstanding_pending_per_signer(
        env: Env,
        cap: u32,
    ) -> Result<(), ContractError> {
        AdminClient::require_admin(&env)?;
        StorageClient::set_max_pending_per_signer(&env, cap);
        Ok(())
    }

    /// Return the outstanding `Pending` count for `signer`.
    pub fn outstanding_pending(env: Env, signer: Address) -> u32 {
        StorageClient::get_pending_count(&env, &signer)
    }

    /// Set the max registerable amount for an anchor (identified by the
    /// payload's `asset_issuer`). Admin-gated. Applies to future
    /// registrations only; existing transactions are unaffected.
    pub fn set_anchor_amount_ceiling(
        env: Env,
        anchor: String,
        ceiling: i128,
    ) -> Result<(), ContractError> {
        AdminClient::require_admin(&env)?;
        Validator::validate_amount(ceiling)?;
        StorageClient::set_anchor_ceiling(&env, &anchor, ceiling);
        Ok(())
    }

    /// Set the default ceiling for anchors with no explicit entry (initially
    /// [`types::DEFAULT_AMOUNT_CEILING`]). Admin-gated.
    pub fn set_default_amount_ceiling(env: Env, ceiling: i128) -> Result<(), ContractError> {
        AdminClient::require_admin(&env)?;
        Validator::validate_amount(ceiling)?;
        StorageClient::set_default_ceiling(&env, ceiling);
        Ok(())
    }

    /// Return the effective amount ceiling for `anchor`.
    pub fn get_amount_ceiling(env: Env, anchor: String) -> i128 {
        StorageClient::get_amount_ceiling(&env, &anchor)
    }

    /// Rotate the trusted relay signer address.
    ///
    /// # Events
    /// Emits [`events::EventRelaySignerRotated`] so off-chain monitoring can
    /// observe the rotation the same way it does [`Self::accept_admin`].
    pub fn set_relay_signer(env: Env, new_signer: Address) -> Result<(), ContractError> {
        AdminClient::require_admin(&env)?;
        // Once a timelock delay is explicitly configured, the immediate path
        // is closed; rotation must go through propose/finalize.
        if StorageClient::get_relay_signer_delay(&env).unwrap_or(0) > 0 {
            return Err(ContractError::TimelockRequired);
        }
        let old_signer = StorageClient::get_relay_signer(&env)?;
        StorageClient::set_relay_signer(&env, &new_signer);
        EventEmitter::relay_signer_rotated(&env, &old_signer, &new_signer);
        Ok(())
    }

    // ── Timelocked relay-signer rotation ──────────────────────────────────────

    /// Configure the timelock delay (ledgers) for relay-signer rotation.
    /// Admin-gated. A non-zero value also disables the immediate
    /// [`Self::set_relay_signer`] path.
    pub fn set_relay_signer_delay(env: Env, delay_ledgers: u32) -> Result<(), ContractError> {
        AdminClient::require_admin(&env)?;
        StorageClient::set_relay_signer_delay(&env, delay_ledgers);
        Ok(())
    }

    /// Start a timelocked rotation of the primary relay signer to `new_signer`.
    /// Admin-gated. A second proposal while one is pending **replaces** it
    /// (restarting the delay). With an N-of-M set (#65) only the primary
    /// signer slot is replaced; membership/threshold changes stay immediate
    /// admin operations.
    ///
    /// # Events
    /// Emits [`events::EventRelaySignerProposed`].
    pub fn propose_relay_signer(env: Env, new_signer: Address) -> Result<(), ContractError> {
        AdminClient::require_admin(&env)?;
        let delay = StorageClient::get_relay_signer_delay(&env)
            .unwrap_or(DEFAULT_RELAY_SIGNER_DELAY_LEDGERS);
        let eta_ledger = env.ledger().sequence().saturating_add(delay);
        StorageClient::set_pending_relay_signer(
            &env,
            &PendingRelaySigner {
                new_signer: new_signer.clone(),
                eta_ledger,
            },
        );
        EventEmitter::relay_signer_proposed(&env, &new_signer, eta_ledger);
        Ok(())
    }

    /// Complete a pending rotation once `eta_ledger` has been reached.
    ///
    /// # Errors
    /// [`ContractError::NoPendingRelaySigner`], [`ContractError::TimelockNotElapsed`].
    ///
    /// # Events
    /// Emits [`events::EventRelaySignerRotated`].
    pub fn finalize_relay_signer(env: Env) -> Result<(), ContractError> {
        AdminClient::require_admin(&env)?;
        let p = StorageClient::get_pending_relay_signer(&env)
            .ok_or(ContractError::NoPendingRelaySigner)?;
        if env.ledger().sequence() < p.eta_ledger {
            return Err(ContractError::TimelockNotElapsed);
        }
        let old_signer = StorageClient::get_relay_signer(&env)?;
        StorageClient::set_relay_signer(&env, &p.new_signer);
        StorageClient::clear_pending_relay_signer(&env);
        EventEmitter::relay_signer_rotated(&env, &old_signer, &p.new_signer);
        Ok(())
    }

    /// Abort a pending rotation. Admin-gated.
    ///
    /// # Events
    /// Emits [`events::EventRelaySignerChangeCancelled`].
    pub fn cancel_relay_signer_change(env: Env) -> Result<(), ContractError> {
        AdminClient::require_admin(&env)?;
        let p = StorageClient::get_pending_relay_signer(&env)
            .ok_or(ContractError::NoPendingRelaySigner)?;
        StorageClient::clear_pending_relay_signer(&env);
        EventEmitter::relay_signer_change_cancelled(&env, &p.new_signer);
        Ok(())
    }

    /// Return the pending relay-signer rotation, if any.
    pub fn pending_relay_signer(env: Env) -> Option<PendingRelaySigner> {
        StorageClient::get_pending_relay_signer(&env)
    }

    // ── Relay signer set (N-of-M) ─────────────────────────────────────────────

    /// Return the relay signer set (lazily migrated from a legacy single
    /// signer as `threshold = 1`).
    pub fn relay_signer_set(env: Env) -> Result<RelaySignerSet, ContractError> {
        StorageClient::get_relay_signer_set(&env)
    }

    /// Register the calling relay signer's approval for the next gated relay
    /// call (multi-invocation quorum pattern; valid for a short ledger window
    /// and consumed by the gated call). `signer` must be a set member.
    pub fn approve_relay_call(env: Env, signer: Address) -> Result<(), ContractError> {
        let set = StorageClient::get_relay_signer_set(&env)?;
        if !set.signers.contains(&signer) {
            return Err(ContractError::NotRelaySigner);
        }
        signer.require_auth();
        StorageClient::set_relay_approval(&env, &signer);
        Ok(())
    }

    /// Add a signer to the relay set. Admin-gated.
    ///
    /// # Events
    /// Emits [`events::EventRelaySignerAdded`].
    pub fn add_relay_signer(env: Env, signer: Address) -> Result<(), ContractError> {
        AdminClient::require_admin(&env)?;
        let mut set = StorageClient::get_relay_signer_set(&env)?;
        if set.signers.contains(&signer) {
            return Err(ContractError::SignerAlreadyExists);
        }
        set.signers.push_back(signer.clone());
        StorageClient::set_relay_signer_set(&env, &set);
        EventEmitter::relay_signer_added(&env, &signer);
        Ok(())
    }

    /// Remove a signer from the relay set. Admin-gated; rejected if it would
    /// leave fewer signers than the current threshold.
    ///
    /// # Events
    /// Emits [`events::EventRelaySignerRemoved`].
    pub fn remove_relay_signer(env: Env, signer: Address) -> Result<(), ContractError> {
        AdminClient::require_admin(&env)?;
        let mut set = StorageClient::get_relay_signer_set(&env)?;
        let idx = set
            .signers
            .first_index_of(&signer)
            .ok_or(ContractError::SignerNotFound)?;
        if set.signers.len() - 1 < set.threshold {
            return Err(ContractError::InvalidThreshold);
        }
        set.signers.remove(idx);
        StorageClient::set_relay_signer_set(&env, &set);
        StorageClient::clear_relay_approval(&env, &signer);
        EventEmitter::relay_signer_removed(&env, &signer);
        Ok(())
    }

    /// Change the quorum threshold. Admin-gated; must satisfy
    /// `1 <= threshold <= signers.len()`.
    ///
    /// # Events
    /// Emits [`events::EventRelayThresholdChanged`].
    pub fn set_relay_threshold(env: Env, threshold: u32) -> Result<(), ContractError> {
        AdminClient::require_admin(&env)?;
        let mut set = StorageClient::get_relay_signer_set(&env)?;
        if threshold == 0 || threshold > set.signers.len() {
            return Err(ContractError::InvalidThreshold);
        }
        let old = set.threshold;
        set.threshold = threshold;
        StorageClient::set_relay_signer_set(&env, &set);
        EventEmitter::relay_threshold_changed(&env, old, threshold);
        Ok(())
    }

    // ── Contract upgrade ───────────────────────────────────────────────────────

    /// Replace the contract WASM in-place.
    ///
    /// Only the current admin may call this.  The new WASM **must** be compatible
    /// with the existing storage schema (`StorageKey` variants, `Transaction`
    /// struct layout).  Persistent storage (admin, relay_signer, transactions)
    /// and instance storage (init flag, pause flag) survive intact; temporary
    /// storage (idempotency keys) is evicted.
    ///
    /// `expected_schema_version` must match the on-chain `SchemaVersion`
    /// (THREAT_MODEL.md finding F-04). This cannot validate that the *new*
    /// WASM is actually compatible — Soroban gives the running code no way to
    /// introspect an uploaded-but-not-yet-installed WASM blob — but it does
    /// guard against invoking `upgrade()` against a contract instance whose
    /// on-chain state isn't what the caller believes it is.
    ///
    /// # Events
    /// Emits [`events::EventContractUpgraded`] on success.
    ///
    /// # Trust
    /// Because this entry point allows the admin to deploy arbitrary WASM, the
    /// admin key **MUST** be held by a multisig or DAO.  See `DECISIONS.md` for
    /// the full rationale and `README.md` for operational requirements.
    pub fn upgrade(
        env: Env,
        new_wasm_hash: BytesN<32>,
        expected_schema_version: u32,
    ) -> Result<(), ContractError> {
        let admin = AdminClient::require_admin(&env)?;
        let schema_version = StorageClient::get_schema_version(&env)?;
        if schema_version != expected_schema_version {
            return Err(ContractError::SchemaVersionMismatch);
        }
        env.deployer()
            .update_current_contract_wasm(new_wasm_hash.clone());
        EventEmitter::contract_upgraded(&env, &admin, &new_wasm_hash, schema_version);
        Ok(())
    }

    // ── Emergency pause / circuit breaker ──────────────────────────────────────

    /// Engage the emergency circuit breaker.  Admin-gated.
    ///
    /// While paused, [`Self::register_callback`] rejects all new ingestion with
    /// [`ContractError::ContractPaused`]. Status transitions
    /// (`start_processing` / `complete_transaction` / `fail_transaction`) are
    /// **deliberately left running** so already-registered work can drain during
    /// an incident, and all read-only queries stay available. Idempotent: pausing
    /// an already-paused contract is a no-op success.
    pub fn pause(env: Env) -> Result<(), ContractError> {
        let admin = AdminClient::require_admin(&env)?;
        StorageClient::set_paused(&env, true);
        EventEmitter::pause_toggled(&env, true, &admin);
        Ok(())
    }

    /// Release the emergency circuit breaker, resuming normal callback
    /// ingestion.  Admin-gated. Idempotent.
    pub fn unpause(env: Env) -> Result<(), ContractError> {
        let admin = AdminClient::require_admin(&env)?;
        StorageClient::set_paused(&env, false);
        EventEmitter::pause_toggled(&env, false, &admin);
        Ok(())
    }

    /// Return whether the emergency pause is currently engaged.
    pub fn is_paused(env: Env) -> bool {
        StorageClient::is_paused(&env)
    }

    /// Liveness probe — returns `true` when the contract is initialised.
    pub fn health(env: Env) -> bool {
        StorageClient::is_initialised(&env)
    }

    /// Return the contract version string (semver).
    pub fn version(env: Env) -> String {
        // NOTE: `&'static str` is not a Soroban-representable return type, so the
        // package version is returned as a host `String`.
        String::from_str(&env, env!("CARGO_PKG_VERSION"))
    }
}
