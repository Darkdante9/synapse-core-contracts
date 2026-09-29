//! # Events
//!
//! Every state transition the contract makes is announced via a typed event
//! so that downstream subscribers (Phase 2 Swap Engine, Phase 3 Cross-Chain
//! Bridge, off-chain indexers) can react without polling.
//!
//! ## Event schema convention
//!
//! Each event is emitted as:
//! ```text
//! topics: [Symbol("synapse"), Symbol("<event_name>")]
//! data:   <typed contracttype struct>
//! ```
//!
//! This two-topic convention is consistent with the Stellar Asset Contract
//! standard and makes event filtering straightforward in Horizon / RPC queries.
//!
//! **Public API:** topic names, payload fields/types/order, and multi-event
//! emission order are versioned for Phase 2 / Phase 3 subscribers. See
//! [`EVENTS.md`](../EVENTS.md) (catalogue + semver) and
//! [`CHANGELOG.md`](../CHANGELOG.md#event-schema).

use soroban_sdk::{contracttype, symbol_short, Env, String};

use crate::types::TransactionStatus;

// ─── Event data structs ───────────────────────────────────────────────────────

/// Emitted by [`SynapseCoreContract::initialize`].
#[contracttype]
pub struct EventInitialised {
    pub admin: soroban_sdk::Address,
    pub relay_signer: soroban_sdk::Address,
    pub ledger: u32,
}

/// Emitted by [`SynapseCoreContract::register_callback`] when a new
/// [`Transaction`] is persisted for the first time.
#[contracttype]
pub struct EventTransactionRegistered {
    pub tx_id: String,
    pub stellar_account: String,
    pub amount: i128,
    pub asset_code: String,
    pub anchor_transaction_id: String,
    pub ledger: u32,
}

/// Emitted by [`SynapseCoreContract::cancel_transaction`].
#[contracttype]
pub struct EventTransactionCancelled {
    pub tx_id: String,
    pub reason: String,
    pub caller: soroban_sdk::Address,
    pub ledger: u32,
}

/// Emitted by [`SynapseCoreContract::retry_transaction`].
#[contracttype]
pub struct EventTransactionRetried {
    pub tx_id: String,
    pub retry_count: u32,
    pub ledger: u32,
}

/// Emitted once by [`SynapseCoreContract::batch_register_callback`] after all
/// per-transaction `TransactionRegistered` events.
#[contracttype]
pub struct EventBatchProcessed {
    pub count: u32,
    pub caller: soroban_sdk::Address,
    pub ledger: u32,
}

/// Emitted on every status change driven by [`SynapseCoreContract::start_processing`],
/// [`SynapseCoreContract::complete_transaction`], or
/// [`SynapseCoreContract::fail_transaction`].
///
/// Phase 2 listens for `new_status == Completed` to trigger the swap flow.
/// Phase 3 listens for `new_status == Completed` after the swap to initiate bridging.
#[contracttype]
pub struct EventStatusChanged {
    pub tx_id: String,
    pub old_status: TransactionStatus,
    pub new_status: TransactionStatus,
    pub ledger: u32,
}

/// Emitted when a transaction reaches terminal state `Completed`.
/// Carries the confirmed Stellar transaction hash for downstream verification.
#[contracttype]
pub struct EventTransactionCompleted {
    pub tx_id: String,
    pub stellar_tx_hash: String,
    pub ledger: u32,
}

/// Emitted when a transaction reaches terminal state `Failed`.
#[contracttype]
pub struct EventTransactionFailed {
    pub tx_id: String,
    pub reason: String,
    pub ledger: u32,
}

/// Emitted when a stale `Pending` transaction reaches terminal state `Expired`.
#[contracttype]
pub struct EventTransactionExpired {
    pub tx_id: String,
    pub registered_at: u64,
    pub expired_at: u64,
    pub ledger: u32,
}

/// Emitted when the admin changes the `Pending` expiry window.
#[contracttype]
pub struct EventExpiryWindowSet {
    pub seconds: u64,
    pub ledger: u32,
}

/// Emitted when a transaction is completed with less than its registered
/// amount via `partial_complete_transaction`.
#[contracttype]
pub struct EventTransactionPartiallyCompleted {
    pub tx_id: String,
    pub original_amount: i128,
    pub settled_amount: i128,
    pub stellar_tx_hash: String,
    pub ledger: u32,
}

/// Emitted when an in-flight transaction is rebound to a different relay signer.
#[contracttype]
pub struct EventTransactionReassigned {
    pub tx_id: String,
    pub old_signer: soroban_sdk::Address,
    pub new_signer: soroban_sdk::Address,
    pub ledger: u32,
}

/// Emitted when the admin-approved standby signer is set.
#[contracttype]
pub struct EventStandbySignerSet {
    pub signer: soroban_sdk::Address,
    pub ledger: u32,
}

/// Emitted when a tag is appended to a transaction.
#[contracttype]
pub struct EventTransactionTagged {
    pub tx_id: String,
    pub tag: String,
    pub tag_count: u32,
    pub ledger: u32,
}

/// Emitted when the admin role is transferred.
#[contracttype]
pub struct EventAdminTransferred {
    pub old_admin: soroban_sdk::Address,
    pub new_admin: soroban_sdk::Address,
    pub ledger: u32,
}

/// Emitted by [`SynapseCoreContract::propose_admin`] when a new admin is
/// nominated. The transfer is not yet effective at this point — see
/// [`EventAdminTransferred`], emitted only once the nominee itself calls
/// `accept_admin` (two-step transfer, THREAT_MODEL.md finding F-03).
#[contracttype]
pub struct EventAdminTransferProposed {
    pub current_admin: soroban_sdk::Address,
    pub proposed_admin: soroban_sdk::Address,
    pub ledger: u32,
}

/// Emitted when the trusted relay signer is rotated.
///
/// Relay-signer compromise lets an attacker register forged callbacks and
/// drive the lifecycle state machine, so off-chain monitoring subscribes to
/// this the same way it does [`EventAdminTransferred`].
#[contracttype]
pub struct EventRelaySignerRotated {
    pub old_signer: soroban_sdk::Address,
    pub new_signer: soroban_sdk::Address,
    pub ledger: u32,
}

/// Emitted by [`SynapseCoreContract::upgrade`] when the contract WASM is
/// replaced in-place.
///
/// Downstream indexers and monitoring tooling subscribe to this to detect
/// unexpected upgrades (potential admin-key compromise).
#[contracttype]
pub struct EventContractUpgraded {
    /// Admin that authorised the upgrade.
    pub admin: soroban_sdk::Address,
    /// The new WASM hash (SHA-256 of the deployed `.wasm`).
    pub new_wasm_hash: soroban_sdk::BytesN<32>,
    pub ledger: u32,
    /// The on-chain schema version that `expected_schema_version` was
    /// checked against before this upgrade proceeded (THREAT_MODEL.md
    /// finding F-04). Additive trailing field — see EVENTS.md semver policy.
    pub schema_version: u32,
}

/// Emitted by [`SynapseCoreContract::pause`] / [`SynapseCoreContract::unpause`]
/// whenever the emergency circuit breaker is toggled.
///
/// Off-chain incident-response tooling subscribes to this so a pause is
/// observable on-chain the moment it happens.
#[contracttype]
pub struct EventPauseToggled {
    /// New pause state: `true` = paused, `false` = unpaused.
    pub paused: bool,
    /// Admin address that performed the toggle.
    pub admin: soroban_sdk::Address,
    pub ledger: u32,
}

/// Emitted by [`SynapseCoreContract::merge_duplicate_transactions`] when an
/// admin links a duplicate record to its canonical original (break-glass).
#[contracttype]
pub struct EventTransactionsMerged {
    pub canonical_tx_id: String,
    pub duplicate_tx_id: String,
    pub admin: soroban_sdk::Address,
    pub reason: String,
    pub ledger: u32,
}

/// Emitted by [`SynapseCoreContract::complete_transaction`], strictly after
/// `status` and `done`, only when a non-zero forwarding route is configured.
/// Purely a signal for a future downstream phase; no cross-contract call.
#[contracttype]
pub struct EventForwardingIntent {
    pub tx_id: String,
    pub next_phase: u32,
}

/// Emitted when a signer is added to the relay signer set.
#[contracttype]
pub struct EventRelaySignerAdded {
    pub signer: soroban_sdk::Address,
    pub ledger: u32,
}

/// Emitted when a signer is removed from the relay signer set.
#[contracttype]
pub struct EventRelaySignerRemoved {
    pub signer: soroban_sdk::Address,
    pub ledger: u32,
}

/// Emitted when the relay quorum threshold changes.
#[contracttype]
pub struct EventRelayThresholdChanged {
    pub old_threshold: u32,
    pub new_threshold: u32,
    pub ledger: u32,
}

/// Emitted by `propose_relay_signer`; the rotation is not yet effective.
#[contracttype]
pub struct EventRelaySignerProposed {
    pub proposed_signer: soroban_sdk::Address,
    pub eta_ledger: u32,
    pub ledger: u32,
}

/// Emitted by `cancel_relay_signer_change`.
#[contracttype]
pub struct EventRelaySignerChangeCancelled {
    pub cancelled_signer: soroban_sdk::Address,
    pub ledger: u32,
}

// ─── Emitter ─────────────────────────────────────────────────────────────────

pub struct EventEmitter;

impl EventEmitter {
    /// Emit [`EventInitialised`].
    pub fn initialised(
        env: &Env,
        admin: &soroban_sdk::Address,
        relay_signer: &soroban_sdk::Address,
    ) {
        env.events().publish(
            (symbol_short!("synapse"), symbol_short!("init")),
            EventInitialised {
                admin: admin.clone(),
                relay_signer: relay_signer.clone(),
                ledger: env.ledger().sequence(),
            },
        );
    }

    /// Emit [`EventTransactionRegistered`].
    pub fn transaction_registered(env: &Env, tx: &crate::types::Transaction) {
        env.events().publish(
            (symbol_short!("synapse"), symbol_short!("reg")),
            EventTransactionRegistered {
                tx_id: tx.id.clone(),
                stellar_account: tx.stellar_account.clone(),
                amount: tx.amount,
                asset_code: tx.asset_code.clone(),
                anchor_transaction_id: tx.anchor_transaction_id.clone(),
                ledger: env.ledger().sequence(),
            },
        );
    }

    /// Emit [`EventContractUpgraded`].
    pub fn contract_upgraded(
        env: &Env,
        admin: &soroban_sdk::Address,
        new_wasm_hash: &soroban_sdk::BytesN<32>,
        schema_version: u32,
    ) {
        env.events().publish(
            (symbol_short!("synapse"), symbol_short!("upgrade")),
            EventContractUpgraded {
                admin: admin.clone(),
                new_wasm_hash: new_wasm_hash.clone(),
                ledger: env.ledger().sequence(),
                schema_version,
            },
        );
    }

    /// Emit [`EventAdminTransferProposed`].
    pub fn admin_transfer_proposed(
        env: &Env,
        current_admin: &soroban_sdk::Address,
        proposed_admin: &soroban_sdk::Address,
    ) {
        env.events().publish(
            (symbol_short!("synapse"), symbol_short!("propose")),
            EventAdminTransferProposed {
                current_admin: current_admin.clone(),
                proposed_admin: proposed_admin.clone(),
                ledger: env.ledger().sequence(),
            },
        );
    }

    /// Emit [`EventRelaySignerRotated`].
    pub fn relay_signer_rotated(
        env: &Env,
        old_signer: &soroban_sdk::Address,
        new_signer: &soroban_sdk::Address,
    ) {
        env.events().publish(
            (symbol_short!("synapse"), symbol_short!("relay")),
            EventRelaySignerRotated {
                old_signer: old_signer.clone(),
                new_signer: new_signer.clone(),
                ledger: env.ledger().sequence(),
            },
        );
    }

    /// Emit [`EventTransactionsMerged`].
    pub fn transactions_merged(
        env: &Env,
        canonical_tx_id: &String,
        duplicate_tx_id: &String,
        admin: &soroban_sdk::Address,
        reason: &String,
    ) {
        env.events().publish(
            (symbol_short!("synapse"), symbol_short!("merged")),
            EventTransactionsMerged {
                canonical_tx_id: canonical_tx_id.clone(),
                duplicate_tx_id: duplicate_tx_id.clone(),
                admin: admin.clone(),
                reason: reason.clone(),
                ledger: env.ledger().sequence(),
            },
        );
    }

    /// Emit [`EventForwardingIntent`].
    pub fn forwarding_intent(env: &Env, tx_id: &String, next_phase: u32) {
        env.events().publish(
            (symbol_short!("synapse"), symbol_short!("fwd")),
            EventForwardingIntent {
                tx_id: tx_id.clone(),
                next_phase,
            },
        );
    }

    /// Emit [`EventRelaySignerAdded`].
    pub fn relay_signer_added(env: &Env, signer: &soroban_sdk::Address) {
        env.events().publish(
            (symbol_short!("synapse"), symbol_short!("rs_add")),
            EventRelaySignerAdded {
                signer: signer.clone(),
                ledger: env.ledger().sequence(),
            },
        );
    }

    /// Emit [`EventRelaySignerRemoved`].
    pub fn relay_signer_removed(env: &Env, signer: &soroban_sdk::Address) {
        env.events().publish(
            (symbol_short!("synapse"), symbol_short!("rs_rm")),
            EventRelaySignerRemoved {
                signer: signer.clone(),
                ledger: env.ledger().sequence(),
            },
        );
    }

    /// Emit [`EventRelayThresholdChanged`].
    pub fn relay_threshold_changed(env: &Env, old_threshold: u32, new_threshold: u32) {
        env.events().publish(
            (symbol_short!("synapse"), symbol_short!("rs_thr")),
            EventRelayThresholdChanged {
                old_threshold,
                new_threshold,
                ledger: env.ledger().sequence(),
            },
        );
    }

    /// Emit [`EventRelaySignerProposed`].
    pub fn relay_signer_proposed(env: &Env, proposed: &soroban_sdk::Address, eta_ledger: u32) {
        env.events().publish(
            (symbol_short!("synapse"), symbol_short!("rs_prop")),
            EventRelaySignerProposed {
                proposed_signer: proposed.clone(),
                eta_ledger,
                ledger: env.ledger().sequence(),
            },
        );
    }

    /// Emit [`EventRelaySignerChangeCancelled`].
    pub fn relay_signer_change_cancelled(env: &Env, cancelled: &soroban_sdk::Address) {
        env.events().publish(
            (symbol_short!("synapse"), symbol_short!("rs_canc")),
            EventRelaySignerChangeCancelled {
                cancelled_signer: cancelled.clone(),
                ledger: env.ledger().sequence(),
            },
        );
    }

    /// Emit [`EventPauseToggled`].
    pub fn pause_toggled(env: &Env, paused: bool, admin: &soroban_sdk::Address) {
        env.events().publish(
            (symbol_short!("synapse"), symbol_short!("pause")),
            EventPauseToggled {
                paused,
                admin: admin.clone(),
                ledger: env.ledger().sequence(),
            },
        );
    }

    /// Emit [`EventStatusChanged`].
    pub fn status_changed(
        env: &Env,
        tx_id: &String,
        old_status: TransactionStatus,
        new_status: TransactionStatus,
    ) {
        env.events().publish(
            (symbol_short!("synapse"), symbol_short!("status")),
            EventStatusChanged {
                tx_id: tx_id.clone(),
                old_status,
                new_status,
                ledger: env.ledger().sequence(),
            },
        );
    }

    /// Emit [`EventTransactionCompleted`].
    pub fn transaction_completed(env: &Env, tx_id: &String, stellar_tx_hash: &String) {
        env.events().publish(
            (symbol_short!("synapse"), symbol_short!("done")),
            EventTransactionCompleted {
                tx_id: tx_id.clone(),
                stellar_tx_hash: stellar_tx_hash.clone(),
                ledger: env.ledger().sequence(),
            },
        );
    }

    /// Emit [`EventTransactionFailed`].
    pub fn transaction_failed(env: &Env, tx_id: &String, reason: &String) {
        env.events().publish(
            (symbol_short!("synapse"), symbol_short!("fail")),
            EventTransactionFailed {
                tx_id: tx_id.clone(),
                reason: reason.clone(),
                ledger: env.ledger().sequence(),
            },
        );
    }

    /// Emit [`EventTransactionCancelled`].
    pub fn transaction_cancelled(
        env: &Env,
        tx_id: &String,
        reason: &String,
        caller: &soroban_sdk::Address,
    ) {
        env.events().publish(
            (symbol_short!("synapse"), symbol_short!("cancel")),
            EventTransactionCancelled {
                tx_id: tx_id.clone(),
                reason: reason.clone(),
                caller: caller.clone(),
                ledger: env.ledger().sequence(),
            },
        );
    }

    /// Emit [`EventTransactionRetried`].
    pub fn transaction_retried(env: &Env, tx_id: &String, retry_count: u32) {
        env.events().publish(
            (symbol_short!("synapse"), symbol_short!("retry")),
            EventTransactionRetried {
                tx_id: tx_id.clone(),
                retry_count,
                ledger: env.ledger().sequence(),
            },
        );
    }

    /// Emit [`EventBatchProcessed`].
    pub fn batch_processed(env: &Env, count: u32, caller: &soroban_sdk::Address) {
        env.events().publish(
            (symbol_short!("synapse"), symbol_short!("batch")),
            EventBatchProcessed {
                count,
                caller: caller.clone(),
                ledger: env.ledger().sequence(),
            },
        );
    }

    /// Emit [`EventAdminTransferred`].
    pub fn admin_transferred(
        env: &Env,
        old_admin: &soroban_sdk::Address,
        new_admin: &soroban_sdk::Address,
    ) {
        env.events().publish(
            (symbol_short!("synapse"), symbol_short!("admin")),
            EventAdminTransferred {
                old_admin: old_admin.clone(),
                new_admin: new_admin.clone(),
                ledger: env.ledger().sequence(),
            },
        );
    }

    /// Emit [`EventTransactionExpired`].
    pub fn transaction_expired(env: &Env, tx_id: &String, registered_at: u64) {
        env.events().publish(
            (symbol_short!("synapse"), symbol_short!("expired")),
            EventTransactionExpired {
                tx_id: tx_id.clone(),
                registered_at,
                expired_at: env.ledger().timestamp(),
                ledger: env.ledger().sequence(),
            },
        );
    }

    /// Emit [`EventExpiryWindowSet`].
    pub fn expiry_window_set(env: &Env, seconds: u64) {
        env.events().publish(
            (symbol_short!("synapse"), symbol_short!("exp_win")),
            EventExpiryWindowSet {
                seconds,
                ledger: env.ledger().sequence(),
            },
        );
    }

    /// Emit [`EventTransactionPartiallyCompleted`].
    pub fn transaction_partially_completed(
        env: &Env,
        tx_id: &String,
        original_amount: i128,
        settled_amount: i128,
        stellar_tx_hash: &String,
    ) {
        env.events().publish(
            (symbol_short!("synapse"), symbol_short!("partial")),
            EventTransactionPartiallyCompleted {
                tx_id: tx_id.clone(),
                original_amount,
                settled_amount,
                stellar_tx_hash: stellar_tx_hash.clone(),
                ledger: env.ledger().sequence(),
            },
        );
    }

    /// Emit [`EventTransactionReassigned`].
    pub fn transaction_reassigned(
        env: &Env,
        tx_id: &String,
        old_signer: &soroban_sdk::Address,
        new_signer: &soroban_sdk::Address,
    ) {
        env.events().publish(
            (symbol_short!("synapse"), symbol_short!("reassign")),
            EventTransactionReassigned {
                tx_id: tx_id.clone(),
                old_signer: old_signer.clone(),
                new_signer: new_signer.clone(),
                ledger: env.ledger().sequence(),
            },
        );
    }

    /// Emit [`EventStandbySignerSet`].
    pub fn standby_signer_set(env: &Env, signer: &soroban_sdk::Address) {
        env.events().publish(
            (symbol_short!("synapse"), symbol_short!("standby")),
            EventStandbySignerSet {
                signer: signer.clone(),
                ledger: env.ledger().sequence(),
            },
        );
    }

    /// Emit [`EventTransactionTagged`].
    pub fn transaction_tagged(env: &Env, tx_id: &String, tag: &String, tag_count: u32) {
        env.events().publish(
            (symbol_short!("synapse"), symbol_short!("tagged")),
            EventTransactionTagged {
                tx_id: tx_id.clone(),
                tag: tag.clone(),
                tag_count,
                ledger: env.ledger().sequence(),
            },
        );
    }
}
