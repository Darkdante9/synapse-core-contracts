//! # Types
//!
//! On-chain equivalents of the `synapse-core` Rust service's domain model.
//! Every struct that touches ledger storage derives [`soroban_sdk::contracttype`].

use soroban_sdk::{contracterror, contracttype, String};

/// Current on-chain storage schema version.
///
/// Bump this whenever [`Transaction`] or [`StorageKey`] layout changes in a
/// way that a running upgrade needs to be aware of. `initialize()` stores it;
/// `SynapseCoreContract::upgrade()` requires the caller to pass the value it
/// currently expects on-chain before proceeding (THREAT_MODEL.md finding
/// F-04). This cannot validate the *new* WASM's schema — Soroban gives the
/// currently-running code no way to introspect an uploaded-but-not-yet-
/// installed WASM blob — so it guards against upgrading the wrong deployment
/// or an unexpected on-chain state, not against an incompatible new binary.
pub const SCHEMA_VERSION: u32 = 1;

// ─── Transaction status ───────────────────────────────────────────────────────

/// Mirrors the `status` column in the `transactions` table.
///
/// State machine:
/// ```text
/// Pending ──► Processing ──► Completed
///         └──────────────► Failed
/// ```
#[contracttype]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TransactionStatus {
    /// Initial state — callback received, not yet picked up by the processor.
    Pending,
    /// Off-chain processor has claimed the job; on-chain verification in progress.
    Processing,
    /// Stellar on-chain settlement confirmed; ready for Phase 2 (Swap Engine).
    Completed,
    /// Terminal failure — reason stored in [`Transaction::failure_reason`].
    Failed,
}

// ─── Callback type ────────────────────────────────────────────────────────────

/// Maps the `callback_type` field from the Anchor Platform webhook.
#[contracttype]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CallbackType {
    Deposit,
    Withdrawal,
}

// ─── Core transaction record ──────────────────────────────────────────────────

/// On-chain mirror of the `transactions` table row.
///
/// Stored in persistent ledger storage keyed by [`StorageKey::Transaction`].
#[contracttype]
#[derive(Clone, Debug)]
pub struct Transaction {
    /// UUID-style unique identifier (generated off-chain, echoed here).
    pub id: String,

    /// Stellar account address of the depositor (G… address, 56 chars).
    pub stellar_account: String,

    /// Deposit amount in stroops (1 XLM = 10_000_000 stroops).
    /// Stored as i128 to match Soroban's native token amount convention.
    pub amount: i128,

    /// Asset code, e.g. "USDC", "USD" (max 12 chars per SEP-11).
    pub asset_code: String,

    /// Asset issuer address. Combined with `asset_code` uniquely identifies
    /// the Stellar asset.
    pub asset_issuer: String,

    /// Current lifecycle status.
    pub status: TransactionStatus,

    /// Ledger sequence number when the transaction was first registered.
    pub created_at_ledger: u32,

    /// Ledger sequence number of the last status update.
    pub updated_at_ledger: u32,

    /// Opaque ID from the Anchor Platform callback payload.
    /// Mirrors `anchor_transaction_id` in the DB schema.
    pub anchor_transaction_id: String,

    /// `deposit` or `withdrawal` — mirrors `callback_type`.
    pub callback_type: CallbackType,

    /// Raw status string received from the Anchor Platform
    /// (e.g. "pending_external", "completed").
    pub callback_status: String,

    /// Stellar transaction hash recorded after on-chain settlement.
    /// Empty string until the transaction reaches `Completed`.
    pub stellar_tx_hash: String,

    /// Short failure reason code — populated only on `Failed`.
    pub failure_reason: String,
}

// ─── Compact on-storage encoding ──────────────────────────────────────────────

/// Compact, on-ledger encoding of [`Transaction`].
///
/// This is the record actually written to persistent storage. It minimizes
/// the per-entry byte footprint relative to [`Transaction`] by:
///
/// * packing `status` and `callback_type` into a single `u8` flag byte
///   (2 bits each, 4 bits reserved for future flags);
/// * narrowing the two ledger-sequence fields from `u32` to `u32`-domain
///   values that fit in the same packed word is not possible without losing
///   range, so they are kept as `u32` but stored adjacently to avoid padding;
/// * omitting `updated_at_ledger` when it equals `created_at_ledger` (the
///   common case for a freshly-registered transaction), reconstructing it on
///   decode — it is derivable in that case and therefore not stored.
///
/// The public [`Transaction`] shape returned by `get_transaction()` is
/// unchanged: [`CompactTransaction::decode`] reconstructs it exactly.
#[contracttype]
#[derive(Clone, Debug)]
pub struct CompactTransaction {
    /// Packed flag byte: bits 0-1 = status, bits 2-3 = callback type.
    pub flags: u8,

    /// Ledger sequence when the transaction was first registered.
    pub created_at_ledger: u32,

    /// Ledger sequence of the last status update. Zero means "same as
    /// `created_at_ledger`" — the value is reconstructed on decode.
    pub updated_at_ledger: u32,

    /// Deposit amount in stroops.
    pub amount: i128,

    /// UUID-style unique identifier.
    pub id: String,

    /// Stellar account address of the depositor.
    pub stellar_account: String,

    /// Asset code, e.g. "USDC".
    pub asset_code: String,

    /// Asset issuer address.
    pub asset_issuer: String,

    /// Opaque ID from the Anchor Platform callback payload.
    pub anchor_transaction_id: String,

    /// Raw status string from the Anchor Platform callback.
    pub callback_status: String,

    /// Stellar transaction hash; empty until `Completed`.
    pub stellar_tx_hash: String,

    /// Short failure reason code; populated only on `Failed`.
    pub failure_reason: String,
}

impl CompactTransaction {
    /// Encode a [`Transaction`] into its compact on-storage form.
    pub fn encode(tx: &Transaction) -> Self {
        let status_bits: u8 = match tx.status {
            TransactionStatus::Pending => 0,
            TransactionStatus::Processing => 1,
            TransactionStatus::Completed => 2,
            TransactionStatus::Failed => 3,
        };
        let callback_bits: u8 = match tx.callback_type {
            CallbackType::Deposit => 0,
            CallbackType::Withdrawal => 1,
        };
        let flags = status_bits | (callback_bits << 2);

        // Omit `updated_at_ledger` when it is derivable from `created_at_ledger`.
        let updated_at_ledger = if tx.updated_at_ledger == tx.created_at_ledger {
            0
        } else {
            tx.updated_at_ledger
        };

        Self {
            flags,
            created_at_ledger: tx.created_at_ledger,
            updated_at_ledger,
            amount: tx.amount,
            id: tx.id.clone(),
            stellar_account: tx.stellar_account.clone(),
            asset_code: tx.asset_code.clone(),
            asset_issuer: tx.asset_issuer.clone(),
            anchor_transaction_id: tx.anchor_transaction_id.clone(),
            callback_status: tx.callback_status.clone(),
            stellar_tx_hash: tx.stellar_tx_hash.clone(),
            failure_reason: tx.failure_reason.clone(),
        }
    }

    /// Decode back into the public [`Transaction`] shape.
    pub fn decode(&self) -> Transaction {
        let status = match self.flags & 0b11 {
            0 => TransactionStatus::Pending,
            1 => TransactionStatus::Processing,
            2 => TransactionStatus::Completed,
            _ => TransactionStatus::Failed,
        };
        let callback_type = match (self.flags >> 2) & 0b11 {
            0 => CallbackType::Deposit,
            _ => CallbackType::Withdrawal,
        };
        let updated_at_ledger = if self.updated_at_ledger == 0 {
            self.created_at_ledger
        } else {
            self.updated_at_ledger
        };

        Transaction {
            id: self.id.clone(),
            stellar_account: self.stellar_account.clone(),
            amount: self.amount,
            asset_code: self.asset_code.clone(),
            asset_issuer: self.asset_issuer.clone(),
            status,
            created_at_ledger: self.created_at_ledger,
            updated_at_ledger,
            anchor_transaction_id: self.anchor_transaction_id.clone(),
            callback_type,
            callback_status: self.callback_status.clone(),
            stellar_tx_hash: self.stellar_tx_hash.clone(),
            failure_reason: self.failure_reason.clone(),
        }
    }
}

// ─── Incoming webhook payload ─────────────────────────────────────────────────

/// Payload forwarded by the trusted relay signer when calling
/// [`SynapseCoreContract::register_callback`].
///
/// This is the on-chain equivalent of the `POST /callback/transaction` body
/// handled by the off-chain `synapse-core` service.
#[contracttype]
#[derive(Clone, Debug)]
pub struct CallbackPayload {
    /// Must match an existing or newly-generated transaction UUID.
    pub transaction_id: String,

    /// Stellar account that initiated the deposit.
    pub stellar_account: String,

    /// Deposit amount in stroops.
    pub amount: i128,

    /// Asset code.
    pub asset_code: String,

    /// Asset issuer address.
    pub asset_issuer: String,

    /// Matches `X-Idempotency-Key` header from the Anchor Platform webhook.
    /// Used for deduplication — mirrors Redis-based idempotency off-chain.
    pub idempotency_key: String,

    /// Anchor Platform's internal transaction ID.
    pub anchor_transaction_id: String,

    /// Callback type from the Anchor Platform.
    pub callback_type: CallbackType,

    /// Raw status from the Anchor Platform callback.
    pub callback_status: String,
}

// ─── Storage keys ─────────────────────────────────────────────────────────────

/// Discriminants used as ledger storage keys.
///
/// Persistent storage keys (admin, relay signer, init flag) use `Symbol`-based
/// variants. Per-transaction data is keyed by the transaction ID string.
#[contracttype]
#[derive(Clone, Debug)]
pub enum StorageKey {
    /// Singleton: whether `initialize()` has been called.
    Initialised,
    /// Singleton: current admin address.
    Admin,
    /// Singleton: trusted relay signer address.
    RelaySigner,
    /// Singleton: emergency-pause / circuit-breaker flag.
    ///
    /// When set to `true` the contract refuses new callback ingestion via
    /// [`crate::SynapseCoreContract::register_callback`]. Absent/`false` means
    /// the contract operates normally.
    Paused,
    /// Per-transaction record keyed by transaction ID.
    Transaction(String),
    /// Idempotency key → cached response ledger; keyed by idempotency key.
    IdempotencyKey(String),
    /// Singleton: address nominated to become admin, pending its own
    /// `accept_admin()` call. Absent when no transfer is in progress.
    PendingAdmin,
    /// Singleton: on-chain storage schema version, set at `initialize()`.
    /// See [`SCHEMA_VERSION`].
    SchemaVersion,
}

// ─── Errors ───────────────────────────────────────────────────────────────────

/// All error codes returned by the contract.
///
/// Uses [`contracterror`] so they surface correctly via the Soroban XDR and
/// can be decoded by SDK clients / frontends.
#[contracterror]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum ContractError {
    // ── Initialisation ──────────────────────────────────────────────────────
    /// `initialize()` has already been called.
    AlreadyInitialised = 1,
    /// Contract has not yet been initialised.
    NotInitialised = 2,

    // ── Authorisation ───────────────────────────────────────────────────────
    /// Caller is not the admin.
    Unauthorised = 10,
    /// Caller is not the trusted relay signer.
    NotRelaySigner = 11,
    /// The contract is paused (emergency circuit breaker engaged); the
    /// requested operation is temporarily disabled.
    ContractPaused = 12,
    /// `accept_admin` was called with no pending admin transfer in progress.
    NoPendingAdminTransfer = 13,
    /// `propose_admin` was called with the contract's own address as the
    /// nominee, which cannot practically call `accept_admin` back and would
    /// permanently brick every admin-gated operation.
    InvalidAdminNominee = 14,

    // ── Payload validation ──────────────────────────────────────────────────
    /// `stellar_account` field is malformed.
    InvalidStellarAccount = 20,
    /// `amount` is zero or negative.
    InvalidAmount = 21,
    /// `asset_code` is empty or exceeds 12 characters.
    InvalidAssetCode = 22,
    /// `asset_issuer` field is malformed.
    InvalidAssetIssuer = 23,
    /// `idempotency_key` is empty.
    MissingIdempotencyKey = 24,
    /// A `String` field exceeds its maximum permitted length.
    FieldTooLong = 25,
}

// ─── Compact encoding round-trip tests ────────────────────────────────────────

#[cfg(test)]
mod compact_tests {
    use super::*;
    use soroban_sdk::Env;

    fn sample(env: &Env) -> Transaction {
        Transaction {
            id: String::from_str(env, "tx-1"),
            stellar_account: String::from_str(env, "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"),
            amount: 10_000_000,
            asset_code: String::from_str(env, "USDC"),
            asset_issuer: String::from_str(env, "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"),
            status: TransactionStatus::Pending,
            created_at_ledger: 1,
            updated_at_ledger: 1,
            anchor_transaction_id: String::from_str(env, "anchor-1"),
            callback_type: CallbackType::Deposit,
            callback_status: String::from_str(env, "pending_external"),
            stellar_tx_hash: String::from_str(env, ""),
            failure_reason: String::from_str(env, ""),
        }
    }

    #[test]
    fn round_trip_all_status_and_callback_combinations() {
        let env = Env::default();
        let statuses = [
            TransactionStatus::Pending,
            TransactionStatus::Processing,
            TransactionStatus::Completed,
            TransactionStatus::Failed,
        ];
        let callbacks = [CallbackType::Deposit, CallbackType::Withdrawal];
        for status in statuses.iter() {
            for callback in callbacks.iter() {
                let mut tx = sample(&env);
                tx.status = status.clone();
                tx.callback_type = callback.clone();
                let decoded = CompactTransaction::encode(&tx).decode();
                assert_eq!(decoded.status, tx.status);
                assert_eq!(decoded.callback_type, tx.callback_type);
                assert_eq!(decoded.id, tx.id);
                assert_eq!(decoded.amount, tx.amount);
                assert_eq!(decoded.created_at_ledger, tx.created_at_ledger);
                assert_eq!(decoded.updated_at_ledger, tx.updated_at_ledger);
            }
        }
    }

    #[test]
    fn round_trip_boundary_ledger_values() {
        let env = Env::default();
        for (created, updated) in [(0u32, 0u32), (0, 1), (u32::MAX, u32::MAX), (u32::MAX, 0), (1, u32::MAX)] {
            let mut tx = sample(&env);
            tx.created_at_ledger = created;
            tx.updated_at_ledger = updated;
            let decoded = CompactTransaction::encode(&tx).decode();
            assert_eq!(decoded.created_at_ledger, created);
            assert_eq!(decoded.updated_at_ledger, updated);
        }
    }

    #[test]
    fn round_trip_boundary_amounts() {
        let env = Env::default();
        for amount in [i128::MIN, -1, 0, 1, i128::MAX] {
            let mut tx = sample(&env);
            tx.amount = amount;
            let decoded = CompactTransaction::encode(&tx).decode();
            assert_eq!(decoded.amount, amount);
        }
    }

    #[test]
    fn round_trip_preserves_all_string_fields() {
        let env = Env::default();
        let mut tx = sample(&env);
        tx.stellar_tx_hash = String::from_str(&env, "deadbeef");
        tx.failure_reason = String::from_str(&env, "insufficient_funds");
        let decoded = CompactTransaction::encode(&tx).decode();
        assert_eq!(decoded.stellar_account, tx.stellar_account);
        assert_eq!(decoded.asset_code, tx.asset_code);
        assert_eq!(decoded.asset_issuer, tx.asset_issuer);
        assert_eq!(decoded.anchor_transaction_id, tx.anchor_transaction_id);
        assert_eq!(decoded.callback_status, tx.callback_status);
        assert_eq!(decoded.stellar_tx_hash, tx.stellar_tx_hash);
        assert_eq!(decoded.failure_reason, tx.failure_reason);
    }
}
