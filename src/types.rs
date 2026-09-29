//! # Types
//!
//! On-chain equivalents of the `synapse-core` Rust service's domain model.
//! Every struct that touches ledger storage derives [`soroban_sdk::contracttype`].

use soroban_sdk::{contracterror, contracttype, Address, String, Vec};

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

/// Contract-wide default max amount (stroops) for anchors (keyed by
/// `asset_issuer`) with no explicit ceiling: 10^15 stroops (100M units at 7
/// decimals). Admin may override via `set_default_amount_ceiling`.
pub const DEFAULT_AMOUNT_CEILING: i128 = 1_000_000_000_000_000;

/// Maximum number of times a `Failed` transaction may be retried.
pub const MAX_RETRIES: u32 = 3;

/// Hard cap on the `limit` accepted by `get_transactions_by_status`.
pub const MAX_PAGE_LIMIT: u32 = 50;

/// Hard cap on the number of payloads accepted by `batch_register_callback`.
pub const MAX_BATCH_SIZE: u32 = 20;

// ─── Transaction status ───────────────────────────────────────────────────────

/// Mirrors the `status` column in the `transactions` table.
///
/// State machine:
/// ```text
/// Pending ──► Processing ──► Completed
///   │             │
///   ├─────────────┴────────► Failed
///   ├─────────────┴────────► Cancelled
///   └─────────────┴────────► Expired (permissionless, after expiry window)
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
    /// Terminal withdrawal — voided by the relay or admin before settlement.
    Cancelled,
    /// Terminal: stayed `Pending` past the configured expiry window and was
    /// expired via the permissionless `expire_transaction`.
    Expired,
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

    /// Number of times this transaction has been moved `Failed -> Pending`
    /// via `retry_transaction`. Capped at [`MAX_RETRIES`].
    pub retry_count: u32,

    /// Ledger timestamp (seconds) when the transaction was registered.
    /// Used to age out stale `Pending` entries.
    pub registered_at: u64,

    /// Amount actually settled when completed via `partial_complete_transaction`.
    /// `None` for full completions and non-completed transactions.
    pub settled_amount: Option<i128>,

    /// Per-transaction relay signer binding set by
    /// `reassign_relay_signer_for_transaction`. `None` means the global
    /// relay signer applies.
    pub assigned_signer: Option<Address>,

    /// Append-only operational tags (bounded count and length; see
    /// `validation.rs`).
    pub tags: Vec<String>,
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

/// One entry in a transaction's append-only lifecycle history.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitionRecord {
    /// Status the transaction entered.
    pub status: TransactionStatus,
    /// Address that drove the transition.
    pub caller: Address,
    /// Ledger close timestamp of the transition.
    pub timestamp: u64,
}

/// Maximum history entries kept per transaction. When exceeded the oldest
/// entry is evicted (drop-oldest, keep-newest); history loss never blocks a
/// state transition.
pub const MAX_HISTORY_LEN: u32 = 32;

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
    /// Optional expiry (ledger timestamp, seconds) of the pending admin proposal.
    PendingAdminExpiry,
    /// Per-address replay-protection nonce (next expected value).
    Nonce(Address),
    /// Per-relay-signer allowlist of anchor instance IDs (empty/absent = all).
    RelayAnchors(Address),
    /// Singleton: max age in seconds of a `Pending` transaction before it
    /// may be expired. Absent means expiry is disabled.
    ExpiryWindow,
    /// Singleton: admin-approved standby relay signer, a valid reassignment
    /// target alongside the current `relay_signer`.
    StandbySigner,
    /// Per-status index: ordered `Vec<String>` of transaction IDs currently in
    /// that status. Maintained by `StorageClient::save_transaction`.
    StatusIndex(TransactionStatus),
    History(String),
    MaxPendingPerSigner,
    PendingCount(Address),
    TxSigner(String),
    Disputed(String),
    AnchorCeiling(String),
    DefaultCeiling,
    /// Merge marker: duplicate tx id -> canonical tx id it was merged into.
    MergedInto(String),
    /// Per-transaction forwarding route (`next_phase`); absent = no forwarding.
    ForwardRoute(String),
    /// Singleton: N-of-M relay signer set ([`RelaySignerSet`]). Absent on
    /// pre-#65 deployments; the legacy `RelaySigner` key is then migrated
    /// lazily to `threshold = 1, signers = [relay_signer]`.
    RelaySignerSet,
    /// Temporary: a signer's standing approval for the next gated relay call.
    RelayApproval(Address),
    /// Singleton: pending timelocked relay-signer change.
    PendingRelaySigner,
    /// Singleton: timelock delay in ledgers (absent = default).
    RelaySignerDelay,
    /// Per-signer ledger timestamp of the last `heartbeat()` call.
    LastHeartbeat(soroban_sdk::Address),
    /// Singleton: staleness window in seconds; absent/0 disables quarantine.
    HeartbeatWindow,
    /// Per-address set of granted [`RoleScope`]s.
    Scopes(soroban_sdk::Address),
    /// Singleton: guardian address set (may `guardian_pause`).
    Guardians,
    /// Singleton: guardian quorum M required by `revoke_admin_emergency`.
    GuardianThreshold,
    /// Singleton: set once the admin was revoked via break-glass.
    AdminVacant,
}

/// Pending timelocked relay-signer rotation, finalisable at `eta_ledger`.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingRelaySigner {
    pub new_signer: Address,
    pub eta_ledger: u32,
}

/// Default relay-signer timelock: ~24h at ~5s/ledger.
pub const DEFAULT_RELAY_SIGNER_DELAY_LEDGERS: u32 = 17_280;

/// N-of-M relay signer set: `threshold` distinct members must co-authorise
/// each relay-gated call.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelaySignerSet {
    pub signers: Vec<Address>,
    pub threshold: u32,
}

/// Narrow processing-lifecycle permissions grantable independently of the
/// relay signer. The relay signer and admin implicitly hold every scope.
#[contracttype]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RoleScope {
    /// May call `start_processing`.
    StartProcessing,
    /// May call `complete_transaction`.
    CompleteTransaction,
    /// May call `fail_transaction`.
    FailTransaction,
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
    /// `asset_issuer` is malformed.
    InvalidAssetIssuer = 23,
    /// `idempotency_key` is empty.
    MissingIdempotencyKey = 24,
    /// A `String` field exceeds its maximum allowed length (cost-control cap).
    StringTooLong = 25,

    // ── Transaction lifecycle ───────────────────────────────────────────────
    /// No transaction with the given ID exists in storage.
    TransactionNotFound = 30,
    /// The requested status transition violates the state machine.
    InvalidStatusTransition = 31,
    /// The transaction is already `Cancelled`; cancelling twice is rejected.
    AlreadyCancelled = 32,
    /// Cancellation was requested from a state that cannot be cancelled
    /// (`Completed` or `Failed`).
    CannotCancel = 33,
    /// The transaction has already used all [`MAX_RETRIES`] retries.
    RetryLimitExceeded = 34,
    /// A pagination `limit` was zero or exceeded `MAX_PAGE_LIMIT`.
    InvalidPageLimit = 35,
    /// A batch was empty or exceeded `MAX_BATCH_SIZE`.
    InvalidBatchSize = 36,

    // ── Idempotency ─────────────────────────────────────────────────────────
    /// Request is a duplicate within the retention window (matches Redis 429).
    DuplicateRequest = 40,

    // ── Storage ─────────────────────────────────────────────────────────────
    /// A ledger read/write produced an unexpected result.
    StorageError = 50,

    // ── Upgrade safety ──────────────────────────────────────────────────────
    /// `upgrade()`'s `expected_schema_version` argument did not match the
    /// on-chain [`SchemaVersion`](StorageKey::SchemaVersion); the upgrade was
    /// aborted before touching contract WASM.
    SchemaVersionMismatch = 60,
    // ── Backpressure ────────────────────────────────────────────────────────
    /// Relay signer already has the maximum allowed outstanding `Pending` transactions.
    OutstandingCapExceeded = 70,

    // ── Expiry ──────────────────────────────────────────────────────────────
    /// `expire_transaction` was called but no expiry window is configured.
    ExpiryNotConfigured = 71,
    /// `expire_transaction` was called before the expiry window elapsed.
    ExpiryNotElapsed = 72,

    // ── Disputes ────────────────────────────────────────────────────────────
    /// Transaction is already under dispute.
    AlreadyDisputed = 80,
    /// Transaction is not under dispute.
    NotDisputed = 81,

    // ── Partial settlement ──────────────────────────────────────────────────
    /// `settled_amount` is not strictly between zero and the original amount.
    InvalidSettledAmount = 82,

    // ── Signer reassignment ─────────────────────────────────────────────────
    /// `new_signer` is neither the relay signer nor the approved standby.
    SignerNotTrusted = 83,

    // ── Tagging ─────────────────────────────────────────────────────────────
    /// The transaction already carries the maximum number of tags.
    TooManyTags = 90,
    /// The tag is empty.
    EmptyTag = 91,

    // ── Amount ceilings ─────────────────────────────────────────────────────
    /// Amount exceeds the anchor's (or the default) ceiling.
    AmountCeilingExceeded = 92,

    // ── Recovery / merge (100+ range) ───────────────────────────────────────
    /// `merge_duplicate_transactions` was given the same id for both sides.
    MergeSelf = 100,
    /// The duplicate (or canonical) record is already merged.
    AlreadyMerged = 101,
    /// The duplicate is `Completed` (settled); merging would be lossy.
    DuplicateSettled = 102,

    // ── Relay signer set (110+ range) ───────────────────────────────────────
    /// Threshold is 0 or exceeds the number of signers.
    InvalidThreshold = 110,
    /// Signer is already a member of the set.
    SignerAlreadyExists = 111,
    /// Signer is not a member of the set.
    SignerNotFound = 112,
    /// Fewer than `threshold` distinct signers authorised the call.
    QuorumNotMet = 113,

    // ── Relay signer timelock (120+ range) ──────────────────────────────────
    /// `finalize_relay_signer` / `cancel_relay_signer_change` with nothing pending.
    NoPendingRelaySigner = 120,
    /// `finalize_relay_signer` called before the delay elapsed.
    TimelockNotElapsed = 121,
    /// A non-zero timelock delay is configured; use propose/finalize.
    TimelockRequired = 122,

    // ── Admin proposal expiry (ADR-0002 amendment) ──────────────────────────
    /// The pending admin proposal has passed its expiry timestamp.
    AdminProposalExpired = 200,
    /// A supplied nonce did not match the caller's next expected nonce.
    InvalidNonce = 210,
    /// The relay signer is not allowlisted for the payload's anchor instance ID.
    AnchorNotAllowed = 220,

    // ── Liveness / quarantine (300+) ────────────────────────────────────────
    /// The relay signer's heartbeat is stale beyond the configured window;
    /// new registrations are refused until it heartbeats or is cleared.
    SignerQuarantined = 300,
    /// Caller is not a guardian.
    NotGuardian = 301,
    /// Guardian quorum is not configured or was not met.
    QuorumNotMetGuardian = 302,
    /// The admin role is vacant (break-glass revocation); admin-gated
    /// operations are unavailable.
    AdminVacant = 303,
}
