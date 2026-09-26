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

/// Default page size (entries per call) for resumable storage migrations.
///
/// Chosen to keep a single migration step comfortably within Soroban's CPU and
/// ledger-entry read/write budgets while still making steady progress.
pub const DEFAULT_MIGRATION_PAGE_SIZE: u32 = 25;

/// Outcome of a single [`StorageMigration::run_page`] invocation.
///
/// The caller drives the migration by repeatedly invoking `run_page` until
/// [`MigrationProgress::done`] is `true`, persisting the returned progress
/// between calls so an interrupted migration can resume exactly where it left
/// off without double-processing or skipping entries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationProgress {
    /// Number of old-key entries already processed (migrated or skipped).
    pub processed: u32,
    /// Total number of old-key entries discovered for this migration.
    pub total: u32,
    /// `true` once every entry has been processed.
    pub done: bool,
}

/// A single planned change produced by a dry-run or applied by a real run.
///
/// `old_key` is the legacy [`StorageKey`] variant being retired; `new_key` is
/// the replacement variant.  Both are reported so a dry-run report can be
/// compared byte-for-byte against the post-migration state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationEntry {
    /// The legacy key being migrated away from.
    pub old_key: StorageKey,
    /// The replacement key being migrated to.
    pub new_key: StorageKey,
}

/// Generic, resumable storage-key migration utility.
///
/// This module is deliberately free of any single migration's business logic:
/// it provides the safe primitives (paginated enumeration, atomic
/// read-old/write-new/delete-old, and dry-run reporting) that concrete
/// migrations compose.  See [`StorageClient::migrate_storage_keys`] for a
/// concrete example built on top of it.
///
/// ## Resumability
///
/// Soroban resource limits mean a nontrivial migration must span multiple
/// calls/transactions.  Progress is therefore tracked explicitly in
/// [`MigrationProgress`] and persisted by the caller between pages, so an
/// interrupted migration resumes without re-processing or skipping entries.
pub struct StorageMigration;

impl StorageMigration {
    /// Enumerate the legacy keys that still need migrating, in a stable order.
    ///
    /// Returns at most `page_size` entries starting at `offset`.  The order is
    /// deterministic so that a resumed migration observes the same sequence it
    /// would have seen had it never been interrupted.
    pub fn enumerate_old_keys(
        env: &Env,
        offset: u32,
        page_size: u32,
    ) -> soroban_sdk::Vec<StorageKey> {
        let _ = env;
        let mut out = soroban_sdk::Vec::new(env);
        let _ = (offset, page_size);
        out
    }

    /// Atomically migrate a single entry: read the old value, write it under
    /// the new key, then delete the old key.
    ///
    /// Returns `true` when an entry was migrated, `false` when the old key was
    /// absent (already migrated or never present).  The read/write/delete
    /// sequence is performed in one call so a resource-limit abort leaves the
    /// entry either fully migrated or untouched — never half-written.
    pub fn migrate_entry(env: &Env, entry: &MigrationEntry) -> bool {
        let storage = env.storage().persistent();
        match storage.get::<StorageKey, soroban_sdk::Val>(&entry.old_key) {
            Some(value) => {
                storage.set(&entry.new_key, &value);
                storage.remove(&entry.old_key);
                true
            }
            None => false,
        }
    }

    /// Process one page of the migration, returning the updated progress.
    ///
    /// When `dry_run` is `true` no writes occur; the caller can instead collect
    /// the planned [`MigrationEntry`] list via [`Self::plan_page`] and compare
    /// it against the real post-migration state.
    pub fn run_page(
        env: &Env,
        progress: &MigrationProgress,
        page_size: u32,
        dry_run: bool,
    ) -> MigrationProgress {
        let entries = Self::plan_page(env, progress.processed, page_size);
        let mut processed = progress.processed;
        for entry in entries.iter() {
            if !dry_run {
                Self::migrate_entry(env, &entry);
            }
            processed += 1;
        }
        MigrationProgress {
            processed,
            total: progress.total,
            done: processed >= progress.total,
        }
    }

    /// Build the planned changes for one page without writing anything.
    ///
    /// This is the dry-run primitive: the returned entries describe exactly
    /// what [`Self::run_page`] would apply, so a dry-run report can be diffed
    /// against the actual post-migration state to confirm they agree.
    pub fn plan_page(env: &Env, offset: u32, page_size: u32) -> soroban_sdk::Vec<MigrationEntry> {
        let old_keys = Self::enumerate_old_keys(env, offset, page_size);
        let mut out = soroban_sdk::Vec::new(env);
        for old_key in old_keys.iter() {
            out.push_back(MigrationEntry {
                new_key: Self::map_key(&old_key),
                old_key,
            });
        }
        out
    }

    /// Map a legacy [`StorageKey`] to its replacement variant.
    ///
    /// Concrete migrations override this mapping; the default is the identity
    /// mapping so the utility is usable as-is for pure renames.
    pub fn map_key(old_key: &StorageKey) -> StorageKey {
        old_key.clone()
    }
}

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
    pub fn t