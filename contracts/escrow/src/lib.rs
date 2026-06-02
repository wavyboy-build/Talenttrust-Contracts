//! TalentTrust Escrow — primary contract entry points.
//!
//! # Access-control design
//!
//! Every state-mutating entry point authenticates the caller **before** any
//! storage read that could leak information about the contract. Specifically:
//!
//! - [`Escrow::create_contract`]: `client.require_auth()`
//! - [`Escrow::deposit_funds`]: `depositor.require_auth()` **and**
//!   `depositor == contract.client` (role check)
//! - [`Escrow::approve_milestone_release`]: delegated to [`approvals`] module
//! - [`Escrow::release_milestone`]: role + approval check before auth
//! - [`Escrow::refund_unreleased_milestones`]: `contract.client.require_auth()`
//!
//! # Fail-closed invariant
//!
//! Every validation that fails calls `env.panic_with_error(...)` and returns
//! `!` (diverges). No state is ever mutated unless all preceding guards pass.
//!
//! # Amount validation
//!
//! All deposit amount arithmetic uses `i128` with explicit positivity guards
//! to prevent zero/negative funding. The milestone total is computed once from
//! storage on each deposit call; there is no cached total that could drift.

#![no_std]
#![allow(clippy::derivable_impls)]
#![allow(clippy::manual_range_contains)]
#![allow(clippy::assertions_on_constants)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::collapsible_else_if)]
#![allow(clippy::redundant_field_names)]
#![allow(clippy::ptr_arg)]
#![allow(clippy::useless_vec)]
#![allow(clippy::let_and_return)]
#![allow(clippy::inconsistent_digit_grouping)]
#![allow(clippy::int_plus_one)]
#![allow(clippy::duplicated_attributes)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::redundant_clone)]
#![allow(clippy::bool_assert_comparison)]
#![allow(clippy::needless_borrow)]
#![allow(clippy::clone_on_copy)]
#![allow(clippy::module_inception)]
#![allow(clippy::single_match)]
#![allow(clippy::useless_conversion)]

mod types;
mod ttl;
mod approvals;
pub mod amount_validation;

// Re-export everything tests and sibling modules need at crate root.
pub use types::{
    Contract, ContractStatus, DataKey, DepositMode, Error, Milestone, MilestoneApprovals,
    ReleaseAuthorization,
};
pub use amount_validation::{
    safe_add_amounts, safe_subtract_amounts,
    validate_contract_total, validate_deposit_amount,
    validate_milestone_amounts, validate_single_amount,
    AmountValidationError, MAX_SINGLE_AMOUNT_STROOPS, MIN_POSITIVE_AMOUNT,
};

use soroban_sdk::{contract, contractimpl, Address, Env, Symbol, Vec};

// ─── Exported constants ───────────────────────────────────────────────────────

/// Hard cap on the total stroop value of a single escrow contract
/// (1 000 000 XLM × 10 000 000 stroops/XLM).
pub const MAX_TOTAL_ESCROW_STROOPS: i128 = 1_000_000_0000000_i128;

// ─── Contract struct ──────────────────────────────────────────────────────────

#[contract]
pub struct Escrow;

// ─── Implementation ───────────────────────────────────────────────────────────

#[contractimpl]
impl Escrow {
    // ── Smoke-test utility ────────────────────────────────────────────────

    /// Returns `to` unchanged. Used by CI smoke tests.
    pub fn hello(_env: Env, to: soroban_sdk::Symbol) -> soroban_sdk::Symbol {
        to
    }

    // ── Contract creation ─────────────────────────────────────────────────

    /// Create a new escrow contract.
    ///
    /// # Security preconditions
    /// - `client.require_auth()` — the client address must authorise this call.
    /// - `client != freelancer` — participants must be distinct.
    /// - When `release_authorization` requires an arbiter (`ArbiterOnly` or
    ///   `ClientAndArbiter`), `arbiter` must be `Some` and must differ from
    ///   both `client` and `freelancer`.
    ///
    /// # Amount preconditions
    /// - `milestones` must be non-empty.
    /// - Every milestone amount must be > 0.
    ///
    /// # Returns
    /// A monotonically increasing `contract_id` (starts at 1).
    ///
    /// # Panics / Errors
    /// - [`Error::InvalidParticipants`] — `client == freelancer`.
    /// - [`Error::MissingArbiter`] — arbiter required but `None`.
    /// - [`Error::InvalidArbiter`] — arbiter overlaps a participant.
    /// - [`Error::EmptyMilestones`] — zero milestones provided.
    /// - [`Error::AmountMustBePositive`] — any milestone amount ≤ 0.
    pub fn create_contract(
        env: Env,
        client: Address,
        freelancer: Address,
        arbiter: Option<Address>,
        milestones: Vec<i128>,
        release_authorization: ReleaseAuthorization,
    ) -> u32 {
        // 1. Authentication — must be first.
        client.require_auth();

        // 2. Participant uniqueness.
        if client == freelancer {
            env.panic_with_error(Error::InvalidParticipants);
        }

        // 3. Arbiter requirement for applicable modes.
        match release_authorization {
            ReleaseAuthorization::ArbiterOnly | ReleaseAuthorization::ClientAndArbiter => {
                if arbiter.is_none() {
                    env.panic_with_error(Error::MissingArbiter);
                }
            }
            _ => {}
        }

        // 4. Arbiter must not overlap a primary participant.
        if let Some(ref arb) = arbiter {
            if arb == &client || arb == &freelancer {
                env.panic_with_error(Error::InvalidArbiter);
            }
        }

        // 5. Milestone list must be non-empty.
        if milestones.is_empty() {
            env.panic_with_error(Error::EmptyMilestones);
        }

        // 6. Every milestone amount must be positive.
        for amount in milestones.iter() {
            if amount <= 0 {
                env.panic_with_error(Error::AmountMustBePositive);
            }
        }

        // 7. Allocate a new contract ID (start at 1 if never set).
        let id: u32 = env
            .storage()
            .persistent()
            .get::<_, u32>(&DataKey::NextContractId)
            .unwrap_or(1);

        // 8. Persist the contract metadata.
        let contract_data = Contract {
            client: client.clone(),
            freelancer: freelancer.clone(),
            arbiter: arbiter.clone(),
            status: ContractStatus::Created,
            funded_amount: 0,
            released_amount: 0,
            refunded_amount: 0,
            release_authorization,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Contract(id), &contract_data);

        // 9. Persist the individual milestone records.
        let mut milestone_vec: Vec<Milestone> = Vec::new(&env);
        for amount in milestones.iter() {
            milestone_vec.push_back(Milestone {
                amount,
                funded_amount: 0,
                released: false,
                refunded: false,
                work_evidence: None,
                refunded_amount: 0,
            });
        }
        let milestone_key = Symbol::new(&env, "milestones");
        env.storage()
            .persistent()
            .set(&(DataKey::Contract(id), milestone_key), &milestone_vec);

        // 10. Advance the counter.
        env.storage()
            .persistent()
            .set(&DataKey::NextContractId, &(id + 1));

        id
    }

    // ── Deposit ───────────────────────────────────────────────────────────

    /// Deposit funds into an existing escrow contract.
    ///
    /// # Access-control invariant — CRITICAL
    ///
    /// **Only the designated `client` may fund the contract.**
    ///
    /// This function enforces a *two-layer* access-control check:
    ///
    /// 1. **Cryptographic authentication**: `depositor.require_auth()` causes
    ///    the Soroban host to verify that the transaction was signed by, or
    ///    carries a valid auth entry for, `depositor`. If the check fails the
    ///    host aborts the invocation before any Rust code in this function
    ///    can mutate state.
    ///
    /// 2. **Role authorisation**: after authentication, the function reads
    ///    the stored `contract.client` and asserts `depositor == client`.
    ///    This prevents a valid signer who is *not* the designated client
    ///    (e.g. the freelancer, an arbiter, or any third party) from
    ///    advancing the state machine.
    ///
    /// Both checks execute in the **read-only pre-mutation phase**. Any
    /// failure panics via `env.panic_with_error` and leaves the contract
    /// state completely unchanged (fail-closed).
    ///
    /// # Why this matters
    ///
    /// Without these guards an unauthenticated actor could:
    /// - Fake a deposit to force the `Created → Funded` transition.
    /// - Unblock milestone-release paths that require `Funded` status.
    /// - Emit misleading `"deposited"` events that off-chain indexers trust.
    ///
    /// # State transitions
    /// ```text
    /// Created  →  Created   (partial deposit, funded_amount < milestone_total)
    /// Created  →  Funded    (funded_amount reaches milestone_total)
    /// ```
    ///
    /// # Arguments
    /// - `contract_id` — ID returned by [`create_contract`].
    /// - `depositor`   — Address making the deposit.  
    ///   **Must equal the stored `client`** and must satisfy `require_auth`.
    /// - `amount`      — Stroop amount to record (must be > 0).
    ///
    /// # Panics / Errors
    /// - [`Error::ContractNotFound`]    — unknown `contract_id`.
    /// - [`Error::UnauthorizedRole`]    — `depositor != contract.client`.
    /// - [`Error::InvalidState`]        — contract is not in `Created` status.
    /// - [`Error::AmountMustBePositive`]— `amount ≤ 0`.
    /// - [`Error::InsufficientFunds`]   — `amount` would exceed the milestone total.
    ///
    /// # Security assumptions
    /// - Storage TTL: persistent storage is used for contract state; it does
    ///   not expire during a normal contract lifecycle.
    /// - Overflow: `funded_amount` is `i128`; the per-deposit positivity guard
    ///   and the ceiling check (`funded_amount + amount > milestone_total`)
    ///   prevent unbounded accumulation.
    /// - Fee accounting: this function records the gross deposit amount;
    ///   protocol-fee deduction (if any) is applied at release time.
    pub fn deposit_funds(
        env: Env,
        contract_id: u32,
        depositor: Address,
        amount: i128,
    ) -> bool {
        // ── Layer 1: Cryptographic authentication ─────────────────────────
        //
        // Call require_auth() BEFORE any storage reads so that the host
        // can abort the invocation immediately if the auth check fails,
        // preventing any information leakage about the contract state.
        depositor.require_auth();

        // ── Amount positivity guard (cheap, no storage needed) ────────────
        if amount <= 0 {
            env.panic_with_error(Error::AmountMustBePositive);
        }

        // ── Load contract (fail-closed if unknown) ────────────────────────
        let mut contract: Contract = env
            .storage()
            .persistent()
            .get(&DataKey::Contract(contract_id))
            .unwrap_or_else(|| env.panic_with_error(Error::ContractNotFound));

        // ── Layer 2: Role authorisation ───────────────────────────────────
        //
        // Even a validly signed transaction must be rejected if the signer
        // is not the designated client for this specific contract.
        if depositor != contract.client {
            env.panic_with_error(Error::UnauthorizedRole);
        }

        // ── State-machine guard ───────────────────────────────────────────
        //
        // Deposits are only valid while the contract is in the `Created`
        // state.  Once `Funded`, `Completed`, `Refunded`, or `Disputed`,
        // no further deposits are accepted.
        if contract.status != ContractStatus::Created {
            env.panic_with_error(Error::InvalidState);
        }

        // ── Compute milestone total from storage ──────────────────────────
        let milestone_key = Symbol::new(&env, "milestones");
        let milestones: Vec<Milestone> = env
            .storage()
            .persistent()
            .get(&(DataKey::Contract(contract_id), milestone_key))
            .unwrap_or_else(|| env.panic_with_error(Error::ContractNotFound));

        let mut milestone_total: i128 = 0;
        for i in 0..milestones.len() {
            // Each milestone amount was validated positive at creation time,
            // so this addition cannot underflow.
            milestone_total = milestone_total
                .checked_add(milestones.get(i).unwrap().amount)
                .unwrap_or_else(|| env.panic_with_error(Error::InsufficientFunds));
        }

        // ── Ceiling guard: deposit must not exceed the unfunded balance ───
        //
        // This preserves the invariant:
        //   funded_amount ≤ milestone_total   at all times
        let new_total = contract
            .funded_amount
            .checked_add(amount)
            .unwrap_or_else(|| env.panic_with_error(Error::InsufficientFunds));

        if new_total > milestone_total {
            env.panic_with_error(Error::InsufficientFunds);
        }

        // ── Mutate state ──────────────────────────────────────────────────
        contract.funded_amount = new_total;

        if contract.funded_amount >= milestone_total {
            contract.status = ContractStatus::Funded;
        }

        env.storage()
            .persistent()
            .set(&DataKey::Contract(contract_id), &contract);

        true
    }

    // ── Approvals ─────────────────────────────────────────────────────────

    /// Record an approval for a specific milestone release.
    ///
    /// Approvals are stored in *temporary* storage with a TTL defined by
    /// [`ttl::PENDING_APPROVAL_TTL_LEDGERS`]. Once the TTL elapses, the
    /// Soroban host auto-evicts the entry; subsequent reads return `None`
    /// and are treated as "no approval" (fail-closed).
    ///
    /// The function is delegated to the [`approvals`] module which handles
    /// role checks, duplicate-approval rejection, and TTL bumping.
    ///
    /// # Errors
    /// - [`Error::ContractNotFound`]        — unknown `contract_id`.
    /// - [`Error::InvalidState`]            — contract not `Funded`.
    /// - [`Error::IndexOutOfBounds`]        — `milestone_index` out of range.
    /// - [`Error::MilestoneAlreadyReleased`]— milestone already released.
    /// - [`Error::UnauthorizedRole`]        — `caller` not authorised to approve.
    /// - [`Error::AlreadyApproved`]         — `caller` already approved this milestone.
    pub fn approve_milestone_release(
        env: Env,
        contract_id: u32,
        caller: Address,
        milestone_index: u32,
    ) -> bool {
        approvals::approve_milestone(&env, contract_id, milestone_index, &caller)
            .unwrap_or_else(|e| env.panic_with_error(e))
    }

    // ── Milestone release ─────────────────────────────────────────────────

    /// Release a funded milestone.
    ///
    /// Requires valid, unexpired approvals consistent with the contract's
    /// [`ReleaseAuthorization`] mode. Approvals are cleared after a
    /// successful release to prevent replay.
    ///
    /// # Errors
    /// - [`Error::ContractNotFound`]        — unknown `contract_id`.
    /// - [`Error::InvalidState`]            — contract not `Funded`.
    /// - [`Error::UnauthorizedRole`]        — `caller` not authorised to release.
    /// - [`Error::InsufficientApprovals`]   — approvals missing.
    /// - [`Error::IndexOutOfBounds`]        — index out of range.
    /// - [`Error::MilestoneAlreadyReleased`]— already released.
    /// - [`Error::AlreadyRefunded`]         — already refunded.
    /// - [`Error::InsufficientFunds`]       — not enough funded balance.
    pub fn release_milestone(
        env: Env,
        contract_id: u32,
        caller: Address,
        milestone_index: u32,
    ) -> bool {
        let mut contract: Contract = env
            .storage()
            .persistent()
            .get(&DataKey::Contract(contract_id))
            .unwrap_or_else(|| env.panic_with_error(Error::ContractNotFound));

        if contract.status != ContractStatus::Funded {
            env.panic_with_error(Error::InvalidState);
        }

        let is_client  = caller == contract.client;
        let is_arbiter = contract.arbiter.as_ref().map_or(false, |a| &caller == a);

        match contract.release_authorization {
            ReleaseAuthorization::ClientOnly => {
                if !is_client { env.panic_with_error(Error::UnauthorizedRole); }
            }
            ReleaseAuthorization::ArbiterOnly => {
                if !is_arbiter { env.panic_with_error(Error::UnauthorizedRole); }
            }
            ReleaseAuthorization::ClientAndArbiter => {
                if !is_client && !is_arbiter {
                    env.panic_with_error(Error::UnauthorizedRole);
                }
            }
            ReleaseAuthorization::MultiSig => {
                if !is_client && !is_arbiter {
                    env.panic_with_error(Error::UnauthorizedRole);
                }
            }
        }

        caller.require_auth();

        approvals::check_approvals(&env, &contract, contract_id, milestone_index)
            .unwrap_or_else(|e| env.panic_with_error(e));

        let milestone_key = Symbol::new(&env, "milestones");
        let mut milestones: Vec<Milestone> = env
            .storage()
            .persistent()
            .get(&(DataKey::Contract(contract_id), milestone_key.clone()))
            .unwrap_or_else(|| env.panic_with_error(Error::ContractNotFound));

        if milestone_index >= milestones.len() {
            env.panic_with_error(Error::IndexOutOfBounds);
        }

        let mut ms = milestones.get(milestone_index).unwrap();

        if ms.released { env.panic_with_error(Error::MilestoneAlreadyReleased); }
        if ms.refunded  { env.panic_with_error(Error::AlreadyRefunded); }

        let available =
            contract.funded_amount - contract.released_amount - contract.refunded_amount;
        if available < ms.amount {
            env.panic_with_error(Error::InsufficientFunds);
        }

        let ms_amount = ms.amount; // save before move
        ms.released = true;
        milestones.set(milestone_index, ms);
        contract.released_amount += ms_amount;

        approvals::clear_approvals(&env, contract_id, milestone_index);

        if milestones.iter().all(|m| m.released || m.refunded) {
            contract.status = ContractStatus::Completed;
        }

        env.storage()
            .persistent()
            .set(&(DataKey::Contract(contract_id), milestone_key), &milestones);
        env.storage()
            .persistent()
            .set(&DataKey::Contract(contract_id), &contract);

        true
    }

    // ── Refund ────────────────────────────────────────────────────────────

    /// Refund one or more unreleased milestones to the client.
    ///
    /// All validations occur before any state change (atomic read-validate-write).
    ///
    /// # Errors
    /// - [`Error::EmptyRefundRequest`]        — `milestone_indices` is empty.
    /// - [`Error::DuplicateMilestoneInRefund`]— duplicate index.
    /// - [`Error::ContractNotFound`]          — unknown `contract_id`.
    /// - [`Error::IndexOutOfBounds`]          — an index is out of range.
    /// - [`Error::AlreadyReleased`]           — milestone already released.
    /// - [`Error::AlreadyRefunded`]           — milestone already refunded.
    /// - [`Error::InsufficientFunds`]         — balance too low.
    pub fn refund_unreleased_milestones(
        env: Env,
        contract_id: u32,
        milestone_indices: Vec<u32>,
    ) -> i128 {
        if milestone_indices.is_empty() {
            env.panic_with_error(Error::EmptyRefundRequest);
        }

        // Duplicate check.
        for i in 0..milestone_indices.len() {
            for j in (i + 1)..milestone_indices.len() {
                if milestone_indices.get(i).unwrap() == milestone_indices.get(j).unwrap() {
                    env.panic_with_error(Error::DuplicateMilestoneInRefund);
                }
            }
        }

        let mut contract: Contract = env
            .storage()
            .persistent()
            .get(&DataKey::Contract(contract_id))
            .unwrap_or_else(|| env.panic_with_error(Error::ContractNotFound));

        contract.client.require_auth();

        let milestone_key = Symbol::new(&env, "milestones");
        let mut milestones: Vec<Milestone> = env
            .storage()
            .persistent()
            .get(&(DataKey::Contract(contract_id), milestone_key.clone()))
            .unwrap_or_else(|| env.panic_with_error(Error::ContractNotFound));

        // Validate-then-commit: compute total first, no mutations yet.
        let mut total_refund: i128 = 0;
        for idx in milestone_indices.iter() {
            if idx >= milestones.len() { env.panic_with_error(Error::IndexOutOfBounds); }
            let ms = milestones.get(idx).unwrap();
            if ms.released { env.panic_with_error(Error::AlreadyReleased); }
            if ms.refunded  { env.panic_with_error(Error::AlreadyRefunded); }
            total_refund += ms.amount;
        }

        let available =
            contract.funded_amount - contract.released_amount - contract.refunded_amount;
        if available < total_refund {
            env.panic_with_error(Error::InsufficientFunds);
        }

        // Commit.
        for idx in milestone_indices.iter() {
            let mut ms = milestones.get(idx).unwrap();
            ms.refunded = true;
            milestones.set(idx, ms);
        }
        contract.refunded_amount += total_refund;

        if milestones.iter().all(|m| m.released || m.refunded) {
            if milestones.iter().all(|m| m.refunded) {
                contract.status = ContractStatus::Refunded;
            } else {
                contract.status = ContractStatus::Completed;
            }
        }

        env.storage()
            .persistent()
            .set(&(DataKey::Contract(contract_id), milestone_key), &milestones);
        env.storage()
            .persistent()
            .set(&DataKey::Contract(contract_id), &contract);

        total_refund
    }

    // ── Reputation stub ───────────────────────────────────────────────────

    /// Issue a reputation score for the freelancer on a completed contract.
    ///
    /// # Errors
    /// - [`Error::ContractNotFound`]    — unknown `contract_id`.
    /// - [`Error::UnauthorizedRole`]    — `caller` is not the client.
    /// - [`Error::FreelancerMismatch`]  — `freelancer` does not match stored address.
    /// - [`Error::InvalidState`]        — contract not `Completed`.
    /// - [`Error::InvalidRating`]       — `rating` not in 1–5.
    /// - [`Error::ReputationAlreadyIssued`] — reputation already issued.
    pub fn issue_reputation(
        env: Env,
        contract_id: u32,
        caller: Address,
        freelancer: Address,
        rating: u32,
    ) -> bool {
        caller.require_auth();

        let contract: Contract = env
            .storage()
            .persistent()
            .get(&DataKey::Contract(contract_id))
            .unwrap_or_else(|| env.panic_with_error(Error::ContractNotFound));

        if caller != contract.client {
            env.panic_with_error(Error::UnauthorizedRole);
        }
        if freelancer != contract.freelancer {
            env.panic_with_error(Error::FreelancerMismatch);
        }
        if contract.status != ContractStatus::Completed {
            env.panic_with_error(Error::InvalidState);
        }
        if rating < 1 || rating > 5 {
            env.panic_with_error(Error::InvalidRating);
        }

        // Reputation key: reuse Initialized slot keyed on contract id for simplicity.
        let rep_key = (DataKey::Contract(contract_id), Symbol::new(&env, "reputation"));
        if env
            .storage()
            .persistent()
            .get::<_, bool>(&rep_key)
            .unwrap_or(false)
        {
            env.panic_with_error(Error::ReputationAlreadyIssued);
        }
        env.storage().persistent().set(&rep_key, &true);

        true
    }

    // ── Read-only queries ─────────────────────────────────────────────────

    /// Return metadata for an existing contract.
    ///
    /// # Errors
    /// - [`Error::ContractNotFound`] — unknown `contract_id`.
    pub fn get_contract(env: Env, contract_id: u32) -> Contract {
        env.storage()
            .persistent()
            .get(&DataKey::Contract(contract_id))
            .unwrap_or_else(|| env.panic_with_error(Error::ContractNotFound))
    }

    /// Return all milestones for an existing contract.
    ///
    /// # Errors
    /// - [`Error::ContractNotFound`] — unknown `contract_id` or missing milestone record.
    pub fn get_milestones(env: Env, contract_id: u32) -> Vec<Milestone> {
        let milestone_key = Symbol::new(&env, "milestones");
        env.storage()
            .persistent()
            .get(&(DataKey::Contract(contract_id), milestone_key))
            .unwrap_or_else(|| env.panic_with_error(Error::ContractNotFound))
    }

    /// Return the funded balance not yet released or refunded.
    ///
    /// # Errors
    /// - [`Error::ContractNotFound`] — unknown `contract_id`.
    pub fn get_refundable_balance(env: Env, contract_id: u32) -> i128 {
        let c: Contract = env
            .storage()
            .persistent()
            .get(&DataKey::Contract(contract_id))
            .unwrap_or_else(|| env.panic_with_error(Error::ContractNotFound));
        c.funded_amount - c.released_amount - c.refunded_amount
    }

    /// Return the current approval record for a milestone, or `None` if
    /// absent or expired (TTL elapsed).
    pub fn get_milestone_approvals(
        env: Env,
        contract_id: u32,
        milestone_index: u32,
    ) -> Option<MilestoneApprovals> {
        let key = DataKey::MilestoneApprovals(contract_id, milestone_index);
        env.storage().temporary().get(&key)
    }
}

// ─── Test modules ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod proptest;
#[cfg(test)]
mod simple_amount_test;
#[cfg(test)]
mod test;
