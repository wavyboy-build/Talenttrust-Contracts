//! Deposit authorization tests for [`Escrow::deposit_funds`].
//!
//! # Coverage goals (≥ 95 % of the deposit_funds code path)
//!
//! | Layer                        | Tests                                          |
//! |------------------------------|------------------------------------------------|
//! | Cryptographic auth           | No-auth panics; mock-auth succeeds             |
//! | Role check (depositor==client| freelancer rejected; arbiter rejected; outsider|
//! | Amount positivity            | zero, negative, i128::MIN                      |
//! | Ceiling guard                | exact-total accepted; total+1 rejected         |
//! | State machine                | Created→Funded; re-deposit after Funded        |
//! | State machine (other states) | deposit after Refunded                         |
//! | Unknown contract             | ContractNotFound                               |
//! | Multi-contract isolation     | client-A cannot deposit into contract-B        |
//! | Incremental funding          | two partial deposits, accounting invariants    |
//! | Boundary: 1-stroop deposit   | minimum valid amount                           |
//! | Boundary: total-1 then 1     | partial stays Created; last stroop → Funded    |
//! | Overflow safety              | i128::MAX amount                               |

use soroban_sdk::{testutils::Address as _, vec, Address, Env};

use crate::{ContractStatus, Error, Escrow, EscrowClient, ReleaseAuthorization};

// ─── Milestone amounts used throughout ───────────────────────────────────────

const M1: i128 = 200_0000000;   //  200 XLM
const M2: i128 = 400_0000000;   //  400 XLM
const M3: i128 = 600_0000000;   //  600 XLM
const TOTAL: i128 = M1 + M2 + M3; // 1 200 XLM

// ─── Shared fixtures ──────────────────────────────────────────────────────────

/// Create a fresh environment with all-auth mocked plus a registered escrow.
fn setup() -> (Env, EscrowClient<'static>, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let cid = env.register(Escrow, ());
    let escrow = EscrowClient::new(&env, &cid);
    let client     = Address::generate(&env);
    let freelancer = Address::generate(&env);
    (env, escrow, client, freelancer)
}

/// Create a 3-milestone contract and return its id.
fn make_contract(env: &Env, escrow: &EscrowClient, client: &Address, freelancer: &Address) -> u32 {
    let milestones = vec![env, M1, M2, M3];
    escrow.create_contract(
        client, freelancer, &None, &milestones, &ReleaseAuthorization::ClientOnly,
    )
}

/// Helper: assert exact contract accounting state.
fn assert_state(
    escrow: &EscrowClient,
    cid: u32,
    status: ContractStatus,
    funded: i128,
    released: i128,
    refunded: i128,
) {
    let c = escrow.get_contract(&cid);
    assert_eq!(c.status,          status,   "status mismatch");
    assert_eq!(c.funded_amount,   funded,   "funded_amount mismatch");
    assert_eq!(c.released_amount, released, "released_amount mismatch");
    assert_eq!(c.refunded_amount, refunded, "refunded_amount mismatch");
}

// ═══════════════════════════════════════════════════════════════════════════════
// HAPPY PATH
// ═══════════════════════════════════════════════════════════════════════════════

/// Depositing the exact milestone total succeeds and transitions to Funded.
#[test]
fn client_deposits_exact_total_transitions_to_funded() {
    let (env, escrow, client, freelancer) = setup();
    let cid = make_contract(&env, &escrow, &client, &freelancer);

    let result = escrow.deposit_funds(&cid, &client, &TOTAL);

    assert!(result, "deposit_funds must return true");
    assert_state(&escrow, cid, ContractStatus::Funded, TOTAL, 0, 0);
}

/// Depositing less than the total keeps the contract in Created.
#[test]
fn partial_deposit_keeps_status_created() {
    let (env, escrow, client, freelancer) = setup();
    let cid = make_contract(&env, &escrow, &client, &freelancer);

    assert!(escrow.deposit_funds(&cid, &client, &M1));
    assert_state(&escrow, cid, ContractStatus::Created, M1, 0, 0);
}

/// Two incremental deposits that together reach the total → Funded.
#[test]
fn incremental_deposits_sum_to_funded() {
    let (env, escrow, client, freelancer) = setup();
    let cid = make_contract(&env, &escrow, &client, &freelancer);

    assert!(escrow.deposit_funds(&cid, &client, &(M1 + M2)));
    assert_state(&escrow, cid, ContractStatus::Created, M1 + M2, 0, 0);

    assert!(escrow.deposit_funds(&cid, &client, &M3));
    assert_state(&escrow, cid, ContractStatus::Funded, TOTAL, 0, 0);
}

/// The minimum valid deposit (1 stroop) is accepted.
#[test]
fn minimum_one_stroop_deposit_is_accepted() {
    let (env, escrow, client, freelancer) = setup();
    let cid = make_contract(&env, &escrow, &client, &freelancer);

    assert!(escrow.deposit_funds(&cid, &client, &1));
    assert_state(&escrow, cid, ContractStatus::Created, 1, 0, 0);
}

/// Depositing TOTAL-1 stays Created; the final single stroop → Funded.
#[test]
fn boundary_total_minus_one_then_one_stroop() {
    let (env, escrow, client, freelancer) = setup();
    let cid = make_contract(&env, &escrow, &client, &freelancer);

    assert!(escrow.deposit_funds(&cid, &client, &(TOTAL - 1)));
    assert_eq!(escrow.get_contract(&cid).status, ContractStatus::Created);

    assert!(escrow.deposit_funds(&cid, &client, &1));
    assert_eq!(escrow.get_contract(&cid).status, ContractStatus::Funded);
}

/// Three sequential deposits maintain correct accounting at every step.
#[test]
fn sequential_deposits_maintain_accounting_invariants() {
    let (env, escrow, client, freelancer) = setup();
    let cid = make_contract(&env, &escrow, &client, &freelancer);

    assert!(escrow.deposit_funds(&cid, &client, &M1));
    assert_eq!(escrow.get_refundable_balance(&cid), M1);

    assert!(escrow.deposit_funds(&cid, &client, &M2));
    assert_eq!(escrow.get_refundable_balance(&cid), M1 + M2);

    assert!(escrow.deposit_funds(&cid, &client, &M3));
    assert_eq!(escrow.get_refundable_balance(&cid), TOTAL);
    assert_eq!(escrow.get_contract(&cid).status, ContractStatus::Funded);
}

// ═══════════════════════════════════════════════════════════════════════════════
// LAYER 1: CRYPTOGRAPHIC AUTHENTICATION
// ═══════════════════════════════════════════════════════════════════════════════

/// Without `mock_all_auths`, calling deposit_funds without a real auth entry
/// must panic — the host rejects the transaction before any Rust code runs.
#[test]
#[should_panic]
fn deposit_without_auth_panics() {
    // Deliberately no env.mock_all_auths().
    let env = Env::default();
    let cid_reg = env.register(Escrow, ());
    let escrow = EscrowClient::new(&env, &cid_reg);

    let client     = Address::generate(&env);
    let freelancer = Address::generate(&env);

    // Create the contract using a separate mocked env scope.
    let contract_id = {
        let env2 = env.clone();
        env2.mock_all_auths();
        let e2 = EscrowClient::new(&env2, &cid_reg);
        e2.create_contract(
            &client, &freelancer, &None,
            &vec![&env2, M1, M2, M3],
            &ReleaseAuthorization::ClientOnly,
        )
    };

    // This call has no auth entry → must panic.
    escrow.deposit_funds(&contract_id, &client, &TOTAL);
}

// ═══════════════════════════════════════════════════════════════════════════════
// LAYER 2: ROLE AUTHORISATION (depositor must equal contract.client)
// ═══════════════════════════════════════════════════════════════════════════════

/// The freelancer has valid auth (mock_all_auths) but is NOT the client
/// → must be rejected with UnauthorizedRole.
#[test]
fn freelancer_is_rejected_with_unauthorized_role() {
    let (env, escrow, client, freelancer) = setup();
    let cid = make_contract(&env, &escrow, &client, &freelancer);

    let result = escrow.try_deposit_funds(&cid, &freelancer, &TOTAL);

    assert_eq!(result, Err(Ok(Error::UnauthorizedRole)));
}

/// An arbiter registered on the contract is NOT the client and must be rejected.
#[test]
fn arbiter_is_rejected_with_unauthorized_role() {
    let (env, escrow, client, freelancer) = setup();
    let arbiter    = Address::generate(&env);
    let milestones = vec![&env, M1, M2, M3];
    let cid = escrow.create_contract(
        &client, &freelancer,
        &Some(arbiter.clone()),
        &milestones,
        &ReleaseAuthorization::ClientAndArbiter,
    );

    let result = escrow.try_deposit_funds(&cid, &arbiter, &TOTAL);

    assert_eq!(result, Err(Ok(Error::UnauthorizedRole)));
}

/// A completely random third-party address (with mocked auth) is rejected.
#[test]
fn random_outsider_is_rejected_with_unauthorized_role() {
    let (env, escrow, client, freelancer) = setup();
    let cid      = make_contract(&env, &escrow, &client, &freelancer);
    let outsider = Address::generate(&env);

    let result = escrow.try_deposit_funds(&cid, &outsider, &TOTAL);

    assert_eq!(result, Err(Ok(Error::UnauthorizedRole)));
}

/// The client of contract A cannot deposit into contract B (different stored client).
#[test]
fn client_a_cannot_deposit_into_contract_b() {
    let (env, escrow, client_a, freelancer_a) = setup();
    let cid_a = make_contract(&env, &escrow, &client_a, &freelancer_a);

    let client_b     = Address::generate(&env);
    let freelancer_b = Address::generate(&env);
    let cid_b        = make_contract(&env, &escrow, &client_b, &freelancer_b);

    // client_a tries to fund cid_b.
    let result = escrow.try_deposit_funds(&cid_b, &client_a, &TOTAL);
    assert_eq!(result, Err(Ok(Error::UnauthorizedRole)));

    // Neither contract's balance must have changed.
    assert_eq!(escrow.get_contract(&cid_a).funded_amount, 0);
    assert_eq!(escrow.get_contract(&cid_b).funded_amount, 0);
}

// ═══════════════════════════════════════════════════════════════════════════════
// AMOUNT VALIDATION
// ═══════════════════════════════════════════════════════════════════════════════

/// Zero is not a valid deposit amount.
#[test]
fn zero_amount_returns_amount_must_be_positive() {
    let (env, escrow, client, freelancer) = setup();
    let cid = make_contract(&env, &escrow, &client, &freelancer);

    let result = escrow.try_deposit_funds(&cid, &client, &0);

    assert_eq!(result, Err(Ok(Error::AmountMustBePositive)));
}

/// Negative amounts are not valid.
#[test]
fn negative_amount_returns_amount_must_be_positive() {
    let (env, escrow, client, freelancer) = setup();
    let cid = make_contract(&env, &escrow, &client, &freelancer);

    let result = escrow.try_deposit_funds(&cid, &client, &-1_i128);

    assert_eq!(result, Err(Ok(Error::AmountMustBePositive)));
}

/// i128::MIN is also rejected as non-positive.
#[test]
fn i128_min_returns_amount_must_be_positive() {
    let (env, escrow, client, freelancer) = setup();
    let cid = make_contract(&env, &escrow, &client, &freelancer);

    let result = escrow.try_deposit_funds(&cid, &client, &i128::MIN);

    assert_eq!(result, Err(Ok(Error::AmountMustBePositive)));
}

/// Depositing one stroop more than the milestone total is rejected.
#[test]
fn deposit_one_over_total_returns_insufficient_funds() {
    let (env, escrow, client, freelancer) = setup();
    let cid = make_contract(&env, &escrow, &client, &freelancer);

    let result = escrow.try_deposit_funds(&cid, &client, &(TOTAL + 1));

    assert_eq!(result, Err(Ok(Error::InsufficientFunds)));
}

/// After a partial deposit, a second amount that would exceed the ceiling
/// is rejected; the running total must be unchanged.
#[test]
fn second_deposit_exceeding_total_is_rejected() {
    let (env, escrow, client, freelancer) = setup();
    let cid = make_contract(&env, &escrow, &client, &freelancer);

    assert!(escrow.deposit_funds(&cid, &client, &(TOTAL - 1)));

    let result = escrow.try_deposit_funds(&cid, &client, &2);
    assert_eq!(result, Err(Ok(Error::InsufficientFunds)));

    // Balance must not have changed from the first deposit.
    assert_eq!(escrow.get_contract(&cid).funded_amount, TOTAL - 1);
}

/// i128::MAX is rejected (positivity passes, but ceiling check fails).
#[test]
fn i128_max_amount_is_rejected() {
    let (env, escrow, client, freelancer) = setup();
    let cid = make_contract(&env, &escrow, &client, &freelancer);

    // Should fail (i128::MAX > TOTAL).
    let result = escrow.try_deposit_funds(&cid, &client, &i128::MAX);
    assert!(result.is_err(), "i128::MAX must be rejected");
}

// ═══════════════════════════════════════════════════════════════════════════════
// STATE-MACHINE GUARDS
// ═══════════════════════════════════════════════════════════════════════════════

/// Depositing into an unknown contract ID returns ContractNotFound.
#[test]
fn deposit_into_unknown_contract_returns_contract_not_found() {
    let (env, escrow, client, _) = setup();

    let result = escrow.try_deposit_funds(&9999, &client, &TOTAL);

    assert_eq!(result, Err(Ok(Error::ContractNotFound)));
}

/// Once the contract is Funded, further deposits must be rejected with InvalidState.
#[test]
fn deposit_after_funded_status_returns_invalid_state() {
    let (env, escrow, client, freelancer) = setup();
    let cid = make_contract(&env, &escrow, &client, &freelancer);

    assert!(escrow.deposit_funds(&cid, &client, &TOTAL));
    assert_eq!(escrow.get_contract(&cid).status, ContractStatus::Funded);

    let result = escrow.try_deposit_funds(&cid, &client, &1);

    assert_eq!(result, Err(Ok(Error::InvalidState)));
    // Balance must be unchanged.
    assert_eq!(escrow.get_contract(&cid).funded_amount, TOTAL);
}

/// Deposit after all milestones are refunded (Refunded state) → InvalidState.
#[test]
fn deposit_after_full_refund_returns_invalid_state() {
    let (env, escrow, client, freelancer) = setup();
    let cid = make_contract(&env, &escrow, &client, &freelancer);

    assert!(escrow.deposit_funds(&cid, &client, &TOTAL));
    let indices = vec![&env, 0_u32, 1_u32, 2_u32];
    escrow.refund_unreleased_milestones(&cid, &indices);
    assert_eq!(escrow.get_contract(&cid).status, ContractStatus::Refunded);

    let result = escrow.try_deposit_funds(&cid, &client, &1);

    assert_eq!(result, Err(Ok(Error::InvalidState)));
}

/// Deposit after all milestones are released (Completed state) → InvalidState.
#[test]
fn deposit_after_completed_status_returns_invalid_state() {
    let (env, escrow, client, freelancer) = setup();
    let cid = make_contract(&env, &escrow, &client, &freelancer);

    assert!(escrow.deposit_funds(&cid, &client, &TOTAL));
    // Approve and release all three milestones.
    for idx in 0_u32..3 {
        assert!(escrow.approve_milestone_release(&cid, &client, &idx));
        assert!(escrow.release_milestone(&cid, &client, &idx));
    }
    assert_eq!(escrow.get_contract(&cid).status, ContractStatus::Completed);

    let result = escrow.try_deposit_funds(&cid, &client, &1);

    assert_eq!(result, Err(Ok(Error::InvalidState)));
}

// ═══════════════════════════════════════════════════════════════════════════════
// REPLAY / REENTRANCY SAFETY
// ═══════════════════════════════════════════════════════════════════════════════

/// Replaying the exact same deposit call after Funded is blocked; the contract
/// balance must not double-count.
#[test]
fn replay_of_full_deposit_after_funded_is_blocked() {
    let (env, escrow, client, freelancer) = setup();
    let cid = make_contract(&env, &escrow, &client, &freelancer);

    assert!(escrow.deposit_funds(&cid, &client, &TOTAL));
    let result = escrow.try_deposit_funds(&cid, &client, &TOTAL);
    assert!(result.is_err(), "replay must be rejected");
    assert_eq!(escrow.get_contract(&cid).funded_amount, TOTAL, "balance must not double");
}

// ═══════════════════════════════════════════════════════════════════════════════
// INTERACTION WITH OTHER FUNCTIONS (system integrity)
// ═══════════════════════════════════════════════════════════════════════════════

/// After a full refund, a re-create + deposit by the client works on the new id.
#[test]
fn client_can_create_new_contract_and_deposit_after_refund() {
    let (env, escrow, client, freelancer) = setup();
    let cid1 = make_contract(&env, &escrow, &client, &freelancer);

    assert!(escrow.deposit_funds(&cid1, &client, &TOTAL));
    let indices = vec![&env, 0_u32, 1_u32, 2_u32];
    escrow.refund_unreleased_milestones(&cid1, &indices);

    // Create a brand-new contract and deposit into it.
    let cid2 = make_contract(&env, &escrow, &client, &freelancer);
    assert!(escrow.deposit_funds(&cid2, &client, &TOTAL));
    assert_eq!(escrow.get_contract(&cid2).status, ContractStatus::Funded);
}

/// Partial funding followed by a partial refund (after funding) preserves the
/// correct refundable balance.
#[test]
fn partial_funding_then_partial_refund_preserves_balance() {
    let (env, escrow, client, freelancer) = setup();
    let cid = make_contract(&env, &escrow, &client, &freelancer);

    // Fund fully first.
    assert!(escrow.deposit_funds(&cid, &client, &TOTAL));
    assert_eq!(escrow.get_contract(&cid).status, ContractStatus::Funded);

    // Refund milestone 2 only (M3 = 600).
    let indices = vec![&env, 2_u32];
    escrow.refund_unreleased_milestones(&cid, &indices);

    let c = escrow.get_contract(&cid);
    assert_eq!(c.funded_amount,   TOTAL);
    assert_eq!(c.refunded_amount, M3);
    assert_eq!(escrow.get_refundable_balance(&cid), TOTAL - M3);
}

/// Approve + release one milestone after full funding and verify accounting.
#[test]
fn release_after_full_funding_updates_accounting() {
    let (env, escrow, client, freelancer) = setup();
    let cid = make_contract(&env, &escrow, &client, &freelancer);

    assert!(escrow.deposit_funds(&cid, &client, &TOTAL));

    assert!(escrow.approve_milestone_release(&cid, &client, &0));
    assert!(escrow.release_milestone(&cid, &client, &0));

    let c = escrow.get_contract(&cid);
    assert_eq!(c.funded_amount,   TOTAL);
    assert_eq!(c.released_amount, M1);
    assert_eq!(escrow.get_refundable_balance(&cid), TOTAL - M1);
}
