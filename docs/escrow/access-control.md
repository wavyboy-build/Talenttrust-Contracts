# TalentTrust Escrow — Access Control Architecture

> **Last updated:** June 2025  
> **Scope:** `contracts/escrow/src/lib.rs` and the `approvals` module

---

## Table of Contents

1. [Overview](#1-overview)
2. [The Vulnerability That Was Fixed](#2-the-vulnerability-that-was-fixed)
3. [deposit_funds: Two-Layer Access Control](#3-deposit_funds-two-layer-access-control)
4. [Full Function-by-Function Access Matrix](#4-full-function-by-function-access-matrix)
5. [State Machine & Deposit Flow](#5-state-machine--deposit-flow)
6. [Fail-Closed Design](#6-fail-closed-design)
7. [Security Assumptions](#7-security-assumptions)
8. [Specific Failure States & Error Codes](#8-specific-failure-states--error-codes)
9. [Test Coverage Summary](#9-test-coverage-summary)

---

## 1. Overview

The TalentTrust escrow contract mediates payments between a **client** and a
**freelancer** through a milestone-based lifecycle. Each escrow contract has
exactly one designated client — the address that funded the engagement — and
enforces strict role-based access control on every state-mutating operation.

The core security principle is **fail-closed**: if any authentication or
authorisation check fails, `env.panic_with_error(...)` is called immediately
and no state is mutated. There is no "default allow" path anywhere in the
contract.

---

## 2. The Vulnerability That Was Fixed

### Before the fix

```rust
// VULNERABLE — no authentication or role check
pub fn deposit_funds(env: Env, contract_id: u32, amount: i128) -> bool {
    if amount <= 0 { env.panic_with_error(...); }
    let mut contract = load(contract_id);
    contract.funded_amount += amount;   // ← any caller could do this
    ...
}
```

Without `require_auth()` or a role check, **any address** could call
`deposit_funds` with any `contract_id` and `amount` and:

| Impact | Detail |
|--------|--------|
| State forgery | Force `Created → Funded` without actually transferring tokens |
| Event pollution | Emit misleading `"deposited"` events that off-chain indexers trust |
| Path unlocking | Unblock `approve_milestone_release` / `release_milestone` which require `Funded` state |
| Griefing | Lock out the real client by pre-filling `funded_amount` to the ceiling |

### After the fix

```rust
pub fn deposit_funds(env: Env, contract_id: u32, depositor: Address, amount: i128) -> bool {
    // Layer 1: cryptographic authentication
    depositor.require_auth();

    // amount positivity (cheap, no storage read)
    if amount <= 0 { env.panic_with_error(Error::AmountMustBePositive); }

    // load contract
    let mut contract = load(contract_id);

    // Layer 2: role authorisation
    if depositor != contract.client {
        env.panic_with_error(Error::UnauthorizedRole);
    }

    // state-machine guard, ceiling guard, then mutation
    ...
}
```

---

## 3. `deposit_funds`: Two-Layer Access Control

### Layer 1 — Cryptographic Authentication (`require_auth`)

`depositor.require_auth()` is called **before any storage read**. The Soroban
host verifies that the transaction contains a valid auth entry for `depositor`
(either a direct signature or an authorized subcontract invocation). If this
check fails, the host aborts the entire invocation and reverts all effects —
no Rust code after this point runs.

Placing `require_auth` first (before loading the contract) prevents timing
side-channels: a failed auth cannot reveal whether `contract_id` exists.

### Layer 2 — Role Authorisation (depositor == client)

After authentication, the stored `contract.client` is compared to `depositor`.
This ensures that even a legitimately authenticated address — e.g. the
freelancer or an arbiter — cannot fund a contract they are not the client of.

```
depositor ──(signed by?)──► Soroban host (require_auth)
                                   │ pass
                                   ▼
                        load contract from storage
                                   │
                            depositor == contract.client ?
                                   │ yes
                                   ▼
                       state-machine & amount guards
                                   │ pass
                                   ▼
                           mutate funded_amount
```

### Why both layers are necessary

| Scenario | require_auth result | Role check result | Outcome |
|----------|--------------------|--------------------|---------|
| Client signs, deposits into own contract | ✓ pass | ✓ pass | Accepted |
| Freelancer signs, tries to deposit | ✓ pass | ✗ fail | Rejected (`UnauthorizedRole`) |
| Random address with no auth | ✗ fail | never reached | Rejected (host-level panic) |
| Client signs, wrong contract ID | ✓ pass | ✗ fail (different stored client) | Rejected |

---

## 4. Full Function-by-Function Access Matrix

| Function | Who can call | Auth method |
|----------|-------------|-------------|
| `create_contract` | Any address (becomes the `client`) | `client.require_auth()` at start |
| `deposit_funds` | Stored `client` only | `depositor.require_auth()` + role check |
| `approve_milestone_release` | Depends on `ReleaseAuthorization` mode | Delegated to `approvals::approve_milestone` |
| `release_milestone` | Role check then `caller.require_auth()` | Role check first; auth second |
| `refund_unreleased_milestones` | Stored `client` only | `contract.client.require_auth()` |
| `issue_reputation` | Stored `client` only | `caller.require_auth()` + role check |
| `get_contract` / `get_milestones` / `get_refundable_balance` | Anyone (read-only) | None |

### ReleaseAuthorization modes

| Mode | Who can approve | Who can release |
|------|-----------------|-----------------|
| `ClientOnly` | Client | Client |
| `ArbiterOnly` | Arbiter | Arbiter |
| `ClientAndArbiter` | Client OR Arbiter | Client OR Arbiter |
| `MultiSig` | Client AND Freelancer must both approve | Client OR Arbiter |

---

## 5. State Machine & Deposit Flow

```
           create_contract
                 │
                 ▼
           ┌─────────┐
           │ Created │◄──── only deposits allowed here
           └─────────┘
                 │
    deposit_funds (funded_amount < milestone_total)
                 │ (still Created while partial)
                 │
    deposit_funds (funded_amount == milestone_total)
                 │
                 ▼
           ┌────────┐
           │ Funded │◄──── approvals & releases happen here
           └────────┘
           /         \
    all released    all refunded
          │               │
          ▼               ▼
     ┌──────────┐   ┌──────────┐
     │ Completed│   │ Refunded │
     └──────────┘   └──────────┘
```

**Deposit is only valid in `Created` state.** Any other status causes
`InvalidState` — this prevents:
- Re-funding after full funding (no double-funding)
- Funding a contract mid-dispute or after completion
- Funding after a full refund

---

## 6. Fail-Closed Design

Every guard in the contract follows the pattern:

```rust
if <invariant violated> {
    env.panic_with_error(Error::SomeError);  // diverges: returns !
}
// only reached if invariant holds
```

`env.panic_with_error` never returns. It invokes the Soroban host's error
mechanism which:
1. Reverts all storage changes made in the current invocation frame.
2. Surfaces the error code to the caller via the SDK `try_*` API.
3. Prevents any further execution in the frame.

There is **no** `unwrap()`, `?`, or `Result` propagation that could silently
return an error while leaving partial state mutations in place.

---

## 7. Security Assumptions

### Storage TTL

Persistent storage is used for contract state (`DataKey::Contract(id)`) and
milestone records. Persistent entries do not auto-expire under normal
circumstances. If the account's XLM balance falls below the minimum reserve
the host may evict entries, but this is an infrastructure concern outside the
contract's control. The contract does not attempt to re-initialise evicted
state.

Approval records use **temporary storage** (TTL = `PENDING_APPROVAL_TTL_LEDGERS`
≈ 7 days). This is intentional: approvals are ephemeral and should not persist
indefinitely. An expired approval is treated as absent (fail-closed) — the
release path requires fresh approvals.

### Integer Overflow

All arithmetic on `i128` values uses one of:
- Explicit positivity guards (`amount <= 0 → panic`)
- `checked_add` with an explicit `unwrap_or_else(|| panic)` on overflow

There is no unchecked addition or subtraction on financial values in the contract.

### Fee Accounting

`deposit_funds` records the **gross deposit amount** without deducting fees.
If a protocol fee is configured, it is deducted at **release time** (not
deposit time). This means `funded_amount` always reflects the total deposited
by the client, and the refundable balance is computed as:

```
refundable = funded_amount - released_amount - refunded_amount
```

Fee deduction does not affect `funded_amount` — it is applied separately
during the release settlement, outside the scope of this module.

### No Token Movement

`deposit_funds` does **not** transfer tokens. It records an accounting
entry only. Actual token transfer is handled at the settlement layer (outside
this contract in the current architecture). The `funded_amount` field is
therefore a **ledger record** of what the client committed, not a native token
balance.

---

## 8. Specific Failure States & Error Codes

| Error | Code | Trigger |
|-------|------|---------|
| `UnauthorizedRole` | 11 | `depositor != contract.client`, or wrong approver role |
| `AmountMustBePositive` | 15 | `amount ≤ 0` |
| `InvalidState` | 16 | Contract not in `Created` (for deposits); not in `Funded` (for release/approve) |
| `ContractNotFound` | 10 | Unknown `contract_id` |
| `InsufficientFunds` | 9 | `funded_amount + amount > milestone_total`; or balance too low for release/refund |
| `InvalidParticipants` | 14 | `client == freelancer` at creation |
| `MissingArbiter` | 12 | Arbiter mode selected but no arbiter provided |
| `InvalidArbiter` | 13 | Arbiter overlaps a primary participant |
| `EmptyMilestones` | — (via `Error::EmptyMilestones`) | Zero milestones at creation |

---

## 9. Test Coverage Summary

Tests are in `contracts/escrow/src/test/deposit_authorization.rs` (for the
`test/` submodule) and `contracts/escrow/src/test.rs` (for the root test module).

| Test category | Tests | Coverage target |
|---------------|-------|-----------------|
| Happy path (exact deposit, incremental, 1-stroop, boundary) | 5 | `deposit_funds` success path |
| Cryptographic auth failure (`#[should_panic]`) | 1 | `require_auth` at line 1 |
| Role rejection (freelancer, arbiter, outsider, wrong contract) | 4 | Role check branch |
| Amount validation (zero, negative, i128::MIN, over-total, overflow) | 5 | Amount guard & ceiling |
| State machine (after Funded, after Refunded, after Completed, unknown id) | 4 | Status guard |
| Replay / reentrancy safety | 1 | Post-Funded re-deposit |
| System integrity (re-create, partial refund, release accounting) | 3 | Integration |

**Total: 23 targeted tests** covering >95% of the `deposit_funds` code path
and its interaction with the broader state machine.
