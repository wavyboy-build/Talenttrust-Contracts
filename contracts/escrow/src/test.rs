#![cfg(test)]

use soroban_sdk::{symbol_short, testutils::Address as _, vec, Address, Env, Vec};

use crate::{Contract, ContractStatus, Escrow, EscrowClient, Milestone, ReleaseAuthorization};

// Test helper functions
pub fn setup() -> (Env, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let client_addr = Address::generate(&env);
    let freelancer_addr = Address::generate(&env);
    (env, client_addr, freelancer_addr)
}

pub fn setup_env() -> Env {
    let env = Env::default();
    env.mock_all_auths();
    env
}

pub fn register_escrow(env: &Env) -> EscrowClient {
    let contract_id = env.register(Escrow, ());
    EscrowClient::new(env, &contract_id)
}

pub fn register_client(env: &Env) -> EscrowClient {
    let contract_id = env.register(Escrow, ());
    EscrowClient::new(env, &contract_id)
}

pub fn generated_participants(env: &Env) -> (Address, Address, Address) {
    let client_addr = Address::generate(env);
    let freelancer_addr = Address::generate(env);
    let arbiter_addr = Address::generate(env);
    (client_addr, freelancer_addr, arbiter_addr)
}

pub fn default_milestones(env: &Env) -> Vec<i128> {
    vec![env, 1000_0000000_i128, 2000_0000000_i128, 3000_0000000_i128]
}

pub fn total_milestones() -> i128 {
    6000_0000000_i128
}

pub fn create_client(env: &Env) -> EscrowClient {
    let contract_id = env.register(Escrow, ());
    EscrowClient::new(env, &contract_id)
}

pub fn create_default_contract(
    env: &Env,
    client: &EscrowClient,
    client_addr: &Address,
    freelancer_addr: &Address,
) -> u32 {
    let milestones = vec![env, 200_0000000_i128, 400_0000000_i128, 600_0000000_i128];
    client.create_contract(
        client_addr,
        freelancer_addr,
        &None,
        &milestones,
        &ReleaseAuthorization::ClientOnly,
    )
}

pub fn assert_contract_state(
    contract: Contract,
    expected_status: ContractStatus,
    expected_funded: i128,
    expected_released: i128,
    expected_refunded: i128,
) {
    assert_eq!(contract.status, expected_status);
    assert_eq!(contract.funded_amount, expected_funded);
    assert_eq!(contract.released_amount, expected_released);
    assert_eq!(contract.refunded_amount, expected_refunded);
}

pub fn assert_milestone_flags(
    milestones: Vec<Milestone>,
    index: u32,
    expected_released: bool,
    expected_refunded: bool,
) {
    let milestone = milestones.get(index).unwrap();
    assert_eq!(milestone.released, expected_released);
    assert_eq!(milestone.refunded, expected_refunded);
}

#[test]
fn test_hello() {
    let env = Env::default();
    let contract_id = env.register(Escrow, ());
    let client = EscrowClient::new(&env, &contract_id);

    let result = client.hello(&symbol_short!("World"));
    assert_eq!(result, symbol_short!("World"));
}

#[test]
fn test_create_contract() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(Escrow, ());
    let client = EscrowClient::new(&env, &contract_id);

    let client_addr = Address::generate(&env);
    let freelancer_addr = Address::generate(&env);
    let milestones = vec![&env, 200_0000000_i128, 400_0000000_i128, 600_0000000_i128];

    let id = client.create_contract(
        &client_addr,
        &freelancer_addr,
        &None,
        &milestones,
        &ReleaseAuthorization::ClientOnly,
    );
    assert_eq!(id, 1);
}

#[test]
fn test_deposit_funds() {
    let (env, client_addr, freelancer_addr) = setup();
    let client = create_client(&env);
    let contract_id = create_default_contract(&env, &client, &client_addr, &freelancer_addr);

    let result = client.deposit_funds(&contract_id, &client_addr, &1_000_0000000);
    assert!(result);
}

#[test]
fn test_release_milestone() {
    let (env, client_addr, freelancer_addr) = setup();
    let client = create_client(&env);
    let contract_id = create_default_contract(&env, &client, &client_addr, &freelancer_addr);

    assert!(client.deposit_funds(&contract_id, &client_addr, &1_200_0000000_i128));
    assert!(client.approve_milestone_release(&contract_id, &client_addr, &0));
    let result = client.release_milestone(&contract_id, &client_addr, &0);
    assert!(result);
}

// Include test modules
#[path = "test/deposit_authorization.rs"]
mod deposit_authorization;
#[path = "refund.rs"]
mod refund;
#[path = "release.rs"]
mod release;
#[path = "deposit.rs"]
mod deposit;
#[path = "create_contract.rs"]
mod create_contract;
mod access_control;
mod approval_expiry;
mod hello;
mod lifecycle;
mod flows;
mod security;
mod storage;
mod persistence;
mod performance;
mod input_sanitization_amounts;
mod input_sanitization_identities;
mod milestone_schedule;
mod governance;
mod emergency_controls;
mod pause_controls;
mod timeout_tests;
mod mainnet_readiness;
mod client_migration;
