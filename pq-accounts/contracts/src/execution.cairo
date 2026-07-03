//! Shared account execution and validation helpers.
//!
//! The helpers keep the concrete account modules focused on public-key storage and
//! signature verification while preserving the same transaction-flow checks across all
//! verifier-backed accounts.

use core::num::traits::Zero;
use starknet::SyscallResultTrait;
use starknet::account::Call;

/// Minimum accepted transaction version for invoke, declare, and deploy-account flows.
pub const MIN_TRANSACTION_VERSION: u256 = 1;

/// Offset used by Starknet query-version transactions.
pub const QUERY_OFFSET: u256 = 0x100000000000000000000000000000000;

/// Error emitted when an account entrypoint is called by another contract.
pub const INVALID_CALLER: felt252 = 'Account: invalid caller';

/// Error emitted when the transaction version is not supported by the account.
pub const INVALID_TX_VERSION: felt252 = 'Account: invalid tx version';

/// Error emitted when the transaction signature does not verify.
pub const INVALID_SIGNATURE: felt252 = 'Account: invalid signature';

/// Asserts that `__execute__` is entered directly by the protocol.
pub fn assert_protocol_caller() {
    let sender = starknet::get_caller_address();
    assert(sender.is_zero(), INVALID_CALLER);
}

/// Asserts that the current transaction version is supported by the account.
pub fn assert_valid_tx_version() {
    let tx_info = starknet::get_tx_info().unbox();
    let tx_version: u256 = tx_info.version.into();
    if tx_version >= QUERY_OFFSET {
        assert(QUERY_OFFSET + MIN_TRANSACTION_VERSION <= tx_version, INVALID_TX_VERSION);
    } else {
        assert(MIN_TRANSACTION_VERSION <= tx_version, INVALID_TX_VERSION);
    }
}

/// Executes each call in order using Starknet's contract-call syscall.
pub fn execute_calls(calls: Span<Call>) {
    for call in calls {
        let Call { to, selector, calldata } = *call;
        starknet::syscalls::call_contract_syscall(to, selector, calldata).unwrap_syscall();
    }
}

/// Converts a boolean signature result into the SNIP-6 return convention.
pub fn signature_result(valid: bool) -> felt252 {
    if valid {
        starknet::VALIDATED
    } else {
        0
    }
}

/// Asserts a signature result and returns the Starknet validation marker.
pub fn assert_valid_signature(valid: bool) -> felt252 {
    assert(valid, INVALID_SIGNATURE);
    starknet::VALIDATED
}

/// Reports whether an interface id is supported by every account in this package.
pub fn supports_account_interface(interface_id: felt252) -> bool {
    interface_id == crate::interface::ISRC5_ID || interface_id == crate::interface::ISRC6_ID
}
