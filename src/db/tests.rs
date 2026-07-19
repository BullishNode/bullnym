use super::*;

const ALL_STATUSES: &[SwapStatus] = &[
    SwapStatus::Pending,
    SwapStatus::LockupMempool,
    SwapStatus::LockupConfirmed,
    SwapStatus::Claiming,
    SwapStatus::Claimed,
    SwapStatus::ClaimFailed,
    SwapStatus::Expired,
    SwapStatus::ClaimStuck,
    SwapStatus::MrhDirect,
    SwapStatus::LockupRefunded,
];

const ALL_CHAIN_SWAP_STATUSES: &[ChainSwapStatus] = &[
    ChainSwapStatus::Pending,
    ChainSwapStatus::UserLockMempool,
    ChainSwapStatus::UserLockConfirmed,
    ChainSwapStatus::ServerLockMempool,
    ChainSwapStatus::ServerLockConfirmed,
    ChainSwapStatus::Claiming,
    ChainSwapStatus::Claimed,
    ChainSwapStatus::ClaimFailed,
    ChainSwapStatus::ClaimStuck,
    ChainSwapStatus::Expired,
    ChainSwapStatus::LockupFailed,
    ChainSwapStatus::Refunded,
    ChainSwapStatus::RefundDue,
    ChainSwapStatus::Refunding,
];

#[test]
fn swap_status_round_trip() {
    for status in ALL_STATUSES {
        let s = status.to_string();
        let parsed: SwapStatus = s.parse().unwrap();
        assert_eq!(parsed, *status);
    }
}

#[test]
fn swap_status_terminal() {
    assert!(SwapStatus::Claimed.is_terminal());
    assert!(SwapStatus::Expired.is_terminal());
    assert!(SwapStatus::ClaimStuck.is_terminal());
    assert!(SwapStatus::MrhDirect.is_terminal());
    assert!(SwapStatus::LockupRefunded.is_terminal());
    assert!(!SwapStatus::Pending.is_terminal());
    assert!(!SwapStatus::LockupMempool.is_terminal());
    assert!(!SwapStatus::LockupConfirmed.is_terminal());
    assert!(!SwapStatus::Claiming.is_terminal());
    assert!(!SwapStatus::ClaimFailed.is_terminal());
}

#[test]
fn swap_status_claimable() {
    assert!(SwapStatus::LockupMempool.is_claimable());
    assert!(SwapStatus::LockupConfirmed.is_claimable());
    assert!(SwapStatus::Claiming.is_claimable());
    assert!(SwapStatus::ClaimFailed.is_claimable());
    assert!(!SwapStatus::Pending.is_claimable());
    assert!(!SwapStatus::Claimed.is_claimable());
    assert!(!SwapStatus::Expired.is_claimable());
    assert!(!SwapStatus::ClaimStuck.is_claimable());
    assert!(!SwapStatus::MrhDirect.is_claimable());
    assert!(!SwapStatus::LockupRefunded.is_claimable());
}

#[test]
fn swap_status_terminal_disjoint_from_claimable() {
    for status in ALL_STATUSES {
        assert!(
            !(status.is_terminal() && status.is_claimable()),
            "status {status} is both terminal and claimable"
        );
    }
}

#[test]
fn swap_status_unknown_rejected() {
    assert!("garbage".parse::<SwapStatus>().is_err());
}

#[test]
fn chain_swap_status_round_trip() {
    for status in ALL_CHAIN_SWAP_STATUSES {
        let s = status.to_string();
        let parsed: ChainSwapStatus = s.parse().unwrap();
        assert_eq!(parsed, *status);
    }
}

#[test]
fn chain_swap_status_terminal() {
    assert!(ChainSwapStatus::Claimed.is_terminal());
    assert!(ChainSwapStatus::ClaimStuck.is_terminal());
    assert!(ChainSwapStatus::Expired.is_terminal());
    assert!(ChainSwapStatus::LockupFailed.is_terminal());
    assert!(ChainSwapStatus::Refunded.is_terminal());
    assert!(!ChainSwapStatus::Pending.is_terminal());
    assert!(!ChainSwapStatus::UserLockMempool.is_terminal());
    assert!(!ChainSwapStatus::UserLockConfirmed.is_terminal());
    assert!(!ChainSwapStatus::ServerLockMempool.is_terminal());
    assert!(!ChainSwapStatus::ServerLockConfirmed.is_terminal());
    assert!(!ChainSwapStatus::Claiming.is_terminal());
    assert!(!ChainSwapStatus::ClaimFailed.is_terminal());
    // refund_due is the non-terminal join point of the refund waterfall — the
    // reconciler must keep revisiting it until it drains to claimed/refunded.
    assert!(!ChainSwapStatus::RefundDue.is_terminal());
    // refunding is a non-terminal in-flight recovery — ambiguity replays the
    // write-ahead bytes, so the reconciler must keep revisiting it.
    assert!(!ChainSwapStatus::Refunding.is_terminal());
}

#[test]
fn chain_swap_status_unknown_rejected() {
    assert!("garbage".parse::<ChainSwapStatus>().is_err());
}
