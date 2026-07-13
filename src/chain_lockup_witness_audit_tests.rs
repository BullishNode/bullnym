use std::str::FromStr;

use bitcoin::{Address, Network};

use super::{manifest_set_fixture, provider_response};
use crate::chain_lockup_witness_audit::{
    audit_manifest_set_against_chain_lockup_witness_v1, ChainLockupConflictFieldV1,
    ChainLockupFindingClassificationV1, ChainLockupInclusionV1,
    ChainLockupManifestClassificationV1, ChainLockupSpendV1, ChainLockupWitnessAuditError,
    ChainLockupWitnessChainV1, PrevalidatedChainLockupObservationV1,
    MAX_CHAIN_LOCKUP_WITNESS_ADDRESS_BYTES_V1, MAX_CHAIN_LOCKUP_WITNESS_MANIFESTS_V1,
    MAX_CHAIN_LOCKUP_WITNESS_OBSERVATIONS_PER_MANIFEST_V1,
    MAX_CHAIN_LOCKUP_WITNESS_OBSERVATIONS_V1, MAX_CHAIN_LOCKUP_WITNESS_SCRIPT_HEX_CHARS_V1,
};
use crate::swap_manifest::SwapManifestV1;
use uuid::Uuid;

fn manifest(
    sequence: u64,
    previous_manifest_id: Option<Uuid>,
    discriminator: u128,
    scalar: u8,
) -> SwapManifestV1 {
    let claim_index = i64::try_from(discriminator * 2 + 100).unwrap();
    let refund_index = claim_index + 1;
    manifest_set_fixture(
        sequence,
        previous_manifest_id,
        discriminator,
        claim_index,
        refund_index,
        refund_index + 2,
        scalar,
        scalar + 1,
        scalar + 2,
    )
}

fn bitcoin_script(address: &str) -> String {
    let address = Address::from_str(address)
        .unwrap()
        .require_network(Network::Bitcoin)
        .unwrap();
    hex::encode(address.script_pubkey().as_bytes())
}

fn txid(discriminator: u64) -> String {
    format!("{discriminator:064x}")
}

fn observation(
    manifest: &SwapManifestV1,
    discriminator: u64,
) -> PrevalidatedChainLockupObservationV1 {
    PrevalidatedChainLockupObservationV1 {
        manifest_id: manifest.restore_identity.manifest_id,
        chain_swap_id: manifest.restore_identity.chain_swap_id,
        chain: ChainLockupWitnessChainV1::BitcoinMainnet,
        lockup_address: manifest.creation.lockup_address.clone(),
        lockup_script_pubkey_hex: bitcoin_script(&manifest.creation.lockup_address),
        txid: txid(discriminator),
        vout: u32::try_from(discriminator % 8).unwrap(),
        amount_sat: u64::try_from(manifest.creation.user_lock_amount_sat).unwrap(),
        inclusion: ChainLockupInclusionV1::Mempool,
        spend: ChainLockupSpendV1::Unspent,
    }
}

fn confirmed(confirmations: u32, height: u32, byte: u8) -> ChainLockupInclusionV1 {
    ChainLockupInclusionV1::Confirmed {
        confirmations,
        block_height: height,
        block_hash: format!("{byte:02x}").repeat(32),
    }
}

fn two_manifests() -> (SwapManifestV1, SwapManifestV1) {
    let first = manifest(1, None, 1_701, 0x31);
    let second = manifest(2, Some(first.restore_identity.manifest_id), 1_702, 0x41);
    (first, second)
}

#[test]
fn chain_lockup_audit_accepts_empty_and_classifies_a_complete_empty_scan_as_missing() {
    let empty = audit_manifest_set_against_chain_lockup_witness_v1(&[], &[]).unwrap();
    assert_eq!(empty.manifest_set.manifest_count, 0);
    assert!(empty.manifests.is_empty());
    assert_eq!(empty.observation_count, 0);

    let one = manifest(1, None, 1_703, 0x51);
    let missing =
        audit_manifest_set_against_chain_lockup_witness_v1(std::slice::from_ref(&one), &[])
            .unwrap();
    assert_eq!(missing.manifests.len(), 1);
    assert_eq!(
        missing.manifests[0].classification,
        ChainLockupManifestClassificationV1::Missing
    );
    assert!(missing.manifests[0].findings.is_empty());
    assert_eq!(missing.missing_manifest_count, 1);
}

#[test]
fn chain_lockup_audit_classifies_exact_unconfirmed_and_confirmed_outputs() {
    let (first, second) = two_manifests();
    let first_observation = observation(&first, 11);
    let mut second_observation = observation(&second, 12);
    second_observation.inclusion = confirmed(3, 910_000, 0xa1);

    let audit = audit_manifest_set_against_chain_lockup_witness_v1(
        &[second.clone(), first.clone()],
        &[second_observation, first_observation],
    )
    .unwrap();
    assert_eq!(
        audit.manifests[0].manifest_id,
        first.restore_identity.manifest_id
    );
    assert_eq!(
        audit.manifests[1].manifest_id,
        second.restore_identity.manifest_id
    );
    assert_eq!(
        audit.manifests[0].classification,
        ChainLockupManifestClassificationV1::Unconfirmed
    );
    assert_eq!(
        audit.manifests[1].classification,
        ChainLockupManifestClassificationV1::Confirmed
    );
    assert_eq!(audit.unconfirmed_manifest_count, 1);
    assert_eq!(audit.confirmed_manifest_count, 1);
}

#[test]
fn chain_lockup_audit_classifies_mempool_and_confirmed_spends_without_policy() {
    let (first, second) = two_manifests();
    let mut mempool_spend = observation(&first, 21);
    mempool_spend.spend = ChainLockupSpendV1::Spent {
        spending_txid: txid(121),
        inclusion: ChainLockupInclusionV1::Mempool,
    };
    let mut confirmed_spend = observation(&second, 22);
    confirmed_spend.inclusion = confirmed(5, 910_000, 0xa2);
    confirmed_spend.spend = ChainLockupSpendV1::Spent {
        spending_txid: txid(122),
        inclusion: confirmed(2, 910_003, 0xa3),
    };

    let audit = audit_manifest_set_against_chain_lockup_witness_v1(
        &[first, second],
        &[mempool_spend, confirmed_spend],
    )
    .unwrap();
    assert!(audit.manifests.iter().all(|manifest| {
        manifest.classification == ChainLockupManifestClassificationV1::Spent
            && manifest.findings[0].classification == ChainLockupFindingClassificationV1::Spent
    }));
    assert_eq!(audit.spent_manifest_count, 2);
}

#[test]
fn chain_lockup_audit_reports_original_amount_mismatch_as_conflict() {
    let one = manifest(1, None, 1_704, 0x61);
    for delta in [-1_i64, 1] {
        let mut observed = observation(&one, u64::try_from(31 + delta).unwrap());
        observed.amount_sat = u64::try_from(one.creation.user_lock_amount_sat + delta).unwrap();
        let audit = audit_manifest_set_against_chain_lockup_witness_v1(
            std::slice::from_ref(&one),
            &[observed],
        )
        .unwrap();
        assert_eq!(
            audit.manifests[0].classification,
            ChainLockupManifestClassificationV1::Conflicting
        );
        assert_eq!(
            audit.manifests[0].findings[0].classification,
            ChainLockupFindingClassificationV1::Conflicting {
                fields: vec![ChainLockupConflictFieldV1::ExpectedAmount]
            }
        );
    }
}

#[test]
fn chain_lockup_audit_classifies_a_canonical_wrong_chain_target_as_conflicting() {
    let one = manifest(1, None, 1_705, 0x71);
    let response = provider_response(&one);
    let liquid_address = response.claim_details.lockup_address;
    let liquid_script = boltz_client::elements::Address::from_str(&liquid_address)
        .unwrap()
        .script_pubkey();
    let mut observed = observation(&one, 41);
    observed.chain = ChainLockupWitnessChainV1::LiquidMainnet;
    observed.lockup_address = liquid_address;
    observed.lockup_script_pubkey_hex = hex::encode(liquid_script.as_bytes());

    let audit =
        audit_manifest_set_against_chain_lockup_witness_v1(std::slice::from_ref(&one), &[observed])
            .unwrap();
    assert_eq!(
        audit.manifests[0].findings[0].classification,
        ChainLockupFindingClassificationV1::Conflicting {
            fields: vec![
                ChainLockupConflictFieldV1::Chain,
                ChainLockupConflictFieldV1::LockupAddress,
                ChainLockupConflictFieldV1::LockupScriptPubkey,
            ]
        }
    );
}

#[test]
fn chain_lockup_audit_conflict_summary_has_priority_but_preserves_all_findings() {
    let one = manifest(1, None, 1_706, 0x21);
    let mut unconfirmed = observation(&one, 51);
    let mut confirmed_observation = observation(&one, 49);
    confirmed_observation.inclusion = confirmed(2, 920_000, 0xb1);
    let mut spent = observation(&one, 50);
    spent.spend = ChainLockupSpendV1::Spent {
        spending_txid: txid(150),
        inclusion: ChainLockupInclusionV1::Mempool,
    };
    let mut conflicting = observation(&one, 48);
    conflicting.amount_sat += 1;
    unconfirmed.vout = 7;

    let audit = audit_manifest_set_against_chain_lockup_witness_v1(
        &[one],
        &[unconfirmed, confirmed_observation, spent, conflicting],
    )
    .unwrap();
    assert_eq!(
        audit.manifests[0].classification,
        ChainLockupManifestClassificationV1::Conflicting
    );
    assert_eq!(audit.manifests[0].findings.len(), 4);
    assert_eq!(
        audit.manifests[0]
            .findings
            .iter()
            .map(|finding| finding.txid.as_str())
            .collect::<Vec<_>>(),
        [txid(48), txid(49), txid(50), txid(51)]
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
    );
}

#[test]
fn chain_lockup_audit_rejects_partial_crossed_and_unknown_association_tags() {
    let (first, second) = two_manifests();
    let mut wrong_swap = observation(&first, 61);
    wrong_swap.chain_swap_id = Uuid::from_u128(9_001);
    assert_eq!(
        audit_manifest_set_against_chain_lockup_witness_v1(
            &[first.clone(), second.clone()],
            &[wrong_swap],
        )
        .unwrap_err(),
        ChainLockupWitnessAuditError::PartialObservationIdentity
    );

    let mut wrong_manifest = observation(&first, 62);
    wrong_manifest.manifest_id = Uuid::from_u128(9_002);
    assert_eq!(
        audit_manifest_set_against_chain_lockup_witness_v1(
            &[first.clone(), second.clone()],
            &[wrong_manifest],
        )
        .unwrap_err(),
        ChainLockupWitnessAuditError::PartialObservationIdentity
    );

    let mut crossed = observation(&first, 63);
    crossed.chain_swap_id = second.restore_identity.chain_swap_id;
    assert_eq!(
        audit_manifest_set_against_chain_lockup_witness_v1(
            &[first.clone(), second.clone()],
            &[crossed],
        )
        .unwrap_err(),
        ChainLockupWitnessAuditError::PartialObservationIdentity
    );

    let mut unknown = observation(&first, 64);
    unknown.manifest_id = Uuid::from_u128(9_003);
    unknown.chain_swap_id = Uuid::from_u128(9_004);
    assert_eq!(
        audit_manifest_set_against_chain_lockup_witness_v1(&[first, second], &[unknown])
            .unwrap_err(),
        ChainLockupWitnessAuditError::UnknownObservationIdentity
    );
}

#[test]
fn chain_lockup_audit_rejects_duplicate_outpoints_within_and_across_manifests() {
    let (first, second) = two_manifests();
    let original = observation(&first, 71);
    let mut duplicate = original.clone();
    duplicate.amount_sat += 1;
    assert_eq!(
        audit_manifest_set_against_chain_lockup_witness_v1(
            &[first.clone(), second.clone()],
            &[original.clone(), duplicate],
        )
        .unwrap_err(),
        ChainLockupWitnessAuditError::DuplicateObservationOutpoint
    );

    let mut cross_manifest = observation(&second, 72);
    cross_manifest.txid = original.txid.clone();
    cross_manifest.vout = original.vout;
    assert_eq!(
        audit_manifest_set_against_chain_lockup_witness_v1(
            &[first, second],
            &[original, cross_manifest],
        )
        .unwrap_err(),
        ChainLockupWitnessAuditError::DuplicateObservationOutpoint
    );
}

#[test]
fn chain_lockup_audit_rejects_partial_transaction_inclusion_across_outputs() {
    let one = manifest(1, None, 1_715, 0x51);
    let mut first = observation(&one, 73);
    first.vout = 0;
    let mut second = observation(&one, 74);
    second.txid = first.txid.clone();
    second.vout = 1;
    second.inclusion = confirmed(1, 925_000, 0xb2);

    assert_eq!(
        audit_manifest_set_against_chain_lockup_witness_v1(&[one], &[first, second]).unwrap_err(),
        ChainLockupWitnessAuditError::ConflictingTransactionInclusion
    );
}

#[test]
fn chain_lockup_audit_rejects_conflicting_inclusion_for_one_spender() {
    let one = manifest(1, None, 1_716, 0x61);
    let shared_spender = txid(175);
    let mut first = observation(&one, 75);
    first.inclusion = confirmed(2, 925_000, 0xb4);
    first.spend = ChainLockupSpendV1::Spent {
        spending_txid: shared_spender.clone(),
        inclusion: ChainLockupInclusionV1::Mempool,
    };
    let mut second = observation(&one, 76);
    second.inclusion = confirmed(2, 925_000, 0xb4);
    second.spend = ChainLockupSpendV1::Spent {
        spending_txid: shared_spender,
        inclusion: confirmed(1, 925_001, 0xb3),
    };

    assert_eq!(
        audit_manifest_set_against_chain_lockup_witness_v1(&[one], &[first, second]).unwrap_err(),
        ChainLockupWitnessAuditError::ConflictingTransactionInclusion
    );
}

#[test]
fn chain_lockup_audit_rejects_partial_confirmation_and_impossible_spend_identity() {
    let one = manifest(1, None, 1_707, 0x31);
    let mut zero_confirmations = observation(&one, 81);
    zero_confirmations.inclusion = confirmed(0, 930_000, 0xc1);
    assert_eq!(
        audit_manifest_set_against_chain_lockup_witness_v1(
            std::slice::from_ref(&one),
            &[zero_confirmations],
        )
        .unwrap_err(),
        ChainLockupWitnessAuditError::InvalidPublicObservation
    );

    let mut zero_height = observation(&one, 82);
    zero_height.inclusion = confirmed(1, 0, 0xc2);
    assert_eq!(
        audit_manifest_set_against_chain_lockup_witness_v1(
            std::slice::from_ref(&one),
            &[zero_height],
        )
        .unwrap_err(),
        ChainLockupWitnessAuditError::InvalidPublicObservation
    );

    let mut self_spend = observation(&one, 83);
    self_spend.spend = ChainLockupSpendV1::Spent {
        spending_txid: self_spend.txid.clone(),
        inclusion: ChainLockupInclusionV1::Mempool,
    };
    assert_eq!(
        audit_manifest_set_against_chain_lockup_witness_v1(
            std::slice::from_ref(&one),
            &[self_spend],
        )
        .unwrap_err(),
        ChainLockupWitnessAuditError::InvalidPublicObservation
    );

    let mut confirmed_child_of_mempool = observation(&one, 84);
    confirmed_child_of_mempool.spend = ChainLockupSpendV1::Spent {
        spending_txid: txid(184),
        inclusion: confirmed(1, 930_001, 0xc3),
    };
    assert_eq!(
        audit_manifest_set_against_chain_lockup_witness_v1(
            std::slice::from_ref(&one),
            &[confirmed_child_of_mempool],
        )
        .unwrap_err(),
        ChainLockupWitnessAuditError::InvalidPublicObservation
    );
}

#[test]
fn chain_lockup_audit_rejects_incoherent_confirmed_spend_order() {
    let one = manifest(1, None, 1_708, 0x41);
    for (spend_confirmations, spend_height) in [(6, 940_001), (1, 939_999)] {
        let mut observed = observation(&one, u64::from(spend_confirmations) + 90);
        observed.inclusion = confirmed(5, 940_000, 0xd1);
        observed.spend = ChainLockupSpendV1::Spent {
            spending_txid: txid(200 + u64::from(spend_confirmations)),
            inclusion: confirmed(spend_confirmations, spend_height, 0xd2),
        };
        assert_eq!(
            audit_manifest_set_against_chain_lockup_witness_v1(
                std::slice::from_ref(&one),
                &[observed],
            )
            .unwrap_err(),
            ChainLockupWitnessAuditError::InvalidPublicObservation
        );
    }
}

#[test]
fn chain_lockup_audit_rejects_confirmed_facts_from_different_tips_or_blocks() {
    let one = manifest(1, None, 1_714, 0x41);

    let mut different_tip = observation(&one, 99);
    different_tip.inclusion = confirmed(5, 940_000, 0xd3);
    different_tip.spend = ChainLockupSpendV1::Spent {
        spending_txid: txid(299),
        inclusion: confirmed(1, 940_003, 0xd4),
    };

    let mut same_height_different_block = observation(&one, 100);
    same_height_different_block.inclusion = confirmed(2, 940_010, 0xd5);
    same_height_different_block.spend = ChainLockupSpendV1::Spent {
        spending_txid: txid(300),
        inclusion: confirmed(2, 940_010, 0xd6),
    };

    for invalid in [different_tip, same_height_different_block] {
        assert_eq!(
            audit_manifest_set_against_chain_lockup_witness_v1(
                std::slice::from_ref(&one),
                &[invalid],
            )
            .unwrap_err(),
            ChainLockupWitnessAuditError::InvalidPublicObservation
        );
    }
}

#[test]
fn chain_lockup_audit_rejects_noncanonical_public_strings_and_address_script_pairs() {
    let one = manifest(1, None, 1_709, 0x51);
    let mut uppercase_txid = observation(&one, 101);
    uppercase_txid.txid = "AA".repeat(32);
    let mut malformed_hash = observation(&one, 102);
    malformed_hash.inclusion = ChainLockupInclusionV1::Confirmed {
        confirmations: 1,
        block_height: 950_000,
        block_hash: "g".repeat(64),
    };
    let mut wrong_script = observation(&one, 103);
    wrong_script.lockup_script_pubkey_hex = "00".repeat(34);
    let mut whitespace_address = observation(&one, 104);
    whitespace_address.lockup_address.push(' ');

    for invalid in [
        uppercase_txid,
        malformed_hash,
        wrong_script,
        whitespace_address,
    ] {
        assert_eq!(
            audit_manifest_set_against_chain_lockup_witness_v1(
                std::slice::from_ref(&one),
                &[invalid],
            )
            .unwrap_err(),
            ChainLockupWitnessAuditError::InvalidPublicObservation
        );
    }
}

#[test]
fn chain_lockup_audit_enforces_count_and_string_limits_before_allocation() {
    let one = manifest(1, None, 1_710, 0x61);
    let oversized_manifests = vec![one.clone(); MAX_CHAIN_LOCKUP_WITNESS_MANIFESTS_V1 + 1];
    assert_eq!(
        audit_manifest_set_against_chain_lockup_witness_v1(&oversized_manifests, &[]).unwrap_err(),
        ChainLockupWitnessAuditError::TooManyManifestRecords
    );

    let one_observation = observation(&one, 111);
    let oversized_observations =
        vec![one_observation.clone(); MAX_CHAIN_LOCKUP_WITNESS_OBSERVATIONS_V1 + 1];
    assert_eq!(
        audit_manifest_set_against_chain_lockup_witness_v1(
            std::slice::from_ref(&one),
            &oversized_observations,
        )
        .unwrap_err(),
        ChainLockupWitnessAuditError::TooManyObservationRecords
    );

    for oversized in [
        {
            let mut value = one_observation.clone();
            value.lockup_address = "x".repeat(MAX_CHAIN_LOCKUP_WITNESS_ADDRESS_BYTES_V1 + 1);
            value
        },
        {
            let mut value = one_observation;
            value.lockup_script_pubkey_hex =
                "00".repeat(MAX_CHAIN_LOCKUP_WITNESS_SCRIPT_HEX_CHARS_V1 / 2 + 1);
            value
        },
    ] {
        assert_eq!(
            audit_manifest_set_against_chain_lockup_witness_v1(
                std::slice::from_ref(&one),
                &[oversized],
            )
            .unwrap_err(),
            ChainLockupWitnessAuditError::ObservationStringLimitExceeded
        );
    }
}

#[test]
fn chain_lockup_audit_enforces_per_manifest_limit_before_duplicate_coalescing() {
    let one = manifest(1, None, 1_711, 0x71);
    let observations = (0..=MAX_CHAIN_LOCKUP_WITNESS_OBSERVATIONS_PER_MANIFEST_V1)
        .map(|index| observation(&one, 1_000 + u64::try_from(index).unwrap()))
        .collect::<Vec<_>>();
    assert_eq!(
        audit_manifest_set_against_chain_lockup_witness_v1(&[one], &observations).unwrap_err(),
        ChainLockupWitnessAuditError::TooManyObservationsForManifest
    );
}

#[test]
fn manifest_set_validation_precedes_substantive_observation_validation() {
    let invalid_manifest = manifest(2, Some(Uuid::from_u128(123)), 1_712, 0x21);
    let mut invalid_observation = observation(&invalid_manifest, 121);
    invalid_observation.manifest_id = Uuid::nil();
    assert_eq!(
        audit_manifest_set_against_chain_lockup_witness_v1(
            &[invalid_manifest],
            &[invalid_observation],
        )
        .unwrap_err(),
        ChainLockupWitnessAuditError::InvalidManifestSet
    );
}

#[test]
fn chain_lockup_audit_debug_and_errors_are_bounded_and_redacted() {
    const SENTINEL: &str = "PublicChainAddressScriptTxidHashOrAmountMustNotEscape";

    let one = manifest(1, None, 1_713, 0x31);
    let sensitive_inclusion = ChainLockupInclusionV1::Confirmed {
        confirmations: 1,
        block_height: 960_000,
        block_hash: SENTINEL.into(),
    };
    let sensitive_spend = ChainLockupSpendV1::Spent {
        spending_txid: SENTINEL.into(),
        inclusion: sensitive_inclusion.clone(),
    };
    let sensitive_observation = PrevalidatedChainLockupObservationV1 {
        manifest_id: one.restore_identity.manifest_id,
        chain_swap_id: one.restore_identity.chain_swap_id,
        chain: ChainLockupWitnessChainV1::BitcoinMainnet,
        lockup_address: SENTINEL.into(),
        lockup_script_pubkey_hex: SENTINEL.into(),
        txid: SENTINEL.into(),
        vout: 0,
        amount_sat: 42,
        inclusion: sensitive_inclusion.clone(),
        spend: sensitive_spend.clone(),
    };
    for debug in [
        format!("{sensitive_inclusion:?}"),
        format!("{sensitive_spend:?}"),
        format!("{sensitive_observation:?}"),
    ] {
        assert!(!debug.contains(SENTINEL), "sensitive Debug output: {debug}");
    }

    let valid = observation(&one, 131);
    let audit = audit_manifest_set_against_chain_lockup_witness_v1(&[one], &[valid]).unwrap();
    let debug = format!("{audit:?}");
    assert!(!debug.contains(&audit.manifests[0].findings[0].txid));
    assert!(!debug.contains(&audit.manifests[0].expected_amount_sat.to_string()));

    for error in [
        ChainLockupWitnessAuditError::TooManyManifestRecords,
        ChainLockupWitnessAuditError::TooManyObservationRecords,
        ChainLockupWitnessAuditError::ObservationStringLimitExceeded,
        ChainLockupWitnessAuditError::InvalidManifestSet,
        ChainLockupWitnessAuditError::InvalidPublicObservation,
        ChainLockupWitnessAuditError::UnknownObservationIdentity,
        ChainLockupWitnessAuditError::PartialObservationIdentity,
        ChainLockupWitnessAuditError::DuplicateObservationOutpoint,
        ChainLockupWitnessAuditError::ConflictingTransactionInclusion,
        ChainLockupWitnessAuditError::TooManyObservationsForManifest,
        ChainLockupWitnessAuditError::InvalidManifestLockupTarget,
    ] {
        let display = error.to_string();
        let debug = format!("{error:?}");
        assert!(display.len() <= 80, "unbounded audit error: {display}");
        assert!(!display.contains(SENTINEL));
        assert!(!debug.contains(SENTINEL));
        assert!(std::error::Error::source(&error).is_none());
    }
}
