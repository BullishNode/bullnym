use std::collections::BTreeMap;

use super::{
    manifest_set_fixture, provider_response, public_key_from_scalar, replace_provider_response,
};
use crate::local_chain_swap_recovery_audit::{
    audit_manifest_set_against_local_recovery_snapshot_v1, LocalChainSwapRecoveryAllocationV1,
    LocalChainSwapRecoveryAuditError, LocalChainSwapRecoveryEvidenceV1,
    LocalChainSwapRecoveryFieldV1, LocalChainSwapRecoveryInventoryRecordV1,
    LocalChainSwapRecoverySnapshotSummaryV1, LocalChainSwapRecoverySnapshotV1,
    LocalChainSwapRecoveryStructuralClassV1, LocalRecoveryHighWaterRelationV1,
    LocalRecoveryLineageHighWaterV1, MAX_RECOVERY_AUDIT_LOCAL_LINEAGES_V1,
    MAX_RECOVERY_AUDIT_LOCAL_RECORDS_V1, MAX_RECOVERY_AUDIT_MANIFEST_RECORDS_V1,
};
use crate::swap_manifest::{SwapManifestV1, MAX_UNHARDENED_SWAP_CHILD_INDEX};
use uuid::Uuid;

fn local_evidence(manifest: &SwapManifestV1) -> LocalChainSwapRecoveryEvidenceV1 {
    LocalChainSwapRecoveryEvidenceV1 {
        chain_swap_id: manifest.restore_identity.chain_swap_id,
        boltz_swap_id: manifest.restore_identity.boltz_swap_id.clone(),
        root_fingerprint: manifest.derivation_lineage.root_fingerprint.clone(),
        key_epoch: manifest.derivation_lineage.key_epoch,
        derivation_scheme_version: manifest.derivation_lineage.derivation_scheme_version,
        claim: LocalChainSwapRecoveryAllocationV1 {
            allocation_id: manifest.derivation_lineage.claim.allocation_id,
            child_index: manifest.derivation_lineage.claim.child_index,
            compressed_public_key_hex: manifest.derivation_lineage.claim.public_key_hex.clone(),
        },
        refund: LocalChainSwapRecoveryAllocationV1 {
            allocation_id: manifest.derivation_lineage.refund.allocation_id,
            child_index: manifest.derivation_lineage.refund.child_index,
            compressed_public_key_hex: manifest.derivation_lineage.refund.public_key_hex.clone(),
        },
        claim_preimage_sha256: manifest
            .derivation_lineage
            .claim
            .preimage_hash_hex
            .clone()
            .unwrap(),
        canonical_creation_response_sha256: manifest.creation.creation_response_sha256.clone(),
    }
}

fn snapshot(
    records: Vec<LocalChainSwapRecoveryEvidenceV1>,
    lineage_high_waters: Vec<LocalRecoveryLineageHighWaterV1>,
) -> LocalChainSwapRecoverySnapshotV1 {
    let chain_inventory = records
        .iter()
        .map(|record| LocalChainSwapRecoveryInventoryRecordV1 {
            boltz_swap_id: record.boltz_swap_id.clone(),
            structural_class: LocalChainSwapRecoveryStructuralClassV1::CurrentV1,
            legacy_derivation: None,
        })
        .collect::<Vec<_>>();
    LocalChainSwapRecoverySnapshotV1 {
        summary: LocalChainSwapRecoverySnapshotSummaryV1 {
            record_count: records.len(),
            chain_inventory_record_count: chain_inventory.len(),
            chain_inventory,
            active_root_fingerprint: "0011223344556677".into(),
            active_root_legacy_high_water: None,
            lineage_high_waters,
        },
        records,
    }
}

fn snapshot_for_records(
    records: Vec<LocalChainSwapRecoveryEvidenceV1>,
) -> LocalChainSwapRecoverySnapshotV1 {
    let mut high_waters: BTreeMap<(String, i32, i32), i64> = BTreeMap::new();
    for record in &records {
        let child_index = record.claim.child_index.max(record.refund.child_index);
        high_waters
            .entry((
                record.root_fingerprint.clone(),
                record.key_epoch,
                record.derivation_scheme_version,
            ))
            .and_modify(|current| *current = (*current).max(child_index))
            .or_insert(child_index);
    }
    snapshot(
        records,
        high_waters
            .into_iter()
            .map(
                |((root_fingerprint, key_epoch, derivation_scheme_version), child_index)| {
                    LocalRecoveryLineageHighWaterV1 {
                        root_fingerprint,
                        key_epoch,
                        derivation_scheme_version,
                        child_index,
                    }
                },
            )
            .collect(),
    )
}

fn high_water(
    record: &LocalChainSwapRecoveryEvidenceV1,
    child_index: i64,
) -> LocalRecoveryLineageHighWaterV1 {
    LocalRecoveryLineageHighWaterV1 {
        root_fingerprint: record.root_fingerprint.clone(),
        key_epoch: record.key_epoch,
        derivation_scheme_version: record.derivation_scheme_version,
        child_index,
    }
}

fn single_manifest() -> SwapManifestV1 {
    manifest_set_fixture(1, None, 800, 1_000, 1_001, 1_003, 90, 91, 0x91)
}

fn toggle_compressed_parity(public_key: &str) -> String {
    let replacement = match &public_key[..2] {
        "02" => "03",
        "03" => "02",
        _ => unreachable!(),
    };
    format!("{replacement}{}", &public_key[2..])
}

#[test]
fn local_recovery_audit_accepts_empty_and_order_independent_exact_sets() {
    let empty = audit_manifest_set_against_local_recovery_snapshot_v1(
        &[],
        &snapshot(Vec::new(), Vec::new()),
    )
    .unwrap();
    assert_eq!(empty.manifest_set.manifest_count, 0);
    assert_eq!(empty.local_record_count, 0);
    assert_eq!(empty.exact_match_count, 0);
    assert!(empty.manifest_only_chain_swap_ids.is_empty());
    assert!(empty.local_only_chain_swap_ids.is_empty());
    assert!(empty.lineage_high_waters.is_empty());

    let first = manifest_set_fixture(1, None, 801, 1_010, 1_011, 1_013, 92, 93, 0x92);
    let second = manifest_set_fixture(
        2,
        Some(first.restore_identity.manifest_id),
        802,
        1_020,
        1_021,
        1_023,
        94,
        95,
        0x93,
    );
    let first_local = local_evidence(&first);
    let second_local = local_evidence(&second);
    let local = snapshot(
        vec![second_local.clone(), first_local],
        vec![high_water(&second_local, 1_023)],
    );
    let audit = audit_manifest_set_against_local_recovery_snapshot_v1(
        &[second.clone(), first.clone()],
        &local,
    )
    .unwrap();

    assert_eq!(audit.manifest_set.manifest_count, 2);
    assert_eq!(
        audit.manifest_set.last_manifest_id,
        Some(second.restore_identity.manifest_id)
    );
    assert_eq!(audit.local_record_count, 2);
    assert_eq!(audit.exact_match_count, 2);
    assert!(audit.manifest_only_chain_swap_ids.is_empty());
    assert!(audit.local_only_chain_swap_ids.is_empty());
    assert_eq!(audit.lineage_high_waters.len(), 1);
    assert_eq!(
        audit.lineage_high_waters[0].relation,
        LocalRecoveryHighWaterRelationV1::Equal
    );
}

#[test]
fn local_recovery_audit_returns_sorted_manifest_and_local_only_candidates() {
    let first = manifest_set_fixture(1, None, 930, 1_100, 1_101, 1_101, 96, 97, 0x94);
    let second = manifest_set_fixture(
        2,
        Some(first.restore_identity.manifest_id),
        910,
        1_110,
        1_111,
        1_111,
        98,
        99,
        0x95,
    );
    let third = manifest_set_fixture(
        3,
        Some(second.restore_identity.manifest_id),
        920,
        1_120,
        1_121,
        1_121,
        100,
        101,
        0x96,
    );
    let local_zulu = manifest_set_fixture(1, None, 990, 1_200, 1_201, 1_201, 102, 103, 0x97);
    let local_alpha = manifest_set_fixture(1, None, 905, 1_210, 1_211, 1_211, 104, 105, 0x98);
    let local = snapshot_for_records(vec![
        local_evidence(&local_zulu),
        local_evidence(&local_alpha),
    ]);

    let audit = audit_manifest_set_against_local_recovery_snapshot_v1(
        &[third.clone(), first.clone(), second.clone()],
        &local,
    )
    .unwrap();
    let mut expected_manifest_only = vec![
        first.restore_identity.chain_swap_id,
        second.restore_identity.chain_swap_id,
        third.restore_identity.chain_swap_id,
    ];
    expected_manifest_only.sort_unstable();
    let mut expected_local_only = vec![
        local_zulu.restore_identity.chain_swap_id,
        local_alpha.restore_identity.chain_swap_id,
    ];
    expected_local_only.sort_unstable();

    assert_eq!(audit.exact_match_count, 0);
    assert_eq!(audit.manifest_only_chain_swap_ids, expected_manifest_only);
    assert_eq!(audit.local_only_chain_swap_ids, expected_local_only);
}

#[test]
fn local_recovery_audit_rejects_both_partial_cross_identity_directions() {
    let manifest = single_manifest();

    let mut same_chain = local_evidence(&manifest);
    same_chain.boltz_swap_id = "DifferentProviderIdentity".into();
    assert_eq!(
        audit_manifest_set_against_local_recovery_snapshot_v1(
            std::slice::from_ref(&manifest),
            &snapshot_for_records(vec![same_chain]),
        )
        .unwrap_err(),
        LocalChainSwapRecoveryAuditError::PartialCrossIdentity
    );

    let mut same_boltz = local_evidence(&manifest);
    same_boltz.chain_swap_id = Uuid::from_u128(999_999);
    assert_eq!(
        audit_manifest_set_against_local_recovery_snapshot_v1(
            std::slice::from_ref(&manifest),
            &snapshot_for_records(vec![same_boltz]),
        )
        .unwrap_err(),
        LocalChainSwapRecoveryAuditError::PartialCrossIdentity
    );
}

#[test]
fn local_recovery_audit_rejects_crossed_identity_pairs() {
    let first = manifest_set_fixture(1, None, 811, 1_300, 1_301, 1_301, 106, 107, 0xa1);
    let second = manifest_set_fixture(
        2,
        Some(first.restore_identity.manifest_id),
        812,
        1_310,
        1_311,
        1_311,
        108,
        109,
        0xa2,
    );
    let mut first_local = local_evidence(&first);
    let mut second_local = local_evidence(&second);
    std::mem::swap(
        &mut first_local.boltz_swap_id,
        &mut second_local.boltz_swap_id,
    );

    assert_eq!(
        audit_manifest_set_against_local_recovery_snapshot_v1(
            &[first, second],
            &snapshot_for_records(vec![first_local, second_local]),
        )
        .unwrap_err(),
        LocalChainSwapRecoveryAuditError::PartialCrossIdentity
    );
}

fn assert_field_conflict(
    manifest: &SwapManifestV1,
    local: LocalChainSwapRecoveryEvidenceV1,
    expected: LocalChainSwapRecoveryFieldV1,
) {
    assert_eq!(
        audit_manifest_set_against_local_recovery_snapshot_v1(
            std::slice::from_ref(manifest),
            &snapshot_for_records(vec![local]),
        )
        .unwrap_err(),
        LocalChainSwapRecoveryAuditError::FieldConflict(expected)
    );
}

#[test]
fn local_recovery_audit_requires_every_exact_match_field() {
    let manifest = single_manifest();
    let base = local_evidence(&manifest);

    let mut changed = base.clone();
    changed.root_fingerprint = "8899aabbccddeeff".into();
    assert_field_conflict(
        &manifest,
        changed,
        LocalChainSwapRecoveryFieldV1::RootFingerprint,
    );

    let mut changed = base.clone();
    changed.key_epoch += 1;
    assert_field_conflict(&manifest, changed, LocalChainSwapRecoveryFieldV1::KeyEpoch);

    let mut changed = base.clone();
    changed.derivation_scheme_version += 1;
    assert_field_conflict(
        &manifest,
        changed,
        LocalChainSwapRecoveryFieldV1::DerivationSchemeVersion,
    );

    let mut changed = base.clone();
    changed.claim.allocation_id = Uuid::from_u128(700_001);
    assert_field_conflict(
        &manifest,
        changed,
        LocalChainSwapRecoveryFieldV1::ClaimAllocationId,
    );

    let mut changed = base.clone();
    changed.claim.child_index += 2;
    assert_field_conflict(
        &manifest,
        changed,
        LocalChainSwapRecoveryFieldV1::ClaimChildIndex,
    );

    let mut changed = base.clone();
    changed.claim.compressed_public_key_hex = public_key_from_scalar(110).to_string();
    assert_field_conflict(
        &manifest,
        changed,
        LocalChainSwapRecoveryFieldV1::ClaimPublicKey,
    );

    let mut changed = base.clone();
    changed.refund.allocation_id = Uuid::from_u128(700_002);
    assert_field_conflict(
        &manifest,
        changed,
        LocalChainSwapRecoveryFieldV1::RefundAllocationId,
    );

    let mut changed = base.clone();
    changed.refund.child_index += 2;
    assert_field_conflict(
        &manifest,
        changed,
        LocalChainSwapRecoveryFieldV1::RefundChildIndex,
    );

    let mut changed = base.clone();
    changed.refund.compressed_public_key_hex = public_key_from_scalar(111).to_string();
    assert_field_conflict(
        &manifest,
        changed,
        LocalChainSwapRecoveryFieldV1::RefundPublicKey,
    );

    let mut changed = base.clone();
    changed.claim_preimage_sha256 = "ab".repeat(32);
    assert_field_conflict(
        &manifest,
        changed,
        LocalChainSwapRecoveryFieldV1::ClaimPreimageSha256,
    );

    let mut changed = base;
    changed.canonical_creation_response_sha256 = "cd".repeat(32);
    assert_field_conflict(
        &manifest,
        changed,
        LocalChainSwapRecoveryFieldV1::CanonicalCreationResponseSha256,
    );
}

fn assert_invalid_local(record: LocalChainSwapRecoveryEvidenceV1) {
    assert_eq!(
        audit_manifest_set_against_local_recovery_snapshot_v1(
            &[],
            &snapshot_for_records(vec![record]),
        )
        .unwrap_err(),
        LocalChainSwapRecoveryAuditError::InvalidLocalEvidence
    );
}

#[test]
fn local_recovery_audit_validates_all_local_evidence_boundaries() {
    let manifest = single_manifest();
    let base = local_evidence(&manifest);

    let mut invalid = base.clone();
    invalid.chain_swap_id = Uuid::nil();
    assert_invalid_local(invalid);

    for malformed in ["", "not-valid", &"A".repeat(129)] {
        let mut invalid = base.clone();
        invalid.boltz_swap_id = malformed.into();
        assert_invalid_local(invalid);
    }

    for malformed in ["0011", "00112233445566GG"] {
        let mut invalid = base.clone();
        invalid.root_fingerprint = malformed.into();
        assert_invalid_local(invalid);
    }

    let mut invalid = base.clone();
    invalid.key_epoch = 0;
    assert_invalid_local(invalid);
    let mut invalid = base.clone();
    invalid.derivation_scheme_version = 0;
    assert_invalid_local(invalid);

    for malformed in ["ab".repeat(31), "AB".repeat(32)] {
        let mut invalid = base.clone();
        invalid.claim_preimage_sha256 = malformed;
        assert_invalid_local(invalid);
    }
    for malformed in ["cd".repeat(31), "CD".repeat(32)] {
        let mut invalid = base.clone();
        invalid.canonical_creation_response_sha256 = malformed;
        assert_invalid_local(invalid);
    }

    let mut invalid = base.clone();
    invalid.claim.allocation_id = Uuid::nil();
    assert_invalid_local(invalid);
    let mut invalid = base.clone();
    invalid.claim.child_index = -1;
    assert_invalid_local(invalid);
    let mut invalid = base.clone();
    invalid.claim.child_index = MAX_UNHARDENED_SWAP_CHILD_INDEX + 1;
    assert_invalid_local(invalid);

    for malformed in ["04".repeat(33), "02".to_owned() + &"ff".repeat(32)] {
        let mut invalid = base.clone();
        invalid.claim.compressed_public_key_hex = malformed;
        assert_invalid_local(invalid);
    }

    let mut invalid = base.clone();
    invalid.refund.allocation_id = invalid.claim.allocation_id;
    assert_invalid_local(invalid);
    let mut invalid = base.clone();
    invalid.refund.child_index = invalid.claim.child_index;
    assert_invalid_local(invalid);
    let mut invalid = base;
    invalid.refund.compressed_public_key_hex =
        toggle_compressed_parity(&invalid.claim.compressed_public_key_hex);
    assert_invalid_local(invalid);
}

fn two_distinct_local_records() -> (
    LocalChainSwapRecoveryEvidenceV1,
    LocalChainSwapRecoveryEvidenceV1,
) {
    let first = manifest_set_fixture(1, None, 820, 1_400, 1_401, 1_401, 112, 113, 0xb1);
    let second = manifest_set_fixture(1, None, 821, 1_410, 1_411, 1_411, 114, 115, 0xb2);
    (local_evidence(&first), local_evidence(&second))
}

fn assert_duplicate_local(
    records: Vec<LocalChainSwapRecoveryEvidenceV1>,
    expected: LocalChainSwapRecoveryAuditError,
) {
    assert_eq!(
        audit_manifest_set_against_local_recovery_snapshot_v1(&[], &snapshot_for_records(records),)
            .unwrap_err(),
        expected
    );
}

#[test]
fn local_recovery_audit_rejects_every_duplicate_local_identity() {
    let (first, mut second) = two_distinct_local_records();
    second.chain_swap_id = first.chain_swap_id;
    assert_duplicate_local(
        vec![first.clone(), second],
        LocalChainSwapRecoveryAuditError::DuplicateLocalChainSwapId,
    );

    let (first, mut second) = two_distinct_local_records();
    second.boltz_swap_id = first.boltz_swap_id.clone();
    assert_duplicate_local(
        vec![first.clone(), second],
        LocalChainSwapRecoveryAuditError::DuplicateLocalBoltzSwapId,
    );

    let (first, mut second) = two_distinct_local_records();
    second.claim.allocation_id = first.claim.allocation_id;
    assert_duplicate_local(
        vec![first.clone(), second],
        LocalChainSwapRecoveryAuditError::DuplicateLocalAllocationId,
    );

    let (first, mut second) = two_distinct_local_records();
    second.claim.child_index = first.claim.child_index;
    assert_duplicate_local(
        vec![first.clone(), second],
        LocalChainSwapRecoveryAuditError::DuplicateLocalDerivationIdentity,
    );

    let (first, mut second) = two_distinct_local_records();
    second.claim.compressed_public_key_hex =
        toggle_compressed_parity(&first.claim.compressed_public_key_hex);
    assert_duplicate_local(
        vec![first.clone(), second],
        LocalChainSwapRecoveryAuditError::DuplicateLocalPublicKey,
    );

    let (first, mut second) = two_distinct_local_records();
    second.claim_preimage_sha256 = first.claim_preimage_sha256.clone();
    assert_duplicate_local(
        vec![first.clone(), second],
        LocalChainSwapRecoveryAuditError::DuplicateLocalClaimPreimageHash,
    );

    let (first, mut second) = two_distinct_local_records();
    second.canonical_creation_response_sha256 = first.canonical_creation_response_sha256.clone();
    assert_duplicate_local(
        vec![first, second],
        LocalChainSwapRecoveryAuditError::DuplicateLocalCreationResponseHash,
    );
}

#[test]
fn local_recovery_audit_validates_snapshot_summary_and_allocator_coverage() {
    let record = local_evidence(&single_manifest());

    let mut wrong_count = snapshot_for_records(vec![record.clone()]);
    wrong_count.summary.record_count = 0;
    assert_eq!(
        audit_manifest_set_against_local_recovery_snapshot_v1(&[], &wrong_count).unwrap_err(),
        LocalChainSwapRecoveryAuditError::SnapshotRecordCountMismatch
    );

    let missing = snapshot(vec![record.clone()], Vec::new());
    assert_eq!(
        audit_manifest_set_against_local_recovery_snapshot_v1(&[], &missing).unwrap_err(),
        LocalChainSwapRecoveryAuditError::MissingLocalLineageHighWater
    );

    let trailing = snapshot(
        vec![record.clone()],
        vec![high_water(&record, record.refund.child_index - 1)],
    );
    assert_eq!(
        audit_manifest_set_against_local_recovery_snapshot_v1(&[], &trailing).unwrap_err(),
        LocalChainSwapRecoveryAuditError::LocalLineageHighWaterTrailsEvidence
    );

    let duplicate = snapshot(
        vec![record.clone()],
        vec![
            high_water(&record, record.refund.child_index),
            high_water(&record, record.refund.child_index + 1),
        ],
    );
    assert_eq!(
        audit_manifest_set_against_local_recovery_snapshot_v1(&[], &duplicate).unwrap_err(),
        LocalChainSwapRecoveryAuditError::DuplicateLocalLineage
    );

    let mut invalid_high_water = high_water(&record, -1);
    invalid_high_water.root_fingerprint = "0011223344556677".into();
    let invalid = snapshot(Vec::new(), vec![invalid_high_water]);
    assert_eq!(
        audit_manifest_set_against_local_recovery_snapshot_v1(&[], &invalid).unwrap_err(),
        LocalChainSwapRecoveryAuditError::InvalidLocalLineageHighWater
    );
}

#[test]
fn local_recovery_audit_classifies_all_high_water_relations_without_rejecting_ahead() {
    let manifest = single_manifest();
    let record = local_evidence(&manifest);
    let signed = manifest
        .derivation_lineage
        .allocation_high_water_child_index;

    for (local_child_index, expected) in [
        (signed, LocalRecoveryHighWaterRelationV1::Equal),
        (signed + 10, LocalRecoveryHighWaterRelationV1::LocalAhead),
        (signed - 1, LocalRecoveryHighWaterRelationV1::LocalBehind),
    ] {
        let local = snapshot(
            vec![record.clone()],
            vec![high_water(&record, local_child_index)],
        );
        let audit = audit_manifest_set_against_local_recovery_snapshot_v1(
            std::slice::from_ref(&manifest),
            &local,
        )
        .unwrap();
        assert_eq!(audit.lineage_high_waters[0].relation, expected);
        assert_eq!(
            audit.lineage_high_waters[0].signed_manifest_child_index,
            Some(signed)
        );
        assert_eq!(
            audit.lineage_high_waters[0].local_child_index,
            Some(local_child_index)
        );
    }

    let local_missing = audit_manifest_set_against_local_recovery_snapshot_v1(
        std::slice::from_ref(&manifest),
        &snapshot(Vec::new(), Vec::new()),
    )
    .unwrap();
    assert_eq!(
        local_missing.lineage_high_waters[0].relation,
        LocalRecoveryHighWaterRelationV1::LocalMissing
    );

    let extra_lineage = LocalRecoveryLineageHighWaterV1 {
        root_fingerprint: "ffeeddccbbaa9988".into(),
        key_epoch: 2,
        derivation_scheme_version: 3,
        child_index: 42,
    };
    let manifest_missing = audit_manifest_set_against_local_recovery_snapshot_v1(
        &[],
        &snapshot(Vec::new(), vec![extra_lineage]),
    )
    .unwrap();
    assert_eq!(
        manifest_missing.lineage_high_waters[0].relation,
        LocalRecoveryHighWaterRelationV1::ManifestMissing
    );
}

#[test]
fn local_recovery_audit_sorts_lineage_comparisons() {
    let local = snapshot(
        Vec::new(),
        vec![
            LocalRecoveryLineageHighWaterV1 {
                root_fingerprint: "ffeeddccbbaa9988".into(),
                key_epoch: 1,
                derivation_scheme_version: 1,
                child_index: 2,
            },
            LocalRecoveryLineageHighWaterV1 {
                root_fingerprint: "0011223344556677".into(),
                key_epoch: 1,
                derivation_scheme_version: 1,
                child_index: 1,
            },
        ],
    );
    let audit = audit_manifest_set_against_local_recovery_snapshot_v1(&[], &local).unwrap();
    assert_eq!(
        audit
            .lineage_high_waters
            .iter()
            .map(|lineage| lineage.root_fingerprint.as_str())
            .collect::<Vec<_>>(),
        ["0011223344556677", "ffeeddccbbaa9988"]
    );
}

#[test]
fn local_recovery_audit_enforces_limits_before_manifest_validation() {
    let individually_valid_but_duplicate = single_manifest();
    let oversized_manifests =
        vec![individually_valid_but_duplicate; MAX_RECOVERY_AUDIT_MANIFEST_RECORDS_V1 + 1];
    assert_eq!(
        audit_manifest_set_against_local_recovery_snapshot_v1(
            &oversized_manifests,
            &snapshot(Vec::new(), Vec::new()),
        )
        .unwrap_err(),
        LocalChainSwapRecoveryAuditError::TooManyManifestRecords
    );

    let record = local_evidence(&single_manifest());
    let oversized_records = vec![record; MAX_RECOVERY_AUDIT_LOCAL_RECORDS_V1 + 1];
    let oversized_local = LocalChainSwapRecoverySnapshotV1 {
        summary: LocalChainSwapRecoverySnapshotSummaryV1 {
            record_count: oversized_records.len(),
            chain_inventory_record_count: 0,
            chain_inventory: Vec::new(),
            active_root_fingerprint: "0011223344556677".into(),
            active_root_legacy_high_water: None,
            lineage_high_waters: Vec::new(),
        },
        records: oversized_records,
    };
    assert_eq!(
        audit_manifest_set_against_local_recovery_snapshot_v1(&[], &oversized_local).unwrap_err(),
        LocalChainSwapRecoveryAuditError::TooManyLocalRecords
    );

    let one_high_water = LocalRecoveryLineageHighWaterV1 {
        root_fingerprint: "0011223344556677".into(),
        key_epoch: 1,
        derivation_scheme_version: 1,
        child_index: 1,
    };
    let oversized_lineages = snapshot(
        Vec::new(),
        vec![one_high_water; MAX_RECOVERY_AUDIT_LOCAL_LINEAGES_V1 + 1],
    );
    assert_eq!(
        audit_manifest_set_against_local_recovery_snapshot_v1(&[], &oversized_lineages)
            .unwrap_err(),
        LocalChainSwapRecoveryAuditError::TooManyLocalLineages
    );
}

#[test]
fn manifest_set_validation_precedes_substantive_local_validation() {
    let invalid_set_member = manifest_set_fixture(
        2,
        Some(Uuid::from_u128(123)),
        850,
        1_500,
        1_501,
        1_501,
        116,
        117,
        0xc1,
    );
    let mut invalid_local = local_evidence(&single_manifest());
    invalid_local.chain_swap_id = Uuid::nil();

    assert_eq!(
        audit_manifest_set_against_local_recovery_snapshot_v1(
            &[invalid_set_member],
            &snapshot_for_records(vec![invalid_local]),
        )
        .unwrap_err(),
        LocalChainSwapRecoveryAuditError::InvalidManifestSet
    );
}

#[test]
fn local_recovery_debug_and_errors_are_bounded_and_redacted() {
    const SENTINEL: &str = "OperationalProviderNymKeyOrHashMustNotEscape";

    let mut first = manifest_set_fixture(1, None, 860, 1_600, 1_601, 1_601, 118, 119, 0xc2);
    first.restore_identity.boltz_swap_id = SENTINEL.into();
    let mut first_response = provider_response(&first);
    first_response.id = SENTINEL.into();
    replace_provider_response(&mut first, &first_response);
    let mut second = manifest_set_fixture(
        2,
        Some(first.restore_identity.manifest_id),
        861,
        1_610,
        1_611,
        1_611,
        120,
        121,
        0xc3,
    );
    second.restore_identity.boltz_swap_id = SENTINEL.into();
    let mut second_response = provider_response(&second);
    second_response.id = SENTINEL.into();
    replace_provider_response(&mut second, &second_response);
    let manifest_error = audit_manifest_set_against_local_recovery_snapshot_v1(
        &[first, second],
        &snapshot(Vec::new(), Vec::new()),
    )
    .unwrap_err();
    assert_eq!(
        manifest_error,
        LocalChainSwapRecoveryAuditError::InvalidManifestSet
    );
    assert!(std::error::Error::source(&manifest_error).is_none());
    assert!(!manifest_error.to_string().contains(SENTINEL));
    assert!(!format!("{manifest_error:?}").contains(SENTINEL));

    let sensitive = LocalChainSwapRecoveryEvidenceV1 {
        chain_swap_id: Uuid::from_u128(1),
        boltz_swap_id: SENTINEL.into(),
        root_fingerprint: SENTINEL.into(),
        key_epoch: 1,
        derivation_scheme_version: 1,
        claim: LocalChainSwapRecoveryAllocationV1 {
            allocation_id: Uuid::from_u128(2),
            child_index: 1,
            compressed_public_key_hex: SENTINEL.into(),
        },
        refund: LocalChainSwapRecoveryAllocationV1 {
            allocation_id: Uuid::from_u128(3),
            child_index: 2,
            compressed_public_key_hex: SENTINEL.into(),
        },
        claim_preimage_sha256: SENTINEL.into(),
        canonical_creation_response_sha256: SENTINEL.into(),
    };
    let sensitive_summary = LocalChainSwapRecoverySnapshotSummaryV1 {
        record_count: 1,
        chain_inventory_record_count: 1,
        chain_inventory: vec![LocalChainSwapRecoveryInventoryRecordV1 {
            boltz_swap_id: SENTINEL.into(),
            structural_class: LocalChainSwapRecoveryStructuralClassV1::CurrentV1,
            legacy_derivation: None,
        }],
        active_root_fingerprint: SENTINEL.into(),
        active_root_legacy_high_water: Some(2),
        lineage_high_waters: vec![LocalRecoveryLineageHighWaterV1 {
            root_fingerprint: SENTINEL.into(),
            key_epoch: 1,
            derivation_scheme_version: 1,
            child_index: 2,
        }],
    };
    let sensitive_snapshot = LocalChainSwapRecoverySnapshotV1 {
        records: vec![sensitive.clone()],
        summary: sensitive_summary.clone(),
    };
    for debug in [
        format!("{sensitive:?}"),
        format!("{sensitive_summary:?}"),
        format!("{sensitive_snapshot:?}"),
    ] {
        assert!(!debug.contains(SENTINEL), "sensitive Debug output: {debug}");
    }

    let errors = vec![
        LocalChainSwapRecoveryAuditError::InvalidManifestSet,
        LocalChainSwapRecoveryAuditError::TooManyManifestRecords,
        LocalChainSwapRecoveryAuditError::TooManyLocalRecords,
        LocalChainSwapRecoveryAuditError::TooManyLocalLineages,
        LocalChainSwapRecoveryAuditError::SnapshotRecordCountMismatch,
        LocalChainSwapRecoveryAuditError::InvalidLocalEvidence,
        LocalChainSwapRecoveryAuditError::InvalidLocalLineageHighWater,
        LocalChainSwapRecoveryAuditError::DuplicateLocalChainSwapId,
        LocalChainSwapRecoveryAuditError::DuplicateLocalBoltzSwapId,
        LocalChainSwapRecoveryAuditError::DuplicateLocalAllocationId,
        LocalChainSwapRecoveryAuditError::DuplicateLocalDerivationIdentity,
        LocalChainSwapRecoveryAuditError::DuplicateLocalPublicKey,
        LocalChainSwapRecoveryAuditError::DuplicateLocalClaimPreimageHash,
        LocalChainSwapRecoveryAuditError::DuplicateLocalCreationResponseHash,
        LocalChainSwapRecoveryAuditError::DuplicateLocalLineage,
        LocalChainSwapRecoveryAuditError::MissingLocalLineageHighWater,
        LocalChainSwapRecoveryAuditError::LocalLineageHighWaterTrailsEvidence,
        LocalChainSwapRecoveryAuditError::PartialCrossIdentity,
        LocalChainSwapRecoveryAuditError::FieldConflict(
            LocalChainSwapRecoveryFieldV1::ClaimPublicKey,
        ),
    ];
    for error in errors {
        let display = error.to_string();
        let debug = format!("{error:?}");
        assert!(display.len() <= 96, "unbounded audit error: {display}");
        assert!(!display.contains(SENTINEL));
        assert!(!debug.contains(SENTINEL));
    }

    let manifest = single_manifest();
    let record = local_evidence(&manifest);
    let provider_id = record.boltz_swap_id.clone();
    let root_fingerprint = record.root_fingerprint.clone();
    let claim_key = record.claim.compressed_public_key_hex.clone();
    let claim_hash = record.claim_preimage_sha256.clone();
    let local = snapshot(
        vec![record.clone()],
        vec![high_water(
            &record,
            manifest
                .derivation_lineage
                .allocation_high_water_child_index,
        )],
    );
    let audit = audit_manifest_set_against_local_recovery_snapshot_v1(&[manifest], &local).unwrap();
    let debug = format!("{audit:?}");
    for forbidden in [provider_id, root_fingerprint, claim_key, claim_hash] {
        assert!(
            !debug.contains(&forbidden),
            "sensitive audit Debug output: {debug}"
        );
    }
}
