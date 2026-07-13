#[path = "support/issue64_completion.rs"]
mod support;

use pay_service::current_fee_snapshot::CurrentFeeSnapshot;
use pay_service::fee_policy::{BitcoinFeePolicy, FeeObservationSource, FeeRail, LiquidFeePolicy};

use support::{
    assert_swap_admission_closed_for_fee_policy, bitcoin_construction_fee, liquid_construction_fee,
    live_bitcoin, live_liquid, JournaledRecoveryFixture, PersistedLkgFixture, RestartedFeeFixture,
    RuntimeDecisions, NOW_UNIX,
};

#[test]
fn accepted_fresh_per_rail_evidence_changes_the_next_construction_fee() {
    let snapshot = CurrentFeeSnapshot::new();
    let bitcoin_policy = BitcoinFeePolicy::default();
    let liquid_policy = LiquidFeePolicy::default();

    snapshot
        .update_bitcoin(live_bitcoin(2.0, NOW_UNIX, "mempool-primary"))
        .unwrap();
    snapshot
        .update_liquid(live_liquid(0.1, NOW_UNIX, "liquid-esplora-primary"))
        .unwrap();
    let initial =
        RuntimeDecisions::from_snapshot(&snapshot, &bitcoin_policy, &liquid_policy, NOW_UNIX);
    assert!(initial.ready());
    let initial_bitcoin = bitcoin_construction_fee(initial.bitcoin.as_ref().unwrap(), 200);
    let initial_liquid = liquid_construction_fee(initial.liquid.as_ref().unwrap(), 300);

    snapshot
        .update_bitcoin(live_bitcoin(25.0, NOW_UNIX + 1, "mempool-failover"))
        .unwrap();
    snapshot
        .update_liquid(live_liquid(1.25, NOW_UNIX + 1, "liquid-esplora-failover"))
        .unwrap();
    let changed =
        RuntimeDecisions::from_snapshot(&snapshot, &bitcoin_policy, &liquid_policy, NOW_UNIX + 1);
    assert!(changed.ready());
    let changed_bitcoin = bitcoin_construction_fee(changed.bitcoin.as_ref().unwrap(), 200);
    let changed_liquid = liquid_construction_fee(changed.liquid.as_ref().unwrap(), 300);

    assert_eq!(initial_bitcoin.fee_sat, 400);
    assert_eq!(changed_bitcoin.fee_sat, 5_000);
    assert_eq!(initial_liquid.fee_sat, 30);
    assert_eq!(changed_liquid.fee_sat, 375);
    assert_ne!(initial_bitcoin, changed_bitcoin);
    assert_ne!(initial_liquid, changed_liquid);
}

#[test]
fn missing_stale_failed_or_rail_disagreeing_evidence_never_guesses_admission_open() {
    let bitcoin_policy = BitcoinFeePolicy::default();
    let liquid_policy = LiquidFeePolicy::default();

    let missing_after_failed_refresh = CurrentFeeSnapshot::new();
    let missing = RuntimeDecisions::from_snapshot(
        &missing_after_failed_refresh,
        &bitcoin_policy,
        &liquid_policy,
        NOW_UNIX,
    );
    assert!(missing.bitcoin.is_err());
    assert!(missing.liquid.is_err());
    assert_swap_admission_closed_for_fee_policy(&missing.apply_to_admission());

    let stale = CurrentFeeSnapshot::new();
    stale
        .update_bitcoin(live_bitcoin(
            4.0,
            NOW_UNIX - bitcoin_policy.live_max_age_secs() - 1,
            "stale-bitcoin",
        ))
        .unwrap();
    stale
        .update_liquid(live_liquid(
            0.25,
            NOW_UNIX - liquid_policy.live_max_age_secs() - 1,
            "stale-liquid",
        ))
        .unwrap();
    let stale = RuntimeDecisions::from_snapshot(&stale, &bitcoin_policy, &liquid_policy, NOW_UNIX);
    assert!(stale.bitcoin.is_err());
    assert!(stale.liquid.is_err());
    assert_swap_admission_closed_for_fee_policy(&stale.apply_to_admission());

    // Ordered source failover does not require equal rates. The integrity
    // disagreement that closes readiness is one accepted rail versus one
    // unavailable/rejected rail at the same clock read.
    let rail_disagreement = CurrentFeeSnapshot::new();
    rail_disagreement
        .update_bitcoin(live_bitcoin(8.0, NOW_UNIX, "bitcoin-only"))
        .unwrap();
    let rail_disagreement = RuntimeDecisions::from_snapshot(
        &rail_disagreement,
        &bitcoin_policy,
        &liquid_policy,
        NOW_UNIX,
    );
    assert!(rail_disagreement.bitcoin.is_ok());
    assert!(rail_disagreement.liquid.is_err());
    assert!(!rail_disagreement.ready());
    assert_swap_admission_closed_for_fee_policy(&rail_disagreement.apply_to_admission());
}

#[test]
fn recent_persisted_lkg_restores_after_restart_with_exact_provenance() {
    let bitcoin_policy = BitcoinFeePolicy::default();
    let liquid_policy = LiquidFeePolicy::default();

    let first_process = CurrentFeeSnapshot::new();
    first_process
        .update_bitcoin(live_bitcoin(12.5, NOW_UNIX, "mempool:primary"))
        .unwrap();
    first_process
        .update_liquid(live_liquid(0.25, NOW_UNIX, "liquid-esplora:primary"))
        .unwrap();
    let first_decisions =
        RuntimeDecisions::from_snapshot(&first_process, &bitcoin_policy, &liquid_policy, NOW_UNIX);
    let persisted_bitcoin =
        PersistedLkgFixture::capture_bitcoin(first_decisions.bitcoin.as_ref().unwrap());
    let persisted_liquid =
        PersistedLkgFixture::capture_liquid(first_decisions.liquid.as_ref().unwrap());
    drop(first_process);

    let mut restarted_process = RestartedFeeFixture::new();
    restarted_process.restore_bitcoin_last_known_good(persisted_bitcoin.restore_bitcoin().unwrap());
    restarted_process.restore_liquid_last_known_good(persisted_liquid.restore_liquid().unwrap());
    let restored = restarted_process.decisions(&bitcoin_policy, &liquid_policy, NOW_UNIX + 30);
    assert!(restored.ready());

    let bitcoin = restored.bitcoin.unwrap();
    assert_eq!(bitcoin.source(), FeeObservationSource::BitcoinLastKnownGood);
    assert_eq!(bitcoin.rate().as_f64(), 12.5);
    assert_eq!(bitcoin.observed_at_unix(), NOW_UNIX);
    assert_eq!(
        bitcoin.provenance().expose_for_persistence(),
        "mempool:primary"
    );

    let liquid = restored.liquid.unwrap();
    assert_eq!(liquid.source(), FeeObservationSource::LiquidLastKnownGood);
    assert_eq!(liquid.rate().as_f64(), 0.25);
    assert_eq!(liquid.observed_at_unix(), NOW_UNIX);
    assert_eq!(
        liquid.provenance().expose_for_persistence(),
        "liquid-esplora:primary"
    );

    // Restored evidence cannot be persisted again to extend its lifetime.
    assert!(!restarted_process.has_live_evidence_eligible_for_persistence());
}

#[test]
fn expired_future_or_invalid_restored_evidence_fails_closed() {
    let bitcoin_policy = BitcoinFeePolicy::default();
    let liquid_policy = LiquidFeePolicy::default();

    let mut expired = RestartedFeeFixture::new();
    expired.restore_bitcoin_last_known_good(
        PersistedLkgFixture {
            rail: FeeRail::Bitcoin,
            original_source: FeeObservationSource::LiveBitcoin,
            rate_sat_per_vbyte: 5.0,
            observed_at_unix: NOW_UNIX - bitcoin_policy.last_known_good_max_age_secs() - 1,
            provenance: "expired-bitcoin".to_owned(),
        }
        .restore_bitcoin()
        .unwrap(),
    );
    expired.restore_liquid_last_known_good(
        PersistedLkgFixture {
            rail: FeeRail::Liquid,
            original_source: FeeObservationSource::LiveLiquid,
            rate_sat_per_vbyte: 0.25,
            observed_at_unix: NOW_UNIX - liquid_policy.last_known_good_max_age_secs() - 1,
            provenance: "expired-liquid".to_owned(),
        }
        .restore_liquid()
        .unwrap(),
    );
    let expired = expired.decisions(&bitcoin_policy, &liquid_policy, NOW_UNIX);
    assert!(expired.bitcoin.is_err());
    assert!(expired.liquid.is_err());
    assert_swap_admission_closed_for_fee_policy(&expired.apply_to_admission());

    let mut future = RestartedFeeFixture::new();
    future.restore_bitcoin_last_known_good(
        PersistedLkgFixture {
            rail: FeeRail::Bitcoin,
            original_source: FeeObservationSource::LiveBitcoin,
            rate_sat_per_vbyte: 5.0,
            observed_at_unix: NOW_UNIX + 1,
            provenance: "future-bitcoin".to_owned(),
        }
        .restore_bitcoin()
        .unwrap(),
    );
    let future_error = future
        .decisions(&bitcoin_policy, &liquid_policy, NOW_UNIX)
        .bitcoin;
    assert!(future_error.is_err());

    for invalid in [
        PersistedLkgFixture {
            rail: FeeRail::Bitcoin,
            original_source: FeeObservationSource::LiveBitcoin,
            rate_sat_per_vbyte: 0.0,
            observed_at_unix: NOW_UNIX,
            provenance: "zero-rate".to_owned(),
        },
        PersistedLkgFixture {
            rail: FeeRail::Bitcoin,
            original_source: FeeObservationSource::LiveBitcoin,
            rate_sat_per_vbyte: 5.0,
            observed_at_unix: NOW_UNIX,
            provenance: " ".to_owned(),
        },
        PersistedLkgFixture {
            rail: FeeRail::Bitcoin,
            original_source: FeeObservationSource::LiveLiquid,
            rate_sat_per_vbyte: 5.0,
            observed_at_unix: NOW_UNIX,
            provenance: "wrong-source".to_owned(),
        },
    ] {
        assert!(invalid.restore_bitcoin().is_err());
    }
}

#[test]
fn refresh_failure_uses_only_a_still_valid_lkg() {
    let bitcoin_policy = BitcoinFeePolicy::default();
    let liquid_policy = LiquidFeePolicy::default();
    let mut snapshot = RestartedFeeFixture::new();

    // A failed refresh supplies no live candidate. A restored quote remains
    // authority only for its original observation window.
    snapshot.restore_bitcoin_last_known_good(
        PersistedLkgFixture {
            rail: FeeRail::Bitcoin,
            original_source: FeeObservationSource::LiveBitcoin,
            rate_sat_per_vbyte: 7.5,
            observed_at_unix: NOW_UNIX,
            provenance: "persisted-bitcoin-after-refresh-failure".to_owned(),
        }
        .restore_bitcoin()
        .unwrap(),
    );
    snapshot.restore_liquid_last_known_good(
        PersistedLkgFixture {
            rail: FeeRail::Liquid,
            original_source: FeeObservationSource::LiveLiquid,
            rate_sat_per_vbyte: 0.5,
            observed_at_unix: NOW_UNIX,
            provenance: "persisted-liquid-after-refresh-failure".to_owned(),
        }
        .restore_liquid()
        .unwrap(),
    );

    let last_valid_instant = NOW_UNIX
        + bitcoin_policy
            .last_known_good_max_age_secs()
            .min(liquid_policy.last_known_good_max_age_secs());
    let valid = snapshot.decisions(&bitcoin_policy, &liquid_policy, last_valid_instant);
    assert!(valid.ready());
    assert_eq!(
        valid.bitcoin.as_ref().unwrap().source(),
        FeeObservationSource::BitcoinLastKnownGood
    );
    assert_eq!(
        valid.liquid.as_ref().unwrap().source(),
        FeeObservationSource::LiquidLastKnownGood
    );

    let expired = snapshot.decisions(&bitcoin_policy, &liquid_policy, last_valid_instant + 1);
    assert!(!expired.ready());
    assert_swap_admission_closed_for_fee_policy(&expired.apply_to_admission());
}

#[test]
fn journal_replay_preserves_the_original_chosen_rate_and_bytes() {
    let policy = BitcoinFeePolicy::default();
    let original_live = live_bitcoin(5.0, NOW_UNIX, "mempool-at-construction");
    let original = policy
        .decide_typed(Some(&original_live), None, NOW_UNIX)
        .unwrap();
    let journaled = JournaledRecoveryFixture::commit(&original, 200);

    let later_live = live_bitcoin(100.0, NOW_UNIX + 1, "mempool-after-restart");
    let later = policy
        .decide_typed(Some(&later_live), None, NOW_UNIX + 1)
        .unwrap();
    let replayed = journaled.replay(Some(&later));

    assert_eq!(journaled.rate_sat_per_vbyte, 5.0);
    assert_eq!(journaled.actual_fee_sat, 1_000);
    assert_eq!(replayed, journaled);
    assert_ne!(replayed.rate_sat_per_vbyte, later.rate().as_f64());
    assert_eq!(replayed.provenance, "mempool-at-construction");
}
