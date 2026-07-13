use std::collections::HashSet;

use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use super::InvoiceAccountingTolerances;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectPaymentSource {
    Bitcoin,
    Liquid,
}

impl DirectPaymentSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::Bitcoin => "bitcoin_direct",
            Self::Liquid => "liquid_direct",
        }
    }

    fn rail(self) -> &'static str {
        match self {
            Self::Bitcoin => "bitcoin",
            Self::Liquid => "liquid",
        }
    }

    fn event_key(self, txid: &str, vout: i32) -> String {
        format!("{}:{txid}:{vout}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectEvidenceVerification {
    Verified,
    Unverified,
}

impl DirectEvidenceVerification {
    fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Unverified => "unverified",
        }
    }

    fn is_verified(self) -> bool {
        self == Self::Verified
    }

    fn event_state(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Unverified => "unclassified",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectRegressionReason {
    Conflict,
    Evicted,
    Replaced,
    InvalidReplacement,
    Reorged,
}

impl DirectRegressionReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::Conflict => "conflict",
            Self::Evicted => "evicted",
            Self::Replaced => "replaced",
            Self::InvalidReplacement => "invalid_replacement",
            Self::Reorged => "reorged",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectPositivePhase {
    Provisional,
    Confirmed,
    Finalized,
}

impl DirectPositivePhase {
    fn observation_state(self) -> &'static str {
        match self {
            Self::Provisional => "seen_unconfirmed",
            Self::Confirmed => "awaiting_confirmations",
            Self::Finalized => "counted",
        }
    }

    fn activates_accounting(self) -> bool {
        matches!(self, Self::Confirmed | Self::Finalized)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectObservationPhase {
    Provisional,
    Confirmed,
    Finalized,
    /// The same authoritative view proved that a prior inclusion block
    /// regressed and supplied the current positive state. This preserves the
    /// prior block identity in the append-only transition without exposing a
    /// transient invoice incident between demotion and reappearance.
    ReobservedAfterBlockRegression {
        phase: DirectPositivePhase,
        prior_block_height: i32,
        prior_block_hash: [u8; 32],
        reason: DirectRegressionReason,
    },
    ResolutionPending(DirectRegressionReason),
}

impl DirectObservationPhase {
    pub fn reobserved_after_block_regression(
        phase: DirectPositivePhase,
        prior_block_height: i32,
        prior_block_hash: &str,
        reason: DirectRegressionReason,
    ) -> Result<Self, String> {
        if prior_block_height <= 0 {
            return Err("prior direct-payment block height must be positive".to_string());
        }
        if reason != DirectRegressionReason::Reorged {
            return Err("block-regression reobservation requires a reorg reason".to_string());
        }
        let decoded = hex::decode(prior_block_hash)
            .map_err(|_| "prior direct-payment block hash must be hexadecimal".to_string())?;
        let prior_block_hash: [u8; 32] = decoded
            .try_into()
            .map_err(|_| "prior direct-payment block hash must be 32 bytes".to_string())?;
        Ok(Self::ReobservedAfterBlockRegression {
            phase,
            prior_block_height,
            prior_block_hash,
            reason,
        })
    }

    fn observation_state(self) -> &'static str {
        match self {
            Self::Provisional => "seen_unconfirmed",
            Self::Confirmed => "awaiting_confirmations",
            Self::Finalized => "counted",
            Self::ReobservedAfterBlockRegression { phase, .. } => phase.observation_state(),
            Self::ResolutionPending(_) => "resolution_pending",
        }
    }

    fn regression_reason(self) -> Option<&'static str> {
        match self {
            Self::ResolutionPending(reason) => Some(reason.as_str()),
            _ => None,
        }
    }

    fn transition_reason(self) -> Option<&'static str> {
        match self {
            Self::ReobservedAfterBlockRegression { reason, .. }
            | Self::ResolutionPending(reason) => Some(reason.as_str()),
            _ => None,
        }
    }

    fn block_regression(
        self,
    ) -> Option<(DirectPositivePhase, i32, [u8; 32], DirectRegressionReason)> {
        match self {
            Self::ReobservedAfterBlockRegression {
                phase,
                prior_block_height,
                prior_block_hash,
                reason,
            } => Some((phase, prior_block_height, prior_block_hash, reason)),
            _ => None,
        }
    }

    fn activates_accounting(self, verification: DirectEvidenceVerification) -> bool {
        verification.is_verified()
            && match self {
                Self::Confirmed | Self::Finalized => true,
                Self::ReobservedAfterBlockRegression { phase, .. } => phase.activates_accounting(),
                Self::Provisional | Self::ResolutionPending(_) => false,
            }
    }

    #[cfg(test)]
    fn contributes_to_presentation(self, verification: DirectEvidenceVerification) -> bool {
        verification.is_verified() && !matches!(self, Self::ResolutionPending(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectOutputObservation<'a> {
    pub event_key: &'a str,
    pub txid: &'a str,
    pub vout: i32,
    pub address: &'a str,
    pub amount_sat: i64,
    pub asset_id: Option<&'a str>,
    pub confirmations: i32,
    pub block_height: Option<i32>,
    pub block_hash: Option<&'a str>,
    pub verification: DirectEvidenceVerification,
    pub phase: DirectObservationPhase,
    /// A positively validated replacement may supersede one prior direct
    /// outpoint. Merely disappearing from a scan never sets this field.
    pub supersedes_event_key: Option<&'a str>,
}

impl DirectOutputObservation<'_> {
    fn validate(&self, source: DirectPaymentSource) -> Result<(), sqlx::Error> {
        if self.event_key != source.event_key(self.txid, self.vout) {
            return protocol_error("direct event_key must match source:txid:vout");
        }
        if self.txid.len() != 64 || !self.txid.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return protocol_error("direct txid must be 64 hexadecimal characters");
        }
        if self.vout < 0 {
            return protocol_error("direct vout must be non-negative");
        }
        if self.address.is_empty() || self.address.len() > 200 {
            return protocol_error("direct address length is invalid");
        }
        if self.amount_sat <= 0 {
            return protocol_error("direct amount_sat must be positive");
        }
        if self.confirmations < 0 {
            return protocol_error("direct confirmations must be non-negative");
        }
        if self.block_height.is_some_and(|height| height <= 0) {
            return protocol_error("direct block height must be positive");
        }
        if self.block_hash.is_some_and(|hash| {
            hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit())
        }) {
            return protocol_error("direct block hash must be 64 hexadecimal characters");
        }
        if let Some((_, prior_height, _, reason)) = self.phase.block_regression() {
            if prior_height <= 0 || reason != DirectRegressionReason::Reorged {
                return protocol_error(
                    "positive block-regression evidence requires a prior block and reorg reason",
                );
            }
        }
        match source {
            DirectPaymentSource::Bitcoin if self.asset_id.is_some() => {
                return protocol_error("Bitcoin direct evidence must not carry an asset id");
            }
            DirectPaymentSource::Liquid => {
                let Some(asset_id) = self.asset_id else {
                    return protocol_error("Liquid direct evidence requires an asset id");
                };
                if asset_id.len() != 64 || !asset_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return protocol_error(
                        "Liquid direct asset id must be 64 hexadecimal characters",
                    );
                }
            }
            DirectPaymentSource::Bitcoin => {}
        }
        match self.phase {
            DirectObservationPhase::Provisional
            | DirectObservationPhase::ReobservedAfterBlockRegression {
                phase: DirectPositivePhase::Provisional,
                ..
            } => {
                if self.confirmations != 0
                    || self.block_height.is_some()
                    || self.block_hash.is_some()
                {
                    return protocol_error(
                        "provisional direct evidence cannot carry block confirmation evidence",
                    );
                }
            }
            DirectObservationPhase::Confirmed
            | DirectObservationPhase::Finalized
            | DirectObservationPhase::ReobservedAfterBlockRegression {
                phase: DirectPositivePhase::Confirmed | DirectPositivePhase::Finalized,
                ..
            } => {
                if self.verification != DirectEvidenceVerification::Verified {
                    return protocol_error("confirmed direct evidence must be positively verified");
                }
                if self.confirmations <= 0
                    || self.block_height.is_none()
                    || self.block_hash.is_none()
                {
                    return protocol_error(
                        "confirmed direct evidence requires confirmations, block height, and block hash",
                    );
                }
            }
            DirectObservationPhase::ResolutionPending(_) => {}
        }
        if let Some(superseded) = self.supersedes_event_key {
            let source_prefix = format!("{}:", source.as_str());
            if superseded == self.event_key || !superseded.starts_with(&source_prefix) {
                return protocol_error(
                    "superseded direct event must be a distinct event from the same source",
                );
            }
            if self.verification != DirectEvidenceVerification::Verified
                || matches!(self.phase, DirectObservationPhase::ResolutionPending(_))
            {
                return protocol_error(
                    "only positive verified direct evidence may supersede an event",
                );
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct DirectObservationBatch<'a> {
    pub invoice_id: Uuid,
    pub source: DirectPaymentSource,
    /// Stable identifier for the authoritative backend/checker that produced
    /// the batch. It is audit metadata, not a concurrency token.
    pub authority: &'a str,
    pub generation: i64,
    pub observations: &'a [DirectOutputObservation<'a>],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyDirectObservationOutcome {
    Applied { changed: bool },
    AlreadyApplied,
    Stale { current_generation: i64 },
    Closed,
}

/// Immutable Bitcoin-direct evidence that still needs authoritative tx-specific
/// follow-up. Rows may come from the pre-047 observation writer or from a
/// legacy countable event that has not yet been linked to a verified
/// observation.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct BitcoinDirectWatchEvidence {
    pub event_key: String,
    pub txid: String,
    pub vout: i32,
    pub address: String,
    pub amount_sat: i64,
    pub confirmations: i32,
    pub block_height: Option<i32>,
    pub block_hash: Option<String>,
    pub last_seen_state: Option<String>,
}

/// Load a caller-bounded prefix of non-superseded Bitcoin-direct identities for
/// one invoice. The watcher requests one sentinel beyond its hard limit so an
/// oversized obligation fails closed without loading unbounded evidence.
pub async fn list_bitcoin_direct_watch_evidence(
    pool: &PgPool,
    invoice_id: Uuid,
    limit: i64,
) -> Result<Vec<BitcoinDirectWatchEvidence>, sqlx::Error> {
    sqlx::query_as(
        "SELECT * FROM ( \
         SELECT o.event_key, o.txid, o.vout, o.address, o.amount_sat, \
                o.confirmations, o.block_height, \
                o.inclusion_block_hash AS block_hash, \
                o.last_seen_state::TEXT AS last_seen_state \
         FROM invoice_payment_observations o \
         WHERE o.invoice_id = $1 \
           AND o.source = 'bitcoin_direct' \
           AND o.last_seen_state <> 'superseded' \
         UNION ALL \
         SELECT e.event_key, e.txid, e.vout, e.address, e.amount_sat, \
                0::INTEGER AS confirmations, NULL::INTEGER AS block_height, \
                NULL::TEXT AS block_hash, NULL::TEXT AS last_seen_state \
         FROM invoice_payment_events e \
         WHERE e.invoice_id = $1 \
           AND e.source = 'bitcoin_direct' \
           AND e.accounting_state <> 'superseded' \
           AND e.txid IS NOT NULL \
           AND e.vout IS NOT NULL \
           AND e.address IS NOT NULL \
           AND NOT EXISTS ( \
               SELECT 1 FROM invoice_payment_observations o \
               WHERE o.event_key = e.event_key \
             ) \
         ) evidence \
         ORDER BY event_key \
         LIMIT $2",
    )
    .bind(invoice_id)
    .bind(limit)
    .fetch_all(pool)
    .await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AccountingReplayEvent {
    rail: &'static str,
    amount_sat: i64,
    sequence: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AccountingProjection {
    status: &'static str,
    received_sat: i64,
}

#[derive(Debug, sqlx::FromRow)]
struct LockedInvoice {
    amount_sat: i64,
    status: String,
    presentation_status: Option<String>,
    direct_settlement_status: String,
    swap_settlement_status: String,
    settlement_status: String,
    paid_via: Option<String>,
    paid_amount_sat: Option<i64>,
    expired: bool,
}

#[derive(Debug, sqlx::FromRow)]
struct StoredObservation {
    id: Uuid,
    invoice_id: Uuid,
    rail: String,
    source: String,
    event_key: String,
    txid: String,
    vout: i32,
    address: String,
    amount_sat: i64,
    asset_id: Option<String>,
    confirmations: i32,
    block_height: Option<i32>,
    inclusion_block_hash: Option<String>,
    last_seen_state: String,
    verification_state: String,
    invalidation_reason: Option<String>,
    superseded_by_observation_id: Option<Uuid>,
    superseded_by_payment_event_id: Option<Uuid>,
}

#[derive(Debug, sqlx::FromRow)]
struct StoredEvent {
    id: Uuid,
    invoice_id: Uuid,
    rail: String,
    source: Option<String>,
    event_key: String,
    txid: Option<String>,
    vout: Option<i32>,
    address: Option<String>,
    amount_sat: i64,
    accounting_state: String,
    verification_state: String,
    observation_id: Option<Uuid>,
    superseded_by_event_id: Option<Uuid>,
    deactivation_reason: Option<String>,
}

#[derive(Debug)]
struct ObservationTransitionBefore {
    observation_state: Option<String>,
    verification_state: Option<String>,
}

#[derive(Debug)]
struct ObservationMutation {
    id: Uuid,
    changed: bool,
    transition_before: ObservationTransitionBefore,
    should_append_transition: bool,
}

#[derive(Debug)]
struct EventMutation {
    id: Uuid,
    changed: bool,
    from_state: Option<String>,
    to_state: &'static str,
}

#[derive(Debug)]
struct PendingDirectTransition {
    observation_id: Uuid,
    payment_event_id: Uuid,
    transition_kind: &'static str,
    from_observation_state: Option<String>,
    to_observation_state: &'static str,
    from_verification_state: Option<String>,
    to_verification_state: String,
    from_event_state: Option<String>,
    to_event_state: &'static str,
    reason: Option<&'static str>,
    metadata: serde_json::Value,
}

#[derive(Debug)]
struct SupersessionMutation {
    changed: bool,
    transition: Option<PendingDirectTransition>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InvalidationTimestampMutation {
    Preserve,
    Stamp,
    Clear,
}

fn invalidation_timestamp_mutation(
    prior_reason: Option<&str>,
    next_reason: Option<&str>,
) -> InvalidationTimestampMutation {
    match (prior_reason, next_reason) {
        (_, None) => InvalidationTimestampMutation::Clear,
        (prior, next) if prior == next => InvalidationTimestampMutation::Preserve,
        _ => InvalidationTimestampMutation::Stamp,
    }
}

#[derive(Debug, sqlx::FromRow)]
struct ProjectionEvent {
    rail: String,
    source: Option<String>,
    amount_sat: i64,
    accounting_sequence: i64,
    accounting_state: String,
    observation_state: Option<String>,
    verification_state: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReducedProjection {
    status: &'static str,
    presentation_status: &'static str,
    direct_settlement_status: &'static str,
    settlement_status: &'static str,
    received_sat: i64,
}

fn replay_accounting(
    amount_sat: i64,
    expired: bool,
    mut events: Vec<AccountingReplayEvent>,
    tolerances: InvoiceAccountingTolerances,
) -> AccountingProjection {
    events.sort_by_key(|event| event.sequence);
    let mut status = if expired { "underpaid" } else { "unpaid" };
    let mut received_sat = 0_i64;
    for event in events {
        received_sat = received_sat.saturating_add(event.amount_sat);
        let configured_tolerance = match event.rail {
            "bitcoin" => tolerances.btc_sat,
            "liquid" => tolerances.liquid_sat,
            "lightning" => tolerances.lightning_sat,
            _ => 0,
        }
        .max(0);
        let tolerance_sat = configured_tolerance.min((amount_sat / 100).max(1));
        let computed = if received_sat > amount_sat {
            "overpaid"
        } else if amount_sat.saturating_sub(received_sat) <= tolerance_sat {
            "paid"
        } else if status == "underpaid" || expired {
            "underpaid"
        } else {
            "partially_paid"
        };
        status =
            if matches!(status, "paid" | "overpaid") && !matches!(computed, "paid" | "overpaid") {
                status
            } else {
                computed
            };
    }
    AccountingProjection {
        status,
        received_sat,
    }
}

fn presentation_status_for(
    amount_sat: i64,
    events: &[ProjectionEvent],
    tolerances: InvoiceAccountingTolerances,
) -> &'static str {
    let replay_events = events
        .iter()
        .filter(|event| {
            if event.accounting_state == "superseded" {
                return false;
            }
            if matches!(
                event.accounting_state.as_str(),
                "active" | "legacy_unverified"
            ) {
                return true;
            }
            matches!(
                event.source.as_deref(),
                Some("bitcoin_direct" | "liquid_direct")
            ) && event.verification_state == "verified"
                && matches!(event.observation_state.as_deref(), Some("seen_unconfirmed"))
        })
        .map(|event| AccountingReplayEvent {
            rail: match event.rail.as_str() {
                "bitcoin" => "bitcoin",
                "liquid" => "liquid",
                "lightning" => "lightning",
                _ => "unknown",
            },
            amount_sat: event.amount_sat,
            sequence: event.accounting_sequence,
        })
        .collect();
    match replay_accounting(amount_sat, false, replay_events, tolerances).status {
        "partially_paid" | "underpaid" => "partial",
        "paid" => "payment_received",
        "overpaid" => "overpaid",
        _ => "unpaid",
    }
}

fn direct_settlement_status_for(events: &[ProjectionEvent], prior_status: &str) -> &'static str {
    let direct = events.iter().filter(|event| {
        matches!(
            event.source.as_deref(),
            Some("bitcoin_direct" | "liquid_direct")
        ) && event.accounting_state != "superseded"
    });
    let mut saw_positive = false;
    let mut all_finalized = true;
    let mut saw_legacy = false;
    for event in direct {
        if event.accounting_state == "legacy_unverified" {
            saw_legacy = true;
            continue;
        }
        if event.verification_state != "verified" {
            continue;
        }
        match event.observation_state.as_deref() {
            Some("resolution_pending") => return "resolution_pending",
            Some("seen_unconfirmed" | "awaiting_confirmations") => {
                saw_positive = true;
                all_finalized = false;
            }
            Some("counted") => saw_positive = true,
            _ => {}
        }
    }
    if !saw_positive && saw_legacy {
        match prior_status {
            "pending" => "pending",
            "settled" => "settled",
            "resolution_pending" => "resolution_pending",
            _ => "none",
        }
    } else if !saw_positive {
        "none"
    } else if all_finalized && saw_legacy {
        match prior_status {
            "settled" => "settled",
            "resolution_pending" => "resolution_pending",
            _ => "pending",
        }
    } else if all_finalized {
        "settled"
    } else {
        "pending"
    }
}

fn public_settlement_status(direct: &str, swap: &str) -> &'static str {
    if swap == "claim_stuck" {
        "claim_stuck"
    } else if swap == "failed" {
        "failed"
    } else if swap == "refunded" {
        "refunded"
    } else if direct == "resolution_pending" {
        "resolution_pending"
    } else if direct == "pending" || swap == "pending" {
        "pending"
    } else if direct == "settled" || swap == "settled" {
        "settled"
    } else {
        "none"
    }
}

fn reduce_projection(
    invoice: &LockedInvoice,
    events: &[ProjectionEvent],
    tolerances: InvoiceAccountingTolerances,
) -> ReducedProjection {
    let accounting_events = events
        .iter()
        .filter(|event| {
            matches!(
                event.accounting_state.as_str(),
                "active" | "legacy_unverified"
            )
        })
        .map(|event| AccountingReplayEvent {
            rail: match event.rail.as_str() {
                "bitcoin" => "bitcoin",
                "liquid" => "liquid",
                "lightning" => "lightning",
                _ => "unknown",
            },
            amount_sat: event.amount_sat,
            sequence: event.accounting_sequence,
        })
        .collect();
    let accounting = replay_accounting(
        invoice.amount_sat,
        invoice.expired,
        accounting_events,
        tolerances,
    );
    let direct_settlement_status =
        direct_settlement_status_for(events, &invoice.direct_settlement_status);
    let presentation_status = presentation_status_for(invoice.amount_sat, events, tolerances);
    let status = if accounting.received_sat == 0 {
        if presentation_status != "unpaid" || direct_settlement_status == "resolution_pending" {
            "in_progress"
        } else if invoice.status == "underpaid" {
            "underpaid"
        } else {
            "unpaid"
        }
    } else {
        accounting.status
    };
    ReducedProjection {
        status,
        presentation_status,
        direct_settlement_status,
        settlement_status: public_settlement_status(
            direct_settlement_status,
            &invoice.swap_settlement_status,
        ),
        received_sat: accounting.received_sat,
    }
}

fn protocol_error<T>(message: impl Into<String>) -> Result<T, sqlx::Error> {
    Err(sqlx::Error::Protocol(message.into()))
}

fn validate_observation_batch(
    source: DirectPaymentSource,
    observations: &[DirectOutputObservation<'_>],
) -> Result<(), sqlx::Error> {
    let mut event_keys = HashSet::with_capacity(observations.len());
    for observation in observations {
        observation.validate(source)?;
        if !event_keys.insert(observation.event_key) {
            return protocol_error("direct observation batch contains a duplicate event_key");
        }
    }

    let mut superseded_keys = HashSet::new();
    for observation in observations {
        let Some(superseded_key) = observation.supersedes_event_key else {
            continue;
        };
        if !superseded_keys.insert(superseded_key) {
            return protocol_error("direct observation batch contains competing replacements");
        }
        if event_keys.contains(superseded_key) {
            return protocol_error(
                "direct observation batch cannot observe and supersede the same event",
            );
        }
    }
    Ok(())
}

/// Reserve a database-monotonic generation before starting external chain I/O.
/// The later apply rejects an older concurrent result even across restarts.
pub async fn reserve_direct_observation_generation(
    pool: &PgPool,
    invoice_id: Uuid,
    source: DirectPaymentSource,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "INSERT INTO invoice_direct_scan_heads \
             (invoice_id, source, issued_generation, applied_generation, last_started_at) \
         VALUES ($1, $2, 1, 0, NOW()) \
         ON CONFLICT (invoice_id, source) DO UPDATE SET \
             issued_generation = invoice_direct_scan_heads.issued_generation + 1, \
             last_started_at = NOW(), updated_at = NOW() \
         RETURNING issued_generation",
    )
    .bind(invoice_id)
    .bind(source.as_str())
    .fetch_one(pool)
    .await
}

/// Atomically apply one complete positive/regression observation batch. This
/// API deliberately has no absence command: an omitted event is not evidence
/// that value disappeared, and the M-scan policy belongs to a later change.
pub async fn apply_direct_observation_batch(
    pool: &PgPool,
    batch: DirectObservationBatch<'_>,
    tolerances: InvoiceAccountingTolerances,
) -> Result<ApplyDirectObservationOutcome, sqlx::Error> {
    if batch.generation <= 0 {
        return protocol_error("direct observation generation must be positive");
    }
    if batch.authority.trim().is_empty() || batch.authority.len() > 200 {
        return protocol_error("direct observation authority is invalid");
    }
    validate_observation_batch(batch.source, batch.observations)?;

    let mut tx = pool.begin().await?;
    let offer_lock_key = super::invoice_lightning_lock_key(batch.invoice_id);
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(&offer_lock_key)
        .execute(&mut *tx)
        .await?;
    let invoice = sqlx::query_as::<_, LockedInvoice>(
        "SELECT amount_sat, status, presentation_status, \
                direct_settlement_status, swap_settlement_status, settlement_status, \
                paid_via, paid_amount_sat, expires_at <= NOW() AS expired \
         FROM invoices WHERE id = $1 FOR UPDATE",
    )
    .bind(batch.invoice_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| sqlx::Error::RowNotFound)?;

    let head: Option<(i64, i64)> = sqlx::query_as(
        "SELECT issued_generation, applied_generation \
         FROM invoice_direct_scan_heads \
         WHERE invoice_id = $1 AND source = $2 FOR UPDATE",
    )
    .bind(batch.invoice_id)
    .bind(batch.source.as_str())
    .fetch_optional(&mut *tx)
    .await?;
    let Some((issued_generation, applied_generation)) = head else {
        return protocol_error("direct observation generation was not reserved");
    };
    if batch.generation < issued_generation {
        tx.rollback().await?;
        return Ok(ApplyDirectObservationOutcome::Stale {
            current_generation: issued_generation,
        });
    }
    if batch.generation > issued_generation {
        return protocol_error("direct observation generation was never issued");
    }
    if batch.generation == applied_generation {
        tx.rollback().await?;
        return Ok(ApplyDirectObservationOutcome::AlreadyApplied);
    }
    if matches!(invoice.status.as_str(), "cancelled" | "expired") {
        mark_generation_applied(&mut tx, &batch, "cancelled").await?;
        tx.commit().await?;
        return Ok(ApplyDirectObservationOutcome::Closed);
    }

    // Serialize Liquid discovery against the compatibility/Boltz settlement
    // writer. The watcher may have fetched its exclusion set before a Boltz
    // claim committed; rechecking under the shared advisory boundary makes
    // either ordering safe: Boltz-first observations are ignored here, while
    // direct-first observations are superseded by the later Boltz writer.
    let boltz_settlement_txids: HashSet<String> = if batch.source == DirectPaymentSource::Liquid {
        sqlx::query_scalar(
            "SELECT DISTINCT LOWER(txid) \
                 FROM invoice_payment_events \
                 WHERE invoice_id = $1 \
                   AND source IN ('lightning_boltz_reverse', 'bitcoin_boltz_chain') \
                   AND txid IS NOT NULL",
        )
        .bind(batch.invoice_id)
        .fetch_all(&mut *tx)
        .await?
        .into_iter()
        .collect()
    } else {
        HashSet::new()
    };

    let mut changed = false;
    let mut pending_transitions = Vec::new();
    for observation in batch.observations {
        if boltz_settlement_txids.contains(&observation.txid.to_ascii_lowercase()) {
            continue;
        }
        let observation_mutation =
            upsert_direct_observation_locked(&mut tx, &batch, observation).await?;
        changed |= observation_mutation.changed;

        let event_mutation = ensure_direct_event_locked(
            &mut tx,
            batch.invoice_id,
            batch.source,
            observation_mutation.id,
            observation,
        )
        .await?;
        changed |= event_mutation.changed;

        if observation_mutation.should_append_transition || event_mutation.changed {
            pending_transitions.push(pending_direct_transition(
                observation_mutation.id,
                event_mutation.id,
                &observation_mutation.transition_before,
                event_mutation.from_state.as_deref(),
                event_mutation.to_state,
                observation,
            ));
        }

        if let Some(superseded_key) = observation.supersedes_event_key {
            let supersession = supersede_direct_event_locked(
                &mut tx,
                &batch,
                superseded_key,
                observation_mutation.id,
                event_mutation.id,
            )
            .await?;
            changed |= supersession.changed;
            if let Some(transition) = supersession.transition {
                pending_transitions.push(transition);
            }
        }
    }

    let projection_events = load_projection_events_locked(&mut tx, batch.invoice_id).await?;
    let projection = reduce_projection(&invoice, &projection_events, tolerances);
    let active_rails: Vec<String> = projection_events
        .iter()
        .filter(|event| {
            matches!(
                event.accounting_state.as_str(),
                "active" | "legacy_unverified"
            )
        })
        .map(|event| event.rail.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    let paid_via = match active_rails.as_slice() {
        [] => None,
        [rail] => Some(rail.as_str()),
        _ => Some("mixed"),
    };
    let paid_amount_sat = (projection.received_sat > 0).then_some(projection.received_sat);
    append_transitions_locked(
        &mut tx,
        &batch,
        &pending_transitions,
        &invoice,
        &projection,
        paid_amount_sat,
    )
    .await?;
    let projection_changed = invoice.status != projection.status
        || invoice.presentation_status.as_deref() != Some(projection.presentation_status)
        || invoice.direct_settlement_status != projection.direct_settlement_status
        || invoice.settlement_status != projection.settlement_status
        || invoice.paid_via.as_deref() != paid_via
        || invoice.paid_amount_sat != paid_amount_sat;
    if projection_changed {
        sqlx::query(
            "UPDATE invoices SET \
                 status = $2, presentation_status = $3, \
                 direct_settlement_status = $4, settlement_status = $5, \
                 paid_via = $6, paid_amount_sat = $7, \
                 paid_at = CASE \
                     WHEN $2 IN ('paid', 'overpaid') THEN COALESCE(paid_at, NOW()) \
                     ELSE NULL END, \
                 direct_payment_projection_version = direct_payment_projection_version + 1 \
             WHERE id = $1",
        )
        .bind(batch.invoice_id)
        .bind(projection.status)
        .bind(projection.presentation_status)
        .bind(projection.direct_settlement_status)
        .bind(projection.settlement_status)
        .bind(paid_via)
        .bind(paid_amount_sat)
        .execute(&mut *tx)
        .await?;
        changed = true;
    }
    mark_generation_applied(&mut tx, &batch, "applied").await?;
    tx.commit().await?;
    Ok(ApplyDirectObservationOutcome::Applied { changed })
}

async fn mark_generation_applied(
    tx: &mut Transaction<'_, Postgres>,
    batch: &DirectObservationBatch<'_>,
    outcome: &str,
) -> Result<(), sqlx::Error> {
    let rows = sqlx::query(
        "UPDATE invoice_direct_scan_heads SET applied_generation = $3, \
             last_applied_at = NOW(), last_authority = $4, last_outcome = $5, \
             updated_at = NOW() \
         WHERE invoice_id = $1 AND source = $2 \
           AND issued_generation = $3 AND applied_generation < $3",
    )
    .bind(batch.invoice_id)
    .bind(batch.source.as_str())
    .bind(batch.generation)
    .bind(batch.authority)
    .bind(outcome)
    .execute(&mut **tx)
    .await?
    .rows_affected();
    if rows != 1 {
        return protocol_error("direct observation generation lost its apply race");
    }
    Ok(())
}

async fn upsert_direct_observation_locked(
    tx: &mut Transaction<'_, Postgres>,
    batch: &DirectObservationBatch<'_>,
    observation: &DirectOutputObservation<'_>,
) -> Result<ObservationMutation, sqlx::Error> {
    let stored = sqlx::query_as::<_, StoredObservation>(
        "SELECT id, invoice_id, rail, source, event_key, txid, vout, address, \
                amount_sat, asset_id, confirmations, block_height, \
                inclusion_block_hash, last_seen_state, verification_state, \
                invalidation_reason, \
                superseded_by_observation_id, superseded_by_payment_event_id \
         FROM invoice_payment_observations WHERE event_key = $1 FOR UPDATE",
    )
    .bind(observation.event_key)
    .fetch_optional(&mut **tx)
    .await?;
    validate_block_regression_prior(
        stored.as_ref().map(|stored| {
            (
                stored.last_seen_state.as_str(),
                stored.block_height,
                stored.inclusion_block_hash.as_deref(),
            )
        }),
        observation.phase,
    )?;
    let next_state = observation.phase.observation_state();
    let next_verification = observation.verification.as_str();
    if let Some(stored) = stored {
        validate_stored_observation(&stored, batch, observation)?;
        if stored.last_seen_state == "superseded"
            || stored.superseded_by_observation_id.is_some()
            || stored.superseded_by_payment_event_id.is_some()
        {
            return protocol_error(
                "a superseded direct observation cannot be reactivated in place",
            );
        }
        if confirmed_block_identity_conflicts(
            ConfirmedBlockIdentity {
                state: &stored.last_seen_state,
                height: stored.block_height,
                hash: stored.inclusion_block_hash.as_deref(),
            },
            &stored.verification_state,
            ConfirmedBlockIdentity {
                state: next_state,
                height: observation.block_height,
                hash: observation.block_hash,
            },
            observation.phase,
        ) {
            return protocol_error(
                "confirmed direct block identity requires an explicit regression before replacement",
            );
        }
        let transition_change =
            stored.last_seen_state != next_state || stored.verification_state != next_verification;
        let invalidation_reason_change =
            stored.invalidation_reason.as_deref() != observation.phase.regression_reason();
        let invalidation_timestamp_mutation = invalidation_timestamp_mutation(
            stored.invalidation_reason.as_deref(),
            observation.phase.regression_reason(),
        );
        let logical_change = stored.confirmations != observation.confirmations
            || stored.block_height != observation.block_height
            || stored.inclusion_block_hash.as_deref() != observation.block_hash
            || transition_change
            || invalidation_reason_change;
        sqlx::query(
            "UPDATE invoice_payment_observations SET \
                 confirmations = $2, block_height = $3, inclusion_block_hash = $4, \
                 last_seen_state = $5, verification_state = $6, \
                 lifecycle_version = lifecycle_version + CASE WHEN $7 THEN 1 ELSE 0 END, \
                 latest_successful_check_at = NOW(), latest_check_authority = $8, \
                 last_applied_generation = $9, \
                 invalidation_reason = $10, \
                 invalidated_at = CASE \
                     WHEN $10::TEXT IS NULL THEN NULL \
                     WHEN $11 THEN NOW() \
                     ELSE invalidated_at END, \
                 last_seen_at = NOW() \
             WHERE id = $1",
        )
        .bind(stored.id)
        .bind(observation.confirmations)
        .bind(observation.block_height)
        .bind(observation.block_hash)
        .bind(next_state)
        .bind(next_verification)
        .bind(logical_change)
        .bind(batch.authority)
        .bind(batch.generation)
        .bind(observation.phase.regression_reason())
        .bind(matches!(
            invalidation_timestamp_mutation,
            InvalidationTimestampMutation::Stamp
        ))
        .execute(&mut **tx)
        .await?;
        Ok(ObservationMutation {
            id: stored.id,
            changed: logical_change,
            transition_before: ObservationTransitionBefore {
                observation_state: Some(stored.last_seen_state),
                verification_state: Some(stored.verification_state),
            },
            should_append_transition: transition_change
                || invalidation_reason_change
                || observation.phase.block_regression().is_some(),
        })
    } else {
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO invoice_payment_observations \
                 (invoice_id, rail, source, event_key, txid, vout, address, amount_sat, \
                  asset_id, confirmations, block_height, inclusion_block_hash, \
                  last_seen_state, verification_state, lifecycle_version, \
                  latest_successful_check_at, latest_check_authority, \
                  last_applied_generation, invalidation_reason, invalidated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, \
                     $13, $14, 1, NOW(), $15, $16, $17, \
                     CASE WHEN $17::TEXT IS NULL THEN NULL ELSE NOW() END) \
             RETURNING id",
        )
        .bind(batch.invoice_id)
        .bind(batch.source.rail())
        .bind(batch.source.as_str())
        .bind(observation.event_key)
        .bind(observation.txid)
        .bind(observation.vout)
        .bind(observation.address)
        .bind(observation.amount_sat)
        .bind(observation.asset_id)
        .bind(observation.confirmations)
        .bind(observation.block_height)
        .bind(observation.block_hash)
        .bind(next_state)
        .bind(next_verification)
        .bind(batch.authority)
        .bind(batch.generation)
        .bind(observation.phase.regression_reason())
        .fetch_one(&mut **tx)
        .await?;
        Ok(ObservationMutation {
            id,
            changed: true,
            transition_before: ObservationTransitionBefore {
                observation_state: None,
                verification_state: None,
            },
            should_append_transition: true,
        })
    }
}

fn validate_stored_observation(
    stored: &StoredObservation,
    batch: &DirectObservationBatch<'_>,
    observation: &DirectOutputObservation<'_>,
) -> Result<(), sqlx::Error> {
    if stored.invoice_id != batch.invoice_id
        || stored.rail != batch.source.rail()
        || stored.source != batch.source.as_str()
        || stored.event_key != observation.event_key
        || stored.txid != observation.txid
        || stored.vout != observation.vout
        || stored.address != observation.address
        || stored.amount_sat != observation.amount_sat
        || stored.asset_id.as_deref() != observation.asset_id
    {
        return protocol_error("direct observation immutable evidence mismatch");
    }
    Ok(())
}

fn validate_block_regression_prior(
    stored: Option<(&str, Option<i32>, Option<&str>)>,
    phase: DirectObservationPhase,
) -> Result<(), sqlx::Error> {
    let Some((_, prior_height, prior_hash, _)) = phase.block_regression() else {
        return Ok(());
    };
    let Some((stored_state, stored_height, stored_hash)) = stored else {
        return protocol_error(
            "positive block-regression evidence requires a stored prior observation",
        );
    };
    let prior_hash = hex::encode(prior_hash);
    if !matches!(stored_state, "awaiting_confirmations" | "counted")
        || stored_height != Some(prior_height)
        || !stored_hash.is_some_and(|hash| hash.eq_ignore_ascii_case(&prior_hash))
    {
        return protocol_error(
            "positive block-regression proof does not match stored block identity",
        );
    }
    Ok(())
}

struct ConfirmedBlockIdentity<'a> {
    state: &'a str,
    height: Option<i32>,
    hash: Option<&'a str>,
}

fn confirmed_block_identity_conflicts(
    stored: ConfirmedBlockIdentity<'_>,
    stored_verification_state: &str,
    next: ConfirmedBlockIdentity<'_>,
    phase: DirectObservationPhase,
) -> bool {
    let stored_has_positive_block = matches!(stored.state, "awaiting_confirmations" | "counted");
    let next_has_positive_block = matches!(next.state, "awaiting_confirmations" | "counted");
    let legacy_missing_hash_enrichment = stored_verification_state == "legacy_unverified"
        && stored.height == next.height
        && stored.hash.is_none()
        && next.hash.is_some();
    stored_has_positive_block
        && next_has_positive_block
        && (stored.height != next.height || stored.hash != next.hash)
        && !legacy_missing_hash_enrichment
        && phase.block_regression().is_none()
}

fn direct_transition_kind(
    before: &ObservationTransitionBefore,
    from_event_state: Option<&str>,
    observation: &DirectOutputObservation<'_>,
) -> &'static str {
    if observation.verification == DirectEvidenceVerification::Unverified {
        return "evidence_unverified";
    }
    if observation.verification == DirectEvidenceVerification::Verified
        && (before.verification_state.as_deref() == Some("legacy_unverified")
            || from_event_state == Some("legacy_unverified"))
    {
        return "legacy_revalidated";
    }
    match observation.phase {
        DirectObservationPhase::Provisional
        | DirectObservationPhase::Confirmed
        | DirectObservationPhase::Finalized
            if before.observation_state.as_deref() == Some("resolution_pending") =>
        {
            "reactivated"
        }
        DirectObservationPhase::Provisional => "observed_provisional",
        DirectObservationPhase::Confirmed => "accounting_activated",
        DirectObservationPhase::Finalized => "finalized",
        DirectObservationPhase::ReobservedAfterBlockRegression { .. } => "reactivated",
        DirectObservationPhase::ResolutionPending(_) => "resolution_pending",
    }
}

fn direct_transition_metadata(observation: &DirectOutputObservation<'_>) -> serde_json::Value {
    let Some((_, prior_height, prior_hash, reason)) = observation.phase.block_regression() else {
        return serde_json::json!({});
    };
    serde_json::json!({
        "block_regression_reason": reason.as_str(),
        "prior_block_height": prior_height,
        "prior_block_hash": hex::encode(prior_hash),
        "current_block_height": observation.block_height,
        "current_block_hash": observation.block_hash,
    })
}

fn pending_direct_transition(
    observation_id: Uuid,
    payment_event_id: Uuid,
    before: &ObservationTransitionBefore,
    from_event_state: Option<&str>,
    to_event_state: &str,
    observation: &DirectOutputObservation<'_>,
) -> PendingDirectTransition {
    PendingDirectTransition {
        observation_id,
        payment_event_id,
        transition_kind: direct_transition_kind(before, from_event_state, observation),
        from_observation_state: before.observation_state.clone(),
        to_observation_state: observation.phase.observation_state(),
        from_verification_state: before.verification_state.clone(),
        to_verification_state: observation.verification.as_str().to_owned(),
        from_event_state: from_event_state.map(str::to_owned),
        to_event_state: match to_event_state {
            "active" => "active",
            "inactive" => "inactive",
            _ => unreachable!("direct reducer produced an unsupported event state"),
        },
        reason: observation.phase.transition_reason(),
        metadata: direct_transition_metadata(observation),
    }
}

async fn append_transitions_locked(
    tx: &mut Transaction<'_, Postgres>,
    batch: &DirectObservationBatch<'_>,
    transitions: &[PendingDirectTransition],
    invoice: &LockedInvoice,
    projection: &ReducedProjection,
    paid_amount_sat: Option<i64>,
) -> Result<(), sqlx::Error> {
    for transition in transitions {
        let idempotency_key = format!("direct:{}:{}", transition.observation_id, batch.generation);
        sqlx::query(
            "INSERT INTO invoice_direct_payment_transitions \
                 (idempotency_key, invoice_id, observation_id, payment_event_id, \
                  source, generation, transition_kind, \
                  from_observation_state, to_observation_state, \
                  from_verification_state, to_verification_state, \
                  from_event_state, to_event_state, reason, \
                  from_presentation_status, to_presentation_status, \
                  from_settlement_status, to_settlement_status, \
                  from_invoice_status, to_invoice_status, \
                  from_paid_amount_sat, to_paid_amount_sat, metadata) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, \
                     $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23) \
             ON CONFLICT (observation_id, generation) DO NOTHING",
        )
        .bind(idempotency_key)
        .bind(batch.invoice_id)
        .bind(transition.observation_id)
        .bind(transition.payment_event_id)
        .bind(batch.source.as_str())
        .bind(batch.generation)
        .bind(transition.transition_kind)
        .bind(transition.from_observation_state.as_deref())
        .bind(transition.to_observation_state)
        .bind(transition.from_verification_state.as_deref())
        .bind(&transition.to_verification_state)
        .bind(transition.from_event_state.as_deref())
        .bind(transition.to_event_state)
        .bind(transition.reason)
        .bind(invoice.presentation_status.as_deref())
        .bind(projection.presentation_status)
        .bind(&invoice.settlement_status)
        .bind(projection.settlement_status)
        .bind(&invoice.status)
        .bind(projection.status)
        .bind(invoice.paid_amount_sat)
        .bind(paid_amount_sat)
        .bind(&transition.metadata)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

async fn ensure_direct_event_locked(
    tx: &mut Transaction<'_, Postgres>,
    invoice_id: Uuid,
    source: DirectPaymentSource,
    observation_id: Uuid,
    observation: &DirectOutputObservation<'_>,
) -> Result<EventMutation, sqlx::Error> {
    let stored = load_event_for_update(tx, observation.event_key).await?;
    let should_activate = observation
        .phase
        .activates_accounting(observation.verification);
    let desired_state = if should_activate {
        "active"
    } else {
        "inactive"
    };
    let desired_reason = if should_activate {
        None
    } else if let Some((_, _, _, reason)) = observation.phase.block_regression() {
        Some(reason.as_str())
    } else {
        observation
            .phase
            .regression_reason()
            .or(Some("not_confirmed"))
    };
    if let Some(stored) = stored {
        validate_stored_event(&stored, invoice_id, source, observation_id, observation)?;
        if stored.accounting_state == "superseded" || stored.superseded_by_event_id.is_some() {
            return protocol_error("a superseded direct event is terminal");
        }
        let desired_verification = observation.verification.event_state();
        let changed = stored.accounting_state != desired_state
            || stored.verification_state != desired_verification
            || stored.observation_id != Some(observation_id)
            || stored.deactivation_reason.as_deref() != desired_reason;
        let from_state = stored.accounting_state.clone();
        sqlx::query(
            "UPDATE invoice_payment_events SET \
                 accounting_state = $2, verification_state = $3, observation_id = $4, \
                 state_version = state_version + CASE WHEN $6 THEN 1 ELSE 0 END, \
                 last_activated_at = CASE \
                     WHEN $2 = 'active' AND accounting_state <> 'active' THEN NOW() \
                     ELSE last_activated_at END, \
                 deactivated_at = CASE \
                     WHEN $2 = 'active' THEN NULL \
                     WHEN accounting_state <> $2 THEN NOW() \
                     ELSE deactivated_at END, \
                 deactivation_reason = CASE WHEN $2 = 'active' THEN NULL ELSE $5 END \
             WHERE id = $1",
        )
        .bind(stored.id)
        .bind(desired_state)
        .bind(observation.verification.event_state())
        .bind(observation_id)
        .bind(desired_reason)
        .bind(changed)
        .execute(&mut **tx)
        .await?;
        Ok(EventMutation {
            id: stored.id,
            changed,
            from_state: Some(from_state),
            to_state: desired_state,
        })
    } else {
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO invoice_payment_events \
                 (invoice_id, rail, source, event_key, amount_sat, txid, vout, address, \
                  accounting_state, verification_state, observation_id, \
                  last_activated_at, deactivated_at, deactivation_reason) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, \
                     CASE WHEN $9 = 'active' THEN NOW() ELSE NULL END, \
                     CASE WHEN $9 = 'active' THEN NULL ELSE NOW() END, $12) \
             RETURNING id",
        )
        .bind(invoice_id)
        .bind(source.rail())
        .bind(source.as_str())
        .bind(observation.event_key)
        .bind(observation.amount_sat)
        .bind(observation.txid)
        .bind(observation.vout)
        .bind(observation.address)
        .bind(desired_state)
        .bind(observation.verification.event_state())
        .bind(observation_id)
        .bind(desired_reason)
        .fetch_one(&mut **tx)
        .await?;
        Ok(EventMutation {
            id,
            changed: true,
            from_state: None,
            to_state: desired_state,
        })
    }
}

async fn load_event_for_update(
    tx: &mut Transaction<'_, Postgres>,
    event_key: &str,
) -> Result<Option<StoredEvent>, sqlx::Error> {
    sqlx::query_as::<_, StoredEvent>(
        "SELECT id, invoice_id, rail, source, event_key, txid, vout, address, \
                amount_sat, accounting_state, verification_state, observation_id, \
                superseded_by_event_id, deactivation_reason \
         FROM invoice_payment_events WHERE event_key = $1 FOR UPDATE",
    )
    .bind(event_key)
    .fetch_optional(&mut **tx)
    .await
}

fn validate_stored_event(
    stored: &StoredEvent,
    invoice_id: Uuid,
    source: DirectPaymentSource,
    observation_id: Uuid,
    observation: &DirectOutputObservation<'_>,
) -> Result<(), sqlx::Error> {
    if stored.invoice_id != invoice_id
        || stored.rail != source.rail()
        || stored.source.as_deref() != Some(source.as_str())
        || stored.event_key != observation.event_key
        || stored.txid.as_deref() != Some(observation.txid)
        || stored.vout != Some(observation.vout)
        || stored.address.as_deref() != Some(observation.address)
        || stored.amount_sat != observation.amount_sat
        || stored.observation_id.is_some_and(|id| id != observation_id)
    {
        return protocol_error("direct accounting event immutable evidence mismatch");
    }
    Ok(())
}

async fn supersede_direct_event_locked(
    tx: &mut Transaction<'_, Postgres>,
    batch: &DirectObservationBatch<'_>,
    superseded_key: &str,
    replacement_observation_id: Uuid,
    replacement_event_id: Uuid,
) -> Result<SupersessionMutation, sqlx::Error> {
    let old_observation = sqlx::query_as::<_, StoredObservation>(
        "SELECT id, invoice_id, rail, source, event_key, txid, vout, address, \
                amount_sat, asset_id, confirmations, block_height, \
                inclusion_block_hash, last_seen_state, verification_state, \
                invalidation_reason, \
                superseded_by_observation_id, superseded_by_payment_event_id \
         FROM invoice_payment_observations WHERE event_key = $1 FOR UPDATE",
    )
    .bind(superseded_key)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| sqlx::Error::Protocol("superseded observation does not exist".into()))?;
    if old_observation.invoice_id != batch.invoice_id
        || old_observation.source != batch.source.as_str()
        || old_observation.id == replacement_observation_id
    {
        return protocol_error("replacement cannot supersede that direct observation");
    }
    let old_event = load_event_for_update(tx, superseded_key)
        .await?
        .ok_or_else(|| sqlx::Error::Protocol("superseded event does not exist".into()))?;
    if old_event.invoice_id != batch.invoice_id || old_event.id == replacement_event_id {
        return protocol_error("replacement cannot supersede that direct event");
    }
    if !direct_supersession_should_apply(
        &old_observation.last_seen_state,
        old_observation.superseded_by_observation_id,
        old_observation.superseded_by_payment_event_id,
        &old_event.accounting_state,
        old_event.superseded_by_event_id,
        replacement_observation_id,
        replacement_event_id,
    )? {
        return Ok(SupersessionMutation {
            changed: false,
            transition: None,
        });
    }
    sqlx::query(
        "UPDATE invoice_payment_observations SET \
             last_seen_state = 'superseded', \
             lifecycle_version = lifecycle_version + 1, \
             invalidation_reason = 'replaced', invalidated_at = NOW(), \
             superseded_by_observation_id = $2, \
             latest_successful_check_at = NOW(), latest_check_authority = $3, \
             last_applied_generation = $4, last_seen_at = NOW() \
         WHERE id = $1",
    )
    .bind(old_observation.id)
    .bind(replacement_observation_id)
    .bind(batch.authority)
    .bind(batch.generation)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "UPDATE invoice_payment_events SET \
             accounting_state = 'superseded', superseded_by_event_id = $2, \
             state_version = state_version + 1, \
             deactivated_at = NOW(), deactivation_reason = 'replaced' \
         WHERE id = $1",
    )
    .bind(old_event.id)
    .bind(replacement_event_id)
    .execute(&mut **tx)
    .await?;
    Ok(SupersessionMutation {
        changed: true,
        transition: Some(PendingDirectTransition {
            observation_id: old_observation.id,
            payment_event_id: old_event.id,
            transition_kind: "replacement",
            from_observation_state: Some(old_observation.last_seen_state),
            to_observation_state: "superseded",
            from_verification_state: Some(old_observation.verification_state.clone()),
            to_verification_state: old_observation.verification_state,
            from_event_state: Some(old_event.accounting_state),
            to_event_state: "superseded",
            reason: Some("replaced"),
            metadata: serde_json::json!({}),
        }),
    })
}

fn direct_supersession_should_apply(
    observation_state: &str,
    superseded_by_observation_id: Option<Uuid>,
    superseded_by_payment_event_id: Option<Uuid>,
    event_state: &str,
    superseded_by_event_id: Option<Uuid>,
    replacement_observation_id: Uuid,
    replacement_event_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let observation_is_terminal = observation_state == "superseded"
        || superseded_by_observation_id.is_some()
        || superseded_by_payment_event_id.is_some();
    let event_is_terminal = event_state == "superseded" || superseded_by_event_id.is_some();
    if !observation_is_terminal && !event_is_terminal {
        return Ok(true);
    }
    if observation_state == "superseded"
        && superseded_by_observation_id == Some(replacement_observation_id)
        && superseded_by_payment_event_id.is_none()
        && event_state == "superseded"
        && superseded_by_event_id == Some(replacement_event_id)
    {
        return Ok(false);
    }
    protocol_error("direct evidence was already superseded by a different payment")
}

async fn load_projection_events_locked(
    tx: &mut Transaction<'_, Postgres>,
    invoice_id: Uuid,
) -> Result<Vec<ProjectionEvent>, sqlx::Error> {
    sqlx::query_as::<_, ProjectionEvent>(
        "SELECT e.rail, e.source, e.amount_sat, e.accounting_sequence, e.accounting_state, \
                o.last_seen_state AS observation_state, e.verification_state \
         FROM invoice_payment_events e \
         LEFT JOIN invoice_payment_observations o ON o.id = e.observation_id \
         WHERE e.invoice_id = $1 \
         ORDER BY e.accounting_sequence ASC, e.id ASC",
    )
    .bind(invoice_id)
    .fetch_all(&mut **tx)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    const TXID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const BLOCK_HASH: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const NEW_BLOCK_HASH: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn block_identity<'a>(
        state: &'a str,
        height: Option<i32>,
        hash: Option<&'a str>,
    ) -> ConfirmedBlockIdentity<'a> {
        ConfirmedBlockIdentity {
            state,
            height,
            hash,
        }
    }

    fn tolerances() -> InvoiceAccountingTolerances {
        InvoiceAccountingTolerances {
            btc_sat: 300,
            liquid_sat: 60,
            lightning_sat: 1,
            payment_grace_secs: 0,
        }
    }

    fn invoice() -> LockedInvoice {
        LockedInvoice {
            amount_sat: 100_000,
            status: "unpaid".into(),
            presentation_status: Some("unpaid".into()),
            direct_settlement_status: "none".into(),
            swap_settlement_status: "none".into(),
            settlement_status: "none".into(),
            paid_via: None,
            paid_amount_sat: None,
            expired: false,
        }
    }

    fn projection_event(
        accounting_state: &str,
        observation_state: &str,
        amount_sat: i64,
    ) -> ProjectionEvent {
        ProjectionEvent {
            rail: "bitcoin".into(),
            source: Some("bitcoin_direct".into()),
            amount_sat,
            accounting_sequence: 1,
            accounting_state: accounting_state.into(),
            observation_state: Some(observation_state.into()),
            verification_state: "verified".into(),
        }
    }

    fn bitcoin_observation<'a>(
        event_key: &'a str,
        txid: &'a str,
        vout: i32,
        verification: DirectEvidenceVerification,
        phase: DirectObservationPhase,
        supersedes_event_key: Option<&'a str>,
    ) -> DirectOutputObservation<'a> {
        let has_block = matches!(
            phase.observation_state(),
            "awaiting_confirmations" | "counted"
        );
        DirectOutputObservation {
            event_key,
            txid,
            vout,
            address: "bc1qreducerfoundation",
            amount_sat: 100_000,
            asset_id: None,
            confirmations: i32::from(has_block),
            block_height: has_block.then_some(900_000),
            block_hash: has_block.then_some(BLOCK_HASH),
            verification,
            phase,
            supersedes_event_key,
        }
    }

    #[test]
    fn accounting_replay_is_stable_by_sequence_and_preserves_per_rail_tolerance() {
        let events = vec![
            AccountingReplayEvent {
                rail: "liquid",
                amount_sat: 150,
                sequence: 2,
            },
            AccountingReplayEvent {
                rail: "bitcoin",
                amount_sat: 99_750,
                sequence: 1,
            },
        ];
        let projection = replay_accounting(100_000, false, events, tolerances());
        assert_eq!(projection.status, "paid");
        assert_eq!(projection.received_sat, 99_900);
    }

    #[test]
    fn replay_without_active_events_has_no_accounting_value() {
        let projection = replay_accounting(100_000, false, Vec::new(), tolerances());
        assert_eq!(projection.status, "unpaid");
        assert_eq!(projection.received_sat, 0);
    }

    #[test]
    fn verified_provisional_value_changes_presentation_but_not_accounting() {
        let projection = reduce_projection(
            &invoice(),
            &[projection_event("inactive", "seen_unconfirmed", 100_000)],
            tolerances(),
        );
        assert_eq!(projection.status, "in_progress");
        assert_eq!(projection.presentation_status, "payment_received");
        assert_eq!(projection.direct_settlement_status, "pending");
        assert_eq!(projection.settlement_status, "pending");
        assert_eq!(projection.received_sat, 0);
    }

    #[test]
    fn presentation_combines_accounted_swap_and_provisional_direct_value() {
        let mut direct = projection_event("inactive", "seen_unconfirmed", 40_000);
        direct.accounting_sequence = 2;
        let swap = ProjectionEvent {
            rail: "lightning".into(),
            source: Some("lightning_boltz_reverse".into()),
            amount_sat: 60_000,
            accounting_sequence: 1,
            accounting_state: "active".into(),
            observation_state: None,
            verification_state: "not_applicable".into(),
        };
        let projection = reduce_projection(&invoice(), &[swap, direct], tolerances());
        assert_eq!(projection.status, "partially_paid");
        assert_eq!(projection.presentation_status, "payment_received");
        assert_eq!(projection.direct_settlement_status, "pending");
        assert_eq!(projection.received_sat, 60_000);
    }

    #[test]
    fn resolution_pending_excludes_invalidated_value_from_presentation() {
        let projection = reduce_projection(
            &invoice(),
            &[projection_event("inactive", "resolution_pending", 40_000)],
            tolerances(),
        );
        assert_eq!(projection.status, "in_progress");
        assert_eq!(projection.presentation_status, "unpaid");
        assert_eq!(projection.direct_settlement_status, "resolution_pending");
        assert_eq!(projection.received_sat, 0);
    }

    #[test]
    fn swap_incidents_remain_public_over_direct_resolution() {
        for incident in ["claim_stuck", "failed", "refunded"] {
            assert_eq!(
                public_settlement_status("resolution_pending", incident),
                incident
            );
        }
        assert_eq!(
            public_settlement_status("resolution_pending", "none"),
            "resolution_pending"
        );
    }

    #[test]
    fn confirmed_then_finalized_separates_accounting_from_finality() {
        let confirmed = reduce_projection(
            &invoice(),
            &[projection_event(
                "active",
                "awaiting_confirmations",
                100_000,
            )],
            tolerances(),
        );
        assert_eq!(confirmed.status, "paid");
        assert_eq!(confirmed.presentation_status, "payment_received");
        assert_eq!(confirmed.direct_settlement_status, "pending");
        assert_eq!(confirmed.received_sat, 100_000);

        let finalized = reduce_projection(
            &invoice(),
            &[projection_event("active", "counted", 100_000)],
            tolerances(),
        );
        assert_eq!(finalized.status, "paid");
        assert_eq!(finalized.direct_settlement_status, "settled");
        assert_eq!(finalized.settlement_status, "settled");
    }

    #[test]
    fn positive_regression_removes_accounting_without_silent_unpaid() {
        let projection = reduce_projection(
            &invoice(),
            &[projection_event("inactive", "resolution_pending", 100_000)],
            tolerances(),
        );
        assert_eq!(projection.status, "in_progress");
        assert_eq!(projection.presentation_status, "unpaid");
        assert_eq!(projection.direct_settlement_status, "resolution_pending");
        assert_eq!(projection.received_sat, 0);
    }

    #[test]
    fn superseded_value_is_not_presented_or_counted() {
        let projection = reduce_projection(
            &invoice(),
            &[projection_event("superseded", "superseded", 100_000)],
            tolerances(),
        );
        assert_eq!(projection.status, "unpaid");
        assert_eq!(projection.presentation_status, "unpaid");
        assert_eq!(projection.direct_settlement_status, "none");
        assert_eq!(projection.received_sat, 0);
    }

    #[test]
    fn confirmed_evidence_requires_complete_block_identity() {
        let observation = DirectOutputObservation {
            event_key: &format!("bitcoin_direct:{TXID}:0"),
            txid: TXID,
            vout: 0,
            address: "bc1qfoundation",
            amount_sat: 100_000,
            asset_id: None,
            confirmations: 1,
            block_height: Some(900_000),
            block_hash: None,
            verification: DirectEvidenceVerification::Verified,
            phase: DirectObservationPhase::Confirmed,
            supersedes_event_key: None,
        };
        assert!(observation.validate(DirectPaymentSource::Bitcoin).is_err());
    }

    #[test]
    fn only_verified_positive_evidence_can_activate_accounting_and_presentation() {
        assert!(DirectObservationPhase::Confirmed
            .activates_accounting(DirectEvidenceVerification::Verified));
        assert!(!DirectObservationPhase::Confirmed
            .activates_accounting(DirectEvidenceVerification::Unverified));
        assert!(DirectObservationPhase::Provisional
            .contributes_to_presentation(DirectEvidenceVerification::Verified));
        assert!(!DirectObservationPhase::Provisional
            .contributes_to_presentation(DirectEvidenceVerification::Unverified));
    }

    #[test]
    fn a_valid_replacement_must_be_verified_and_distinct() {
        let event_key = format!("bitcoin_direct:{TXID}:1");
        let superseded = format!("bitcoin_direct:{}:0", "c".repeat(64));
        let observation = DirectOutputObservation {
            event_key: &event_key,
            txid: TXID,
            vout: 1,
            address: "bc1qreplacement",
            amount_sat: 100_000,
            asset_id: None,
            confirmations: 1,
            block_height: Some(900_000),
            block_hash: Some(BLOCK_HASH),
            verification: DirectEvidenceVerification::Verified,
            phase: DirectObservationPhase::Confirmed,
            supersedes_event_key: Some(&superseded),
        };
        assert!(observation.validate(DirectPaymentSource::Bitcoin).is_ok());
    }

    #[test]
    fn confirmed_unverified_evidence_is_rejected_before_writes() {
        let event_key = format!("bitcoin_direct:{TXID}:0");
        let observation = bitcoin_observation(
            &event_key,
            TXID,
            0,
            DirectEvidenceVerification::Unverified,
            DirectObservationPhase::Confirmed,
            None,
        );
        assert!(observation.validate(DirectPaymentSource::Bitcoin).is_err());
    }

    #[test]
    fn unverified_non_accounting_evidence_uses_its_dedicated_transition_kind() {
        let event_key = format!("bitcoin_direct:{TXID}:0");
        let before = ObservationTransitionBefore {
            observation_state: Some("seen_unconfirmed".into()),
            verification_state: Some("verified".into()),
        };
        for phase in [
            DirectObservationPhase::Provisional,
            DirectObservationPhase::ResolutionPending(DirectRegressionReason::Conflict),
        ] {
            let observation = bitcoin_observation(
                &event_key,
                TXID,
                0,
                DirectEvidenceVerification::Unverified,
                phase,
                None,
            );
            assert!(observation.validate(DirectPaymentSource::Bitcoin).is_ok());
            assert_eq!(
                direct_transition_kind(&before, Some("inactive"), &observation),
                "evidence_unverified"
            );
        }
    }

    #[test]
    fn invalidation_timestamp_is_sticky_until_reason_or_positive_state_changes() {
        assert_eq!(
            invalidation_timestamp_mutation(Some("reorged"), Some("reorged")),
            InvalidationTimestampMutation::Preserve
        );
        assert_eq!(
            invalidation_timestamp_mutation(Some("reorged"), Some("conflict")),
            InvalidationTimestampMutation::Stamp
        );
        assert_eq!(
            invalidation_timestamp_mutation(None, Some("reorged")),
            InvalidationTimestampMutation::Stamp
        );
        assert_eq!(
            invalidation_timestamp_mutation(Some("reorged"), None),
            InvalidationTimestampMutation::Clear
        );
    }

    #[test]
    fn one_batch_cannot_contain_competing_replacements() {
        let replacement_a_txid = "c".repeat(64);
        let replacement_b_txid = "d".repeat(64);
        let old_key = format!("bitcoin_direct:{TXID}:0");
        let replacement_a_key = format!("bitcoin_direct:{replacement_a_txid}:0");
        let replacement_b_key = format!("bitcoin_direct:{replacement_b_txid}:0");
        let observations = [
            bitcoin_observation(
                &replacement_a_key,
                &replacement_a_txid,
                0,
                DirectEvidenceVerification::Verified,
                DirectObservationPhase::Confirmed,
                Some(&old_key),
            ),
            bitcoin_observation(
                &replacement_b_key,
                &replacement_b_txid,
                0,
                DirectEvidenceVerification::Verified,
                DirectObservationPhase::Confirmed,
                Some(&old_key),
            ),
        ];
        assert!(validate_observation_batch(DirectPaymentSource::Bitcoin, &observations).is_err());
    }

    #[test]
    fn a_distinct_later_replacement_cannot_claim_an_already_superseded_event() {
        let old_replacement_observation_id = Uuid::new_v4();
        let old_replacement_event_id = Uuid::new_v4();
        assert!(!direct_supersession_should_apply(
            "superseded",
            Some(old_replacement_observation_id),
            None,
            "superseded",
            Some(old_replacement_event_id),
            old_replacement_observation_id,
            old_replacement_event_id,
        )
        .unwrap());
        assert!(direct_supersession_should_apply(
            "superseded",
            Some(old_replacement_observation_id),
            None,
            "superseded",
            Some(old_replacement_event_id),
            Uuid::new_v4(),
            Uuid::new_v4(),
        )
        .is_err());
    }

    #[test]
    fn boltz_supersession_is_terminal_to_direct_replacement() {
        assert!(direct_supersession_should_apply(
            "superseded",
            None,
            Some(Uuid::new_v4()),
            "superseded",
            Some(Uuid::new_v4()),
            Uuid::new_v4(),
            Uuid::new_v4(),
        )
        .is_err());
    }

    #[test]
    fn confirmed_to_provisional_is_an_audited_accounting_demotion() {
        let event_key = format!("bitcoin_direct:{TXID}:0");
        let observation = bitcoin_observation(
            &event_key,
            TXID,
            0,
            DirectEvidenceVerification::Verified,
            DirectObservationPhase::Provisional,
            None,
        );
        let before = ObservationTransitionBefore {
            observation_state: Some("awaiting_confirmations".into()),
            verification_state: Some("verified".into()),
        };
        let observation_id = Uuid::new_v4();
        let event_id = Uuid::new_v4();
        let transition = pending_direct_transition(
            observation_id,
            event_id,
            &before,
            Some("active"),
            "inactive",
            &observation,
        );
        assert_eq!(transition.observation_id, observation_id);
        assert_eq!(transition.payment_event_id, event_id);
        assert_eq!(transition.transition_kind, "observed_provisional");
        assert_eq!(transition.from_event_state.as_deref(), Some("active"));
        assert_eq!(transition.to_event_state, "inactive");
    }

    #[test]
    fn positive_legacy_evidence_is_labeled_revalidated() {
        let event_key = format!("bitcoin_direct:{TXID}:0");
        let observation = bitcoin_observation(
            &event_key,
            TXID,
            0,
            DirectEvidenceVerification::Verified,
            DirectObservationPhase::Confirmed,
            None,
        );
        let before = ObservationTransitionBefore {
            observation_state: Some("awaiting_confirmations".into()),
            verification_state: Some("legacy_unverified".into()),
        };
        let transition = pending_direct_transition(
            Uuid::new_v4(),
            Uuid::new_v4(),
            &before,
            Some("legacy_unverified"),
            "active",
            &observation,
        );
        assert_eq!(transition.transition_kind, "legacy_revalidated");
        assert_eq!(
            transition.from_event_state.as_deref(),
            Some("legacy_unverified")
        );
        assert_eq!(transition.to_event_state, "active");
    }

    #[test]
    fn confirmed_block_identity_change_requires_an_explicit_demotion() {
        assert!(!confirmed_block_identity_conflicts(
            block_identity("awaiting_confirmations", Some(900_000), Some(BLOCK_HASH)),
            "verified",
            block_identity("counted", Some(900_000), Some(BLOCK_HASH)),
            DirectObservationPhase::Finalized,
        ));
        assert!(confirmed_block_identity_conflicts(
            block_identity("awaiting_confirmations", Some(900_000), Some(BLOCK_HASH)),
            "verified",
            block_identity(
                "awaiting_confirmations",
                Some(900_001),
                Some(&"c".repeat(64)),
            ),
            DirectObservationPhase::Confirmed,
        ));
        assert!(!confirmed_block_identity_conflicts(
            block_identity("awaiting_confirmations", Some(900_000), Some(BLOCK_HASH)),
            "verified",
            block_identity("seen_unconfirmed", None, None),
            DirectObservationPhase::Provisional,
        ));

        let atomic_reobservation = DirectObservationPhase::reobserved_after_block_regression(
            DirectPositivePhase::Confirmed,
            900_000,
            BLOCK_HASH,
            DirectRegressionReason::Reorged,
        )
        .unwrap();
        assert!(!confirmed_block_identity_conflicts(
            block_identity("awaiting_confirmations", Some(900_000), Some(BLOCK_HASH)),
            "verified",
            block_identity(
                "awaiting_confirmations",
                Some(900_001),
                Some(&"c".repeat(64)),
            ),
            atomic_reobservation,
        ));
        assert!(!confirmed_block_identity_conflicts(
            block_identity("counted", Some(900_000), None),
            "legacy_unverified",
            block_identity("counted", Some(900_000), Some(BLOCK_HASH)),
            DirectObservationPhase::Finalized,
        ));
        assert!(confirmed_block_identity_conflicts(
            block_identity("counted", Some(900_000), None),
            "verified",
            block_identity("counted", Some(900_000), Some(BLOCK_HASH)),
            DirectObservationPhase::Finalized,
        ));
        assert!(confirmed_block_identity_conflicts(
            block_identity("counted", Some(900_000), None),
            "legacy_unverified",
            block_identity("counted", Some(900_001), Some(BLOCK_HASH)),
            DirectObservationPhase::Finalized,
        ));
        assert!(confirmed_block_identity_conflicts(
            block_identity("counted", Some(900_000), Some(BLOCK_HASH)),
            "legacy_unverified",
            block_identity("counted", Some(900_000), Some(NEW_BLOCK_HASH)),
            DirectObservationPhase::Finalized,
        ));
    }

    #[test]
    fn atomic_block_regression_requires_and_audits_matching_prior_identity() {
        assert!(DirectObservationPhase::reobserved_after_block_regression(
            DirectPositivePhase::Confirmed,
            900_000,
            BLOCK_HASH,
            DirectRegressionReason::Conflict,
        )
        .is_err());
        let phase = DirectObservationPhase::reobserved_after_block_regression(
            DirectPositivePhase::Confirmed,
            900_000,
            BLOCK_HASH,
            DirectRegressionReason::Reorged,
        )
        .unwrap();
        assert!(validate_block_regression_prior(None, phase).is_err());
        assert!(validate_block_regression_prior(
            Some(("awaiting_confirmations", Some(900_001), Some(BLOCK_HASH))),
            phase,
        )
        .is_err());
        assert!(validate_block_regression_prior(
            Some(("awaiting_confirmations", Some(900_000), Some(BLOCK_HASH))),
            phase,
        )
        .is_ok());

        let observation = DirectOutputObservation {
            event_key:
                "bitcoin_direct:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:0",
            txid: TXID,
            vout: 0,
            address: "bc1qreducerfoundation",
            amount_sat: 100_000,
            asset_id: None,
            confirmations: 1,
            block_height: Some(900_001),
            block_hash: Some(NEW_BLOCK_HASH),
            verification: DirectEvidenceVerification::Verified,
            phase,
            supersedes_event_key: None,
        };
        observation.validate(DirectPaymentSource::Bitcoin).unwrap();
        let transition = pending_direct_transition(
            Uuid::new_v4(),
            Uuid::new_v4(),
            &ObservationTransitionBefore {
                observation_state: Some("awaiting_confirmations".into()),
                verification_state: Some("verified".into()),
            },
            Some("active"),
            "active",
            &observation,
        );
        assert_eq!(transition.transition_kind, "reactivated");
        assert_eq!(transition.reason, Some("reorged"));
        assert_eq!(transition.metadata["prior_block_height"], 900_000);
        assert_eq!(transition.metadata["prior_block_hash"], BLOCK_HASH);
        assert_eq!(transition.metadata["current_block_height"], 900_001);
        assert_eq!(transition.metadata["current_block_hash"], NEW_BLOCK_HASH);
    }
}
