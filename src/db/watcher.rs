use sqlx::PgPool;
use uuid::Uuid;

use super::invoices::WatcherScanCursor;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatcherLaneWorker {
    BitcoinDirect,
    LiquidDirect,
}

impl WatcherLaneWorker {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BitcoinDirect => "bitcoin_direct",
            Self::LiquidDirect => "liquid_direct",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatcherLane {
    Recent,
    Historical,
}

impl WatcherLane {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recent => "recent",
            Self::Historical => "historical",
        }
    }
}

/// Load a restart rotation offset. A row with a null pair is equivalent to no
/// saved offset; persisted progress is scheduling input and never health proof.
pub async fn load_watcher_lane_cursor(
    pool: &PgPool,
    worker: WatcherLaneWorker,
    lane: WatcherLane,
) -> Result<Option<WatcherScanCursor>, sqlx::Error> {
    let row = sqlx::query_as::<_, (Option<String>, Option<Uuid>)>(
        "SELECT cursor_created_at::TEXT, cursor_invoice_id \
         FROM watcher_lane_progress \
         WHERE worker = $1 AND lane = $2",
    )
    .bind(worker.as_str())
    .bind(lane.as_str())
    .fetch_optional(pool)
    .await?;

    match row {
        None | Some((None, None)) => Ok(None),
        Some((Some(created_at), Some(id))) => Ok(Some(WatcherScanCursor { created_at, id })),
        Some(_) => Err(sqlx::Error::Protocol(
            "watcher lane cursor contains a partial key".into(),
        )),
    }
}

/// Advance one lane only after its caller has fully applied or explicitly
/// isolated the invoice obligation. The upsert is intentionally separate from
/// the idempotent obligation transaction: a crash between them repeats work;
/// it cannot skip work.
pub async fn persist_watcher_lane_cursor(
    pool: &PgPool,
    worker: WatcherLaneWorker,
    lane: WatcherLane,
    cursor: &WatcherScanCursor,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO watcher_lane_progress ( \
             worker, lane, cursor_created_at, cursor_invoice_id, updated_at \
         ) VALUES ($1, $2, $3::timestamptz, $4, clock_timestamp()) \
         ON CONFLICT (worker, lane) DO UPDATE \
         SET cursor_created_at = EXCLUDED.cursor_created_at, \
             cursor_invoice_id = EXCLUDED.cursor_invoice_id, \
             updated_at = clock_timestamp()",
    )
    .bind(worker.as_str())
    .bind(lane.as_str())
    .bind(&cursor.created_at)
    .bind(cursor.id)
    .execute(pool)
    .await?;
    Ok(())
}

const BITCOIN_WATCHER_ELIGIBLE_PREDICATE: &str = "bitcoin_address IS NOT NULL \
       AND ( \
             ( \
               status IN ('unpaid', 'in_progress', 'partially_paid') \
               AND accept_btc = TRUE \
               AND expires_at + ($2 || ' seconds')::interval > $3::timestamptz \
             ) \
             OR status IN ('cancelled', 'expired') \
             OR EXISTS ( \
               SELECT 1 FROM invoice_payment_observations o \
               WHERE o.invoice_id = invoices.id \
                 AND o.source = 'bitcoin_direct' \
                 AND o.last_seen_state <> 'superseded' \
             ) \
             OR EXISTS ( \
               SELECT 1 FROM invoice_payment_events e \
               WHERE e.invoice_id = invoices.id \
                 AND e.source = 'bitcoin_direct' \
                 AND e.accounting_state <> 'superseded' \
             ) \
           )";

/// One canonical priority definition shared by both page and lag queries.
/// Historical is constructed as its literal negation inside the same eligible
/// set, so an invoice cannot enter both lanes or fall into a nullable gap.
const BITCOIN_WATCHER_PRIORITY_PREDICATE: &str = "( \
             created_at > $3::timestamptz - ($1 || ' seconds')::interval \
             OR COALESCE(presentation_status = 'partial', FALSE) \
             OR direct_settlement_status IN ('pending', 'resolution_pending') \
           )";

const BITCOIN_WATCHER_PAGE_SQL_TEMPLATE: &str = "SELECT \
            id, bitcoin_address, amount_sat, fiat_currency, \
            created_at::TEXT AS created_at_cursor \
     FROM invoices \
     WHERE {eligible} \
       AND {lane_predicate} \
       AND created_at <= $3::timestamptz \
       AND ( \
             $4::timestamptz IS NULL \
             OR (created_at, id) > ($4::timestamptz, $5::uuid) \
           ) \
       AND ( \
             $6::timestamptz IS NULL \
             OR (created_at, id) <= ($6::timestamptz, $7::uuid) \
           ) \
     ORDER BY created_at ASC, id ASC \
     LIMIT $8";

const BITCOIN_WATCHER_LAG_SQL_TEMPLATE: &str = "SELECT \
            COUNT(*)::BIGINT, \
            MIN(created_at)::TEXT, \
            COALESCE( \
                GREATEST( \
                    0, \
                    FLOOR(EXTRACT(EPOCH FROM ( \
                        $3::timestamptz - MIN(created_at) \
                    )))::BIGINT \
                ), \
                0 \
            )::BIGINT \
     FROM invoices \
     WHERE {eligible} \
       AND {lane_predicate} \
       AND created_at <= $3::timestamptz";

fn bitcoin_watcher_lane_sql(template: &str, lane: WatcherLane) -> String {
    let lane_predicate = match lane {
        WatcherLane::Recent => BITCOIN_WATCHER_PRIORITY_PREDICATE.to_string(),
        WatcherLane::Historical => format!("NOT {BITCOIN_WATCHER_PRIORITY_PREDICATE}"),
    };
    template
        .replace("{eligible}", BITCOIN_WATCHER_ELIGIBLE_PREDICATE)
        .replace("{lane_predicate}", &lane_predicate)
}

#[derive(Debug, sqlx::FromRow)]
pub struct BitcoinWatcherInvoicePageRow {
    pub id: Uuid,
    pub bitcoin_address: String,
    pub amount_sat: i64,
    /// Present only for fiat-fixed invoices. The watcher uses this exact
    /// invoice snapshot to request a candidate covering first observation.
    pub fiat_currency: Option<String>,
    pub created_at_cursor: String,
}

impl BitcoinWatcherInvoicePageRow {
    pub fn scan_cursor(&self) -> WatcherScanCursor {
        WatcherScanCursor {
            created_at: self.created_at_cursor.clone(),
            id: self.id,
        }
    }
}

pub struct BitcoinWatcherInvoicePage {
    pub rows: Vec<BitcoinWatcherInvoicePageRow>,
    pub has_more: bool,
}

/// Deterministic, bounded page in one frozen Bitcoin invoice lane. The caller
/// supplies a lower cursor and an optional inclusive wrap limit.
#[allow(clippy::too_many_arguments)]
pub async fn list_bitcoin_watcher_invoice_page(
    pool: &PgPool,
    active_window_secs: i64,
    payment_grace_secs: i64,
    snapshot: &str,
    lane: WatcherLane,
    cursor: Option<&WatcherScanCursor>,
    wrap_limit: Option<&WatcherScanCursor>,
    batch_size: usize,
) -> Result<BitcoinWatcherInvoicePage, sqlx::Error> {
    let fetch_limit = batch_size
        .checked_add(1)
        .and_then(|limit| i64::try_from(limit).ok())
        .ok_or_else(|| sqlx::Error::Protocol("Bitcoin watcher batch limit overflow".into()))?;
    let sql = bitcoin_watcher_lane_sql(BITCOIN_WATCHER_PAGE_SQL_TEMPLATE, lane);
    let mut rows = sqlx::query_as::<_, BitcoinWatcherInvoicePageRow>(&sql)
        .bind(active_window_secs)
        .bind(payment_grace_secs)
        .bind(snapshot)
        .bind(cursor.map(|cursor| cursor.created_at.as_str()))
        .bind(cursor.map(|cursor| cursor.id))
        .bind(wrap_limit.map(|cursor| cursor.created_at.as_str()))
        .bind(wrap_limit.map(|cursor| cursor.id))
        .bind(fetch_limit)
        .fetch_all(pool)
        .await?;
    let has_more = rows.len() > batch_size;
    rows.truncate(batch_size);
    Ok(BitcoinWatcherInvoicePage { rows, has_more })
}

pub async fn bitcoin_watcher_lane_lag(
    pool: &PgPool,
    active_window_secs: i64,
    payment_grace_secs: i64,
    snapshot: &str,
    lane: WatcherLane,
) -> Result<(i64, Option<String>, i64), sqlx::Error> {
    let sql = bitcoin_watcher_lane_sql(BITCOIN_WATCHER_LAG_SQL_TEMPLATE, lane);
    sqlx::query_as(&sql)
        .bind(active_window_secs)
        .bind(payment_grace_secs)
        .bind(snapshot)
        .fetch_one(pool)
        .await
}

// =====================================================================
// Chain watcher helpers (added 2026-04-27)
// =====================================================================

const NYM_WATCHER_BATCH_SIZE: usize = 1_000;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WatcherNymScanEpoch {
    snapshot: Option<String>,
    cursor: Option<String>,
    current: Option<WatcherNymAddressScan>,
}

/// Frozen address work for one nym inside a process-local watcher epoch.
///
/// `next_index..=end_index` is captured from the row as it first enters the
/// epoch. Advancing `users.next_addr_idx` while history is processed therefore
/// cannot grow this epoch's work forever. The exact `next_index` is retained
/// across rate-limit and backend failures so no address is skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatcherNymAddressScan {
    pub nym: String,
    pub ct_descriptor: String,
    pub next_index: u32,
    pub end_index: u32,
}

impl WatcherNymScanEpoch {
    pub fn snapshot(&self) -> Option<&str> {
        self.snapshot.as_deref()
    }

    pub fn cursor(&self) -> Option<&str> {
        self.cursor.as_deref()
    }

    /// Keyset position for the next database page. A frozen current nym is
    /// resumed entirely from process-local state, so later rows can be fetched
    /// strictly after it without depending on the nym still being active.
    pub fn query_cursor(&self) -> Option<&str> {
        self.current
            .as_ref()
            .map(|current| current.nym.as_str())
            .or_else(|| self.cursor())
    }

    pub fn current(&self) -> Option<&WatcherNymAddressScan> {
        self.current.as_ref()
    }

    pub fn begin(&mut self, snapshot: String) {
        if self.snapshot.is_none() {
            self.snapshot = Some(snapshot);
        }
    }

    pub fn advance(&mut self, nym: String) {
        self.cursor = Some(nym);
        self.current = None;
    }

    /// Start a bounded address scan unless one is already in flight. The
    /// descriptor and inclusive end are frozen with the first row observation.
    pub fn begin_nym(
        &mut self,
        nym: String,
        ct_descriptor: String,
        base_index: u32,
        lookahead: u32,
    ) -> bool {
        if self.current.is_some() {
            return true;
        }

        // `users.next_addr_idx` is i32 and a history hit stores
        // `observed_idx + 1`. Keep the entire frozen range within that exact
        // representable domain; wrapping or lossy `as i32` casts are forbidden.
        let Some(end_index) = base_index.checked_add(lookahead) else {
            return false;
        };
        if end_index >= i32::MAX as u32 {
            return false;
        }
        self.current = Some(WatcherNymAddressScan {
            nym,
            ct_descriptor,
            next_index: base_index,
            end_index,
        });
        true
    }

    /// Mark the exact current address as safely visited. Returns `true` once
    /// the frozen inclusive range is drained and the nym keyset cursor advances.
    pub fn visit_current_address(&mut self) -> bool {
        let Some(current) = self.current.as_mut() else {
            return false;
        };
        if current.next_index < current.end_index {
            current.next_index += 1;
            return false;
        }

        self.finish_current_nym();
        true
    }

    /// Retire a malformed, deactivated, or disappeared current nym without
    /// allowing it to pin every later keyset row.
    pub fn finish_current_nym(&mut self) {
        if let Some(current) = self.current.take() {
            self.cursor = Some(current.nym);
        }
    }

    pub fn finish(&mut self) {
        self.snapshot = None;
        self.cursor = None;
        self.current = None;
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ActiveNymForWatcher {
    pub nym: String,
    pub ct_descriptor: String,
    pub next_addr_idx: i32,
}

pub struct ActiveNymWatcherPage {
    pub rows: Vec<ActiveNymForWatcher>,
    pub has_more: bool,
}

fn truncate_to_nym_watcher_batch<T>(rows: &mut Vec<T>, limit: usize) -> bool {
    let has_more = rows.len() > limit;
    rows.truncate(limit);
    has_more
}

/// Deterministic page through all watchable nyms that existed at `snapshot`.
/// The process-local caller retains the same snapshot and `nym` cursor until
/// the epoch completes, so a permanently full first page cannot starve later
/// rows and newly-created users wait for the next epoch. Deactivation closes
/// new Lightning Address instructions; it does not erase addresses already
/// issued from the retained descriptor. Purge clears the descriptor and thus
/// removes the row from this set.
pub async fn list_active_nyms_for_watcher_page(
    pool: &PgPool,
    snapshot: &str,
    cursor: Option<&str>,
) -> Result<ActiveNymWatcherPage, sqlx::Error> {
    let mut rows = sqlx::query_as::<_, ActiveNymForWatcher>(
        "SELECT nym, ct_descriptor, next_addr_idx \
         FROM users \
         WHERE (is_active = TRUE \
                OR (ct_descriptor <> '' \
                    AND (last_callback_at IS NOT NULL OR has_been_used = TRUE))) \
           AND created_at <= $1::timestamptz \
           AND ($2::text IS NULL OR nym > $2::text) \
         ORDER BY nym ASC \
         LIMIT $3",
    )
    .bind(snapshot)
    .bind(cursor)
    .bind((NYM_WATCHER_BATCH_SIZE + 1) as i64)
    .fetch_all(pool)
    .await?;
    let has_more = truncate_to_nym_watcher_batch(&mut rows, NYM_WATCHER_BATCH_SIZE);
    Ok(ActiveNymWatcherPage { rows, has_more })
}

/// Deterministic page through the active recent-callback tier. Both the activity-window
/// cutoff and the maximum callback timestamp are anchored to the epoch's
/// PostgreSQL snapshot: activity occurring after the cutoff waits for the
/// next epoch instead of changing membership between pages. Offline obligations
/// remain in the historical watchable tier without adding an unindexed scan of
/// every inactive row to each fast tick.
pub async fn list_recently_active_nyms_for_watcher_page(
    pool: &PgPool,
    active_window_secs: u32,
    snapshot: &str,
    cursor: Option<&str>,
) -> Result<ActiveNymWatcherPage, sqlx::Error> {
    let mut rows = sqlx::query_as::<_, ActiveNymForWatcher>(
        "SELECT nym, ct_descriptor, next_addr_idx \
         FROM users \
         WHERE is_active = TRUE \
           AND created_at <= $1::timestamptz \
           AND last_callback_at > $1::timestamptz - ($2 || ' seconds')::interval \
           AND last_callback_at <= $1::timestamptz \
           AND ($3::text IS NULL OR nym > $3::text) \
         ORDER BY nym ASC \
         LIMIT $4",
    )
    .bind(snapshot)
    .bind(active_window_secs as i32)
    .bind(cursor)
    .bind((NYM_WATCHER_BATCH_SIZE + 1) as i64)
    .fetch_all(pool)
    .await?;
    let has_more = truncate_to_nym_watcher_batch(&mut rows, NYM_WATCHER_BATCH_SIZE);
    Ok(ActiveNymWatcherPage { rows, has_more })
}

pub async fn list_active_nyms_for_watcher(
    pool: &PgPool,
) -> Result<Vec<ActiveNymForWatcher>, sqlx::Error> {
    let rows: Vec<(String, String, i32)> = sqlx::query_as(
        "SELECT nym, ct_descriptor, next_addr_idx \
           FROM users \
          WHERE is_active = TRUE \
             OR (ct_descriptor <> '' \
                 AND (last_callback_at IS NOT NULL OR has_been_used = TRUE))",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(nym, ct_descriptor, next_addr_idx)| ActiveNymForWatcher {
            nym,
            ct_descriptor,
            next_addr_idx,
        })
        .collect())
}

/// Watcher's active recent set: users whose `last_callback_at` is within the
/// last `active_window_secs`. This is the hot list scanned every fast
/// tick. Bounded in size by real callback traffic, not by the size of
/// the `users` table. Product deactivation moves retained obligations to the
/// historical watchable tier instead of ending observation.
pub async fn list_recently_active_nyms_for_watcher(
    pool: &PgPool,
    active_window_secs: u32,
) -> Result<Vec<ActiveNymForWatcher>, sqlx::Error> {
    let rows: Vec<(String, String, i32)> = sqlx::query_as(
        "SELECT nym, ct_descriptor, next_addr_idx \
         FROM users \
         WHERE is_active = TRUE \
           AND last_callback_at > NOW() - ($1 || ' seconds')::interval",
    )
    .bind(active_window_secs as i32)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(nym, ct_descriptor, next_addr_idx)| ActiveNymForWatcher {
            nym,
            ct_descriptor,
            next_addr_idx,
        })
        .collect())
}

/// Mark that a user was just hit by `/lnurlp/callback`. Drives the
/// watcher's activity prioritization. Best-effort: an error here is
/// logged but not propagated — failing to update activity should never
/// fail a successful payment-address lookup.
pub async fn touch_user_callback(pool: &PgPool, nym: &str) {
    if let Err(e) =
        sqlx::query("UPDATE users SET last_callback_at = NOW() WHERE nym = $1 AND is_active = TRUE")
            .bind(nym)
            .execute(pool)
            .await
    {
        tracing::warn!("touch_user_callback: nym={nym} failed: {e}");
    }
}

/// Advance `users.next_addr_idx` past `observed_idx`, but only if it hasn't
/// already advanced beyond it. Idempotent under concurrent observations:
/// the `next_addr_idx <= observed_idx` guard ensures this update is a no-op
/// when the row has already moved on (e.g. due to a request handler
/// allocation racing with the watcher). This remains live after product
/// deactivation for an already-issued address; a purge clears the descriptor
/// and prevents any later cursor mutation.
pub async fn advance_next_addr_idx(
    pool: &PgPool,
    nym: &str,
    observed_idx: u32,
) -> Result<(), sqlx::Error> {
    let observed_idx = i32::try_from(observed_idx).map_err(|_| {
        sqlx::Error::Protocol("observed Liquid address index exceeds i32 storage".into())
    })?;
    let next_addr_idx = observed_idx.checked_add(1).ok_or_else(|| {
        sqlx::Error::Protocol("next Liquid address index exceeds i32 storage".into())
    })?;
    sqlx::query(
        "UPDATE users SET next_addr_idx = $2 \
         WHERE nym = $1 AND ct_descriptor <> '' AND next_addr_idx <= $3",
    )
    .bind(nym)
    .bind(next_addr_idx)
    .bind(observed_idx)
    .execute(pool)
    .await?;
    Ok(())
}

/// Mark every still-pending reservation that targets `addr_index` for `nym`
/// as fulfilled. Called by the chain watcher when a payment is observed at
/// `derive(descriptor, addr_index)` — under last-unused mode many concurrent
/// senders may share a single addr_index, so a single observed payment can
/// flip multiple rows. Returns the number of rows updated for diagnostics.
pub async fn mark_reservations_fulfilled_at_idx(
    pool: &PgPool,
    nym: &str,
    addr_index: u32,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE outpoint_addresses \
            SET fulfilled = TRUE, fulfilled_at = NOW() \
          WHERE nym = $1 AND addr_index = $2 AND fulfilled = FALSE",
    )
    .bind(nym)
    .bind(addr_index as i32)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitcoin_lane_queries_share_one_priority_and_exact_historical_negation() {
        let recent =
            bitcoin_watcher_lane_sql(BITCOIN_WATCHER_PAGE_SQL_TEMPLATE, WatcherLane::Recent);
        let historical =
            bitcoin_watcher_lane_sql(BITCOIN_WATCHER_PAGE_SQL_TEMPLATE, WatcherLane::Historical);

        assert!(recent.contains(BITCOIN_WATCHER_PRIORITY_PREDICATE));
        assert!(historical.contains(&format!("NOT {BITCOIN_WATCHER_PRIORITY_PREDICATE}")));
        assert_eq!(
            recent.matches(BITCOIN_WATCHER_ELIGIBLE_PREDICATE).count(),
            1
        );
        assert_eq!(
            historical
                .matches(BITCOIN_WATCHER_ELIGIBLE_PREDICATE)
                .count(),
            1
        );
        assert!(BITCOIN_WATCHER_PRIORITY_PREDICATE
            .contains("COALESCE(presentation_status = 'partial', FALSE)"));
        assert!(BITCOIN_WATCHER_PRIORITY_PREDICATE
            .contains("direct_settlement_status IN ('pending', 'resolution_pending')"));
        assert!(
            BITCOIN_WATCHER_ELIGIBLE_PREDICATE.contains("OR status IN ('cancelled', 'expired')")
        );
        assert!(!recent.contains("NOW()"));
        assert!(recent.contains("(created_at, id) >"));
        assert!(recent.contains("(created_at, id) <="));

        let recent_lag =
            bitcoin_watcher_lane_sql(BITCOIN_WATCHER_LAG_SQL_TEMPLATE, WatcherLane::Recent);
        let historical_lag =
            bitcoin_watcher_lane_sql(BITCOIN_WATCHER_LAG_SQL_TEMPLATE, WatcherLane::Historical);
        assert!(recent_lag.contains(BITCOIN_WATCHER_PRIORITY_PREDICATE));
        assert!(historical_lag.contains(&format!("NOT {BITCOIN_WATCHER_PRIORITY_PREDICATE}")));
    }

    #[test]
    fn nym_watcher_batch_detects_only_the_sentinel_boundary() {
        for (fetched, expected_more) in [
            (NYM_WATCHER_BATCH_SIZE - 1, false),
            (NYM_WATCHER_BATCH_SIZE, false),
            (NYM_WATCHER_BATCH_SIZE + 1, true),
        ] {
            let mut rows = vec![(); fetched];
            assert_eq!(
                truncate_to_nym_watcher_batch(&mut rows, NYM_WATCHER_BATCH_SIZE),
                expected_more,
                "unexpected has_more for {fetched} fetched nyms"
            );
            assert_eq!(rows.len(), fetched.min(NYM_WATCHER_BATCH_SIZE));
        }
    }

    #[test]
    fn nym_epoch_keeps_snapshot_and_resumes_after_the_last_complete_nym() {
        let mut epoch = WatcherNymScanEpoch::default();
        epoch.begin("2026-07-12 12:00:00+00".to_string());
        epoch.advance("alice".to_string());

        // A later page retains the original PostgreSQL cutoff and begins
        // after the last nym whose whole lookahead completed.
        epoch.begin("2026-07-12 13:00:00+00".to_string());
        assert_eq!(epoch.snapshot(), Some("2026-07-12 12:00:00+00"));
        assert_eq!(epoch.cursor(), Some("alice"));

        epoch.advance("bob".to_string());
        assert_eq!(epoch.cursor(), Some("bob"));

        epoch.finish();
        assert!(epoch.snapshot().is_none());
        assert!(epoch.cursor().is_none());
    }

    #[test]
    fn all_history_across_frozen_range_converges_without_extending_the_epoch() {
        let mut epoch = WatcherNymScanEpoch::default();
        epoch.begin("2026-07-12 12:00:00+00".to_string());
        assert!(epoch.begin_nym("busy".to_string(), "frozen-descriptor".to_string(), 40, 3));

        // Model history at every address: after each pair of safe idempotent
        // writes, the caller visits exactly one frozen index. Live advancement
        // of users.next_addr_idx cannot append work beyond index 43.
        for expected_index in 40..=43 {
            let current = epoch.current().expect("frozen nym address");
            assert_eq!(current.next_index, expected_index);
            assert_eq!(current.end_index, 43);
            assert_eq!(
                epoch.visit_current_address(),
                expected_index == 43,
                "frozen range completed at the wrong address"
            );
        }
        assert!(epoch.current().is_none());
        assert_eq!(epoch.cursor(), Some("busy"));
        assert_eq!(epoch.query_cursor(), Some("busy"));
    }

    #[test]
    fn mid_nym_resume_retains_exact_address_and_frozen_descriptor() {
        let mut epoch = WatcherNymScanEpoch::default();
        epoch.begin("2026-07-12 12:00:00+00".to_string());
        assert!(epoch.begin_nym(
            "bob".to_string(),
            "descriptor-at-epoch-start".to_string(),
            7,
            2,
        ));
        assert!(!epoch.visit_current_address());

        let retained = epoch.current().expect("partial frozen nym").clone();
        assert_eq!(retained.next_index, 8);
        assert_eq!(retained.end_index, 9);
        assert_eq!(epoch.cursor(), None);
        assert_eq!(epoch.query_cursor(), Some("bob"));

        // A retry cannot replace the retained subcursor with refreshed live
        // row state after token exhaustion or a backend error.
        assert!(epoch.begin_nym(
            "bob".to_string(),
            "changed-live-descriptor".to_string(),
            500,
            10,
        ));
        assert_eq!(epoch.current(), Some(&retained));
    }

    #[test]
    fn failed_or_partial_nym_retains_exact_subcursor() {
        let mut epoch = WatcherNymScanEpoch::default();
        epoch.begin("2026-07-12 12:00:00+00".to_string());
        epoch.advance("alice".to_string());
        assert!(epoch.begin_nym("bob".to_string(), "descriptor".to_string(), 12, 4));
        let before_failure = epoch.current().expect("current nym").clone();

        // A backend failure deliberately calls neither visit nor finish, so
        // the same address is retried while DB paging starts after bob.
        assert_eq!(epoch.cursor(), Some("alice"));
        assert_eq!(epoch.query_cursor(), Some("bob"));
        assert_eq!(epoch.current(), Some(&before_failure));
        assert_eq!(epoch.snapshot(), Some("2026-07-12 12:00:00+00"));
    }

    #[test]
    fn disappeared_or_malformed_nym_can_be_retired_and_full_finish_clears_state() {
        let mut epoch = WatcherNymScanEpoch::default();
        epoch.begin("2026-07-12 12:00:00+00".to_string());
        assert!(epoch.begin_nym("gone".to_string(), "descriptor".to_string(), 1, 10));

        // The caller may retire a malformed nym immediately. A disappeared or
        // purged nym instead remains safely bounded in memory and reaches this
        // same state after its frozen range drains.
        epoch.finish_current_nym();
        assert!(epoch.current().is_none());
        assert_eq!(epoch.cursor(), Some("gone"));
        assert_eq!(epoch.query_cursor(), Some("gone"));

        assert!(epoch.begin_nym("later".to_string(), "descriptor".to_string(), 3, 1));
        epoch.finish();
        assert!(epoch.snapshot().is_none());
        assert!(epoch.cursor().is_none());
        assert!(epoch.current().is_none());
        assert!(epoch.query_cursor().is_none());
    }

    #[test]
    fn unrepresentable_frozen_range_is_rejected_without_partial_state() {
        let mut epoch = WatcherNymScanEpoch::default();
        assert!(!epoch.begin_nym(
            "overflow".to_string(),
            "descriptor".to_string(),
            i32::MAX as u32 - 1,
            1,
        ));
        assert!(epoch.current().is_none());
        assert!(epoch.cursor().is_none());
    }
}
