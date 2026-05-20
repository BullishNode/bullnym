use sqlx::PgPool;
use uuid::Uuid;

// =====================================================================
// Invoices
//
// Unified payment-intent abstraction. `origin` discriminates two creation
// flows: 'checkout' (anonymous browser, server-rate-limited per source) and
// 'wallet' (recipient's mobile, Schnorr-signed). Lightning offers attach
// 1:N via `swap_records.invoice_id`; Liquid offer is 1:1 and present at
// invoice creation for flows that accept Liquid or Lightning.
//
// Timestamp columns are NOT read into Rust structs as DateTime values —
// the workspace deliberately avoids the chrono/time sqlx feature flag.
// Instead, projections expose timestamps as `BIGINT` Unix epoch seconds
// via `EXTRACT(EPOCH FROM col)::BIGINT AS col_unix`. SQL boolean
// expressions (`expires_at < NOW()` etc.) handle every comparison
// server-side.
// =====================================================================

#[derive(Debug, sqlx::FromRow)]
pub struct Invoice {
    pub id: Uuid,
    /// Merchant payment-page nym; NULL for unlinked (wallet-only) invoices.
    pub nym_owner: Option<String>,
    /// Canonical recipient identity (hex x-only Schnorr pubkey). Always set.
    pub npub_owner: String,
    pub origin: String,
    pub fiat_amount_minor: Option<i32>,
    pub fiat_currency: Option<String>,
    pub amount_sat: i64,
    pub rate_minor_per_btc: Option<i64>,
    pub memo: Option<String>,
    pub recipient_label: Option<String>,
    pub bitcoin_address: Option<String>,
    pub accept_btc: bool,
    pub accept_ln: bool,
    pub accept_liquid: bool,
    pub public_description: Option<String>,
    pub invoice_number: Option<String>,
    pub liquid_address: Option<String>,
    pub liquid_address_index: Option<i32>,
    pub status: String,
    pub paid_via: Option<String>,
    pub paid_amount_sat: Option<i64>,
    pub pricing_mode: String,
    pub settlement_status: String,
    pub liquid_blinding_key_hex: Option<String>,
    /// Unix epoch seconds. See section comment above for the timestamp
    /// projection convention.
    pub created_at_unix: i64,
    pub expires_at_unix: i64,
    pub rate_locked_at_unix: i64,
    pub rate_locks_until_unix: i64,
    pub paid_at_unix: Option<i64>,
    pub cancelled_at_unix: Option<i64>,
}

/// Single source of truth for the `Invoice` SQL projection. Centralized
/// so a new column added to the struct is reflected in exactly one place
/// (mirrors the SwapRecord pattern). FromRow matches by alias name, so
/// the order is cosmetic.
const INVOICE_COLUMNS: &str =
    "id, nym_owner, npub_owner, origin, fiat_amount_minor, fiat_currency, amount_sat, \
     rate_minor_per_btc, memo, recipient_label, \
     bitcoin_address, accept_btc, accept_ln, accept_liquid, \
     public_description, invoice_number, \
     liquid_address, liquid_address_index, status, paid_via, paid_amount_sat, \
     pricing_mode, settlement_status, liquid_blinding_key_hex, \
     EXTRACT(EPOCH FROM created_at)::BIGINT       AS created_at_unix, \
     EXTRACT(EPOCH FROM expires_at)::BIGINT       AS expires_at_unix, \
     EXTRACT(EPOCH FROM rate_locked_at)::BIGINT   AS rate_locked_at_unix, \
     EXTRACT(EPOCH FROM rate_locks_until)::BIGINT AS rate_locks_until_unix, \
     EXTRACT(EPOCH FROM paid_at)::BIGINT          AS paid_at_unix, \
     EXTRACT(EPOCH FROM cancelled_at)::BIGINT     AS cancelled_at_unix";

pub struct NewInvoice<'a> {
    /// Merchant payment-page nym, or `None` for unlinked (wallet-only) invoices.
    pub nym_owner: Option<&'a str>,
    /// Canonical recipient identity (hex x-only Schnorr pubkey). Required.
    pub npub_owner: &'a str,
    /// 'checkout' or 'wallet'. Caller validates against the enum upstream.
    pub origin: &'a str,
    pub fiat_amount_minor: Option<i32>,
    pub fiat_currency: Option<&'a str>,
    pub amount_sat: i64,
    pub rate_minor_per_btc: Option<i64>,
    /// Wall-clock seconds the rate stays locked from `now()`. For
    /// sat-denominated invoices, pass `expires_in_secs` so
    /// `rate_locks_until == expires_at` and the on-demand refresh path
    /// naturally never fires.
    pub rate_lock_secs: i64,
    pub memo: Option<&'a str>,
    pub recipient_label: Option<&'a str>,
    pub public_description: Option<&'a str>,
    pub invoice_number: Option<&'a str>,
    pub accept_btc: bool,
    pub accept_ln: bool,
    pub accept_liquid: bool,
    /// Wallet-supplied BTC mainnet address (NULL when accept_btc=FALSE).
    pub bitcoin_address: Option<&'a str>,
    /// Liquid mainnet CT address (NULL when both accept_ln=FALSE and
    /// accept_liquid=FALSE). Two supply paths feed this field:
    ///   - Wallet-origin (Get-paid): wallet supplies the address directly.
    ///   - Checkout-origin (donation page): server eagerly allocates
    ///     via `allocate_next_liquid_for_active_nym` BEFORE this insert.
    ///
    /// In both cases `liquid_address_index` on the invoice row stays
    /// NULL; the address is the chain watcher's lookup key, not the
    /// descriptor index.
    pub liquid_address: Option<&'a str>,
    pub liquid_blinding_key_hex: Option<&'a str>,
    /// Wall-clock seconds the invoice stays valid from `now()`.
    pub expires_in_secs: i64,
}

/// Insert a new invoice row. The caller is responsible for populating
/// `liquid_address` when `accept_ln` or `accept_liquid` is TRUE — the
/// `invoices_ln_or_liquid_addr_chk` constraint requires it at INSERT
/// time. Two supply paths:
///   - Wallet-origin (Get-paid): the wallet supplies the address.
///   - Checkout-origin (donation page): the caller invokes
///     `allocate_next_liquid_for_active_nym` to bump the owner's
///     descriptor index and derive the next address, then passes the
///     result through `NewInvoice.liquid_address`.
///
/// Lightning offers attach via a separate `record_swap` call that sets
/// `swap_records.invoice_id`; the claimer routes the LN claim to the
/// invoice's `liquid_address` via `resolve_claim_address` branch (B).
pub async fn insert_invoice(
    pool: &PgPool,
    invoice: &NewInvoice<'_>,
) -> Result<Invoice, sqlx::Error> {
    let mut tx = pool.begin().await?;

    let inserted = sqlx::query_as::<_, Invoice>(&format!(
        "INSERT INTO invoices \
            (nym_owner, npub_owner, origin, fiat_amount_minor, fiat_currency, amount_sat, \
             rate_minor_per_btc, rate_locks_until, memo, recipient_label, \
             public_description, invoice_number, \
             accept_btc, accept_ln, accept_liquid, \
             bitcoin_address, liquid_address, pricing_mode, liquid_blinding_key_hex, \
             expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, \
                 NOW() + ($8 || ' seconds')::interval, $9, $10, \
                 $11, $12, $13, $14, $15, $16, $17, \
                 CASE WHEN $7::BIGINT IS NULL THEN 'sat_fixed' ELSE 'fiat_fixed' END, $18, \
                 NOW() + ($19 || ' seconds')::interval) \
         RETURNING {INVOICE_COLUMNS}"
    ))
    .bind(invoice.nym_owner)
    .bind(invoice.npub_owner)
    .bind(invoice.origin)
    .bind(invoice.fiat_amount_minor)
    .bind(invoice.fiat_currency)
    .bind(invoice.amount_sat)
    .bind(invoice.rate_minor_per_btc)
    .bind(invoice.rate_lock_secs)
    .bind(invoice.memo)
    .bind(invoice.recipient_label)
    .bind(invoice.public_description)
    .bind(invoice.invoice_number)
    .bind(invoice.accept_btc)
    .bind(invoice.accept_ln)
    .bind(invoice.accept_liquid)
    .bind(invoice.bitcoin_address)
    .bind(invoice.liquid_address)
    .bind(invoice.liquid_blinding_key_hex)
    .bind(invoice.expires_in_secs)
    .fetch_one(&mut *tx)
    .await?;

    if let Some(address) = invoice.bitcoin_address {
        sqlx::query(
            "INSERT INTO invoice_payment_addresses (invoice_id, rail, address) \
             VALUES ($1, 'bitcoin', $2)",
        )
        .bind(inserted.id)
        .bind(address)
        .execute(&mut *tx)
        .await?;
    }

    if let Some(address) = invoice.liquid_address {
        sqlx::query(
            "INSERT INTO invoice_payment_addresses (invoice_id, rail, address) \
             VALUES ($1, 'liquid', $2)",
        )
        .bind(inserted.id)
        .bind(address)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(inserted)
}

pub async fn get_invoice_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Invoice>, sqlx::Error> {
    sqlx::query_as::<_, Invoice>(&format!(
        "SELECT {INVOICE_COLUMNS} FROM invoices WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await
}

/// Best-effort cleanup for checkout creation failures after the invoice row
/// exists but before any payment offer was returned to the sender.
pub async fn delete_unpaid_invoice_without_swaps(
    pool: &PgPool,
    id: Uuid,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        "DELETE FROM invoices i \
         WHERE i.id = $1 \
           AND i.status = 'unpaid' \
           AND NOT EXISTS (SELECT 1 FROM swap_records s WHERE s.invoice_id = i.id)",
    )
    .bind(id)
    .execute(pool)
    .await
    .map(|r| r.rows_affected())
}

/// List invoices for an npub_owner, newest-first, with optional filters.
///
/// `status_filter`: `Some("unpaid"|"paid"|...)` filters by status;
/// `None` returns all statuses. `page` is one-based and `page_size`
/// is caller-clamped.
///
/// Predicate uses `($p::TYPE IS NULL OR ...)` so the planner can skip the
/// filter entirely when not provided. The composite index
/// `invoices_npub_owner_status_created_idx` services the ORDER BY.
pub async fn list_invoices_by_npub(
    pool: &PgPool,
    npub_owner: &str,
    status_filter: Option<&str>,
    page: i64,
    page_size: i64,
) -> Result<Vec<Invoice>, sqlx::Error> {
    let offset = (page.saturating_sub(1)).saturating_mul(page_size);
    sqlx::query_as::<_, Invoice>(&format!(
        "SELECT {INVOICE_COLUMNS} FROM invoices \
         WHERE npub_owner = $1 \
           AND ($2::TEXT IS NULL OR status = $2) \
         ORDER BY created_at DESC \
         LIMIT $3 OFFSET $4"
    ))
    .bind(npub_owner)
    .bind(status_filter)
    .bind(page_size)
    .bind(offset)
    .fetch_all(pool)
    .await
}

/// List unpaid invoices' Liquid addresses for a nym_owner, ordered by
/// address_index. Returned shape `(invoice_id, address_index, address,
/// remaining amount and blinding key) gives the chain watcher everything
/// it needs to unblind candidate txs and record exact payment events.
///
/// Scoped to rows with a stored descriptor index. Wallet-supplied addresses
/// are covered by `list_unpaid_invoices_with_liquid_address`.
pub async fn list_unpaid_invoice_liquid_addresses(
    pool: &PgPool,
    nym_owner: &str,
) -> Result<Vec<(Uuid, i32, String, i64, String)>, sqlx::Error> {
    sqlx::query_as::<_, (Uuid, i32, String, i64, String)>(
        "SELECT id, liquid_address_index, liquid_address, amount_sat, liquid_blinding_key_hex \
         FROM invoices \
         WHERE nym_owner = $1 \
           AND status IN ('unpaid', 'in_progress', 'partially_paid') \
           AND accept_liquid = TRUE \
           AND liquid_address IS NOT NULL \
           AND liquid_blinding_key_hex IS NOT NULL \
           AND liquid_address_index IS NOT NULL \
         ORDER BY liquid_address_index ASC",
    )
    .bind(nym_owner)
    .fetch_all(pool)
    .await
}

/// Address-keyed scan for the chain watcher: every unpaid/in_progress
/// invoice with a settable Liquid address, regardless of nym_owner (so
/// linked + unlinked are covered uniformly) and regardless of how the
/// address was sourced (descriptor allocator OR wallet-supplied).
///
/// `ORDER BY created_at ASC` keeps scans deterministic if a client ever
/// reuses a wallet-supplied address. Payment events are idempotent by
/// outpoint, so repeated watcher ticks do not double count. Bounded by
/// `LIMIT 1000` so a runaway invoice pipeline can't blow the watcher's
/// per-tick budget; the next tick re-queries.
///
/// Returned shape: `(invoice_id, liquid_address, amount_sat)`.
pub async fn list_unpaid_invoices_with_liquid_address(
    pool: &PgPool,
) -> Result<Vec<(Uuid, String, i64, String)>, sqlx::Error> {
    sqlx::query_as::<_, (Uuid, String, i64, String)>(
        "SELECT id, liquid_address, GREATEST(amount_sat - COALESCE(paid_amount_sat, 0), 0), liquid_blinding_key_hex \
         FROM invoices \
         WHERE (status IN ('unpaid', 'in_progress', 'partially_paid') \
                OR (origin = 'checkout' AND status = 'underpaid')) \
           AND accept_liquid = TRUE \
           AND liquid_address IS NOT NULL \
           AND liquid_blinding_key_hex IS NOT NULL \
           AND expires_at > NOW() \
         ORDER BY created_at ASC \
         LIMIT 1000",
    )
    .fetch_all(pool)
    .await
}

#[derive(Debug, Clone, Copy)]
pub struct InvoiceAccountingTolerances {
    pub btc_sat: i64,
    pub liquid_sat: i64,
    pub lightning_sat: i64,
}

impl Default for InvoiceAccountingTolerances {
    fn default() -> Self {
        Self {
            btc_sat: 300,
            liquid_sat: 60,
            lightning_sat: 1,
        }
    }
}

impl From<&crate::config::InvoiceAccountingConfig> for InvoiceAccountingTolerances {
    fn from(cfg: &crate::config::InvoiceAccountingConfig) -> Self {
        Self {
            btc_sat: cfg.btc_shortfall_tolerance_sat,
            liquid_sat: cfg.liquid_shortfall_tolerance_sat,
            lightning_sat: cfg.lightning_shortfall_tolerance_sat,
        }
    }
}

impl InvoiceAccountingTolerances {
    fn for_rail(self, rail: &str) -> i64 {
        match rail {
            "bitcoin" => self.btc_sat,
            "liquid" => self.liquid_sat,
            "lightning" => self.lightning_sat,
            _ => 0,
        }
        .max(0)
    }
}

fn payment_tolerance_sat_for_amount(
    amount_sat: i64,
    rail: &str,
    tolerances: InvoiceAccountingTolerances,
) -> i64 {
    let one_percent = (amount_sat / 100).max(1);
    tolerances.for_rail(rail).min(one_percent).max(0)
}

pub struct InvoicePaymentEvidence<'a> {
    pub rail: &'a str,
    pub source: &'a str,
    pub event_key: &'a str,
    pub amount_sat: i64,
    pub txid: Option<&'a str>,
    pub vout: Option<i32>,
    pub boltz_swap_id: Option<&'a str>,
    pub address: Option<&'a str>,
}

#[derive(Debug, sqlx::FromRow)]
pub struct InvoicePaymentObservation {
    pub rail: String,
    pub source: String,
    pub event_key: String,
    pub txid: String,
    pub vout: i32,
    pub address: String,
    pub amount_sat: i64,
    pub confirmations: i32,
    pub block_height: Option<i32>,
    pub last_seen_state: String,
    pub first_seen_at_unix: i64,
    pub last_seen_at_unix: i64,
}

pub struct NewInvoicePaymentObservation<'a> {
    pub rail: &'a str,
    pub source: &'a str,
    pub event_key: &'a str,
    pub txid: &'a str,
    pub vout: i32,
    pub address: &'a str,
    pub amount_sat: i64,
    pub confirmations: i32,
    pub block_height: Option<i32>,
    pub last_seen_state: &'a str,
}

impl NewInvoicePaymentObservation<'_> {
    fn validate(&self) -> Result<(), sqlx::Error> {
        if self.rail != "bitcoin" || self.source != "bitcoin_direct" {
            return Err(sqlx::Error::Protocol(format!(
                "invalid invoice payment observation source/rail pair: {}/{}",
                self.source, self.rail
            )));
        }
        if self.amount_sat <= 0 {
            return Err(sqlx::Error::Protocol(
                "observation amount_sat must be > 0".into(),
            ));
        }
        if self.vout < 0 {
            return Err(sqlx::Error::Protocol(
                "observation vout must be non-negative".into(),
            ));
        }
        if self.txid.len() != 64 || !self.txid.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(sqlx::Error::Protocol(
                "observation txid must be 64 hex characters".into(),
            ));
        }
        let expected_event_key = format!("bitcoin_direct:{}:{}", self.txid, self.vout);
        if self.event_key != expected_event_key {
            return Err(sqlx::Error::Protocol(
                "observation event_key must be bitcoin_direct:<txid>:<vout>".into(),
            ));
        }
        if self.address.len() < 14 || self.address.len() > 90 {
            return Err(sqlx::Error::Protocol(
                "observation address length is invalid".into(),
            ));
        }
        if self.confirmations < 0 {
            return Err(sqlx::Error::Protocol(
                "observation confirmations must be non-negative".into(),
            ));
        }
        match self.last_seen_state {
            "seen_unconfirmed" => {
                if self.confirmations != 0 || self.block_height.is_some() {
                    return Err(sqlx::Error::Protocol(
                        "seen_unconfirmed observation must have zero confirmations and no block height".into(),
                    ));
                }
            }
            "awaiting_confirmations" | "counted" => {
                if self.confirmations <= 0 || self.block_height.is_none() {
                    return Err(sqlx::Error::Protocol(
                        "confirmed observation must include confirmations and block height".into(),
                    ));
                }
            }
            "not_seen" => {}
            _ => {
                return Err(sqlx::Error::Protocol(format!(
                    "unknown observation state: {}",
                    self.last_seen_state
                )));
            }
        }
        Ok(())
    }
}

pub async fn upsert_invoice_payment_observation(
    pool: &PgPool,
    invoice_id: Uuid,
    observation: NewInvoicePaymentObservation<'_>,
) -> Result<u64, sqlx::Error> {
    observation.validate()?;
    sqlx::query(
        "INSERT INTO invoice_payment_observations \
            (invoice_id, rail, source, event_key, txid, vout, address, amount_sat, \
             confirmations, block_height, last_seen_state) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
         ON CONFLICT (event_key) DO UPDATE SET \
             amount_sat = EXCLUDED.amount_sat, \
             confirmations = EXCLUDED.confirmations, \
             block_height = EXCLUDED.block_height, \
             last_seen_state = EXCLUDED.last_seen_state, \
             last_seen_at = NOW() \
         WHERE invoice_payment_observations.invoice_id = EXCLUDED.invoice_id",
    )
    .bind(invoice_id)
    .bind(observation.rail)
    .bind(observation.source)
    .bind(observation.event_key)
    .bind(observation.txid)
    .bind(observation.vout)
    .bind(observation.address)
    .bind(observation.amount_sat)
    .bind(observation.confirmations)
    .bind(observation.block_height)
    .bind(observation.last_seen_state)
    .execute(pool)
    .await
    .map(|r| r.rows_affected())
}

pub async fn mark_missing_bitcoin_payment_observations_not_seen(
    pool: &PgPool,
    invoice_id: Uuid,
    seen_event_keys: &[String],
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        "UPDATE invoice_payment_observations \
         SET last_seen_state = 'not_seen', last_seen_at = NOW() \
         WHERE invoice_id = $1 \
           AND source = 'bitcoin_direct' \
           AND rail = 'bitcoin' \
           AND last_seen_state IN ('seen_unconfirmed', 'awaiting_confirmations') \
           AND NOT (event_key = ANY($2::TEXT[]))",
    )
    .bind(invoice_id)
    .bind(seen_event_keys)
    .execute(pool)
    .await
    .map(|r| r.rows_affected())
}

pub async fn list_invoice_payment_observations(
    pool: &PgPool,
    invoice_id: Uuid,
    limit: i64,
) -> Result<Vec<InvoicePaymentObservation>, sqlx::Error> {
    sqlx::query_as::<_, InvoicePaymentObservation>(
        "SELECT rail, source, event_key, txid, vout, address, amount_sat, \
                confirmations, block_height, last_seen_state, \
                EXTRACT(EPOCH FROM first_seen_at)::BIGINT AS first_seen_at_unix, \
                EXTRACT(EPOCH FROM last_seen_at)::BIGINT AS last_seen_at_unix \
         FROM invoice_payment_observations \
         WHERE invoice_id = $1 \
           AND source = 'bitcoin_direct' \
           AND rail = 'bitcoin' \
         ORDER BY last_seen_at DESC, first_seen_at DESC \
         LIMIT $2",
    )
    .bind(invoice_id)
    .bind(limit.clamp(0, 50))
    .fetch_all(pool)
    .await
}

impl InvoicePaymentEvidence<'_> {
    fn validate(&self) -> Result<(), sqlx::Error> {
        if self.amount_sat <= 0 {
            return Err(sqlx::Error::Protocol(
                "payment amount_sat must be > 0".into(),
            ));
        }
        if !matches!(self.rail, "bitcoin" | "liquid" | "lightning") {
            return Err(sqlx::Error::Protocol(format!(
                "unknown invoice payment rail: {}",
                self.rail
            )));
        }

        match self.source {
            "bitcoin_direct" if self.rail == "bitcoin" => {
                if self.txid.is_none()
                    || self.vout.is_none()
                    || self.vout.is_some_and(|v| v < 0)
                    || self.address.is_none()
                    || self.boltz_swap_id.is_some()
                {
                    return Err(sqlx::Error::Protocol(
                        "bitcoin_direct evidence requires txid, non-negative vout, address, and no boltz_swap_id".into(),
                    ));
                }
            }
            "liquid_direct" if self.rail == "liquid" => {
                if self.txid.is_none()
                    || self.vout.is_none()
                    || self.vout.is_some_and(|v| v < 0)
                    || self.address.is_none()
                    || self.boltz_swap_id.is_some()
                {
                    return Err(sqlx::Error::Protocol(
                        "liquid_direct evidence requires txid, non-negative vout, address, and no boltz_swap_id".into(),
                    ));
                }
            }
            "lightning_boltz_reverse" if self.rail == "lightning" => {
                if self.txid.is_none() || self.boltz_swap_id.is_none() || self.vout.is_some() {
                    return Err(sqlx::Error::Protocol(
                        "lightning_boltz_reverse evidence requires txid, boltz_swap_id, and no vout".into(),
                    ));
                }
            }
            "bitcoin_boltz_chain" if self.rail == "bitcoin" => {
                if self.txid.is_none() || self.boltz_swap_id.is_none() || self.vout.is_some() {
                    return Err(sqlx::Error::Protocol(
                        "bitcoin_boltz_chain evidence requires txid, boltz_swap_id, and no vout"
                            .into(),
                    ));
                }
            }
            _ => {
                return Err(sqlx::Error::Protocol(format!(
                    "invalid invoice payment source/rail pair: {}/{}",
                    self.source, self.rail
                )));
            }
        }
        Ok(())
    }
}

pub async fn record_invoice_payment(
    pool: &PgPool,
    id: Uuid,
    evidence: InvoicePaymentEvidence<'_>,
    tolerances: InvoiceAccountingTolerances,
) -> Result<u64, sqlx::Error> {
    evidence.validate()?;

    let mut tx = pool.begin().await?;
    let inv = sqlx::query_as::<_, Invoice>(&format!(
        "SELECT {INVOICE_COLUMNS} FROM invoices WHERE id = $1 FOR UPDATE"
    ))
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;

    if inv.status == "cancelled" {
        tx.commit().await?;
        return Ok(0);
    }

    let inserted: Option<(Uuid,)> = sqlx::query_as(
        "INSERT INTO invoice_payment_events \
            (invoice_id, rail, source, event_key, amount_sat, txid, vout, boltz_swap_id, address) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         ON CONFLICT (event_key) DO NOTHING \
         RETURNING id",
    )
    .bind(id)
    .bind(evidence.rail)
    .bind(evidence.source)
    .bind(evidence.event_key)
    .bind(evidence.amount_sat)
    .bind(evidence.txid)
    .bind(evidence.vout)
    .bind(evidence.boltz_swap_id)
    .bind(evidence.address)
    .fetch_optional(&mut *tx)
    .await?;

    if inserted.is_none() {
        tx.commit().await?;
        return Ok(0);
    }

    let (received_sat,): (i64,) = sqlx::query_as(
        "SELECT COALESCE(SUM(amount_sat), 0)::BIGINT \
         FROM invoice_payment_events WHERE invoice_id = $1",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;

    let rails: Vec<(String,)> = sqlx::query_as(
        "SELECT DISTINCT rail FROM invoice_payment_events WHERE invoice_id = $1 ORDER BY rail",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await?;
    let paid_via = if rails.len() == 1 {
        rails[0].0.as_str()
    } else {
        "mixed"
    };

    let tolerance_sat = payment_tolerance_sat_for_amount(inv.amount_sat, evidence.rail, tolerances);
    let remaining_sat = inv.amount_sat.saturating_sub(received_sat);
    let expired = inv.expires_at_unix <= chrono_like_unix_now();
    let new_status = if received_sat > inv.amount_sat {
        "overpaid"
    } else if remaining_sat <= tolerance_sat {
        "paid"
    } else if inv.status == "underpaid" {
        "underpaid"
    } else if expired {
        "underpaid"
    } else {
        "partially_paid"
    };
    let settlement_status = if matches!(new_status, "paid" | "overpaid") {
        "settled"
    } else {
        "none"
    };

    sqlx::query(
        "UPDATE invoices SET \
            status = $2, \
            paid_via = $3, \
            paid_amount_sat = $4, \
            settlement_status = $5, \
            paid_at = CASE WHEN $2 IN ('paid', 'overpaid') THEN COALESCE(paid_at, NOW()) ELSE paid_at END \
         WHERE id = $1",
    )
    .bind(id)
    .bind(new_status)
    .bind(paid_via)
    .bind(received_sat)
    .bind(settlement_status)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(1)
}

pub async fn invoice_payment_event_exists(
    pool: &PgPool,
    invoice_id: Uuid,
    event_key: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS( \
            SELECT 1 FROM invoice_payment_events \
            WHERE invoice_id = $1 AND event_key = $2 \
        )",
    )
    .bind(invoice_id)
    .bind(event_key)
    .fetch_one(pool)
    .await
}

fn chrono_like_unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Flip an invoice to `in_progress` on the FIRST mempool sighting of a
/// payment tx (BTC watcher, or the LN claimer's `transaction.mempool`
/// hook used by webhook and reconciler paths). Idempotent under the
/// `WHERE status = 'unpaid'`
/// guard: a second sighting tick is a no-op (returns 0). Crucially, a
/// later `record_invoice_payment` call can still advance an
/// `in_progress` row to paid/under/over.
///
/// Returns rows_affected: 1 = flip happened; 0 = no-op (already
/// in_progress, paid, expired, cancelled, or row absent).
pub async fn mark_invoice_in_progress(pool: &PgPool, id: Uuid) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE invoices SET status = 'in_progress', settlement_status = 'pending' \
         WHERE id = $1 AND status = 'unpaid'",
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

pub async fn mark_invoice_settlement_status(
    pool: &PgPool,
    id: Option<Uuid>,
    settlement_status: &str,
) -> Result<u64, sqlx::Error> {
    let Some(id) = id else {
        return Ok(0);
    };
    if !matches!(
        settlement_status,
        "none" | "pending" | "settled" | "claim_stuck" | "refunded" | "failed"
    ) {
        return Err(sqlx::Error::Protocol(format!(
            "unknown invoice settlement_status: {settlement_status}"
        )));
    }
    sqlx::query(
        "UPDATE invoices SET settlement_status = $2 \
         WHERE id = $1 AND status NOT IN ('paid', 'underpaid', 'overpaid', 'expired', 'cancelled')",
    )
    .bind(id)
    .bind(settlement_status)
    .execute(pool)
    .await
    .map(|r| r.rows_affected())
}

pub async fn mark_invoice_settlement_status_for_swap(
    pool: &PgPool,
    swap_id: Uuid,
    settlement_status: &str,
) -> Result<u64, sqlx::Error> {
    if !matches!(
        settlement_status,
        "none" | "pending" | "settled" | "claim_stuck" | "refunded" | "failed"
    ) {
        return Err(sqlx::Error::Protocol(format!(
            "unknown invoice settlement_status: {settlement_status}"
        )));
    }
    sqlx::query(
        "UPDATE invoices i SET settlement_status = $2 \
         FROM swap_records s \
         WHERE s.id = $1 \
           AND s.invoice_id = i.id \
           AND i.status NOT IN ('paid', 'underpaid', 'overpaid', 'expired', 'cancelled')",
    )
    .bind(swap_id)
    .bind(settlement_status)
    .execute(pool)
    .await
    .map(|r| r.rows_affected())
}

/// Cancel an unpaid invoice (recipient-initiated via signed
/// `invoice-cancel`). Idempotent: re-call on a row that's already
/// non-unpaid returns 0 rows affected. Caller verifies the Schnorr
/// signature AND that the invoice's nym maps to the verifying npub
/// upstream — this fn does not re-check ownership.
pub async fn cancel_invoice(pool: &PgPool, id: Uuid) -> Result<(u64, String), sqlx::Error> {
    let result = sqlx::query(
        "UPDATE invoices SET status = 'cancelled', cancelled_at = NOW() \
         WHERE id = $1 AND status = 'unpaid'",
    )
    .bind(id)
    .execute(pool)
    .await?;
    let rows = result.rows_affected();
    if rows == 1 {
        return Ok((rows, "cancelled".to_string()));
    }
    let status = sqlx::query_scalar::<_, String>("SELECT status FROM invoices WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await?;
    Ok((rows, status))
}

/// Background sweep: flip every unpaid OR in_progress invoice past its
/// outer deadline to 'expired'. Idempotent (set-based UPDATE; predicate
/// excludes already-terminal rows). Run from `gc.rs` on the periodic GC
/// cycle.
///
/// `in_progress` is included because a payer may broadcast a tx that
/// makes it to mempool (flipping the row to in_progress) but never
/// confirms (RBF replaced, mempool eviction, low-fee drop). After the
/// outer expiry we want the row out of the active corpus regardless of
/// its mempool stage. Backed by the partial index
/// `invoices_unpaid_or_inprog_expiry_idx` (migration 021).
pub async fn expire_invoices_past_deadline(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE invoices SET status = CASE \
            WHEN status = 'partially_paid' THEN 'underpaid' \
            ELSE 'expired' \
         END \
         WHERE status IN ('unpaid', 'in_progress', 'partially_paid') AND expires_at < NOW()",
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

pub async fn terminalize_stale_checkout_partial_invoice(
    pool: &PgPool,
    id: Uuid,
    grace_secs: u64,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE invoices i \
         SET status = 'underpaid' \
         WHERE i.id = $1 \
           AND i.origin = 'checkout' \
           AND i.status = 'partially_paid' \
           AND i.settlement_status NOT IN ('pending', 'claim_stuck', 'refunded') \
           AND ( \
             SELECT MAX(e.created_at) \
             FROM invoice_payment_events e \
             WHERE e.invoice_id = i.id \
           ) < NOW() - ($2 || ' seconds')::interval",
    )
    .bind(id)
    .bind(grace_secs as i64)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

pub async fn terminalize_stale_checkout_partial_invoices(
    pool: &PgPool,
    grace_secs: u64,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "WITH stale AS ( \
             SELECT i.id \
             FROM invoices i \
             JOIN LATERAL ( \
               SELECT MAX(e.created_at) AS latest_payment_at \
               FROM invoice_payment_events e \
               WHERE e.invoice_id = i.id \
             ) ev ON TRUE \
             WHERE i.origin = 'checkout' \
               AND i.status = 'partially_paid' \
               AND i.settlement_status NOT IN ('pending', 'claim_stuck', 'refunded') \
               AND ev.latest_payment_at < NOW() - ($1 || ' seconds')::interval \
             ORDER BY ev.latest_payment_at ASC \
             LIMIT 1000 \
         ) \
         UPDATE invoices i \
         SET status = 'underpaid' \
         FROM stale \
         WHERE i.id = stale.id",
    )
    .bind(grace_secs as i64)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Bump `users.next_addr_idx` for an active nym and derive the next Liquid
/// address without touching any invoice row. Returns `(address, index)` so
/// the caller can pass `address` into `NewInvoice.liquid_address` at insert
/// time.
///
/// Use this when creating an invoice with `accept_ln = TRUE` or
/// `accept_liquid = TRUE` and no wallet-supplied address — the
/// `invoices_ln_or_liquid_addr_chk` constraint requires
/// `liquid_address` to be set at INSERT time, so the allocator must
/// run before insert. The donation-page checkout flow is the primary
/// caller.
///
/// Uses the `donation:{nym}` advisory lock so concurrent allocator calls for
/// the same nym serialize on the `next_addr_idx` bump.
///
/// Returns `Ok(None)` when the nym is unknown or `is_active = FALSE`.
pub async fn allocate_next_liquid_for_active_nym<F>(
    pool: &PgPool,
    nym: &str,
    derive_address: F,
) -> Result<Option<(String, i32)>, sqlx::Error>
where
    F: Fn(&str, u32) -> Result<String, sqlx::Error>,
{
    let mut tx = pool.begin().await?;

    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1)::bigint)")
        .bind(format!("donation:{nym}"))
        .execute(&mut *tx)
        .await?;

    let row: Option<(String, i32)> = sqlx::query_as(
        "SELECT ct_descriptor, next_addr_idx FROM users WHERE nym = $1 AND is_active = TRUE",
    )
    .bind(nym)
    .fetch_optional(&mut *tx)
    .await?;

    let Some((ct_descriptor, mut address_index)) = row else {
        return Ok(None);
    };

    for _ in 0..100 {
        let idx_u32 = u32::try_from(address_index).map_err(|_| {
            sqlx::Error::Protocol(format!("address index overflow: {address_index}"))
        })?;
        let address = derive_address(&ct_descriptor, idx_u32)?;
        let in_use: bool = sqlx::query_scalar(
            "SELECT EXISTS( \
                SELECT 1 FROM invoice_payment_addresses \
                WHERE rail = 'liquid' AND address = $1 \
            )",
        )
        .bind(&address)
        .fetch_one(&mut *tx)
        .await?;

        if !in_use {
            sqlx::query("UPDATE users SET next_addr_idx = $2 WHERE nym = $1")
                .bind(nym)
                .bind(address_index + 1)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            return Ok(Some((address, address_index)));
        }

        address_index += 1;
    }

    sqlx::query("UPDATE users SET next_addr_idx = $2 WHERE nym = $1")
        .bind(nym)
        .bind(address_index)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    Err(sqlx::Error::Protocol(format!(
        "could not allocate unused Liquid address for {nym} after 100 attempts"
    )))
}

/// Read the most recent BOLT11 for an invoice (latest swap_records row
/// whose `invoice_id = $1`). Returns the invoice/BOLT11 string, or None
/// if no Lightning offer has been created yet for this invoice.
///
/// Service path: the status endpoint surfaces this so the page can render
/// a fresh QR after a rate refresh creates a new swap.
pub async fn latest_lightning_pr_for_invoice(
    pool: &PgPool,
    invoice_id: Uuid,
) -> Result<Option<(String, i64)>, sqlx::Error> {
    let row: Option<(String, i64)> = sqlx::query_as(
        "SELECT invoice, amount_sat FROM swap_records \
         WHERE invoice_id = $1 \
         ORDER BY created_at DESC \
         LIMIT 1",
    )
    .bind(invoice_id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}
