use std::collections::HashMap;

use sqlx::{PgPool, Postgres, Transaction};
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
    /// Alias slug the invoice was created under (via `/a/<slug>/invoice`), if
    /// any. When set, the invoice's public-facing URL (bolt11 description,
    /// BIP21 message) is `/a/<slug>/i/<id>` instead of the nym path, so the
    /// nym never appears in the payment payload the payer sees.
    pub public_slug: Option<String>,
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
    pub presentation_status: Option<String>,
    pub direct_settlement_status: String,
    pub swap_settlement_status: String,
    pub direct_payment_projection_version: i64,
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
    "id, nym_owner, public_slug, npub_owner, origin, fiat_amount_minor, fiat_currency, amount_sat, \
     rate_minor_per_btc, memo, recipient_label, \
     bitcoin_address, accept_btc, accept_ln, accept_liquid, \
     public_description, invoice_number, \
     liquid_address, liquid_address_index, status, paid_via, paid_amount_sat, \
     pricing_mode, settlement_status, presentation_status, \
     direct_settlement_status, swap_settlement_status, \
     direct_payment_projection_version, liquid_blinding_key_hex, \
     EXTRACT(EPOCH FROM created_at)::BIGINT       AS created_at_unix, \
     EXTRACT(EPOCH FROM expires_at)::BIGINT       AS expires_at_unix, \
     EXTRACT(EPOCH FROM rate_locked_at)::BIGINT   AS rate_locked_at_unix, \
     EXTRACT(EPOCH FROM rate_locks_until)::BIGINT AS rate_locks_until_unix, \
     EXTRACT(EPOCH FROM paid_at)::BIGINT          AS paid_at_unix, \
     EXTRACT(EPOCH FROM cancelled_at)::BIGINT     AS cancelled_at_unix";

pub struct NewInvoice<'a> {
    /// Merchant payment-page nym, or `None` for unlinked (wallet-only) invoices.
    pub nym_owner: Option<&'a str>,
    /// Alias slug the invoice is created under (`/a/<slug>/invoice`), or `None`
    /// for nym-path and wallet-origin invoices. Drives the nym-free public URL
    /// embedded in payment payloads.
    pub public_slug: Option<&'a str>,
    /// Canonical recipient identity (hex x-only Schnorr pubkey). Required.
    pub npub_owner: &'a str,
    /// 'checkout' or 'wallet'. Caller validates against the enum upstream.
    pub origin: &'a str,
    /// Exact checkout descriptor/cursor namespace. Required only for checkout
    /// invoices so each fiat direct quote can allocate a unique destination.
    pub checkout_surface_kind: Option<&'a str>,
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
    ///   - Checkout-origin: server eagerly allocates from the surface
    ///     descriptor, or from the permanent-nym compatibility allocator,
    ///     BEFORE this insert.
    ///
    /// In both cases `liquid_address_index` on the invoice row stays
    /// NULL; the address is the chain watcher's lookup key, not the
    /// descriptor index.
    pub liquid_address: Option<&'a str>,
    pub liquid_blinding_key_hex: Option<&'a str>,
    /// Wall-clock seconds the invoice stays valid from `now()`.
    pub expires_in_secs: i64,
}

/// Immutable five-minute fiat conversion snapshot.  Provider instructions are
/// separate [`InvoiceQuoteOffer`] rows so creating/reusing this version never
/// performs a network mutation.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct InvoiceQuoteVersion {
    pub id: Uuid,
    pub invoice_id: Uuid,
    pub version_number: i32,
    pub fiat_face_amount_minor: i32,
    pub fiat_target_amount_minor: i32,
    pub fiat_currency: String,
    pub rate_minor_per_btc: i64,
    pub rate_source: String,
    pub rate_observed_at_unix: i64,
    pub rate_fetched_at_unix: i64,
    pub rate_fresh_until_unix: i64,
    pub merchant_amount_sat: i64,
    pub created_at_unix: i64,
    pub expires_at_unix: i64,
}

const INVOICE_QUOTE_VERSION_COLUMNS: &str =
    "id, invoice_id, version_number, fiat_face_amount_minor, fiat_target_amount_minor, fiat_currency, \
     rate_minor_per_btc, rate_source, \
     FLOOR(EXTRACT(EPOCH FROM rate_observed_at))::BIGINT AS rate_observed_at_unix, \
     FLOOR(EXTRACT(EPOCH FROM rate_fetched_at))::BIGINT AS rate_fetched_at_unix, \
     FLOOR(EXTRACT(EPOCH FROM rate_fresh_until))::BIGINT AS rate_fresh_until_unix, \
     merchant_amount_sat, \
     FLOOR(EXTRACT(EPOCH FROM created_at))::BIGINT AS created_at_unix, \
     FLOOR(EXTRACT(EPOCH FROM expires_at))::BIGINT AS expires_at_unix";

#[derive(Debug, Clone)]
pub struct NewInvoiceQuoteVersion<'a> {
    pub rate_minor_per_btc: i64,
    pub rate_source: &'a str,
    pub rate_observed_at_unix: i64,
    pub rate_fetched_at_unix: i64,
    pub rate_fresh_until_unix: i64,
    /// Runtime policy bounds applied after the locked remaining-fiat target is
    /// converted at this candidate rate. They are not persisted evidence.
    pub minimum_merchant_amount_sat: i64,
    pub maximum_merchant_amount_sat: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvoiceQuoteResolution {
    pub quote: InvoiceQuoteVersion,
    pub created: bool,
}

#[derive(sqlx::FromRow)]
struct InvoiceQuoteEligibilityRow {
    pricing_mode: String,
    fiat_amount_minor: Option<i32>,
    fiat_currency: Option<String>,
    status: String,
    presentation_status: Option<String>,
    before_invoice_expiry: bool,
}

/// One immutable payer instruction identity within a quote version.  Direct
/// instructions and provider-backed instructions use the same attribution
/// shape; this function only persists already-known evidence and never calls a
/// provider.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct InvoiceQuoteOffer {
    pub id: Uuid,
    pub invoice_id: Uuid,
    pub quote_version_id: Uuid,
    pub rail: String,
    pub offer_kind: String,
    pub request_key: String,
    pub provider: Option<String>,
    pub provider_offer_id: Option<String>,
    pub provider_attempt_id: Option<Uuid>,
    pub direct_address: Option<String>,
    pub direct_liquid_blinding_key_hex: Option<String>,
    pub direct_address_index: Option<i32>,
    pub payer_amount_sat: i64,
    pub created_at_unix: i64,
    pub expires_at_unix: i64,
}

const INVOICE_QUOTE_OFFER_COLUMNS: &str =
    "id, invoice_id, quote_version_id, rail, offer_kind, request_key, \
     provider, provider_offer_id, provider_attempt_id, direct_address, \
     direct_liquid_blinding_key_hex, direct_address_index, payer_amount_sat, \
     FLOOR(EXTRACT(EPOCH FROM created_at))::BIGINT AS created_at_unix, \
     FLOOR(EXTRACT(EPOCH FROM expires_at))::BIGINT AS expires_at_unix";

#[derive(Debug, Clone)]
pub struct NewInvoiceQuoteOffer<'a> {
    pub invoice_id: Uuid,
    pub quote_version_id: Uuid,
    pub rail: &'a str,
    pub offer_kind: &'a str,
    pub request_key: &'a str,
    pub provider: Option<&'a str>,
    pub provider_offer_id: Option<&'a str>,
    pub provider_attempt_id: Option<Uuid>,
    pub direct_address: Option<&'a str>,
    pub direct_liquid_blinding_key_hex: Option<&'a str>,
    pub direct_address_index: Option<i32>,
    pub payer_amount_sat: i64,
    pub expires_at_unix: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvoiceQuoteOfferResolution {
    pub offer: InvoiceQuoteOffer,
    pub created: bool,
}

fn invoice_quote_offer_matches_candidate(
    offer: &InvoiceQuoteOffer,
    candidate: &NewInvoiceQuoteOffer<'_>,
) -> bool {
    offer.invoice_id == candidate.invoice_id
        && offer.quote_version_id == candidate.quote_version_id
        && offer.rail == candidate.rail
        && offer.offer_kind == candidate.offer_kind
        && offer.request_key == candidate.request_key
        && offer.provider.as_deref() == candidate.provider
        && offer.provider_offer_id.as_deref() == candidate.provider_offer_id
        && offer.provider_attempt_id == candidate.provider_attempt_id
        && offer.direct_address.as_deref() == candidate.direct_address
        && offer.direct_liquid_blinding_key_hex.as_deref()
            == candidate.direct_liquid_blinding_key_hex
        && offer.direct_address_index == candidate.direct_address_index
        && offer.payer_amount_sat == candidate.payer_amount_sat
        && offer.expires_at_unix == candidate.expires_at_unix
}

/// Immutable identity of the exact quote and payer instruction that produced
/// a swap or payment event. The pair is optional at persistence boundaries so
/// rows created before migration 061 remain valid, but new quote-aware callers
/// must always supply both IDs together through this value object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvoiceQuoteAttribution {
    pub quote_version_id: Uuid,
    pub quote_offer_id: Uuid,
}

/// Validate quote attribution against the complete immutable payer-offer
/// identity. There is deliberately no expiry predicate: a copied instruction
/// remains an observable obligation after its five-minute quote window closes.
///
/// Keeping this check on the same transaction as the owning insert prevents a
/// wrong-invoice, wrong-rail, or crossed provider identity from relying only
/// on the coarser composite foreign key in migration 061.
pub(crate) async fn validate_invoice_quote_attribution<'e, E>(
    executor: E,
    invoice_id: Uuid,
    attribution: InvoiceQuoteAttribution,
    expected_rail: &str,
    expected_offer_kind: &str,
    expected_provider: Option<&str>,
    expected_provider_offer_id: Option<&str>,
    expected_direct_address: Option<&str>,
) -> Result<(), sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let valid: bool = sqlx::query_scalar(
        "SELECT EXISTS ( \
             SELECT 1 FROM invoice_quote_offers \
              WHERE id = $1 \
                AND quote_version_id = $2 \
                AND invoice_id = $3 \
                AND rail = $4 \
                AND offer_kind = $5 \
                AND provider IS NOT DISTINCT FROM $6::TEXT \
                AND provider_offer_id IS NOT DISTINCT FROM $7::TEXT \
                AND direct_address IS NOT DISTINCT FROM $8::TEXT \
         )",
    )
    .bind(attribution.quote_offer_id)
    .bind(attribution.quote_version_id)
    .bind(invoice_id)
    .bind(expected_rail)
    .bind(expected_offer_kind)
    .bind(expected_provider)
    .bind(expected_provider_offer_id)
    .bind(expected_direct_address)
    .fetch_one(executor)
    .await?;
    if !valid {
        return Err(sqlx::Error::Protocol(format!(
            "invoice quote attribution does not match invoice/rail/offer identity: invoice={invoice_id}, rail={expected_rail}, offer_kind={expected_offer_kind}"
        )));
    }
    Ok(())
}

/// Exact server-owned value used by `presentation_status` and payable top-up
/// instructions. Active/legacy accounting events contribute, as do verified
/// provisional direct observations. Superseded or unverified evidence never
/// contributes. A missing map entry means the invoice has no event rows; the
/// caller may fall back to its accounting cache for legacy compatibility.
pub async fn invoice_presentation_received_sats<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    invoice_ids: &[Uuid],
) -> Result<HashMap<Uuid, i64>, sqlx::Error> {
    if invoice_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows = sqlx::query_as::<_, (Uuid, i64)>(
        "SELECT e.invoice_id, COALESCE(SUM(e.amount_sat), 0)::BIGINT \
         FROM invoice_payment_events e \
         LEFT JOIN invoice_payment_observations o ON o.id = e.observation_id \
         WHERE e.invoice_id = ANY($1::UUID[]) \
           AND e.accounting_state <> 'superseded' \
           AND ( \
             e.accounting_state IN ('active', 'legacy_unverified') \
             OR ( \
               e.source IN ('bitcoin_direct', 'liquid_direct') \
               AND e.verification_state = 'verified' \
               AND o.last_seen_state = 'seen_unconfirmed' \
             ) \
           ) \
         GROUP BY e.invoice_id",
    )
    .bind(invoice_ids)
    .fetch_all(executor)
    .await?;
    Ok(rows.into_iter().collect())
}

/// Single-invoice transaction-aware counterpart used while an offer creator
/// owns the invoice projection advisory boundary. `None` means no contributing
/// event row exists, preserving the legacy cached-value fallback at callers.
pub async fn invoice_presentation_received_sat<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    invoice_id: Uuid,
) -> Result<Option<i64>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT COALESCE(SUM(e.amount_sat), 0)::BIGINT \
         FROM invoice_payment_events e \
         LEFT JOIN invoice_payment_observations o ON o.id = e.observation_id \
         WHERE e.invoice_id = $1 \
           AND e.accounting_state <> 'superseded' \
           AND ( \
             e.accounting_state IN ('active', 'legacy_unverified') \
             OR ( \
               e.source IN ('bitcoin_direct', 'liquid_direct') \
               AND e.verification_state = 'verified' \
               AND o.last_seen_state = 'seen_unconfirmed' \
             ) \
           ) \
         GROUP BY e.invoice_id",
    )
    .bind(invoice_id)
    .fetch_optional(executor)
    .await
}

/// Insert a new invoice row. The caller is responsible for populating
/// `liquid_address` when `accept_ln` or `accept_liquid` is TRUE — the
/// `invoices_ln_or_liquid_addr_chk` constraint requires it at INSERT
/// time. Two supply paths:
///   - Wallet-origin (Get-paid): the wallet supplies the address.
///   - Checkout-origin: the caller invokes a Page/POS descriptor allocator or
///     `allocate_next_liquid_for_permanent_nym`, then passes the result through
///     `NewInvoice.liquid_address`.
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
             public_slug, expires_at, presentation_status, checkout_surface_kind) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, \
                 NOW() + ($8 || ' seconds')::interval, $9, $10, \
                 $11, $12, $13, $14, $15, $16, $17, \
                 CASE WHEN $4::INTEGER IS NULL THEN 'sat_fixed' ELSE 'fiat_fixed' END, $18, \
                 $20, NOW() + ($19 || ' seconds')::interval, 'unpaid', $21) \
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
    .bind(invoice.public_slug)
    .bind(invoice.checkout_surface_kind)
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

/// Return the invoice's current quote or create exactly one new five-minute
/// version. The invoice projection advisory lock and row lock serialize every
/// caller, including payment reducers and payer-offer creation. A retry after
/// response loss therefore returns the committed version rather than adding a
/// second one.
///
/// Fully valued active partial evidence is subtracted under the same lock, so
/// the next version prices only the remaining fiat. Any unvalued event keeps
/// the separate late-observation policy fail-closed.
pub async fn create_or_reuse_current_invoice_quote(
    pool: &PgPool,
    invoice_id: Uuid,
    candidate: &NewInvoiceQuoteVersion<'_>,
) -> Result<InvoiceQuoteResolution, sqlx::Error> {
    let mut tx = pool.begin().await?;
    lock_invoice_lightning_projection(&mut tx, invoice_id).await?;

    let invoice_state = sqlx::query_as::<_, InvoiceQuoteEligibilityRow>(
        "SELECT pricing_mode, fiat_amount_minor, fiat_currency, status, \
                    presentation_status, \
                    expires_at > clock_timestamp() AS before_invoice_expiry \
               FROM invoices WHERE id = $1 FOR UPDATE",
    )
    .bind(invoice_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(invoice_state) = invoice_state else {
        return Err(sqlx::Error::RowNotFound);
    };
    if invoice_state.pricing_mode != "fiat_fixed"
        || invoice_state.fiat_amount_minor.is_none()
        || invoice_state.fiat_currency.is_none()
        || !matches!(
            invoice_state.status.as_str(),
            "unpaid" | "partially_paid" | "in_progress"
        )
        || !matches!(
            invoice_state.presentation_status.as_deref(),
            Some("unpaid" | "partial")
        )
        || !invoice_state.before_invoice_expiry
    {
        return Err(sqlx::Error::Protocol(
            "invoice is not eligible for a current fiat quote".to_string(),
        ));
    }

    if let Some(quote) = sqlx::query_as::<_, InvoiceQuoteVersion>(&format!(
        "SELECT {INVOICE_QUOTE_VERSION_COLUMNS} \
           FROM invoice_quote_versions \
          WHERE invoice_id = $1 AND expires_at > clock_timestamp() \
          ORDER BY version_number DESC LIMIT 1"
    ))
    .bind(invoice_id)
    .fetch_optional(&mut *tx)
    .await?
    {
        tx.commit().await?;
        return Ok(InvoiceQuoteResolution {
            quote,
            created: false,
        });
    }

    let unresolved_event_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS ( \
             SELECT 1 FROM invoice_payment_events \
              WHERE invoice_id = $1 \
                AND (invoice_quote_version_id IS NULL \
                     OR invoice_quote_offer_id IS NULL \
                     OR quote_first_observed_at IS NULL \
                     OR fiat_credited_minor IS NULL \
                     OR fiat_credit_policy IS NULL \
                     OR fiat_valued_at IS NULL) \
         )",
    )
    .bind(invoice_id)
    .fetch_one(&mut *tx)
    .await?;
    if unresolved_event_exists {
        return Err(sqlx::Error::Protocol(
            "invoice has payment evidence awaiting fiat valuation policy".into(),
        ));
    }

    let active_fiat_credit: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(active_fiat_credited_minor), 0)::BIGINT \
           FROM invoice_quote_active_fiat_projection WHERE invoice_id = $1",
    )
    .bind(invoice_id)
    .fetch_one(&mut *tx)
    .await?;
    let face_minor = i64::from(invoice_state.fiat_amount_minor.expect("validated above"));
    let fiat_target_amount_minor = face_minor
        .checked_sub(active_fiat_credit)
        .ok_or_else(|| sqlx::Error::Protocol("active fiat credit exceeds invoice face".into()))?;
    if fiat_target_amount_minor <= 0 || fiat_target_amount_minor > face_minor {
        return Err(sqlx::Error::Protocol(
            "invoice has no valid remaining fiat target".into(),
        ));
    }
    let merchant_amount_sat = i64::try_from(
        i128::from(fiat_target_amount_minor)
            .checked_mul(100_000_000_i128)
            .and_then(|value| value.checked_div(i128::from(candidate.rate_minor_per_btc)))
            .ok_or_else(|| sqlx::Error::Protocol("fiat quote conversion overflow".into()))?,
    )
    .map_err(|_| sqlx::Error::Protocol("fiat quote amount exceeds storage range".into()))?;
    if merchant_amount_sat < candidate.minimum_merchant_amount_sat
        || merchant_amount_sat > candidate.maximum_merchant_amount_sat
    {
        return Err(sqlx::Error::Protocol(format!(
            "quoted amount {merchant_amount_sat} sat is outside {}..={}",
            candidate.minimum_merchant_amount_sat, candidate.maximum_merchant_amount_sat
        )));
    }

    let quote = sqlx::query_as::<_, InvoiceQuoteVersion>(&format!(
        "INSERT INTO invoice_quote_versions ( \
             invoice_id, fiat_target_amount_minor, rate_minor_per_btc, rate_source, rate_observed_at, \
             rate_fetched_at, rate_fresh_until, merchant_amount_sat \
         ) VALUES ( \
             $1, $2, $3, $4, to_timestamp($5), to_timestamp($6), \
             to_timestamp($7), $8 \
         ) RETURNING {INVOICE_QUOTE_VERSION_COLUMNS}"
    ))
    .bind(invoice_id)
    .bind(i32::try_from(fiat_target_amount_minor).map_err(|_| {
        sqlx::Error::Protocol("remaining fiat target exceeds storage range".into())
    })?)
    .bind(candidate.rate_minor_per_btc)
    .bind(candidate.rate_source)
    .bind(candidate.rate_observed_at_unix)
    .bind(candidate.rate_fetched_at_unix)
    .bind(candidate.rate_fresh_until_unix)
    .bind(merchant_amount_sat)
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(InvoiceQuoteResolution {
        quote,
        created: true,
    })
}

/// Read-only current-quote lookup. It never fetches a rate or creates a
/// provider offer, making it safe for status polls and crawlers.
pub async fn current_invoice_quote<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    invoice_id: Uuid,
) -> Result<Option<InvoiceQuoteVersion>, sqlx::Error> {
    sqlx::query_as::<_, InvoiceQuoteVersion>(&format!(
        "SELECT {INVOICE_QUOTE_VERSION_COLUMNS} \
           FROM invoice_quote_versions \
          WHERE invoice_id = $1 AND expires_at > clock_timestamp() \
          ORDER BY version_number DESC LIMIT 1"
    ))
    .bind(invoice_id)
    .fetch_optional(executor)
    .await
}

/// Recomputed fiat projection used by every payment reducer. Immutable event
/// deltas remain audit evidence; current accounting and presentation are
/// derived cumulatively per quote so split payments and reorgs are order-safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::FromRow)]
pub(crate) struct FiatInvoiceCreditProjection {
    pub face_minor: i64,
    pub active_credit_minor: i64,
    pub presentation_credit_minor: i64,
    pub active_overpaid: bool,
    pub presentation_overpaid: bool,
    pub unresolved_evidence: bool,
}

pub(crate) async fn invoice_fiat_credit_projection<'e, E>(
    executor: E,
    invoice_id: Uuid,
) -> Result<FiatInvoiceCreditProjection, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as(
        "WITH per_quote AS ( \
             SELECT q.id, p.active_fiat_credited_minor, \
                    p.active_eligible_sat > q.merchant_amount_sat AS active_overpaid, \
                    COALESCE(SUM(e.amount_sat) FILTER (WHERE \
                        e.fiat_credited_minor IS NOT NULL \
                        AND e.quote_first_observed_at < q.expires_at \
                        AND e.accounting_state <> 'superseded' \
                        AND ( \
                          e.accounting_state IN ('active', 'legacy_unverified') \
                          OR (e.source IN ('bitcoin_direct', 'liquid_direct') \
                              AND e.verification_state = 'verified' \
                              AND o.last_seen_state = 'seen_unconfirmed') \
                        ) \
                    ), 0)::BIGINT AS presentation_eligible_sat, \
                    q.fiat_target_amount_minor, q.merchant_amount_sat, \
                    q.rate_minor_per_btc \
               FROM invoice_quote_versions q \
               JOIN invoice_quote_active_fiat_projection p \
                 ON p.quote_version_id = q.id \
          LEFT JOIN invoice_payment_events e \
                 ON e.invoice_id = q.invoice_id \
                AND e.invoice_quote_version_id = q.id \
          LEFT JOIN invoice_payment_observations o ON o.id = e.observation_id \
              WHERE q.invoice_id = $1 \
           GROUP BY q.id, p.active_fiat_credited_minor, p.active_eligible_sat \
         ), projected AS ( \
             SELECT COALESCE(SUM(active_fiat_credited_minor), 0)::BIGINT \
                        AS active_credit_minor, \
                    COALESCE(SUM(invoice_quote_credit_for_sats( \
                        fiat_target_amount_minor, merchant_amount_sat, \
                        rate_minor_per_btc, presentation_eligible_sat \
                    )), 0)::BIGINT AS presentation_credit_minor, \
                    COALESCE(BOOL_OR(active_overpaid), FALSE) AS active_overpaid, \
                    COALESCE(BOOL_OR( \
                        presentation_eligible_sat > merchant_amount_sat \
                    ), FALSE) AS presentation_overpaid \
               FROM per_quote \
         ) \
         SELECT i.fiat_amount_minor::BIGINT AS face_minor, \
                projected.active_credit_minor, projected.presentation_credit_minor, \
                (projected.active_overpaid \
                 OR projected.active_credit_minor > i.fiat_amount_minor) AS active_overpaid, \
                (projected.presentation_overpaid \
                 OR projected.presentation_credit_minor > i.fiat_amount_minor) \
                    AS presentation_overpaid, \
                EXISTS ( \
                    SELECT 1 FROM invoice_payment_events e \
                     WHERE e.invoice_id = i.id \
                       AND (e.invoice_quote_version_id IS NULL \
                            OR e.invoice_quote_offer_id IS NULL \
                            OR e.quote_first_observed_at IS NULL \
                            OR e.fiat_credited_minor IS NULL \
                            OR e.fiat_credit_policy IS NULL \
                            OR e.fiat_valued_at IS NULL) \
                ) AS unresolved_evidence \
           FROM invoices i CROSS JOIN projected \
          WHERE i.id = $1 AND i.pricing_mode = 'fiat_fixed' \
            AND i.fiat_amount_minor IS NOT NULL",
    )
    .bind(invoice_id)
    .fetch_one(executor)
    .await
}

pub(crate) fn fiat_invoice_status(
    prior_status: &str,
    projection: FiatInvoiceCreditProjection,
    expired: bool,
) -> &'static str {
    if prior_status == "cancelled" {
        return "cancelled";
    }
    if prior_status == "expired" {
        return "expired";
    }
    if projection.unresolved_evidence && projection.active_credit_minor < projection.face_minor {
        return "in_progress";
    }
    if projection.active_credit_minor >= projection.face_minor {
        if projection.active_overpaid {
            "overpaid"
        } else {
            "paid"
        }
    } else if projection.active_credit_minor > 0 {
        if expired {
            "underpaid"
        } else {
            "partially_paid"
        }
    } else if projection.presentation_credit_minor > 0 {
        "in_progress"
    } else if expired {
        "underpaid"
    } else {
        "unpaid"
    }
}

pub(crate) fn fiat_invoice_presentation_status(
    projection: FiatInvoiceCreditProjection,
) -> &'static str {
    if projection.presentation_credit_minor >= projection.face_minor {
        if projection.presentation_overpaid {
            "overpaid"
        } else {
            "payment_received"
        }
    } else if projection.presentation_credit_minor > 0 {
        "partial"
    } else {
        "unpaid"
    }
}

/// Persist or replay one already-created direct/provider offer identity. The
/// caller-supplied request key is scoped to `(quote, rail)`; an exact retry
/// returns the original row and a conflicting retry fails closed.
pub async fn record_or_reuse_invoice_quote_offer(
    pool: &PgPool,
    candidate: &NewInvoiceQuoteOffer<'_>,
) -> Result<InvoiceQuoteOfferResolution, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let resolution = record_or_reuse_invoice_quote_offer_in_tx(&mut tx, candidate).await?;
    tx.commit().await?;
    Ok(resolution)
}

/// Exact immutable offer for one invoice/quote/rail. More than one row is a
/// protocol violation rather than an arbitrary latest-wins choice.
pub async fn invoice_quote_offer_for_rail<'e, E>(
    executor: E,
    invoice_id: Uuid,
    quote_version_id: Uuid,
    rail: &str,
) -> Result<Option<InvoiceQuoteOffer>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let rows = sqlx::query_as::<_, InvoiceQuoteOffer>(&format!(
        "SELECT {INVOICE_QUOTE_OFFER_COLUMNS} FROM invoice_quote_offers \
          WHERE invoice_id = $1 AND quote_version_id = $2 AND rail = $3 \
          ORDER BY created_at, id LIMIT 2"
    ))
    .bind(invoice_id)
    .bind(quote_version_id)
    .bind(rail)
    .fetch_all(executor)
    .await?;
    match rows.len() {
        0 => Ok(None),
        1 => Ok(rows.into_iter().next()),
        _ => Err(sqlx::Error::Protocol(format!(
            "invoice quote has multiple {rail} payer offers"
        ))),
    }
}

/// Return the persisted BOLT11 only when the exact quote offer and canonical
/// reverse-swap row still agree and remain unfunded/payable.
pub async fn lightning_pr_for_invoice_quote_offer<'e, E>(
    executor: E,
    invoice_id: Uuid,
    quote_version_id: Uuid,
    quote_offer_id: Uuid,
    provider_offer_id: &str,
) -> Result<Option<(String, i64)>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as(
        "SELECT swap.invoice, swap.amount_sat \
           FROM swap_records swap \
           JOIN invoice_quote_offers offer \
             ON offer.id = swap.invoice_quote_offer_id \
            AND offer.quote_version_id = swap.invoice_quote_version_id \
            AND offer.invoice_id = swap.invoice_id \
          WHERE swap.invoice_id = $1 \
            AND swap.invoice_quote_version_id = $2 \
            AND swap.invoice_quote_offer_id = $3 \
            AND swap.boltz_swap_id = $4 \
            AND swap.status = 'pending' \
            AND offer.rail = 'lightning' \
            AND offer.offer_kind = 'boltz_reverse' \
            AND offer.provider = 'boltz' \
            AND offer.provider_offer_id = swap.boltz_swap_id",
    )
    .bind(invoice_id)
    .bind(quote_version_id)
    .bind(quote_offer_id)
    .bind(provider_offer_id)
    .fetch_optional(executor)
    .await
}

/// Transaction-aware quote-offer persistence for provider paths that must
/// commit the immutable offer identity and canonical swap attribution on the
/// same invoice-locking connection.
pub async fn record_or_reuse_invoice_quote_offer_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    candidate: &NewInvoiceQuoteOffer<'_>,
) -> Result<InvoiceQuoteOfferResolution, sqlx::Error> {
    lock_invoice_lightning_projection(tx, candidate.invoice_id).await?;

    if let Some(offer) = sqlx::query_as::<_, InvoiceQuoteOffer>(&format!(
        "SELECT {INVOICE_QUOTE_OFFER_COLUMNS} \
           FROM invoice_quote_offers \
          WHERE quote_version_id = $1 AND rail = $2 AND request_key = $3"
    ))
    .bind(candidate.quote_version_id)
    .bind(candidate.rail)
    .bind(candidate.request_key)
    .fetch_optional(&mut **tx)
    .await?
    {
        if !invoice_quote_offer_matches_candidate(&offer, candidate) {
            return Err(sqlx::Error::Protocol(
                "invoice quote offer request key was replayed with different evidence".to_string(),
            ));
        }
        return Ok(InvoiceQuoteOfferResolution {
            offer,
            created: false,
        });
    }

    let offer = sqlx::query_as::<_, InvoiceQuoteOffer>(&format!(
        "INSERT INTO invoice_quote_offers ( \
             invoice_id, quote_version_id, rail, offer_kind, request_key, \
             provider, provider_offer_id, provider_attempt_id, direct_address, \
             direct_liquid_blinding_key_hex, direct_address_index, payer_amount_sat, expires_at \
         ) VALUES ( \
             $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, \
             CASE WHEN $4 = 'direct' THEN ( \
                 SELECT expires_at FROM invoice_quote_versions \
                  WHERE id = $2 AND invoice_id = $1 \
             ) ELSE to_timestamp($13) END \
         ) \
         RETURNING {INVOICE_QUOTE_OFFER_COLUMNS}"
    ))
    .bind(candidate.invoice_id)
    .bind(candidate.quote_version_id)
    .bind(candidate.rail)
    .bind(candidate.offer_kind)
    .bind(candidate.request_key)
    .bind(candidate.provider)
    .bind(candidate.provider_offer_id)
    .bind(candidate.provider_attempt_id)
    .bind(candidate.direct_address)
    .bind(candidate.direct_liquid_blinding_key_hex)
    .bind(candidate.direct_address_index)
    .bind(candidate.payer_amount_sat)
    .bind(candidate.expires_at_unix)
    .fetch_one(&mut **tx)
    .await?;

    Ok(InvoiceQuoteOfferResolution {
        offer,
        created: true,
    })
}

/// Atomically allocate and persist one unique direct-Liquid destination for a
/// checkout fiat quote. The page cursor and immutable offer commit together;
/// an exact retry reads the existing offer before touching the cursor.
pub async fn record_or_reuse_checkout_liquid_quote_offer<F>(
    pool: &PgPool,
    candidate: &NewInvoiceQuoteOffer<'_>,
    derive_destination: F,
) -> Result<InvoiceQuoteOfferResolution, sqlx::Error>
where
    F: Fn(&str, u32) -> Result<(String, String), sqlx::Error>,
{
    if candidate.rail != "liquid"
        || candidate.offer_kind != "direct"
        || candidate.provider.is_some()
        || candidate.provider_offer_id.is_some()
        || candidate.provider_attempt_id.is_some()
        || candidate.direct_address.is_some()
        || candidate.direct_liquid_blinding_key_hex.is_some()
        || candidate.direct_address_index.is_some()
    {
        return Err(sqlx::Error::Protocol(
            "checkout Liquid allocator requires an unallocated direct offer candidate".into(),
        ));
    }

    let mut tx = pool.begin().await?;
    lock_invoice_lightning_projection(&mut tx, candidate.invoice_id).await?;

    if let Some(offer) = sqlx::query_as::<_, InvoiceQuoteOffer>(&format!(
        "SELECT {INVOICE_QUOTE_OFFER_COLUMNS} \
           FROM invoice_quote_offers \
          WHERE quote_version_id = $1 AND rail = 'liquid' AND request_key = $2"
    ))
    .bind(candidate.quote_version_id)
    .bind(candidate.request_key)
    .fetch_optional(&mut *tx)
    .await?
    {
        let replay_matches = offer.invoice_id == candidate.invoice_id
            && offer.quote_version_id == candidate.quote_version_id
            && offer.rail == candidate.rail
            && offer.offer_kind == candidate.offer_kind
            && offer.request_key == candidate.request_key
            && offer.provider.is_none()
            && offer.provider_offer_id.is_none()
            && offer.provider_attempt_id.is_none()
            && offer.direct_address.is_some()
            && offer.direct_liquid_blinding_key_hex.is_some()
            && offer.direct_address_index.is_some()
            && offer.payer_amount_sat == candidate.payer_amount_sat
            && offer.expires_at_unix == candidate.expires_at_unix;
        if !replay_matches {
            return Err(sqlx::Error::Protocol(
                "checkout Liquid quote request was replayed with different evidence".into(),
            ));
        }
        tx.commit().await?;
        return Ok(InvoiceQuoteOfferResolution {
            offer,
            created: false,
        });
    }

    let invoice_surface: Option<(String, String)> = sqlx::query_as(
        "SELECT nym_owner, checkout_surface_kind FROM invoices \
          WHERE id = $1 AND origin = 'checkout' \
            AND pricing_mode = 'fiat_fixed' \
            AND nym_owner IS NOT NULL AND checkout_surface_kind IS NOT NULL \
          FOR UPDATE",
    )
    .bind(candidate.invoice_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((nym, kind)) = invoice_surface else {
        return Err(sqlx::Error::Protocol(
            "direct fiat Liquid offers require a checkout descriptor surface".into(),
        ));
    };

    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1)::BIGINT)")
        .bind(format!("donation-page:{nym}:{kind}"))
        .execute(&mut *tx)
        .await?;
    let page: Option<(String, i32)> = sqlx::query_as(
        "SELECT ct_descriptor, next_addr_idx FROM donation_pages \
          WHERE nym = $1 AND kind = $2 AND enabled = TRUE \
            AND archived_at IS NULL AND ct_descriptor IS NOT NULL \
          FOR UPDATE",
    )
    .bind(&nym)
    .bind(&kind)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((descriptor, mut address_index)) = page else {
        return Err(sqlx::Error::Protocol(
            "checkout descriptor surface is unavailable for a direct quote".into(),
        ));
    };

    for _ in 0..100 {
        let index = u32::try_from(address_index).map_err(|_| {
            sqlx::Error::Protocol(format!("quote address index overflow: {address_index}"))
        })?;
        let (address, blinding_key_hex) = derive_destination(&descriptor, index)?;
        let in_use: bool = sqlx::query_scalar(
            "SELECT EXISTS ( \
                 SELECT 1 FROM invoice_payment_addresses \
                  WHERE rail = 'liquid' AND address = $1 \
                 UNION ALL \
                 SELECT 1 FROM invoice_quote_offers \
                  WHERE rail = 'liquid' AND direct_address = $1 \
             )",
        )
        .bind(&address)
        .fetch_one(&mut *tx)
        .await?;
        if in_use {
            address_index = address_index
                .checked_add(1)
                .ok_or_else(|| sqlx::Error::Protocol("quote address index exhausted".into()))?;
            continue;
        }

        let allocated = NewInvoiceQuoteOffer {
            invoice_id: candidate.invoice_id,
            quote_version_id: candidate.quote_version_id,
            rail: candidate.rail,
            offer_kind: candidate.offer_kind,
            request_key: candidate.request_key,
            provider: None,
            provider_offer_id: None,
            provider_attempt_id: None,
            direct_address: Some(&address),
            direct_liquid_blinding_key_hex: Some(&blinding_key_hex),
            direct_address_index: Some(address_index),
            payer_amount_sat: candidate.payer_amount_sat,
            expires_at_unix: candidate.expires_at_unix,
        };
        let resolution = record_or_reuse_invoice_quote_offer_in_tx(&mut tx, &allocated).await?;
        let next_index = address_index
            .checked_add(1)
            .ok_or_else(|| sqlx::Error::Protocol("quote address index exhausted".into()))?;
        sqlx::query(
            "UPDATE donation_pages SET next_addr_idx = $3 \
              WHERE nym = $1 AND kind = $2",
        )
        .bind(&nym)
        .bind(&kind)
        .bind(next_index)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        return Ok(resolution);
    }

    sqlx::query("UPDATE donation_pages SET next_addr_idx = $3 WHERE nym = $1 AND kind = $2")
        .bind(&nym)
        .bind(&kind)
        .bind(address_index)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Err(sqlx::Error::Protocol(format!(
        "could not allocate a unique quote Liquid destination for {nym}/{kind} after 100 attempts"
    )))
}

pub async fn get_invoice_by_id<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    id: Uuid,
) -> Result<Option<Invoice>, sqlx::Error> {
    sqlx::query_as::<_, Invoice>(&format!(
        "SELECT {INVOICE_COLUMNS} FROM invoices WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(executor)
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
pub async fn list_invoices_by_npub<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
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
    .fetch_all(executor)
    .await
}

/// Address-keyed scan for the chain watcher: every payable invoice, every
/// closed invoice whose address can still receive late money, plus every
/// non-superseded direct-Liquid observation/event that needs permanent reorg
/// monitoring. Cancellation and expiry suppress instructions, never evidence.
/// Linked and unlinked invoices are covered uniformly regardless of whether
/// the address came from the descriptor allocator or the wallet.
///
/// The production watcher pages through disjoint recent and historical lanes.
/// Each process freezes PostgreSQL time once per lane traversal, then keysets
/// on `(created_at, id)`. A persisted cursor chooses the rotation start only;
/// the process wraps through the frozen start before treating the lane as
/// healthy. One sentinel row beyond the 1,000-row work batch distinguishes a
/// completed range from deferred work without a count.
const LIQUID_WATCHER_BATCH_SIZE: usize = 1_000;

pub(crate) const LIQUID_WATCHER_PAGE_SQL: &str = "WITH targets AS ( \
       SELECT invoices.id, invoices.id AS invoice_id, liquid_address, \
              GREATEST(amount_sat - COALESCE(paid_amount_sat, 0), 0) AS amount_sat, \
              liquid_blinding_key_hex, created_at, \
              NULL::UUID AS invoice_quote_version_id, \
              NULL::UUID AS invoice_quote_offer_id \
         FROM invoices \
        WHERE ( \
             ( \
               (status IN ('unpaid', 'in_progress', 'partially_paid') \
                OR (origin = 'checkout' AND status = 'underpaid')) \
               AND expires_at + ($1 || ' seconds')::interval > $2::timestamptz \
             ) \
             OR status IN ('cancelled', 'expired') \
             OR direct_settlement_status IN ('pending', 'resolution_pending') \
             OR EXISTS ( \
                  SELECT 1 FROM invoice_payment_observations direct_observation \
                  WHERE direct_observation.invoice_id = invoices.id \
                    AND direct_observation.source = 'liquid_direct' \
                    AND direct_observation.last_seen_state <> 'superseded' \
             ) \
             OR EXISTS ( \
                  SELECT 1 FROM invoice_payment_events direct_event \
                  WHERE direct_event.invoice_id = invoices.id \
                    AND direct_event.source = 'liquid_direct' \
                    AND direct_event.accounting_state <> 'superseded' \
                    AND direct_event.superseded_by_event_id IS NULL \
             ) \
           ) \
          AND accept_liquid = TRUE \
          AND liquid_address IS NOT NULL \
          AND liquid_blinding_key_hex IS NOT NULL \
       UNION ALL \
       SELECT quote_offer.id, invoices.id AS invoice_id, \
              quote_offer.direct_address AS liquid_address, \
              quote_offer.payer_amount_sat AS amount_sat, \
              quote_offer.direct_liquid_blinding_key_hex AS liquid_blinding_key_hex, \
              quote_offer.created_at, quote_offer.quote_version_id, quote_offer.id \
         FROM invoice_quote_offers quote_offer \
         JOIN invoices ON invoices.id = quote_offer.invoice_id \
        WHERE quote_offer.rail = 'liquid' \
          AND quote_offer.offer_kind = 'direct' \
          AND quote_offer.direct_address IS NOT NULL \
          AND quote_offer.direct_liquid_blinding_key_hex IS NOT NULL \
          AND ( \
             ( \
               (status IN ('unpaid', 'in_progress', 'partially_paid') \
                OR (origin = 'checkout' AND status = 'underpaid')) \
               AND expires_at + ($1 || ' seconds')::interval > $2::timestamptz \
             ) \
             OR status IN ('cancelled', 'expired') \
             OR direct_settlement_status IN ('pending', 'resolution_pending') \
             OR EXISTS ( \
                  SELECT 1 FROM invoice_payment_observations direct_observation \
                  WHERE direct_observation.invoice_id = invoices.id \
                    AND direct_observation.source = 'liquid_direct' \
                    AND direct_observation.last_seen_state <> 'superseded' \
             ) \
             OR EXISTS ( \
                  SELECT 1 FROM invoice_payment_events direct_event \
                  WHERE direct_event.invoice_id = invoices.id \
                    AND direct_event.source = 'liquid_direct' \
                    AND direct_event.accounting_state <> 'superseded' \
                    AND direct_event.superseded_by_event_id IS NULL \
             ) \
          ) \
     ) \
     SELECT id, invoice_id, liquid_address, amount_sat, liquid_blinding_key_hex, \
            created_at::TEXT AS created_at_cursor, invoice_quote_version_id, \
            invoice_quote_offer_id \
       FROM targets \
      WHERE created_at <= $2::timestamptz \
       AND ( \
             $3::timestamptz IS NULL \
             OR (created_at, id) > ($3::timestamptz, $4::uuid) \
           ) \
     ORDER BY created_at ASC, id ASC \
     LIMIT $5";

const LIQUID_WATCHER_ELIGIBLE_PREDICATE_SQL: &str = "( \
             ( \
               (status IN ('unpaid', 'in_progress', 'partially_paid') \
                OR (origin = 'checkout' AND status = 'underpaid')) \
               AND expires_at + ($1 || ' seconds')::interval > $2::timestamptz \
             ) \
             OR status IN ('cancelled', 'expired') \
             OR direct_settlement_status IN ('pending', 'resolution_pending') \
             OR EXISTS ( \
                  SELECT 1 FROM invoice_payment_observations direct_observation \
                  WHERE direct_observation.invoice_id = invoices.id \
                    AND direct_observation.source = 'liquid_direct' \
                    AND direct_observation.last_seen_state <> 'superseded' \
             ) \
             OR EXISTS ( \
                  SELECT 1 FROM invoice_payment_events direct_event \
                  WHERE direct_event.invoice_id = invoices.id \
                    AND direct_event.source = 'liquid_direct' \
                    AND direct_event.accounting_state <> 'superseded' \
                    AND direct_event.superseded_by_event_id IS NULL \
             ) \
           ) \
       AND accept_liquid = TRUE \
       AND liquid_address IS NOT NULL \
       AND liquid_blinding_key_hex IS NOT NULL";

/// Canonical priority predicate shared by both lanes. Old invoices with a
/// partial presentation or unsettled direct evidence remain on the fast lane;
/// historical is the exact negation within the same eligible cohort.
pub(crate) const LIQUID_WATCHER_RECENT_PREDICATE_SQL: &str = "( \
             created_at > $2::timestamptz - ($3 || ' seconds')::interval \
             OR COALESCE(presentation_status = 'partial', FALSE) \
             OR direct_settlement_status IN ('pending', 'resolution_pending') \
           )";

/// Lane-aware production query. `{lane_predicate}` is replaced with the
/// canonical priority predicate above or its exact negation. Eligibility
/// deliberately matches the compatibility query so lifecycle closure cannot
/// erase late-money or reorg obligations.
pub(crate) const LIQUID_WATCHER_LANE_PAGE_SQL: &str = "WITH targets AS ( \
       SELECT invoices.id, invoices.id AS invoice_id, liquid_address, \
              GREATEST(amount_sat - COALESCE(paid_amount_sat, 0), 0) AS amount_sat, \
              liquid_blinding_key_hex, created_at, presentation_status, \
              direct_settlement_status, \
              NULL::UUID AS invoice_quote_version_id, \
              NULL::UUID AS invoice_quote_offer_id \
         FROM invoices WHERE {eligible} \
       UNION ALL \
       SELECT quote_offer.id, invoices.id AS invoice_id, \
              quote_offer.direct_address, quote_offer.payer_amount_sat, \
              quote_offer.direct_liquid_blinding_key_hex, quote_offer.created_at, \
              invoices.presentation_status, invoices.direct_settlement_status, \
              quote_offer.quote_version_id, quote_offer.id \
         FROM invoice_quote_offers quote_offer \
         JOIN invoices ON invoices.id = quote_offer.invoice_id \
        WHERE {eligible} \
          AND quote_offer.rail = 'liquid' \
          AND quote_offer.offer_kind = 'direct' \
          AND quote_offer.direct_address IS NOT NULL \
          AND quote_offer.direct_liquid_blinding_key_hex IS NOT NULL \
     ) \
     SELECT id, invoice_id, liquid_address, amount_sat, liquid_blinding_key_hex, \
            created_at::TEXT AS created_at_cursor, invoice_quote_version_id, \
            invoice_quote_offer_id \
       FROM targets \
      WHERE {lane_predicate} \
       AND created_at <= $2::timestamptz \
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

pub(crate) const LIQUID_WATCHER_LANE_LAG_SQL: &str = "WITH targets AS ( \
       SELECT invoices.id, created_at, presentation_status, direct_settlement_status \
         FROM invoices WHERE {eligible} \
       UNION ALL \
       SELECT quote_offer.id, quote_offer.created_at, invoices.presentation_status, \
              invoices.direct_settlement_status \
         FROM invoice_quote_offers quote_offer \
         JOIN invoices ON invoices.id = quote_offer.invoice_id \
        WHERE {eligible} \
          AND quote_offer.rail = 'liquid' \
          AND quote_offer.offer_kind = 'direct' \
          AND quote_offer.direct_address IS NOT NULL \
          AND quote_offer.direct_liquid_blinding_key_hex IS NOT NULL \
     ) SELECT \
            COUNT(*)::BIGINT, \
            MIN(created_at)::TEXT, \
            COALESCE( \
                GREATEST( \
                    0, \
                    FLOOR(EXTRACT(EPOCH FROM ( \
                        $2::timestamptz - MIN(created_at) \
                    )))::BIGINT \
                ), \
                0 \
            )::BIGINT \
     FROM targets \
     WHERE {lane_predicate} \
       AND created_at <= $2::timestamptz";

type LiquidWatcherInvoice = (Uuid, String, i64, String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatcherScanCursor {
    pub created_at: String,
    pub id: Uuid,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WatcherScanEpoch {
    snapshot: Option<String>,
    cursor: Option<WatcherScanCursor>,
}

impl WatcherScanEpoch {
    pub fn snapshot(&self) -> Option<&str> {
        self.snapshot.as_deref()
    }

    pub fn cursor(&self) -> Option<&WatcherScanCursor> {
        self.cursor.as_ref()
    }

    pub fn begin(&mut self, snapshot: String) {
        if self.snapshot.is_none() {
            self.snapshot = Some(snapshot);
        }
    }

    pub fn advance(&mut self, cursor: WatcherScanCursor) {
        self.cursor = Some(cursor);
    }

    pub fn finish(&mut self) {
        self.snapshot = None;
        self.cursor = None;
    }
}

#[derive(Debug, sqlx::FromRow)]
pub struct LiquidWatcherInvoicePageRow {
    /// Unique scan target identity: invoice id for its settlement address, or
    /// quote-offer id for an immutable per-quote direct destination.
    pub id: Uuid,
    pub invoice_id: Uuid,
    pub liquid_address: String,
    pub amount_sat: i64,
    pub liquid_blinding_key_hex: String,
    pub created_at_cursor: String,
    pub invoice_quote_version_id: Option<Uuid>,
    pub invoice_quote_offer_id: Option<Uuid>,
}

impl LiquidWatcherInvoicePageRow {
    pub fn scan_cursor(&self) -> WatcherScanCursor {
        WatcherScanCursor {
            created_at: self.created_at_cursor.clone(),
            id: self.id,
        }
    }
}

pub struct LiquidWatcherInvoicePage {
    pub rows: Vec<LiquidWatcherInvoicePageRow>,
    pub has_more: bool,
}

pub struct LiquidWatcherInvoiceBatch {
    pub rows: Vec<LiquidWatcherInvoice>,
    pub has_more: bool,
}

fn truncate_to_watcher_batch<T>(rows: &mut Vec<T>, limit: usize) -> bool {
    let has_more = rows.len() > limit;
    rows.truncate(limit);
    has_more
}

/// Database-clock cutoff for one process-local watcher epoch. Text is used so
/// the watcher does not need a second timestamp library; PostgreSQL parses its
/// own representation back as `timestamptz` in the page query.
pub async fn watcher_scan_snapshot(pool: &PgPool) -> Result<String, sqlx::Error> {
    sqlx::query_scalar("SELECT clock_timestamp()::TEXT")
        .fetch_one(pool)
        .await
}

pub async fn list_unpaid_invoices_with_liquid_address_page(
    pool: &PgPool,
    payment_grace_secs: u64,
    snapshot: &str,
    cursor: Option<&WatcherScanCursor>,
) -> Result<LiquidWatcherInvoicePage, sqlx::Error> {
    let mut rows = sqlx::query_as::<_, LiquidWatcherInvoicePageRow>(LIQUID_WATCHER_PAGE_SQL)
        .bind(payment_grace_secs as i64)
        .bind(snapshot)
        .bind(cursor.map(|cursor| cursor.created_at.as_str()))
        .bind(cursor.map(|cursor| cursor.id))
        .bind((LIQUID_WATCHER_BATCH_SIZE + 1) as i64)
        .fetch_all(pool)
        .await?;
    let has_more = truncate_to_watcher_batch(&mut rows, LIQUID_WATCHER_BATCH_SIZE);
    Ok(LiquidWatcherInvoicePage { rows, has_more })
}

fn liquid_watcher_lane_sql(template: &str, recent: bool) -> String {
    let lane_predicate = if recent {
        LIQUID_WATCHER_RECENT_PREDICATE_SQL.to_string()
    } else {
        format!("NOT {LIQUID_WATCHER_RECENT_PREDICATE_SQL}")
    };
    template
        .replace("{eligible}", LIQUID_WATCHER_ELIGIBLE_PREDICATE_SQL)
        .replace("{lane_predicate}", &lane_predicate)
}

pub async fn list_liquid_watcher_invoice_lane_page(
    pool: &PgPool,
    payment_grace_secs: u64,
    active_window_secs: u32,
    snapshot: &str,
    recent: bool,
    cursor: Option<&WatcherScanCursor>,
    wrap_limit: Option<&WatcherScanCursor>,
) -> Result<LiquidWatcherInvoicePage, sqlx::Error> {
    let sql = liquid_watcher_lane_sql(LIQUID_WATCHER_LANE_PAGE_SQL, recent);
    let mut rows = sqlx::query_as::<_, LiquidWatcherInvoicePageRow>(&sql)
        .bind(payment_grace_secs as i64)
        .bind(snapshot)
        .bind(active_window_secs as i64)
        .bind(cursor.map(|cursor| cursor.created_at.as_str()))
        .bind(cursor.map(|cursor| cursor.id))
        .bind(wrap_limit.map(|cursor| cursor.created_at.as_str()))
        .bind(wrap_limit.map(|cursor| cursor.id))
        .bind((LIQUID_WATCHER_BATCH_SIZE + 1) as i64)
        .fetch_all(pool)
        .await?;
    let has_more = truncate_to_watcher_batch(&mut rows, LIQUID_WATCHER_BATCH_SIZE);
    Ok(LiquidWatcherInvoicePage { rows, has_more })
}

/// Frozen-lane backlog observation. `oldest_due_lag_secs` is bounded at zero
/// when the lane is empty or database time would otherwise produce a negative
/// duration.
pub async fn liquid_watcher_lane_lag(
    pool: &PgPool,
    payment_grace_secs: u64,
    active_window_secs: u32,
    snapshot: &str,
    recent: bool,
) -> Result<(i64, Option<String>, i64), sqlx::Error> {
    let sql = liquid_watcher_lane_sql(LIQUID_WATCHER_LANE_LAG_SQL, recent);
    sqlx::query_as(&sql)
        .bind(payment_grace_secs as i64)
        .bind(snapshot)
        .bind(active_window_secs as i64)
        .fetch_one(pool)
        .await
}

pub async fn list_unpaid_invoices_with_liquid_address_batch(
    pool: &PgPool,
    payment_grace_secs: u64,
) -> Result<LiquidWatcherInvoiceBatch, sqlx::Error> {
    let snapshot = watcher_scan_snapshot(pool).await?;
    let page =
        list_unpaid_invoices_with_liquid_address_page(pool, payment_grace_secs, &snapshot, None)
            .await?;
    let has_more = page.has_more;
    let rows = page
        .rows
        .into_iter()
        .map(|row| {
            (
                row.invoice_id,
                row.liquid_address,
                row.amount_sat,
                row.liquid_blinding_key_hex,
            )
        })
        .collect();
    Ok(LiquidWatcherInvoiceBatch { rows, has_more })
}

/// Compatibility projection for callers that only need the bounded row set.
/// Returned shape: `(invoice_id, liquid_address, amount_sat, blinding_key_hex)`.
pub async fn list_unpaid_invoices_with_liquid_address(
    pool: &PgPool,
    payment_grace_secs: u64,
) -> Result<Vec<LiquidWatcherInvoice>, sqlx::Error> {
    Ok(
        list_unpaid_invoices_with_liquid_address_batch(pool, payment_grace_secs)
            .await?
            .rows,
    )
}

#[derive(Debug, Clone, Copy)]
pub struct InvoiceAccountingTolerances {
    pub btc_sat: i64,
    pub liquid_sat: i64,
    pub lightning_sat: i64,
    /// Not a tolerance: the post-expiry grace window (seconds) the watchers
    /// keep polling an invoice for. Carried in this bundle because it is the
    /// invoice-accounting config already threaded to both chain watchers; see
    /// `InvoiceAccountingConfig::payment_grace_secs`.
    pub payment_grace_secs: u64,
}

impl Default for InvoiceAccountingTolerances {
    fn default() -> Self {
        Self {
            btc_sat: 300,
            liquid_sat: 60,
            lightning_sat: 1,
            payment_grace_secs: 3600,
        }
    }
}

impl From<&crate::config::InvoiceAccountingConfig> for InvoiceAccountingTolerances {
    fn from(cfg: &crate::config::InvoiceAccountingConfig) -> Self {
        Self {
            btc_sat: cfg.btc_shortfall_tolerance_sat,
            liquid_sat: cfg.liquid_shortfall_tolerance_sat,
            lightning_sat: cfg.lightning_shortfall_tolerance_sat,
            payment_grace_secs: cfg.payment_grace_secs,
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

/// One shortfall-tolerance contract for every projection of an invoice.
///
/// A payer sees one `payment_tolerance_sat` value even when several rails are
/// accepted, so accounting and presentation must enforce that same value. Use
/// the strictest accepted-rail tolerance, capped at one percent of the invoice
/// amount. This is intentionally independent of which rail delivers the latest
/// event; otherwise a mixed-rail invoice can be accepted outside its public
/// contract and its result can depend on event order.
pub(crate) fn invoice_payment_tolerance_sat(
    amount_sat: i64,
    accept_btc: bool,
    accept_liquid: bool,
    accept_ln: bool,
    tolerances: InvoiceAccountingTolerances,
) -> i64 {
    let rail_tolerance = [
        accept_btc.then_some(tolerances.for_rail("bitcoin")),
        accept_liquid.then_some(tolerances.for_rail("liquid")),
        accept_ln.then_some(tolerances.for_rail("lightning")),
    ]
    .into_iter()
    .flatten()
    .min()
    .unwrap_or(tolerances.for_rail("lightning"));
    let one_percent = (amount_sat / 100).max(1);
    rail_tolerance.min(one_percent).max(0)
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
struct BoltzSupersededDirectEvent {
    direct_event_id: Uuid,
    observation_id: Option<Uuid>,
    source: String,
    from_event_state: String,
    from_observation_state: Option<String>,
    observation_verification_state: Option<String>,
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

pub async fn list_invoice_payment_observations<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
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
    .fetch_all(executor)
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

/// Compute the next invoice status from the recomputed `received_sat` total.
///
/// Pure (no I/O) so it is unit-testable. Enforces the **settled-stickiness
/// invariant**: an invoice that has already reached `paid`/`overpaid` never
/// regresses to a non-settled status. Without this, a later payment event on a
/// tighter-tolerance rail (or a cross-rail dedup prune) can recompute the
/// status as `partially_paid` and clobber `settlement_status` back to `none` —
/// i.e. receiving *more* money un-pays a settled invoice, which GC then
/// terminalizes to `underpaid`.
fn resolve_invoice_status(
    prior_status: &str,
    amount_sat: i64,
    received_sat: i64,
    tolerance_sat: i64,
    expired: bool,
) -> &'static str {
    let computed = if received_sat > amount_sat {
        "overpaid"
    } else if amount_sat.saturating_sub(received_sat) <= tolerance_sat {
        "paid"
    } else if prior_status == "underpaid" || expired {
        "underpaid"
    } else {
        "partially_paid"
    };

    // Never regress a settled invoice back to a non-settled status.
    if matches!(prior_status, "paid" | "overpaid") && !matches!(computed, "paid" | "overpaid") {
        if prior_status == "overpaid" {
            "overpaid"
        } else {
            "paid"
        }
    } else {
        computed
    }
}

fn resolve_invoice_presentation_status(
    prior_accounting_status: &str,
    amount_sat: i64,
    events: &[(String, i64)],
    tolerance_sat: i64,
) -> &'static str {
    let mut received_sat = 0_i64;
    let mut status = "unpaid";
    for (_rail, event_amount_sat) in events {
        received_sat = received_sat.saturating_add(*event_amount_sat);
        let computed = if received_sat > amount_sat {
            "overpaid"
        } else if amount_sat.saturating_sub(received_sat) <= tolerance_sat {
            "payment_received"
        } else {
            "partial"
        };
        status = if matches!(status, "payment_received" | "overpaid") && computed == "partial" {
            status
        } else {
            computed
        };
    }
    // Keep presentation aligned with the durable accounting stickiness
    // contract. This matters during rollout: an invoice accepted under the
    // historical rail-local tolerance must not visually regress when a later
    // event is evaluated under the corrected invoice-wide tolerance.
    if prior_accounting_status == "overpaid" && status != "overpaid" {
        "overpaid"
    } else if prior_accounting_status == "paid"
        && !matches!(status, "payment_received" | "overpaid")
    {
        "payment_received"
    } else {
        status
    }
}

fn compose_invoice_settlement_status(direct: &str, swap: &str) -> &'static str {
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

async fn lock_invoice_lightning_projection(
    tx: &mut Transaction<'_, Postgres>,
    invoice_id: Uuid,
) -> Result<(), sqlx::Error> {
    let key = super::invoice_lightning_lock_key(invoice_id);
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(key)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

pub async fn record_invoice_payment(
    pool: &PgPool,
    id: Uuid,
    evidence: InvoicePaymentEvidence<'_>,
    tolerances: InvoiceAccountingTolerances,
) -> Result<u64, sqlx::Error> {
    record_invoice_payment_with_optional_quote_attribution(pool, id, evidence, None, tolerances)
        .await
}

/// Quote-aware payment writer for direct and provider-backed evidence. The
/// exact offer identity is immutable on first insert; an idempotent retry must
/// present the same attribution. Provider settlements also recover attribution
/// from their persisted swap row so crash-repair callers cannot drop lineage.
pub async fn record_invoice_payment_with_quote_attribution(
    pool: &PgPool,
    id: Uuid,
    evidence: InvoicePaymentEvidence<'_>,
    attribution: InvoiceQuoteAttribution,
    tolerances: InvoiceAccountingTolerances,
) -> Result<u64, sqlx::Error> {
    record_invoice_payment_with_optional_quote_attribution(
        pool,
        id,
        evidence,
        Some(attribution),
        tolerances,
    )
    .await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PersistedProviderQuoteAttribution {
    attribution: InvoiceQuoteAttribution,
    first_observed_at_unix: i64,
}

async fn persisted_provider_quote_attribution(
    tx: &mut Transaction<'_, Postgres>,
    invoice_id: Uuid,
    evidence: &InvoicePaymentEvidence<'_>,
) -> Result<Option<PersistedProviderQuoteAttribution>, sqlx::Error> {
    let Some(boltz_swap_id) = evidence.boltz_swap_id else {
        return Ok(None);
    };
    let row: Option<(Option<Uuid>, Option<Uuid>, Option<Uuid>, Option<i64>)> = match evidence.source
    {
        "lightning_boltz_reverse" => {
            sqlx::query_as(
                "SELECT invoice_id, invoice_quote_version_id, invoice_quote_offer_id, \
                        FLOOR(EXTRACT(EPOCH FROM quote_payment_first_observed_at))::BIGINT \
               FROM swap_records WHERE boltz_swap_id = $1",
            )
            .bind(boltz_swap_id)
            .fetch_optional(&mut **tx)
            .await?
        }
        "bitcoin_boltz_chain" => {
            sqlx::query_as(
                "SELECT invoice_id, invoice_quote_version_id, invoice_quote_offer_id, \
                        FLOOR(EXTRACT(EPOCH FROM quote_payment_first_observed_at))::BIGINT \
               FROM chain_swap_records WHERE boltz_swap_id = $1",
            )
            .bind(boltz_swap_id)
            .fetch_optional(&mut **tx)
            .await?
        }
        _ => None,
    };
    let Some((persisted_invoice_id, quote_version_id, quote_offer_id, first_observed_at_unix)) =
        row
    else {
        return Ok(None);
    };
    if persisted_invoice_id != Some(invoice_id) {
        return Err(sqlx::Error::Protocol(
            "provider settlement swap belongs to a different invoice".into(),
        ));
    }
    match (quote_version_id, quote_offer_id) {
        (None, None) => Ok(None),
        (Some(quote_version_id), Some(quote_offer_id)) => {
            let first_observed_at_unix = first_observed_at_unix.ok_or_else(|| {
                sqlx::Error::Protocol(
                    "quote-attributed provider settlement lacks durable first-observed time".into(),
                )
            })?;
            Ok(Some(PersistedProviderQuoteAttribution {
                attribution: InvoiceQuoteAttribution {
                    quote_version_id,
                    quote_offer_id,
                },
                first_observed_at_unix,
            }))
        }
        _ => Err(sqlx::Error::Protocol(
            "provider settlement swap has partial quote attribution".into(),
        )),
    }
}

fn payment_offer_identity<'a>(
    evidence: &'a InvoicePaymentEvidence<'a>,
) -> (
    &'static str,
    &'static str,
    Option<&'static str>,
    Option<&'a str>,
) {
    match evidence.source {
        "bitcoin_direct" => ("bitcoin", "direct", None, None),
        "liquid_direct" => ("liquid", "direct", None, None),
        "lightning_boltz_reverse" => (
            "lightning",
            "boltz_reverse",
            Some("boltz"),
            evidence.boltz_swap_id,
        ),
        "bitcoin_boltz_chain" => (
            "bitcoin",
            "boltz_chain",
            Some("boltz"),
            evidence.boltz_swap_id,
        ),
        _ => unreachable!("InvoicePaymentEvidence::validate rejects unknown source"),
    }
}

async fn record_invoice_payment_with_optional_quote_attribution(
    pool: &PgPool,
    id: Uuid,
    evidence: InvoicePaymentEvidence<'_>,
    requested_attribution: Option<InvoiceQuoteAttribution>,
    tolerances: InvoiceAccountingTolerances,
) -> Result<u64, sqlx::Error> {
    evidence.validate()?;

    let mut tx = pool.begin().await?;
    lock_invoice_lightning_projection(&mut tx, id).await?;
    let inv = sqlx::query_as::<_, Invoice>(&format!(
        "SELECT {INVOICE_COLUMNS} FROM invoices WHERE id = $1 FOR UPDATE"
    ))
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;

    let persisted_attribution =
        persisted_provider_quote_attribution(&mut tx, id, &evidence).await?;
    let attribution = match (requested_attribution, persisted_attribution) {
        (Some(requested), Some(persisted)) if requested != persisted.attribution => {
            return Err(sqlx::Error::Protocol(
                "payment quote attribution conflicts with its persisted provider swap".into(),
            ));
        }
        (Some(requested), Some(persisted)) => Some((requested, persisted.first_observed_at_unix)),
        (Some(_), None) => {
            return Err(sqlx::Error::Protocol(
                "quote-attributed payment requires durable provider observation evidence".into(),
            ));
        }
        (None, persisted) => {
            persisted.map(|persisted| (persisted.attribution, persisted.first_observed_at_unix))
        }
    };
    if let Some((attribution, _)) = attribution {
        let (rail, offer_kind, provider, provider_offer_id) = payment_offer_identity(&evidence);
        if evidence.rail != rail {
            return Err(sqlx::Error::Protocol(
                "payment evidence rail does not match its quote offer identity".into(),
            ));
        }
        validate_invoice_quote_attribution(
            &mut *tx,
            id,
            attribution,
            rail,
            offer_kind,
            provider,
            provider_offer_id,
            None,
        )
        .await?;
    }

    let is_direct_liquid_payment = evidence.source == "liquid_direct";
    let is_boltz_settlement = matches!(
        evidence.source,
        "lightning_boltz_reverse" | "bitcoin_boltz_chain"
    );

    if is_direct_liquid_payment {
        let (boltz_settlement_exists,): (bool,) = sqlx::query_as(
            "SELECT EXISTS ( \
                SELECT 1 FROM invoice_payment_events \
                 WHERE invoice_id = $1 \
                   AND txid = $2 \
                   AND source IN ('lightning_boltz_reverse', 'bitcoin_boltz_chain') \
             )",
        )
        .bind(id)
        .bind(evidence.txid)
        .fetch_one(&mut *tx)
        .await?;
        if boltz_settlement_exists {
            tx.commit().await?;
            return Ok(0);
        }
    }

    let (accounting_state, verification_state) =
        if matches!(evidence.source, "bitcoin_direct" | "liquid_direct") {
            ("legacy_unverified", "legacy_unverified")
        } else {
            ("active", "not_applicable")
        };
    let inserted: Option<(Uuid,)> = sqlx::query_as(
        "INSERT INTO invoice_payment_events \
            (invoice_id, rail, source, event_key, amount_sat, txid, vout, \
             boltz_swap_id, address, accounting_state, verification_state, \
             invoice_quote_version_id, invoice_quote_offer_id, quote_first_observed_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, \
                 CASE WHEN $12::UUID IS NULL THEN NULL ELSE to_timestamp($14) END) \
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
    .bind(accounting_state)
    .bind(verification_state)
    .bind(attribution.map(|(attribution, _)| attribution.quote_version_id))
    .bind(attribution.map(|(attribution, _)| attribution.quote_offer_id))
    .bind(attribution.map(|(_, first_observed_at_unix)| first_observed_at_unix))
    .fetch_optional(&mut *tx)
    .await?;

    let inserted_event = inserted.is_some();
    let recorded_event_id = if let Some((event_id,)) = inserted {
        event_id
    } else {
        let existing = sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM invoice_payment_events \
             WHERE invoice_id = $1 AND event_key = $2 \
               AND rail = $3 AND source = $4 AND amount_sat = $5 \
               AND txid IS NOT DISTINCT FROM $6::TEXT \
               AND vout IS NOT DISTINCT FROM $7::INTEGER \
               AND boltz_swap_id IS NOT DISTINCT FROM $8::TEXT \
               AND address IS NOT DISTINCT FROM $9::TEXT \
               AND invoice_quote_version_id IS NOT DISTINCT FROM $10::UUID \
               AND invoice_quote_offer_id IS NOT DISTINCT FROM $11::UUID",
        )
        .bind(id)
        .bind(evidence.event_key)
        .bind(evidence.rail)
        .bind(evidence.source)
        .bind(evidence.amount_sat)
        .bind(evidence.txid)
        .bind(evidence.vout)
        .bind(evidence.boltz_swap_id)
        .bind(evidence.address)
        .bind(attribution.map(|(attribution, _)| attribution.quote_version_id))
        .bind(attribution.map(|(attribution, _)| attribution.quote_offer_id))
        .fetch_optional(&mut *tx)
        .await?;
        existing.ok_or_else(|| {
            sqlx::Error::Protocol(
                "invoice payment event key was replayed with different evidence or quote attribution"
                    .into(),
            )
        })?
    };

    // A Boltz claim transaction can also appear at the invoice's direct
    // Liquid address. Preserve that direct evidence for audit/replay, but make
    // it non-countable and point it at the canonical Boltz accounting event.
    let mut superseded_direct_events: Vec<BoltzSupersededDirectEvent> = if is_boltz_settlement {
        sqlx::query_as(
            "WITH candidates AS MATERIALIZED ( \
                     SELECT id, observation_id, source, accounting_state \
                     FROM invoice_payment_events \
                     WHERE invoice_id = $1 \
                       AND txid = $2 \
                       AND source = 'liquid_direct' \
                       AND accounting_state IN ('active', 'inactive', 'legacy_unverified') \
                     FOR UPDATE \
                 ), updated AS ( \
                     UPDATE invoice_payment_events e SET \
                         accounting_state = 'superseded', \
                         state_version = state_version + 1, \
                         deactivated_at = NOW(), \
                         deactivation_reason = 'boltz_supersession', \
                         superseded_by_event_id = $3 \
                     FROM candidates c \
                     WHERE e.id = c.id \
                     RETURNING e.id \
                 ) \
                 SELECT c.id AS direct_event_id, c.observation_id, c.source, \
                        c.accounting_state AS from_event_state, \
                        NULL::TEXT AS from_observation_state, \
                        NULL::TEXT AS observation_verification_state \
                 FROM candidates c JOIN updated u ON u.id = c.id",
        )
        .bind(id)
        .bind(evidence.txid)
        .bind(recorded_event_id)
        .fetch_all(&mut *tx)
        .await?
    } else {
        Vec::new()
    };

    for superseded in &mut superseded_direct_events {
        if let Some(observation_id) = superseded.observation_id {
            let prior = sqlx::query_as(
                "SELECT last_seen_state, verification_state \
                 FROM invoice_payment_observations WHERE id = $1 FOR UPDATE",
            )
            .bind(observation_id)
            .fetch_optional(&mut *tx)
            .await?;
            if let Some((from_state, verification_state)) = prior {
                sqlx::query(
                    "UPDATE invoice_payment_observations SET \
                         last_seen_state = 'superseded', \
                         lifecycle_version = lifecycle_version + 1, \
                         invalidation_reason = 'boltz_supersession', \
                         invalidated_at = NOW(), \
                         superseded_by_observation_id = NULL, \
                         superseded_by_payment_event_id = $2, \
                         last_seen_at = NOW() \
                     WHERE id = $1",
                )
                .bind(observation_id)
                .bind(recorded_event_id)
                .execute(&mut *tx)
                .await?;
                superseded.from_observation_state = Some(from_state);
                superseded.observation_verification_state = Some(verification_state);
            }
        }
    }
    let superseded_direct_rows = superseded_direct_events.len() as u64;

    if !inserted_event && superseded_direct_rows == 0 {
        tx.commit().await?;
        return Ok(0);
    }

    let (received_sat,): (i64,) = sqlx::query_as(
        "SELECT COALESCE(SUM(amount_sat), 0)::BIGINT \
         FROM invoice_payment_events \
         WHERE invoice_id = $1 \
           AND accounting_state IN ('active', 'legacy_unverified')",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;

    let presentation_events: Vec<(String, i64)> = sqlx::query_as(
        "SELECT e.rail, e.amount_sat \
         FROM invoice_payment_events e \
         LEFT JOIN invoice_payment_observations o ON o.id = e.observation_id \
         WHERE e.invoice_id = $1 \
           AND e.accounting_state <> 'superseded' \
           AND ( \
             e.accounting_state IN ('active', 'legacy_unverified') \
             OR ( \
               e.source IN ('bitcoin_direct', 'liquid_direct') \
               AND e.verification_state = 'verified' \
               AND o.last_seen_state = 'seen_unconfirmed' \
             ) \
           ) \
         ORDER BY e.accounting_sequence",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await?;
    let fiat_projection = if inv.pricing_mode == "fiat_fixed" {
        Some(invoice_fiat_credit_projection(&mut *tx, id).await?)
    } else {
        None
    };
    let tolerance_sat = invoice_payment_tolerance_sat(
        inv.amount_sat,
        inv.accept_btc,
        inv.accept_liquid,
        inv.accept_ln,
        tolerances,
    );
    let presentation_status = fiat_projection.map_or_else(
        || {
            resolve_invoice_presentation_status(
                &inv.status,
                inv.amount_sat,
                &presentation_events,
                tolerance_sat,
            )
        },
        fiat_invoice_presentation_status,
    );

    let rails: Vec<(String,)> = sqlx::query_as(
        "SELECT DISTINCT rail FROM invoice_payment_events \
         WHERE invoice_id = $1 \
           AND accounting_state IN ('active', 'legacy_unverified') \
         ORDER BY rail",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await?;
    let paid_via = if rails.len() == 1 {
        rails[0].0.as_str()
    } else {
        "mixed"
    };

    let expired = inv.expires_at_unix <= chrono_like_unix_now();
    let new_status = if let Some(projection) = fiat_projection {
        fiat_invoice_status(&inv.status, projection, expired)
    } else {
        match inv.status.as_str() {
            // Cancellation/expiry close instructions but remain durable lifecycle
            // markers after money lands. `presentation_status`, `paid_via`, and
            // `paid_amount_sat` carry the honest payment projection.
            "cancelled" => "cancelled",
            "expired" => "expired",
            _ => resolve_invoice_status(
                &inv.status,
                inv.amount_sat,
                received_sat,
                tolerance_sat,
                expired,
            ),
        }
    };
    let payment_settlement_status =
        if matches!(presentation_status, "payment_received" | "overpaid") {
            "settled"
        } else {
            "none"
        };
    let direct_evidence_remains: bool = sqlx::query_scalar(
        "SELECT EXISTS ( \
            SELECT 1 FROM invoice_payment_events \
            WHERE invoice_id = $1 \
              AND source IN ('bitcoin_direct', 'liquid_direct') \
              AND accounting_state <> 'superseded' \
        )",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    let direct_settlement_status = if matches!(evidence.source, "bitcoin_direct" | "liquid_direct")
    {
        payment_settlement_status
    } else if is_boltz_settlement && !direct_evidence_remains {
        "none"
    } else {
        inv.direct_settlement_status.as_str()
    };
    let swap_settlement_status = if is_boltz_settlement {
        // `record_invoice_payment` is reached only after the merchant-side
        // Boltz claim boundary succeeds. That component is settled even when
        // this payment is only a partial contribution to the invoice total.
        "settled"
    } else {
        inv.swap_settlement_status.as_str()
    };
    let settlement_status =
        compose_invoice_settlement_status(direct_settlement_status, swap_settlement_status);

    sqlx::query(
        "UPDATE invoices SET \
            status = $2, \
            presentation_status = $3, \
            paid_via = $4, \
            paid_amount_sat = $5, \
            settlement_status = $6, \
            direct_settlement_status = $7, \
            swap_settlement_status = $8, \
            direct_payment_projection_version = direct_payment_projection_version + \
                CASE WHEN $9 OR direct_settlement_status IS DISTINCT FROM $7 THEN 1 ELSE 0 END, \
            paid_at = CASE \
                WHEN $2 IN ('paid', 'overpaid') \
                  OR ($2 IN ('cancelled', 'expired') \
                      AND $3 IN ('payment_received', 'overpaid')) \
                THEN COALESCE(paid_at, NOW()) \
                ELSE paid_at END \
         WHERE id = $1",
    )
    .bind(id)
    .bind(new_status)
    .bind(presentation_status)
    .bind(paid_via)
    .bind(received_sat)
    .bind(settlement_status)
    .bind(direct_settlement_status)
    .bind(swap_settlement_status)
    .bind(superseded_direct_rows > 0)
    .execute(&mut *tx)
    .await?;

    for superseded in &superseded_direct_events {
        let idempotency_key = format!(
            "boltz-supersession:{}:{recorded_event_id}",
            superseded.direct_event_id
        );
        let to_observation_state = superseded.observation_id.map(|_| "superseded");
        let observation_verification = superseded.observation_verification_state.as_deref();
        sqlx::query(
            "INSERT INTO invoice_direct_payment_transitions \
                 (idempotency_key, invoice_id, observation_id, payment_event_id, \
                  source, generation, transition_kind, from_observation_state, \
                  to_observation_state, from_verification_state, \
                  to_verification_state, from_event_state, to_event_state, reason, \
                  from_presentation_status, to_presentation_status, \
                  from_settlement_status, to_settlement_status, \
                  from_invoice_status, to_invoice_status, \
                  from_paid_amount_sat, to_paid_amount_sat, metadata) \
             VALUES ($1, $2, $3, $4, $5, 0, 'superseded', $6, $7, $8, $8, \
                     $9, 'superseded', 'boltz_supersession', $10, $11, \
                     $12, $13, $14, $15, $16, $17, \
                     jsonb_build_object('superseded_by_payment_event_id', $18::TEXT)) \
             ON CONFLICT (idempotency_key) DO NOTHING",
        )
        .bind(idempotency_key)
        .bind(id)
        .bind(superseded.observation_id)
        .bind(superseded.direct_event_id)
        .bind(&superseded.source)
        .bind(superseded.from_observation_state.as_deref())
        .bind(to_observation_state)
        .bind(observation_verification)
        .bind(&superseded.from_event_state)
        .bind(inv.presentation_status.as_deref())
        .bind(presentation_status)
        .bind(&inv.settlement_status)
        .bind(settlement_status)
        .bind(&inv.status)
        .bind(new_status)
        .bind(inv.paid_amount_sat)
        .bind((received_sat > 0).then_some(received_sat))
        .bind(recorded_event_id.to_string())
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(u64::from(inserted_event))
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

/// Transaction ids already accounted through a Boltz settlement for this
/// invoice. A Liquid claim can pay the same invoice address and therefore also
/// appear in direct script history; watcher discovery must exclude that tx
/// before constructing direct observations or it can double count the claim.
pub async fn invoice_boltz_settlement_txids(
    pool: &PgPool,
    invoice_id: Uuid,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT DISTINCT LOWER(txid) \
         FROM invoice_payment_events \
         WHERE invoice_id = $1 \
           AND source IN ('lightning_boltz_reverse', 'bitcoin_boltz_chain') \
           AND txid IS NOT NULL \
         ORDER BY LOWER(txid)",
    )
    .bind(invoice_id)
    .fetch_all(pool)
    .await
}

fn chrono_like_unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvoiceInProgressComponent {
    Direct,
    Swap,
}

/// Atomically preserve the legacy `in_progress`/`pending` projection while
/// attributing the mempool evidence to the correct component cache. Returns
/// true only when this call changed the invoice status from `unpaid`.
pub async fn mark_invoice_in_progress_for_component(
    pool: &PgPool,
    id: Uuid,
    component: InvoiceInProgressComponent,
) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    lock_invoice_lightning_projection(&mut tx, id).await?;
    let flipped = mark_invoice_in_progress_for_component_locked(&mut tx, id, component).await?;
    tx.commit().await?;
    Ok(flipped)
}

async fn mark_invoice_in_progress_for_component_locked(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    component: InvoiceInProgressComponent,
) -> Result<bool, sqlx::Error> {
    let is_direct = component == InvoiceInProgressComponent::Direct;
    let flipped: Option<bool> = sqlx::query_scalar(
        "WITH locked AS MATERIALIZED ( \
             SELECT status, direct_settlement_status, swap_settlement_status \
             FROM invoices WHERE id = $1 FOR UPDATE \
         ), next_components AS MATERIALIZED ( \
             SELECT status, \
                    CASE WHEN $2 THEN 'pending' ELSE direct_settlement_status END \
                        AS direct_status, \
                    CASE WHEN $2 THEN swap_settlement_status ELSE 'pending' END \
                        AS swap_status \
             FROM locked \
         ), updated AS ( \
             UPDATE invoices i SET \
                 status = CASE WHEN next_components.status = 'unpaid' \
                               THEN 'in_progress' ELSE i.status END, \
                 settlement_status = CASE \
                     WHEN next_components.swap_status IN ('claim_stuck', 'failed', 'refunded') \
                         THEN next_components.swap_status \
                     WHEN next_components.direct_status = 'resolution_pending' \
                         THEN 'resolution_pending' \
                     WHEN next_components.direct_status = 'pending' \
                          OR next_components.swap_status = 'pending' THEN 'pending' \
                     WHEN next_components.direct_status = 'settled' \
                          OR next_components.swap_status = 'settled' THEN 'settled' \
                     ELSE 'none' END, \
                 direct_settlement_status = next_components.direct_status, \
                 swap_settlement_status = next_components.swap_status, \
                 direct_payment_projection_version = i.direct_payment_projection_version + \
                     CASE WHEN $2 AND i.direct_settlement_status IS DISTINCT FROM 'pending' \
                          THEN 1 ELSE 0 END \
             FROM next_components \
             WHERE i.id = $1 \
               AND i.status NOT IN ('expired', 'cancelled') \
               AND ( \
                   NOT $2 \
                   OR i.status NOT IN ('paid', 'underpaid', 'overpaid') \
               ) \
             RETURNING next_components.status = 'unpaid' \
         ) \
         SELECT * FROM updated",
    )
    .bind(id)
    .bind(is_direct)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(flipped.unwrap_or(false))
}

fn chain_swap_in_progress_projection_allowed(parent_status: &str) -> bool {
    matches!(
        parent_status,
        "user_lock_mempool"
            | "user_lock_confirmed"
            | "server_lock_mempool"
            | "server_lock_confirmed"
            | "claiming"
            | "claim_failed"
            | "refund_due"
            | "refunding"
    )
}

/// Re-drive payer-side chain-swap progress only while the current parent is a
/// funded pre-final branch. The shared invoice projection lock is acquired
/// before the parent row, matching exact settlement CAS; a late provider
/// delivery therefore cannot regress `claimed`, `claim_stuck`, `refunded`, or
/// any other terminal/unsupported branch back to settlement-pending.
pub async fn mark_chain_swap_invoice_in_progress_if_current(
    pool: &PgPool,
    chain_swap_id: Uuid,
    invoice_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    lock_invoice_lightning_projection(&mut tx, invoice_id).await?;
    let invoice_exists: Option<bool> =
        sqlx::query_scalar("SELECT TRUE FROM invoices WHERE id = $1 FOR UPDATE")
            .bind(invoice_id)
            .fetch_optional(&mut *tx)
            .await?;
    if invoice_exists.is_none() {
        tx.commit().await?;
        return Ok(false);
    }
    let parent: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT invoice_id, status FROM chain_swap_records WHERE id = $1 FOR UPDATE",
    )
    .bind(chain_swap_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((locked_invoice_id, parent_status)) = parent else {
        tx.commit().await?;
        return Ok(false);
    };
    if locked_invoice_id != invoice_id {
        return Err(sqlx::Error::Protocol(
            "chain swap invoice changed while publishing in-progress state".into(),
        ));
    }
    if !chain_swap_in_progress_projection_allowed(&parent_status) {
        tx.commit().await?;
        return Ok(false);
    }
    let flipped = mark_invoice_in_progress_for_component_locked(
        &mut tx,
        invoice_id,
        InvoiceInProgressComponent::Swap,
    )
    .await?;
    tx.commit().await?;
    Ok(flipped)
}

#[cfg(test)]
mod chain_swap_in_progress_projection_tests {
    use super::chain_swap_in_progress_projection_allowed;

    #[test]
    fn projection_accepts_only_funded_pre_final_chain_states() {
        for status in [
            "user_lock_mempool",
            "user_lock_confirmed",
            "server_lock_mempool",
            "server_lock_confirmed",
            "claiming",
            "claim_failed",
            "refund_due",
            "refunding",
        ] {
            assert!(
                chain_swap_in_progress_projection_allowed(status),
                "{status}"
            );
        }
        for status in [
            "pending",
            "claimed",
            "claim_stuck",
            "expired",
            "lockup_failed",
            "refunded",
            "unknown",
        ] {
            assert!(
                !chain_swap_in_progress_projection_allowed(status),
                "{status}"
            );
        }
    }
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
    let mut tx = pool.begin().await?;
    lock_invoice_lightning_projection(&mut tx, id).await?;
    let rows = sqlx::query(
        "UPDATE invoices SET \
             settlement_status = CASE \
                 WHEN $2 IN ('claim_stuck', 'failed', 'refunded') THEN $2 \
                 WHEN direct_settlement_status = 'resolution_pending' \
                     THEN 'resolution_pending' \
                 WHEN direct_settlement_status = 'pending' OR $2 = 'pending' THEN 'pending' \
                 WHEN direct_settlement_status = 'settled' OR $2 = 'settled' THEN 'settled' \
                 ELSE 'none' END, \
             swap_settlement_status = $2 \
         WHERE id = $1 AND status NOT IN ('expired', 'cancelled')",
    )
    .bind(id)
    .bind(settlement_status)
    .execute(&mut *tx)
    .await
    .map(|result| result.rows_affected())?;
    tx.commit().await?;
    Ok(rows)
}

/// Publish a chain-claim failure projection only while the exact obligation is
/// still stuck. The invoice lock is acquired before the parent and attempt,
/// matching exact settlement CAS order so whichever transaction wins first
/// determines the projection and the loser becomes a no-op.
pub async fn mark_chain_swap_invoice_claim_stuck_if_current(
    pool: &PgPool,
    chain_swap_id: Uuid,
) -> Result<u64, sqlx::Error> {
    let Some(invoice_id): Option<Uuid> =
        sqlx::query_scalar("SELECT invoice_id FROM chain_swap_records WHERE id = $1")
            .bind(chain_swap_id)
            .fetch_optional(pool)
            .await?
    else {
        return Ok(0);
    };
    let mut tx = pool.begin().await?;
    lock_invoice_lightning_projection(&mut tx, invoice_id).await?;
    let parent: Option<(Uuid, String, Option<String>)> = sqlx::query_as(
        "SELECT invoice_id, status, claim_txid FROM chain_swap_records \
          WHERE id = $1 FOR UPDATE",
    )
    .bind(chain_swap_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((locked_invoice_id, parent_status, claim_txid)) = parent else {
        tx.commit().await?;
        return Ok(0);
    };
    if locked_invoice_id != invoice_id {
        return Err(sqlx::Error::Protocol(
            "chain swap invoice changed while publishing claim failure".into(),
        ));
    }
    let attempt_status = if let Some(claim_txid) = claim_txid.as_deref() {
        sqlx::query_scalar::<_, String>(
            "SELECT status FROM chain_swap_tx_attempts \
              WHERE chain_swap_id = $1 AND txid = $2 \
                AND purpose IN ('liquid_claim','liquid_claim_replacement') \
              FOR UPDATE",
        )
        .bind(chain_swap_id)
        .bind(claim_txid)
        .fetch_optional(&mut *tx)
        .await?
    } else {
        None
    };
    if !chain_claim_stuck_projection_allowed(&parent_status, attempt_status.as_deref()) {
        tx.commit().await?;
        return Ok(0);
    }
    let rows = sqlx::query(
        "UPDATE invoices SET settlement_status = 'claim_stuck', \
             swap_settlement_status = 'claim_stuck' \
          WHERE id = $1 AND status NOT IN ('expired', 'cancelled')",
    )
    .bind(invoice_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    tx.commit().await?;
    Ok(rows)
}

fn chain_claim_stuck_projection_allowed(parent_status: &str, attempt_status: Option<&str>) -> bool {
    parent_status == "claim_stuck" && !matches!(attempt_status, Some("confirmed" | "finalized"))
}

#[cfg(test)]
mod chain_claim_stuck_projection_tests {
    use super::chain_claim_stuck_projection_allowed;

    #[test]
    fn projection_requires_current_stuck_unsettled_obligation() {
        for attempt in [None, Some("constructed"), Some("broadcast_ambiguous")] {
            assert!(chain_claim_stuck_projection_allowed("claim_stuck", attempt));
        }
        for attempt in [Some("confirmed"), Some("finalized")] {
            assert!(!chain_claim_stuck_projection_allowed(
                "claim_stuck",
                attempt
            ));
        }
        for parent in ["claiming", "claim_failed", "claimed", "refunded"] {
            assert!(!chain_claim_stuck_projection_allowed(parent, None));
        }
    }
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
    let mut tx = pool.begin().await?;
    let invoice_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT invoice_id FROM swap_records WHERE id = $1 AND invoice_id IS NOT NULL",
    )
    .bind(swap_id)
    .fetch_optional(&mut *tx)
    .await?
    .flatten();
    let Some(invoice_id) = invoice_id else {
        tx.commit().await?;
        return Ok(0);
    };
    lock_invoice_lightning_projection(&mut tx, invoice_id).await?;
    let rows = sqlx::query(
        "UPDATE invoices i SET \
             settlement_status = CASE \
                 WHEN $2 IN ('claim_stuck', 'failed', 'refunded') THEN $2 \
                 WHEN i.direct_settlement_status = 'resolution_pending' \
                     THEN 'resolution_pending' \
                 WHEN i.direct_settlement_status = 'pending' OR $2 = 'pending' THEN 'pending' \
                 WHEN i.direct_settlement_status = 'settled' OR $2 = 'settled' THEN 'settled' \
                 ELSE 'none' END, \
             swap_settlement_status = $2 \
         FROM swap_records s \
         WHERE s.id = $1 \
           AND s.invoice_id = i.id \
           AND i.status NOT IN ('expired', 'cancelled')",
    )
    .bind(swap_id)
    .bind(settlement_status)
    .execute(&mut *tx)
    .await
    .map(|result| result.rows_affected())?;
    tx.commit().await?;
    Ok(rows)
}

/// Cancel an invoice only while every server-owned projection proves that it
/// is fresh and unpaid (recipient-initiated via signed `invoice-cancel`).
/// Idempotent: re-call on a row that's already non-cancellable returns 0 rows
/// affected. Caller verifies the Schnorr
/// signature AND that the invoice's nym maps to the verifying npub
/// upstream — this fn does not re-check ownership.
pub async fn cancel_invoice(pool: &PgPool, id: Uuid) -> Result<(u64, String), sqlx::Error> {
    let mut tx = pool.begin().await?;
    lock_invoice_lightning_projection(&mut tx, id).await?;
    let result = sqlx::query(
        "UPDATE invoices SET status = 'cancelled', cancelled_at = NOW() \
         WHERE id = $1 \
           AND status = 'unpaid' \
           AND presentation_status = 'unpaid' \
           AND settlement_status = 'none'",
    )
    .bind(id)
    .execute(&mut *tx)
    .await?;
    let rows = result.rows_affected();
    if rows == 1 {
        tx.commit().await?;
        return Ok((rows, "cancelled".to_string()));
    }
    let status = sqlx::query_scalar::<_, String>("SELECT status FROM invoices WHERE id = $1")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok((rows, status))
}

/// Background sweep: close invoices past their outer deadline only when the
/// server-owned projections prove that no payment or settlement is pending.
/// Idempotent (set-based UPDATE; predicate excludes already-terminal rows).
/// Run from `gc.rs` on the periodic GC cycle.
///
/// `in_progress` is included because a payer may broadcast a tx that
/// makes it to mempool (flipping the row to in_progress) but never
/// confirms (RBF replaced, mempool eviction, low-fee drop). Such a row becomes
/// expiry-eligible only after the watcher clears its settlement projection.
/// A concurrent watcher update conflicts on the invoice row; PostgreSQL then
/// rechecks this predicate against the committed projection before updating.
/// Backed by the partial index `invoices_unpaid_or_inprog_expiry_idx`
/// (migration 021).
pub async fn expire_invoices_past_deadline(
    pool: &PgPool,
    payment_grace_secs: u64,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE invoices SET status = CASE \
            WHEN status = 'partially_paid' THEN 'underpaid' \
            ELSE 'expired' \
         END \
         WHERE expires_at < NOW() - ($1 || ' seconds')::interval \
           AND ( \
             ( \
               status IN ('unpaid', 'in_progress') \
               AND presentation_status = 'unpaid' \
               AND settlement_status = 'none' \
             ) \
             OR ( \
               status = 'partially_paid' \
               AND settlement_status IN ('none', 'settled') \
             ) \
           )",
    )
    .bind(payment_grace_secs as i64)
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
               AND e.accounting_state IN ('active', 'legacy_unverified') \
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
                 AND e.accounting_state IN ('active', 'legacy_unverified') \
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
/// run before insert. Use this variant only for a flow whose availability is
/// deliberately coupled to the Lightning Address.
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
    allocate_next_liquid_for_nym_availability(pool, nym, false, derive_address).await
}

/// Compatibility allocator for a Payment Page that predates page-specific
/// descriptors. Permanent ownership, not Lightning Address availability,
/// authorizes this cursor: taking the LA offline must not take Page checkout
/// offline. New Page/POS rows should use their own donation_pages descriptor.
pub async fn allocate_next_liquid_for_permanent_nym<F>(
    pool: &PgPool,
    nym: &str,
    derive_address: F,
) -> Result<Option<(String, i32)>, sqlx::Error>
where
    F: Fn(&str, u32) -> Result<String, sqlx::Error>,
{
    allocate_next_liquid_for_nym_availability(pool, nym, true, derive_address).await
}

async fn allocate_next_liquid_for_nym_availability<F>(
    pool: &PgPool,
    nym: &str,
    allow_offline: bool,
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
        "SELECT ct_descriptor, next_addr_idx \
           FROM users \
          WHERE nym = $1 AND (is_active = TRUE OR $2)",
    )
    .bind(nym)
    .bind(allow_offline)
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

/// Read the most recent BOLT11 for an invoice only while that newest reverse
/// swap is still pending. A terminal newest row deliberately returns `None`;
/// filtering pending rows before ordering would incorrectly resurrect an older
/// offer after the provider terminalized its replacement.
///
/// Service path: the status endpoint surfaces this so the page can render
/// a fresh QR after a rate refresh creates a new swap.
pub async fn latest_lightning_pr_for_invoice<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    invoice_id: Uuid,
) -> Result<Option<(String, i64)>, sqlx::Error> {
    let row: Option<(String, i64)> = sqlx::query_as(
        "SELECT invoice, amount_sat FROM ( \
             SELECT invoice, amount_sat, status \
             FROM swap_records \
             WHERE invoice_id = $1 \
             ORDER BY created_at DESC, id DESC \
             LIMIT 1 \
         ) latest \
         WHERE status = 'pending'",
    )
    .bind(invoice_id)
    .fetch_optional(executor)
    .await?;
    Ok(row)
}

#[cfg(test)]
mod status_tests {
    use super::{
        invoice_payment_tolerance_sat, liquid_watcher_lane_sql,
        resolve_invoice_presentation_status, resolve_invoice_status, truncate_to_watcher_batch,
        InvoiceAccountingTolerances, WatcherScanCursor, WatcherScanEpoch,
        LIQUID_WATCHER_BATCH_SIZE, LIQUID_WATCHER_LANE_LAG_SQL, LIQUID_WATCHER_LANE_PAGE_SQL,
        LIQUID_WATCHER_PAGE_SQL, LIQUID_WATCHER_RECENT_PREDICATE_SQL,
    };
    use uuid::Uuid;

    // amount 100_000; btc tolerance 300, liquid tolerance 60 (illustrative).
    const AMT: i64 = 100_000;

    #[test]
    fn mixed_invoice_enforcement_matches_the_advertised_minimum() {
        let tolerances = InvoiceAccountingTolerances::default();
        let advertised = invoice_payment_tolerance_sat(AMT, true, true, true, tolerances);

        assert_eq!(advertised, 1);
        assert_eq!(
            resolve_invoice_status("unpaid", AMT, 99_750, advertised, false),
            "partially_paid",
            "a Bitcoin event must not widen the mixed invoice's public tolerance"
        );
        assert_eq!(
            resolve_invoice_presentation_status(
                "unpaid",
                AMT,
                &[("bitcoin".to_string(), 99_750)],
                advertised,
            ),
            "partial",
            "presentation and accounting must share the public tolerance"
        );
        assert_eq!(
            resolve_invoice_status("unpaid", AMT, 99_999, advertised, false),
            "paid",
            "the exact advertised boundary must remain payable"
        );
        assert_eq!(
            resolve_invoice_presentation_status(
                "unpaid",
                AMT,
                &[("bitcoin".to_string(), 99_999)],
                advertised,
            ),
            "payment_received"
        );
        assert_eq!(
            resolve_invoice_status("paid", AMT, 99_750, advertised, false),
            "paid",
            "the corrected tolerance must preserve durable paid stickiness"
        );
        assert_eq!(
            resolve_invoice_presentation_status(
                "paid",
                AMT,
                &[("bitcoin".to_string(), 99_750)],
                advertised,
            ),
            "payment_received",
            "a legacy paid invoice must not visually regress during rollout"
        );
    }

    fn recent_liquid_lane_facts(
        age_new: bool,
        presentation_status: &str,
        direct_settlement_status: &str,
    ) -> bool {
        age_new
            || presentation_status == "partial"
            || matches!(direct_settlement_status, "pending" | "resolution_pending")
    }

    #[test]
    fn liquid_watcher_expiry_membership_is_frozen_at_the_scan_epoch() {
        assert!(LIQUID_WATCHER_PAGE_SQL
            .contains("expires_at + ($1 || ' seconds')::interval > $2::timestamptz"));
        assert!(!LIQUID_WATCHER_PAGE_SQL.contains("NOW()"));
    }

    #[test]
    fn liquid_watcher_keeps_all_live_direct_evidence_in_cohort() {
        assert!(LIQUID_WATCHER_PAGE_SQL.contains("OR status IN ('cancelled', 'expired')"));
        assert!(!LIQUID_WATCHER_PAGE_SQL.contains("status NOT IN ('cancelled', 'expired')"));
        assert!(LIQUID_WATCHER_PAGE_SQL
            .contains("direct_settlement_status IN ('pending', 'resolution_pending')"));
        assert!(LIQUID_WATCHER_PAGE_SQL.contains("direct_observation.source = 'liquid_direct'"));
        assert!(
            LIQUID_WATCHER_PAGE_SQL.contains("direct_observation.last_seen_state <> 'superseded'")
        );
        assert!(LIQUID_WATCHER_PAGE_SQL.contains("direct_event.source = 'liquid_direct'"));
        assert!(LIQUID_WATCHER_PAGE_SQL.contains("direct_event.accounting_state <> 'superseded'"));
        assert!(LIQUID_WATCHER_PAGE_SQL.contains("direct_event.superseded_by_event_id IS NULL"));
    }

    #[test]
    fn liquid_invoice_lanes_share_one_priority_predicate_and_exact_negation() {
        let recent_page = liquid_watcher_lane_sql(LIQUID_WATCHER_LANE_PAGE_SQL, true);
        let historical_page = liquid_watcher_lane_sql(LIQUID_WATCHER_LANE_PAGE_SQL, false);
        let recent_lag = liquid_watcher_lane_sql(LIQUID_WATCHER_LANE_LAG_SQL, true);
        let historical_lag = liquid_watcher_lane_sql(LIQUID_WATCHER_LANE_LAG_SQL, false);

        for sql in [&recent_page, &recent_lag] {
            assert!(sql.contains(LIQUID_WATCHER_RECENT_PREDICATE_SQL));
            assert!(!sql.contains(&format!("NOT {LIQUID_WATCHER_RECENT_PREDICATE_SQL}")));
            assert!(!sql.contains("{eligible}"));
            assert!(!sql.contains("{lane_predicate}"));
        }
        for sql in [&historical_page, &historical_lag] {
            assert!(sql.contains(&format!("NOT {LIQUID_WATCHER_RECENT_PREDICATE_SQL}")));
            assert!(!sql.contains("{eligible}"));
            assert!(!sql.contains("{lane_predicate}"));
        }
    }

    #[test]
    fn old_partial_or_settling_liquid_targets_stay_recent() {
        assert!(LIQUID_WATCHER_RECENT_PREDICATE_SQL.contains("presentation_status = 'partial'"));
        assert!(LIQUID_WATCHER_RECENT_PREDICATE_SQL
            .contains("direct_settlement_status IN ('pending', 'resolution_pending')"));
        assert!(LIQUID_WATCHER_RECENT_PREDICATE_SQL.contains("created_at >"));
        assert!(!LIQUID_WATCHER_RECENT_PREDICATE_SQL.contains("status = 'partially_paid'"));

        let historical = liquid_watcher_lane_sql(LIQUID_WATCHER_LANE_PAGE_SQL, false);
        assert!(historical.contains("OR status IN ('cancelled', 'expired')"));
        assert!(historical.contains(&format!("NOT {LIQUID_WATCHER_RECENT_PREDICATE_SQL}")));

        assert!(recent_liquid_lane_facts(false, "partial", "none"));
        assert!(recent_liquid_lane_facts(false, "unpaid", "pending"));
        assert!(recent_liquid_lane_facts(
            false,
            "payment_received",
            "resolution_pending"
        ));
        assert!(recent_liquid_lane_facts(true, "unpaid", "none"));

        // Old cancelled/expired rows remain in the eligible cohort above, but
        // without partial or settling evidence they are the exact complement.
        assert!(!recent_liquid_lane_facts(false, "unpaid", "none"));
    }

    #[test]
    fn within_tolerance_is_paid() {
        assert_eq!(
            resolve_invoice_status("unpaid", AMT, 99_750, 300, false),
            "paid"
        );
    }

    #[test]
    fn overpaid_when_exceeding_amount() {
        assert_eq!(
            resolve_invoice_status("paid", AMT, 100_500, 60, false),
            "overpaid"
        );
    }

    #[test]
    fn partial_when_short_beyond_tolerance() {
        assert_eq!(
            resolve_invoice_status("unpaid", AMT, 90_000, 300, false),
            "partially_paid"
        );
    }

    #[test]
    fn expired_short_is_underpaid() {
        assert_eq!(
            resolve_invoice_status("unpaid", AMT, 90_000, 300, true),
            "underpaid"
        );
    }

    // The R2 regression: a settled invoice must not un-pay when active evidence
    // or the applicable tolerance contract becomes stricter. This also keeps
    // rollout compatible with invoices accepted under the historical
    // rail-local tolerance.
    #[test]
    fn settled_paid_does_not_regress_when_the_threshold_tightens() {
        assert_eq!(
            resolve_invoice_status("paid", AMT, 99_900, 1, false),
            "paid"
        );
    }

    #[test]
    fn settled_overpaid_does_not_regress() {
        // A cross-rail prune lowered the sum back under amount, recompute would
        // be partially_paid, but an overpaid invoice stays settled.
        assert_eq!(
            resolve_invoice_status("overpaid", AMT, 99_000, 60, false),
            "overpaid"
        );
    }

    #[test]
    fn settled_paid_stays_paid_even_when_expired() {
        // Expiry must not un-settle an already-paid invoice.
        assert_eq!(
            resolve_invoice_status("paid", AMT, 99_900, 60, true),
            "paid"
        );
    }

    #[test]
    fn underpaid_stays_underpaid_when_still_short() {
        assert_eq!(
            resolve_invoice_status("underpaid", AMT, 95_000, 300, false),
            "underpaid"
        );
    }

    #[test]
    fn liquid_watcher_batch_detects_only_the_sentinel_boundary() {
        for (fetched, expected_more) in [
            (LIQUID_WATCHER_BATCH_SIZE - 1, false),
            (LIQUID_WATCHER_BATCH_SIZE, false),
            (LIQUID_WATCHER_BATCH_SIZE + 1, true),
        ] {
            let mut rows = vec![(); fetched];
            assert_eq!(
                truncate_to_watcher_batch(&mut rows, LIQUID_WATCHER_BATCH_SIZE),
                expected_more,
                "unexpected has_more for {fetched} fetched rows"
            );
            assert_eq!(rows.len(), fetched.min(LIQUID_WATCHER_BATCH_SIZE));
        }
    }

    #[test]
    fn watcher_epoch_keeps_snapshot_across_pages_and_resets_only_on_finish() {
        let mut epoch = WatcherScanEpoch::default();
        epoch.begin("2026-07-12 12:00:00+00".to_string());
        let first = WatcherScanCursor {
            created_at: "2026-07-12 11:00:00+00".to_string(),
            id: Uuid::from_u128(1),
        };
        epoch.advance(first.clone());

        // Starting the next page cannot move the epoch cutoff. Rows created
        // after the original PostgreSQL snapshot wait for the next epoch.
        epoch.begin("2026-07-12 13:00:00+00".to_string());
        assert_eq!(epoch.snapshot(), Some("2026-07-12 12:00:00+00"));
        assert_eq!(epoch.cursor(), Some(&first));

        let second = WatcherScanCursor {
            created_at: "2026-07-12 11:30:00+00".to_string(),
            id: Uuid::from_u128(2),
        };
        epoch.advance(second.clone());
        assert_eq!(epoch.cursor(), Some(&second));

        epoch.finish();
        assert!(epoch.snapshot().is_none());
        assert!(epoch.cursor().is_none());
    }

    #[test]
    fn failed_page_leaves_epoch_cursor_on_last_proven_row() {
        let mut epoch = WatcherScanEpoch::default();
        epoch.begin("2026-07-12 12:00:00+00".to_string());
        let proven = WatcherScanCursor {
            created_at: "2026-07-12 11:00:00+00".to_string(),
            id: Uuid::from_u128(10),
        };
        epoch.advance(proven.clone());

        // A failed row deliberately performs no `advance`; the next page
        // therefore starts immediately after the last proven row and retries
        // the failure instead of skipping past it.
        assert_eq!(epoch.cursor(), Some(&proven));
        assert_eq!(epoch.snapshot(), Some("2026-07-12 12:00:00+00"));
    }
}
