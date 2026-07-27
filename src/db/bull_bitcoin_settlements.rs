use sqlx::{Connection, FromRow, PgConnection, PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::bull_bitcoin::{EncryptedCredential, OrderObservation};

use super::fiat_settlement::{lock_owner, require_active_identity};

#[derive(Debug)]
pub enum BullBitcoinSettlementStoreError {
    SourceIdentityNotActive,
    CredentialUnavailable,
    RequestKeyConflict,
    IllegalState,
    Sqlx(sqlx::Error),
}

impl From<sqlx::Error> for BullBitcoinSettlementStoreError {
    fn from(error: sqlx::Error) -> Self {
        Self::Sqlx(error)
    }
}

#[derive(Clone, Debug)]
pub struct NewBullBitcoinSettlement<'a> {
    pub owner_npub: &'a str,
    pub invoice_id: Option<Uuid>,
    pub invoice_quote_version_id: Option<Uuid>,
    pub reverse_swap_id: Option<Uuid>,
    pub chain_swap_id: Option<Uuid>,
    pub credential_id: Uuid,
    pub product: &'a str,
    pub purpose: &'a str,
    pub payer_rail: &'a str,
    pub request_key: &'a str,
    pub fiat_percentage: i16,
    pub fiat_currency: &'a str,
    pub requested_bitcoin_sat: i64,
    pub expected_instruction_script_len: Option<i32>,
}

#[derive(Clone, Debug, PartialEq, Eq, FromRow)]
pub struct StoredBullBitcoinSettlement {
    pub id: Uuid,
    pub owner_npub: String,
    pub invoice_id: Option<Uuid>,
    pub invoice_quote_version_id: Option<Uuid>,
    pub reverse_swap_id: Option<Uuid>,
    pub chain_swap_id: Option<Uuid>,
    pub credential_id: Uuid,
    pub product: String,
    pub purpose: String,
    pub payer_rail: String,
    pub request_key: String,
    pub fiat_percentage: i16,
    pub fiat_currency: String,
    pub provider_state: String,
    pub funding_route: Option<String>,
    pub fallback_category: Option<String>,
    pub settlement_status: String,
    pub requested_bitcoin_sat: i64,
    pub bull_bitcoin_order_id: Option<Uuid>,
    pub order_correlation_source: Option<String>,
    pub order_correlated_at_unix_micros: Option<i64>,
    pub expected_instruction_script_len: Option<i32>,
    pub instruction_kind: Option<String>,
    pub payer_instruction: Option<String>,
    pub instruction_expires_at_unix: Option<i64>,
    pub funding_committed_at_unix: Option<i64>,
    pub retention_until_unix: Option<i64>,
    pub reconcile_attempts: i32,
    pub actual_received_sat: Option<i64>,
    pub quote_payment_first_observed_at_unix_micros: Option<i64>,
    pub credited_fiat_minor: Option<i64>,
    pub quoted_fiat_minor: Option<i64>,
    pub execution_rate_minor_per_btc: Option<i64>,
    pub provider_final: bool,
    pub provider_last_read_error_class: Option<String>,
    pub provider_last_read_error_at_unix_micros: Option<i64>,
    pub provider_last_success_at_unix_micros: Option<i64>,
    pub provider_not_found_first_at_unix_micros: Option<i64>,
    pub provider_not_found_consecutive: i32,
    pub provider_missing_since_unix_micros: Option<i64>,
    pub provider_missing_last_resolved_at_unix_micros: Option<i64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderNotFoundOutcome {
    pub consecutive: i32,
    pub escalated_now: bool,
    pub persistent_missing: bool,
    pub financial_evidence_present: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredEncryptedCredential {
    pub id: Uuid,
    pub owner_npub: String,
    pub encrypted: EncryptedCredential,
}

#[derive(Clone, Debug, PartialEq, Eq, FromRow)]
pub struct SwapFiatSettlementPolicy {
    pub reverse_swap_id: Option<Uuid>,
    pub chain_swap_id: Option<Uuid>,
    pub invoice_id: Option<Uuid>,
    pub owner_npub: String,
    pub credential_id: Uuid,
    pub product: String,
    pub fiat_percentage: i16,
    pub fiat_currency: String,
}

#[derive(Clone, Debug, PartialEq, Eq, FromRow)]
pub struct ActiveFiatSettlementSetting {
    pub owner_npub: String,
    pub credential_id: Uuid,
    pub fiat_percentage: i16,
    pub fiat_currency: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewBullBitcoinClaimOutput<'a> {
    pub role: &'a str,
    pub txid: &'a str,
    pub vout: i16,
    pub script_pubkey_hex: &'a str,
    pub authorized_amount_sat: i64,
    pub asset_commitment_sha256: &'a str,
    pub value_commitment_sha256: &'a str,
    pub nonce_commitment_sha256: &'a str,
    pub surjection_proof_sha256: &'a str,
    pub rangeproof_sha256: &'a str,
}

#[derive(Clone, Debug, PartialEq, Eq, FromRow)]
pub struct StoredBullBitcoinClaimOutput {
    pub settlement_id: Uuid,
    pub role: String,
    pub txid: String,
    pub vout: i16,
    pub script_pubkey_hex: String,
    pub authorized_amount_sat: i64,
    pub asset_commitment_sha256: String,
    pub value_commitment_sha256: String,
    pub nonce_commitment_sha256: String,
    pub surjection_proof_sha256: String,
    pub rangeproof_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReverseMixedSettlementAccounting {
    pub settlement_id: Uuid,
    pub invoice_id: Option<Uuid>,
    pub claim_txid: String,
    pub merchant_amount_sat: i64,
    pub bull_bitcoin_amount_sat: i64,
}

#[derive(FromRow)]
struct ReverseMixedSettlementAccountingRow {
    settlement_id: Uuid,
    invoice_id: Option<Uuid>,
    provider_state: String,
    funding_route: Option<String>,
    funding_committed: bool,
    merchant_txid: Option<String>,
    merchant_amount_sat: Option<i64>,
    bull_bitcoin_txid: Option<String>,
    bull_bitcoin_amount_sat: Option<i64>,
}

/// Privacy-minimal, local-only projection for the signed merchant invoice
/// list. It deliberately excludes payer instructions, transaction identifiers,
/// account identity, and raw provider state. It includes only the immutable
/// invoice reference rate and provider-final execution rate needed for the
/// merchant accounting contract.
#[derive(Clone, Debug, PartialEq, Eq, FromRow)]
pub struct InvoiceBullBitcoinSettlementProjection {
    pub invoice_id: Uuid,
    pub purpose: String,
    pub bull_bitcoin_order_id: Option<Uuid>,
    pub fiat_currency: String,
    pub settlement_status: String,
    pub creation_rate_minor_per_btc: Option<i64>,
    pub creation_rate_currency: Option<String>,
    pub credited_fiat_minor: Option<i64>,
    pub quoted_fiat_minor: Option<i64>,
    pub execution_rate_minor_per_btc: Option<i64>,
    pub fiat_percentage: Option<i16>,
    pub funding_route: Option<String>,
    pub fallback_category: Option<String>,
    pub merchant_bitcoin_sat: Option<i64>,
    pub merchant_bitcoin_settled: bool,
}

/// Privacy-minimal local projection for the signed Lightning Address
/// settlement list. It intentionally omits payer instructions, payer rails,
/// requested/received Bitcoin amounts, provider state, transaction IDs,
/// account identity, and credential references.
#[derive(Clone, Debug, PartialEq, Eq, FromRow)]
pub struct LightningAddressBullBitcoinSettlementProjection {
    pub purpose: String,
    pub bull_bitcoin_order_id: Option<Uuid>,
    pub fiat_currency: String,
    pub settlement_status: String,
    pub credited_fiat_minor: Option<i64>,
    pub funding_route: Option<String>,
    pub fallback_category: Option<String>,
    pub merchant_bitcoin_sat: Option<i64>,
    pub merchant_bitcoin_settled: bool,
}

const SETTLEMENT_PROJECTION: &str =
    "id, owner_npub, invoice_id, invoice_quote_version_id, reverse_swap_id, chain_swap_id, \
     credential_id, product, purpose, payer_rail, \
     request_key, fiat_percentage, fiat_currency, provider_state, \
     funding_route, fallback_category, settlement_status, requested_bitcoin_sat, \
     bull_bitcoin_order_id, order_correlation_source, \
     (EXTRACT(EPOCH FROM order_correlated_at) * 1000000)::BIGINT \
         AS order_correlated_at_unix_micros, \
     expected_instruction_script_len, \
     instruction_kind, payer_instruction, \
     extract(epoch FROM instruction_expires_at)::BIGINT AS instruction_expires_at_unix, \
     extract(epoch FROM funding_committed_at)::BIGINT AS funding_committed_at_unix, \
     extract(epoch FROM retention_until)::BIGINT AS retention_until_unix, reconcile_attempts, \
     actual_received_sat, \
     (EXTRACT(EPOCH FROM quote_payment_first_observed_at) * 1000000)::BIGINT \
         AS quote_payment_first_observed_at_unix_micros, \
     credited_fiat_minor, quoted_fiat_minor, \
     execution_rate_minor_per_btc, provider_final, \
     provider_last_read_error_class, \
     (EXTRACT(EPOCH FROM provider_last_read_error_at) * 1000000)::BIGINT \
         AS provider_last_read_error_at_unix_micros, \
     (EXTRACT(EPOCH FROM provider_last_success_at) * 1000000)::BIGINT \
         AS provider_last_success_at_unix_micros, \
     (EXTRACT(EPOCH FROM provider_not_found_first_at) * 1000000)::BIGINT \
         AS provider_not_found_first_at_unix_micros, \
     provider_not_found_consecutive, \
     (EXTRACT(EPOCH FROM provider_missing_since) * 1000000)::BIGINT \
         AS provider_missing_since_unix_micros, \
     (EXTRACT(EPOCH FROM provider_missing_last_resolved_at) * 1000000)::BIGINT \
         AS provider_missing_last_resolved_at_unix_micros";

/// Copy an invoice's immutable mixed policy onto the reverse swap in the same
/// transaction that makes the Boltz obligation durable. A 0%/100% policy does
/// not create a mixed-swap row.
pub async fn capture_invoice_reverse_mixed_policy(
    tx: &mut Transaction<'_, Postgres>,
    reverse_swap_id: Uuid,
    invoice_id: Uuid,
    mixed_claim_fee_budget_sat: Option<i64>,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "INSERT INTO swap_fiat_settlement_policies ( \
             reverse_swap_id, owner_npub, credential_id, product, \
             fiat_percentage, fiat_currency \
         ) \
         SELECT $1, policy.owner_npub, policy.credential_id, policy.product, \
                policy.fiat_percentage, policy.fiat_currency \
           FROM invoice_fiat_settlement_policies policy \
          WHERE policy.invoice_id = $2 \
            AND policy.fiat_percentage BETWEEN 1 AND 99",
    )
    .bind(reverse_swap_id)
    .bind(invoice_id)
    .execute(&mut **tx)
    .await?;
    if result.rows_affected() == 0 {
        return Ok(false);
    }
    // Historical/manual fixtures predate the funded claim authority. They may
    // still capture the immutable split policy with NULL authority so their
    // existing dynamic claim behavior remains recoverable. Every newly
    // payer-exposed mixed offer passes Some below.
    let Some(budget) = mixed_claim_fee_budget_sat else {
        return Ok(true);
    };
    if budget <= 0 {
        return Err(sqlx::Error::Protocol(
            "mixed reverse policy has an invalid funded claim budget".into(),
        ));
    }
    let authority = sqlx::query(
        "UPDATE swap_records \
            SET mixed_claim_path = 'script', mixed_claim_fee_budget_sat = $2 \
          WHERE (id = $1 AND mixed_claim_path IS NULL \
            AND mixed_claim_fee_budget_sat IS NULL) \
             OR (id = $1 AND mixed_claim_path = 'script' \
            AND mixed_claim_fee_budget_sat = $2)",
    )
    .bind(reverse_swap_id)
    .bind(budget)
    .execute(&mut **tx)
    .await?;
    if authority.rows_affected() != 1 {
        return Err(sqlx::Error::Protocol(
            "mixed reverse policy could not bind its claim authority".into(),
        ));
    }
    Ok(true)
}

/// Chain-swap counterpart to [`capture_invoice_reverse_mixed_policy`].
pub async fn capture_invoice_chain_mixed_policy(
    tx: &mut Transaction<'_, Postgres>,
    chain_swap_id: Uuid,
    invoice_id: Uuid,
    mixed_claim_fee_budget_sat: Option<i64>,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "INSERT INTO swap_fiat_settlement_policies ( \
             chain_swap_id, owner_npub, credential_id, product, \
             fiat_percentage, fiat_currency \
         ) \
         SELECT $1, policy.owner_npub, policy.credential_id, policy.product, \
                policy.fiat_percentage, policy.fiat_currency \
           FROM invoice_fiat_settlement_policies policy \
          WHERE policy.invoice_id = $2 \
            AND policy.fiat_percentage BETWEEN 1 AND 99",
    )
    .bind(chain_swap_id)
    .bind(invoice_id)
    .execute(&mut **tx)
    .await?;
    if result.rows_affected() == 0 {
        return Ok(false);
    }
    let Some(budget) = mixed_claim_fee_budget_sat else {
        return Ok(true);
    };
    if budget <= 0 {
        return Err(sqlx::Error::Protocol(
            "mixed chain policy has an invalid funded claim budget".into(),
        ));
    }
    let authority = sqlx::query(
        "UPDATE chain_swap_records \
            SET mixed_claim_path = 'script', mixed_claim_fee_budget_sat = $2 \
          WHERE (id = $1 AND mixed_claim_path IS NULL \
            AND mixed_claim_fee_budget_sat IS NULL) \
             OR (id = $1 AND mixed_claim_path = 'script' \
            AND mixed_claim_fee_budget_sat = $2)",
    )
    .bind(chain_swap_id)
    .bind(budget)
    .execute(&mut **tx)
    .await?;
    if authority.rows_affected() != 1 {
        return Err(sqlx::Error::Protocol(
            "mixed chain policy could not bind its claim authority".into(),
        ));
    }
    Ok(true)
}

/// Capture the current Lightning Address mixed policy after a Boltz response
/// and before its BOLT11 is exposed. The owner lock serializes this snapshot
/// with mobile setting changes and credential deletion.
pub async fn active_lightning_address_fiat_setting(
    pool: &PgPool,
    nym: &str,
) -> Result<Option<ActiveFiatSettlementSetting>, sqlx::Error> {
    sqlx::query_as(
        "SELECT setting.owner_npub, setting.credential_id, \
                setting.fiat_percentage, setting.fiat_currency \
           FROM users account \
           JOIN fiat_settlement_settings setting \
             ON setting.owner_npub = account.npub \
            AND setting.product = 'lightning_address' \
           JOIN bull_bitcoin_credentials credential \
             ON credential.id = setting.credential_id \
            AND credential.owner_npub = setting.owner_npub \
          WHERE account.nym = $1 AND account.is_active \
            AND credential.admitted_for_new_orders \
            AND credential.ciphertext IS NOT NULL \
            AND credential.nonce IS NOT NULL",
    )
    .bind(nym)
    .fetch_optional(pool)
    .await
}

/// Revalidate the exact setting observed before Boltz I/O and, for any nonzero
/// fiat allocation, capture it onto the newly inserted swap. `None` means the callback
/// observed no fiat policy and requires that to remain true at commit.
pub async fn validate_and_capture_lightning_address_policy(
    tx: &mut Transaction<'_, Postgres>,
    reverse_swap_id: Uuid,
    nym: &str,
    expected: Option<&ActiveFiatSettlementSetting>,
) -> Result<bool, sqlx::Error> {
    let owner_npub = match expected {
        Some(setting) => setting.owner_npub.clone(),
        None => {
            sqlx::query_scalar::<_, String>("SELECT npub FROM users WHERE nym = $1 AND is_active")
                .bind(nym)
                .fetch_one(&mut **tx)
                .await?
        }
    };
    lock_owner(tx, &owner_npub).await?;
    if expected.is_none() {
        let still_absent: bool = sqlx::query_scalar(
            "SELECT NOT EXISTS ( \
                 SELECT 1 FROM fiat_settlement_settings setting \
                  WHERE setting.owner_npub = $1 \
                    AND setting.product = 'lightning_address' \
             ) AND EXISTS ( \
                 SELECT 1 FROM users \
                  WHERE nym = $2 AND npub = $1 AND is_active \
             )",
        )
        .bind(&owner_npub)
        .bind(nym)
        .fetch_one(&mut **tx)
        .await?;
        if !still_absent {
            return Err(sqlx::Error::Protocol(
                "Lightning Address fiat setting changed during offer creation".into(),
            ));
        }
        return Ok(false);
    }
    let expected = expected.ok_or_else(|| {
        sqlx::Error::Protocol("Lightning Address fiat policy disappeared during validation".into())
    })?;
    if !(1..=100).contains(&expected.fiat_percentage) {
        return Err(sqlx::Error::Protocol(
            "only a nonzero Lightning Address fiat policy can bind a Boltz swap".into(),
        ));
    }
    let result = sqlx::query(
        "INSERT INTO swap_fiat_settlement_policies ( \
             reverse_swap_id, owner_npub, credential_id, product, \
             fiat_percentage, fiat_currency \
         ) \
         SELECT $1, setting.owner_npub, setting.credential_id, setting.product, \
                setting.fiat_percentage, setting.fiat_currency \
           FROM fiat_settlement_settings setting \
           JOIN bull_bitcoin_credentials credential \
             ON credential.id = setting.credential_id \
            AND credential.owner_npub = setting.owner_npub \
           JOIN users account \
             ON account.npub = setting.owner_npub \
            AND account.nym = $3 AND account.is_active \
          WHERE setting.owner_npub = $2 \
            AND setting.product = 'lightning_address' \
            AND setting.credential_id = $4 \
            AND setting.fiat_percentage = $5 \
            AND setting.fiat_currency = $6 \
            AND credential.admitted_for_new_orders \
            AND credential.ciphertext IS NOT NULL \
            AND credential.nonce IS NOT NULL",
    )
    .bind(reverse_swap_id)
    .bind(&owner_npub)
    .bind(nym)
    .bind(expected.credential_id)
    .bind(expected.fiat_percentage)
    .bind(&expected.fiat_currency)
    .execute(&mut **tx)
    .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn reverse_swap_fiat_settlement_policy(
    connection: &mut PgConnection,
    reverse_swap_id: Uuid,
) -> Result<Option<SwapFiatSettlementPolicy>, sqlx::Error> {
    sqlx::query_as(
        "SELECT policy.reverse_swap_id, policy.chain_swap_id, swap.invoice_id, \
                policy.owner_npub, policy.credential_id, policy.product, \
                policy.fiat_percentage, policy.fiat_currency \
           FROM swap_fiat_settlement_policies policy \
           JOIN swap_records swap ON swap.id = policy.reverse_swap_id \
          WHERE policy.reverse_swap_id = $1",
    )
    .bind(reverse_swap_id)
    .fetch_optional(connection)
    .await
}

pub async fn chain_swap_fiat_settlement_policy(
    connection: &mut PgConnection,
    chain_swap_id: Uuid,
) -> Result<Option<SwapFiatSettlementPolicy>, sqlx::Error> {
    sqlx::query_as(
        "SELECT policy.reverse_swap_id, policy.chain_swap_id, swap.invoice_id, \
                policy.owner_npub, policy.credential_id, policy.product, \
                policy.fiat_percentage, policy.fiat_currency \
           FROM swap_fiat_settlement_policies policy \
           JOIN chain_swap_records swap ON swap.id = policy.chain_swap_id \
          WHERE policy.chain_swap_id = $1",
    )
    .bind(chain_swap_id)
    .fetch_optional(connection)
    .await
}

pub async fn invoice_bull_bitcoin_settlement_projections<'e, E>(
    executor: E,
    owner_npub: &str,
    invoice_ids: &[Uuid],
) -> Result<Vec<InvoiceBullBitcoinSettlementProjection>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    if invoice_ids.is_empty() {
        return Ok(Vec::new());
    }
    sqlx::query_as(
        "SELECT settlement.invoice_id, settlement.purpose, \
                settlement.bull_bitcoin_order_id, settlement.fiat_currency, \
                settlement.settlement_status, \
                CASE WHEN invoice.pricing_mode = 'fiat_fixed' \
                      AND creation_quote.rate_minor_per_btc > 0 \
                      AND creation_quote.fiat_currency = invoice.fiat_currency \
                     THEN creation_quote.rate_minor_per_btc END \
                    AS creation_rate_minor_per_btc, \
                CASE WHEN invoice.pricing_mode = 'fiat_fixed' \
                      AND creation_quote.rate_minor_per_btc > 0 \
                      AND creation_quote.fiat_currency = invoice.fiat_currency \
                     THEN creation_quote.fiat_currency END \
                    AS creation_rate_currency, \
                settlement.credited_fiat_minor, \
                settlement.quoted_fiat_minor, \
                CASE WHEN settlement.provider_final \
                     THEN settlement.execution_rate_minor_per_btc END \
                    AS execution_rate_minor_per_btc, \
                settlement.fiat_percentage, \
                settlement.funding_route, settlement.fallback_category, \
                merchant.authorized_amount_sat AS merchant_bitcoin_sat, \
                EXISTS ( \
                    SELECT 1 FROM invoice_payment_events event \
                     WHERE event.invoice_id = settlement.invoice_id \
                       AND event.txid = merchant.txid \
                       AND event.amount_sat = merchant.authorized_amount_sat \
                       AND event.source IN ( \
                           'lightning_boltz_reverse', 'bitcoin_boltz_chain' \
                       ) \
                       AND event.accounting_state = 'active' \
                ) AS merchant_bitcoin_settled \
           FROM bull_bitcoin_settlements settlement \
           JOIN invoices invoice ON invoice.id = settlement.invoice_id \
            AND invoice.npub_owner = settlement.owner_npub \
           LEFT JOIN invoice_quote_versions creation_quote \
             ON creation_quote.invoice_id = invoice.id \
            AND creation_quote.version_number = 1 \
           LEFT JOIN bull_bitcoin_claim_outputs merchant \
             ON merchant.settlement_id = settlement.id \
            AND merchant.role = 'merchant' \
          WHERE settlement.owner_npub = $1 AND settlement.invoice_id = ANY($2) \
            AND ( \
                (settlement.provider_state = 'bound' \
                 AND settlement.funding_route = 'bull_bitcoin' \
                 AND settlement.funding_committed_at IS NOT NULL) \
                OR settlement.funding_route = 'bitcoin_fallback' \
            ) \
            AND NOT ( \
                invoice.status IN ('expired', 'cancelled') \
                AND COALESCE(invoice.presentation_status, invoice.status) = 'unpaid' \
                AND settlement.purpose = 'fiat_only' \
                AND settlement.actual_received_sat IS NULL \
                AND NOT settlement.provider_final \
                AND settlement.settlement_status IN ('pending', 'unavailable') \
                AND NOT EXISTS ( \
                    SELECT 1 FROM invoice_payment_events event \
                     WHERE event.invoice_id = invoice.id \
                ) \
            ) \
          ORDER BY settlement.created_at, settlement.id",
    )
    .bind(owner_npub)
    .bind(invoice_ids)
    .fetch_all(executor)
    .await
}

pub async fn lightning_address_bull_bitcoin_settlement_projections<'e, E>(
    executor: E,
    owner_npub: &str,
    offset: i64,
    limit: i64,
) -> Result<Vec<LightningAddressBullBitcoinSettlementProjection>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as(
        "SELECT settlement.purpose, settlement.bull_bitcoin_order_id, \
                settlement.fiat_currency, settlement.settlement_status, \
                settlement.credited_fiat_minor, settlement.funding_route, \
                settlement.fallback_category, \
                merchant.authorized_amount_sat AS merchant_bitcoin_sat, \
                COALESCE(reverse_swap.status = 'claimed' \
                         AND reverse_swap.claim_txid = merchant.txid, FALSE) \
                    AS merchant_bitcoin_settled \
           FROM bull_bitcoin_settlements settlement \
           JOIN users account ON account.npub = settlement.owner_npub \
            AND account.is_active \
           LEFT JOIN bull_bitcoin_claim_outputs merchant \
             ON merchant.settlement_id = settlement.id \
            AND merchant.role = 'merchant' \
           LEFT JOIN swap_records reverse_swap \
             ON reverse_swap.id = settlement.reverse_swap_id \
          WHERE settlement.owner_npub = $1 \
            AND settlement.product = 'lightning_address' \
            AND settlement.invoice_id IS NULL \
            AND ( \
                (settlement.provider_state = 'bound' \
                 AND settlement.funding_route = 'bull_bitcoin' \
                 AND settlement.funding_committed_at IS NOT NULL) \
                OR settlement.funding_route = 'bitcoin_fallback' \
            ) \
          ORDER BY settlement.created_at DESC, settlement.id DESC \
          OFFSET $2 LIMIT $3",
    )
    .bind(owner_npub)
    .bind(offset)
    .bind(limit)
    .fetch_all(executor)
    .await
}

pub async fn reserve_bull_bitcoin_settlement(
    connection: &mut PgConnection,
    settlement: &NewBullBitcoinSettlement<'_>,
) -> Result<StoredBullBitcoinSettlement, BullBitcoinSettlementStoreError> {
    let mut transaction = connection.begin().await?;
    lock_owner(&mut transaction, settlement.owner_npub).await?;
    require_active_identity(&mut transaction, settlement.owner_npub)
        .await
        .map_err(|error| match error {
            super::FiatSettlementStoreError::SourceIdentityNotActive => {
                BullBitcoinSettlementStoreError::SourceIdentityNotActive
            }
            super::FiatSettlementStoreError::Sqlx(error) => {
                BullBitcoinSettlementStoreError::Sqlx(error)
            }
            _ => BullBitcoinSettlementStoreError::CredentialUnavailable,
        })?;

    if let Some(invoice_id) = settlement.invoice_id {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(super::invoice_lightning_lock_key(invoice_id))
            .execute(&mut *transaction)
            .await?;
        if settlement.purpose == "fiat_only" {
            let payment_already_observed: bool = sqlx::query_scalar(
                "SELECT EXISTS ( \
                     SELECT 1 FROM bull_bitcoin_settlements \
                      WHERE invoice_id = $1 AND purpose = 'fiat_only' \
                        AND actual_received_sat IS NOT NULL \
                 )",
            )
            .bind(invoice_id)
            .fetch_one(&mut *transaction)
            .await?;
            if payment_already_observed {
                return Err(BullBitcoinSettlementStoreError::IllegalState);
            }
        }
    }

    let select_sql = format!(
        "SELECT {SETTLEMENT_PROJECTION} FROM bull_bitcoin_settlements \
          WHERE owner_npub = $1 AND request_key = $2"
    );
    if let Some(existing) = sqlx::query_as::<_, StoredBullBitcoinSettlement>(&select_sql)
        .bind(settlement.owner_npub)
        .bind(settlement.request_key)
        .fetch_optional(&mut *transaction)
        .await?
    {
        validate_reservation_identity(&existing, settlement)?;
        transaction.commit().await?;
        return Ok(existing);
    }

    let credential_admitted = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS ( \
             SELECT 1 FROM bull_bitcoin_credentials \
              WHERE id = $1 AND owner_npub = $2 \
                AND admitted_for_new_orders \
                AND ciphertext IS NOT NULL AND nonce IS NOT NULL \
         )",
    )
    .bind(settlement.credential_id)
    .bind(settlement.owner_npub)
    .fetch_one(&mut *transaction)
    .await?;
    if !credential_admitted {
        return Err(BullBitcoinSettlementStoreError::CredentialUnavailable);
    }

    // Lightning Address callbacks do not have an invoice policy to authorize
    // the reservation. Revalidate the exact mobile-selected setting while the
    // owner mutation lock is held, so a concurrent disable/currency change
    // either wins before this intent or happens after its durable reservation.
    if settlement.product == "lightning_address" && settlement.purpose == "fiat_only" {
        let setting_matches = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS ( \
                 SELECT 1 FROM fiat_settlement_settings \
                  WHERE owner_npub = $1 AND product = 'lightning_address' \
                    AND credential_id = $2 AND fiat_percentage = 100 \
                    AND fiat_currency = $3 \
             )",
        )
        .bind(settlement.owner_npub)
        .bind(settlement.credential_id)
        .bind(settlement.fiat_currency)
        .fetch_one(&mut *transaction)
        .await?;
        if !setting_matches {
            return Err(BullBitcoinSettlementStoreError::CredentialUnavailable);
        }
    }

    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO bull_bitcoin_settlements ( \
             id, owner_npub, invoice_id, invoice_quote_version_id, reverse_swap_id, chain_swap_id, \
             credential_id, product, purpose, \
             payer_rail, request_key, fiat_percentage, fiat_currency, \
             requested_bitcoin_sat, expected_instruction_script_len \
         ) VALUES ( \
             $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15 \
         )",
    )
    .bind(id)
    .bind(settlement.owner_npub)
    .bind(settlement.invoice_id)
    .bind(settlement.invoice_quote_version_id)
    .bind(settlement.reverse_swap_id)
    .bind(settlement.chain_swap_id)
    .bind(settlement.credential_id)
    .bind(settlement.product)
    .bind(settlement.purpose)
    .bind(settlement.payer_rail)
    .bind(settlement.request_key)
    .bind(settlement.fiat_percentage)
    .bind(settlement.fiat_currency)
    .bind(settlement.requested_bitcoin_sat)
    .bind(settlement.expected_instruction_script_len)
    .execute(&mut *transaction)
    .await?;

    let stored = sqlx::query_as::<_, StoredBullBitcoinSettlement>(&format!(
        "SELECT {SETTLEMENT_PROJECTION} FROM bull_bitcoin_settlements WHERE id = $1"
    ))
    .bind(id)
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(stored)
}

pub async fn begin_bull_bitcoin_dispatch(
    connection: &mut PgConnection,
    settlement_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE bull_bitcoin_settlements \
            SET provider_state = 'dispatch_started', updated_at = now() \
          WHERE id = $1 AND provider_state = 'reserved' \
            AND funding_route IS NULL",
    )
    .bind(settlement_id)
    .execute(connection)
    .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn load_bull_bitcoin_settlement(
    connection: &mut PgConnection,
    settlement_id: Uuid,
) -> Result<StoredBullBitcoinSettlement, sqlx::Error> {
    sqlx::query_as::<_, StoredBullBitcoinSettlement>(&format!(
        "SELECT {SETTLEMENT_PROJECTION} FROM bull_bitcoin_settlements WHERE id = $1"
    ))
    .bind(settlement_id)
    .fetch_one(connection)
    .await
}

pub async fn load_bull_bitcoin_settlement_by_request_key(
    connection: &mut PgConnection,
    owner_npub: &str,
    request_key: &str,
) -> Result<Option<StoredBullBitcoinSettlement>, sqlx::Error> {
    sqlx::query_as::<_, StoredBullBitcoinSettlement>(&format!(
        "SELECT {SETTLEMENT_PROJECTION} FROM bull_bitcoin_settlements \
          WHERE owner_npub = $1 AND request_key = $2"
    ))
    .bind(owner_npub)
    .bind(request_key)
    .fetch_optional(connection)
    .await
}

pub async fn load_bull_bitcoin_credential(
    connection: &mut PgConnection,
    credential_id: Uuid,
) -> Result<Option<StoredEncryptedCredential>, sqlx::Error> {
    let row = sqlx::query_as::<_, (Uuid, String, Vec<u8>, Vec<u8>, i16)>(
        "SELECT id, owner_npub, ciphertext, nonce, encryption_format \
           FROM bull_bitcoin_credentials \
          WHERE id = $1 AND ciphertext IS NOT NULL AND nonce IS NOT NULL",
    )
    .bind(credential_id)
    .fetch_optional(connection)
    .await?;
    row.map(|(id, owner_npub, ciphertext, nonce, format_version)| {
        let nonce: [u8; 24] = nonce.try_into().map_err(|_| {
            sqlx::Error::Decode("Bull Bitcoin credential nonce has the wrong length".into())
        })?;
        Ok(StoredEncryptedCredential {
            id,
            owner_npub,
            encrypted: EncryptedCredential {
                ciphertext,
                nonce,
                format_version,
            },
        })
    })
    .transpose()
}

#[allow(clippy::too_many_arguments)]
pub async fn bind_bull_bitcoin_order(
    connection: &mut PgConnection,
    settlement_id: Uuid,
    order_id: Uuid,
    instruction_kind: &str,
    payer_instruction: &str,
    instruction_expires_at_unix: Option<i64>,
    retention_secs: i64,
    quoted_fiat_minor: Option<i64>,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE bull_bitcoin_settlements \
            SET provider_state = 'bound', \
                funding_route = CASE WHEN purpose = 'fiat_only' \
                    THEN 'bull_bitcoin' ELSE NULL END, \
                settlement_status = CASE WHEN purpose = 'fiat_only' \
                    THEN 'pending' ELSE 'none' END, \
                funding_committed_at = CASE WHEN purpose = 'fiat_only' \
                    THEN now() ELSE NULL END, \
                bull_bitcoin_order_id = $2, \
                order_correlation_source = COALESCE( \
                    order_correlation_source, 'provider_response'), \
                order_correlated_at = COALESCE(order_correlated_at, clock_timestamp()), \
                instruction_kind = $3, payer_instruction = $4, \
                instruction_expires_at = CASE WHEN $5::BIGINT IS NULL \
                    THEN NULL ELSE to_timestamp($5) END, \
                retention_until = now() + make_interval(secs => $6::DOUBLE PRECISION), \
                quoted_fiat_minor = $7, \
                next_attempt_at = now(), updated_at = now() \
          WHERE id = $1 AND provider_state = 'dispatch_started' \
            AND funding_route IS NULL \
            AND (bull_bitcoin_order_id IS NULL OR bull_bitcoin_order_id = $2)",
    )
    .bind(settlement_id)
    .bind(order_id)
    .bind(instruction_kind)
    .bind(payer_instruction)
    .bind(instruction_expires_at_unix)
    .bind(retention_secs)
    .bind(quoted_fiat_minor)
    .execute(connection)
    .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn abandon_bull_bitcoin_dispatch(
    connection: &mut PgConnection,
    settlement_id: Uuid,
    fallback_category: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE bull_bitcoin_settlements \
            SET provider_state = 'abandoned', \
                funding_route = 'bitcoin_fallback', \
                fallback_category = $2, updated_at = now() \
          WHERE id = $1 AND provider_state IN ('reserved', 'dispatch_started') \
            AND bull_bitcoin_order_id IS NULL",
    )
    .bind(settlement_id)
    .bind(fallback_category)
    .execute(connection)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Retain correlation evidence from an invalid/ambiguous create response
/// without treating that response as a usable provider binding. `None` still
/// marks the durable dispatch as needing reconciliation and never selects a
/// fallback route.
pub async fn record_ambiguous_bull_bitcoin_dispatch(
    connection: &mut PgConnection,
    settlement_id: Uuid,
    candidate_order_id: Option<Uuid>,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE bull_bitcoin_settlements \
            SET bull_bitcoin_order_id = COALESCE(bull_bitcoin_order_id, $2), \
                order_correlation_source = CASE \
                    WHEN bull_bitcoin_order_id IS NULL AND $2::UUID IS NOT NULL \
                    THEN 'provider_response' \
                    ELSE order_correlation_source END, \
                order_correlated_at = CASE \
                    WHEN bull_bitcoin_order_id IS NULL AND $2::UUID IS NOT NULL \
                    THEN clock_timestamp() \
                    ELSE order_correlated_at END, \
                next_attempt_at = now(), updated_at = clock_timestamp() \
          WHERE id = $1 AND provider_state = 'dispatch_started' \
            AND funding_route IS NULL \
            AND (bull_bitcoin_order_id IS NULL \
                 OR bull_bitcoin_order_id IS NOT DISTINCT FROM $2)",
    )
    .bind(settlement_id)
    .bind(candidate_order_id)
    .execute(connection)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// A mixed order may be bound but not yet referenced by claim bytes. In that
/// narrow state no payer-facing Bull Bitcoin destination has been funded, so
/// a minimum/policy/credential failure can still route the whole claim to the
/// merchant wallet without revoking the upstream key or order.
pub async fn route_unfunded_mixed_settlement_to_fallback(
    connection: &mut PgConnection,
    settlement_id: Uuid,
    fallback_category: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE bull_bitcoin_settlements \
            SET funding_route = 'bitcoin_fallback', fallback_category = $2, \
                instruction_kind = NULL, payer_instruction = NULL, \
                instruction_expires_at = NULL, next_attempt_at = NULL, \
                updated_at = now() \
          WHERE id = $1 AND purpose IN ('mixed', 'provider_only') \
            AND provider_state = 'bound' AND funding_route IS NULL \
            AND funding_committed_at IS NULL AND settlement_status = 'none'",
    )
    .bind(settlement_id)
    .bind(fallback_category)
    .execute(connection)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Persist both verified claim outputs and make the upstream order eligible
/// for reconciliation in one transaction. The migration trigger independently
/// checks that the Bull Bitcoin amount equals the order's exact requested sats.
pub async fn commit_mixed_bull_bitcoin_funding(
    tx: &mut Transaction<'_, Postgres>,
    settlement_id: Uuid,
    merchant: &NewBullBitcoinClaimOutput<'_>,
    bull_bitcoin: &NewBullBitcoinClaimOutput<'_>,
) -> Result<(), sqlx::Error> {
    for output in [merchant, bull_bitcoin] {
        sqlx::query(
            "INSERT INTO bull_bitcoin_claim_outputs ( \
                 settlement_id, role, txid, vout, script_pubkey_hex, \
                 authorized_amount_sat, asset_commitment_sha256, \
                 value_commitment_sha256, nonce_commitment_sha256, \
                 surjection_proof_sha256, rangeproof_sha256 \
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        )
        .bind(settlement_id)
        .bind(output.role)
        .bind(output.txid)
        .bind(output.vout)
        .bind(output.script_pubkey_hex)
        .bind(output.authorized_amount_sat)
        .bind(output.asset_commitment_sha256)
        .bind(output.value_commitment_sha256)
        .bind(output.nonce_commitment_sha256)
        .bind(output.surjection_proof_sha256)
        .bind(output.rangeproof_sha256)
        .execute(&mut **tx)
        .await?;
    }
    let updated = sqlx::query(
        "UPDATE bull_bitcoin_settlements \
            SET funding_route = 'bull_bitcoin', funding_committed_at = now(), \
                settlement_status = 'pending', instruction_kind = NULL, \
                payer_instruction = NULL, instruction_expires_at = NULL, \
                next_attempt_at = now(), updated_at = now() \
          WHERE id = $1 AND purpose = 'mixed' \
            AND provider_state = 'bound' AND funding_route IS NULL \
            AND funding_committed_at IS NULL AND settlement_status = 'none'",
    )
    .bind(settlement_id)
    .execute(&mut **tx)
    .await?;
    if updated.rows_affected() != 1 {
        return Err(sqlx::Error::Protocol(
            "mixed Bull Bitcoin funding transition lost its exact row".into(),
        ));
    }
    Ok(())
}

/// Persist the sole provider output for a swap-backed 100%-fiat Lightning
/// Address and make the exact order eligible for reconciliation atomically.
pub async fn commit_provider_only_bull_bitcoin_funding(
    tx: &mut Transaction<'_, Postgres>,
    settlement_id: Uuid,
    bull_bitcoin: &NewBullBitcoinClaimOutput<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO bull_bitcoin_claim_outputs ( \
             settlement_id, role, txid, vout, script_pubkey_hex, \
             authorized_amount_sat, asset_commitment_sha256, \
             value_commitment_sha256, nonce_commitment_sha256, \
             surjection_proof_sha256, rangeproof_sha256 \
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
    )
    .bind(settlement_id)
    .bind(bull_bitcoin.role)
    .bind(bull_bitcoin.txid)
    .bind(bull_bitcoin.vout)
    .bind(bull_bitcoin.script_pubkey_hex)
    .bind(bull_bitcoin.authorized_amount_sat)
    .bind(bull_bitcoin.asset_commitment_sha256)
    .bind(bull_bitcoin.value_commitment_sha256)
    .bind(bull_bitcoin.nonce_commitment_sha256)
    .bind(bull_bitcoin.surjection_proof_sha256)
    .bind(bull_bitcoin.rangeproof_sha256)
    .execute(&mut **tx)
    .await?;
    let updated = sqlx::query(
        "UPDATE bull_bitcoin_settlements \
            SET funding_route = 'bull_bitcoin', funding_committed_at = now(), \
                settlement_status = 'pending', instruction_kind = NULL, \
                payer_instruction = NULL, instruction_expires_at = NULL, \
                next_attempt_at = now(), updated_at = now() \
          WHERE id = $1 AND purpose = 'provider_only' \
            AND provider_state = 'bound' AND funding_route IS NULL \
            AND funding_committed_at IS NULL AND settlement_status = 'none'",
    )
    .bind(settlement_id)
    .execute(&mut **tx)
    .await?;
    if updated.rows_affected() != 1 {
        return Err(sqlx::Error::Protocol(
            "provider-only Bull Bitcoin funding transition lost its exact row".into(),
        ));
    }
    Ok(())
}

pub async fn load_bull_bitcoin_claim_outputs<'e, E>(
    executor: E,
    settlement_id: Uuid,
) -> Result<Vec<StoredBullBitcoinClaimOutput>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as(
        "SELECT settlement_id, role, txid, vout, script_pubkey_hex, \
                authorized_amount_sat, asset_commitment_sha256, \
                value_commitment_sha256, nonce_commitment_sha256, \
                surjection_proof_sha256, rangeproof_sha256 \
           FROM bull_bitcoin_claim_outputs \
          WHERE settlement_id = $1 ORDER BY vout",
    )
    .bind(settlement_id)
    .fetch_all(executor)
    .await
}

/// Resolve the exact two-output accounting authority for a claimed reverse
/// swap. A mixed policy that routed to Bitcoin is intentionally projected as
/// `None`; a funded mixed order with incomplete or inconsistent output evidence
/// is an integrity error and must never fall through to the historical gross
/// swap amount.
pub async fn reverse_mixed_settlement_accounting(
    pool: &PgPool,
    reverse_swap_id: Uuid,
) -> Result<Option<ReverseMixedSettlementAccounting>, sqlx::Error> {
    let row = sqlx::query_as::<_, ReverseMixedSettlementAccountingRow>(
        "SELECT settlement.id AS settlement_id, settlement.invoice_id, \
                settlement.provider_state, settlement.funding_route, \
                settlement.funding_committed_at IS NOT NULL AS funding_committed, \
                merchant.txid AS merchant_txid, \
                merchant.authorized_amount_sat AS merchant_amount_sat, \
                bull_bitcoin.txid AS bull_bitcoin_txid, \
                bull_bitcoin.authorized_amount_sat AS bull_bitcoin_amount_sat \
           FROM bull_bitcoin_settlements settlement \
           LEFT JOIN bull_bitcoin_claim_outputs merchant \
             ON merchant.settlement_id = settlement.id AND merchant.role = 'merchant' \
           LEFT JOIN bull_bitcoin_claim_outputs bull_bitcoin \
             ON bull_bitcoin.settlement_id = settlement.id \
            AND bull_bitcoin.role = 'bull_bitcoin' \
          WHERE settlement.reverse_swap_id = $1 AND settlement.purpose = 'mixed'",
    )
    .bind(reverse_swap_id)
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    if row.funding_route.as_deref() == Some("bitcoin_fallback") {
        if row.funding_committed || row.merchant_txid.is_some() || row.bull_bitcoin_txid.is_some() {
            return Err(sqlx::Error::Protocol(
                "mixed Bitcoin fallback unexpectedly carries funding evidence".into(),
            ));
        }
        return Ok(None);
    }
    if row.provider_state != "bound"
        || row.funding_route.as_deref() != Some("bull_bitcoin")
        || !row.funding_committed
    {
        return Err(sqlx::Error::Protocol(
            "claimed mixed reverse swap has no committed funding authority".into(),
        ));
    }
    let merchant_txid = row.merchant_txid.ok_or_else(|| {
        sqlx::Error::Protocol("mixed reverse settlement lacks merchant output evidence".into())
    })?;
    let bull_bitcoin_txid = row.bull_bitcoin_txid.ok_or_else(|| {
        sqlx::Error::Protocol("mixed reverse settlement lacks Bull Bitcoin output evidence".into())
    })?;
    let merchant_amount_sat = row
        .merchant_amount_sat
        .filter(|amount| *amount > 0)
        .ok_or_else(|| sqlx::Error::Protocol("mixed reverse merchant amount is invalid".into()))?;
    let bull_bitcoin_amount_sat = row
        .bull_bitcoin_amount_sat
        .filter(|amount| *amount > 0)
        .ok_or_else(|| {
            sqlx::Error::Protocol("mixed reverse Bull Bitcoin amount is invalid".into())
        })?;
    if merchant_txid != bull_bitcoin_txid {
        return Err(sqlx::Error::Protocol(
            "mixed reverse outputs reference different claim transactions".into(),
        ));
    }
    Ok(Some(ReverseMixedSettlementAccounting {
        settlement_id: row.settlement_id,
        invoice_id: row.invoice_id,
        claim_txid: merchant_txid,
        merchant_amount_sat,
        bull_bitcoin_amount_sat,
    }))
}

pub async fn claim_ambiguous_bull_bitcoin_dispatches(
    pool: &PgPool,
    stale_after_secs: i64,
    retry_after_secs: i64,
    limit: i64,
) -> Result<Vec<StoredBullBitcoinSettlement>, sqlx::Error> {
    let rows = sqlx::query_scalar::<_, Uuid>(
        "WITH due AS ( \
             SELECT id FROM bull_bitcoin_settlements \
              WHERE provider_state = 'dispatch_started' \
                AND funding_route IS NULL \
                AND (bull_bitcoin_order_id IS NOT NULL \
                     OR updated_at < now() - make_interval(secs => $1::DOUBLE PRECISION)) \
                AND (next_attempt_at IS NULL OR next_attempt_at <= now()) \
              ORDER BY COALESCE(next_attempt_at, updated_at), id \
              FOR UPDATE SKIP LOCKED LIMIT $3 \
         ) \
         UPDATE bull_bitcoin_settlements settlement \
            SET next_attempt_at = now() + \
                    make_interval(secs => $2::DOUBLE PRECISION), \
                last_checked_at = now(), \
                reconcile_attempts = reconcile_attempts + 1, \
                updated_at = now() \
           FROM due WHERE settlement.id = due.id \
         RETURNING settlement.id",
    )
    .bind(stale_after_secs)
    .bind(retry_after_secs)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    sqlx::query_as::<_, StoredBullBitcoinSettlement>(&format!(
        "SELECT {SETTLEMENT_PROJECTION} FROM bull_bitcoin_settlements \
          WHERE id = ANY($1) ORDER BY id"
    ))
    .bind(rows)
    .fetch_all(pool)
    .await
}

pub async fn claim_bull_bitcoin_reconciliation_batch(
    pool: &PgPool,
    limit: i64,
    lease_secs: i64,
) -> Result<Vec<StoredBullBitcoinSettlement>, sqlx::Error> {
    let rows = sqlx::query_scalar::<_, Uuid>(
        "WITH due AS ( \
             SELECT id FROM bull_bitcoin_settlements \
              WHERE provider_state = 'bound' \
                AND funding_route = 'bull_bitcoin' \
                AND funding_committed_at IS NOT NULL \
                AND bull_bitcoin_order_id IS NOT NULL \
                AND ( \
                    (settlement_status = 'pending' \
                     AND (next_attempt_at IS NULL OR next_attempt_at <= now())) \
                    OR (settlement_status = 'integrity_error' \
                        AND provider_missing_since IS NOT NULL \
                        AND (next_attempt_at IS NULL OR next_attempt_at <= now())) \
                    OR (settlement_status = 'settled' AND purpose = 'fiat_only' \
                        AND invoice_id IS NOT NULL \
                        AND NOT EXISTS ( \
                            SELECT 1 FROM invoice_payment_events event \
                             WHERE event.bull_bitcoin_settlement_id = \
                                   bull_bitcoin_settlements.id \
                        )) \
                ) \
              ORDER BY COALESCE(next_attempt_at, created_at), id \
              FOR UPDATE SKIP LOCKED LIMIT $1 \
         ) \
         UPDATE bull_bitcoin_settlements settlement \
            SET next_attempt_at = now() + \
                    make_interval(secs => $2::DOUBLE PRECISION), \
                updated_at = now() \
           FROM due WHERE settlement.id = due.id \
         RETURNING settlement.id",
    )
    .bind(limit)
    .bind(lease_secs)
    .fetch_all(pool)
    .await?;
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    sqlx::query_as::<_, StoredBullBitcoinSettlement>(&format!(
        "SELECT {SETTLEMENT_PROJECTION} FROM bull_bitcoin_settlements \
          WHERE id = ANY($1) ORDER BY id"
    ))
    .bind(rows)
    .fetch_all(pool)
    .await
}

pub async fn record_bull_bitcoin_observation(
    pool: &PgPool,
    settlement_id: Uuid,
    observation: &OrderObservation,
    next_poll_secs: i64,
    late_watch_poll_secs: i64,
    valuation_candidate: Option<&super::NewInvoiceQuoteVersion<'_>>,
) -> Result<(), sqlx::Error> {
    let mut transaction = pool.begin().await?;
    let invoice_id: Option<Uuid> =
        sqlx::query_scalar("SELECT invoice_id FROM bull_bitcoin_settlements WHERE id = $1")
            .bind(settlement_id)
            .fetch_one(&mut *transaction)
            .await?;
    if let Some(invoice_id) = invoice_id {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(super::invoice_lightning_lock_key(invoice_id))
            .execute(&mut *transaction)
            .await?;
    }
    let persisted_observation: Option<(Option<Uuid>, Option<Uuid>, Option<i64>)> = sqlx::query_as(
        "UPDATE bull_bitcoin_settlements \
            SET order_status = $2, payin_status = $3, payout_status = $4, \
                actual_received_sat = COALESCE($5, actual_received_sat), \
                credited_fiat_minor = CASE WHEN $8 THEN NULL ELSE $6 END, \
                quoted_fiat_minor = COALESCE($10, quoted_fiat_minor), \
                execution_rate_minor_per_btc = COALESCE( \
                    $11, execution_rate_minor_per_btc), \
                provider_final = $7, \
                provider_last_read_error_class = NULL, \
                provider_last_read_error_at = NULL, \
                provider_last_success_at = now(), \
                provider_not_found_first_at = NULL, \
                provider_not_found_consecutive = 0, \
                provider_missing_last_resolved_at = CASE \
                    WHEN provider_missing_since IS NOT NULL THEN now() \
                    ELSE provider_missing_last_resolved_at END, \
                provider_missing_since = NULL, \
                settlement_status = CASE \
                    WHEN $7 THEN 'settled' \
                    WHEN $8 THEN 'unavailable' \
                    ELSE 'pending' END, \
                terminal_at = CASE WHEN $7 THEN now() ELSE NULL END, \
                payer_instruction = CASE \
                    WHEN $7 OR $8 OR COALESCE($5, actual_received_sat) IS NOT NULL \
                    THEN NULL ELSE payer_instruction END, \
                instruction_kind = CASE \
                    WHEN $7 OR $8 OR COALESCE($5, actual_received_sat) IS NOT NULL \
                    THEN NULL ELSE instruction_kind END, \
                last_checked_at = now(), reconcile_attempts = 0, \
                next_attempt_at = CASE WHEN $7 OR $8 THEN NULL \
                    ELSE now() + make_interval(secs => (CASE \
                        WHEN purpose = 'fiat_only' \
                         AND COALESCE($5, actual_received_sat) IS NULL \
                         AND invoice_id IS NOT NULL \
                         AND EXISTS ( \
                             SELECT 1 FROM invoices invoice \
                              WHERE invoice.id = bull_bitcoin_settlements.invoice_id \
                                AND invoice.status IN ('expired', 'cancelled') \
                                AND COALESCE(invoice.presentation_status, invoice.status) = 'unpaid' \
                                AND NOT EXISTS ( \
                                    SELECT 1 FROM invoice_payment_events event \
                                     WHERE event.invoice_id = invoice.id \
                                ) \
                         ) THEN GREATEST($9, $12) \
                        ELSE $9 END)::DOUBLE PRECISION) END, \
                updated_at = now() \
          WHERE id = $1 AND provider_state = 'bound' \
            AND funding_route = 'bull_bitcoin' \
            AND (settlement_status = 'pending' \
                 OR (settlement_status = 'integrity_error' \
                     AND provider_missing_since IS NOT NULL)) \
         RETURNING invoice_id, \
                   invoice_quote_version_id AS instruction_quote_version_id, \
                   (EXTRACT(EPOCH FROM quote_payment_first_observed_at) * 1000000)::BIGINT \
                       AS first_observed_at_unix_micros",
    )
    .bind(settlement_id)
    .bind(&observation.order_status)
    .bind(&observation.payin_status)
    .bind(&observation.payout_status)
    .bind(observation.actual_received_sat)
    .bind(
        observation
            .credited_fiat_minor
            .map(|amount| amount.as_minor()),
    )
    .bind(observation.provider_final)
    .bind(observation.provider_terminal)
    .bind(next_poll_secs)
    .bind(
        observation
            .quoted_fiat_minor
            .map(|amount| amount.as_minor()),
    )
    .bind(
        observation
            .execution_rate_minor_per_btc
            .map(|amount| amount.as_minor()),
    )
    .bind(late_watch_poll_secs)
    .fetch_optional(&mut *transaction)
    .await?;
    if let (
        Some(candidate),
        Some((Some(invoice_id), Some(instruction_quote_version_id), Some(first_observed_at))),
    ) = (valuation_candidate, persisted_observation)
    {
        let captured = super::capture_late_observation_candidate_locked(
            &mut transaction,
            super::PersistedInvoiceQuoteObservation {
                invoice_id,
                instruction_quote_version_id,
                first_observed_at_unix_micros: first_observed_at,
            },
            candidate,
        )
        .await?;
        if !captured {
            tracing::warn!(
                event = "invoice_bull_bitcoin_observation_rate_not_covering",
                %settlement_id,
                "Bull Bitcoin funds were recorded without fiat valuation because the pre-fetched rate did not cover the exact first observation"
            );
        }
    }
    transaction.commit().await?;
    Ok(())
}

pub async fn record_bull_bitcoin_retry(
    pool: &PgPool,
    settlement_id: Uuid,
    delay_secs: i64,
    late_watch_poll_secs: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE bull_bitcoin_settlements \
            SET reconcile_attempts = reconcile_attempts + 1, \
                last_checked_at = now(), \
                next_attempt_at = now() + make_interval(secs => (CASE \
                    WHEN purpose = 'fiat_only' \
                     AND actual_received_sat IS NULL \
                     AND invoice_id IS NOT NULL \
                     AND EXISTS ( \
                         SELECT 1 FROM invoices invoice \
                          WHERE invoice.id = bull_bitcoin_settlements.invoice_id \
                            AND invoice.status IN ('expired', 'cancelled') \
                            AND COALESCE(invoice.presentation_status, invoice.status) = 'unpaid' \
                            AND NOT EXISTS ( \
                                SELECT 1 FROM invoice_payment_events event \
                                 WHERE event.invoice_id = invoice.id \
                            ) \
                     ) THEN GREATEST($2, $3) \
                    ELSE $2 END)::DOUBLE PRECISION), \
                updated_at = now() \
          WHERE id = $1 AND settlement_status = 'pending'",
    )
    .bind(settlement_id)
    .bind(delay_secs)
    .bind(late_watch_poll_secs)
    .execute(pool)
    .await?;
    Ok(())
}

/// Persist one authenticated exact-order 404. Escalation requires both the
/// configured consecutive count and elapsed-time thresholds. The immutable
/// provider binding is retained in every outcome; this function never routes,
/// abandons, or replaces an order.
pub async fn record_bull_bitcoin_provider_not_found(
    pool: &PgPool,
    settlement_id: Uuid,
    delay_secs: i64,
    persistent_watch_secs: i64,
    escalation_attempts: i32,
    escalation_secs: i64,
    provider_api_healthy: bool,
) -> Result<ProviderNotFoundOutcome, sqlx::Error> {
    let outcome = sqlx::query_as::<_, (i32, bool, bool, bool)>(
        "WITH target AS ( \
             SELECT settlement.*, \
                    (settlement.actual_received_sat IS NOT NULL \
                     OR (settlement.purpose = 'mixed' \
                         AND settlement.funding_committed_at IS NOT NULL) \
                     OR EXISTS ( \
                         SELECT 1 FROM bull_bitcoin_claim_outputs output \
                          WHERE output.settlement_id = settlement.id \
                     ) \
                     OR EXISTS ( \
                         SELECT 1 FROM invoice_payment_events event \
                          WHERE event.bull_bitcoin_settlement_id = settlement.id \
                     )) AS financial_evidence_present \
               FROM bull_bitcoin_settlements settlement \
              WHERE settlement.id = $1 \
                AND settlement.provider_state = 'bound' \
                AND settlement.funding_route = 'bull_bitcoin' \
                AND (settlement.settlement_status = 'pending' \
                     OR (settlement.settlement_status = 'integrity_error' \
                         AND settlement.provider_missing_since IS NOT NULL)) \
              FOR UPDATE \
         ), decision AS ( \
             SELECT target.*, \
                    CASE WHEN $6 \
                         THEN target.provider_not_found_consecutive + 1 \
                         ELSE 0 END AS next_consecutive, \
                    CASE WHEN $6 \
                         THEN COALESCE(target.provider_not_found_first_at, now()) \
                         ELSE NULL END AS next_first_at, \
                    ($6 \
                     AND target.provider_not_found_consecutive + 1 >= $4 \
                     AND now() >= COALESCE(target.provider_not_found_first_at, now()) \
                         + make_interval(secs => $5::DOUBLE PRECISION)) \
                        AS should_escalate \
               FROM target \
         ), updated AS ( \
             UPDATE bull_bitcoin_settlements settlement \
                SET provider_last_read_error_class = CASE WHEN $6 \
                        THEN 'not_found' ELSE 'not_found_unverified' END, \
                    provider_last_read_error_at = now(), \
                    provider_not_found_first_at = decision.next_first_at, \
                    provider_not_found_consecutive = decision.next_consecutive, \
                    provider_missing_since = CASE \
                        WHEN decision.should_escalate \
                        THEN COALESCE(settlement.provider_missing_since, now()) \
                        ELSE settlement.provider_missing_since END, \
                    settlement_status = CASE \
                        WHEN decision.should_escalate THEN 'integrity_error' \
                        ELSE settlement.settlement_status END, \
                    last_checked_at = now(), \
                    reconcile_attempts = settlement.reconcile_attempts + 1, \
                    next_attempt_at = now() + make_interval(secs => (CASE \
                        WHEN settlement.provider_missing_since IS NOT NULL \
                             OR decision.should_escalate THEN $3 \
                        ELSE $2 END)::DOUBLE PRECISION), \
                    updated_at = now() \
               FROM decision \
              WHERE settlement.id = decision.id \
          RETURNING decision.next_consecutive, \
                    (decision.provider_missing_since IS NULL \
                     AND decision.should_escalate) AS escalated_now, \
                    (decision.provider_missing_since IS NOT NULL \
                     OR decision.should_escalate) AS persistent_missing, \
                    decision.financial_evidence_present \
         ) \
         SELECT * FROM updated",
    )
    .bind(settlement_id)
    .bind(delay_secs)
    .bind(persistent_watch_secs)
    .bind(escalation_attempts)
    .bind(escalation_secs)
    .bind(provider_api_healthy)
    .fetch_optional(pool)
    .await?
    .ok_or(sqlx::Error::RowNotFound)?;
    Ok(ProviderNotFoundOutcome {
        consecutive: outcome.0,
        escalated_now: outcome.1,
        persistent_missing: outcome.2,
        financial_evidence_present: outcome.3,
    })
}

/// Return the conservative local/provider evidence predicate used to classify
/// a missing-order hold. This never makes an abandonment decision.
pub async fn bull_bitcoin_financial_evidence_present(
    pool: &PgPool,
    settlement_id: Uuid,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT settlement.actual_received_sat IS NOT NULL \
                OR (settlement.purpose = 'mixed' \
                    AND settlement.funding_committed_at IS NOT NULL) \
                OR EXISTS ( \
                    SELECT 1 FROM bull_bitcoin_claim_outputs output \
                     WHERE output.settlement_id = settlement.id \
                ) \
                OR EXISTS ( \
                    SELECT 1 FROM invoice_payment_events event \
                     WHERE event.bull_bitcoin_settlement_id = settlement.id \
                        OR (settlement.invoice_id IS NOT NULL \
                            AND event.invoice_id = settlement.invoice_id) \
                ) \
           FROM bull_bitcoin_settlements settlement WHERE settlement.id = $1",
    )
    .bind(settlement_id)
    .fetch_one(pool)
    .await
}

/// Record a retryable transport/upstream exact-order read failure separately
/// from authenticated NotFound. A transient failure breaks a 404 streak but
/// cannot clear an already-escalated missing-order integrity hold.
pub async fn record_bull_bitcoin_provider_transient_retry(
    pool: &PgPool,
    settlement_id: Uuid,
    delay_secs: i64,
    persistent_watch_secs: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE bull_bitcoin_settlements \
            SET provider_last_read_error_class = 'transient', \
                provider_last_read_error_at = now(), \
                provider_not_found_first_at = NULL, \
                provider_not_found_consecutive = 0, \
                reconcile_attempts = reconcile_attempts + 1, \
                last_checked_at = now(), \
                next_attempt_at = now() + make_interval(secs => (CASE \
                    WHEN provider_missing_since IS NOT NULL THEN $3 \
                    ELSE $2 END)::DOUBLE PRECISION), \
                updated_at = now() \
          WHERE id = $1 AND provider_state = 'bound' \
            AND funding_route = 'bull_bitcoin' \
            AND (settlement_status = 'pending' \
                 OR (settlement_status = 'integrity_error' \
                     AND provider_missing_since IS NOT NULL))",
    )
    .bind(settlement_id)
    .bind(delay_secs)
    .bind(persistent_watch_secs)
    .execute(pool)
    .await?;
    Ok(())
}

/// An authentication failure while reading a previously bound order is an
/// access incident, not proof that the financial obligation disappeared.
/// Preserve the credential generation, order, instruction, and ordinary retry
/// path so an operator/provider correction can recover the same order.
pub async fn record_bull_bitcoin_provider_authentication_retry(
    pool: &PgPool,
    settlement_id: Uuid,
    delay_secs: i64,
    persistent_watch_secs: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE bull_bitcoin_settlements \
            SET provider_last_read_error_class = 'authentication', \
                provider_last_read_error_at = now(), \
                provider_not_found_first_at = NULL, \
                provider_not_found_consecutive = 0, \
                reconcile_attempts = reconcile_attempts + 1, \
                last_checked_at = now(), \
                next_attempt_at = now() + make_interval(secs => (CASE \
                    WHEN provider_missing_since IS NOT NULL THEN $3 \
                    ELSE $2 END)::DOUBLE PRECISION), \
                updated_at = now() \
          WHERE id = $1 AND provider_state = 'bound' \
            AND funding_route = 'bull_bitcoin' \
            AND (settlement_status = 'pending' \
                 OR (settlement_status = 'integrity_error' \
                     AND provider_missing_since IS NOT NULL))",
    )
    .bind(settlement_id)
    .bind(delay_secs)
    .bind(persistent_watch_secs)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn record_bull_bitcoin_terminal_problem(
    pool: &PgPool,
    settlement_id: Uuid,
    settlement_status: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE bull_bitcoin_settlements \
            SET settlement_status = $2, payer_instruction = NULL, \
                instruction_kind = NULL, last_checked_at = now(), \
                next_attempt_at = NULL, updated_at = now() \
          WHERE id = $1 AND settlement_status = 'pending' \
            AND $2 IN ('unavailable', 'integrity_error')",
    )
    .bind(settlement_id)
    .bind(settlement_status)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn invalidate_bull_bitcoin_credential(
    pool: &PgPool,
    credential_id: Uuid,
) -> Result<(), sqlx::Error> {
    let mut connection = pool.acquire().await?;
    invalidate_bull_bitcoin_credential_on_connection(&mut connection, credential_id).await
}

pub async fn invalidate_bull_bitcoin_credential_on_connection(
    connection: &mut PgConnection,
    credential_id: Uuid,
) -> Result<(), sqlx::Error> {
    let mut transaction = connection.begin().await?;
    let owner = sqlx::query_scalar::<_, String>(
        "SELECT owner_npub FROM bull_bitcoin_credentials WHERE id = $1 FOR UPDATE",
    )
    .bind(credential_id)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(owner) = owner else {
        transaction.commit().await?;
        return Ok(());
    };
    lock_owner(&mut transaction, &owner).await?;
    sqlx::query("DELETE FROM fiat_settlement_settings WHERE owner_npub = $1")
        .bind(&owner)
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "UPDATE bull_bitcoin_settlements \
            SET funding_route = 'bitcoin_fallback', \
                fallback_category = 'conversion_unavailable', \
                instruction_kind = NULL, payer_instruction = NULL, \
                instruction_expires_at = NULL, next_attempt_at = NULL, \
                updated_at = now() \
          WHERE credential_id = $1 AND purpose IN ('mixed', 'provider_only') \
            AND provider_state = 'bound' AND funding_route IS NULL \
            AND funding_committed_at IS NULL AND settlement_status = 'none'",
    )
    .bind(credential_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "UPDATE bull_bitcoin_settlements \
            SET settlement_status = 'unavailable', payer_instruction = NULL, \
                instruction_kind = NULL, next_attempt_at = NULL, \
                last_checked_at = now(), updated_at = now() \
          WHERE credential_id = $1 AND provider_state = 'bound' \
            AND settlement_status = 'pending'",
    )
    .bind(credential_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "UPDATE bull_bitcoin_credentials \
            SET admitted_for_new_orders = FALSE, \
                deletion_requested_at = COALESCE(deletion_requested_at, now()), \
                ciphertext = NULL, nonce = NULL, erased_at = now() \
          WHERE id = $1",
    )
    .bind(credential_id)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(())
}

pub async fn expire_bull_bitcoin_retention(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE bull_bitcoin_settlements \
            SET settlement_status = 'unavailable', payer_instruction = NULL, \
                instruction_kind = NULL, next_attempt_at = NULL, updated_at = now() \
          WHERE provider_state = 'bound' AND settlement_status = 'pending' \
            AND retention_until IS NOT NULL AND retention_until <= now() \
            AND purpose = 'fiat_only' AND actual_received_sat IS NULL \
            AND invoice_id IS NULL",
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

pub async fn finalize_drained_bull_bitcoin_credentials(pool: &PgPool) -> Result<u64, sqlx::Error> {
    // An integrity hold may be the only durable evidence for a funded provider
    // order whose response could not be trusted. Keep the key until an
    // operator resolves that obligation; it is not a drained terminal row.
    let result = sqlx::query(
        "UPDATE bull_bitcoin_credentials credential \
            SET ciphertext = NULL, nonce = NULL, erased_at = now() \
          WHERE credential.deletion_requested_at IS NOT NULL \
            AND credential.erased_at IS NULL \
            AND NOT EXISTS ( \
                SELECT 1 FROM bull_bitcoin_settlements settlement \
                 WHERE settlement.credential_id = credential.id \
                   AND (settlement.provider_state = 'dispatch_started' \
                        OR (settlement.provider_state = 'bound' \
                            AND settlement.settlement_status \
                                IN ('pending', 'integrity_error'))) \
            )",
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

fn validate_reservation_identity(
    stored: &StoredBullBitcoinSettlement,
    requested: &NewBullBitcoinSettlement<'_>,
) -> Result<(), BullBitcoinSettlementStoreError> {
    if stored.owner_npub != requested.owner_npub
        || stored.invoice_id != requested.invoice_id
        || stored.invoice_quote_version_id != requested.invoice_quote_version_id
        || stored.reverse_swap_id != requested.reverse_swap_id
        || stored.chain_swap_id != requested.chain_swap_id
        || stored.credential_id != requested.credential_id
        || stored.product != requested.product
        || stored.purpose != requested.purpose
        || stored.payer_rail != requested.payer_rail
        || stored.request_key != requested.request_key
        || stored.fiat_percentage != requested.fiat_percentage
        || stored.fiat_currency != requested.fiat_currency
        || stored.requested_bitcoin_sat != requested.requested_bitcoin_sat
        || (stored.expected_instruction_script_len.is_some()
            && stored.expected_instruction_script_len != requested.expected_instruction_script_len)
    {
        return Err(BullBitcoinSettlementStoreError::RequestKeyConflict);
    }
    Ok(())
}
