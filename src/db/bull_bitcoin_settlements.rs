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
}

#[derive(Clone, Debug, PartialEq, Eq, FromRow)]
pub struct StoredBullBitcoinSettlement {
    pub id: Uuid,
    pub owner_npub: String,
    pub invoice_id: Option<Uuid>,
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
    pub instruction_kind: Option<String>,
    pub payer_instruction: Option<String>,
    pub instruction_expires_at_unix: Option<i64>,
    pub funding_committed_at_unix: Option<i64>,
    pub retention_until_unix: Option<i64>,
    pub reconcile_attempts: i32,
    pub actual_received_sat: Option<i64>,
    pub credited_fiat_minor: Option<i64>,
    pub provider_final: bool,
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
/// account identity, rates, and raw provider state. The one Bitcoin amount is
/// the exact merchant output needed to explain a mixed settlement.
#[derive(Clone, Debug, PartialEq, Eq, FromRow)]
pub struct InvoiceBullBitcoinSettlementProjection {
    pub invoice_id: Uuid,
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

const SETTLEMENT_PROJECTION: &str = "id, owner_npub, invoice_id, reverse_swap_id, chain_swap_id, \
     credential_id, product, purpose, payer_rail, \
     request_key, fiat_percentage, fiat_currency, provider_state, \
     funding_route, fallback_category, settlement_status, requested_bitcoin_sat, \
     bull_bitcoin_order_id, instruction_kind, payer_instruction, \
     extract(epoch FROM instruction_expires_at)::BIGINT AS instruction_expires_at_unix, \
     extract(epoch FROM funding_committed_at)::BIGINT AS funding_committed_at_unix, \
     extract(epoch FROM retention_until)::BIGINT AS retention_until_unix, reconcile_attempts, \
     actual_received_sat, credited_fiat_minor, provider_final";

/// Copy an invoice's immutable mixed policy onto the reverse swap in the same
/// transaction that makes the Boltz obligation durable. A 0%/100% policy does
/// not create a mixed-swap row.
pub async fn capture_invoice_reverse_mixed_policy(
    tx: &mut Transaction<'_, Postgres>,
    reverse_swap_id: Uuid,
    invoice_id: Uuid,
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
    Ok(result.rows_affected() == 1)
}

/// Chain-swap counterpart to [`capture_invoice_reverse_mixed_policy`].
pub async fn capture_invoice_chain_mixed_policy(
    tx: &mut Transaction<'_, Postgres>,
    chain_swap_id: Uuid,
    invoice_id: Uuid,
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
    Ok(result.rows_affected() == 1)
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

/// Revalidate the exact setting observed before Boltz I/O and, for a mixed
/// setting, capture it onto the newly inserted swap. `None` means the callback
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
    if expected.fiat_percentage == 100 {
        let exact: bool = sqlx::query_scalar(
            "SELECT EXISTS ( \
                 SELECT 1 FROM fiat_settlement_settings setting \
                 JOIN bull_bitcoin_credentials credential \
                   ON credential.id = setting.credential_id \
                  AND credential.owner_npub = setting.owner_npub \
                 JOIN users account ON account.npub = setting.owner_npub \
                  AND account.nym = $2 AND account.is_active \
                  WHERE setting.owner_npub = $1 \
                    AND setting.product = 'lightning_address' \
                    AND setting.credential_id = $3 \
                    AND setting.fiat_percentage = 100 \
                    AND setting.fiat_currency = $4 \
                    AND credential.admitted_for_new_orders \
                    AND credential.ciphertext IS NOT NULL \
                    AND credential.nonce IS NOT NULL \
             )",
        )
        .bind(&owner_npub)
        .bind(nym)
        .bind(expected.credential_id)
        .bind(&expected.fiat_currency)
        .fetch_one(&mut **tx)
        .await?;
        if !exact {
            return Err(sqlx::Error::Protocol(
                "Lightning Address fiat setting changed during offer creation".into(),
            ));
        }
        return Ok(false);
    }
    if !(1..=99).contains(&expected.fiat_percentage) {
        return Err(sqlx::Error::Protocol(
            "only a mixed Lightning Address policy can bind a Boltz swap".into(),
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
                settlement.settlement_status, settlement.credited_fiat_minor, \
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
             id, owner_npub, invoice_id, reverse_swap_id, chain_swap_id, \
             credential_id, product, purpose, \
             payer_rail, request_key, fiat_percentage, fiat_currency, \
             requested_bitcoin_sat \
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
    )
    .bind(id)
    .bind(settlement.owner_npub)
    .bind(settlement.invoice_id)
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

pub async fn bind_bull_bitcoin_order(
    connection: &mut PgConnection,
    settlement_id: Uuid,
    order_id: Uuid,
    instruction_kind: &str,
    payer_instruction: &str,
    instruction_expires_at_unix: Option<i64>,
    retention_secs: i64,
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
                instruction_kind = $3, payer_instruction = $4, \
                instruction_expires_at = CASE WHEN $5::BIGINT IS NULL \
                    THEN NULL ELSE to_timestamp($5) END, \
                retention_until = now() + make_interval(secs => $6::DOUBLE PRECISION), \
                next_attempt_at = now(), updated_at = now() \
          WHERE id = $1 AND provider_state = 'dispatch_started' \
            AND funding_route IS NULL",
    )
    .bind(settlement_id)
    .bind(order_id)
    .bind(instruction_kind)
    .bind(payer_instruction)
    .bind(instruction_expires_at_unix)
    .bind(retention_secs)
    .execute(connection)
    .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn abandon_bull_bitcoin_dispatch(
    connection: &mut PgConnection,
    settlement_id: Uuid,
    fallback_category: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE bull_bitcoin_settlements \
            SET provider_state = 'abandoned', \
                funding_route = 'bitcoin_fallback', \
                fallback_category = $2, updated_at = now() \
          WHERE id = $1 AND provider_state IN ('reserved', 'dispatch_started')",
    )
    .bind(settlement_id)
    .bind(fallback_category)
    .execute(connection)
    .await?;
    Ok(())
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
          WHERE id = $1 AND purpose = 'mixed' \
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

pub async fn recover_stale_bull_bitcoin_dispatches(
    pool: &PgPool,
    stale_after_secs: i64,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE bull_bitcoin_settlements \
            SET provider_state = 'abandoned', \
                funding_route = 'bitcoin_fallback', \
                fallback_category = 'ambiguous_create', updated_at = now() \
          WHERE provider_state = 'dispatch_started' \
            AND updated_at < now() - make_interval(secs => $1::DOUBLE PRECISION)",
    )
    .bind(stale_after_secs)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
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
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE bull_bitcoin_settlements \
            SET order_status = $2, payin_status = $3, payout_status = $4, \
                actual_received_sat = $5, credited_fiat_minor = $6, \
                provider_final = $7, \
                settlement_status = CASE WHEN $7 THEN 'settled' ELSE 'pending' END, \
                terminal_at = CASE WHEN $7 THEN now() ELSE NULL END, \
                payer_instruction = CASE WHEN $7 THEN NULL ELSE payer_instruction END, \
                instruction_kind = CASE WHEN $7 THEN NULL ELSE instruction_kind END, \
                last_checked_at = now(), reconcile_attempts = 0, \
                next_attempt_at = CASE WHEN $7 THEN NULL \
                    ELSE now() + make_interval(secs => $8::DOUBLE PRECISION) END, \
                updated_at = now() \
          WHERE id = $1 AND provider_state = 'bound' \
            AND funding_route = 'bull_bitcoin' \
            AND settlement_status = 'pending'",
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
    .bind(next_poll_secs)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn record_bull_bitcoin_retry(
    pool: &PgPool,
    settlement_id: Uuid,
    delay_secs: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE bull_bitcoin_settlements \
            SET reconcile_attempts = reconcile_attempts + 1, \
                last_checked_at = now(), \
                next_attempt_at = now() + \
                    make_interval(secs => $2::DOUBLE PRECISION), \
                updated_at = now() \
          WHERE id = $1 AND settlement_status = 'pending'",
    )
    .bind(settlement_id)
    .bind(delay_secs)
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
          WHERE credential_id = $1 AND purpose = 'mixed' \
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
            AND retention_until IS NOT NULL AND retention_until <= now()",
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

pub async fn finalize_drained_bull_bitcoin_credentials(pool: &PgPool) -> Result<u64, sqlx::Error> {
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
                            AND settlement.settlement_status = 'pending')) \
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
    {
        return Err(BullBitcoinSettlementStoreError::RequestKeyConflict);
    }
    Ok(())
}
