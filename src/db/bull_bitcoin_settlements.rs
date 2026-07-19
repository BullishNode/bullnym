use sqlx::{Connection, FromRow, PgConnection, PgPool};
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
    pub credential_id: Uuid,
    pub product: &'a str,
    pub purpose: &'a str,
    pub payer_rail: &'a str,
    pub request_key: &'a str,
    pub fiat_percentage: i16,
    pub fiat_currency: &'a str,
    pub terms_version: &'a str,
    pub requested_bitcoin_sat: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, FromRow)]
pub struct StoredBullBitcoinSettlement {
    pub id: Uuid,
    pub owner_npub: String,
    pub invoice_id: Option<Uuid>,
    pub credential_id: Uuid,
    pub product: String,
    pub purpose: String,
    pub payer_rail: String,
    pub request_key: String,
    pub fiat_percentage: i16,
    pub fiat_currency: String,
    pub terms_version: String,
    pub provider_state: String,
    pub funding_route: Option<String>,
    pub fallback_category: Option<String>,
    pub settlement_status: String,
    pub requested_bitcoin_sat: i64,
    pub bull_bitcoin_order_id: Option<Uuid>,
    pub instruction_kind: Option<String>,
    pub payer_instruction: Option<String>,
    pub instruction_expires_at_unix: Option<i64>,
    pub retention_until_unix: Option<i64>,
    pub reconcile_attempts: i32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredEncryptedCredential {
    pub id: Uuid,
    pub owner_npub: String,
    pub encrypted: EncryptedCredential,
}

const SETTLEMENT_PROJECTION: &str =
    "id, owner_npub, invoice_id, credential_id, product, purpose, payer_rail, \
     request_key, fiat_percentage, fiat_currency, terms_version, provider_state, \
     funding_route, fallback_category, settlement_status, requested_bitcoin_sat, \
     bull_bitcoin_order_id, instruction_kind, payer_instruction, \
     extract(epoch FROM instruction_expires_at)::BIGINT AS instruction_expires_at_unix, \
     extract(epoch FROM retention_until)::BIGINT AS retention_until_unix, reconcile_attempts";

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

    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO bull_bitcoin_settlements ( \
             id, owner_npub, invoice_id, credential_id, product, purpose, \
             payer_rail, request_key, fiat_percentage, fiat_currency, \
             terms_version, requested_bitcoin_sat \
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
    )
    .bind(id)
    .bind(settlement.owner_npub)
    .bind(settlement.invoice_id)
    .bind(settlement.credential_id)
    .bind(settlement.product)
    .bind(settlement.purpose)
    .bind(settlement.payer_rail)
    .bind(settlement.request_key)
    .bind(settlement.fiat_percentage)
    .bind(settlement.fiat_currency)
    .bind(settlement.terms_version)
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
                funding_route = 'bull_bitcoin', \
                settlement_status = 'pending', \
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
                AND settlement_status = 'pending' \
                AND bull_bitcoin_order_id IS NOT NULL \
                AND (next_attempt_at IS NULL OR next_attempt_at <= now()) \
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
        || stored.credential_id != requested.credential_id
        || stored.product != requested.product
        || stored.purpose != requested.purpose
        || stored.payer_rail != requested.payer_rail
        || stored.request_key != requested.request_key
        || stored.fiat_percentage != requested.fiat_percentage
        || stored.fiat_currency != requested.fiat_currency
        || stored.terms_version != requested.terms_version
        || stored.requested_bitcoin_sat != requested.requested_bitcoin_sat
    {
        return Err(BullBitcoinSettlementStoreError::RequestKeyConflict);
    }
    Ok(())
}
