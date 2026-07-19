use sqlx::{FromRow, PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::bull_bitcoin::{EncryptedCredential, FiatCurrency, Product, TERMS_VERSION};

use super::bull_bitcoin_settlements::StoredEncryptedCredential;

pub(super) const OWNER_LOCK_NAMESPACE: i64 = 7_111_929_681_017_003_517;

#[derive(Debug)]
pub enum FiatSettlementStoreError {
    SourceIdentityNotActive,
    CredentialRequired,
    CredentialDraining,
    CredentialChanged,
    Sqlx(sqlx::Error),
}

impl From<sqlx::Error> for FiatSettlementStoreError {
    fn from(error: sqlx::Error) -> Self {
        Self::Sqlx(error)
    }
}

#[derive(Clone, Debug)]
pub struct NewEncryptedCredential {
    pub id: Uuid,
    pub encrypted: EncryptedCredential,
}

#[derive(Clone, Debug)]
pub enum FiatSettlementCredential {
    Existing { expected_id: Uuid },
    New(NewEncryptedCredential),
}

#[derive(Clone, Debug, PartialEq, Eq, FromRow)]
pub struct FiatSettlementSettingRow {
    pub product: String,
    pub fiat_percentage: i16,
    pub fiat_currency: String,
    pub terms_version: String,
    pub terms_accepted_at_unix: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialLifecycle {
    Absent,
    Active,
    DeletionPending,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FiatSettlementConfiguration {
    pub settings: Vec<FiatSettlementSettingRow>,
    pub credential: CredentialLifecycle,
}

pub async fn upsert_fiat_settlement_setting(
    pool: &PgPool,
    owner_npub: &str,
    product: Product,
    fiat_percentage: i16,
    fiat_currency: FiatCurrency,
    signed_at_unix: i64,
    credential: FiatSettlementCredential,
) -> Result<FiatSettlementConfiguration, FiatSettlementStoreError> {
    let mut transaction = pool.begin().await?;
    lock_owner(&mut transaction, owner_npub).await?;
    require_active_identity(&mut transaction, owner_npub).await?;

    if let FiatSettlementCredential::Existing {
        expected_id: expected_credential_id,
    } = &credential
    {
        let active_credential_id = sqlx::query_scalar::<_, Uuid>(
            "SELECT id \
               FROM bull_bitcoin_credentials \
              WHERE owner_npub = $1 AND admitted_for_new_orders \
              FOR UPDATE",
        )
        .bind(owner_npub)
        .fetch_optional(&mut *transaction)
        .await?;
        if active_credential_id != Some(*expected_credential_id) {
            return Err(FiatSettlementStoreError::CredentialChanged);
        }
    }

    // An exact retried signed mutation is already complete. Do not rotate the
    // credential a second time merely because the client did not receive the
    // first HTTP response.
    let exact_retry_credential = sqlx::query_scalar::<_, Uuid>(
        "SELECT setting.credential_id \
           FROM fiat_settlement_settings setting \
           JOIN bull_bitcoin_credentials credential \
             ON credential.id = setting.credential_id \
            AND credential.owner_npub = setting.owner_npub \
          WHERE setting.owner_npub = $1 \
            AND setting.product = $2 \
            AND setting.fiat_percentage = $3 \
            AND setting.fiat_currency = $4 \
            AND setting.terms_version = $5 \
            AND extract(epoch FROM setting.terms_accepted_at)::BIGINT = $6 \
            AND credential.admitted_for_new_orders",
    )
    .bind(owner_npub)
    .bind(product.as_str())
    .bind(fiat_percentage)
    .bind(fiat_currency.as_str())
    .bind(TERMS_VERSION)
    .bind(signed_at_unix)
    .fetch_optional(&mut *transaction)
    .await?;

    if exact_retry_credential.is_none() {
        let active_credential = sqlx::query_scalar::<_, Uuid>(
            "SELECT id \
               FROM bull_bitcoin_credentials \
              WHERE owner_npub = $1 AND admitted_for_new_orders \
              FOR UPDATE",
        )
        .bind(owner_npub)
        .fetch_optional(&mut *transaction)
        .await?;

        let credential_id = match credential {
            FiatSettlementCredential::New(new_credential) => {
                if let Some(old_id) = active_credential {
                    if credential_has_live_dependencies(&mut transaction, old_id).await? {
                        return Err(FiatSettlementStoreError::CredentialDraining);
                    }
                    sqlx::query(
                        "UPDATE bull_bitcoin_credentials \
                            SET admitted_for_new_orders = FALSE, \
                                deletion_requested_at = now(), \
                                ciphertext = NULL, nonce = NULL, erased_at = now() \
                          WHERE id = $1",
                    )
                    .bind(old_id)
                    .execute(&mut *transaction)
                    .await?;
                } else if owner_has_draining_credential(&mut transaction, owner_npub).await? {
                    return Err(FiatSettlementStoreError::CredentialDraining);
                }

                insert_credential(&mut transaction, owner_npub, &new_credential).await?;
                sqlx::query(
                    "UPDATE fiat_settlement_settings \
                        SET credential_id = $2, updated_at = now() \
                      WHERE owner_npub = $1",
                )
                .bind(owner_npub)
                .bind(new_credential.id)
                .execute(&mut *transaction)
                .await?;
                new_credential.id
            }
            FiatSettlementCredential::Existing { .. } => {
                active_credential.ok_or(FiatSettlementStoreError::CredentialRequired)?
            }
        };

        sqlx::query(
            "INSERT INTO fiat_settlement_settings ( \
                 owner_npub, product, credential_id, fiat_percentage, \
                 fiat_currency, terms_version, terms_accepted_at, updated_at \
             ) VALUES ($1, $2, $3, $4, $5, $6, to_timestamp($7), now()) \
             ON CONFLICT (owner_npub, product) DO UPDATE SET \
                 credential_id = EXCLUDED.credential_id, \
                 fiat_percentage = EXCLUDED.fiat_percentage, \
                 fiat_currency = EXCLUDED.fiat_currency, \
                 terms_version = EXCLUDED.terms_version, \
                 terms_accepted_at = EXCLUDED.terms_accepted_at, \
                 updated_at = now()",
        )
        .bind(owner_npub)
        .bind(product.as_str())
        .bind(credential_id)
        .bind(fiat_percentage)
        .bind(fiat_currency.as_str())
        .bind(TERMS_VERSION)
        .bind(signed_at_unix)
        .execute(&mut *transaction)
        .await?;
    }

    let configuration = select_configuration_in_transaction(&mut transaction, owner_npub).await?;
    transaction.commit().await?;
    Ok(configuration)
}

pub async fn load_active_bull_bitcoin_credential(
    pool: &PgPool,
    owner_npub: &str,
) -> Result<Option<StoredEncryptedCredential>, FiatSettlementStoreError> {
    let row = sqlx::query_as::<_, (Uuid, String, Vec<u8>, Vec<u8>, i16)>(
        "SELECT id, owner_npub, ciphertext, nonce, encryption_format \
           FROM bull_bitcoin_credentials \
          WHERE owner_npub = $1 \
            AND admitted_for_new_orders \
            AND ciphertext IS NOT NULL \
            AND nonce IS NOT NULL",
    )
    .bind(owner_npub)
    .fetch_optional(pool)
    .await?;

    row.map(|(id, owner_npub, ciphertext, nonce, format_version)| {
        let nonce: [u8; 24] = nonce.try_into().map_err(|_| {
            sqlx::Error::Decode("Bull Bitcoin credential nonce has the wrong length".into())
        })?;
        Ok::<StoredEncryptedCredential, sqlx::Error>(StoredEncryptedCredential {
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
    .map_err(FiatSettlementStoreError::from)
}

pub async fn delete_fiat_settlement_setting(
    pool: &PgPool,
    owner_npub: &str,
    product: Product,
) -> Result<FiatSettlementConfiguration, FiatSettlementStoreError> {
    let mut transaction = pool.begin().await?;
    lock_owner(&mut transaction, owner_npub).await?;
    require_active_identity(&mut transaction, owner_npub).await?;
    sqlx::query("DELETE FROM fiat_settlement_settings WHERE owner_npub = $1 AND product = $2")
        .bind(owner_npub)
        .bind(product.as_str())
        .execute(&mut *transaction)
        .await?;
    let configuration = select_configuration_in_transaction(&mut transaction, owner_npub).await?;
    transaction.commit().await?;
    Ok(configuration)
}

pub async fn request_bull_bitcoin_credential_deletion(
    pool: &PgPool,
    owner_npub: &str,
) -> Result<FiatSettlementConfiguration, FiatSettlementStoreError> {
    let mut transaction = pool.begin().await?;
    lock_owner(&mut transaction, owner_npub).await?;
    require_active_identity(&mut transaction, owner_npub).await?;

    sqlx::query("DELETE FROM fiat_settlement_settings WHERE owner_npub = $1")
        .bind(owner_npub)
        .execute(&mut *transaction)
        .await?;

    if let Some(credential_id) = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM bull_bitcoin_credentials \
          WHERE owner_npub = $1 AND admitted_for_new_orders FOR UPDATE",
    )
    .bind(owner_npub)
    .fetch_optional(&mut *transaction)
    .await?
    {
        // A reserved row has not crossed the dispatch boundary and can safely
        // release its key dependency. `dispatch_started` may represent an API
        // call currently in flight, so deletion must retain that generation;
        // its caller or restart recovery will bind or abandon it exactly once.
        sqlx::query(
            "UPDATE bull_bitcoin_settlements \
                SET provider_state = 'abandoned', \
                    funding_route = 'bitcoin_fallback', \
                    fallback_category = 'conversion_unavailable', \
                    updated_at = now() \
              WHERE credential_id = $1 \
                AND provider_state = 'reserved'",
        )
        .bind(credential_id)
        .execute(&mut *transaction)
        .await?;

        // A bound mixed order is not a funding obligation until its exact
        // Liquid output is journaled. Credential deletion therefore routes
        // only that still-unfunded state to the user's Bitcoin wallet. Orders
        // already committed into claim bytes retain the encrypted key until
        // reconciliation drains, exactly like fiat-only orders.
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

        let retain = credential_has_live_dependencies(&mut transaction, credential_id).await?;
        sqlx::query(
            "UPDATE bull_bitcoin_credentials \
                SET admitted_for_new_orders = FALSE, \
                    deletion_requested_at = COALESCE(deletion_requested_at, now()), \
                    ciphertext = CASE WHEN $2 THEN ciphertext ELSE NULL END, \
                    nonce = CASE WHEN $2 THEN nonce ELSE NULL END, \
                    erased_at = CASE WHEN $2 THEN NULL ELSE now() END \
              WHERE id = $1",
        )
        .bind(credential_id)
        .bind(retain)
        .execute(&mut *transaction)
        .await?;
    }

    let configuration = select_configuration_in_transaction(&mut transaction, owner_npub).await?;
    transaction.commit().await?;
    Ok(configuration)
}

pub async fn select_fiat_settlement_configuration(
    pool: &PgPool,
    owner_npub: &str,
) -> Result<FiatSettlementConfiguration, FiatSettlementStoreError> {
    let mut transaction = pool.begin().await?;
    require_active_identity(&mut transaction, owner_npub).await?;
    let configuration = select_configuration_in_transaction(&mut transaction, owner_npub).await?;
    transaction.commit().await?;
    Ok(configuration)
}

pub(super) async fn lock_owner(
    transaction: &mut Transaction<'_, Postgres>,
    owner_npub: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, $2))")
        .bind(owner_npub)
        .bind(OWNER_LOCK_NAMESPACE)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

pub(super) async fn require_active_identity(
    transaction: &mut Transaction<'_, Postgres>,
    owner_npub: &str,
) -> Result<(), FiatSettlementStoreError> {
    let active = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM users WHERE npub = $1 AND is_active)",
    )
    .bind(owner_npub)
    .fetch_one(&mut **transaction)
    .await?;
    if !active {
        return Err(FiatSettlementStoreError::SourceIdentityNotActive);
    }
    Ok(())
}

async fn insert_credential(
    transaction: &mut Transaction<'_, Postgres>,
    owner_npub: &str,
    credential: &NewEncryptedCredential,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO bull_bitcoin_credentials ( \
             id, owner_npub, ciphertext, nonce, encryption_format \
         ) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(credential.id)
    .bind(owner_npub)
    .bind(&credential.encrypted.ciphertext)
    .bind(credential.encrypted.nonce.as_slice())
    .bind(credential.encrypted.format_version)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn credential_has_live_dependencies(
    transaction: &mut Transaction<'_, Postgres>,
    credential_id: Uuid,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS ( \
             SELECT 1 FROM bull_bitcoin_settlements \
              WHERE credential_id = $1 \
                AND NOT provider_final \
                AND (provider_state = 'dispatch_started' \
                     OR (provider_state = 'bound' \
                         AND funding_route = 'bull_bitcoin' \
                         AND funding_committed_at IS NOT NULL)) \
         )",
    )
    .bind(credential_id)
    .fetch_one(&mut **transaction)
    .await
}

async fn owner_has_draining_credential(
    transaction: &mut Transaction<'_, Postgres>,
    owner_npub: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS ( \
             SELECT 1 \
               FROM bull_bitcoin_credentials credential \
              WHERE credential.owner_npub = $1 \
                AND credential.deletion_requested_at IS NOT NULL \
                AND credential.erased_at IS NULL \
         )",
    )
    .bind(owner_npub)
    .fetch_one(&mut **transaction)
    .await
}

async fn select_configuration_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    owner_npub: &str,
) -> Result<FiatSettlementConfiguration, sqlx::Error> {
    let settings = sqlx::query_as::<_, FiatSettlementSettingRow>(
        "SELECT product, fiat_percentage, fiat_currency, terms_version, \
                extract(epoch FROM terms_accepted_at)::BIGINT \
                    AS terms_accepted_at_unix \
           FROM fiat_settlement_settings \
          WHERE owner_npub = $1 \
          ORDER BY product",
    )
    .bind(owner_npub)
    .fetch_all(&mut **transaction)
    .await?;

    let lifecycle = sqlx::query_as::<_, (bool, bool)>(
        "SELECT \
             EXISTS (SELECT 1 FROM bull_bitcoin_credentials \
                      WHERE owner_npub = $1 AND admitted_for_new_orders), \
             EXISTS (SELECT 1 FROM bull_bitcoin_credentials \
                      WHERE owner_npub = $1 \
                        AND deletion_requested_at IS NOT NULL \
                        AND erased_at IS NULL)",
    )
    .bind(owner_npub)
    .fetch_one(&mut **transaction)
    .await?;

    let credential = match lifecycle {
        (true, _) => CredentialLifecycle::Active,
        (false, true) => CredentialLifecycle::DeletionPending,
        (false, false) => CredentialLifecycle::Absent,
    };
    Ok(FiatSettlementConfiguration {
        settings,
        credential,
    })
}
