//! Durable, rail-neutral LNURL payer-comment intent ledger.
//!
//! This is intentionally a persistence seam, not an HTTP API. The public
//! callback still lacks a stable Lightning idempotency token and Bullnym has no
//! authenticated Lightning-Address payment-history route. A later coordinator
//! can wire both rails only after it can supply one stable intent digest across
//! retries. Until then these functions prevent a partial implementation from
//! silently dropping direct-Liquid or fallback comments.

use std::fmt;

use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::lnurl_comment::{
    LnurlCommentIntentKey, LnurlCommentRail, LnurlCommentStoredValueError, LnurlPayerComment,
};

/// PostgreSQL advisory-lock class (ASCII `LCMT`) for one merchant/intent key.
const LNURL_COMMENT_LOCK_CLASS: i32 = 1_280_474_196;
const REFERENCE_MAX_BYTES: usize = 255;
pub const MAX_AUTHENTICATED_HISTORY_PAGE_SIZE: u16 = 100;
pub const MAX_AUTHENTICATED_HISTORY_PAGE_NUMBER: u16 = 1_000;

const INTENT_COLUMNS: &str = "intent_id, owner_npub, nym, idempotency_key, \
    amount_msat, comment, comment_grapheme_count, instruction_rail, \
    instruction_reference, payment_evidence_reference, \
    EXTRACT(EPOCH FROM created_at)::BIGINT AS created_at_unix, \
    EXTRACT(EPOCH FROM instruction_bound_at)::BIGINT AS instruction_bound_at_unix, \
    EXTRACT(EPOCH FROM payment_evidenced_at)::BIGINT AS payment_evidenced_at_unix";

#[derive(Clone, Copy)]
pub struct NewLnurlCommentIntent<'a> {
    /// Merchant identity resolved from the active nym before persistence.
    pub owner_npub: &'a str,
    pub nym: &'a str,
    /// Opaque stable digest supplied by the future callback coordinator.
    pub idempotency_key: &'a LnurlCommentIntentKey,
    pub amount_msat: u64,
    pub comment: &'a LnurlPayerComment,
}

#[derive(Clone, PartialEq, Eq)]
pub struct LnurlCommentInstruction {
    pub rail: LnurlCommentRail,
    reference: String,
    pub bound_at_unix: i64,
}

impl LnurlCommentInstruction {
    pub fn reference(&self) -> &str {
        &self.reference
    }
}

impl fmt::Debug for LnurlCommentInstruction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LnurlCommentInstruction")
            .field("rail", &self.rail)
            .field("reference", &"<redacted>")
            .field("bound_at_unix", &self.bound_at_unix)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct LnurlCommentPaymentEvidence {
    reference: String,
    pub evidenced_at_unix: i64,
}

impl LnurlCommentPaymentEvidence {
    pub fn reference(&self) -> &str {
        &self.reference
    }
}

impl fmt::Debug for LnurlCommentPaymentEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LnurlCommentPaymentEvidence")
            .field("reference", &"<redacted>")
            .field("evidenced_at_unix", &self.evidenced_at_unix)
            .finish()
    }
}

/// One private comment intent and its monotonic instruction/payment bindings.
///
/// This type has no `Serialize` implementation. A future authenticated route
/// must explicitly project the comment as escaped plain text after checking
/// [`Self::payment_evidence`].
#[derive(Clone, PartialEq, Eq)]
pub struct LnurlCommentIntent {
    pub intent_id: Uuid,
    owner_npub: String,
    nym: String,
    idempotency_key: LnurlCommentIntentKey,
    pub amount_msat: u64,
    comment: LnurlPayerComment,
    pub instruction: Option<LnurlCommentInstruction>,
    pub payment_evidence: Option<LnurlCommentPaymentEvidence>,
    pub created_at_unix: i64,
}

/// One bounded, evidence-gated merchant history page.
///
/// This remains an internal persistence type: the HTTP boundary must project
/// each intent into a narrower DTO that omits owner keys, idempotency keys,
/// provider references, and payment-evidence references.
pub struct AuthenticatedLnurlCommentHistoryPage {
    pub intents: Vec<LnurlCommentIntent>,
    pub has_more: bool,
}

impl LnurlCommentIntent {
    pub fn owner_npub(&self) -> &str {
        &self.owner_npub
    }

    pub fn nym(&self) -> &str {
        &self.nym
    }

    pub fn idempotency_key(&self) -> &LnurlCommentIntentKey {
        &self.idempotency_key
    }

    pub fn comment(&self) -> &LnurlPayerComment {
        &self.comment
    }
}

impl fmt::Debug for LnurlCommentIntent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LnurlCommentIntent")
            .field("intent_id", &self.intent_id)
            .field("owner_npub", &"<redacted>")
            .field("nym", &"<redacted>")
            .field("idempotency_key", &self.idempotency_key)
            .field("amount_msat", &self.amount_msat)
            .field("comment", &self.comment)
            .field("instruction", &self.instruction)
            .field("payment_evidence", &self.payment_evidence)
            .field("created_at_unix", &self.created_at_unix)
            .finish()
    }
}

/// Sanitized persistence failure. Raw SQL errors are intentionally not exposed
/// as `source()`: PostgreSQL detail can contain private comment text.
pub enum LnurlCommentPersistenceError {
    Database,
    InvalidInput { field: &'static str },
    SourceIdentityNotActive,
    IntentNotFound,
    RetryMismatch,
    InstructionNotBound,
    InstructionMismatch,
    PaymentEvidenceMismatch,
    CorruptStoredValue { field: &'static str },
}

impl fmt::Debug for LnurlCommentPersistenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database => formatter.write_str("Database"),
            Self::InvalidInput { field } => formatter
                .debug_struct("InvalidInput")
                .field("field", field)
                .finish(),
            Self::SourceIdentityNotActive => formatter.write_str("SourceIdentityNotActive"),
            Self::IntentNotFound => formatter.write_str("IntentNotFound"),
            Self::RetryMismatch => formatter.write_str("RetryMismatch"),
            Self::InstructionNotBound => formatter.write_str("InstructionNotBound"),
            Self::InstructionMismatch => formatter.write_str("InstructionMismatch"),
            Self::PaymentEvidenceMismatch => formatter.write_str("PaymentEvidenceMismatch"),
            Self::CorruptStoredValue { field } => formatter
                .debug_struct("CorruptStoredValue")
                .field("field", field)
                .finish(),
        }
    }
}

impl fmt::Display for LnurlCommentPersistenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database => formatter.write_str("LNURL comment persistence failed"),
            Self::InvalidInput { field } => write!(formatter, "invalid LNURL comment {field}"),
            Self::SourceIdentityNotActive => {
                formatter.write_str("LNURL comment merchant identity is not active")
            }
            Self::IntentNotFound => formatter.write_str("LNURL comment intent was not found"),
            Self::RetryMismatch => {
                formatter.write_str("LNURL comment intent retry does not match persisted intent")
            }
            Self::InstructionNotBound => {
                formatter.write_str("LNURL comment payment instruction is not bound")
            }
            Self::InstructionMismatch => formatter.write_str(
                "LNURL comment payment instruction retry does not match persisted intent",
            ),
            Self::PaymentEvidenceMismatch => formatter
                .write_str("LNURL comment payment evidence retry does not match persisted intent"),
            Self::CorruptStoredValue { field } => {
                write!(formatter, "LNURL comment intent has invalid stored {field}")
            }
        }
    }
}

impl std::error::Error for LnurlCommentPersistenceError {}

impl From<sqlx::Error> for LnurlCommentPersistenceError {
    fn from(_: sqlx::Error) -> Self {
        Self::Database
    }
}

#[derive(sqlx::FromRow)]
struct LnurlCommentIntentDbRow {
    intent_id: Uuid,
    owner_npub: String,
    nym: String,
    idempotency_key: String,
    amount_msat: i64,
    comment: String,
    comment_grapheme_count: i16,
    instruction_rail: Option<String>,
    instruction_reference: Option<String>,
    payment_evidence_reference: Option<String>,
    created_at_unix: i64,
    instruction_bound_at_unix: Option<i64>,
    payment_evidenced_at_unix: Option<i64>,
}

impl TryFrom<LnurlCommentIntentDbRow> for LnurlCommentIntent {
    type Error = LnurlCommentPersistenceError;

    fn try_from(row: LnurlCommentIntentDbRow) -> Result<Self, Self::Error> {
        if row.intent_id.is_nil() {
            return Err(corrupt("intent_id"));
        }
        validate_npub(&row.owner_npub).map_err(|_| corrupt("owner_npub"))?;
        validate_nym(&row.nym).map_err(|_| corrupt("nym"))?;
        let idempotency_key = LnurlCommentIntentKey::from_stored(row.idempotency_key)
            .map_err(map_stored_value_error)?;
        let amount_msat = u64::try_from(row.amount_msat).map_err(|_| corrupt("amount_msat"))?;
        validate_amount(amount_msat).map_err(|_| corrupt("amount_msat"))?;

        let comment = LnurlPayerComment::try_from(row.comment).map_err(|_| corrupt("comment"))?;
        let stored_graphemes = u16::try_from(row.comment_grapheme_count)
            .map_err(|_| corrupt("comment_grapheme_count"))?;
        if stored_graphemes != comment.grapheme_count() {
            return Err(corrupt("comment_grapheme_count"));
        }
        if row.created_at_unix <= 0 {
            return Err(corrupt("created_at"));
        }

        let instruction = match (
            row.instruction_rail,
            row.instruction_reference,
            row.instruction_bound_at_unix,
        ) {
            (None, None, None) => None,
            (Some(rail), Some(reference), Some(bound_at_unix)) if bound_at_unix > 0 => {
                validate_reference(&reference, "instruction_reference")
                    .map_err(|_| corrupt("instruction_reference"))?;
                Some(LnurlCommentInstruction {
                    rail: LnurlCommentRail::from_stored(&rail).map_err(map_stored_value_error)?,
                    reference,
                    bound_at_unix,
                })
            }
            _ => return Err(corrupt("instruction")),
        };

        let payment_evidence = match (
            row.payment_evidence_reference,
            row.payment_evidenced_at_unix,
        ) {
            (None, None) => None,
            (Some(reference), Some(evidenced_at_unix))
                if evidenced_at_unix > 0 && instruction.is_some() =>
            {
                validate_reference(&reference, "payment_evidence_reference")
                    .map_err(|_| corrupt("payment_evidence_reference"))?;
                Some(LnurlCommentPaymentEvidence {
                    reference,
                    evidenced_at_unix,
                })
            }
            _ => return Err(corrupt("payment_evidence")),
        };

        Ok(Self {
            intent_id: row.intent_id,
            owner_npub: row.owner_npub,
            nym: row.nym,
            idempotency_key,
            amount_msat,
            comment,
            instruction,
            payment_evidence,
            created_at_unix: row.created_at_unix,
        })
    }
}

/// Persist a private comment before any payment instruction is returned.
///
/// Exact retries return the original row, including bindings made after the
/// first insert. Reusing the same merchant-scoped key with different nym,
/// amount, or exact comment fails closed.
pub async fn persist_lnurl_comment_intent(
    pool: &PgPool,
    new_intent: &NewLnurlCommentIntent<'_>,
) -> Result<LnurlCommentIntent, LnurlCommentPersistenceError> {
    validate_new_intent(new_intent)?;
    let amount_msat = i64::try_from(new_intent.amount_msat).map_err(|_| {
        LnurlCommentPersistenceError::InvalidInput {
            field: "amount_msat",
        }
    })?;
    let comment_grapheme_count =
        i16::try_from(new_intent.comment.grapheme_count()).map_err(|_| {
            LnurlCommentPersistenceError::InvalidInput {
                field: "comment_grapheme_count",
            }
        })?;

    let mut tx = pool.begin().await?;
    lock_intent(&mut tx, new_intent.owner_npub, new_intent.idempotency_key).await?;

    if let Some(existing) =
        select_intent_for_update(&mut tx, new_intent.owner_npub, new_intent.idempotency_key).await?
    {
        let existing: LnurlCommentIntent = existing.try_into()?;
        if existing.nym() != new_intent.nym
            || existing.amount_msat != new_intent.amount_msat
            || existing.comment() != new_intent.comment
        {
            return Err(LnurlCommentPersistenceError::RetryMismatch);
        }
        tx.commit().await?;
        return Ok(existing);
    }

    // Share the existing user-lifecycle advisory lock with create/deactivate/
    // purge. The runtime role intentionally has SELECT but not row-lock UPDATE
    // authority on users, so admission is rechecked with a plain read only
    // after this transaction has serialized the lifecycle.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1)::bigint)")
        .bind(new_intent.owner_npub)
        .execute(&mut *tx)
        .await?;

    // Bind the immutable owner snapshot to the exact active nym. The ledger
    // deliberately has no user FK so paid history survives later deactivation
    // and swap cleanup.
    let active_identity: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM users \
          WHERE npub = $1 AND nym = $2 AND is_active = TRUE",
    )
    .bind(new_intent.owner_npub)
    .bind(new_intent.nym)
    .fetch_optional(&mut *tx)
    .await?;
    if active_identity.is_none() {
        return Err(LnurlCommentPersistenceError::SourceIdentityNotActive);
    }

    let row = sqlx::query_as::<_, LnurlCommentIntentDbRow>(&format!(
        "INSERT INTO lnurl_comment_intents (\
             intent_id, owner_npub, nym, idempotency_key, amount_msat, \
             comment, comment_grapheme_count\
         ) VALUES ($1, $2, $3, $4, $5, $6, $7) \
         RETURNING {INTENT_COLUMNS}"
    ))
    .bind(Uuid::new_v4())
    .bind(new_intent.owner_npub)
    .bind(new_intent.nym)
    .bind(new_intent.idempotency_key.as_str())
    .bind(amount_msat)
    .bind(new_intent.comment.as_str())
    .bind(comment_grapheme_count)
    .fetch_one(&mut *tx)
    .await?;
    let intent = row.try_into()?;
    tx.commit().await?;
    Ok(intent)
}

/// Bind the exact instruction selected after rail choice/fallback.
///
/// This must complete before the HTTP handler exposes that instruction. The
/// first binding is immutable; exact restart retries succeed and every
/// different rail/reference pair fails closed.
pub async fn bind_lnurl_comment_instruction(
    pool: &PgPool,
    owner_npub: &str,
    idempotency_key: &LnurlCommentIntentKey,
    rail: LnurlCommentRail,
    instruction_reference: &str,
) -> Result<LnurlCommentIntent, LnurlCommentPersistenceError> {
    let mut tx = pool.begin().await?;
    let intent = bind_lnurl_comment_instruction_in_tx(
        &mut tx,
        owner_npub,
        idempotency_key,
        rail,
        instruction_reference,
    )
    .await?;
    tx.commit().await?;
    Ok(intent)
}

/// Transaction-aware instruction binding for atomic composition with the
/// exact swap/reservation insert that owns the returned payment instruction.
pub async fn bind_lnurl_comment_instruction_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    owner_npub: &str,
    idempotency_key: &LnurlCommentIntentKey,
    rail: LnurlCommentRail,
    instruction_reference: &str,
) -> Result<LnurlCommentIntent, LnurlCommentPersistenceError> {
    validate_npub(owner_npub)?;
    validate_reference(instruction_reference, "instruction_reference")?;
    lock_intent(&mut *tx, owner_npub, idempotency_key).await?;
    let existing = select_intent_for_update(&mut *tx, owner_npub, idempotency_key)
        .await?
        .ok_or(LnurlCommentPersistenceError::IntentNotFound)?;
    let existing: LnurlCommentIntent = existing.try_into()?;
    if let Some(bound) = existing.instruction.as_ref() {
        if bound.rail != rail || bound.reference() != instruction_reference {
            return Err(LnurlCommentPersistenceError::InstructionMismatch);
        }
        return Ok(existing);
    }

    let row = sqlx::query_as::<_, LnurlCommentIntentDbRow>(&format!(
        "UPDATE lnurl_comment_intents \
            SET instruction_rail = $3, instruction_reference = $4 \
          WHERE owner_npub = $1 AND idempotency_key = $2 \
            AND instruction_rail IS NULL \
            AND instruction_reference IS NULL \
            AND instruction_bound_at IS NULL \
         RETURNING {INTENT_COLUMNS}"
    ))
    .bind(owner_npub)
    .bind(idempotency_key.as_str())
    .bind(rail.as_str())
    .bind(instruction_reference)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(LnurlCommentPersistenceError::InstructionMismatch)?;
    row.try_into()
}

/// Bind authoritative eventual-payment evidence to the exact instruction.
///
/// The caller must establish evidence from the rail's authoritative reducer in
/// the same owned integration slice. This seam records its stable reference;
/// the authenticated projection below cannot return abandoned intents.
pub async fn bind_lnurl_comment_payment_evidence(
    pool: &PgPool,
    owner_npub: &str,
    idempotency_key: &LnurlCommentIntentKey,
    instruction_rail: LnurlCommentRail,
    instruction_reference: &str,
    payment_evidence_reference: &str,
) -> Result<LnurlCommentIntent, LnurlCommentPersistenceError> {
    let mut tx = pool.begin().await?;
    let intent = bind_lnurl_comment_payment_evidence_in_tx(
        &mut tx,
        owner_npub,
        idempotency_key,
        instruction_rail,
        instruction_reference,
        payment_evidence_reference,
    )
    .await?;
    tx.commit().await?;
    Ok(intent)
}

/// Transaction-aware evidence binding for atomic composition with the
/// authoritative rail reducer/payment-event write.
pub async fn bind_lnurl_comment_payment_evidence_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    owner_npub: &str,
    idempotency_key: &LnurlCommentIntentKey,
    instruction_rail: LnurlCommentRail,
    instruction_reference: &str,
    payment_evidence_reference: &str,
) -> Result<LnurlCommentIntent, LnurlCommentPersistenceError> {
    validate_npub(owner_npub)?;
    validate_reference(instruction_reference, "instruction_reference")?;
    validate_reference(payment_evidence_reference, "payment_evidence_reference")?;
    lock_intent(&mut *tx, owner_npub, idempotency_key).await?;
    let existing = select_intent_for_update(&mut *tx, owner_npub, idempotency_key)
        .await?
        .ok_or(LnurlCommentPersistenceError::IntentNotFound)?;
    let existing: LnurlCommentIntent = existing.try_into()?;
    let Some(instruction) = existing.instruction.as_ref() else {
        return Err(LnurlCommentPersistenceError::InstructionNotBound);
    };
    if instruction.rail != instruction_rail || instruction.reference() != instruction_reference {
        return Err(LnurlCommentPersistenceError::InstructionMismatch);
    }
    if let Some(evidence) = existing.payment_evidence.as_ref() {
        if evidence.reference() != payment_evidence_reference {
            return Err(LnurlCommentPersistenceError::PaymentEvidenceMismatch);
        }
        return Ok(existing);
    }

    let row = sqlx::query_as::<_, LnurlCommentIntentDbRow>(&format!(
        "UPDATE lnurl_comment_intents \
            SET payment_evidence_reference = $3 \
          WHERE owner_npub = $1 AND idempotency_key = $2 \
            AND instruction_rail = $4 \
            AND instruction_reference = $5 \
            AND payment_evidence_reference IS NULL \
            AND payment_evidenced_at IS NULL \
         RETURNING {INTENT_COLUMNS}"
    ))
    .bind(owner_npub)
    .bind(idempotency_key.as_str())
    .bind(payment_evidence_reference)
    .bind(instruction_rail.as_str())
    .bind(instruction_reference)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(LnurlCommentPersistenceError::PaymentEvidenceMismatch)?;
    row.try_into()
}

/// Evidence-gated projection for a route that has already authenticated the
/// merchant npub.
///
/// No anonymous/public handler calls this function. It deliberately excludes
/// every intent without payment evidence, so an abandoned comment cannot be
/// presented as received money.
pub async fn list_received_lnurl_comments_for_authenticated_merchant(
    pool: &PgPool,
    authenticated_owner_npub: &str,
    limit: u16,
) -> Result<Vec<LnurlCommentIntent>, LnurlCommentPersistenceError> {
    Ok(
        list_received_lnurl_comments_page_for_authenticated_merchant(
            pool,
            authenticated_owner_npub,
            1,
            limit,
        )
        .await?
        .intents,
    )
}

/// Evidence-gated, stably ordered page for an already-authenticated merchant.
///
/// Page bounds are enforced again here rather than trusting the HTTP layer.
/// `LIMIT page_size + 1` proves `has_more` without exposing an unbounded query,
/// and the UUID tie-break makes equal evidence timestamps deterministic.
pub async fn list_received_lnurl_comments_page_for_authenticated_merchant(
    pool: &PgPool,
    authenticated_owner_npub: &str,
    page: u16,
    page_size: u16,
) -> Result<AuthenticatedLnurlCommentHistoryPage, LnurlCommentPersistenceError> {
    validate_npub(authenticated_owner_npub)?;
    if page == 0 || page > MAX_AUTHENTICATED_HISTORY_PAGE_NUMBER {
        return Err(LnurlCommentPersistenceError::InvalidInput {
            field: "history_page",
        });
    }
    if page_size == 0 || page_size > MAX_AUTHENTICATED_HISTORY_PAGE_SIZE {
        return Err(LnurlCommentPersistenceError::InvalidInput {
            field: "history_page_size",
        });
    }
    let offset = i64::from(page - 1) * i64::from(page_size);
    let fetch_limit = i64::from(page_size) + 1;
    let rows = sqlx::query_as::<_, LnurlCommentIntentDbRow>(&format!(
        "SELECT {INTENT_COLUMNS} \
           FROM lnurl_comment_intents \
          WHERE owner_npub = $1 \
            AND payment_evidence_reference IS NOT NULL \
            AND payment_evidenced_at IS NOT NULL \
          ORDER BY payment_evidenced_at DESC, intent_id DESC \
          LIMIT $2 OFFSET $3"
    ))
    .bind(authenticated_owner_npub)
    .bind(fetch_limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;
    let has_more = rows.len() > usize::from(page_size);
    let intents = rows
        .into_iter()
        .take(usize::from(page_size))
        .map(TryInto::try_into)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(AuthenticatedLnurlCommentHistoryPage { intents, has_more })
}

async fn lock_intent(
    tx: &mut Transaction<'_, Postgres>,
    owner_npub: &str,
    idempotency_key: &LnurlCommentIntentKey,
) -> Result<(), LnurlCommentPersistenceError> {
    sqlx::query("SELECT pg_advisory_xact_lock($1, hashtext($2 || ':' || $3))")
        .bind(LNURL_COMMENT_LOCK_CLASS)
        .bind(owner_npub)
        .bind(idempotency_key.as_str())
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn select_intent_for_update(
    tx: &mut Transaction<'_, Postgres>,
    owner_npub: &str,
    idempotency_key: &LnurlCommentIntentKey,
) -> Result<Option<LnurlCommentIntentDbRow>, LnurlCommentPersistenceError> {
    Ok(sqlx::query_as::<_, LnurlCommentIntentDbRow>(&format!(
        "SELECT {INTENT_COLUMNS} \
           FROM lnurl_comment_intents \
          WHERE owner_npub = $1 AND idempotency_key = $2 \
          FOR UPDATE"
    ))
    .bind(owner_npub)
    .bind(idempotency_key.as_str())
    .fetch_optional(&mut **tx)
    .await?)
}

fn validate_new_intent(
    intent: &NewLnurlCommentIntent<'_>,
) -> Result<(), LnurlCommentPersistenceError> {
    validate_npub(intent.owner_npub)?;
    validate_nym(intent.nym)?;
    validate_amount(intent.amount_msat)
}

fn validate_npub(value: &str) -> Result<(), LnurlCommentPersistenceError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(LnurlCommentPersistenceError::InvalidInput {
            field: "owner_npub",
        })
    }
}

fn validate_nym(value: &str) -> Result<(), LnurlCommentPersistenceError> {
    let starts_and_ends_alphanumeric = value
        .bytes()
        .next()
        .zip(value.bytes().last())
        .is_some_and(|(first, last)| first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric());
    if starts_and_ends_alphanumeric
        && value.len() <= 32
        && value == value.trim()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        Ok(())
    } else {
        Err(LnurlCommentPersistenceError::InvalidInput { field: "nym" })
    }
}

fn validate_amount(value: u64) -> Result<(), LnurlCommentPersistenceError> {
    if value > 0 && value.is_multiple_of(1_000) && i64::try_from(value).is_ok() {
        Ok(())
    } else {
        Err(LnurlCommentPersistenceError::InvalidInput {
            field: "amount_msat",
        })
    }
}

fn validate_reference(
    value: &str,
    field: &'static str,
) -> Result<(), LnurlCommentPersistenceError> {
    if !value.is_empty() && value.len() <= REFERENCE_MAX_BYTES && value == value.trim() {
        Ok(())
    } else {
        Err(LnurlCommentPersistenceError::InvalidInput { field })
    }
}

fn map_stored_value_error(error: LnurlCommentStoredValueError) -> LnurlCommentPersistenceError {
    match error {
        LnurlCommentStoredValueError::IntentKey => corrupt("idempotency_key"),
        LnurlCommentStoredValueError::Rail => corrupt("instruction_rail"),
    }
}

const fn corrupt(field: &'static str) -> LnurlCommentPersistenceError {
    LnurlCommentPersistenceError::CorruptStoredValue { field }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_debug_redacts_all_free_text_and_correlation_values() {
        let secret_comment = "private table seven";
        let secret_reference = "provider-secret-reference";
        let comment = LnurlPayerComment::try_from(secret_comment.to_string()).unwrap();
        let intent = LnurlCommentIntent {
            intent_id: Uuid::from_u128(1),
            owner_npub: "a".repeat(64),
            nym: "alice".to_string(),
            idempotency_key: LnurlCommentIntentKey::from_digest([0xcd; 32]),
            amount_msat: 1_000,
            comment,
            instruction: Some(LnurlCommentInstruction {
                rail: LnurlCommentRail::Lightning,
                reference: secret_reference.to_string(),
                bound_at_unix: 1,
            }),
            payment_evidence: None,
            created_at_unix: 1,
        };
        let debug = format!("{intent:?}");
        assert!(!debug.contains(secret_comment));
        assert!(!debug.contains(secret_reference));
        assert!(!debug.contains(&"a".repeat(64)));
        assert!(!debug.contains(intent.idempotency_key().as_str()));
    }

    #[test]
    fn persisted_grapheme_count_must_match_exact_text() {
        let row = LnurlCommentIntentDbRow {
            intent_id: Uuid::from_u128(1),
            owner_npub: "a".repeat(64),
            nym: "alice".to_string(),
            idempotency_key: "b".repeat(64),
            amount_msat: 1_000,
            comment: "e\u{301}".to_string(),
            comment_grapheme_count: 2,
            instruction_rail: None,
            instruction_reference: None,
            payment_evidence_reference: None,
            created_at_unix: 1,
            instruction_bound_at_unix: None,
            payment_evidenced_at_unix: None,
        };
        assert!(matches!(
            LnurlCommentIntent::try_from(row),
            Err(LnurlCommentPersistenceError::CorruptStoredValue {
                field: "comment_grapheme_count"
            })
        ));
    }
}
