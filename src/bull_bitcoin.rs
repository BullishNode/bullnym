//! Privacy-minimal Bull Bitcoin sell-to-fiat-balance boundary.
//!
//! This module deliberately does not model Bull Bitcoin accounts or generic
//! order history. Its only bearer capability creates a sell-to-balance order
//! and reads that exact key-created order. Persistent code stores the narrow
//! normalized projection defined here, never an upstream response body.

use async_trait::async_trait;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::config::BullBitcoinEncryptionKey;

pub const CREDENTIAL_ENCRYPTION_FORMAT_VERSION: i16 = 1;
pub const TERMS_VERSION: &str = "bull-bitcoin-fiat-settlement-v1";
pub const TERMS_REFERENCE: &str = "https://www.bullbitcoin.com/terms-of-service";

pub const COMMON_DISCLOSURE: &str = "By enabling fiat conversion, you agree to Bull Bitcoin's terms and conditions, agree that withdrawals are limited to the methods available for the currency you select, and agree that withdrawals may only be made to an account in your own name. If a full or partial conversion is below Bull Bitcoin's minimum amount, the conversion is overridden and the entire payment is sent to your Bitcoin wallet.";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Product {
    LightningAddress,
    PaymentPage,
    Pos,
    Invoice,
}

impl Product {
    pub const ALL: [Self; 4] = [
        Self::LightningAddress,
        Self::PaymentPage,
        Self::Pos,
        Self::Invoice,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LightningAddress => "lightning_address",
            Self::PaymentPage => "payment_page",
            Self::Pos => "pos",
            Self::Invoice => "invoice",
        }
    }
}

impl FromStr for Product {
    type Err = BullBitcoinError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "lightning_address" => Ok(Self::LightningAddress),
            "payment_page" => Ok(Self::PaymentPage),
            "pos" => Ok(Self::Pos),
            "invoice" => Ok(Self::Invoice),
            _ => Err(BullBitcoinError::InvalidProduct),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FiatCurrency {
    ARS,
    CAD,
    COP,
    CRC,
    EUR,
    MXN,
    USD,
}

impl FiatCurrency {
    pub const ALL: [Self; 7] = [
        Self::CAD,
        Self::EUR,
        Self::MXN,
        Self::CRC,
        Self::COP,
        Self::ARS,
        Self::USD,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ARS => "ARS",
            Self::CAD => "CAD",
            Self::COP => "COP",
            Self::CRC => "CRC",
            Self::EUR => "EUR",
            Self::MXN => "MXN",
            Self::USD => "USD",
        }
    }

    pub const fn disclosure(self) -> &'static str {
        match self {
            Self::CAD => "When converting funds to CAD, you will be able to withdraw your CAD balance to your own bank account via Interac e-Transfer, EFT, or Domestic Wire Transfer.",
            Self::EUR => "When converting funds to EUR, you will be able to withdraw your EUR balance to your own bank account via SEPA.",
            Self::MXN => "When converting funds to MXN, you will be able to withdraw your MXN balance to your own Mexican bank account via SPEI.",
            Self::CRC => "When converting funds to CRC, you will be able to withdraw your CRC balance to your own Costa Rican bank account via SINPE bank transfer or SINPE Móvil.",
            Self::COP => "When converting funds to COP, you will be able to withdraw your COP balance to your own Colombian bank account or Nequi account.",
            Self::ARS => "When converting funds to ARS, you will be able to withdraw your ARS balance to your own Argentine bank account via CBU/CVU bank transfer.",
            Self::USD => "You can only withdraw USD to a Costa Rican bank account via SINPE or to a Canadian bank account via Domestic Wire Transfer. Do not select USD if you do not agree to these withdrawal options. If you select USD and cannot use these withdrawal options, you can still convert your USD balance to Bitcoin.",
        }
    }
}

impl FromStr for FiatCurrency {
    type Err = BullBitcoinError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "ARS" => Ok(Self::ARS),
            "CAD" => Ok(Self::CAD),
            "COP" => Ok(Self::COP),
            "CRC" => Ok(Self::CRC),
            "EUR" => Ok(Self::EUR),
            "MXN" => Ok(Self::MXN),
            "USD" => Ok(Self::USD),
            _ => Err(BullBitcoinError::InvalidCurrency),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BitcoinNetwork {
    Bitcoin,
    Lightning,
    Liquid,
}

impl BitcoinNetwork {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bitcoin => "bitcoin",
            Self::Lightning => "lightning",
            Self::Liquid => "liquid",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BitcoinAmountSat(i64);

impl BitcoinAmountSat {
    pub fn new(value: i64) -> Result<Self, BullBitcoinError> {
        if value <= 0 || value > 2_100_000_000_000_000 {
            return Err(BullBitcoinError::InvalidBitcoinAmount);
        }
        Ok(Self(value))
    }

    pub const fn as_sat(self) -> i64 {
        self.0
    }

    /// Exact JSON-number token with at most eight fractional digits.
    pub fn btc_json_number(self) -> String {
        let whole = self.0 / 100_000_000;
        let remainder = self.0 % 100_000_000;
        if remainder == 0 {
            return whole.to_string();
        }
        let fractional = format!("{remainder:08}");
        format!("{whole}.{}", fractional.trim_end_matches('0'))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FiatAmountMinor(i64);

impl FiatAmountMinor {
    pub fn new(value: i64) -> Result<Self, BullBitcoinError> {
        if value <= 0 {
            return Err(BullBitcoinError::InvalidFiatAmount);
        }
        Ok(Self(value))
    }

    pub const fn as_minor(self) -> i64 {
        self.0
    }

    /// Parse an upstream JSON decimal exactly into two-decimal minor units.
    /// Scientific notation is accepted; excess non-zero precision is not.
    pub fn parse_json_decimal(value: &str) -> Result<Self, BullBitcoinError> {
        let (mantissa, exponent) = match value.find(['e', 'E']) {
            Some(index) => {
                let exponent = value[index + 1..]
                    .parse::<i32>()
                    .map_err(|_| BullBitcoinError::InvalidFiatAmount)?;
                (&value[..index], exponent)
            }
            None => (value, 0),
        };
        if mantissa.starts_with('-') || mantissa.starts_with('+') || mantissa.is_empty() {
            return Err(BullBitcoinError::InvalidFiatAmount);
        }
        let (whole, fractional) = mantissa.split_once('.').unwrap_or((mantissa, ""));
        if whole.is_empty()
            || !whole.bytes().all(|byte| byte.is_ascii_digit())
            || !fractional.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(BullBitcoinError::InvalidFiatAmount);
        }

        let mut digits = String::with_capacity(whole.len() + fractional.len() + 4);
        digits.push_str(whole);
        digits.push_str(fractional);
        let decimal_scale =
            i32::try_from(fractional.len()).map_err(|_| BullBitcoinError::InvalidFiatAmount)?;
        let minor_shift = exponent - decimal_scale + 2;
        if minor_shift >= 0 {
            digits.extend(std::iter::repeat_n(
                '0',
                usize::try_from(minor_shift).map_err(|_| BullBitcoinError::InvalidFiatAmount)?,
            ));
        } else {
            let remove =
                usize::try_from(-minor_shift).map_err(|_| BullBitcoinError::InvalidFiatAmount)?;
            if remove > digits.len() {
                if digits.bytes().any(|byte| byte != b'0') {
                    return Err(BullBitcoinError::InvalidFiatAmount);
                }
                return Err(BullBitcoinError::InvalidFiatAmount);
            }
            let split = digits.len() - remove;
            if digits[split..].bytes().any(|byte| byte != b'0') {
                return Err(BullBitcoinError::InvalidFiatAmount);
            }
            digits.truncate(split);
        }
        let trimmed = digits.trim_start_matches('0');
        let normalized = if trimmed.is_empty() { "0" } else { trimmed };
        let minor = normalized
            .parse::<i64>()
            .map_err(|_| BullBitcoinError::InvalidFiatAmount)?;
        Self::new(minor)
    }
}

/// A scoped key that is validated before it can enter a signed message or DB
/// encryption boundary. Its plaintext is zeroized on drop and never debugged.
pub struct ScopedApiKey(Zeroizing<String>);

impl ScopedApiKey {
    pub fn parse(value: String) -> Result<Self, BullBitcoinError> {
        let valid = value.len() == 69
            && value.starts_with("bbak-")
            && value[5..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if !valid || value.bytes().any(|byte| byte.is_ascii_control()) {
            let mut rejected = value;
            rejected.zeroize();
            return Err(BullBitcoinError::InvalidApiKey);
        }
        Ok(Self(Zeroizing::new(value)))
    }

    pub(crate) fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for ScopedApiKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ScopedApiKey(<redacted>)")
    }
}

#[derive(Clone)]
pub struct CredentialCipher {
    key: BullBitcoinEncryptionKey,
}

impl fmt::Debug for CredentialCipher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialCipher(<redacted>)")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedCredential {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 24],
    pub format_version: i16,
}

impl CredentialCipher {
    pub fn new(key: BullBitcoinEncryptionKey) -> Self {
        Self { key }
    }

    pub fn encrypt(
        &self,
        credential_id: Uuid,
        canonical_owner_npub: &str,
        plaintext: &ScopedApiKey,
    ) -> Result<EncryptedCredential, BullBitcoinError> {
        validate_canonical_npub(canonical_owner_npub)?;
        let cipher = XChaCha20Poly1305::new(self.key.expose().into());
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let associated_data = credential_associated_data(
            credential_id,
            canonical_owner_npub,
            CREDENTIAL_ENCRYPTION_FORMAT_VERSION,
        );
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext.expose().as_bytes(),
                    aad: &associated_data,
                },
            )
            .map_err(|_| BullBitcoinError::CredentialEncryption)?;
        let mut nonce_bytes = [0_u8; 24];
        nonce_bytes.copy_from_slice(&nonce);
        Ok(EncryptedCredential {
            ciphertext,
            nonce: nonce_bytes,
            format_version: CREDENTIAL_ENCRYPTION_FORMAT_VERSION,
        })
    }

    pub fn decrypt(
        &self,
        credential_id: Uuid,
        canonical_owner_npub: &str,
        encrypted: &EncryptedCredential,
    ) -> Result<ScopedApiKey, BullBitcoinError> {
        validate_canonical_npub(canonical_owner_npub)?;
        if encrypted.format_version != CREDENTIAL_ENCRYPTION_FORMAT_VERSION {
            return Err(BullBitcoinError::CredentialEncryption);
        }
        let cipher = XChaCha20Poly1305::new(self.key.expose().into());
        let associated_data = credential_associated_data(
            credential_id,
            canonical_owner_npub,
            encrypted.format_version,
        );
        let mut plaintext = cipher
            .decrypt(
                XNonce::from_slice(&encrypted.nonce),
                Payload {
                    msg: &encrypted.ciphertext,
                    aad: &associated_data,
                },
            )
            .map_err(|_| BullBitcoinError::CredentialEncryption)?;
        let value = match String::from_utf8(plaintext) {
            Ok(value) => value,
            Err(error) => {
                plaintext = error.into_bytes();
                plaintext.zeroize();
                return Err(BullBitcoinError::CredentialEncryption);
            }
        };
        ScopedApiKey::parse(value).map_err(|_| BullBitcoinError::CredentialEncryption)
    }
}

fn credential_associated_data(credential_id: Uuid, owner_npub: &str, version: i16) -> Vec<u8> {
    let mut data = Vec::with_capacity(16 + 64 + 34);
    data.extend_from_slice(b"bullnym-bull-bitcoin-key\0");
    data.extend_from_slice(&version.to_be_bytes());
    data.extend_from_slice(credential_id.as_bytes());
    data.extend_from_slice(owner_npub.as_bytes());
    data
}

fn validate_canonical_npub(value: &str) -> Result<(), BullBitcoinError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(BullBitcoinError::InvalidOwner);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateSellRequest {
    pub currency: FiatCurrency,
    pub network: BitcoinNetwork,
    pub bitcoin_amount: BitcoinAmountSat,
    pub use_payjoin: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PayerInstruction {
    Bitcoin { address_or_bip21: String },
    Lightning { bolt11: String },
    Liquid { confidential_address: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreatedSellOrder {
    pub order_id: Uuid,
    pub currency: FiatCurrency,
    pub network: BitcoinNetwork,
    pub requested_bitcoin: BitcoinAmountSat,
    pub instruction: PayerInstruction,
    pub expires_at_unix: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderObservation {
    pub order_id: Uuid,
    pub currency: FiatCurrency,
    pub order_status: String,
    pub payin_status: String,
    pub payout_status: String,
    pub actual_received_sat: Option<i64>,
    pub credited_fiat_minor: Option<FiatAmountMinor>,
    pub provider_final: bool,
}

#[async_trait]
pub trait BullBitcoinApi: Send + Sync {
    async fn create_sell_to_balance(
        &self,
        key: &ScopedApiKey,
        request: &CreateSellRequest,
    ) -> Result<CreatedSellOrder, BullBitcoinError>;

    async fn get_created_order(
        &self,
        key: &ScopedApiKey,
        order_id: Uuid,
    ) -> Result<OrderObservation, BullBitcoinError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BullBitcoinError {
    InvalidApiKey,
    InvalidOwner,
    InvalidProduct,
    InvalidCurrency,
    InvalidBitcoinAmount,
    InvalidFiatAmount,
    CredentialEncryption,
    Authentication,
    NotFound,
    Minimum,
    Maximum,
    Policy,
    Timeout,
    Transport,
    Upstream,
    MalformedResponse,
    Integrity,
}

impl fmt::Display for BullBitcoinError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidApiKey => "invalid scoped Bull Bitcoin API key",
            Self::InvalidOwner => "invalid canonical owner",
            Self::InvalidProduct => "unsupported fiat-settlement product",
            Self::InvalidCurrency => "unsupported fiat currency",
            Self::InvalidBitcoinAmount => "invalid Bitcoin amount",
            Self::InvalidFiatAmount => "invalid fiat amount",
            Self::CredentialEncryption => "Bull Bitcoin credential cryptography failed",
            Self::Authentication => "Bull Bitcoin credential is unavailable",
            Self::NotFound => "Bull Bitcoin order is unavailable",
            Self::Minimum => "amount is below the Bull Bitcoin minimum",
            Self::Maximum => "amount is above the Bull Bitcoin maximum",
            Self::Policy => "Bull Bitcoin declined this conversion",
            Self::Timeout => "Bull Bitcoin request timed out",
            Self::Transport => "Bull Bitcoin transport failed",
            Self::Upstream => "Bull Bitcoin request failed",
            Self::MalformedResponse => "Bull Bitcoin returned an unsupported response",
            Self::Integrity => "Bull Bitcoin order does not match its local binding",
        })
    }
}

impl std::error::Error for BullBitcoinError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key_material() -> BullBitcoinEncryptionKey {
        BullBitcoinEncryptionKey::parse_hex(&"11".repeat(32)).unwrap()
    }

    fn scoped_key() -> ScopedApiKey {
        ScopedApiKey::parse(format!("bbak-{}", "ab".repeat(32))).unwrap()
    }

    #[test]
    fn satoshi_amounts_encode_as_exact_json_numbers() {
        for (sat, expected) in [
            (1, "0.00000001"),
            (10, "0.0000001"),
            (100_000, "0.001"),
            (100_000_000, "1"),
            (210_000_001, "2.10000001"),
        ] {
            assert_eq!(
                BitcoinAmountSat::new(sat).unwrap().btc_json_number(),
                expected
            );
        }
    }

    #[test]
    fn fiat_decimal_conversion_is_exact_and_rejects_lost_precision() {
        for (decimal, minor) in [
            ("123.45", 12_345),
            ("123", 12_300),
            ("0.01", 1),
            ("1.2e2", 12_000),
            ("123.4500", 12_345),
        ] {
            assert_eq!(
                FiatAmountMinor::parse_json_decimal(decimal)
                    .unwrap()
                    .as_minor(),
                minor
            );
        }
        for invalid in ["0", "-1", "1.001", "0.001", "NaN", "1e100"] {
            assert!(FiatAmountMinor::parse_json_decimal(invalid).is_err());
        }
    }

    #[test]
    fn scoped_key_shape_is_closed_and_debug_is_redacted() {
        let key = scoped_key();
        assert_eq!(format!("{key:?}"), "ScopedApiKey(<redacted>)");
        for invalid in [
            format!("bbak-{}", "AB".repeat(32)),
            format!("bbak-{}", "ab".repeat(31)),
            format!("other-{}", "ab".repeat(32)),
            format!("bbak-{}\0", "ab".repeat(32)),
        ] {
            assert!(ScopedApiKey::parse(invalid).is_err());
        }
    }

    #[test]
    fn credential_encryption_binds_owner_id_and_version() {
        let cipher = CredentialCipher::new(test_key_material());
        let id = Uuid::new_v4();
        let owner = "11".repeat(32);
        let encrypted = cipher.encrypt(id, &owner, &scoped_key()).unwrap();
        assert_ne!(encrypted.ciphertext, scoped_key().expose().as_bytes());
        assert_eq!(
            cipher.decrypt(id, &owner, &encrypted).unwrap().expose(),
            scoped_key().expose()
        );
        assert!(cipher.decrypt(Uuid::new_v4(), &owner, &encrypted).is_err());
        assert!(cipher.decrypt(id, &"22".repeat(32), &encrypted).is_err());
        let mut corrupted = encrypted.clone();
        corrupted.ciphertext[0] ^= 1;
        assert!(cipher.decrypt(id, &owner, &corrupted).is_err());
        assert_eq!(format!("{cipher:?}"), "CredentialCipher(<redacted>)");
    }

    #[test]
    fn disclosures_cover_only_locked_currencies() {
        assert_eq!(FiatCurrency::ALL.len(), 7);
        for currency in FiatCurrency::ALL {
            assert!(!currency.disclosure().is_empty());
            assert_eq!(currency.as_str().parse::<FiatCurrency>().unwrap(), currency);
        }
    }
}
