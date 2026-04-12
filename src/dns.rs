use crate::error::AppError;
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct EasyDnsClient {
    client: Client,
    base_url: String,
    zone_domain: String,
    api_key: String,
    api_token: String,
}

#[derive(Serialize)]
struct AddRecordRequest {
    host: String,
    #[serde(rename = "type")]
    record_type: String,
    rdata: String,
    ttl: u32,
}

#[derive(Deserialize)]
struct AddRecordResponse {
    data: RecordData,
}

#[derive(Deserialize)]
struct RecordData {
    id: String,
}

impl EasyDnsClient {
    pub fn new(
        base_url: &str,
        zone_domain: &str,
        api_key: &str,
        api_token: &str,
    ) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
            zone_domain: zone_domain.to_string(),
            api_key: api_key.to_string(),
            api_token: api_token.to_string(),
        }
    }

    /// Creates a BIP 353 TXT record for a nym.
    /// Returns the easyDNS record ID for later updates/deletes.
    pub async fn create_bip353_record(
        &self,
        nym: &str,
        liquid_address: &str,
    ) -> Result<String, AppError> {
        let host = format!("{nym}.user._bitcoin-payment");
        let rdata = format!("bitcoin:{liquid_address}");

        let url = format!(
            "{}/zones/records/add/{}/TXT",
            self.base_url, self.zone_domain
        );

        let resp = self
            .client
            .put(&url)
            .basic_auth(&self.api_key, Some(&self.api_token))
            .json(&AddRecordRequest {
                host,
                record_type: "TXT".to_string(),
                rdata,
                ttl: 3600,
            })
            .send()
            .await
            .map_err(|e| AppError::DnsError(format!("easyDNS request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(AppError::DnsError(format!(
                "easyDNS returned {status}: {body}"
            )));
        }

        let parsed: AddRecordResponse = resp
            .json()
            .await
            .map_err(|e| AppError::DnsError(format!("failed to parse easyDNS response: {e}")))?;

        Ok(parsed.data.id)
    }

    /// Updates an existing BIP 353 TXT record with a new Liquid address.
    pub async fn update_bip353_record(
        &self,
        record_id: &str,
        nym: &str,
        liquid_address: &str,
    ) -> Result<(), AppError> {
        let host = format!("{nym}.user._bitcoin-payment");
        let rdata = format!("bitcoin:{liquid_address}");

        let url = format!("{}/zones/records/{}", self.base_url, record_id);

        let resp = self
            .client
            .post(&url)
            .basic_auth(&self.api_key, Some(&self.api_token))
            .json(&AddRecordRequest {
                host,
                record_type: "TXT".to_string(),
                rdata,
                ttl: 3600,
            })
            .send()
            .await
            .map_err(|e| AppError::DnsError(format!("easyDNS update failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(AppError::DnsError(format!(
                "easyDNS update returned {status}: {body}"
            )));
        }

        Ok(())
    }

    /// Deletes a BIP 353 TXT record.
    pub async fn delete_record(&self, record_id: &str) -> Result<(), AppError> {
        let url = format!(
            "{}/zones/records/{}/{}",
            self.base_url, self.zone_domain, record_id
        );

        let resp = self
            .client
            .delete(&url)
            .basic_auth(&self.api_key, Some(&self.api_token))
            .send()
            .await
            .map_err(|e| AppError::DnsError(format!("easyDNS delete failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(AppError::DnsError(format!(
                "easyDNS delete returned {status}: {body}"
            )));
        }

        Ok(())
    }
}
