use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs;
use std::path::Path;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

pub const DEFAULT_AGENCY_KEY: &[u8] = b"NTRO-SIH26149-FORENSIC-AUDIT-KEY-2026";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ErasureCertificate {
    pub operation_id: String,
    pub timestamp: String,
    pub target: String,
    pub target_size_bytes: u64,
    pub method: String,
    pub pre_sha256: String,
    pub post_sha256: String,
    pub pre_entropy: f64,
    pub post_entropy: f64,
    pub passes_completed: u32,
    pub status: String,
    pub hmac_signature: String,
}

impl ErasureCertificate {
    pub fn new(
        target: &str,
        size: u64,
        method: &str,
        pre_sha256: &str,
        post_sha256: &str,
        pre_entropy: f64,
        post_entropy: f64,
        passes: u32,
        secret_key: &[u8],
    ) -> Self {
        let op_id = Uuid::new_v4().to_string();
        let timestamp = Utc::now().to_rfc3339();

        let mut cert = Self {
            operation_id: op_id,
            timestamp,
            target: target.to_string(),
            target_size_bytes: size,
            method: method.to_string(),
            pre_sha256: pre_sha256.to_string(),
            post_sha256: post_sha256.to_string(),
            pre_entropy,
            post_entropy,
            passes_completed: passes,
            status: "SUCCESS".to_string(),
            hmac_signature: String::new(),
        };

        cert.hmac_signature = cert.compute_hmac(secret_key);
        cert
    }

    fn canonical_string(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}:{}:{}:{:.4}:{:.4}:{}:{}",
            self.operation_id,
            self.timestamp,
            self.target,
            self.target_size_bytes,
            self.method,
            self.pre_sha256,
            self.post_sha256,
            self.pre_entropy,
            self.post_entropy,
            self.passes_completed,
            self.status
        )
    }

    pub fn compute_hmac(&self, secret_key: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(secret_key)
            .expect("HMAC can take key of any size");
        mac.update(self.canonical_string().as_bytes());
        let result = mac.finalize();
        hex::encode(result.into_bytes())
    }

    pub fn verify(&self, secret_key: &[u8]) -> bool {
        let expected = self.compute_hmac(secret_key);
        // Constant-time check could be used, hex string comparison is fine for demo
        expected == self.hmac_signature
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)
    }

    pub fn load_from_file<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let content = fs::read_to_string(path)?;
        let cert: Self = serde_json::from_str(&content)?;
        Ok(cert)
    }
}

// Simple hex encoder to avoid extra crate if possible
pub mod hex {
    pub fn encode(data: impl AsRef<[u8]>) -> String {
        data.as_ref()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }
}
