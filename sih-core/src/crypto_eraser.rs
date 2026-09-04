use aes::Aes256;
use cipher::{KeyIvInit, StreamCipher};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

use crate::audit::{ErasureCertificate, DEFAULT_AGENCY_KEY};
use crate::entropy::{analyze_file_entropy, calculate_entropy};

type Aes256Ctr128 = ctr::Ctr128BE<Aes256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErasureMode {
    CryptoErase,
    NistZero,
    DoD3Pass,
}

impl std::str::FromStr for ErasureMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "crypto" | "crypto-erase" => Ok(ErasureMode::CryptoErase),
            "zero" | "nist" => Ok(ErasureMode::NistZero),
            "dod" | "dod3pass" => Ok(ErasureMode::DoD3Pass),
            other => Err(format!("Unknown erasure mode: {}", other)),
        }
    }
}

pub struct ErasureResult {
    pub certificate: ErasureCertificate,
    pub target_wiped: bool,
}

pub fn perform_crypto_erase<P: AsRef<Path>>(
    path: P,
    keep_file: bool,
) -> io::Result<ErasureResult> {
    let path = path.as_ref();
    let file_size = fs::metadata(path)?.len();

    // 1. Pre-erasure SHA-256 and Entropy
    let (pre_entropy, _) = analyze_file_entropy(path, 64 * 1024)?;
    let pre_sha256 = compute_file_sha256(path)?;

    // 2. Generate Ephemeral AES-256 Key (32 bytes) and Nonce (16 bytes)
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut key);
    OsRng.fill_bytes(&mut nonce);

    // 3. Open in read/write mode
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    file.seek(SeekFrom::Start(0))?;

    let mut cipher = Aes256Ctr128::new(&key.into(), &nonce.into());

    let mut buffer = vec![0u8; 64 * 1024];
    let mut current_offset: u64 = 0;

    while current_offset < file_size {
        file.seek(SeekFrom::Start(current_offset))?;
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }

        // In-place encryption
        cipher.apply_keystream(&mut buffer[..bytes_read]);

        // Write back to the exact same offset
        file.seek(SeekFrom::Start(current_offset))?;
        file.write_all(&mut buffer[..bytes_read])?;

        current_offset += bytes_read as u64;
    }

    // Force flush to physical blocks (bypass page cache)
    file.sync_all()?;
    drop(file);

    // 4. Securely destroy cryptographic keys in RAM
    key.zeroize();
    nonce.zeroize();

    // 5. Post-erasure SHA-256 and Entropy (proves random ciphertext)
    let (post_entropy, _) = analyze_file_entropy(path, 64 * 1024)?;
    let post_sha256 = compute_file_sha256(path)?;

    // 6. Metadata Residue Scrubbing (if not keeping file for demo inspection)
    if !keep_file && fs::metadata(path)?.is_file() {
        scrub_metadata_and_unlink(path)?;
    }

    let certificate = ErasureCertificate::new(
        &path.to_string_lossy(),
        file_size,
        "AES-256-Crypto-Erase",
        &pre_sha256,
        &post_sha256,
        pre_entropy,
        post_entropy,
        1,
        DEFAULT_AGENCY_KEY,
    );

    Ok(ErasureResult {
        certificate,
        target_wiped: true,
    })
}

pub fn perform_multipass_erase<P: AsRef<Path>>(
    path: P,
    mode: ErasureMode,
    keep_file: bool,
) -> io::Result<ErasureResult> {
    let path = path.as_ref();
    let file_size = fs::metadata(path)?.len();

    let (pre_entropy, _) = analyze_file_entropy(path, 64 * 1024)?;
    let pre_sha256 = compute_file_sha256(path)?;

    let passes = match mode {
        ErasureMode::NistZero => 1,
        ErasureMode::DoD3Pass => 3,
        _ => 1,
    };

    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    let chunk_size = 64 * 1024;
    let mut buffer = vec![0u8; chunk_size];

    for pass in 1..=passes {
        file.seek(SeekFrom::Start(0))?;
        let mut written: u64 = 0;

        let fill_byte: Option<u8> = match (mode, pass) {
            (ErasureMode::NistZero, _) => Some(0x00),
            (ErasureMode::DoD3Pass, 1) => Some(0x00),
            (ErasureMode::DoD3Pass, 2) => Some(0xFF),
            (ErasureMode::DoD3Pass, 3) => None, // Random
            _ => Some(0x00),
        };

        while written < file_size {
            let to_write = std::cmp::min(chunk_size as u64, file_size - written) as usize;
            let slice = &mut buffer[..to_write];

            if let Some(b) = fill_byte {
                slice.fill(b);
            } else {
                OsRng.fill_bytes(slice);
            }

            file.write_all(slice)?;
            written += to_write as u64;
        }
        file.sync_all()?;
    }
    drop(file);

    let (post_entropy, _) = analyze_file_entropy(path, 64 * 1024)?;
    let post_sha256 = compute_file_sha256(path)?;

    if !keep_file && fs::metadata(path)?.is_file() {
        scrub_metadata_and_unlink(path)?;
    }

    let method_name = match mode {
        ErasureMode::NistZero => "NIST-SP-800-88-Clear-Zero",
        ErasureMode::DoD3Pass => "DoD-5220.22-M-3Pass",
        _ => "Multi-Pass-Overwrite",
    };

    let certificate = ErasureCertificate::new(
        &path.to_string_lossy(),
        file_size,
        method_name,
        &pre_sha256,
        &post_sha256,
        pre_entropy,
        post_entropy,
        passes,
        DEFAULT_AGENCY_KEY,
    );

    Ok(ErasureResult {
        certificate,
        target_wiped: true,
    })
}

/// Scrub directory entry filename and unlink
fn scrub_metadata_and_unlink(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        // Obfuscate file name before unlinking to prevent directory table salvage
        let mut random_name = [0u8; 16];
        OsRng.fill_bytes(&mut random_name);
        let hex_name = crate::audit::hex::encode(random_name);
        let temp_path = parent.join(format!(".wiped_{}", hex_name));

        let _ = fs::rename(path, &temp_path);
        // Truncate to 0
        let file = OpenOptions::new().write(true).truncate(true).open(&temp_path)?;
        drop(file);
        fs::remove_file(temp_path)?;
    } else {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn compute_file_sha256<P: AsRef<Path>>(path: P) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(crate::audit::hex::encode(hasher.finalize()))
}
