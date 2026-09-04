mod audit;
mod bifragment;
mod carver;
mod crypto_eraser;
mod disk_generator;
mod entropy;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "sih-core",
    about = "SIH26149: High-Performance Secure Data Erasure & Forensic Carver Engine (NTRO)",
    version = "0.1.0"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a synthetic raw disk image with planted contiguous and fragmented files
    MakeDisk {
        #[arg(short, long, default_value = "demo_disk.raw")]
        output: PathBuf,
        #[arg(short, long, default_value_t = 10)]
        size_mb: u64,
    },

    /// Securely wipe a file or partition using in-place AES-256 crypto-erase or multi-pass overwrite
    Erase {
        #[arg(short, long)]
        target: PathBuf,
        #[arg(short, long, default_value = "crypto")]
        mode: String,
        #[arg(long, default_value_t = false)]
        keep_file: bool,
        #[arg(short, long)]
        cert_out: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Scan a raw disk image and identify recoverable file artifacts
    Scan {
        #[arg(short, long)]
        image: PathBuf,
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Extract all carved artifacts from a raw disk image to an output directory
    Carve {
        #[arg(short, long)]
        image: PathBuf,
        #[arg(short, long, default_value = "./recovered")]
        output_dir: PathBuf,
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Run the advanced bifragment gap carver to reconstruct split non-contiguous files
    Bifragment {
        #[arg(short, long)]
        image: PathBuf,
        #[arg(short, long, default_value = "./recovered_bifragment")]
        output_dir: PathBuf,
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Compute Shannon entropy and analyze data randomness distribution
    Entropy {
        #[arg(short, long)]
        target: PathBuf,
        #[arg(short, long, default_value_t = 4096)]
        block_size: usize,
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Cryptographically verify an HMAC-SHA256 audit certificate
    VerifyCert {
        #[arg(short, long)]
        cert: PathBuf,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::MakeDisk { output, size_mb } => {
            println!("[+] Generating {}MB synthetic disk image: {:?}", size_mb, output);
            disk_generator::generate_demo_disk(&output, size_mb)?;
            println!("[✓] Disk created successfully with MBR, planted JPEG, PDF, and fragmented JPEG!");
        }

        Commands::Erase {
            target,
            mode,
            keep_file,
            cert_out,
            json,
        } => {
            let mode_enum: crypto_eraser::ErasureMode = mode.parse()
                .map_err(|e| format!("Invalid mode: {}", e))?;

            let result = match mode_enum {
                crypto_eraser::ErasureMode::CryptoErase => {
                    crypto_eraser::perform_crypto_erase(&target, keep_file)?
                }
                m => crypto_eraser::perform_multipass_erase(&target, m, keep_file)?,
            };

            if let Some(ref cert_path) = cert_out {
                result.certificate.save_to_file(cert_path)?;
            }

            if json {
                println!("{}", serde_json::to_string_pretty(&result.certificate)?);
            } else {
                println!("[✓] Secure Erasure Completed Successfully!");
                println!("    Target:           {}", result.certificate.target);
                println!("    Method:           {}", result.certificate.method);
                println!("    Pre-SHA256:       {}", result.certificate.pre_sha256);
                println!("    Post-SHA256:      {}", result.certificate.post_sha256);
                println!("    Pre-Entropy:      {:.4} / 8.0", result.certificate.pre_entropy);
                println!("    Post-Entropy:     {:.4} / 8.0 (Random/Ciphertext)", result.certificate.post_entropy);
                println!("    HMAC Signature:   {}", result.certificate.hmac_signature);
                if let Some(cert_path) = cert_out {
                    println!("    Certificate Saved: {:?}", cert_path);
                }
            }
        }

        Commands::Scan { image, json } => {
            let opts = carver::CarverOptions::default();
            let items = carver::scan_and_carve(&image, &opts)?;

            if json {
                println!("{}", serde_json::to_string_pretty(&items)?);
            } else {
                println!("[*] Scanning Raw Disk Image: {:?}", image);
                println!("----------------------------------------------------------------------------------");
                println!("{:<4} | {:<10} | {:<10} | {:<12} | {:<10} | {}", "ID", "Offset", "Type", "Size", "Confidence", "Details");
                println!("----------------------------------------------------------------------------------");
                for item in &items {
                    println!(
                        "{:<4} | 0x{:08x} | {:<10} | {:<12} | {:<9}% | {}",
                        item.id,
                        item.offset,
                        item.file_type,
                        format!("{} B", item.size),
                        item.confidence,
                        item.details
                    );
                }
                println!("----------------------------------------------------------------------------------");
                println!("[✓] Found {} recoverable file artifacts.", items.len());
            }
        }

        Commands::Carve {
            image,
            output_dir,
            json,
        } => {
            let opts = carver::CarverOptions::default();
            let items = carver::scan_and_carve(&image, &opts)?;
            let mut extracted = Vec::new();

            for item in &items {
                let path = carver::extract_item(&image, item, &output_dir)?;
                extracted.push((item.clone(), path));
            }

            if json {
                println!("{}", serde_json::to_string_pretty(&items)?);
            } else {
                println!("[✓] Extracted {} files to directory: {:?}", extracted.len(), output_dir);
                for (item, path) in &extracted {
                    println!("    [Extracted] #{} {} -> {:?}", item.id, item.file_type, path);
                }
            }
        }

        Commands::Bifragment {
            image,
            output_dir,
            json,
        } => {
            let res = bifragment::recover_bifragment_jpeg(&image, &output_dir, 512, 128)?;

            match res {
                Some(bifrag) => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&bifrag)?);
                    } else {
                        println!("[✓] BIFRAGMENT RECONSTRUCTION SUCCESSFUL!");
                        println!("    Fragment 1 Start:  0x{:08x} (Size: {} B)", bifrag.fragment1_offset, bifrag.fragment1_size);
                        println!("    Corruption Gap:    0x{:08x} (Size: {} B)", bifrag.gap_offset, bifrag.gap_size);
                        println!("    Fragment 2 Start:  0x{:08x} (Size: {} B)", bifrag.fragment2_offset, bifrag.fragment2_size);
                        println!("    Total Size:        {} B", bifrag.total_reconstructed_size);
                        println!("    Confidence Score:  {}%", bifrag.confidence);
                        println!("    Recovered Intact:  {}", bifrag.recovered_file_path);
                        println!("    Naive Broken File: {}", bifrag.naive_file_path);
                    }
                }
                None => {
                    if json {
                        println!("null");
                    } else {
                        println!("[-] No fragmented JPEGs detected in image.");
                    }
                }
            }
        }

        Commands::Entropy {
            target,
            block_size,
            json,
        } => {
            let (overall, sectors) = entropy::analyze_file_entropy(&target, block_size)?;
            if json {
                let res = serde_json::json!({
                    "overall_entropy": overall,
                    "sector_count": sectors.len(),
                    "block_size": block_size,
                    "sectors": sectors
                });
                println!("{}", serde_json::to_string_pretty(&res)?);
            } else {
                println!("[*] Entropy Analysis: {:?}", target);
                println!("    Overall Shannon Entropy: {:.4} / 8.0000", overall);
                println!("    Analyzed {} blocks of {} bytes each.", sectors.len(), block_size);
                if overall > 7.9 {
                    println!("    Classification: High Entropy (Encrypted Ciphertext / Compressed Data / Random)");
                } else if overall > 5.0 {
                    println!("    Classification: Moderate Entropy (Document / Standard Executable / Rich Media)");
                } else {
                    println!("    Classification: Low Entropy (Plaintext / Sparse / Unallocated Zeroes)");
                }
            }
        }

        Commands::VerifyCert { cert } => {
            let cert_obj = audit::ErasureCertificate::load_from_file(&cert)?;
            let valid = cert_obj.verify(audit::DEFAULT_AGENCY_KEY);

            println!("[*] Verifying Erasure Certificate: {:?}", cert);
            println!("    Operation UUID: {}", cert_obj.operation_id);
            println!("    Target:         {}", cert_obj.target);
            println!("    Timestamp:      {}", cert_obj.timestamp);
            println!("    HMAC:           {}", cert_obj.hmac_signature);
            if valid {
                println!("[✓] CERTIFICATE INTEGRITY VERIFIED: Valid HMAC-SHA256 (Untampered)");
            } else {
                println!("[✗] ALERT: CERTIFICATE TAMPERED OR INVALID SIGNATURE!");
            }
        }
    }

    Ok(())
}
