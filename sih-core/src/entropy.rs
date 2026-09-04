use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

/// Calculate Shannon entropy for a byte slice:
/// H = -sum(p_i * log2(p_i)) for i in 0..=255
/// Returns value between 0.0 (uniform/zero) and 8.0 (completely random / encrypted)
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }

    let total = data.len() as f64;
    let mut entropy = 0.0;

    for &count in counts.iter() {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Computes average entropy and sector-by-sector entropy over a file or block device
pub fn analyze_file_entropy<P: AsRef<Path>>(
    path: P,
    block_size: usize,
) -> io::Result<(f64, Vec<f64>)> {
    let mut file = File::open(path)?;
    let mut buffer = vec![0u8; block_size];
    let mut sector_entropies = Vec::new();
    let mut total_counts = [0usize; 256];
    let mut total_bytes = 0usize;

    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }

        for &b in &buffer[..bytes_read] {
            total_counts[b as usize] += 1;
        }
        total_bytes += bytes_read;

        let block_ent = calculate_entropy(&buffer[..bytes_read]);
        sector_entropies.push(block_ent);
    }

    if total_bytes == 0 {
        return Ok((0.0, sector_entropies));
    }

    let mut overall_entropy = 0.0;
    let total_f = total_bytes as f64;
    for &count in total_counts.iter() {
        if count > 0 {
            let p = count as f64 / total_f;
            overall_entropy -= p * p.log2();
        }
    }

    Ok((overall_entropy, sector_entropies))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_entropy() {
        let zeroes = vec![0u8; 1024];
        assert_eq!(calculate_entropy(&zeroes), 0.0);
    }

    #[test]
    fn test_random_entropy() {
        use rand::RngCore;
        let mut data = vec![0u8; 65536];
        rand::thread_rng().fill_bytes(&mut data);
        let ent = calculate_entropy(&data);
        assert!(ent > 7.95, "Entropy should be close to 8.0, got {}", ent);
    }
}
