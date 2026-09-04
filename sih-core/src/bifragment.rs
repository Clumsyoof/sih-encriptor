use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BifragmentResult {
    pub fragment1_offset: u64,
    pub fragment1_size: u64,
    pub gap_offset: u64,
    pub gap_size: u64,
    pub fragment2_offset: u64,
    pub fragment2_size: u64,
    pub total_reconstructed_size: u64,
    pub confidence: u32,
    pub status: String,
    pub recovered_file_path: String,
    pub naive_file_path: String,
}

pub fn is_gap_sector(sector: &[u8]) -> bool {
    if sector.is_empty() {
        return true;
    }
    // Detect log text / ASCII cluster
    let ascii_count = sector
        .iter()
        .filter(|&&b| (32..=126).contains(&b) || b == b'\n' || b == b'\r')
        .count();
    if (ascii_count as f64 / sector.len() as f64) > 0.65 {
        return true;
    }

    // Detect all zeros
    if sector.iter().all(|&b| b == 0) {
        return true;
    }

    // Detect illegal markers in JPEG scan
    for i in 0..sector.len().saturating_sub(1) {
        if sector[i] == 0xFF {
            let next = sector[i + 1];
            // In scan data, only 0x00 (byte stuffing), 0xD0..=0xD7 (restart), and 0xD9 (EOI) are allowed
            if next != 0x00 && !(0xD0..=0xD7).contains(&next) && next != 0xD9 && next != 0xFF {
                return true;
            }
        }
    }

    false
}

pub fn recover_bifragment_jpeg<P: AsRef<Path>, Q: AsRef<Path>>(
    image_path: P,
    output_dir: Q,
    sector_size: usize,
    max_gap_sectors: usize,
) -> io::Result<Option<BifragmentResult>> {
    let output_dir = output_dir.as_ref();
    fs::create_dir_all(output_dir)?;

    let mut file = File::open(&image_path)?;
    let total_len = file.metadata()?.len();

    let mut offset: u64 = 0;
    let mut sector = vec![0u8; sector_size];

    while offset < total_len {
        file.seek(SeekFrom::Start(offset))?;
        let bytes_read = file.read(&mut sector)?;
        if bytes_read < 4 {
            break;
        }

        // Detect JPEG start: 0xFF, 0xD8, 0xFF
        if sector[0] == 0xFF && sector[1] == 0xD8 && sector[2] == 0xFF {
            // Find SOS marker (Start of Scan)
            let max_hdr = std::cmp::min(32 * 1024, total_len - offset) as usize;
            let mut hdr_buf = vec![0u8; max_hdr];
            file.seek(SeekFrom::Start(offset))?;
            let n = file.read(&mut hdr_buf)?;
            hdr_buf.truncate(n);

            let mut sos_offset = None;
            for i in 2..hdr_buf.len().saturating_sub(1) {
                if hdr_buf[i] == 0xFF && hdr_buf[i + 1] == 0xDA {
                    sos_offset = Some(offset + (i + 2) as u64);
                    break;
                }
            }

            if let Some(sos) = sos_offset {
                // The first sector entirely in scan data is the one after the SOS header
                let first_scan_sector = ((sos + sector_size as u64 - 1) / sector_size as u64) * sector_size as u64;
                let mut current_sector_offset = first_scan_sector;
                let mut found_gap = false;
                let mut frag1_end_offset = current_sector_offset;
                let mut is_intact = false;

                while current_sector_offset < total_len {
                    file.seek(SeekFrom::Start(current_sector_offset))?;
                    let sn = file.read(&mut sector)?;
                    if sn == 0 {
                        break;
                    }

                    // Check if this sector ends normally with EOI (contiguous)
                    if let Some(eoi_pos) = find_eoi(&sector[..sn]) {
                        is_intact = true;
                        let next_sector = ((current_sector_offset + eoi_pos as u64 + sector_size as u64 - 1)
                            / sector_size as u64)
                            * sector_size as u64;
                        offset = next_sector;
                        break;
                    }

                    // Check if this sector is a gap
                    if is_gap_sector(&sector[..sn]) {
                        found_gap = true;
                        frag1_end_offset = current_sector_offset;
                        break;
                    }

                    current_sector_offset += sector_size as u64;
                }

                if is_intact {
                    continue;
                }

                if found_gap {
                    let gap_start_offset = frag1_end_offset;
                    let frag1_len = gap_start_offset - offset;

                    let gap_limit = std::cmp::min(
                        total_len,
                        gap_start_offset + (max_gap_sectors * sector_size) as u64,
                    );

                    let mut cand_offset = gap_start_offset + sector_size as u64;
                    while cand_offset < gap_limit {
                        file.seek(SeekFrom::Start(cand_offset))?;
                        let sn = file.read(&mut sector)?;
                        if sn == 0 {
                            break;
                        }

                        // Check if candidate sector is a valid continuation
                        if !is_gap_sector(&sector[..sn]) {
                            if let Some(frag2_len) = scan_tail_for_eoi(&mut file, cand_offset, total_len, 64 * 1024)? {
                                let gap_size = cand_offset - gap_start_offset;
                                let frag2_offset = cand_offset;

                                let (recon_path, naive_path, total_size) = splice_and_write(
                                    &mut file,
                                    offset,
                                    frag1_len,
                                    gap_size,
                                    frag2_offset,
                                    frag2_len,
                                    output_dir,
                                )?;

                                let result = BifragmentResult {
                                    fragment1_offset: offset,
                                    fragment1_size: frag1_len,
                                    gap_offset: gap_start_offset,
                                    gap_size,
                                    fragment2_offset: frag2_offset,
                                    fragment2_size: frag2_len,
                                    total_reconstructed_size: total_size,
                                    confidence: 98,
                                    status: "RECONSTRUCTED_GAP_BRIDGED".to_string(),
                                    recovered_file_path: recon_path.to_string_lossy().to_string(),
                                    naive_file_path: naive_path.to_string_lossy().to_string(),
                                };

                                return Ok(Some(result));
                            }
                        }

                        cand_offset += sector_size as u64;
                    }
                }
            }
        }

        offset += sector_size as u64;
    }

    Ok(None)
}

fn find_eoi(data: &[u8]) -> Option<usize> {
    for i in 0..data.len().saturating_sub(1) {
        if data[i] == 0xFF && data[i + 1] == 0xD9 {
            return Some(i + 2);
        }
    }
    None
}

fn scan_tail_for_eoi(
    file: &mut File,
    start: u64,
    total_len: u64,
    max_scan: usize,
) -> io::Result<Option<u64>> {
    let to_read = std::cmp::min(max_scan as u64, total_len - start) as usize;
    let mut buf = vec![0u8; to_read];
    file.seek(SeekFrom::Start(start))?;
    let n = file.read(&mut buf)?;
    buf.truncate(n);

    for i in 0..buf.len().saturating_sub(1) {
        if buf[i] == 0xFF && buf[i + 1] == 0xD9 {
            return Ok(Some((i + 2) as u64));
        }
    }

    Ok(None)
}

fn splice_and_write(
    file: &mut File,
    frag1_start: u64,
    frag1_len: u64,
    gap_size: u64,
    frag2_start: u64,
    frag2_len: u64,
    output_dir: &Path,
) -> io::Result<(PathBuf, PathBuf, u64)> {
    // 1. Read Fragment 1
    let mut frag1 = vec![0u8; frag1_len as usize];
    file.seek(SeekFrom::Start(frag1_start))?;
    file.read_exact(&mut frag1)?;

    // 2. Read Fragment 2
    let mut frag2 = vec![0u8; frag2_len as usize];
    file.seek(SeekFrom::Start(frag2_start))?;
    file.read_exact(&mut frag2)?;

    // 3. Write Reconstructed File
    let reconstructed_file = output_dir.join("bifragment_reconstructed.jpg");
    let mut recon_out = File::create(&reconstructed_file)?;
    recon_out.write_all(&frag1)?;
    recon_out.write_all(&frag2)?;
    recon_out.flush()?;

    let total_size = frag1_len + frag2_len;

    // 4. Write Naive Broken File (which blindly reads through the corruption gap)
    let naive_file = output_dir.join("naive_carve_broken.jpg");
    let naive_total_len = frag1_len + gap_size + frag2_len;
    let mut naive_buf = vec![0u8; naive_total_len as usize];
    file.seek(SeekFrom::Start(frag1_start))?;
    let _ = file.read(&mut naive_buf);

    let mut naive_out = File::create(&naive_file)?;
    naive_out.write_all(&naive_buf)?;
    naive_out.flush()?;

    Ok((reconstructed_file, naive_file, total_size))
}
