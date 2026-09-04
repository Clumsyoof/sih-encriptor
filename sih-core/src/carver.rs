use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarvedItem {
    pub id: usize,
    pub offset: u64,
    pub file_type: String,
    pub size: u64,
    pub confidence: u32,
    pub is_fragmented: bool,
    pub gap_size: u64,
    pub details: String,
}

pub struct CarverOptions {
    pub sector_size: usize,
    pub max_file_size: u64,
}

impl Default for CarverOptions {
    fn default() -> Self {
        Self {
            sector_size: 512,
            max_file_size: 20 * 1024 * 1024, // 20 MB max per carved file
        }
    }
}

pub fn scan_and_carve<P: AsRef<Path>>(
    image_path: P,
    opts: &CarverOptions,
) -> io::Result<Vec<CarvedItem>> {
    let mut file = File::open(image_path)?;
    let total_len = file.metadata()?.len();
    let mut carved_items = Vec::new();

    let mut current_offset: u64 = 0;
    let mut sector_buf = vec![0u8; opts.sector_size];
    let mut item_counter: usize = 1;

    while current_offset < total_len {
        file.seek(SeekFrom::Start(current_offset))?;
        let bytes_read = file.read(&mut sector_buf)?;
        if bytes_read < 4 {
            break;
        }

        // 1. Check for JPEG Header (0xFF, 0xD8, 0xFF)
        if sector_buf[0] == 0xFF && sector_buf[1] == 0xD8 && sector_buf[2] == 0xFF {
            if let Some(item) = inspect_jpeg(&mut file, current_offset, total_len, item_counter, opts) {
                current_offset += ((item.size + opts.sector_size as u64 - 1) / opts.sector_size as u64) * opts.sector_size as u64;
                carved_items.push(item);
                item_counter += 1;
                continue;
            }
        }

        // 2. Check for PDF Header (%PDF-)
        if sector_buf.starts_with(b"%PDF-") {
            if let Some(item) = inspect_pdf(&mut file, current_offset, total_len, item_counter, opts) {
                current_offset += ((item.size + opts.sector_size as u64 - 1) / opts.sector_size as u64) * opts.sector_size as u64;
                carved_items.push(item);
                item_counter += 1;
                continue;
            }
        }

        // 3. Check for ZIP / DOCX Header (PK\x03\x04)
        if sector_buf.starts_with(&[0x50, 0x4B, 0x03, 0x04]) {
            if let Some(item) = inspect_zip(&mut file, current_offset, total_len, item_counter, opts) {
                current_offset += ((item.size + opts.sector_size as u64 - 1) / opts.sector_size as u64) * opts.sector_size as u64;
                carved_items.push(item);
                item_counter += 1;
                continue;
            }
        }

        current_offset += opts.sector_size as u64;
    }

    Ok(carved_items)
}

fn inspect_jpeg(
    file: &mut File,
    start_offset: u64,
    total_len: u64,
    id: usize,
    opts: &CarverOptions,
) -> Option<CarvedItem> {
    let max_read = std::cmp::min(opts.max_file_size, total_len - start_offset) as usize;
    let mut data = vec![0u8; max_read];

    if file.seek(SeekFrom::Start(start_offset)).is_err() {
        return None;
    }
    let read_bytes = file.read(&mut data).ok()?;
    data.truncate(read_bytes);

    if data.len() < 4 {
        return None;
    }

    let mut pos = 2; // after 0xFF, 0xD8
    let mut confidence = 50u32;
    let mut has_sof = false;
    let mut has_sos = false;
    let mut eoi_pos: Option<usize> = None;

    // Structural scan of JPEG segments
    while pos + 1 < data.len() {
        if data[pos] == 0xFF {
            let marker = data[pos + 1];
            // Skip fill bytes (0xFF 0xFF)
            if marker == 0xFF || marker == 0x00 {
                pos += 1;
                continue;
            }

            // SOF0 / SOF2 (Start of Frame)
            if marker == 0xC0 || marker == 0xC2 {
                has_sof = true;
                confidence = confidence.saturating_add(15);
            }
            // SOS (Start of Scan - image data starts here)
            else if marker == 0xDA {
                has_sos = true;
                confidence = confidence.saturating_add(15);
                pos += 2;
                // Once in entropy scan data, look for EOI (0xFF, 0xD9)
                while pos + 1 < data.len() {
                    if data[pos] == 0xFF && data[pos + 1] == 0xD9 {
                        eoi_pos = Some(pos + 2);
                        confidence = confidence.saturating_add(20);
                        break;
                    }
                    pos += 1;
                }
                break;
            }
            // EOI directly
            else if marker == 0xD9 {
                eoi_pos = Some(pos + 2);
                confidence = confidence.saturating_add(20);
                break;
            }

            // Other markers have length field: [pos+2, pos+3]
            if pos + 3 < data.len() {
                let length = ((data[pos + 2] as usize) << 8) | (data[pos + 3] as usize);
                if length >= 2 && pos + 2 + length <= data.len() {
                    pos += 2 + length;
                    continue;
                }
            }
        }
        pos += 1;
    }

    if let Some(end) = eoi_pos {
        let size = end as u64;
        let details = format!(
            "JPEG: Markers SOF0={}, SOS={}, EOI confirmed at +{}B",
            if has_sof { "OK" } else { "Missing" },
            if has_sos { "OK" } else { "Missing" },
            size
        );
        Some(CarvedItem {
            id,
            offset: start_offset,
            file_type: "JPEG".to_string(),
            size,
            confidence: std::cmp::min(100, confidence),
            is_fragmented: false,
            gap_size: 0,
            details,
        })
    } else {
        None
    }
}

fn inspect_pdf(
    file: &mut File,
    start_offset: u64,
    total_len: u64,
    id: usize,
    opts: &CarverOptions,
) -> Option<CarvedItem> {
    let max_read = std::cmp::min(opts.max_file_size, total_len - start_offset) as usize;
    let mut data = vec![0u8; max_read];

    if file.seek(SeekFrom::Start(start_offset)).is_err() {
        return None;
    }
    let read_bytes = file.read(&mut data).ok()?;
    data.truncate(read_bytes);

    // Look for %%EOF marker from back
    let eof_marker = b"%%EOF";
    let mut last_eof = None;

    for i in (0..data.len().saturating_sub(eof_marker.len())).rev() {
        if &data[i..i + eof_marker.len()] == eof_marker {
            // Include trailing newline/CR if any
            let mut end = i + eof_marker.len();
            while end < data.len() && (data[end] == b'\r' || data[end] == b'\n') {
                end += 1;
            }
            last_eof = Some(end);
            break;
        }
    }

    if let Some(end) = last_eof {
        let size = end as u64;
        let mut confidence = 75u32;
        // Check for "trailer" or "xref"
        if data[..end].windows(4).any(|w| w == b"xref") {
            confidence = confidence.saturating_add(20);
        }
        Some(CarvedItem {
            id,
            offset: start_offset,
            file_type: "PDF".to_string(),
            size,
            confidence: std::cmp::min(98, confidence),
            is_fragmented: false,
            gap_size: 0,
            details: format!("PDF Document: Valid %%EOF trailer at offset +{}B", size),
        })
    } else {
        None
    }
}

fn inspect_zip(
    file: &mut File,
    start_offset: u64,
    total_len: u64,
    id: usize,
    opts: &CarverOptions,
) -> Option<CarvedItem> {
    let max_read = std::cmp::min(opts.max_file_size, total_len - start_offset) as usize;
    let mut data = vec![0u8; max_read];

    if file.seek(SeekFrom::Start(start_offset)).is_err() {
        return None;
    }
    let read_bytes = file.read(&mut data).ok()?;
    data.truncate(read_bytes);

    // Look for End of Central Directory record: [0x50, 0x4B, 0x05, 0x06]
    let eocd = [0x50, 0x4B, 0x05, 0x06];
    let mut eocd_pos = None;

    for i in (0..data.len().saturating_sub(22)).rev() {
        if &data[i..i + 4] == &eocd {
            // EOCD record is 22 bytes + comment_length
            let comment_len = if i + 22 <= data.len() {
                ((data[i + 21] as usize) << 8) | (data[i + 20] as usize)
            } else {
                0
            };
            eocd_pos = Some(i + 22 + comment_len);
            break;
        }
    }

    if let Some(end) = eocd_pos {
        let size = std::cmp::min(end, data.len()) as u64;
        Some(CarvedItem {
            id,
            offset: start_offset,
            file_type: "ZIP/DOCX".to_string(),
            size,
            confidence: 92,
            is_fragmented: false,
            gap_size: 0,
            details: format!("ZIP Archive / DOCX Container: EOCD found at +{}B", size),
        })
    } else {
        None
    }
}

/// Extracts a carved item from the raw image and writes it to an output directory
pub fn extract_item<P: AsRef<Path>, Q: AsRef<Path>>(
    image_path: P,
    item: &CarvedItem,
    output_dir: Q,
) -> io::Result<std::path::PathBuf> {
    let output_dir = output_dir.as_ref();
    fs::create_dir_all(output_dir)?;

    let ext = match item.file_type.as_str() {
        "JPEG" => "jpg",
        "PDF" => "pdf",
        "ZIP/DOCX" => "zip",
        _ => "bin",
    };

    let filename = format!("recovered_{:04}_0x{:x}.{}", item.id, item.offset, ext);
    let target_path = output_dir.join(&filename);

    let mut src = File::open(image_path)?;
    src.seek(SeekFrom::Start(item.offset))?;

    let mut dest = File::create(&target_path)?;
    let mut remaining = item.size;
    let mut buf = vec![0u8; 64 * 1024];

    while remaining > 0 {
        let to_read = std::cmp::min(remaining, buf.len() as u64) as usize;
        let n = src.read(&mut buf[..to_read])?;
        if n == 0 {
            break;
        }
        dest.write_all(&buf[..n])?;
        remaining -= n as u64;
    }

    dest.flush()?;
    Ok(target_path)
}
