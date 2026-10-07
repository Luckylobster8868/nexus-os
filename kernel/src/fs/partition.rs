//! GPT partition table parsing (patches 41, 47 — filesystem/partition
//! integration, first step per Part 6/Part 18.10's roadmap).
//!
//! Reads the partition table through hal::registry::block_read() only —
//! never touches drivers::nvme directly. This is deliberate: it means this
//! code works unchanged once a second BlockDevice implementor (AHCI,
//! virtio-blk, ...) exists, matching hal/block.rs's own stated design
//! intent, and it is the first real consumer of the BlockDevice
//! abstraction boundary patch_38 built (previously only kshell tests
//! exercised it).
//!
//! Scope, deliberately narrow (same "prefer the smaller well-scoped
//! step" principle that kept the NVMe I/O path capped at <=4KB/single-
//! namespace):
//!   - Parses the GPT header (LBA 1) and the partition entry array.
//!   - CRC32 validation (patch_47) of BOTH the header (header offset 16,
//!     computed over the first HeaderSize bytes with the checksum field
//!     itself zeroed during calculation, per the UEFI spec) and the
//!     partition entry array (header offset 88, computed over the raw
//!     num_entries * entry_size bytes actually read) — a real, standard
//!     CRC-32/ISO-HDLC implementation (poly 0xEDB88320, the same
//!     algorithm zlib/Ethernet/PNG all use), NOT a stub. A checksum
//!     mismatch is now a hard error (BadHeaderChecksum /
//!     BadPartitionArrayChecksum), not silently accepted. This closes
//!     the real, previously-flagged gap noted in Part 19.8 item 1 — a
//!     corrupted GPT is rejected now, not trusted.
//!   - Does not parse the protective MBR at LBA 0 at all — GPT-vs-not-GPT
//!     disambiguation is entirely via the "EFI PART" signature at LBA 1.
//!   - Does not fall back to the backup GPT header (at the last LBA) if the
//!     primary header is bad (including if its own checksum fails) —
//!     another explicitly deferred gap. A bad primary header is a hard
//!     error, not something this parser silently recovers from.

extern crate alloc;
use alloc::{string::String, vec, vec::Vec};

use crate::hal;

pub const GPT_SIGNATURE: [u8; 8] = *b"EFI PART";

/// Standard CRC-32/ISO-HDLC (poly 0xEDB88320, the reversed form of the
/// well-known 0x04C11DB7 polynomial) — the exact algorithm the UEFI spec
/// mandates for both GPT checksum fields. Implemented bit-by-bit rather
/// than via a 256-entry lookup table, since this only ever runs over a
/// GPT header (92 bytes) and partition array (a few KB) once per mount —
/// not a hot path worth the extra static table for.
fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Hard cap on how many partition entries we'll ever parse, regardless of
/// what the header claims — a corrupt or malicious header could otherwise
/// claim an enormous entry count and cause an unbounded allocation. 128 is
/// the standard default entry count used by virtually all real GPT disks.
const MAX_ENTRIES: u32 = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GptError {
    /// hal::registry::block_size() returned 0 — no BlockDevice registered.
    NoBlockDevice,
    /// A block_read() call failed partway through.
    ReadError,
    /// LBA 1 did not contain the "EFI PART" signature — not a GPT disk
    /// (could be MBR-only, unpartitioned, or simply unformatted).
    BadSignature,
    /// block_size doesn't evenly divide 4096, so this parser's batched
    /// multi-block reads can't safely assume a whole number of blocks
    /// fits in one 4KB read_blocks() call.
    UnsupportedBlockSize,
    /// The header claims more entries than MAX_ENTRIES, an entry size of
    /// 0 or > 512 bytes, or a HeaderSize outside the sane 92..=512 range
    /// — treated as corrupt rather than trusted.
    ImplausibleHeader,
    /// The header's own CRC32 (offset 16) doesn't match a fresh
    /// computation over its first HeaderSize bytes (with the checksum
    /// field itself zeroed) — patch_47. The header is corrupt; nothing
    /// past this point is trusted.
    BadHeaderChecksum,
    /// The partition entry array's CRC32 (header offset 88) doesn't
    /// match a fresh computation over the actual bytes read — patch_47.
    /// The entry array is corrupt; its contents are not trusted.
    BadPartitionArrayChecksum,
}

#[derive(Debug, Clone)]
pub struct GptPartitionEntry {
    pub partition_type_guid: [u8; 16],
    pub unique_guid: [u8; 16],
    pub first_lba: u64,
    pub last_lba: u64,
    pub attributes: u64,
    /// Decoded from the on-disk UTF-16LE name field, stopping at the first
    /// NUL. Any UTF-16 code unit that doesn't map to a valid char is
    /// silently skipped rather than failing the whole parse.
    pub name: String,
}

fn u64_from_le(b: &[u8]) -> u64 {
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&b[0..8]);
    u64::from_le_bytes(arr)
}

fn u32_from_le(b: &[u8]) -> u32 {
    let mut arr = [0u8; 4];
    arr.copy_from_slice(&b[0..4]);
    u32::from_le_bytes(arr)
}

fn decode_utf16le_name(bytes: &[u8]) -> String {
    let mut s = String::new();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let unit = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
        if unit == 0 {
            break;
        }
        if let Some(c) = char::from_u32(unit as u32) {
            s.push(c);
        }
        i += 2;
    }
    s
}

/// Reads and parses the primary GPT partition table via the BlockDevice
/// HAL abstraction. Returns only "used" entries (an all-zero type GUID
/// means "unused slot" per spec and is filtered out).
pub fn read_gpt() -> Result<Vec<GptPartitionEntry>, GptError> {
    let block_size = hal::registry::block_size();
    if block_size == 0 {
        return Err(GptError::NoBlockDevice);
    }
    if block_size as usize > 4096 || 4096 % block_size as usize != 0 {
        return Err(GptError::UnsupportedBlockSize);
    }

    // --- GPT header, LBA 1 ---
    let mut hdr = vec![0u8; block_size as usize];
    hal::registry::block_read(1, &mut hdr).map_err(|_| GptError::ReadError)?;

    if &hdr[0..8] != GPT_SIGNATURE.as_slice() {
        return Err(GptError::BadSignature);
    }

    let header_size = u32_from_le(&hdr[12..16]);
    let stored_header_crc32 = u32_from_le(&hdr[16..20]);
    let partition_entry_lba = u64_from_le(&hdr[72..80]);
    let num_entries = u32_from_le(&hdr[80..84]);
    let entry_size = u32_from_le(&hdr[84..88]);
    let stored_array_crc32 = u32_from_le(&hdr[88..92]);

    // 92 is the spec-fixed GPT header size in every real implementation;
    // 512 is a generous upper bound (== the largest sector size this
    // parser's own UnsupportedBlockSize check would ever let through).
    // Anything outside that range is corrupt, not a legitimate variant.
    if header_size < 92 || header_size as usize > hdr.len() || header_size as usize > 512 {
        return Err(GptError::ImplausibleHeader);
    }
    if num_entries > MAX_ENTRIES || entry_size == 0 || entry_size > 512 {
        return Err(GptError::ImplausibleHeader);
    }

    // --- Header CRC32 (patch_47) ---
    // Per the UEFI spec: computed over the first HeaderSize bytes of the
    // header, with the HeaderCRC32 field itself (offset 16..20) temporarily
    // zeroed during the calculation. Done on a copy so the original bytes
    // (needed below for the fields already parsed above) aren't disturbed.
    let mut hdr_for_crc = hdr[..header_size as usize].to_vec();
    hdr_for_crc[16..20].copy_from_slice(&[0u8; 4]);
    if crc32(&hdr_for_crc) != stored_header_crc32 {
        return Err(GptError::BadHeaderChecksum);
    }

    // --- Partition entry array, starting at partition_entry_lba ---
    // io_read_blocks (and therefore block_read) caps a single call at
    // 4096 bytes, so the entry array (up to 128 * 128 = 16384 bytes) is
    // read in multiple sequential calls, each covering as many whole
    // blocks as fit in one 4KB page.
    let total_bytes = num_entries as usize * entry_size as usize;
    let blocks_per_call = (4096 / block_size as usize).max(1);
    let bytes_per_call = blocks_per_call * block_size as usize;

    let mut raw = Vec::with_capacity(total_bytes);
    let mut lba = partition_entry_lba;
    let mut remaining = total_bytes;
    while remaining > 0 {
        let this_call_bytes = remaining.min(bytes_per_call);
        let call_blocks = (this_call_bytes + block_size as usize - 1) / block_size as usize;
        let call_bytes = call_blocks * block_size as usize;

        let mut buf = vec![0u8; call_bytes];
        hal::registry::block_read(lba, &mut buf).map_err(|_| GptError::ReadError)?;

        let take = this_call_bytes.min(buf.len());
        raw.extend_from_slice(&buf[..take]);

        lba += call_blocks as u64;
        remaining = remaining.saturating_sub(this_call_bytes);
    }

    // --- Partition entry array CRC32 (patch_47) ---
    // Computed over exactly the total_bytes actually belonging to the
    // array (num_entries * entry_size) — `raw` is exactly that length by
    // construction of the read loop above, so no slicing is needed here.
    if crc32(&raw) != stored_array_crc32 {
        return Err(GptError::BadPartitionArrayChecksum);
    }

    let mut entries = Vec::new();
    for i in 0..num_entries as usize {
        let off = i * entry_size as usize;
        if off + 128 > raw.len() {
            break;
        }

        let type_guid_bytes = &raw[off..off + 16];
        if type_guid_bytes.iter().all(|&b| b == 0) {
            continue; // unused entry, per spec
        }

        let mut partition_type_guid = [0u8; 16];
        partition_type_guid.copy_from_slice(type_guid_bytes);
        let mut unique_guid = [0u8; 16];
        unique_guid.copy_from_slice(&raw[off + 16..off + 32]);

        let first_lba = u64_from_le(&raw[off + 32..off + 40]);
        let last_lba = u64_from_le(&raw[off + 40..off + 48]);
        let attributes = u64_from_le(&raw[off + 48..off + 56]);
        let name = decode_utf16le_name(&raw[off + 56..off + 128]);

        entries.push(GptPartitionEntry {
            partition_type_guid,
            unique_guid,
            first_lba,
            last_lba,
            attributes,
            name,
        });
    }

    Ok(entries)
}
