#!/usr/bin/env python3
"""
patch_41_gpt_partition.py

Filesystem/partition integration, step 1 (per Part 6 / Part 18.10's
roadmap): GPT partition table parsing, built entirely against the
BlockDevice HAL abstraction (hal::registry::block_read/block_size), not
against drivers::nvme directly. This is the first real consumer of the
BlockDevice boundary patch_38 built.

Does four things:
  1. Creates kernel/src/fs/partition.rs (new file — aborts if it already
     exists, same "don't clobber" safety as patch_23's hal-file creation).
  2. Adds `pub mod partition;` to kernel/src/fs/mod.rs.
  3. Adds a new `gpttest` kshell command to main.rs, inserted right after
     the existing blockdevtest arm.
  4. Updates the help command's printed list to include gpttest.

Run from ~/nexus-os/kernel/src.
"""
import os
import sys

FS_DIR = "fs"
PARTITION_FILE = os.path.join(FS_DIR, "partition.rs")
MOD_FILE = os.path.join(FS_DIR, "mod.rs")
MAIN_FILE = "main.rs"

PARTITION_RS_CONTENT = '''//! GPT partition table parsing (patch_41 — filesystem/partition
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
//! Scope of this first patch, deliberately narrow (same "prefer the
//! smaller well-scoped step" principle that kept the NVMe I/O path capped
//! at <=4KB/single-namespace):
//!   - Parses the GPT header (LBA 1) and the partition entry array.
//!   - Does NOT verify the CRC32 checksums the spec requires (header CRC32
//!     at header offset 16, partition-array CRC32 at offset 88). This is a
//!     real, known, deliberately deferred gap, not an oversight — a GPT
//!     with a corrupted checksum will currently be accepted as valid. Do
//!     not treat this parser's output as authoritative for anything beyond
//!     kshell test verification until CRC32 validation is added as its own
//!     follow-up patch.
//!   - Does not parse the protective MBR at LBA 0 at all — GPT-vs-not-GPT
//!     disambiguation is entirely via the "EFI PART" signature at LBA 1.
//!   - Does not fall back to the backup GPT header (at the last LBA) if the
//!     primary header is bad — another explicitly deferred gap.

extern crate alloc;
use alloc::{string::String, vec, vec::Vec};

use crate::hal;

pub const GPT_SIGNATURE: [u8; 8] = *b"EFI PART";

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
    /// The header claims more entries than MAX_ENTRIES, or an entry size
    /// of 0 or > 512 bytes — treated as corrupt rather than trusted.
    ImplausibleHeader,
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

    let partition_entry_lba = u64_from_le(&hdr[72..80]);
    let num_entries = u32_from_le(&hdr[80..84]);
    let entry_size = u32_from_le(&hdr[84..88]);

    if num_entries > MAX_ENTRIES || entry_size == 0 || entry_size > 512 {
        return Err(GptError::ImplausibleHeader);
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
'''

MOD_OLD = """pub mod procfs;
pub mod tmpfs;
pub mod vfs;
pub mod elf;
pub mod initrd;"""

MOD_NEW = """pub mod procfs;
pub mod tmpfs;
pub mod vfs;
pub mod elf;
pub mod initrd;
pub mod partition;"""

HELP_OLD = '''        crate::kprint!("Commands: help meminfo version reboot ticks uptime syscalls scrubtest teardowntest multitest audittest heaptest isotest isofault wxtest guardtest captest permtest ipctest spawn restest conctest preempttest drawtest ownertest haltest pcitest mmiotest nvmeinittest identifytest nvmeiotest blockdevtest'''

HELP_NEW = '''        crate::kprint!("Commands: help meminfo version reboot ticks uptime syscalls scrubtest teardowntest multitest audittest heaptest isotest isofault wxtest guardtest captest permtest ipctest spawn restest conctest preempttest drawtest ownertest haltest pcitest mmiotest nvmeinittest identifytest nvmeiotest blockdevtest gpttest'''

DISPATCH_OLD = '''                Err(e) => crate::kprintln!("[blockdevtest] FAIL - hal::registry::block_write returned {:?}", e),
            }
        }
    } else if !b.is_empty() {'''

DISPATCH_NEW = '''                Err(e) => crate::kprintln!("[blockdevtest] FAIL - hal::registry::block_write returned {:?}", e),
            }
        }
    } else if b == b"gpttest" {
        crate::kprintln!("--- GPT partition table test (read-only, via BlockDevice HAL) ---");
        match fs::partition::read_gpt() {
            Ok(entries) => {
                crate::kprintln!("[gpttest] GPT signature valid, {} used partition entry(ies) found", entries.len());
                for (i, e) in entries.iter().enumerate() {
                    crate::kprintln!(
                        "[gpttest]   [{}] LBA {}..={} ({} blocks) name=\\"{}\\"",
                        i,
                        e.first_lba,
                        e.last_lba,
                        e.last_lba.saturating_sub(e.first_lba) + 1,
                        e.name
                    );
                }
                if entries.is_empty() {
                    crate::kprintln!("[gpttest] PASS - valid GPT signature, 0 used entries (empty/unpartitioned GPT disk)");
                } else {
                    crate::kprintln!("[gpttest] PASS - GPT parsed successfully");
                }
            }
            Err(e) => {
                crate::kprintln!("[gpttest] FAIL - read_gpt() returned {:?}", e);
                crate::kprintln!("[gpttest] (this is expected/PASS-equivalent if the attached disk has no GPT yet, e.g. a fresh qemu-img raw file - BadSignature means \\"no GPT found\\", not \\"parser broken\\")");
            }
        }
    } else if !b.is_empty() {'''


def patch_create_file(path, content):
    if os.path.exists(path):
        print(f"ABORT: {path} already exists. Nothing written.")
        return False
    with open(path, "w") as f:
        f.write(content)
    print(f"[patch_41] OK - created {path}")
    return True


def patch_replace(path, old, new, label):
    try:
        with open(path, "r") as f:
            content = f.read()
    except FileNotFoundError:
        print(f"ABORT: {path} not found in current directory")
        return False

    count = content.count(old)
    print(f"[patch_41] {label} match count in {path}: {count}")
    if count != 1:
        print(f"ABORT: expected exactly 1 match for {label}. Nothing written to {path}.")
        return False

    with open(path, "w") as f:
        f.write(content.replace(old, new))
    print(f"[patch_41] OK - patched {path} ({label})")
    return True


def main():
    if not os.path.isdir(FS_DIR):
        print(f"ABORT: {FS_DIR}/ not found — run this from kernel/src")
        sys.exit(1)

    ok = True
    ok &= patch_create_file(PARTITION_FILE, PARTITION_RS_CONTENT)
    ok &= patch_replace(MOD_FILE, MOD_OLD, MOD_NEW, "fs/mod.rs pub mod list")
    ok &= patch_replace(MAIN_FILE, HELP_OLD, HELP_NEW, "help string")
    ok &= patch_replace(MAIN_FILE, DISPATCH_OLD, DISPATCH_NEW, "gpttest dispatch arm")

    if not ok:
        print("[patch_41] ABORTED - one or more steps failed. Review output above.")
        sys.exit(1)

    print("[patch_41] All steps applied successfully.")


if __name__ == "__main__":
    main()
