//! ext2 filesystem driver (patches 42, 45, 46, 47 read-only work; patch_48
//! adds a first, deliberately narrow write slice).
//!
//! Written fresh against this project's own hal::registry::block_read()/
//! block_write() (the BlockDevice HAL abstraction, not drivers::nvme
//! directly), with on-disk field layouts cross-checked against the OSDev
//! wiki's ext2 page and Linux's fs/ext2/ext2.h — the same "external
//! reference as cross-check, not copy source" role Redox's nvmed played
//! for the NVMe driver (see Part 4 bug #31's closing note in this
//! project's own log).
//!
//! Scope, deliberately narrow (same principle that capped the NVMe I/O
//! path at <=4KB/single-namespace, and left GPT CRC32 validation for its
//! own follow-up rather than bundling it with the original GPT parser):
//!   - Direct blocks (i_block[0..12]) AND singly-indirect (i_block[12])
//!     are supported as of patch_46 — see block_pointers(). Doubly and
//!     triply indirect (i_block[13], i_block[14]) are NOT — a file or
//!     directory needing those returns FileTooLarge. The cap is
//!     (12 + block_size/4) * block_size — e.g. roughly 1MB at the common
//!     4096-byte block size, comfortably covering "nearly all real-world
//!     small files" per this project's own sizing note (Part 19.8 item 3).
//!   - Multi-level path resolution (resolve_path(), patch_45) IS supported
//!     — "/a/b/c" walks directory-by-directory from root. lookup_in_root()
//!     remains as a thin single-segment convenience wrapper, not a scope
//!     limit anymore.
//!   - GPT header + partition-array CRC32 are validated (patch_47, in
//!     fs/partition.rs, not this file) before any of this module's own
//!     code ever runs against the partition it's handed.
//!   - WRITE SUPPORT (patch_48 in-place; patch_49 adds real block
//!     allocation for growth) is deliberately narrow, per this project's
//!     own explicit sizing note that this item is "comparable in total
//!     scope to everything already built for ext2's read path so far"
//!     and should not be combined with anything else:
//!       * write_file_in_place() overwrites an EXISTING regular file's
//!         content. If the new content fits within blocks the inode
//!         ALREADY owns (a contiguous run of already-nonzero block
//!         pointers starting at i_block[0] — see
//!         allocated_prefix_capacity()), no allocation happens at all
//!         (patch_48's original behaviour, unchanged).
//!       * If the new content needs MORE space, the growth path allocates
//!         real blocks one at a time (allocate_one_block(), a genuine
//!         block-bitmap scan/set/free-count-decrement across every block
//!         group on the filesystem — not a single-group simplification):
//!         first filling any remaining empty DIRECT slots (i_block[0..12]),
//!         then — if still more are needed — allocating the indirect
//!         block itself (patch_52) and writing further pointers into it.
//!         i_size may grow or shrink freely within the resulting capacity.
//!       * Indirect-block ALLOCATION (patch_52) IS supported now — a file
//!         can grow past 12 direct blocks by having its indirect block
//!         allocated for real, not just read through if one already
//!         exists (patch_46's read-side support). Only doubly/triply
//!         indirect remain out of scope — a file that would need those
//!         returns FileTooLarge, the same error the read side already
//!         used for that boundary.
//!       * File CREATION (patch_50) is real: create_file() allocates a
//!         fresh inode (allocate_one_inode(), the inode-bitmap
//!         counterpart to block allocation) and inserts a new directory
//!         entry for it (insert_dir_entry()) by reusing trailing slack in
//!         an EXISTING directory entry's rec_len — real ext2 directories
//!         routinely have this slack (mke2fs pads the last entry per
//!         block out to the block boundary). Wired in via
//!         Ext2Filesystem::write_owned() (which vfs::write() always calls
//!         — see fs/vfs.rs), which now dispatches to either an overwrite
//!         of an existing file or a real create-then-write, whichever the
//!         target path calls for.
//!       * Directory GROWTH (patch_53): when insert_dir_entry() finds no
//!         existing block with enough slack, it now allocates the
//!         directory a new block via the same grow_inode_to_block_count()
//!         primitive write_file_in_place()'s own growth uses (shared, not
//!         duplicated), initializes that new block as one giant free
//!         (ino=0) entry spanning the whole block, and retries — which
//!         always succeeds against the fresh block. Only returns
//!         DirectoryFull once the directory has reached direct+indirect
//!         capacity and genuinely cannot grow further.
//!       * File DELETION (patch_51) is real, for a regular file only:
//!         delete_file() frees every data block the file owned (including
//!         its singly-indirect block itself, not just the pointers inside
//!         it), zeroes and frees its inode, and removes its directory
//!         entry via remove_dir_entry() — which merges the freed space
//!         into the preceding entry in the same block when possible (the
//!         standard ext2 technique), or leaves a fully-free (ino=0) slot
//!         in place when the deleted entry was first in its block, since
//!         insert_dir_entry() was updated in this same patch to recognize
//!         and directly reuse such a slot. Wired in via
//!         Ext2Filesystem::remove() (a new Filesystem trait method,
//!         patch_51, defaulting to PermissionDenied for every other
//!         backend) and a new fs::vfs::remove() free function.
//!       * Directory DELETION (patch_54): delete_directory() removes an
//!         EMPTY directory (refusing with DirectoryNotEmpty otherwise) —
//!         frees its blocks and inode the same way delete_file() does,
//!         removes its entry from its parent, decrements the parent's
//!         i_links_count by 1 (accounting for the deleted directory's own
//!         ".." link to it), and decrements the owning block group's
//!         bg_used_dirs_count (a field this driver had never touched
//!         before — see decrement_group_used_dirs()'s own doc). Recursive
//!         deletion of a non-empty directory is NOT supported — the
//!         caller must empty it first, matching a real `rmdir`.
//!         Ext2Filesystem::remove() now checks the target's actual type
//!         and dispatches to delete_file() or delete_directory()
//!         accordingly.
//!       * NO inode-record field beyond i_mode/i_uid/i_size/i_gid/
//!         i_links_count/i_block is ever read or written by anything in
//!         this module (creation, growth, or deletion) — timestamps,
//!         extended attributes, and anything past the 128-byte minimum
//!         inode size are simply left at whatever they already were.
//!       * CRASH-SAFETY (patch_55) — real, scoped ordering fixes, NOT a
//!         journal (still no atomicity — every allocation/free/creation/
//!         deletion is several separate write_bytes_at() calls, and a
//!         power loss mid-sequence is still possible). What patch_55
//!         actually did: audited every multi-step write sequence in this
//!         arc for what a crash mid-sequence could leave behind, and
//!         reordered the ones that could leave something genuinely
//!         DANGEROUS (a dangling reference, or a directory block that
//!         gets misparsed as structure) rather than merely wasteful:
//!           - delete_file() / delete_directory() now remove the
//!             directory entry FIRST, before freeing any blocks or the
//!             inode — the reverse of their original patch_51/patch_54
//!             order. Freeing first would leave a live entry pointing at
//!             blocks the bitmap says are free; if anything reallocated
//!             them before the entry was cleaned up, reading through
//!             that stale entry would return a DIFFERENT file's data —
//!             not just a leak, real data confusion. Entry-first means a
//!             crash from that point on can only ever leak resources.
//!           - insert_dir_entry()'s directory-growth path now allocates
//!             a raw block, writes its full "one giant free entry"
//!             content, and only THEN links it into the directory's
//!             inode — the reverse of allocate-then-link. Freed blocks
//!             are never zeroed (by design), so a block made reachable
//!             before being initialized could hold stale data from
//!             whatever used it last, and read_dir_entries() would
//!             misparse that stale data as real directory-entry
//!             structure. Content-first-then-link means a crash before
//!             linking just leaks an allocated-but-unlinked block.
//!           - Everything else audited was already safe by construction
//!             and needed no change — see allocate_one_block()'s,
//!             allocate_one_inode()'s, grow_inode_to_block_count()'s,
//!             and create_file()'s own doc comments for the specific
//!             reasoning in each case (bit-before-counts is self-healing;
//!             initialize-then-publish for a fresh inode already means a
//!             crash only ever leaks, never dangles; i_size is always
//!             advanced last, after content, never before).
//!         What this does NOT provide: true atomicity (a crash can still
//!         interrupt a bitmap-bit write itself, or leave counts stale —
//!         both fsck-fixable, neither dangerous) or a journal/write-ahead
//!         log. Real crash-injection testing (a QEMU restart-mid-write
//!         harness) remains out of scope — this patch is an ordering
//!         audit verified by code review and the full regression suite,
//!         not by actually simulating power loss.
//!     Indirect-block allocation, directory growth, directory deletion,
//!     and now the real crash-safety hazards — all previously on this
//!     list — were closed in patches 52, 53, 54, and 55 respectively.
//!   - No symlink handling.
//!   - Only the first 128 bytes of each inode are read/written, which
//!     covers every field this module uses regardless of the on-disk
//!     s_inode_size (128 is the spec-guaranteed minimum) — extended inode
//!     fields beyond that (e.g. nanosecond timestamps on 256-byte inodes)
//!     are untouched, on both the read and write paths.
//!   - i_size is read/written as the low 32 bits only (i_size_lo) — files
//!     >= 4GiB are out of scope, consistent with everything else here.
//!   - No feature-flag validation (s_feature_incompat / s_feature_ro_compat)
//!     — this module assumes a standard mke2fs-created ext2 filesystem with
//!     the usual defaults, not an ext3/ext4 volume or one using unusual
//!     ext2 feature bits.

extern crate alloc;
use alloc::{string::String, vec, vec::Vec};

use crate::hal;

pub const ROOT_INODE: u32 = 2;
const EXT2_MAGIC: u16 = 0xEF53;
const S_IFDIR: u16 = 0x4000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ext2Error {
    NoBlockDevice,
    ReadError,
    /// A block_write() call failed partway through (patch_48). Since
    /// writes to individual sectors aren't atomic across a multi-sector
    /// call, a failure partway through can leave a file's on-disk content
    /// partially updated — a known, accepted limitation of this first
    /// write slice (see module doc's note that crash-safety is explicitly
    /// deferred to the future, larger write-support effort).
    WriteError,
    BadMagic,
    NotADirectory,
    IsADirectory,
    NotFound,
    InvalidInode,
    /// A file or directory needs doubly/triply indirect blocks (beyond
    /// direct + singly indirect, see module doc) — out of scope. As of
    /// patch_52, this is also what write_file_in_place()'s growth path
    /// returns when a write would need more than direct+indirect can
    /// hold (previously a separate GrowthExceedsDirectBlocks variant,
    /// retired once growth could reach the indirect block for real).
    FileTooLarge,
    /// write_file_in_place() was asked to write more bytes than the
    /// target inode's already-allocated block prefix can hold (patch_48)
    /// — see allocated_prefix_capacity(). This is a hard error only when
    /// the shortfall can't be covered by growth (see FileTooLarge, which
    /// covers the case growth itself can't reach).
    WriteExceedsAllocatedCapacity,
    /// allocate_one_block() (patch_49) scanned every block group and
    /// found no free bit — the filesystem is genuinely full.
    NoFreeBlocks,
    /// allocate_one_inode() (patch_50) scanned every block group and
    /// found no free bit — the filesystem's inode table is genuinely full
    /// (independent of NoFreeBlocks — a filesystem can run out of either
    /// resource before the other).
    NoFreeInodes,
    /// create_file() (patch_50) was asked to create a name that already
    /// exists in the target directory.
    AlreadyExists,
    /// insert_dir_entry() (patch_50) scanned every block the target
    /// directory owns and found no entry with enough trailing slack to
    /// hold the new (inode, name) record. Growing the directory itself
    /// (allocating it a new block) is deliberately out of scope for this
    /// first creation slice — see module doc.
    DirectoryFull,
    /// delete_directory() (patch_54) was asked to remove a directory that
    /// still contains entries other than "." and "..".
    DirectoryNotEmpty,
}

fn u16_from_le(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}

fn u32_from_le(b: &[u8]) -> u32 {
    let mut arr = [0u8; 4];
    arr.copy_from_slice(&b[0..4]);
    u32::from_le_bytes(arr)
}

/// Reads `len` bytes starting at `byte_offset` within the partition
/// beginning at `partition_start_lba`, translating the (possibly
/// sector-unaligned) byte range into whole-sector hal::registry::block_read()
/// calls, batched at up to 4096 bytes per call (the same cap
/// io_read_blocks/block_read enforce). This is the one place in this
/// module that talks to the BlockDevice HAL — every other function in
/// this file goes through this.
fn read_bytes_at(partition_start_lba: u64, byte_offset: u64, len: usize) -> Result<Vec<u8>, Ext2Error> {
    if len == 0 {
        return Ok(Vec::new());
    }
    let sector_size = hal::registry::block_size() as u64;
    if sector_size == 0 {
        return Err(Ext2Error::NoBlockDevice);
    }

    let abs_byte_offset = partition_start_lba * sector_size + byte_offset;
    let start_lba = abs_byte_offset / sector_size;
    let start_offset_in_sector = (abs_byte_offset % sector_size) as usize;
    let end_byte_exclusive = abs_byte_offset + len as u64;
    let last_lba = (end_byte_exclusive - 1) / sector_size;
    let num_lbas = (last_lba - start_lba + 1) as usize;

    let max_lbas_per_call = (4096 / sector_size as usize).max(1);
    let mut raw = Vec::with_capacity(num_lbas * sector_size as usize);
    let mut lba = start_lba;
    let mut remaining_lbas = num_lbas;
    while remaining_lbas > 0 {
        let this_call_lbas = remaining_lbas.min(max_lbas_per_call);
        let call_bytes = this_call_lbas * sector_size as usize;
        let mut buf = vec![0u8; call_bytes];
        hal::registry::block_read(lba, &mut buf).map_err(|_| Ext2Error::ReadError)?;
        raw.extend_from_slice(&buf);
        lba += this_call_lbas as u64;
        remaining_lbas -= this_call_lbas;
    }

    let start = start_offset_in_sector;
    let end = start + len;
    if end > raw.len() {
        return Err(Ext2Error::ReadError);
    }
    Ok(raw[start..end].to_vec())
}

/// Writes `data` starting at `byte_offset` within the partition beginning
/// at `partition_start_lba` (patch_48). Mirrors read_bytes_at()'s LBA/
/// batching math exactly, but is read-modify-write: any sector touched
/// only partially by `data` (the first and/or last sector, when the byte
/// range isn't sector-aligned) is read first so the untouched bytes in
/// that sector are preserved, then the whole batch is written back via
/// hal::registry::block_write(). A byte range that happens to cover whole
/// sectors exactly still goes through the same read-first path for
/// simplicity — this is not a hot enough path in this first write slice
/// (single small files, called once per write_file_in_place()) to justify
/// a separate aligned-fast-path, unlike read_bytes_at's own batching,
/// which IS on kshell tests' hot path.
///
/// This is the one place in this module that calls
/// hal::registry::block_write() — everything else in this file that
/// writes goes through this function, mirroring read_bytes_at's role as
/// the single read chokepoint.
fn write_bytes_at(partition_start_lba: u64, byte_offset: u64, data: &[u8]) -> Result<(), Ext2Error> {
    if data.is_empty() {
        return Ok(());
    }
    let sector_size = hal::registry::block_size() as u64;
    if sector_size == 0 {
        return Err(Ext2Error::NoBlockDevice);
    }

    let abs_byte_offset = partition_start_lba * sector_size + byte_offset;
    let start_lba = abs_byte_offset / sector_size;
    let start_offset_in_sector = (abs_byte_offset % sector_size) as usize;
    let end_byte_exclusive = abs_byte_offset + data.len() as u64;
    let last_lba = (end_byte_exclusive - 1) / sector_size;
    let num_lbas = (last_lba - start_lba + 1) as usize;

    // Read the current contents of every sector this write touches, so
    // any partially-overlapping sector's untouched bytes survive.
    let max_lbas_per_call = (4096 / sector_size as usize).max(1);
    let mut existing = Vec::with_capacity(num_lbas * sector_size as usize);
    let mut lba = start_lba;
    let mut remaining_lbas = num_lbas;
    while remaining_lbas > 0 {
        let this_call_lbas = remaining_lbas.min(max_lbas_per_call);
        let call_bytes = this_call_lbas * sector_size as usize;
        let mut buf = vec![0u8; call_bytes];
        hal::registry::block_read(lba, &mut buf).map_err(|_| Ext2Error::ReadError)?;
        existing.extend_from_slice(&buf);
        lba += this_call_lbas as u64;
        remaining_lbas -= this_call_lbas;
    }

    // Splice the new data into the (now fully-populated) sector-aligned
    // buffer at the correct byte offset within it.
    existing[start_offset_in_sector..start_offset_in_sector + data.len()].copy_from_slice(data);

    // Write the whole sector-aligned buffer back, same batching cap as
    // the read above (and as read_bytes_at itself).
    let mut lba = start_lba;
    let mut remaining_bytes = existing.len();
    let mut off = 0usize;
    while remaining_bytes > 0 {
        let this_call_lbas = (remaining_bytes / sector_size as usize).min(max_lbas_per_call).max(1);
        let call_bytes = (this_call_lbas * sector_size as usize).min(remaining_bytes);
        hal::registry::block_write(lba, &existing[off..off + call_bytes]).map_err(|_| Ext2Error::WriteError)?;
        lba += this_call_lbas as u64;
        off += call_bytes;
        remaining_bytes -= call_bytes;
    }

    Ok(())
}

#[derive(Debug, Clone, Copy)]
pub struct Ext2Superblock {
    pub inodes_count: u32,
    pub blocks_count: u32,
    /// Block 0 or 1 depending on block_size (0 for block_size > 1024,
    /// since then the superblock shares block 0 with the boot area; 1
    /// when block_size == 1024). Needed (patch_49) to compute a global
    /// block number from a block-group-relative bitmap bit index.
    pub first_data_block: u32,
    pub log_block_size: u32,
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub magic: u16,
    pub rev_level: u32,
    pub inode_size: u16,
}

impl Ext2Superblock {
    pub fn block_size(&self) -> u32 {
        1024u32 << self.log_block_size
    }
}

fn parse_superblock(raw: &[u8]) -> Result<Ext2Superblock, Ext2Error> {
    let magic = u16_from_le(&raw[56..58]);
    if magic != EXT2_MAGIC {
        return Err(Ext2Error::BadMagic);
    }
    let rev_level = u32_from_le(&raw[76..80]);
    let inode_size = if rev_level == 0 {
        128
    } else {
        u16_from_le(&raw[88..90])
    };
    Ok(Ext2Superblock {
        inodes_count: u32_from_le(&raw[0..4]),
        blocks_count: u32_from_le(&raw[4..8]),
        first_data_block: u32_from_le(&raw[20..24]),
        log_block_size: u32_from_le(&raw[24..28]),
        blocks_per_group: u32_from_le(&raw[32..36]),
        inodes_per_group: u32_from_le(&raw[40..44]),
        magic,
        rev_level,
        inode_size,
    })
}

#[derive(Debug, Clone)]
pub struct Ext2Fs {
    pub partition_start_lba: u64,
    pub sb: Ext2Superblock,
}

/// Mounts (read-only, in the sense of "parses enough to read") the ext2
/// filesystem believed to start at `partition_start_lba` — the superblock
/// always lives at byte offset 1024 from the start of whatever it's on,
/// regardless of block size, so this doesn't need the partition's block
/// size known in advance.
pub fn mount(partition_start_lba: u64) -> Result<Ext2Fs, Ext2Error> {
    let raw = read_bytes_at(partition_start_lba, 1024, 1024)?;
    let sb = parse_superblock(&raw)?;
    Ok(Ext2Fs { partition_start_lba, sb })
}

struct BlockGroupDescriptor {
    block_bitmap: u32,
    /// bg_inode_bitmap, offset 4 within the 32-byte descriptor (patch_50)
    /// — the inode-allocation counterpart to block_bitmap.
    inode_bitmap: u32,
    inode_table: u32,
    /// bg_free_blocks_count, offset 12 within the 32-byte descriptor
    /// (patch_49) — read so allocation can decrement it, and so a group
    /// with zero free blocks can be skipped without scanning its bitmap.
    free_blocks_count: u16,
    /// bg_free_inodes_count, offset 14 (patch_50) — same role as
    /// free_blocks_count above, for inode allocation.
    free_inodes_count: u16,
}

fn read_block_group_descriptor(fs: &Ext2Fs, group: u32) -> Result<BlockGroupDescriptor, Ext2Error> {
    let block_size = fs.sb.block_size() as u64;
    // The block group descriptor table starts immediately after the block
    // containing the superblock: block 2 when block_size == 1024 (since
    // the superblock then occupies block 1 on its own), block 1 otherwise
    // (block 0 holds both the boot area and the superblock together).
    let bgdt_block: u64 = if block_size == 1024 { 2 } else { 1 };
    let bgd_byte_offset = bgdt_block * block_size + (group as u64 * 32);
    let raw = read_bytes_at(fs.partition_start_lba, bgd_byte_offset, 32)?;
    Ok(BlockGroupDescriptor {
        block_bitmap: u32_from_le(&raw[0..4]),
        inode_bitmap: u32_from_le(&raw[4..8]),
        inode_table: u32_from_le(&raw[8..12]),
        free_blocks_count: u16_from_le(&raw[12..14]),
        free_inodes_count: u16_from_le(&raw[14..16]),
    })
}

/// Decrements bg_free_blocks_count (offset 12 within the 32-byte
/// descriptor) by exactly 1, in place on disk (patch_49). Called once per
/// block allocate_one_block() hands out — see that function's own doc for
/// why this and the superblock's global count are both best-effort
/// bookkeeping in this first allocation slice, not crash-safe.
fn decrement_group_free_blocks(fs: &Ext2Fs, group: u32, current: u16) -> Result<(), Ext2Error> {
    let block_size = fs.sb.block_size() as u64;
    let bgdt_block: u64 = if block_size == 1024 { 2 } else { 1 };
    let bgd_byte_offset = bgdt_block * block_size + (group as u64 * 32);
    let new_count = (current.saturating_sub(1)).to_le_bytes();
    write_bytes_at(fs.partition_start_lba, bgd_byte_offset + 12, &new_count)
}

/// Decrements the superblock's own global s_free_blocks_count (offset 12,
/// u32) by exactly 1, in place on disk (patch_49). Kept in sync purely for
/// on-disk consistency (a real fsck would otherwise flag a mismatch) —
/// nothing in this module currently reads this field back.
fn decrement_superblock_free_blocks(fs: &Ext2Fs) -> Result<(), Ext2Error> {
    let raw = read_bytes_at(fs.partition_start_lba, 1024 + 12, 4)?;
    let current = u32_from_le(&raw);
    let new_count = current.saturating_sub(1).to_le_bytes();
    write_bytes_at(fs.partition_start_lba, 1024 + 12, &new_count)
}

/// Finds one free block anywhere on the filesystem, marks it used in its
/// group's block bitmap, decrements that group's and the superblock's
/// free-block counts, and returns its global block number (patch_49) —
/// this project's first real block allocation, deliberately the smallest
/// possible slice: exactly one block per call (a caller needing several
/// calls this in a loop — see write_file_in_place()'s growth path), no
/// batching, no free-space caching across calls.
///
/// Scans block groups in order (this test image has 8, per its real
/// blocks_count/blocks_per_group — this function is NOT a single-group
/// simplification, it walks all of them). Within a group, scans its
/// bitmap byte-by-byte, bit-by-bit, for the first 0 (free) bit, clamped to
/// that group's real block count (the last group can own fewer than a
/// full blocks_per_group's worth of blocks, when blocks_count isn't an
/// exact multiple - scanning past that into padding bits would allocate a
/// block number beyond the filesystem's real extent).
///
/// NOT crash-safe: the bitmap write and the two free-count decrements are
/// three separate write_bytes_at() calls, not one atomic operation. A
/// power loss between them could leave the on-disk metadata inconsistent
/// (matching this project's own documented, deliberate deferral of crash-
/// safety for this whole write-support effort — see module doc).
fn allocate_one_block(fs: &Ext2Fs) -> Result<u32, Ext2Error> {
    let block_size = fs.sb.block_size() as u64;
    let blocks_per_group = fs.sb.blocks_per_group as u64;
    let num_groups = (fs.sb.blocks_count as u64 + blocks_per_group - 1) / blocks_per_group;

    for group in 0..num_groups as u32 {
        let bgd = read_block_group_descriptor(fs, group)?;
        if bgd.free_blocks_count == 0 {
            continue;
        }

        // How many real blocks this group actually owns - the last group
        // may own fewer than a full blocks_per_group if blocks_count
        // isn't an exact multiple.
        let group_start_block = group as u64 * blocks_per_group;
        let blocks_in_group = ((fs.sb.blocks_count as u64).saturating_sub(group_start_block)).min(blocks_per_group);
        if blocks_in_group == 0 {
            continue;
        }

        let bitmap_bytes = ((blocks_per_group + 7) / 8) as usize;
        let bitmap = read_bytes_at(fs.partition_start_lba, bgd.block_bitmap as u64 * block_size, bitmap_bytes)?;

        for local_index in 0..blocks_in_group as usize {
            let byte_idx = local_index / 8;
            let bit_idx = local_index % 8;
            let byte = bitmap[byte_idx];
            if (byte >> bit_idx) & 1 == 0 {
                // Free bit found - mark it used with a single-byte
                // read-modify-write (write_bytes_at already handles the
                // sector-alignment safety; we only need to supply the one
                // changed byte).
                let new_byte = byte | (1 << bit_idx);
                let byte_offset = bgd.block_bitmap as u64 * block_size + byte_idx as u64;
                write_bytes_at(fs.partition_start_lba, byte_offset, &[new_byte])?;

                decrement_group_free_blocks(fs, group, bgd.free_blocks_count)?;
                decrement_superblock_free_blocks(fs)?;

                let global_block = fs.sb.first_data_block as u64 + group_start_block + local_index as u64;
                return Ok(global_block as u32);
            }
        }
        // This group's free_blocks_count said >0 but no free bit was
        // found in range - a real on-disk inconsistency (or a group
        // holding a count that doesn't match its bitmap). Move on to the
        // next group rather than trusting a corrupt count blindly.
    }

    Err(Ext2Error::NoFreeBlocks)
}

/// Decrements bg_free_inodes_count (offset 14 within the 32-byte
/// descriptor) by exactly 1, in place on disk (patch_50) — the inode
/// counterpart to decrement_group_free_blocks().
fn decrement_group_free_inodes(fs: &Ext2Fs, group: u32, current: u16) -> Result<(), Ext2Error> {
    let block_size = fs.sb.block_size() as u64;
    let bgdt_block: u64 = if block_size == 1024 { 2 } else { 1 };
    let bgd_byte_offset = bgdt_block * block_size + (group as u64 * 32);
    let new_count = (current.saturating_sub(1)).to_le_bytes();
    write_bytes_at(fs.partition_start_lba, bgd_byte_offset + 14, &new_count)
}

/// Decrements the superblock's own global s_free_inodes_count (offset 16,
/// u32) by exactly 1, in place on disk (patch_50) — the inode counterpart
/// to decrement_superblock_free_blocks().
fn decrement_superblock_free_inodes(fs: &Ext2Fs) -> Result<(), Ext2Error> {
    let raw = read_bytes_at(fs.partition_start_lba, 1024 + 16, 4)?;
    let current = u32_from_le(&raw);
    let new_count = current.saturating_sub(1).to_le_bytes();
    write_bytes_at(fs.partition_start_lba, 1024 + 16, &new_count)
}

/// Finds one free inode anywhere on the filesystem, marks it used in its
/// group's inode bitmap, decrements that group's and the superblock's
/// free-inode counts, and returns its 1-indexed global inode number
/// (patch_50) — the inode counterpart to allocate_one_block(), same
/// scan-groups-in-order/one-at-a-time/not-crash-safe shape.
///
/// Relies on the on-disk inode bitmap already correctly marking the
/// reserved low inode numbers (1 through s_first_ino, typically 1..=10)
/// as used, exactly as mke2fs leaves them — this function does not special-
/// case reserved inodes itself, it simply trusts the bitmap's existing
/// used bits, the same way allocate_one_block() trusts the block bitmap's
/// existing used bits for the metadata blocks the superblock/BGDT/bitmaps/
/// inode tables themselves already occupy.
fn allocate_one_inode(fs: &Ext2Fs) -> Result<u32, Ext2Error> {
    let block_size = fs.sb.block_size() as u64;
    let inodes_per_group = fs.sb.inodes_per_group as u64;
    let blocks_per_group = fs.sb.blocks_per_group as u64;
    let num_groups = (fs.sb.blocks_count as u64 + blocks_per_group - 1) / blocks_per_group;

    for group in 0..num_groups as u32 {
        let bgd = read_block_group_descriptor(fs, group)?;
        if bgd.free_inodes_count == 0 {
            continue;
        }

        let group_start_inode = group as u64 * inodes_per_group; // 0-indexed within the global inode space
        let inodes_in_group = ((fs.sb.inodes_count as u64).saturating_sub(group_start_inode)).min(inodes_per_group);
        if inodes_in_group == 0 {
            continue;
        }

        let bitmap_bytes = ((inodes_per_group + 7) / 8) as usize;
        let bitmap = read_bytes_at(fs.partition_start_lba, bgd.inode_bitmap as u64 * block_size, bitmap_bytes)?;

        for local_index in 0..inodes_in_group as usize {
            let byte_idx = local_index / 8;
            let bit_idx = local_index % 8;
            let byte = bitmap[byte_idx];
            if (byte >> bit_idx) & 1 == 0 {
                let new_byte = byte | (1 << bit_idx);
                let byte_offset = bgd.inode_bitmap as u64 * block_size + byte_idx as u64;
                write_bytes_at(fs.partition_start_lba, byte_offset, &[new_byte])?;

                decrement_group_free_inodes(fs, group, bgd.free_inodes_count)?;
                decrement_superblock_free_inodes(fs)?;

                // Inode numbers are 1-indexed globally.
                let global_inode = group_start_inode + local_index as u64 + 1;
                return Ok(global_inode as u32);
            }
        }
    }

    Err(Ext2Error::NoFreeInodes)
}

/// Increments bg_free_blocks_count (offset 12) by 1, in place on disk
/// (patch_51) — the reverse of decrement_group_free_blocks(), used when
/// freeing a block rather than allocating one.
fn increment_group_free_blocks(fs: &Ext2Fs, group: u32, current: u16) -> Result<(), Ext2Error> {
    let block_size = fs.sb.block_size() as u64;
    let bgdt_block: u64 = if block_size == 1024 { 2 } else { 1 };
    let bgd_byte_offset = bgdt_block * block_size + (group as u64 * 32);
    let new_count = current.saturating_add(1).to_le_bytes();
    write_bytes_at(fs.partition_start_lba, bgd_byte_offset + 12, &new_count)
}

/// Increments the superblock's s_free_blocks_count (offset 12, u32) by 1,
/// in place on disk (patch_51) — the reverse of
/// decrement_superblock_free_blocks().
fn increment_superblock_free_blocks(fs: &Ext2Fs) -> Result<(), Ext2Error> {
    let raw = read_bytes_at(fs.partition_start_lba, 1024 + 12, 4)?;
    let current = u32_from_le(&raw);
    let new_count = current.saturating_add(1).to_le_bytes();
    write_bytes_at(fs.partition_start_lba, 1024 + 12, &new_count)
}

/// Frees a single block, previously returned by allocate_one_block()
/// (patch_51): clears its bit in its group's block bitmap, and
/// increments both that group's and the superblock's free-block counts.
/// Does NOT zero the block's data (real ext2 doesn't either — the bitmap
/// bit alone is what makes it "free"; its old content is simply
/// unreachable until the next allocation overwrites it, exactly matching
/// standard filesystem behaviour, not a shortcut specific to this
/// project). NOT crash-safe, same accepted gap as allocate_one_block().
fn free_one_block(fs: &Ext2Fs, global_block: u32) -> Result<(), Ext2Error> {
    let block_size = fs.sb.block_size() as u64;
    let blocks_per_group = fs.sb.blocks_per_group as u64;
    let relative = (global_block as u64).saturating_sub(fs.sb.first_data_block as u64);
    let group = (relative / blocks_per_group) as u32;
    let local_index = (relative % blocks_per_group) as usize;

    let bgd = read_block_group_descriptor(fs, group)?;
    let byte_idx = local_index / 8;
    let bit_idx = local_index % 8;
    let byte_offset = bgd.block_bitmap as u64 * block_size + byte_idx as u64;
    let current_byte = read_bytes_at(fs.partition_start_lba, byte_offset, 1)?;
    let new_byte = current_byte[0] & !(1 << bit_idx);
    write_bytes_at(fs.partition_start_lba, byte_offset, &[new_byte])?;

    increment_group_free_blocks(fs, group, bgd.free_blocks_count)?;
    increment_superblock_free_blocks(fs)?;
    Ok(())
}

/// Increments bg_free_inodes_count (offset 14) by 1, in place on disk
/// (patch_51) — the reverse of decrement_group_free_inodes().
fn increment_group_free_inodes(fs: &Ext2Fs, group: u32, current: u16) -> Result<(), Ext2Error> {
    let block_size = fs.sb.block_size() as u64;
    let bgdt_block: u64 = if block_size == 1024 { 2 } else { 1 };
    let bgd_byte_offset = bgdt_block * block_size + (group as u64 * 32);
    let new_count = current.saturating_add(1).to_le_bytes();
    write_bytes_at(fs.partition_start_lba, bgd_byte_offset + 14, &new_count)
}

/// Increments the superblock's s_free_inodes_count (offset 16, u32) by 1,
/// in place on disk (patch_51) — the reverse of
/// decrement_superblock_free_inodes().
fn increment_superblock_free_inodes(fs: &Ext2Fs) -> Result<(), Ext2Error> {
    let raw = read_bytes_at(fs.partition_start_lba, 1024 + 16, 4)?;
    let current = u32_from_le(&raw);
    let new_count = current.saturating_add(1).to_le_bytes();
    write_bytes_at(fs.partition_start_lba, 1024 + 16, &new_count)
}

/// Frees a single inode, previously returned by allocate_one_inode()
/// (patch_51): clears its bit in its group's inode bitmap, and
/// increments both that group's and the superblock's free-inode counts.
/// Does NOT itself zero the inode record on disk — delete_file() does
/// that separately, before calling this, so the record is already clean
/// by the time the bit is cleared (avoids a window where the bit says
/// "free" but the record still shows a live-looking file).
fn free_one_inode(fs: &Ext2Fs, inode_num: u32) -> Result<(), Ext2Error> {
    let inodes_per_group = fs.sb.inodes_per_group as u64;
    let relative = (inode_num as u64).saturating_sub(1); // inodes are 1-indexed
    let group = (relative / inodes_per_group) as u32;
    let local_index = (relative % inodes_per_group) as usize;
    let block_size = fs.sb.block_size() as u64;

    let bgd = read_block_group_descriptor(fs, group)?;
    let byte_idx = local_index / 8;
    let bit_idx = local_index % 8;
    let byte_offset = bgd.inode_bitmap as u64 * block_size + byte_idx as u64;
    let current_byte = read_bytes_at(fs.partition_start_lba, byte_offset, 1)?;
    let new_byte = current_byte[0] & !(1 << bit_idx);
    write_bytes_at(fs.partition_start_lba, byte_offset, &[new_byte])?;

    increment_group_free_inodes(fs, group, bgd.free_inodes_count)?;
    increment_superblock_free_inodes(fs)?;
    Ok(())
}

/// Decrements an inode's i_links_count field (offset 26 within the record)
/// by 1, saturating at 0 (patch_54) — used when a directory is deleted, to
/// account for the ".." entry it held that counted as a link to its
/// parent. This is the only inode-metadata field patch_54 touches beyond
/// what delete_file()/create_file() already established.
fn decrement_inode_links(fs: &Ext2Fs, inode_num: u32) -> Result<(), Ext2Error> {
    let inode_off = inode_byte_offset(fs, inode_num)?;
    let raw = read_bytes_at(fs.partition_start_lba, inode_off + 26, 2)?;
    let current = u16_from_le(&raw);
    let new_count = current.saturating_sub(1).to_le_bytes();
    write_bytes_at(fs.partition_start_lba, inode_off + 26, &new_count)
}

/// Decrements bg_used_dirs_count (offset 16 within the 32-byte block
/// group descriptor) by 1 for the group that owns `inode_num` (patch_54)
/// — a field this driver had never touched before, since directory
/// CREATION (which would increment it) remains out of scope; every
/// directory currently on this filesystem had it correctly set by
/// mke2fs at filesystem-creation time, so decrementing on deletion is
/// the only direction this driver ever needs.
fn decrement_group_used_dirs(fs: &Ext2Fs, inode_num: u32) -> Result<(), Ext2Error> {
    let inodes_per_group = fs.sb.inodes_per_group as u64;
    let relative = (inode_num as u64).saturating_sub(1);
    let group = (relative / inodes_per_group) as u32;
    let block_size = fs.sb.block_size() as u64;
    let bgdt_block: u64 = if block_size == 1024 { 2 } else { 1 };
    let bgd_byte_offset = bgdt_block * block_size + (group as u64 * 32);

    let raw = read_bytes_at(fs.partition_start_lba, bgd_byte_offset + 16, 2)?;
    let current = u16_from_le(&raw);
    let new_count = current.saturating_sub(1).to_le_bytes();
    write_bytes_at(fs.partition_start_lba, bgd_byte_offset + 16, &new_count)
}

#[derive(Debug, Clone, Copy)]
pub struct Inode {
    pub i_mode: u16,
    pub i_uid: u16,
    pub i_gid: u16,
    pub i_size: u32,
    pub i_links_count: u16,
    pub i_block: [u32; 15],
}

impl Inode {
    pub fn is_directory(&self) -> bool {
        (self.i_mode & 0xF000) == S_IFDIR
    }
}

pub fn read_inode(fs: &Ext2Fs, inode_num: u32) -> Result<Inode, Ext2Error> {
    let byte_offset = inode_byte_offset(fs, inode_num)?;

    // Only the first 128 bytes are read - every field this module uses
    // lives within that range regardless of the on-disk inode size (128
    // is the spec-guaranteed minimum).
    let raw = read_bytes_at(fs.partition_start_lba, byte_offset, 128)?;

    let mut i_block = [0u32; 15];
    for (i, slot) in i_block.iter_mut().enumerate() {
        let off = 40 + i * 4;
        *slot = u32_from_le(&raw[off..off + 4]);
    }

    Ok(Inode {
        i_mode: u16_from_le(&raw[0..2]),
        i_uid: u16_from_le(&raw[2..4]),
        i_size: u32_from_le(&raw[4..8]),
        i_gid: u16_from_le(&raw[24..26]),
        i_links_count: u16_from_le(&raw[26..28]),
        i_block,
    })
}

/// Computes the on-disk byte offset (relative to partition_start_lba) of
/// a given inode number's on-disk record. Factored out of read_inode()
/// (patch_48) so write_file_in_place() can locate the same inode's
/// i_size field (offset 4..8 within the record) to update it after a
/// write, without duplicating the group/index/block-group-descriptor
/// lookup logic.
fn inode_byte_offset(fs: &Ext2Fs, inode_num: u32) -> Result<u64, Ext2Error> {
    if inode_num == 0 {
        return Err(Ext2Error::InvalidInode);
    }
    let group = (inode_num - 1) / fs.sb.inodes_per_group;
    let index_in_group = (inode_num - 1) % fs.sb.inodes_per_group;

    let bgd = read_block_group_descriptor(fs, group)?;
    let block_size = fs.sb.block_size() as u64;
    Ok((bgd.inode_table as u64 * block_size) + (index_in_group as u64 * fs.sb.inode_size as u64))
}

/// Reads a raw indirect block (a block full of u32 LE block-pointer
/// values, block_size/4 of them) and returns it as a Vec<u32>. Used only
/// by block_pointers() below for the singly-indirect slot (i_block[12]).
fn read_pointer_block(fs: &Ext2Fs, block_num: u32) -> Result<Vec<u32>, Ext2Error> {
    let block_size = fs.sb.block_size() as u64;
    let raw = read_bytes_at(fs.partition_start_lba, block_num as u64 * block_size, block_size as usize)?;
    let ptrs_per_block = (block_size / 4) as usize;
    let mut out = Vec::with_capacity(ptrs_per_block);
    for i in 0..ptrs_per_block {
        out.push(u32_from_le(&raw[i * 4..i * 4 + 4]));
    }
    Ok(out)
}

/// Returns every data-block pointer this inode owns, direct blocks
/// (i_block[0..12]) followed by singly-indirect (i_block[12]'s own
/// block_size/4 pointers) — patch_46. A 0 in the returned Vec means
/// "unused/sparse block", matching the existing per-slot convention
/// read_dir_entries()/read_file() already relied on for direct blocks.
///
/// Doubly (i_block[13]) and triply (i_block[14]) indirect are NOT walked
/// — deliberately out of scope, see module doc. This function does not
/// itself decide whether that matters for a given inode; read_file()'s
/// own size check against MAX_SIZE (below) is what actually rejects a
/// file that would need them, so a directory with entries spilling past
/// this range still gets whatever real entries fit rather than a hard
/// error (matching the pre-existing sparse-friendly behaviour of the
/// direct-blocks-only version of this function).
fn block_pointers(fs: &Ext2Fs, inode: &Inode) -> Result<Vec<u32>, Ext2Error> {
    let mut pointers: Vec<u32> = inode.i_block[0..12].to_vec();

    let indirect_block = inode.i_block[12];
    if indirect_block != 0 {
        pointers.extend(read_pointer_block(fs, indirect_block)?);
    }

    Ok(pointers)
}

/// Maximum single-file/directory size this driver supports: 12 direct
/// blocks plus one singly-indirect block's worth of pointers, each
/// pointing at one more block_size-byte block. Doubly/triply indirect
/// (i_block[13], i_block[14]) are out of scope — see module doc.
fn max_supported_size(fs: &Ext2Fs) -> u64 {
    let block_size = fs.sb.block_size() as u64;
    let ptrs_per_block = block_size / 4;
    (12 + ptrs_per_block) * block_size
}

#[derive(Debug, Clone)]
pub struct DirEntry {
    pub inode: u32,
    pub name: String,
    pub file_type: u8,
}

/// Lists the entries of a directory inode. Walks direct + singly-indirect
/// blocks (see block_pointers(), patch_46) — a directory whose entries
/// spill past that range will simply have its later entries silently
/// unavailable, not an error, since that boundary is now roughly 1MB+
/// rather than 12*block_size, and no directory this project tests against
/// approaches it.
pub fn read_dir_entries(fs: &Ext2Fs, dir_inode_num: u32) -> Result<Vec<DirEntry>, Ext2Error> {
    let inode = read_inode(fs, dir_inode_num)?;
    if !inode.is_directory() {
        return Err(Ext2Error::NotADirectory);
    }

    let block_size = fs.sb.block_size() as u64;
    let mut entries = Vec::new();

    for block_num in block_pointers(fs, &inode)? {
        if block_num == 0 {
            continue; // unused/sparse block slot
        }
        let raw = read_bytes_at(fs.partition_start_lba, block_num as u64 * block_size, block_size as usize)?;

        let mut off = 0usize;
        while off + 8 <= raw.len() {
            let ino = u32_from_le(&raw[off..off + 4]);
            let rec_len = u16_from_le(&raw[off + 4..off + 6]) as usize;
            let name_len = raw[off + 6] as usize;
            let file_type = raw[off + 7];

            if rec_len == 0 {
                break; // corrupt entry; avoid an infinite loop
            }
            if ino != 0 && off + 8 + name_len <= raw.len() {
                if let Ok(name) = core::str::from_utf8(&raw[off + 8..off + 8 + name_len]) {
                    entries.push(DirEntry {
                        inode: ino,
                        name: String::from(name),
                        file_type,
                    });
                }
            }
            off += rec_len;
        }
    }

    Ok(entries)
}

/// Looks up a bare filename directly under the partition's root
/// directory. Kept as a thin wrapper over resolve_path() for existing
/// callers (ext2test) — no longer a real scope restriction now that
/// resolve_path() exists, just a convenience for the single-segment case.
pub fn lookup_in_root(fs: &Ext2Fs, name: &str) -> Result<u32, Ext2Error> {
    let entries = read_dir_entries(fs, ROOT_INODE)?;
    entries
        .into_iter()
        .find(|e| e.name == name)
        .map(|e| e.inode)
        .ok_or(Ext2Error::NotFound)
}

/// Resolves a multi-level path (e.g. "a/b/c", leading/trailing '/' and
/// empty segments from "//" ignored) starting from the partition's root
/// directory, walking one directory level at a time via the existing
/// read_dir_entries() — patch_45, closing the "root-directory lookups
/// only" gap noted in this module's doc since patch_42.
///
/// An empty path (after stripping) resolves to ROOT_INODE itself. Every
/// non-final segment that doesn't resolve to a directory is a real error
/// (NotADirectory), not a silent stop — matches how a real Unix path
/// resolver treats e.g. "/etc/passwd/foo".
pub fn resolve_path(fs: &Ext2Fs, path: &str) -> Result<u32, Ext2Error> {
    let mut current = ROOT_INODE;
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    for (i, seg) in segments.iter().enumerate() {
        let is_last = i == segments.len() - 1;
        let entries = read_dir_entries(fs, current)?;
        let found = entries
            .into_iter()
            .find(|e| e.name == *seg)
            .ok_or(Ext2Error::NotFound)?;

        if !is_last {
            let inode = read_inode(fs, found.inode)?;
            if !inode.is_directory() {
                return Err(Ext2Error::NotADirectory);
            }
        }
        current = found.inode;
    }

    Ok(current)
}

/// Reads a regular file's full contents. Direct + singly-indirect blocks
/// (see block_pointers(), patch_46) — files larger than max_supported_size()
/// return FileTooLarge rather than silently truncating.
pub fn read_file(fs: &Ext2Fs, inode_num: u32) -> Result<Vec<u8>, Ext2Error> {
    let inode = read_inode(fs, inode_num)?;
    if inode.is_directory() {
        return Err(Ext2Error::IsADirectory);
    }

    let block_size = fs.sb.block_size() as u64;
    let size = inode.i_size as usize;
    if size as u64 > max_supported_size(fs) {
        return Err(Ext2Error::FileTooLarge);
    }

    let mut data = Vec::with_capacity(size);
    let mut remaining = size;
    for block_num in block_pointers(fs, &inode)? {
        if remaining == 0 {
            break;
        }
        let this_len = remaining.min(block_size as usize);
        if block_num == 0 {
            // Sparse block - real ext2 files can have holes; read as zeros.
            data.extend(core::iter::repeat(0u8).take(this_len));
        } else {
            let raw = read_bytes_at(fs.partition_start_lba, block_num as u64 * block_size, this_len)?;
            data.extend_from_slice(&raw);
        }
        remaining -= this_len;
    }

    Ok(data)
}

/// Returns the number of bytes this inode can be written into WITHOUT any
/// new block allocation (patch_48) — the count of consecutive already-
/// nonzero block pointers starting at i_block[0], times block_size. Stops
/// at the first zero (unallocated/sparse) pointer, even if a later
/// pointer happens to be nonzero (a real hole past that point) — this
/// first write slice deliberately does not attempt to reason about holes
/// for writing, only for reading (see read_file()'s existing sparse-zero-
/// fill logic, which remains read-only behaviour, unaffected by this).
fn allocated_prefix_capacity(fs: &Ext2Fs, inode: &Inode) -> Result<u64, Ext2Error> {
    let block_size = fs.sb.block_size() as u64;
    let mut count: u64 = 0;
    for block_num in block_pointers(fs, inode)? {
        if block_num == 0 {
            break;
        }
        count += 1;
    }
    Ok(count * block_size)
}

/// Links `new_block` into `inode_num`'s block-pointer list at logical
/// slot `slot` (0-indexed: 0..12 direct, 12+ within the indirect block),
/// allocating and zeroing the indirect block itself first if needed
/// (patch_55). Extracted from grow_inode_to_block_count() so a caller
/// that needs full control over allocate-then-initialize-then-publish
/// ordering — see insert_dir_entry()'s directory-growth path, and the
/// crash-safety discussion in this module's doc — can allocate a raw
/// block, write its real content FIRST, and only then call this to make
/// it reachable, rather than being forced into
/// grow_inode_to_block_count()'s own allocate-then-link-immediately
/// order (fine for regular file data, which is never parsed as
/// structure; NOT safe for a directory block, which is).
fn link_block_into_inode(fs: &Ext2Fs, inode_num: u32, slot: usize, new_block: u32) -> Result<(), Ext2Error> {
    let block_size = fs.sb.block_size() as u64;
    let inode_off = inode_byte_offset(fs, inode_num)?;
    if slot < 12 {
        write_bytes_at(fs.partition_start_lba, inode_off + 40 + (slot as u64) * 4, &new_block.to_le_bytes())?;
    } else {
        let inode = read_inode(fs, inode_num)?;
        let mut indirect_block_num = inode.i_block[12];
        if indirect_block_num == 0 {
            indirect_block_num = allocate_one_block(fs)?;
            // Zero the freshly allocated indirect block BEFORE linking it
            // into the inode - its pointer slots must read as 0 (unused)
            // by the time anything can reach it, same ordering principle
            // driving this whole patch.
            let zeros = vec![0u8; block_size as usize];
            write_bytes_at(fs.partition_start_lba, indirect_block_num as u64 * block_size, &zeros)?;
            write_bytes_at(fs.partition_start_lba, inode_off + 40 + 12 * 4, &indirect_block_num.to_le_bytes())?;
        }
        let idx = slot - 12;
        let ptr_byte_offset = indirect_block_num as u64 * block_size + (idx as u64) * 4;
        write_bytes_at(fs.partition_start_lba, ptr_byte_offset, &new_block.to_le_bytes())?;
    }
    Ok(())
}

/// Ensures `inode_num` owns at least `target_block_count` blocks (direct
/// + indirect combined), allocating and linking new ones as needed via
/// allocate_one_block() + link_block_into_inode() (patch_53; refactored
/// in patch_55 to share link_block_into_inode() with the directory-growth
/// path). Shared growth primitive — used by write_file_in_place()'s own
/// growth path AND (indirectly, via link_block_into_inode()) by
/// insert_dir_entry()'s directory-growth fallback, so the direct/indirect
/// allocation and linking logic exists in exactly one place rather than
/// being duplicated between "grow a file" and "grow a directory."
///
/// No-op (Ok, no allocation) if the inode already owns
/// target_block_count or more blocks. Returns FileTooLarge if
/// target_block_count exceeds direct+indirect capacity — doubly/triply
/// indirect remain out of scope.
///
/// Crash-safety note (patch_55): this function allocates a block and
/// links it into the inode in the same step, before any content is
/// written into it. For regular file data (the only caller that uses
/// this function directly) that's an acceptable ordering — a crash in
/// that gap leaves a block linked but not yet holding the new content,
/// which write_file_in_place() then writes and only afterward advances
/// i_size to cover, so a reader never sees a linked-but-uninitialized
/// block as valid data. It would NOT be acceptable for a directory
/// block, whose content is PARSED as structure — see
/// insert_dir_entry()'s own use of link_block_into_inode() directly
/// (not this function) for why that path allocates and initializes
/// first, publishing the link only afterward.
///
/// Assumes (does not defensively re-verify) that this inode's existing
/// block-pointer prefix has no holes — true for every inode this driver
/// itself has ever written, since nothing in this module creates sparse
/// files. A hole from some other source would be silently overwritten by
/// a newly allocated pointer at that slot; this is a real, accepted
/// simplification, not an oversight.
fn grow_inode_to_block_count(fs: &Ext2Fs, inode_num: u32, target_block_count: usize) -> Result<(), Ext2Error> {
    let inode = read_inode(fs, inode_num)?;
    let block_size = fs.sb.block_size() as u64;
    let ptrs_per_block = (block_size / 4) as usize;
    let max_capacity_blocks = 12 + ptrs_per_block;
    if target_block_count > max_capacity_blocks {
        return Err(Ext2Error::FileTooLarge);
    }

    let pointers = block_pointers(fs, &inode)?;
    let mut used_blocks = pointers.iter().take_while(|&&b| b != 0).count();
    if used_blocks >= target_block_count {
        return Ok(());
    }

    while used_blocks < target_block_count {
        let new_block = allocate_one_block(fs)?;
        link_block_into_inode(fs, inode_num, used_blocks, new_block)?;
        used_blocks += 1;
    }

    Ok(())
}

/// Overwrites an EXISTING regular file's content (patch_48 in-place;
/// patch_49 real growth into direct blocks; patch_52 extends growth past
/// direct blocks into the indirect block, via the shared
/// grow_inode_to_block_count() primitive) — see the module doc's "WRITE
/// SUPPORT" section for full scope. If `data` fits within the inode's
/// already-allocated block prefix (allocated_prefix_capacity()), this
/// behaves exactly as patch_48 did — no allocation touched at all.
///
/// If `data` is larger, grow_inode_to_block_count() allocates exactly as
/// many additional blocks as needed, direct slots first and the indirect
/// block after. i_size is updated to data.len() in either case.
///
/// Returns IsADirectory if the target inode is a directory,
/// WriteExceedsAllocatedCapacity only in the (now rarer) case growth
/// itself isn't even attempted-worthy, FileTooLarge if the needed growth
/// would exceed direct+indirect capacity entirely, and NoFreeBlocks if
/// the filesystem has no space left to grow into.
pub fn write_file_in_place(fs: &Ext2Fs, inode_num: u32, data: &[u8]) -> Result<(), Ext2Error> {
    let inode = read_inode(fs, inode_num)?;
    if inode.is_directory() {
        return Err(Ext2Error::IsADirectory);
    }

    let block_size = fs.sb.block_size() as u64;
    let capacity = allocated_prefix_capacity(fs, &inode)?;

    if data.len() as u64 > capacity {
        let target_block_count = ((data.len() as u64 + block_size - 1) / block_size) as usize;
        grow_inode_to_block_count(fs, inode_num, target_block_count)?;
    }

    // Re-read the inode fresh so the block list below reflects exactly
    // what's now on disk (whether or not growth just ran above) - avoids
    // keeping two parallel in-memory views of the pointer array that
    // could drift from what was actually written.
    let inode = read_inode(fs, inode_num)?;

    // Write the new content into the (now possibly-grown) block list, in
    // order, exactly mirroring read_file()'s own block-walking loop shape
    // (minus the sparse-zero-fill branch, which never applies here).
    let mut remaining = data.len();
    let mut off = 0usize;
    for block_num in block_pointers(fs, &inode)? {
        if remaining == 0 {
            break;
        }
        let this_len = remaining.min(block_size as usize);
        write_bytes_at(fs.partition_start_lba, block_num as u64 * block_size, &data[off..off + this_len])?;
        off += this_len;
        remaining -= this_len;
    }

    // Update i_size (offset 4..8 within the inode record) to reflect the
    // new length — the only inode metadata field this write path touches
    // beyond any new i_block[] pointers written above.
    let inode_off = inode_byte_offset(fs, inode_num)?;
    let new_size = (data.len() as u32).to_le_bytes();
    write_bytes_at(fs.partition_start_lba, inode_off + 4, &new_size)?;

    Ok(())
}

/// Rounds up to the next multiple of 4 — ext2 directory-entry rec_len and
/// the "actual" space an entry needs (8-byte header + name) are both
/// always 4-byte aligned.
fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Inserts a new (inode_num, name) directory entry into dir_inode_num's
/// directory, using slack space in an EXISTING entry's rec_len (patch_50),
/// or a fully-free (ino=0) slot left by a prior deletion (patch_51) —
/// real ext2 directory entries routinely have rec_len larger than the
/// 8-byte-header-plus-name they actually need (mke2fs leaves the last
/// entry in each block padded out to the block boundary), and this is
/// exactly that slack being reused, the same way a real ext2
/// implementation's own insertion path works for the common case.
///
/// Scans every block the directory owns (block_pointers(), so this
/// benefits from patch_46's indirect-block reading same as everything
/// else) for the first entry whose rec_len exceeds its own actual need by
/// at least enough to also fit the new entry. If NO existing block has
/// room, patch_53 grows the directory by one block
/// (grow_inode_to_block_count(), the same shared primitive
/// write_file_in_place()'s own growth uses), initializes that new block
/// as one single giant free (ino=0) entry spanning the whole block, and
/// retries — the retry is guaranteed to succeed against the fresh block's
/// full-block slack (any real filename fits well within one block), so
/// this recurses at most once. Only returns DirectoryFull when the
/// directory has already reached direct+indirect capacity and genuinely
/// cannot grow further.
fn insert_dir_entry(fs: &Ext2Fs, dir_inode_num: u32, name: &str, new_inode: u32, file_type: u8) -> Result<(), Ext2Error> {
    let dir_inode = read_inode(fs, dir_inode_num)?;
    if !dir_inode.is_directory() {
        return Err(Ext2Error::NotADirectory);
    }
    let block_size = fs.sb.block_size() as u64;
    let needed_len = align4(8 + name.len());

    for block_num in block_pointers(fs, &dir_inode)? {
        if block_num == 0 {
            continue;
        }
        let block_byte_offset = block_num as u64 * block_size;
        let raw = read_bytes_at(fs.partition_start_lba, block_byte_offset, block_size as usize)?;

        let mut off = 0usize;
        while off + 8 <= raw.len() {
            let ino = u32_from_le(&raw[off..off + 4]);
            let rec_len = u16_from_le(&raw[off + 4..off + 6]) as usize;
            let existing_name_len = raw[off + 6] as usize;
            if rec_len == 0 {
                break; // corrupt entry; avoid an infinite loop, same guard as read_dir_entries()
            }

            if ino == 0 {
                // A fully-free slot (patch_51: left behind by
                // remove_dir_entry() when the deleted entry was the first
                // in its block, so there was no preceding live entry to
                // merge its space into). The WHOLE rec_len is directly
                // reusable in place - no shrink/split needed, since
                // there's no live entry here to preserve.
                if rec_len >= needed_len {
                    write_bytes_at(fs.partition_start_lba, block_byte_offset + off as u64, &new_inode.to_le_bytes())?;
                    // rec_len is left unchanged (the slot's full size is
                    // inherited by the new entry - matches how a real
                    // ext2 implementation reuses a fully-free dirent).
                    write_bytes_at(fs.partition_start_lba, block_byte_offset + off as u64 + 6, &[name.len() as u8])?;
                    write_bytes_at(fs.partition_start_lba, block_byte_offset + off as u64 + 7, &[file_type])?;
                    write_bytes_at(fs.partition_start_lba, block_byte_offset + off as u64 + 8, name.as_bytes())?;
                    return Ok(());
                }
                off += rec_len;
                continue;
            }

            // A live entry (ino != 0): consider the TRAILING slack past
            // what it actually needs, same as before patch_51.
            let actual_len = align4(8 + existing_name_len);
            let slack = rec_len.saturating_sub(actual_len);

            if slack >= needed_len {
                let new_entry_off = off + actual_len;

                // Shrink the existing entry's rec_len to its real size.
                write_bytes_at(fs.partition_start_lba, block_byte_offset + off as u64 + 4, &(actual_len as u16).to_le_bytes())?;

                // Write the new entry into the freed slack.
                write_bytes_at(fs.partition_start_lba, block_byte_offset + new_entry_off as u64, &new_inode.to_le_bytes())?;
                write_bytes_at(fs.partition_start_lba, block_byte_offset + new_entry_off as u64 + 4, &(slack as u16).to_le_bytes())?;
                write_bytes_at(fs.partition_start_lba, block_byte_offset + new_entry_off as u64 + 6, &[name.len() as u8])?;
                write_bytes_at(fs.partition_start_lba, block_byte_offset + new_entry_off as u64 + 7, &[file_type])?;
                write_bytes_at(fs.partition_start_lba, block_byte_offset + new_entry_off as u64 + 8, name.as_bytes())?;

                return Ok(());
            }

            off += rec_len;
        }
    }

    // No existing block had room. Grow the directory by one block and
    // retry - the retry's own scan will find the fresh block's full-block
    // ino=0 slack via the branch above.
    //
    // Crash-safety (patch_55): unlike grow_inode_to_block_count()'s own
    // allocate-then-link-immediately order (fine for regular file data,
    // which is only ever returned as raw bytes, never parsed), a
    // directory block's content IS parsed as structure by
    // read_dir_entries() — freed blocks are never zeroed on free (by
    // design, matching real ext2), so a block that became reachable
    // before being initialized could have anything in it from whatever
    // used it last, and would be misread as real directory entries. So
    // this allocates the raw block and writes its real content FIRST,
    // and only calls link_block_into_inode() — making it reachable —
    // afterward. A crash before linking just leaves an allocated-but-
    // unlinked block (a harmless leak); it can never leave a reachable,
    // uninitialized one.
    let pointers = block_pointers(fs, &dir_inode)?;
    let used_blocks = pointers.iter().take_while(|&&b| b != 0).count();
    let ptrs_per_block = (block_size / 4) as usize;
    if used_blocks >= 12 + ptrs_per_block {
        return Err(Ext2Error::DirectoryFull);
    }

    let new_block_num = allocate_one_block(fs)?;
    let mut empty_block = vec![0u8; block_size as usize];
    empty_block[4..6].copy_from_slice(&(block_size as u16).to_le_bytes());
    write_bytes_at(fs.partition_start_lba, new_block_num as u64 * block_size, &empty_block)?;
    link_block_into_inode(fs, dir_inode_num, used_blocks, new_block_num)?;

    insert_dir_entry(fs, dir_inode_num, name, new_inode, file_type)
}

/// Creates a new, empty regular file named `name` inside dir_inode_num's
/// directory, owned by (uid, gid) (patch_50) — this project's first real
/// ext2 file creation. Allocates one inode (allocate_one_inode()), writes
/// a minimal fresh inode record (mode 0o100644 - regular file, rw-r--r--;
/// i_size 0; i_links_count 1; every i_block[] slot 0, i.e. no data blocks
/// yet), inserts its directory entry (insert_dir_entry()), and returns the
/// new inode number. The caller (Ext2Filesystem::write_owned()) is
/// responsible for writing any actual content afterward, via the existing
/// write_file_in_place() growth path — creation itself never allocates
/// data blocks, only the inode.
///
/// Returns AlreadyExists if `name` already exists in the directory,
/// NotADirectory if dir_inode_num isn't one, and propagates NoFreeInodes/
/// DirectoryFull from the two steps above unchanged.
fn create_file(fs: &Ext2Fs, dir_inode_num: u32, name: &str, uid: u32, gid: u32) -> Result<u32, Ext2Error> {
    let existing = read_dir_entries(fs, dir_inode_num)?;
    if existing.iter().any(|e| e.name == name) {
        return Err(Ext2Error::AlreadyExists);
    }

    let new_inode_num = allocate_one_inode(fs)?;

    // Fresh, minimal inode record - see this function's own doc for which
    // fields are set and why the rest are left zero.
    let mut inode_buf = [0u8; 128];
    inode_buf[0..2].copy_from_slice(&0o100644u16.to_le_bytes()); // i_mode: S_IFREG | 0644
    inode_buf[2..4].copy_from_slice(&(uid as u16).to_le_bytes());
    inode_buf[4..8].copy_from_slice(&0u32.to_le_bytes()); // i_size
    inode_buf[24..26].copy_from_slice(&(gid as u16).to_le_bytes());
    inode_buf[26..28].copy_from_slice(&1u16.to_le_bytes()); // i_links_count
    // i_block[0..15] (offset 40..100) already zero from the buffer init.

    let inode_off = inode_byte_offset(fs, new_inode_num)?;
    write_bytes_at(fs.partition_start_lba, inode_off, &inode_buf)?;

    const EXT2_FT_REG_FILE: u8 = 1;
    insert_dir_entry(fs, dir_inode_num, name, new_inode_num, EXT2_FT_REG_FILE)?;

    Ok(new_inode_num)
}

/// Removes `name`'s directory entry from dir_inode_num's directory
/// (patch_51), returning the inode number it pointed to. Scans every
/// block the directory owns; when the matching entry is found:
///   - If it is NOT the first entry in its block, merges its rec_len into
///     the immediately preceding entry in the SAME block (a directory
///     entry chain never spans blocks) — the standard ext2 unlink
///     technique, and exactly what makes that reclaimed space show up as
///     trailing slack the next time insert_dir_entry() scans this block.
///   - If it IS the first entry in its block, there is no preceding entry
///     to merge into, so it is instead left in place with ino set to 0
///     and its rec_len UNCHANGED — a fully-free slot, which patch_51's
///     updated insert_dir_entry() now recognizes and reuses directly.
///
/// Returns NotFound if `name` doesn't exist in the directory.
fn remove_dir_entry(fs: &Ext2Fs, dir_inode_num: u32, name: &str) -> Result<u32, Ext2Error> {
    let dir_inode = read_inode(fs, dir_inode_num)?;
    if !dir_inode.is_directory() {
        return Err(Ext2Error::NotADirectory);
    }
    let block_size = fs.sb.block_size() as u64;

    for block_num in block_pointers(fs, &dir_inode)? {
        if block_num == 0 {
            continue;
        }
        let block_byte_offset = block_num as u64 * block_size;
        let raw = read_bytes_at(fs.partition_start_lba, block_byte_offset, block_size as usize)?;

        let mut off = 0usize;
        let mut prev_off: Option<usize> = None;
        while off + 8 <= raw.len() {
            let ino = u32_from_le(&raw[off..off + 4]);
            let rec_len = u16_from_le(&raw[off + 4..off + 6]) as usize;
            let name_len = raw[off + 6] as usize;
            if rec_len == 0 {
                break;
            }

            if ino != 0 && off + 8 + name_len <= raw.len() {
                if let Ok(entry_name) = core::str::from_utf8(&raw[off + 8..off + 8 + name_len]) {
                    if entry_name == name {
                        let deleted_inode = ino;
                        match prev_off {
                            Some(p) => {
                                // Merge into the preceding entry: its
                                // rec_len grows to also cover this one.
                                let prev_rec_len = u16_from_le(&raw[p + 4..p + 6]) as usize;
                                let new_prev_rec_len = prev_rec_len + rec_len;
                                write_bytes_at(fs.partition_start_lba, block_byte_offset + p as u64 + 4, &(new_prev_rec_len as u16).to_le_bytes())?;
                            }
                            None => {
                                // First entry in the block - no predecessor
                                // to merge into. Zero ino, leave rec_len
                                // as-is (a fully-free slot).
                                write_bytes_at(fs.partition_start_lba, block_byte_offset + off as u64, &0u32.to_le_bytes())?;
                            }
                        }
                        return Ok(deleted_inode);
                    }
                }
            }

            prev_off = Some(off);
            off += rec_len;
        }
    }

    Err(Ext2Error::NotFound)
}

/// Deletes a regular file (patch_51; reordered in patch_55 for real
/// crash-safety — see below). Removes its directory entry
/// (remove_dir_entry()), frees every data block it owned — including its
/// singly-indirect block itself, not just the pointers inside it, since
/// block_pointers() only returns those inner pointers — zeroes its inode
/// record, and frees the inode (free_one_inode()).
///
/// Crash-safety (patch_55): the directory entry is removed FIRST, before
/// anything is freed — the reverse of this function's original patch_51
/// order. Freeing blocks before removing the entry would leave a real
/// hazard: a crash in that gap leaves a live directory entry pointing at
/// blocks the bitmap now says are free, and if anything reallocates them
/// before the entry is ever cleaned up, reading through that stale entry
/// would return a DIFFERENT file's data — not just a leak, a genuine
/// data-confusion hazard. Removing the entry first means a crash after
/// that point only ever leaks the now-unreferenced blocks/inode (bitmap
/// bits stay marked used, nothing points to them) — safe, if wasteful,
/// and exactly the ordering a real unlink() uses for the same reason.
///
/// Returns NotFound if `name` doesn't exist, IsADirectory if it names a
/// directory (directory deletion is delete_directory()'s job — see
/// module doc).
fn delete_file(fs: &Ext2Fs, dir_inode_num: u32, name: &str) -> Result<(), Ext2Error> {
    let existing = read_dir_entries(fs, dir_inode_num)?;
    let target = existing.iter().find(|e| e.name == name).ok_or(Ext2Error::NotFound)?;
    let inode_num = target.inode;

    let inode = read_inode(fs, inode_num)?;
    if inode.is_directory() {
        return Err(Ext2Error::IsADirectory);
    }

    // Remove the directory entry FIRST (patch_55) - see this function's
    // own doc comment for why this ordering, not the reverse, is the
    // crash-safe one.
    let _ = remove_dir_entry(fs, dir_inode_num, name)?;

    // Now free every data block, direct and (the pointers inside)
    // indirect - nothing can reach this inode via the directory anymore,
    // so a crash from here on can only ever leak resources, never leave
    // a dangling reference.
    for block_num in block_pointers(fs, &inode)? {
        if block_num != 0 {
            free_one_block(fs, block_num)?;
        }
    }
    // The indirect block itself (i_block[12]) is not among
    // block_pointers()'s returned entries - it holds pointers, it isn't
    // one - so it needs freeing separately if this inode had one.
    if inode.i_block[12] != 0 {
        free_one_block(fs, inode.i_block[12])?;
    }

    // Zero the inode record before freeing its bit, so there is never a
    // window where the bit says "free" but the record still looks live.
    let inode_off = inode_byte_offset(fs, inode_num)?;
    write_bytes_at(fs.partition_start_lba, inode_off, &[0u8; 128])?;
    free_one_inode(fs, inode_num)?;

    Ok(())
}

/// Removes an EMPTY directory (patch_54; reordered in patch_55 for real
/// crash-safety, same reasoning as delete_file() — see below) — refuses
/// (DirectoryNotEmpty) unless the target contains only "." and ".." and
/// no other live entries. On success: removes its entry from its
/// PARENT's directory (remove_dir_entry()) and decrements the parent's
/// i_links_count by 1 (the deleted directory's own ".." entry counted as
/// a link to the parent — real, standard ext2 bookkeeping this driver
/// hadn't needed until now), THEN frees every data block the directory
/// owned (including its indirect block itself, same as delete_file()),
/// zeroes and frees its inode, and decrements the owning block group's
/// bg_used_dirs_count by 1 (see decrement_group_used_dirs()'s own doc
/// for why this driver only ever needs to decrement that field, never
/// increment it).
///
/// Crash-safety (patch_55): the directory entry is removed from the
/// PARENT first, before this directory's own blocks/inode are freed —
/// the reverse of this function's original patch_54 order, for exactly
/// the same reason as delete_file()'s own reordering: freeing blocks
/// before removing the parent's entry would leave a live entry pointing
/// at blocks the bitmap says are free, reachable and reallocatable to
/// something else before the entry is ever cleaned up. Removing the
/// entry first means a crash from that point on only ever leaks
/// resources, never leaves a dangling reference.
///
/// Returns NotFound if `name` doesn't exist, NotADirectory if it names a
/// regular file (use delete_file() for that), and DirectoryNotEmpty if
/// the directory still has real content. Recursive deletion (removing a
/// non-empty directory and everything inside it) is NOT supported — the
/// caller must empty it first, same as a real `rmdir`.
fn delete_directory(fs: &Ext2Fs, parent_inode_num: u32, name: &str) -> Result<(), Ext2Error> {
    let existing = read_dir_entries(fs, parent_inode_num)?;
    let target = existing.iter().find(|e| e.name == name).ok_or(Ext2Error::NotFound)?;
    let dir_inode_num = target.inode;

    let inode = read_inode(fs, dir_inode_num)?;
    if !inode.is_directory() {
        return Err(Ext2Error::NotADirectory);
    }

    let entries = read_dir_entries(fs, dir_inode_num)?;
    let has_real_content = entries.iter().any(|e| e.name != "." && e.name != "..");
    if has_real_content {
        return Err(Ext2Error::DirectoryNotEmpty);
    }

    // Remove from the parent's listing FIRST (patch_55), and account for
    // the ".." link this directory held on its parent - see this
    // function's own doc comment for why this ordering matters.
    let _ = remove_dir_entry(fs, parent_inode_num, name)?;
    decrement_inode_links(fs, parent_inode_num)?;

    // Now free every data block, direct and (the pointers inside)
    // indirect, plus the indirect block itself if one exists - nothing
    // can reach this directory via its parent anymore, so a crash from
    // here on can only ever leak resources.
    for block_num in block_pointers(fs, &inode)? {
        if block_num != 0 {
            free_one_block(fs, block_num)?;
        }
    }
    if inode.i_block[12] != 0 {
        free_one_block(fs, inode.i_block[12])?;
    }

    // Zero the inode record before freeing its bit, so there is never a
    // window where the bit says "free" but the record still looks live.
    let inode_off = inode_byte_offset(fs, dir_inode_num)?;
    write_bytes_at(fs.partition_start_lba, inode_off, &[0u8; 128])?;
    free_one_inode(fs, dir_inode_num)?;

    decrement_group_used_dirs(fs, dir_inode_num)?;

    Ok(())
}

// ─── VFS integration (patch_43) ────────────────────────────────────────────
//
// Wraps the read-only driver above (mount()/read_dir_entries()/read_file())
// behind the vfs::Filesystem trait, so ext2 becomes mountable at a real
// path (e.g. "/mnt") alongside tmpfs, rather than only reachable via direct
// fs::ext2::* calls from a kshell test. As of patch_45, multi-level paths
// below the mountpoint resolve via resolve_path() rather than being
// rejected — read/readdir/stat all walk the real directory tree.

use crate::fs::vfs::{DirEntry as VfsDirEntry, FileStat, FsError, Filesystem};

pub struct Ext2Filesystem {
    inner: Ext2Fs,
    mountpoint: String,
}

impl Ext2Filesystem {
    /// Strips the mountpoint prefix and any leading '/' from an absolute
    /// VFS path, returning the path relative to this filesystem's root.
    /// Ok("") means "the mount root itself". As of patch_45, a remaining
    /// '/' is no longer rejected here — resolve_path() below now walks
    /// multi-level paths for real, so this is just prefix-stripping.
    fn relative_name<'a>(&self, path: &'a str) -> Result<&'a str, FsError> {
        if !path.starts_with(self.mountpoint.as_str()) {
            return Err(FsError::InvalidPath);
        }
        Ok(path[self.mountpoint.len()..].trim_start_matches('/'))
    }

    /// Resolves a VFS-absolute path to an inode number via resolve_path(),
    /// translating Ext2Error into the matching FsError.
    fn resolve(&self, path: &str) -> Result<u32, FsError> {
        let name = self.relative_name(path)?;
        if name.is_empty() {
            return Ok(ROOT_INODE);
        }
        resolve_path(&self.inner, name).map_err(|e| match e {
            Ext2Error::NotFound => FsError::NotFound,
            Ext2Error::NotADirectory => FsError::NotADirectory,
            _ => FsError::IoError,
        })
    }
}

impl Filesystem for Ext2Filesystem {
    fn name(&self) -> &'static str { "ext2" }

    fn read(&self, path: &str, buf: &mut [u8]) -> Result<usize, FsError> {
        let inode_num = self.resolve(path)?;
        let data = read_file(&self.inner, inode_num).map_err(|e| match e {
            Ext2Error::IsADirectory => FsError::IsADirectory,
            _ => FsError::IoError,
        })?;
        let n = buf.len().min(data.len());
        buf[..n].copy_from_slice(&data[..n]);
        Ok(n)
    }

    fn write(&self, path: &str, buf: &[u8]) -> Result<usize, FsError> {
        // patch_48/49: real, for an EXISTING regular file, within its
        // already-allocated capacity or by growing into new direct
        // blocks. Creation (a path that doesn't exist yet) is handled by
        // write_owned() below, which is what vfs::write() actually calls
        // — this function is reused directly by write_owned() for the
        // existing-file case, and remains callable on its own for any
        // caller that already knows the file exists.
        let inode_num = self.resolve(path)?;
        write_file_in_place(&self.inner, inode_num, buf).map_err(|e| match e {
            Ext2Error::IsADirectory => FsError::IsADirectory,
            Ext2Error::NotFound => FsError::NotFound,
            Ext2Error::WriteExceedsAllocatedCapacity
            | Ext2Error::NoFreeBlocks
            | Ext2Error::FileTooLarge => FsError::NoSpace,
            _ => FsError::IoError,
        })?;
        Ok(buf.len())
    }

    fn write_owned(&self, path: &str, buf: &[u8], uid: u32, gid: u32) -> Result<usize, FsError> {
        // vfs::write() always calls this (never write() directly) — see
        // fs/vfs.rs's own write() dispatch. patch_50: if the path already
        // exists, behave exactly as write() always has (uid/gid ignored,
        // matching patch_48/49's unchanged existing-file semantics). If it
        // doesn't, create a new empty file (using uid/gid as its owner)
        // and then write the content into it via the same growth path
        // write_file_in_place() already provides for existing files —
        // creation itself only ever allocates the inode, never any data
        // blocks; the content write immediately after handles that.
        match self.resolve(path) {
            Ok(_) => self.write(path, buf),
            Err(FsError::NotFound) => {
                let rel = self.relative_name(path)?;
                let (parent_rel, name) = match rel.rfind('/') {
                    Some(idx) => (&rel[..idx], &rel[idx + 1..]),
                    None => ("", rel),
                };
                if name.is_empty() {
                    return Err(FsError::InvalidPath);
                }
                let parent_inode = if parent_rel.is_empty() {
                    ROOT_INODE
                } else {
                    resolve_path(&self.inner, parent_rel).map_err(|e| match e {
                        Ext2Error::NotFound => FsError::NotFound,
                        Ext2Error::NotADirectory => FsError::NotADirectory,
                        _ => FsError::IoError,
                    })?
                };

                let new_inode = create_file(&self.inner, parent_inode, name, uid, gid).map_err(|e| match e {
                    Ext2Error::AlreadyExists => FsError::InvalidPath, // race: created between resolve() and here
                    Ext2Error::NotADirectory => FsError::NotADirectory,
                    Ext2Error::NoFreeInodes | Ext2Error::DirectoryFull => FsError::NoSpace,
                    _ => FsError::IoError,
                })?;

                if buf.is_empty() {
                    return Ok(0);
                }
                write_file_in_place(&self.inner, new_inode, buf).map_err(|e| match e {
                    Ext2Error::WriteExceedsAllocatedCapacity
                    | Ext2Error::NoFreeBlocks
                    | Ext2Error::FileTooLarge => FsError::NoSpace,
                    _ => FsError::IoError,
                })?;
                Ok(buf.len())
            }
            Err(e) => Err(e),
        }
    }

    fn remove(&self, path: &str) -> Result<(), FsError> {
        // patch_51: real deletion for a regular file. patch_54 extends
        // this to empty directories too (delete_directory()) - dispatch
        // on the target's actual type rather than trying delete_file()
        // first and reacting to its IsADirectory error, since
        // delete_directory() needs its own emptiness check regardless.
        // Splits path the same way write_owned()'s creation branch does,
        // since both delete_file() and delete_directory() need the
        // PARENT directory's inode plus the bare filename, not the full
        // path.
        let rel = self.relative_name(path)?;
        let (parent_rel, name) = match rel.rfind('/') {
            Some(idx) => (&rel[..idx], &rel[idx + 1..]),
            None => ("", rel),
        };
        if name.is_empty() {
            return Err(FsError::InvalidPath);
        }
        let parent_inode = if parent_rel.is_empty() {
            ROOT_INODE
        } else {
            resolve_path(&self.inner, parent_rel).map_err(|e| match e {
                Ext2Error::NotFound => FsError::NotFound,
                Ext2Error::NotADirectory => FsError::NotADirectory,
                _ => FsError::IoError,
            })?
        };

        let target_entries = read_dir_entries(&self.inner, parent_inode).map_err(|_| FsError::IoError)?;
        let target = target_entries.iter().find(|e| e.name == name).ok_or(FsError::NotFound)?;
        let target_inode = read_inode(&self.inner, target.inode).map_err(|_| FsError::IoError)?;

        if target_inode.is_directory() {
            delete_directory(&self.inner, parent_inode, name).map_err(|e| match e {
                Ext2Error::NotFound => FsError::NotFound,
                Ext2Error::NotADirectory => FsError::NotADirectory,
                Ext2Error::DirectoryNotEmpty => FsError::DirectoryNotEmpty,
                _ => FsError::IoError,
            })
        } else {
            delete_file(&self.inner, parent_inode, name).map_err(|e| match e {
                Ext2Error::NotFound => FsError::NotFound,
                Ext2Error::IsADirectory => FsError::IsADirectory,
                Ext2Error::NotADirectory => FsError::NotADirectory,
                _ => FsError::IoError,
            })
        }
    }

    fn readdir(&self, path: &str) -> Result<Vec<VfsDirEntry>, FsError> {
        let dir_inode_num = self.resolve(path)?;
        let dir_inode = read_inode(&self.inner, dir_inode_num).map_err(|_| FsError::IoError)?;
        if !dir_inode.is_directory() {
            return Err(FsError::NotADirectory);
        }
        let entries = read_dir_entries(&self.inner, dir_inode_num).map_err(|_| FsError::IoError)?;
        let mut out = Vec::new();
        for e in entries {
            if e.name == "." || e.name == ".." {
                continue; // match tmpfs::readdir's own convention of omitting these
            }
            let inode = read_inode(&self.inner, e.inode).map_err(|_| FsError::IoError)?;
            out.push(VfsDirEntry {
                name: e.name,
                is_dir: inode.is_directory(),
                size: inode.i_size as u64,
            });
        }
        Ok(out)
    }

    fn stat(&self, path: &str) -> Result<FileStat, FsError> {
        let inode_num = self.resolve(path)?;
        let inode = read_inode(&self.inner, inode_num).map_err(|_| FsError::IoError)?;
        Ok(FileStat {
            size: inode.i_size as u64,
            is_dir: inode.is_directory(),
            mode: inode.i_mode as u32,
            uid: inode.i_uid as u32,
            gid: inode.i_gid as u32,
            // ext2 inode timestamps aren't parsed by this driver yet - 0
            // matches tmpfs::stat()'s own existing atime/mtime convention
            // for the same "not tracked yet" reason, not a new gap.
            atime: 0,
            mtime: 0,
        })
    }
}

/// Mounts an ext2 partition at `mountpoint` through the real VFS, so
/// ordinary fs::vfs::read()/write()/stat()/readdir() calls (and therefore
/// open()/read_fd()/write_fd()) work against it exactly like tmpfs.
pub fn mount_to_vfs(mountpoint: &str, partition_start_lba: u64) -> Result<(), Ext2Error> {
    let inner = mount(partition_start_lba)?;
    crate::fs::vfs::mount(mountpoint, alloc::boxed::Box::new(Ext2Filesystem {
        inner,
        mountpoint: String::from(mountpoint),
    }));
    Ok(())
}
