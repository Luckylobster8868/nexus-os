#!/usr/bin/env python3
"""
patch_43_ext2_vfs_integration.py

Filesystem/partition integration, step 3: wires the read-only ext2 driver
(patch_42) into the real vfs::Filesystem trait, so it becomes mountable at
a path (e.g. "/mnt") and reachable through ordinary fs::vfs:: calls - the
same chokepoints tmpfs already goes through, including real permission
enforcement (check_permission()) driven by the actual on-disk ext2
uid/gid/mode, not simulated.

Does four things:
  1. Appends an Ext2Filesystem adapter + mount_to_vfs() to the END of the
     existing fs/ext2.rs (does not recreate the file - it must already
     exist from patch_42).
  2. Adds a new fs::vfs::readdir() free function to fs/vfs.rs - this did
     not exist before this patch (only read/write/stat/open had top-level
     mount-table-resolving wrappers; readdir was trait-only). Added
     following stat()'s exact existing pattern (same mount lookup, no
     permission check). vfs.rs's own mount_root() already has a
     pre-existing TODO anticipating exactly this kind of real-filesystem
     integration.
  3. Adds a new `ext2mounttest` kshell command to main.rs, right after the
     existing ext2test arm (patch_42).
  4. Updates the help command's printed list to include ext2mounttest.

Every step checks whether it has already been applied (via a unique
marker) before touching anything, and is safe to re-run: a step that
detects it's already applied is skipped, not re-applied - this defends
against the exact scenario that caused patch_42's fs/mod.rs to get
accidentally duplicated when it was re-run against an already-patched file.

Requires patch_41 and patch_42 already applied.
Run from ~/nexus-os/kernel/src.
"""
import os
import sys

FS_DIR = "fs"
EXT2_FILE = os.path.join(FS_DIR, "ext2.rs")
VFS_FILE = os.path.join(FS_DIR, "vfs.rs")
MAIN_FILE = "main.rs"

EXT2_RS_OLD = '    let mut data = Vec::with_capacity(size);\n    let mut remaining = size;\n    for &block_num in inode.i_block[0..12].iter() {\n        if remaining == 0 {\n            break;\n        }\n        let this_len = remaining.min(block_size as usize);\n        if block_num == 0 {\n            // Sparse block - real ext2 files can have holes; read as zeros.\n            data.extend(core::iter::repeat(0u8).take(this_len));\n        } else {\n            let raw = read_bytes_at(fs.partition_start_lba, block_num as u64 * block_size, this_len)?;\n            data.extend_from_slice(&raw);\n        }\n        remaining -= this_len;\n    }\n\n    Ok(data)\n}'

EXT2_RS_NEW = '    let mut data = Vec::with_capacity(size);\n    let mut remaining = size;\n    for &block_num in inode.i_block[0..12].iter() {\n        if remaining == 0 {\n            break;\n        }\n        let this_len = remaining.min(block_size as usize);\n        if block_num == 0 {\n            // Sparse block - real ext2 files can have holes; read as zeros.\n            data.extend(core::iter::repeat(0u8).take(this_len));\n        } else {\n            let raw = read_bytes_at(fs.partition_start_lba, block_num as u64 * block_size, this_len)?;\n            data.extend_from_slice(&raw);\n        }\n        remaining -= this_len;\n    }\n\n    Ok(data)\n}\n\n// ─── VFS integration (patch_43) ────────────────────────────────────────────\n//\n// Wraps the read-only driver above (mount()/read_dir_entries()/read_file())\n// behind the vfs::Filesystem trait, so ext2 becomes mountable at a real\n// path (e.g. "/mnt") alongside tmpfs, rather than only reachable via direct\n// fs::ext2::* calls from a kshell test. Root-directory-only, matching the\n// underlying driver\'s own explicitly deferred scope (see module doc) - a\n// path with more than one path segment below the mountpoint returns\n// InvalidPath, not a silent wrong answer.\n\nuse crate::fs::vfs::{DirEntry as VfsDirEntry, FileStat, FsError, Filesystem};\n\npub struct Ext2Filesystem {\n    inner: Ext2Fs,\n    mountpoint: String,\n}\n\nimpl Ext2Filesystem {\n    /// Strips the mountpoint prefix and any leading \'/\' from an absolute\n    /// VFS path, returning the bare filename relative to this filesystem\'s\n    /// root. Ok("") means "the mount root itself". A remaining \'/\' means a\n    /// path more than one level deep, which this first slice doesn\'t\n    /// support (see module doc\'s "root-directory lookups only").\n    fn relative_name<\'a>(&self, path: &\'a str) -> Result<&\'a str, FsError> {\n        if !path.starts_with(self.mountpoint.as_str()) {\n            return Err(FsError::InvalidPath);\n        }\n        let rest = path[self.mountpoint.len()..].trim_start_matches(\'/\');\n        if rest.contains(\'/\') {\n            return Err(FsError::InvalidPath);\n        }\n        Ok(rest)\n    }\n}\n\nimpl Filesystem for Ext2Filesystem {\n    fn name(&self) -> &\'static str { "ext2" }\n\n    fn read(&self, path: &str, buf: &mut [u8]) -> Result<usize, FsError> {\n        let name = self.relative_name(path)?;\n        if name.is_empty() {\n            return Err(FsError::IsADirectory);\n        }\n        let inode_num = lookup_in_root(&self.inner, name).map_err(|_| FsError::NotFound)?;\n        let data = read_file(&self.inner, inode_num).map_err(|_| FsError::IoError)?;\n        let n = buf.len().min(data.len());\n        buf[..n].copy_from_slice(&data[..n]);\n        Ok(n)\n    }\n\n    fn write(&self, _path: &str, _buf: &[u8]) -> Result<usize, FsError> {\n        // Real, deliberate limitation, not a stub oversight - see module\n        // doc: this driver is read-only. Write support is a follow-up\n        // patch, same as CRC32 validation on the GPT parser was deferred.\n        Err(FsError::PermissionDenied)\n    }\n\n    fn readdir(&self, path: &str) -> Result<Vec<VfsDirEntry>, FsError> {\n        let name = self.relative_name(path)?;\n        if !name.is_empty() {\n            // Only the mount root itself is listable in this first slice.\n            return Err(FsError::NotADirectory);\n        }\n        let entries = read_dir_entries(&self.inner, ROOT_INODE).map_err(|_| FsError::IoError)?;\n        let mut out = Vec::new();\n        for e in entries {\n            if e.name == "." || e.name == ".." {\n                continue; // match tmpfs::readdir\'s own convention of omitting these\n            }\n            let inode = read_inode(&self.inner, e.inode).map_err(|_| FsError::IoError)?;\n            out.push(VfsDirEntry {\n                name: e.name,\n                is_dir: inode.is_directory(),\n                size: inode.i_size as u64,\n            });\n        }\n        Ok(out)\n    }\n\n    fn stat(&self, path: &str) -> Result<FileStat, FsError> {\n        let name = self.relative_name(path)?;\n        let inode_num = if name.is_empty() {\n            ROOT_INODE\n        } else {\n            lookup_in_root(&self.inner, name).map_err(|_| FsError::NotFound)?\n        };\n        let inode = read_inode(&self.inner, inode_num).map_err(|_| FsError::IoError)?;\n        Ok(FileStat {\n            size: inode.i_size as u64,\n            is_dir: inode.is_directory(),\n            mode: inode.i_mode as u32,\n            uid: inode.i_uid as u32,\n            gid: inode.i_gid as u32,\n            // ext2 inode timestamps aren\'t parsed by this driver yet - 0\n            // matches tmpfs::stat()\'s own existing atime/mtime convention\n            // for the same "not tracked yet" reason, not a new gap.\n            atime: 0,\n            mtime: 0,\n        })\n    }\n}\n\n/// Mounts an ext2 partition at `mountpoint` through the real VFS, so\n/// ordinary fs::vfs::read()/write()/stat()/readdir() calls (and therefore\n/// open()/read_fd()/write_fd()) work against it exactly like tmpfs.\npub fn mount_to_vfs(mountpoint: &str, partition_start_lba: u64) -> Result<(), Ext2Error> {\n    let inner = mount(partition_start_lba)?;\n    crate::fs::vfs::mount(mountpoint, alloc::boxed::Box::new(Ext2Filesystem {\n        inner,\n        mountpoint: String::from(mountpoint),\n    }));\n    Ok(())\n}'

EXT2_RS_MARKER = 'pub struct Ext2Filesystem {'

VFS_RS_OLD = 'pub fn stat(path: &str) -> Result<FileStat, FsError> {\n    let mounts = MOUNTS.read();\n    let entry = mounts.iter().rev()\n        .find(|m| path.starts_with(m.mountpoint.as_str()))\n        .ok_or(FsError::NotMounted)?;\n    entry.fs.stat(path)\n}\n\n/// Write a file by absolute path.\npub fn write(path: &str, buf: &[u8]) -> Result<usize, FsError> {'

VFS_RS_NEW = "pub fn stat(path: &str) -> Result<FileStat, FsError> {\n    let mounts = MOUNTS.read();\n    let entry = mounts.iter().rev()\n        .find(|m| path.starts_with(m.mountpoint.as_str()))\n        .ok_or(FsError::NotMounted)?;\n    entry.fs.stat(path)\n}\n\n/// List the entries of a directory by absolute path (patch_43). Same\n/// mount-table resolution as read()/write()/stat(); no permission check of\n/// its own, matching stat()'s own precedent - this simplified VFS doesn't\n/// model directory-level execute/search permission separately from\n/// file-level read/write yet.\npub fn readdir(path: &str) -> Result<Vec<DirEntry>, FsError> {\n    let mounts = MOUNTS.read();\n    let entry = mounts.iter().rev()\n        .find(|m| path.starts_with(m.mountpoint.as_str()))\n        .ok_or(FsError::NotMounted)?;\n    entry.fs.readdir(path)\n}\n\n/// Write a file by absolute path.\npub fn write(path: &str, buf: &[u8]) -> Result<usize, FsError> {"

VFS_RS_MARKER = '/// List the entries of a directory by absolute path (patch_43).'

MAIN_HELP_OLD = '        crate::kprint!("Commands: help meminfo version reboot ticks uptime syscalls scrubtest teardowntest multitest audittest heaptest isotest isofault wxtest guardtest captest permtest ipctest spawn restest conctest preempttest drawtest ownertest haltest pcitest mmiotest nvmeinittest identifytest nvmeiotest blockdevtest gpttest ext2test'

MAIN_HELP_NEW = '        crate::kprint!("Commands: help meminfo version reboot ticks uptime syscalls scrubtest teardowntest multitest audittest heaptest isotest isofault wxtest guardtest captest permtest ipctest spawn restest conctest preempttest drawtest ownertest haltest pcitest mmiotest nvmeinittest identifytest nvmeiotest blockdevtest gpttest ext2test ext2mounttest'

MAIN_HELP_MARKER = 'ext2mounttest'

DISPATCH_OLD = '            Err(e) => crate::kprintln!("[ext2test] FAIL - lookup_in_root(\\"hello.txt\\") returned {:?} (did you create it on the host before booting?)", e),\n                                }\n                            }\n                            Err(e) => crate::kprintln!("[ext2test] FAIL - read_dir_entries returned {:?}", e),\n                        }\n                    }\n                    Err(e) => crate::kprintln!("[ext2test] FAIL - mount returned {:?} (is the partition actually formatted as ext2?)", e),\n                }\n            }\n            Ok(_) => crate::kprintln!("[ext2test] FAIL - GPT parsed but has no used partitions"),\n            Err(e) => crate::kprintln!("[ext2test] FAIL - read_gpt returned {:?} (run gpttest first to confirm GPT is present)", e),\n        }\n    } else if !b.is_empty() {'

DISPATCH_NEW = '            Err(e) => crate::kprintln!("[ext2test] FAIL - lookup_in_root(\\"hello.txt\\") returned {:?} (did you create it on the host before booting?)", e),\n                                }\n                            }\n                            Err(e) => crate::kprintln!("[ext2test] FAIL - read_dir_entries returned {:?}", e),\n                        }\n                    }\n                    Err(e) => crate::kprintln!("[ext2test] FAIL - mount returned {:?} (is the partition actually formatted as ext2?)", e),\n                }\n            }\n            Ok(_) => crate::kprintln!("[ext2test] FAIL - GPT parsed but has no used partitions"),\n            Err(e) => crate::kprintln!("[ext2test] FAIL - read_gpt returned {:?} (run gpttest first to confirm GPT is present)", e),\n        }\n    } else if b == b"ext2mounttest" {\n        crate::kprintln!("--- ext2 VFS integration test (mount_to_vfs, then real fs::vfs:: calls only) ---");\n        match fs::partition::read_gpt() {\n            Ok(entries) if !entries.is_empty() => {\n                let part = &entries[0];\n                match fs::ext2::mount_to_vfs("/mnt", part.first_lba) {\n                    Ok(()) => {\n                        crate::kprintln!("[ext2mounttest] mounted ext2 at /mnt via fs::vfs::mount");\n                        match fs::vfs::readdir("/mnt") {\n                            Ok(dirents) => {\n                                crate::kprintln!("[ext2mounttest] fs::vfs::readdir(\\"/mnt\\"): {} entries", dirents.len());\n                                for e in &dirents {\n                                    crate::kprintln!("[ext2mounttest]   name=\\"{}\\" is_dir={} size={}", e.name, e.is_dir, e.size);\n                                }\n                            }\n                            Err(e) => crate::kprintln!("[ext2mounttest] FAIL - fs::vfs::readdir returned {:?}", e),\n                        }\n\n                        let mut buf = [0u8; 64];\n                        match fs::vfs::read("/mnt/hello.txt", &mut buf) {\n                            Ok(n) => {\n                                let expected: &[u8] = b"Noxisa ext2 read test";\n                                let got = &buf[..n];\n                                crate::kprintln!("[ext2mounttest] fs::vfs::read(\\"/mnt/hello.txt\\"): {} bytes", n);\n                                if got == expected {\n                                    crate::kprintln!("[ext2mounttest] memcmp PASS - matches via the real permission-checked vfs::read() chokepoint");\n                                } else {\n                                    crate::kprintln!("[ext2mounttest] FAIL - contents do not match expected test string");\n                                }\n                            }\n                            Err(e) => crate::kprintln!("[ext2mounttest] FAIL - fs::vfs::read returned {:?}", e),\n                        }\n\n                        match fs::vfs::write("/mnt/hello.txt", b"x") {\n                            Err(_) => crate::kprintln!("[ext2mounttest] PASS - fs::vfs::write correctly denied (read-only ext2 driver)"),\n                            Ok(_) => crate::kprintln!("[ext2mounttest] FAIL - fs::vfs::write unexpectedly succeeded against a read-only filesystem"),\n                        }\n\n                        crate::kprintln!("[ext2mounttest] PASS - ext2 mounted and reachable through the real VFS layer");\n                    }\n                    Err(e) => crate::kprintln!("[ext2mounttest] FAIL - mount_to_vfs returned {:?}", e),\n                }\n            }\n            Ok(_) => crate::kprintln!("[ext2mounttest] FAIL - GPT parsed but has no used partitions"),\n            Err(e) => crate::kprintln!("[ext2mounttest] FAIL - read_gpt returned {:?} (run gpttest first)", e),\n        }\n    } else if !b.is_empty() {'

DISPATCH_MARKER = 'b == b"ext2mounttest"'


def patch_replace_idempotent(path, old, new, marker, label):
    """Match-count-checked replace, but first checks whether `marker` is
    already present in the file - if so, this step is a safe no-op rather
    than re-matching `old` (which may still be a literal substring of the
    file even after a previous successful patch)."""
    try:
        with open(path, "r") as f:
            content = f.read()
    except FileNotFoundError:
        print(f"ABORT: {path} not found in current directory")
        return False

    if marker in content:
        print(f"[patch_43] {label}: marker already present in {path} - skipping (already applied)")
        return True

    count = content.count(old)
    print(f"[patch_43] {label} match count in {path}: {count}")
    if count != 1:
        print(f"ABORT: expected exactly 1 match for {label}. Nothing written to {path}.")
        return False

    with open(path, "w") as f:
        f.write(content.replace(old, new))
    print(f"[patch_43] OK - patched {path} ({label})")
    return True


def main():
    if not os.path.isdir(FS_DIR):
        print(f"ABORT: {FS_DIR}/ not found - run this from kernel/src")
        sys.exit(1)
    if not os.path.exists(EXT2_FILE):
        print(f"ABORT: {EXT2_FILE} not found - run patch_42 first")
        sys.exit(1)

    ok = True
    ok &= patch_replace_idempotent(EXT2_FILE, EXT2_RS_OLD, EXT2_RS_NEW, EXT2_RS_MARKER, "ext2.rs VFS adapter append")
    ok &= patch_replace_idempotent(VFS_FILE, VFS_RS_OLD, VFS_RS_NEW, VFS_RS_MARKER, "vfs.rs readdir() free function")
    ok &= patch_replace_idempotent(MAIN_FILE, MAIN_HELP_OLD, MAIN_HELP_NEW, MAIN_HELP_MARKER, "help string")
    ok &= patch_replace_idempotent(MAIN_FILE, DISPATCH_OLD, DISPATCH_NEW, DISPATCH_MARKER, "ext2mounttest dispatch arm")

    if not ok:
        print("[patch_43] ABORTED - one or more steps failed. Review output above.")
        sys.exit(1)

    print("[patch_43] All steps applied successfully.")


if __name__ == "__main__":
    main()
