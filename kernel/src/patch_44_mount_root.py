#!/usr/bin/env python3
"""
patch_44_mount_root.py

Filesystem/partition integration, step 4: wires fs::vfs::mount_root() to
actually do the GPT-probe + ext2-mount it was already TODO-commented for,
and calls it once at boot (after hal::init(), so the BlockDevice HAL is
registered first) - so the root filesystem is mounted automatically, not
only on-demand via a kshell test command.

Does four things:
  1. Replaces vfs.rs's mount_root() stub body with real GPT+ext2 mounting
     logic. Non-fatal on failure (kernel still boots with /tmp only if no
     disk/GPT/ext2 is found - e.g. plain QEMU with no NVMe image attached).
  2. Adds a `fs::vfs::mount_root();` call in main.rs's boot sequence, right
     after hal::init() and before kshell starts.
  3. Adds a new `roottest` kshell command that reads /hello.txt with no
     prior mount command - proving mount_root() actually ran at boot, not
     that a test command mounted it just-in-time.
  4. Updates the help command's printed list to include roottest.

Every step is idempotent (marker-checked) - safe to re-run.

Requires patch_41, patch_42, and patch_43 already applied.
Run from ~/nexus-os/kernel/src.
"""
import os
import sys

FS_DIR = "fs"
VFS_FILE = os.path.join(FS_DIR, "vfs.rs")
MAIN_FILE = "main.rs"

VFS_MOUNTROOT_OLD = '/// Mount the root filesystem from the NVMe drive.\npub fn mount_root() {\n    crate::kprintln!("[vfs] Mounting root filesystem");\n    // TODO: probe /dev/nvme0n1p1, detect ext4 magic, mount it\n}'

VFS_MOUNTROOT_NEW = '/// Mount the root filesystem from the NVMe drive (patch_44). Non-fatal if\n/// no GPT/ext2 is found - the kernel continues with only /tmp available\n/// rather than panicking, since not every boot (QEMU without an attached\n/// NVMe image, or a blank/unpartitioned drive) has a real root filesystem\n/// to mount yet.\npub fn mount_root() {\n    crate::kprintln!("[vfs] Mounting root filesystem");\n    match crate::fs::partition::read_gpt() {\n        Ok(entries) if !entries.is_empty() => {\n            let part = &entries[0];\n            match crate::fs::ext2::mount_to_vfs("/", part.first_lba) {\n                Ok(()) => crate::kprintln!("[vfs] Root filesystem (ext2) mounted at / from LBA {}", part.first_lba),\n                Err(e) => crate::kprintln!("[vfs] WARNING - root ext2 mount failed: {:?} (continuing with /tmp only)", e),\n            }\n        }\n        Ok(_) => crate::kprintln!("[vfs] WARNING - GPT found but no used partitions; root filesystem not mounted (continuing with /tmp only)"),\n        Err(e) => crate::kprintln!("[vfs] WARNING - no GPT found ({:?}); root filesystem not mounted (continuing with /tmp only)", e),\n    }\n}'

VFS_MOUNTROOT_MARKER = 'Root filesystem (ext2) mounted at'

MAIN_BOOT_OLD = '    hal::init();\n\n    kprintln!("[boot] Handing off to scheduler - kshell starts now (native)...");'

MAIN_BOOT_NEW = '    hal::init();\n\n    fs::vfs::mount_root();\n\n    kprintln!("[boot] Handing off to scheduler - kshell starts now (native)...");'

MAIN_BOOT_MARKER = 'fs::vfs::mount_root();'

HELP_OLD = '        crate::kprint!("Commands: help meminfo version reboot ticks uptime syscalls scrubtest teardowntest multitest audittest heaptest isotest isofault wxtest guardtest captest permtest ipctest spawn restest conctest preempttest drawtest ownertest haltest pcitest mmiotest nvmeinittest identifytest nvmeiotest blockdevtest gpttest ext2test ext2mounttest'

HELP_NEW = '        crate::kprint!("Commands: help meminfo version reboot ticks uptime syscalls scrubtest teardowntest multitest audittest heaptest isotest isofault wxtest guardtest captest permtest ipctest spawn restest conctest preempttest drawtest ownertest haltest pcitest mmiotest nvmeinittest identifytest nvmeiotest blockdevtest gpttest ext2test ext2mounttest roottest'

HELP_MARKER = 'roottest'

DISPATCH_OLD = '            Ok(_) => crate::kprintln!("[ext2mounttest] FAIL - GPT parsed but has no used partitions"),\n            Err(e) => crate::kprintln!("[ext2mounttest] FAIL - read_gpt returned {:?} (run gpttest first)", e),\n        }\n    } else if !b.is_empty() {'

DISPATCH_NEW = '            Ok(_) => crate::kprintln!("[ext2mounttest] FAIL - GPT parsed but has no used partitions"),\n            Err(e) => crate::kprintln!("[ext2mounttest] FAIL - read_gpt returned {:?} (run gpttest first)", e),\n        }\n    } else if b == b"roottest" {\n        crate::kprintln!("--- root filesystem test (proves mount_root() at boot, no manual mount command run) ---");\n        let mut buf = [0u8; 64];\n        match fs::vfs::read("/hello.txt", &mut buf) {\n            Ok(n) => {\n                let expected: &[u8] = b"Noxisa ext2 read test";\n                let got = &buf[..n];\n                crate::kprintln!("[roottest] fs::vfs::read(\\"/hello.txt\\"): {} bytes", n);\n                if got == expected {\n                    crate::kprintln!("[roottest] memcmp PASS - root filesystem was already mounted at boot, before this command ran");\n                    crate::kprintln!("[roottest] PASS - mount_root() works");\n                } else {\n                    crate::kprintln!("[roottest] FAIL - contents do not match expected test string");\n                }\n            }\n            Err(e) => crate::kprintln!("[roottest] FAIL - fs::vfs::read(\\"/hello.txt\\") returned {:?} (was a GPT+ext2 disk with hello.txt at its root actually attached this boot?)", e),\n        }\n    } else if !b.is_empty() {'

DISPATCH_MARKER = 'b == b"roottest"'


def patch_replace_idempotent(path, old, new, marker, label):
    try:
        with open(path, "r") as f:
            content = f.read()
    except FileNotFoundError:
        print(f"ABORT: {path} not found in current directory")
        return False

    if marker in content:
        print(f"[patch_44] {label}: marker already present in {path} - skipping (already applied)")
        return True

    count = content.count(old)
    print(f"[patch_44] {label} match count in {path}: {count}")
    if count != 1:
        print(f"ABORT: expected exactly 1 match for {label}. Nothing written to {path}.")
        return False

    with open(path, "w") as f:
        f.write(content.replace(old, new))
    print(f"[patch_44] OK - patched {path} ({label})")
    return True


def main():
    if not os.path.isdir(FS_DIR):
        print(f"ABORT: {FS_DIR}/ not found - run this from kernel/src")
        sys.exit(1)

    ok = True
    ok &= patch_replace_idempotent(VFS_FILE, VFS_MOUNTROOT_OLD, VFS_MOUNTROOT_NEW, VFS_MOUNTROOT_MARKER, "vfs.rs mount_root() implementation")
    ok &= patch_replace_idempotent(MAIN_FILE, MAIN_BOOT_OLD, MAIN_BOOT_NEW, MAIN_BOOT_MARKER, "main.rs boot-sequence mount_root() call")
    ok &= patch_replace_idempotent(MAIN_FILE, HELP_OLD, HELP_NEW, HELP_MARKER, "help string")
    ok &= patch_replace_idempotent(MAIN_FILE, DISPATCH_OLD, DISPATCH_NEW, DISPATCH_MARKER, "roottest dispatch arm")

    if not ok:
        print("[patch_44] ABORTED - one or more steps failed. Review output above.")
        sys.exit(1)

    print("[patch_44] All steps applied successfully.")


if __name__ == "__main__":
    main()
