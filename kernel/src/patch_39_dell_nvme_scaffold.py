#!/usr/bin/env python3
"""
patch_39_dell_nvme_scaffold.py

TEMPORARY Dell hardware scaffolding. Auto-runs pcitest -> mmiotest ->
nvmeinittest -> identifytest -> nvmeiotest -> blockdevtest at boot (the Dell
has no serial capture and no working keyboard path to kshell, per this
project's own established convention from the CAP_DRAW/tmpfs Dell session).

Draws a small 24x24 marker into the taskbar for each test, green=PASS,
red=FAIL, positioned to the right of the 3 existing window-swatch icons
(which sit at x=20/56/92), starting at x=140 and stepping by 30px.

*** WARNING ***
nvmeiotest and blockdevtest WRITE a real test pattern to LBA 0 of NVMe
namespace 1 on whatever controller is physically attached. On real hardware
with only one internal NVMe drive, this is that drive's real GPT/protective-
MBR sector. This patch is intended to run exactly once against a machine
whose owner has explicitly accepted that risk. Revert with
patch_40_revert_dell_nvme_scaffold.py immediately after photographing the
Dell's screen, per this project's standing scaffolding-then-revert workflow.

Run from ~/nexus-os/kernel/src (matches this project's own patch convention).
"""
import sys

TARGET = "main.rs"

OLD = '''    hal::init();

    kprintln!("[boot] Handing off to scheduler - kshell starts now (native)...");'''

NEW = '''    hal::init();

    // === DELL HARDWARE SCAFFOLDING (TEMPORARY - see patch_39/patch_40) ===
    // Auto-runs the full NVMe test sequence since the Dell has no serial
    // capture and no working keyboard path to kshell. Draws a 24x24 marker
    // into the taskbar per test (green=PASS, red=FAIL), left to right:
    // pcitest, mmiotest, nvmeinittest, identifytest, nvmeiotest, blockdevtest.
    // WARNING: nvmeiotest and blockdevtest WRITE to real LBA 0 of NVMe
    // namespace 1 on the attached controller - on this hardware, that is the
    // real internal drive's GPT/protective-MBR sector.
    {
        use crate::drivers::gpu::{dimensions, fill_rect};
        let (_w, h) = dimensions();
        let taskbar_y = h.saturating_sub(48);
        let icon_y = taskbar_y + (48 - 24) / 2;
        let mark = |slot: u32, ok: bool| {
            let x = 140 + slot * 30;
            let colour = if ok { 0x0000FF00u32 } else { 0x00FF0000u32 };
            fill_rect(x, icon_y, 24, 24, colour);
        };

        let nvme_dev = drivers::pci::find_nvme();
        let pci_ok = matches!(&nvme_dev, Some(dev) if matches!(&dev.bar0, Some(b) if b.is_mmio));
        mark(0, pci_ok);
        kprintln!("[dell-scaffold] pcitest: {}", if pci_ok { "PASS" } else { "FAIL" });

        if let Some(dev) = &nvme_dev {
            if let Some(bar) = &dev.bar0 {
                if bar.is_mmio {
                    let virt = unsafe { memory::paging::map_mmio(bar.base, 0x1000) };
                    let regs = unsafe { drivers::nvme::NvmeRegs::new(virt) };
                    let cap = regs.cap();
                    let mmio_ok = cap != 0 && cap != u64::MAX;
                    mark(1, mmio_ok);
                    kprintln!("[dell-scaffold] mmiotest: {}", if mmio_ok { "PASS" } else { "FAIL" });

                    let init_ok = drivers::nvme::init_admin_queues(&regs, 64).is_ok();
                    mark(2, init_ok);
                    kprintln!("[dell-scaffold] nvmeinittest: {}", if init_ok { "PASS" } else { "FAIL" });
                    drivers::nvme::invalidate_persistent_state();

                    let identify_ok = drivers::nvme::identify_controller().is_ok()
                        && drivers::nvme::identify_namespace(1).is_ok();
                    mark(3, identify_ok);
                    kprintln!("[dell-scaffold] identifytest: {}", if identify_ok { "PASS" } else { "FAIL" });

                    let io_ok = match drivers::nvme::identify_namespace(1) {
                        Ok(ns) => match ns.block_size {
                            Some(bs) if bs as usize <= 0x1000 => {
                                let mut pattern = alloc::vec![0u8; bs as usize];
                                for (i, b) in pattern.iter_mut().enumerate() {
                                    *b = (i as u8).wrapping_mul(31).wrapping_add(7);
                                }
                                let mut readback = alloc::vec![0u8; bs as usize];
                                drivers::nvme::io_write_blocks(1, 0, bs, &pattern).is_ok()
                                    && drivers::nvme::io_read_blocks(1, 0, bs, &mut readback).is_ok()
                                    && readback == pattern
                            }
                            _ => false,
                        },
                        Err(_) => false,
                    };
                    mark(4, io_ok);
                    kprintln!("[dell-scaffold] nvmeiotest: {}", if io_ok { "PASS" } else { "FAIL" });

                    let bs = hal::registry::block_size();
                    let block_ok = if bs == 0 || bs as usize > 0x1000 {
                        false
                    } else {
                        let mut pattern = alloc::vec![0u8; bs as usize];
                        for (i, b) in pattern.iter_mut().enumerate() {
                            *b = (i as u8).wrapping_mul(17).wrapping_add(3);
                        }
                        let mut readback = alloc::vec![0u8; bs as usize];
                        hal::registry::block_write(0, &pattern).is_ok()
                            && hal::registry::block_read(0, &mut readback).is_ok()
                            && readback == pattern
                    };
                    mark(5, block_ok);
                    kprintln!("[dell-scaffold] blockdevtest: {}", if block_ok { "PASS" } else { "FAIL" });
                }
            }
        }
    }
    // === END DELL HARDWARE SCAFFOLDING ===

    kprintln!("[boot] Handing off to scheduler - kshell starts now (native)...");'''


def main():
    try:
        with open(TARGET, "r") as f:
            content = f.read()
    except FileNotFoundError:
        print(f"ABORT: {TARGET} not found in current directory ({__file__} must be run from kernel/src)")
        sys.exit(1)

    count = content.count(OLD)
    print(f"[patch_39] match count in {TARGET}: {count}")
    if count != 1:
        print("ABORT: expected exactly 1 match. Nothing written.")
        sys.exit(1)

    new_content = content.replace(OLD, NEW)
    with open(TARGET, "w") as f:
        f.write(new_content)
    print(f"[patch_39] OK - wrote {TARGET}")


if __name__ == "__main__":
    main()
