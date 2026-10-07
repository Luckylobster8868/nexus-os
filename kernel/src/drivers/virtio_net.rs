// Portions adapted from virtio-drivers (https://github.com/rcore-os/virtio-drivers)
// Copyright (c) 2019-2020 rCore Developers — MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

//! VirtIO-Net driver for Noxisa (Patch 56).
//!
//! Polling-based, matching the existing NVMe architecture. Uses Noxisa's
//! own PMM + paging for DMA allocation and MMIO mapping. Does NOT use the
//! upstream virtio-drivers crate as a dependency — the core algorithms are
//! adapted into Noxisa-owned code here.

use alloc::vec::Vec;
use core::sync::atomic::{fence, Ordering, AtomicU16};
use spin::Mutex;

use crate::drivers::pci::{self, PciDevice, VirtioCapInfo};
use crate::memory::{paging, pmm};

// ── Error type ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VirtioNetError {
    NoDevice,
    NoBars,
    MissingCapability(&'static str),
    InitFailed,
    QueueFull,
    NotReady,
}

// ── VirtIO device status bits (spec §2.1) ───────────────────────────────────

const STATUS_ACKNOWLEDGE: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_DRIVER_OK: u8 = 4;
const STATUS_FEATURES_OK: u8 = 8;

// ── VirtIO-Net feature bits we care about ───────────────────────────────────

const VIRTIO_NET_F_MAC: u64 = 1 << 5;
const VIRTIO_NET_F_STATUS: u64 = 1 << 16;

// ── Virtqueue constants ─────────────────────────────────────────────────────

const QUEUE_SIZE: u16 = 64;
const RX_QUEUE: u16 = 0;
const TX_QUEUE: u16 = 1;

// ── Virtqueue descriptor flags ──────────────────────────────────────────────

const DESC_F_NEXT: u16 = 1;
const DESC_F_WRITE: u16 = 2;

// ── virtio_net_hdr (10 bytes, legacy/transitional) ──────────────────────────

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct VirtioNetHdr {
    flags: u8,
    gso_type: u8,
    hdr_len: u16,
    gso_size: u16,
    csum_start: u16,
    csum_offset: u16,
}

impl VirtioNetHdr {
    const fn zeroed() -> Self {
        Self { flags: 0, gso_type: 0, hdr_len: 0, gso_size: 0, csum_start: 0, csum_offset: 0 }
    }
    const SIZE: usize = 10;
}

// ── Virtqueue ring structures (spec §2.6 Split Virtqueues) ──────────────────

#[repr(C, align(16))]
#[derive(Debug, Clone, Copy)]
struct Descriptor {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

/// Avail ring: driver writes, device reads.
/// Layout: flags(u16), idx(u16), ring[QUEUE_SIZE](u16), used_event(u16)
///
/// Used ring: device writes, driver reads.
/// Layout: flags(u16), idx(u16), ring[QUEUE_SIZE](UsedElem), avail_event(u16)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct UsedElem {
    id: u32,
    len: u32,
}

// ── Per-queue state ─────────────────────────────────────────────────────────

struct VirtQueue {
    /// Physical address of descriptor table (page-aligned, DMA).
    desc_phys: u64,
    /// Virtual address of descriptor table.
    desc_virt: u64,
    /// Virtual address of available ring.
    avail_virt: u64,
    /// Virtual address of used ring.
    used_virt: u64,
    /// Physical address of available ring.
    avail_phys: u64,
    /// Physical address of used ring.
    used_phys: u64,
    /// Number of descriptors in use.
    num_used: u16,
    /// Head of free descriptor list.
    free_head: u16,
    /// Our copy of the avail ring idx.
    avail_idx: u16,
    /// Last used ring idx we've seen.
    last_used_idx: u16,
}

impl VirtQueue {
    /// Allocate DMA memory for a split virtqueue and initialise the free list.
    fn new() -> Result<Self, VirtioNetError> {
        let q = QUEUE_SIZE as usize;
        // Descriptor table: 16 bytes each, aligned to 16.
        let desc_bytes = q * 16;
        // Available ring: 2+2 + 2*q + 2 bytes = 6 + 2*q
        let avail_bytes = 6 + 2 * q;
        // Used ring: 2+2 + 8*q + 2 bytes = 6 + 8*q
        let used_bytes = 6 + 8 * q;

        // Allocate pages for each region.
        let desc_pages = (desc_bytes + 4095) / 4096;
        let avail_pages = (avail_bytes + 4095) / 4096;
        let used_pages = (used_bytes + 4095) / 4096;

        let desc_phys = pmm::alloc_contiguous_frames(desc_pages)
            .ok_or(VirtioNetError::InitFailed)?;
        let avail_phys = pmm::alloc_contiguous_frames(avail_pages)
            .ok_or(VirtioNetError::InitFailed)?;
        let used_phys = pmm::alloc_contiguous_frames(used_pages)
            .ok_or(VirtioNetError::InitFailed)?;

        let desc_virt = paging::phys_to_virt(desc_phys);
        let avail_virt = paging::phys_to_virt(avail_phys);
        let used_virt = paging::phys_to_virt(used_phys);

        // Zero everything.
        unsafe {
            core::ptr::write_bytes(desc_virt as *mut u8, 0, desc_pages * 4096);
            core::ptr::write_bytes(avail_virt as *mut u8, 0, avail_pages * 4096);
            core::ptr::write_bytes(used_virt as *mut u8, 0, used_pages * 4096);
        }

        // Link descriptors into a free list: desc[i].next = i+1
        for i in 0..(q as u16 - 1) {
            unsafe {
                let desc = (desc_virt as *mut Descriptor).add(i as usize);
                (*desc).next = i + 1;
            }
        }

        Ok(VirtQueue {
            desc_phys,
            desc_virt,
            avail_virt,
            used_virt,
            avail_phys,
            used_phys,
            num_used: 0,
            free_head: 0,
            avail_idx: 0,
            last_used_idx: 0,
        })
    }

    /// Add a single buffer (read-only from device perspective for TX,
    /// write-only for RX) to the available ring.
    /// Returns the descriptor index (token).
    unsafe fn add_buf(&mut self, phys: u64, len: u32, device_writable: bool) -> Result<u16, VirtioNetError> {
        if self.num_used >= QUEUE_SIZE {
            return Err(VirtioNetError::QueueFull);
        }
        let head = self.free_head;
        let desc = (self.desc_virt as *mut Descriptor).add(head as usize);
        let next_free = (*desc).next;

        (*desc).addr = phys;
        (*desc).len = len;
        (*desc).flags = if device_writable { DESC_F_WRITE } else { 0 };
        (*desc).next = 0;

        self.free_head = next_free;
        self.num_used += 1;

        // Write to available ring.
        let avail_ring = self.avail_virt as *mut u16;
        // avail_ring layout: [flags(u16), idx(u16), ring[0], ring[1], ...]
        let slot = self.avail_idx & (QUEUE_SIZE - 1);
        // ring starts at offset 2 (in u16 units: flags + idx = 2 u16s)
        *avail_ring.add(2 + slot as usize) = head;

        fence(Ordering::SeqCst);

        self.avail_idx = self.avail_idx.wrapping_add(1);
        // Write the new avail_idx. We use a volatile write since the
        // device reads this field.
        core::ptr::write_volatile(avail_ring.add(1), self.avail_idx);

        Ok(head)
    }

    /// Check if there are completed (used) entries.
    fn can_pop(&self) -> bool {
        let used = self.used_virt as *const u16;
        // used ring layout: [flags(u16), idx(u16), ring[0].id(u32), ring[0].len(u32), ...]
        let device_idx = unsafe { core::ptr::read_volatile(used.add(1)) };
        self.last_used_idx != device_idx
    }

    /// Pop a used entry. Returns (descriptor_index, bytes_written_by_device).
    unsafe fn pop_used(&mut self) -> Option<(u16, u32)> {
        if !self.can_pop() {
            return None;
        }
        fence(Ordering::SeqCst);

        let slot = self.last_used_idx & (QUEUE_SIZE - 1);
        // Used ring: flags(u16), idx(u16), then UsedElem[QUEUE_SIZE].
        // Each UsedElem is 8 bytes. Byte offset from start:
        //   4 + slot * 8
        let used_base = self.used_virt as *const u8;
        let elem_ptr = used_base.add(4 + slot as usize * 8) as *const UsedElem;
        let elem = core::ptr::read_volatile(elem_ptr);

        // Return descriptor to free list.
        let desc = (self.desc_virt as *mut Descriptor).add(elem.id as usize);
        (*desc).next = self.free_head;
        (*desc).addr = 0;
        (*desc).len = 0;
        (*desc).flags = 0;
        self.free_head = elem.id as u16;
        self.num_used -= 1;

        self.last_used_idx = self.last_used_idx.wrapping_add(1);
        Some((elem.id as u16, elem.len))
    }
}

// ── VirtIO-Net device state (global singleton) ──────────────────────────────

struct VirtioNetState {
    pci: PciDevice,
    mac: [u8; 6],
    /// MMIO base virtual address of the common config structure.
    common_cfg_virt: u64,
    /// MMIO base virtual address of the ISR status register.
    isr_virt: u64,
    /// MMIO base virtual address of the device-specific config.
    device_cfg_virt: u64,
    /// MMIO base virtual address of the notify region.
    notify_virt: u64,
    notify_off_multiplier: u32,
    rx_queue: VirtQueue,
    tx_queue: VirtQueue,
    /// Pre-allocated RX buffers (physical addresses).
    rx_buffers: Vec<(u64, u64)>, // (phys, virt) pairs
}

static VIRTIO_NET: Mutex<Option<VirtioNetState>> = Mutex::new(None);

// ── CommonCfg MMIO register offsets (VirtIO spec §4.1.4.3) ──────────────────

const CC_DEVICE_FEATURE_SELECT: usize = 0x00;
const CC_DEVICE_FEATURE: usize = 0x04;
const CC_DRIVER_FEATURE_SELECT: usize = 0x08;
const CC_DRIVER_FEATURE: usize = 0x0C;
const CC_MSIX_CONFIG: usize = 0x10;
const CC_NUM_QUEUES: usize = 0x12;
const CC_DEVICE_STATUS: usize = 0x14;
const CC_CONFIG_GENERATION: usize = 0x15;
const CC_QUEUE_SELECT: usize = 0x16;
const CC_QUEUE_SIZE: usize = 0x18;
const CC_QUEUE_MSIX_VECTOR: usize = 0x1A;
const CC_QUEUE_ENABLE: usize = 0x1C;
const CC_QUEUE_NOTIFY_OFF: usize = 0x1E;
const CC_QUEUE_DESC: usize = 0x20;
const CC_QUEUE_DRIVER: usize = 0x28;
const CC_QUEUE_DEVICE: usize = 0x30;

// ── MMIO helpers ────────────────────────────────────────────────────────────

unsafe fn mmio_read_u8(base: u64, offset: usize) -> u8 {
    core::ptr::read_volatile((base + offset as u64) as *const u8)
}

unsafe fn mmio_write_u8(base: u64, offset: usize, val: u8) {
    core::ptr::write_volatile((base + offset as u64) as *mut u8, val);
}

unsafe fn mmio_read_u16(base: u64, offset: usize) -> u16 {
    core::ptr::read_volatile((base + offset as u64) as *const u16)
}

unsafe fn mmio_write_u16(base: u64, offset: usize, val: u16) {
    core::ptr::write_volatile((base + offset as u64) as *mut u16, val);
}

unsafe fn mmio_read_u32(base: u64, offset: usize) -> u32 {
    core::ptr::read_volatile((base + offset as u64) as *const u32)
}

unsafe fn mmio_write_u32(base: u64, offset: usize, val: u32) {
    core::ptr::write_volatile((base + offset as u64) as *mut u32, val);
}

unsafe fn mmio_write_u64(base: u64, offset: usize, val: u64) {
    core::ptr::write_volatile((base + offset as u64) as *mut u64, val);
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Initialise the VirtIO-Net device. Returns Ok(()) if a device was found
/// and successfully initialised. Safe to call if no device is present
/// (returns Err(NoDevice)).
pub fn init() -> Result<(), VirtioNetError> {
    let pci_dev = pci::find_virtio_net().ok_or(VirtioNetError::NoDevice)?;
    crate::kprintln!("[virtio-net] Found VirtIO-Net: bus={} dev={} func={} vendor={:#06x} device={:#06x}",
        pci_dev.bus, pci_dev.device, pci_dev.function,
        pci_dev.vendor_id, pci_dev.device_id);

    // Enable bus-mastering + memory space.
    pci::enable_bus_master(pci_dev.bus, pci_dev.device, pci_dev.function);

    // Walk PCI capabilities to find VirtIO config regions.
    let mut common_cfg: Option<VirtioCapInfo> = None;
    let mut notify_cfg: Option<VirtioCapInfo> = None;
    let mut notify_off_multiplier: u32 = 0;
    let mut isr_cfg: Option<VirtioCapInfo> = None;
    let mut device_cfg: Option<VirtioCapInfo> = None;

    pci::walk_capabilities(pci_dev.bus, pci_dev.device, pci_dev.function, |cap_id, offset| {
        if cap_id != pci::PCI_CAP_ID_VNDR {
            return;
        }
        let cfg_type = pci::read_virtio_cap_cfg_type(pci_dev.bus, pci_dev.device, pci_dev.function, offset);
        let info = pci::read_virtio_cap(pci_dev.bus, pci_dev.device, pci_dev.function, offset);

        match cfg_type {
            pci::VIRTIO_PCI_CAP_COMMON_CFG if common_cfg.is_none() => {
                common_cfg = Some(info);
            }
            pci::VIRTIO_PCI_CAP_NOTIFY_CFG if notify_cfg.is_none() => {
                notify_cfg = Some(info);
                // notify_off_multiplier is at cap_offset + 16
                let _raw = pci::read_virtio_cap(pci_dev.bus, pci_dev.device, pci_dev.function, offset);
                // Actually read the multiplier separately — it's a u32 at cap_offset+16.
                // We'll re-read using config_read:
                // The cap structure for notify is 20 bytes: standard 16 + 4 for multiplier.
                // config_read_u32 needs the full PCI config offset.
                // offset+16 gives us the notify_off_multiplier field.
                // But offset is a u8, so offset+16 must fit in u8. Since caps are in
                // the 0x40..0xFF range, offset+16 < 256 in practice.
                if offset.checked_add(16).is_some() {
                    // Read the 4-byte notify_off_multiplier from PCI config space
                    let b = pci_dev.bus;
                    let d = pci_dev.device;
                    let f = pci_dev.function;
                    // We need raw PCI config read at (offset+16). Since our
                    // config_read_u32 takes u8, we must check overflow.
                    let off16 = offset.wrapping_add(16);
                    // Read it via two u16 reads to be safe with alignment
                    let lo = crate::drivers::pci::config_read_u16(b, d, f, off16);
                    let hi = crate::drivers::pci::config_read_u16(b, d, f, off16.wrapping_add(2));
                    notify_off_multiplier = (hi as u32) << 16 | lo as u32;
                }
            }
            pci::VIRTIO_PCI_CAP_ISR_CFG if isr_cfg.is_none() => {
                isr_cfg = Some(info);
            }
            pci::VIRTIO_PCI_CAP_DEVICE_CFG if device_cfg.is_none() => {
                device_cfg = Some(info);
            }
            _ => {}
        }
    });

    let common_cfg = common_cfg.ok_or(VirtioNetError::MissingCapability("common_cfg"))?;
    let notify_cfg = notify_cfg.ok_or(VirtioNetError::MissingCapability("notify_cfg"))?;
    let isr_cfg = isr_cfg.ok_or(VirtioNetError::MissingCapability("isr_cfg"))?;

    // Map the BAR regions into virtual memory.
    fn map_cap(pci_dev: &PciDevice, cap: &VirtioCapInfo) -> Result<u64, VirtioNetError> {
        let bar = pci::read_bar(pci_dev.bus, pci_dev.device, pci_dev.function, cap.bar)
            .ok_or(VirtioNetError::NoBars)?;
        if !bar.is_mmio {
            return Err(VirtioNetError::NoBars);
        }
        let phys = bar.base + cap.offset as u64;
        let size = cap.length as usize;
        // Align size up to page boundary for map_mmio.
        let size_aligned = (size + 4095) & !4095;
        let virt = unsafe { paging::map_mmio(phys, size_aligned as u64) };
        Ok(virt)
    }

    let common_cfg_virt = map_cap(&pci_dev, &common_cfg)?;
    let notify_virt = map_cap(&pci_dev, &notify_cfg)?;
    let isr_virt = map_cap(&pci_dev, &isr_cfg)?;
    let device_cfg_virt = if let Some(ref dc) = device_cfg {
        map_cap(&pci_dev, dc)?
    } else {
        0
    };

    crate::kprintln!("[virtio-net] MMIO mapped: common={:#x} notify={:#x} isr={:#x} devcfg={:#x}",
        common_cfg_virt, notify_virt, isr_virt, device_cfg_virt);

    // ── Device initialisation (VirtIO spec §3.1.1) ──────────────────────

    // 1. Reset device.
    unsafe { mmio_write_u8(common_cfg_virt, CC_DEVICE_STATUS, 0); }
    // Wait for reset to take effect.
    for _ in 0..1000 {
        if unsafe { mmio_read_u8(common_cfg_virt, CC_DEVICE_STATUS) } == 0 {
            break;
        }
        core::hint::spin_loop();
    }

    // 2. Set ACKNOWLEDGE.
    unsafe { mmio_write_u8(common_cfg_virt, CC_DEVICE_STATUS, STATUS_ACKNOWLEDGE); }

    // 3. Set DRIVER.
    unsafe {
        let s = mmio_read_u8(common_cfg_virt, CC_DEVICE_STATUS);
        mmio_write_u8(common_cfg_virt, CC_DEVICE_STATUS, s | STATUS_DRIVER);
    }

    // 4. Feature negotiation — we only need MAC.
    unsafe {
        mmio_write_u32(common_cfg_virt, CC_DEVICE_FEATURE_SELECT, 0);
        let device_features_lo = mmio_read_u32(common_cfg_virt, CC_DEVICE_FEATURE);
        mmio_write_u32(common_cfg_virt, CC_DEVICE_FEATURE_SELECT, 1);
        let device_features_hi = mmio_read_u32(common_cfg_virt, CC_DEVICE_FEATURE);
        let device_features = (device_features_hi as u64) << 32 | device_features_lo as u64;

        crate::kprintln!("[virtio-net] Device features: {:#018x}", device_features);

        // We accept MAC and STATUS if offered, nothing else.
        let driver_features = device_features & (VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS);
        mmio_write_u32(common_cfg_virt, CC_DRIVER_FEATURE_SELECT, 0);
        mmio_write_u32(common_cfg_virt, CC_DRIVER_FEATURE, driver_features as u32);
        mmio_write_u32(common_cfg_virt, CC_DRIVER_FEATURE_SELECT, 1);
        mmio_write_u32(common_cfg_virt, CC_DRIVER_FEATURE, (driver_features >> 32) as u32);
    }

    // 5. Set FEATURES_OK.
    unsafe {
        let s = mmio_read_u8(common_cfg_virt, CC_DEVICE_STATUS);
        mmio_write_u8(common_cfg_virt, CC_DEVICE_STATUS, s | STATUS_FEATURES_OK);
    }

    // Check that FEATURES_OK is still set.
    let status = unsafe { mmio_read_u8(common_cfg_virt, CC_DEVICE_STATUS) };
    if status & STATUS_FEATURES_OK == 0 {
        crate::kprintln!("[virtio-net] ERROR: device did not accept features");
        return Err(VirtioNetError::InitFailed);
    }

    // 6. Read MAC address from device config space.
    let mut mac = [0u8; 6];
    if device_cfg_virt != 0 {
        for i in 0..6 {
            mac[i] = unsafe { mmio_read_u8(device_cfg_virt, i) };
        }
    }
    crate::kprintln!("[virtio-net] MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    // 7. Set up virtqueues.
    let mut rx_queue = VirtQueue::new()?;
    let mut tx_queue = VirtQueue::new()?;

    // Configure RX queue (index 0).
    unsafe {
        mmio_write_u16(common_cfg_virt, CC_QUEUE_SELECT, RX_QUEUE);
        let max_size = mmio_read_u16(common_cfg_virt, CC_QUEUE_SIZE);
        crate::kprintln!("[virtio-net] RX max queue size: {}", max_size);
        mmio_write_u16(common_cfg_virt, CC_QUEUE_SIZE, QUEUE_SIZE);
        mmio_write_u64(common_cfg_virt, CC_QUEUE_DESC, rx_queue.desc_phys);
        mmio_write_u64(common_cfg_virt, CC_QUEUE_DRIVER, rx_queue.avail_phys);
        mmio_write_u64(common_cfg_virt, CC_QUEUE_DEVICE, rx_queue.used_phys);
        mmio_write_u16(common_cfg_virt, CC_QUEUE_ENABLE, 1);
    }

    // Configure TX queue (index 1).
    unsafe {
        mmio_write_u16(common_cfg_virt, CC_QUEUE_SELECT, TX_QUEUE);
        let max_size = mmio_read_u16(common_cfg_virt, CC_QUEUE_SIZE);
        crate::kprintln!("[virtio-net] TX max queue size: {}", max_size);
        mmio_write_u16(common_cfg_virt, CC_QUEUE_SIZE, QUEUE_SIZE);
        mmio_write_u64(common_cfg_virt, CC_QUEUE_DESC, tx_queue.desc_phys);
        mmio_write_u64(common_cfg_virt, CC_QUEUE_DRIVER, tx_queue.avail_phys);
        mmio_write_u64(common_cfg_virt, CC_QUEUE_DEVICE, tx_queue.used_phys);
        mmio_write_u16(common_cfg_virt, CC_QUEUE_ENABLE, 1);
    }

    // 8. Pre-allocate RX buffers and post them to the RX queue.
    let rx_buf_size: u32 = 1526 + VirtioNetHdr::SIZE as u32; // MTU + header
    let mut rx_buffers = Vec::new();
    let num_rx_buffers = 16u16; // fill ~1/4 of the queue

    for _ in 0..num_rx_buffers {
        let phys = pmm::alloc_frame().ok_or(VirtioNetError::InitFailed)?;
        let virt = paging::phys_to_virt(phys);
        // Zero the buffer.
        unsafe { core::ptr::write_bytes(virt as *mut u8, 0, 4096); }
        rx_buffers.push((phys, virt));
        // Post to RX queue — device writable.
        unsafe { rx_queue.add_buf(phys, rx_buf_size, true)?; }
    }

    // Notify the device about the RX buffers.
    unsafe {
        mmio_write_u16(common_cfg_virt, CC_QUEUE_SELECT, RX_QUEUE);
        let notify_off = mmio_read_u16(common_cfg_virt, CC_QUEUE_NOTIFY_OFF);
        let notify_addr = notify_virt + (notify_off as u64) * (notify_off_multiplier as u64);
        mmio_write_u16(notify_addr, 0, RX_QUEUE);
    }

    // 9. Set DRIVER_OK — device is live.
    unsafe {
        let s = mmio_read_u8(common_cfg_virt, CC_DEVICE_STATUS);
        mmio_write_u8(common_cfg_virt, CC_DEVICE_STATUS, s | STATUS_DRIVER_OK);
    }

    crate::kprintln!("[virtio-net] Device initialised, DRIVER_OK set");

    *VIRTIO_NET.lock() = Some(VirtioNetState {
        pci: pci_dev,
        mac,
        common_cfg_virt,
        isr_virt,
        device_cfg_virt,
        notify_virt,
        notify_off_multiplier,
        rx_queue,
        tx_queue,
        rx_buffers,
    });

    Ok(())
}

/// Send a raw Ethernet frame. A VirtIO net header is prepended automatically.
pub fn send(packet: &[u8]) -> Result<(), VirtioNetError> {
    let mut guard = VIRTIO_NET.lock();
    let state = guard.as_mut().ok_or(VirtioNetError::NotReady)?;

    // Allocate a temporary TX buffer: header + packet.
    let total_len = VirtioNetHdr::SIZE + packet.len();
    let phys = pmm::alloc_frame().ok_or(VirtioNetError::InitFailed)?;
    let virt = paging::phys_to_virt(phys);

    unsafe {
        // Write zero VirtIO header.
        let hdr = VirtioNetHdr::zeroed();
        core::ptr::copy_nonoverlapping(
            &hdr as *const VirtioNetHdr as *const u8,
            virt as *mut u8,
            VirtioNetHdr::SIZE,
        );
        // Copy packet data after header.
        core::ptr::copy_nonoverlapping(
            packet.as_ptr(),
            (virt as *mut u8).add(VirtioNetHdr::SIZE),
            packet.len(),
        );
    }

    // Post to TX queue — device readable.
    unsafe {
        state.tx_queue.add_buf(phys, total_len as u32, false)?;
    }

    // Notify device.
    unsafe {
        mmio_write_u16(state.common_cfg_virt, CC_QUEUE_SELECT, TX_QUEUE);
        let notify_off = mmio_read_u16(state.common_cfg_virt, CC_QUEUE_NOTIFY_OFF);
        let notify_addr = state.notify_virt + (notify_off as u64) * (state.notify_off_multiplier as u64);
        mmio_write_u16(notify_addr, 0, TX_QUEUE);
    }

    // Poll for completion (matches NVMe pattern).
    for _ in 0..1_000_000 {
        if state.tx_queue.can_pop() {
            unsafe { state.tx_queue.pop_used(); }
            // Free the TX buffer.
            pmm::free_frame(phys);
            return Ok(());
        }
        core::hint::spin_loop();
    }

    // Timeout — free buffer anyway.
    pmm::free_frame(phys);
    Err(VirtioNetError::InitFailed)
}

/// Receive a raw Ethernet frame. Returns None if no packet is available.
/// The returned Vec contains the raw Ethernet frame (VirtIO header stripped).
pub fn recv() -> Option<Vec<u8>> {
    let mut guard = VIRTIO_NET.lock();
    let state = guard.as_mut()?;

    if !state.rx_queue.can_pop() {
        return None;
    }

    let (desc_idx, total_len) = unsafe { state.rx_queue.pop_used()? };

    // Find the corresponding buffer.
    let idx = desc_idx as usize;
    if idx >= state.rx_buffers.len() {
        return None;
    }
    let (_phys, virt) = state.rx_buffers[idx];

    // Skip the VirtIO net header.
    let hdr_size = VirtioNetHdr::SIZE;
    if (total_len as usize) <= hdr_size {
        // Re-post the buffer.
        repost_rx_buffer(state, idx);
        return None;
    }
    let pkt_len = total_len as usize - hdr_size;
    let mut result = Vec::with_capacity(pkt_len);
    unsafe {
        let data_ptr = (virt as *const u8).add(hdr_size);
        result.extend_from_slice(core::slice::from_raw_parts(data_ptr, pkt_len));
    }

    // Re-post the buffer for future receives.
    repost_rx_buffer(state, idx);

    Some(result)
}

fn repost_rx_buffer(state: &mut VirtioNetState, idx: usize) {
    let (phys, virt) = state.rx_buffers[idx];
    let rx_buf_size = 1526 + VirtioNetHdr::SIZE as u32;
    // Zero the buffer.
    unsafe {
        core::ptr::write_bytes(virt as *mut u8, 0, 4096);
        let _ = state.rx_queue.add_buf(phys, rx_buf_size, true);
    }
    // Notify device about new RX buffer.
    unsafe {
        mmio_write_u16(state.common_cfg_virt, CC_QUEUE_SELECT, RX_QUEUE);
        let notify_off = mmio_read_u16(state.common_cfg_virt, CC_QUEUE_NOTIFY_OFF);
        let notify_addr = state.notify_virt + (notify_off as u64) * (state.notify_off_multiplier as u64);
        mmio_write_u16(notify_addr, 0, RX_QUEUE);
    }
}

/// Return the MAC address. Returns [0;6] if not initialised.
pub fn mac_address() -> [u8; 6] {
    VIRTIO_NET.lock().as_ref().map(|s| s.mac).unwrap_or([0; 6])
}

/// Returns true if the driver has been initialised.
pub fn is_ready() -> bool {
    VIRTIO_NET.lock().is_some()
}
