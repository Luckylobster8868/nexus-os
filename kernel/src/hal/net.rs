use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

/// A network interface device.
pub trait NetworkDevice: Send + Sync {
    /// Send a raw Ethernet frame.
    fn send(&self, frame: &[u8]) -> Result<(), ()>;
    /// Receive a raw Ethernet frame. Returns None if no packet is available.
    fn receive(&self) -> Option<Vec<u8>>;
    /// Get the MAC address of the interface.
    fn mac_address(&self) -> [u8; 6];
}

static RX_BYTES: AtomicUsize = AtomicUsize::new(0);
static TX_BYTES: AtomicUsize = AtomicUsize::new(0);

pub fn record_rx(bytes: usize) {
    RX_BYTES.fetch_add(bytes, Ordering::Relaxed);
}

pub fn record_tx(bytes: usize) {
    TX_BYTES.fetch_add(bytes, Ordering::Relaxed);
}

pub fn get_stats() -> (usize, usize) {
    (
        RX_BYTES.load(Ordering::Relaxed),
        TX_BYTES.load(Ordering::Relaxed),
    )
}

pub struct VirtIONetDevice;

impl NetworkDevice for VirtIONetDevice {
    fn send(&self, frame: &[u8]) -> Result<(), ()> {
        crate::drivers::virtio_net::send(frame).map_err(|_| ())
    }

    fn receive(&self) -> Option<alloc::vec::Vec<u8>> {
        crate::drivers::virtio_net::recv()
    }

    fn mac_address(&self) -> [u8; 6] {
        crate::drivers::virtio_net::mac_address()
    }
}

pub static VIRTIO_NET: VirtIONetDevice = VirtIONetDevice;
