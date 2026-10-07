use alloc::vec::Vec;
use smoltcp::phy::{Device, DeviceCapabilities, RxToken, TxToken, Medium};
use smoltcp::time::Instant;

use crate::hal::registry;
use crate::drivers::pit;

/// smoltcp Device wrapper around the HAL network registry.
pub struct HalNetDevice;

impl Device for HalNetDevice {
    type RxToken<'a> = HalRxToken;
    type TxToken<'a> = HalTxToken;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        match registry::net_receive() {
            Some(frame) => {
                crate::hal::net::record_rx(frame.len());
                Some((HalRxToken(frame), HalTxToken))
            }
            None => None,
        }
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(HalTxToken)
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = 1500;
        caps.max_burst_size = Some(1);
        caps.medium = Medium::Ethernet;
        caps
    }
}

pub struct HalRxToken(Vec<u8>);

impl RxToken for HalRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

pub struct HalTxToken;

impl TxToken for HalTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = alloc::vec![0u8; len];
        let result = f(&mut buffer);
        if registry::net_send(&buffer).is_ok() {
            crate::hal::net::record_tx(len);
        }
        result
    }
}

/// Helper to get current time for smoltcp.
pub fn current_time() -> Instant {
    Instant::from_millis(pit::ms() as i64)
}

use spin::Mutex;
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr, Ipv4Address};

#[derive(Clone, Copy, Debug)]
pub struct SocketMeta {
    pub smol_handle: smoltcp::iface::SocketHandle,
    pub bound_port: Option<u16>,
    pub is_listening: bool,
}

pub struct NetworkState<'a> {
    pub iface: Interface,
    pub sockets: SocketSet<'a>,
    pub socket_meta: Vec<Option<SocketMeta>>,
}

pub static NET_STATE: Mutex<Option<NetworkState<'static>>> = Mutex::new(None);

pub fn init() {
    let mac = registry::net_mac_address().unwrap_or([0; 6]);
    if mac == [0; 6] {
        crate::kprintln!("[net] No MAC address, skipping network init");
        return;
    }

    let hw_addr = EthernetAddress::from_bytes(&mac);
    let config = Config::new(hw_addr.into());

    let mut device = HalNetDevice;
    let mut iface = Interface::new(config, &mut device, current_time());

    iface.update_ip_addrs(|ip_addrs| {
        ip_addrs
            .push(IpCidr::new(IpAddress::v4(10, 0, 2, 15), 24))
            .unwrap();
    });
    iface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address::new(10, 0, 2, 2))
        .unwrap();

    let sockets = SocketSet::new(alloc::vec![]);

    *NET_STATE.lock() = Some(NetworkState { iface, sockets, socket_meta: alloc::vec![None; 32] });
    crate::kprintln!("[net] Initialised: IP 10.0.2.15/24, MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

pub fn poll() {
    if let Some(state) = NET_STATE.lock().as_mut() {
        let timestamp = current_time();
        let mut device = HalNetDevice;
        let _ = state.iface.poll(timestamp, &mut device, &mut state.sockets);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketHandle(pub usize);

pub fn socket_close(handle: SocketHandle) {
    if let Some(state) = NET_STATE.lock().as_mut() {
        if let Some(Some(meta)) = state.socket_meta.get_mut(handle.0) {
            let smol_handle = meta.smol_handle;
            state.socket_meta[handle.0] = None;
            let socket = state.sockets.get_mut(smol_handle);
            if let smoltcp::socket::Socket::Tcp(ref mut tcp) = socket {
                tcp.close();
            }
            let timestamp = current_time();
            let mut device = HalNetDevice;
            let _ = state.iface.poll(timestamp, &mut device, &mut state.sockets);
            // We intentionally do NOT remove the smoltcp socket here!
            // The socket must remain in the SocketSet so it can process the FIN-ACK and TIME-WAIT states.
            // If we remove it immediately, any incoming ACKs will trigger a RST from smoltcp,
            // which causes the host (e.g., QEMU SLIRP) to abort the connection and drop buffered data.
        }
    }
}

pub fn socket_send(handle: SocketHandle, buf: &[u8]) -> Result<usize, ()> {
    if let Some(state) = NET_STATE.lock().as_mut() {
        let timestamp = current_time();
        let mut device = HalNetDevice;
        let mut sent = 0;
        if let Some(Some(meta)) = state.socket_meta.get(handle.0) {
            let socket: &mut smoltcp::socket::Socket = state.sockets.get_mut(meta.smol_handle);
            match socket {
                smoltcp::socket::Socket::Tcp(ref mut tcp) => {
                    if tcp.can_send() {
                        sent = tcp.send_slice(buf).map_err(|_| ())?;
                    } else if !tcp.may_send() {
                        return Err(()); // Not connected, or closed
                    } else {
                        return Err(()); // Would block (buffer full)
                    }
                }
                smoltcp::socket::Socket::Udp(ref mut _udp) => {
                    return Err(()); // UDP sending via socket_send unsupported, needs full sendto with destination
                }
                _ => return Err(()),
            }
        }
        // Poll immediately after queuing bytes so packets are transmitted on the wire right away!
        let _ = state.iface.poll(timestamp, &mut device, &mut state.sockets);
        return Ok(sent);
    }
    Err(())
}

pub fn socket_recv(handle: SocketHandle, buf: &mut [u8]) -> Result<usize, ()> {
    if let Some(state) = NET_STATE.lock().as_mut() {
        let timestamp = current_time();
        let mut device = HalNetDevice;
        let _ = state.iface.poll(timestamp, &mut device, &mut state.sockets);
        let mut recvd = 0;
        if let Some(Some(meta)) = state.socket_meta.get(handle.0) {
            let socket: &mut smoltcp::socket::Socket = state.sockets.get_mut(meta.smol_handle);
            match socket {
                smoltcp::socket::Socket::Tcp(ref mut tcp) => {
                    if tcp.can_recv() {
                        recvd = tcp.recv_slice(buf).map_err(|_| ())?;
                    } else if !tcp.may_recv() {
                        return Ok(0); // EOF (remote closed and buffer empty)
                    } else {
                        return Err(()); // Would block
                    }
                }
                smoltcp::socket::Socket::Udp(ref mut udp) => {
                    if udp.can_recv() {
                        if let Ok((len, _)) = udp.recv_slice(buf) {
                            recvd = len;
                        } else {
                            return Err(());
                        }
                    } else {
                        return Err(());
                    }
                }
                _ => return Err(()),
            }
        }
        return Ok(recvd);
    }
    Err(())
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct SockaddrIn {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: u32,
    pub sin_zero: [u8; 8],
}

fn copy_from_user<T>(user_ptr: *const T) -> Option<T> {
    let addr = user_ptr as usize;
    // Basic lower-half canonical address check for userspace
    if addr == 0 || addr >= 0x0000_8000_0000_0000 {
        return None;
    }
    // Also check that it doesn't wrap/overflow
    if addr.checked_add(core::mem::size_of::<T>()).is_none() {
        return None;
    }
    Some(unsafe { core::ptr::read_unaligned(user_ptr) })
}

pub fn sys_socket(domain: i32, type_: i32, _protocol: i32) -> i32 {
    let mut guard = NET_STATE.lock();
    let state = match guard.as_mut() {
        Some(s) => s,
        None => return -1,
    };
    
    // AF_INET = 2, SOCK_STREAM = 1, SOCK_DGRAM = 2
    if domain != 2 { return -1; }
    
    let smol_handle = if type_ == 1 {
        // TCP
        let rx_buffer = smoltcp::socket::tcp::SocketBuffer::new(alloc::vec![0; 4096]);
        let tx_buffer = smoltcp::socket::tcp::SocketBuffer::new(alloc::vec![0; 4096]);
        let socket = smoltcp::socket::tcp::Socket::new(rx_buffer, tx_buffer);
        state.sockets.add(socket)
    } else if type_ == 2 {
        // UDP
        let rx_buffer = smoltcp::socket::udp::PacketBuffer::new(
            alloc::vec![smoltcp::socket::udp::PacketMetadata::EMPTY; 16],
            alloc::vec![0; 4096]
        );
        let tx_buffer = smoltcp::socket::udp::PacketBuffer::new(
            alloc::vec![smoltcp::socket::udp::PacketMetadata::EMPTY; 16],
            alloc::vec![0; 4096]
        );
        let socket = smoltcp::socket::udp::Socket::new(rx_buffer, tx_buffer);
        state.sockets.add(socket)
    } else {
        return -1;
    };
    
    let nox_handle = if let Some(idx) = state.socket_meta.iter().position(|s| s.is_none()) {
        idx
    } else {
        let idx = state.socket_meta.len();
        state.socket_meta.push(None);
        idx
    };
    state.socket_meta[nox_handle] = Some(SocketMeta {
        smol_handle,
        bound_port: None,
        is_listening: false,
    });
    
    let handle = SocketHandle(nox_handle);
    crate::scheduler::Scheduler::get().alloc_fd(crate::scheduler::FdEntry::Socket(handle))
}

/// Connects a socket to a remote address.
///
/// This is a **blocking syscall**. It initiates a TCP 3-way handshake and
/// blocks the calling task in a `poll()` + `yield_now()` loop until the
/// connection is established (or until a 5-second timeout expires). It uses
/// cooperative yielding to ensure other tasks (and the timer ISR) can run
/// while waiting for network responses.
pub fn sys_connect(fd: i32, addr_ptr: *const SockaddrIn, addr_len: u32) -> i32 {
    if addr_len < core::mem::size_of::<SockaddrIn>() as u32 { return -1; }
    
    let addr = match copy_from_user(addr_ptr) {
        Some(a) => a,
        None => return -1, // Invalid pointer
    };
    if addr.sin_family != 2 { return -1; } // only AF_INET
    
    let handle = match crate::scheduler::Scheduler::get().fd_info(fd) {
        Some(crate::scheduler::FdEntry::Socket(h)) => h,
        _ => return -1,
    };
    
    let bytes = addr.sin_addr.to_ne_bytes();
    let ip = Ipv4Address::new(bytes[0], bytes[1], bytes[2], bytes[3]);
    let target_addr = IpAddress::Ipv4(ip);
    let port = u16::from_be(addr.sin_port);
    
    crate::kprintln!("[net] sys_connect connecting to {}.{}.{}.{}:{}", bytes[0], bytes[1], bytes[2], bytes[3], port);

    // Initiate the connect under the lock, then drop it so we can poll.
    {
        let mut guard = NET_STATE.lock();
        let state = match guard.as_mut() {
            Some(s) => s,
            None => return -1,
        };
        
        let cx = state.iface.context();
        if let Some(Some(meta)) = state.socket_meta.get(handle.0) {
            let socket: &mut smoltcp::socket::Socket = state.sockets.get_mut(meta.smol_handle);
            match socket {
                smoltcp::socket::Socket::Tcp(ref mut tcp) => {
                    let local_port = 49152 + (pit::ms() % 16384) as u16;
                    if tcp.connect(cx, (target_addr, port), local_port).is_err() {
                        return -1;
                    }
                }
                _ => return -1, // Only TCP connect supported for now
            }
            // First poll sends the SYN.
            let timestamp = current_time();
            let mut device = HalNetDevice;
            let _ = state.iface.poll(timestamp, &mut device, &mut state.sockets);
        } else {
            return -1;
        }
    } // ← lock dropped here

    // Block until the TCP 3-way handshake completes (or times out).
    let start = pit::ms();
    loop {
        if pit::ms().wrapping_sub(start) > 5000 {
            crate::kprintln!("[net] sys_connect: timeout waiting for TCP handshake");
            return -1;
        }
        // Poll the network — processes incoming SYN-ACK, sends ACK, etc.
        poll();
        // Re-acquire lock to inspect socket state.
        let mut guard = NET_STATE.lock();
        if let Some(state) = guard.as_mut() {
            if let Some(Some(meta)) = state.socket_meta.get(handle.0) {
                let socket: &mut smoltcp::socket::Socket = state.sockets.get_mut(meta.smol_handle);
                match socket {
                    smoltcp::socket::Socket::Tcp(ref tcp) => {
                        if tcp.may_send() {
                            return 0; // Handshake complete — Established
                        }
                        if !tcp.is_active() {
                            return -1; // RST or refused
                        }
                    }
                    _ => return -1,
                }
            } else {
                return -1;
            }
        } else {
            return -1;
        }
        
        crate::scheduler::yield_now();
    }
}

pub fn sys_bind(fd: i32, addr_ptr: *const SockaddrIn, addr_len: u32) -> i32 {
    if addr_len < core::mem::size_of::<SockaddrIn>() as u32 {
        return -1;
    }
    let addr = match copy_from_user(addr_ptr) {
        Some(a) => a,
        None => return -1,
    };
    if addr.sin_family != 2 {
        return -1; // AF_INET only
    }
    let handle = match crate::scheduler::Scheduler::get().fd_info(fd) {
        Some(crate::scheduler::FdEntry::Socket(h)) => h,
        _ => return -1,
    };
    let port = u16::from_be(addr.sin_port);
    if port == 0 {
        return -1;
    }

    let mut guard = NET_STATE.lock();
    let state = match guard.as_mut() {
        Some(s) => s,
        None => return -1,
    };

    if let Some(Some(meta)) = state.socket_meta.get_mut(handle.0) {
        if meta.bound_port.is_some() {
            return -1; // already bound
        }
        meta.bound_port = Some(port);
        crate::kprintln!("[net] sys_bind: bound socket {:?} to port {}", handle, port);
        0
    } else {
        -1
    }
}

pub fn sys_listen(fd: i32, _backlog: i32) -> i32 {
    let handle = match crate::scheduler::Scheduler::get().fd_info(fd) {
        Some(crate::scheduler::FdEntry::Socket(h)) => h,
        _ => return -1,
    };

    let mut guard = NET_STATE.lock();
    let state = match guard.as_mut() {
        Some(s) => s,
        None => return -1,
    };

    if let Some(Some(meta)) = state.socket_meta.get_mut(handle.0) {
        let port = match meta.bound_port {
            Some(p) => p,
            None => return -1, // must bind before listen
        };
        let socket: &mut smoltcp::socket::Socket = state.sockets.get_mut(meta.smol_handle);
        match socket {
            smoltcp::socket::Socket::Tcp(ref mut tcp) => {
                if tcp.listen(port).is_err() {
                    return -1;
                }
                meta.is_listening = true;
                crate::kprintln!("[net] sys_listen: listening on port {}", port);
                0
            }
            _ => -1,
        }
    } else {
        -1
    }
}

pub fn sys_accept(fd: i32, addr_ptr: *mut SockaddrIn, addr_len_ptr: *mut u32) -> i32 {
    let handle = match crate::scheduler::Scheduler::get().fd_info(fd) {
        Some(crate::scheduler::FdEntry::Socket(h)) => h,
        _ => return -1,
    };

    let listen_port = {
        let guard = NET_STATE.lock();
        let state = match guard.as_ref() {
            Some(s) => s,
            None => return -1,
        };
        match state.socket_meta.get(handle.0) {
            Some(Some(meta)) if meta.is_listening => match meta.bound_port {
                Some(p) => p,
                None => return -1,
            },
            _ => return -1,
        }
    };

    crate::kprintln!("[net] sys_accept: waiting for connection on port {}...", listen_port);

    let mut iter: u32 = 0;
    loop {
        poll();
        iter += 1;

        {
            let mut guard = NET_STATE.lock();
            if let Some(state) = guard.as_mut() {
                if let Some(Some(meta)) = state.socket_meta.get(handle.0) {
                    let smol_handle = meta.smol_handle;
                    let socket: &mut smoltcp::socket::Socket = state.sockets.get_mut(smol_handle);
                    if let smoltcp::socket::Socket::Tcp(ref mut tcp) = socket {
                        let tcp_st = tcp.state();
                        if iter <= 5 || iter % 10000 == 0 || tcp_st != smoltcp::socket::tcp::State::Listen {
                            crate::kprintln!("[net] sys_accept: iter {} tcp state={:?}", iter, tcp_st);
                        }
                        if tcp_st == smoltcp::socket::tcp::State::Established {
                            let remote_endpoint = tcp.remote_endpoint();
                            crate::kprintln!("[net] sys_accept: connection accepted from {:?}", remote_endpoint);

                            if !addr_ptr.is_null() && !addr_len_ptr.is_null() {
                                if let Some(endpoint) = remote_endpoint {
                                    let (ip_bytes, remote_port) = match endpoint.addr {
                                        IpAddress::Ipv4(ip) => (ip.octets(), endpoint.port),
                                        _ => ([0, 0, 0, 0], 0),
                                    };
                                    let sin = SockaddrIn {
                                        sin_family: 2,
                                        sin_port: remote_port.to_be(),
                                        sin_addr: u32::from_ne_bytes(ip_bytes),
                                        sin_zero: [0; 8],
                                    };
                                    let addr_u = addr_ptr as usize;
                                    if addr_u != 0 && addr_u < 0x0000_8000_0000_0000 {
                                        unsafe {
                                            core::ptr::write_unaligned(addr_ptr, sin);
                                            core::ptr::write_unaligned(addr_len_ptr, core::mem::size_of::<SockaddrIn>() as u32);
                                        }
                                    }
                                }
                            }

                            // 1. Allocate new SocketHandle for connected socket
                            let conn_nox_handle = if let Some(idx) = state.socket_meta.iter().position(|s| s.is_none()) {
                                idx
                            } else {
                                let idx = state.socket_meta.len();
                                state.socket_meta.push(None);
                                idx
                            };
                            state.socket_meta[conn_nox_handle] = Some(SocketMeta {
                                smol_handle,
                                bound_port: Some(listen_port),
                                is_listening: false,
                            });
                            let conn_handle = SocketHandle(conn_nox_handle);

                            // 2. Allocate fresh replacement TCP socket for the listener
                            let rx_buffer = smoltcp::socket::tcp::SocketBuffer::new(alloc::vec![0; 4096]);
                            let tx_buffer = smoltcp::socket::tcp::SocketBuffer::new(alloc::vec![0; 4096]);
                            let mut new_listener = smoltcp::socket::tcp::Socket::new(rx_buffer, tx_buffer);
                            if let Err(e) = new_listener.listen(listen_port) {
                                crate::kprintln!("[net] sys_accept: warning, failed to re-listen: {:?}", e);
                            }
                            let new_smol_handle = state.sockets.add(new_listener);

                            // 3. Put replacement listener on the listening handle
                            state.socket_meta[handle.0] = Some(SocketMeta {
                                smol_handle: new_smol_handle,
                                bound_port: Some(listen_port),
                                is_listening: true,
                            });

                            drop(guard);

                            let new_fd = crate::scheduler::Scheduler::get().alloc_fd(crate::scheduler::FdEntry::Socket(conn_handle));
                            crate::kprintln!("[net] sys_accept: returning new_fd={}", new_fd);
                            return new_fd;
                        }
                    }
                } else {
                    return -1; // Listening socket closed
                }
            } else {
                return -1;
            }
        }

        if iter <= 5 || iter % 10000 == 0 {
            crate::kprintln!("[net] sys_accept: about to yield...");
        }
        crate::scheduler::yield_now();
        if iter <= 5 || iter % 10000 == 0 {
            crate::kprintln!("[net] sys_accept: resumed from yield!");
        }
    }
}

pub fn sys_close(fd: i32) -> i32 {
    if crate::fs::vfs::close_fd(fd) {
        0
    } else {
        -1
    }
}

pub fn sys_sendto(fd: i32, buf: *const u8, len: u64, _flags: i32, _addr_ptr: *const SockaddrIn, _addr_len: u32) -> i64 {
    let handle = match crate::scheduler::Scheduler::get().fd_info(fd) {
        Some(crate::scheduler::FdEntry::Socket(h)) => h,
        _ => return -1,
    };
    // Basic validation of user buffer
    let addr = buf as usize;
    if addr == 0 || addr >= 0x0000_8000_0000_0000 || addr.checked_add(len as usize).is_none() {
        return -1;
    }
    let slice = unsafe { core::slice::from_raw_parts(buf, len as usize) };
    
    // For now, sys_sendto just acts as sys_write for a connected TCP socket.
    // The simplified socket_send ignores destination. This is documented.
    match socket_send(handle, slice) {
        Ok(n) => n as i64,
        Err(_) => -1,
    }
}

pub fn sys_recvfrom(fd: i32, buf: *mut u8, len: u64, _flags: i32, _addr_ptr: *mut SockaddrIn, _addr_len: *mut u32) -> i64 {
    let handle = match crate::scheduler::Scheduler::get().fd_info(fd) {
        Some(crate::scheduler::FdEntry::Socket(h)) => h,
        _ => return -1,
    };
    // Basic validation of user buffer
    let addr = buf as usize;
    if addr == 0 || addr >= 0x0000_8000_0000_0000 || addr.checked_add(len as usize).is_none() {
        return -1;
    }
    let slice = unsafe { core::slice::from_raw_parts_mut(buf, len as usize) };
    
    // Simplified socket_recv doesn't populate addr_ptr for now.
    match socket_recv(handle, slice) {
        Ok(n) => n as i64,
        Err(_) => -1,
    }
}
