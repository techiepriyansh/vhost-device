// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{
    collections::{HashMap, HashSet, VecDeque},
    io,
    io::Read,
    num::Wrapping,
    ops::DerefMut,
    os::unix::{
        net::{UnixListener, UnixStream},
        prelude::{AsRawFd, FromRawFd, RawFd},
    },
    sync::{Arc, Mutex, RwLock},
};

use log::{info, warn};
use virtio_vsock::packet::VsockPacket;
use vm_memory::bitmap::BitmapSlice;
use vmm_sys_util::epoll::EventSet;

use crate::{
    rxops::*,
    vhu_vsock::{
        ConnMapKey, Error, Result, VSOCK_HOST_CID, VSOCK_OP_REQUEST, VSOCK_OP_RST,
        VSOCK_TYPE_STREAM,
    },
    vhu_vsock_thread::EpollHelpers,
    vsock_conn::*,
};

pub(crate) struct VsockThreadBackend {
    /// Map of ConnMapKey objects indexed by raw file descriptors.
    pub listener_map: RwLock<HashMap<RawFd, ConnMapKey>>,
    /// Map of vsock connection objects indexed by ConnMapKey objects.
    pub conn_map: RwLock<HashMap<ConnMapKey, Arc<Mutex<VsockConnection<UnixStream>>>>>,
    /// Queue of ConnMapKey objects indicating pending rx operations.
    pub backend_rxq: RwLock<VecDeque<ConnMapKey>>,
    /// Map of host-side unix streams indexed by raw file descriptors.
    pub stream_map: RwLock<HashMap<i32, UnixStream>>,
    /// Host socket raw file descriptor.
    host_sock: RawFd,
    /// Host side socket for listening to new connections from the host.
    host_socket_path: String,
    /// Listener listening for new connections on the host.
    host_listener: UnixListener,
    /// epoll for registering new host-side connections.
    pub epoll_fd: i32,
    /// CID of the guest.
    guest_cid: u64,
    /// host side port on which application listens.
    local_port: Mutex<Wrapping<u32>>,
    /// Set of allocated local ports.
    pub local_port_set: RwLock<HashSet<u32>>,
}

impl VsockThreadBackend {
    /// New instance of VsockThreadBackend.
    pub fn new(uds_path: String, guest_cid: u64) -> Result<Self> {
        // TODO: better error handling, maybe add a param to force the unlink
        let _ = std::fs::remove_file(uds_path.clone());

        let host_listener = UnixListener::bind(&uds_path)
            .and_then(|sock| sock.set_nonblocking(true).map(|_| sock))
            .map_err(Error::UnixBind)?;

        let epoll_fd = epoll::create(true).map_err(Error::EpollFdCreate)?;

        let host_raw_fd = host_listener.as_raw_fd();

        let thread_backend = Self {
            listener_map: RwLock::new(HashMap::new()),
            conn_map: RwLock::new(HashMap::new()),
            backend_rxq: RwLock::new(VecDeque::new()),
            // Need this map to prevent connected stream from closing
            // TODO: think of a better solution
            stream_map: RwLock::new(HashMap::new()),
            host_sock: host_raw_fd,
            host_socket_path: uds_path,
            host_listener,
            epoll_fd,
            guest_cid,
            local_port: Mutex::new(Wrapping(0)),
            local_port_set: RwLock::new(HashSet::new()),
        };

        EpollHelpers::epoll_register(epoll_fd, host_raw_fd, epoll::Events::EPOLLIN)?;

        Ok(thread_backend)
    }

    /// Checks if there are pending rx requests in the backend rxq.
    pub fn pending_rx(&self) -> bool {
        !self.backend_rxq.read().unwrap().is_empty()
    }

    /// Deliver a vsock packet to the guest vsock driver.
    ///
    /// Returns:
    /// - `Ok(())` if the packet was successfully filled in
    /// - `Err(Error::EmptyBackendRxQ) if there was no available data
    pub fn recv_pkt<B: BitmapSlice>(&self, pkt: &mut VsockPacket<B>) -> Result<()> {
        // Pop an event from the backend_rxq
        let key = self
            .backend_rxq
            .write()
            .unwrap()
            .pop_front()
            .ok_or(Error::EmptyBackendRxQ)?;
        let conn_mutex = match self.conn_map.read().unwrap().get(&key) {
            Some(conn) => conn.clone(),
            None => {
                // assume that the connection does not exist
                return Ok(());
            }
        };
        let mut conn = conn_mutex.lock().unwrap();

        if conn.rx_queue.peek() == Some(RxOps::Reset) {
            // Handle RST events here
            self.conn_map.write().unwrap().remove(&key).unwrap();
            self.listener_map
                .write()
                .unwrap()
                .remove(&conn.stream.as_raw_fd());
            self.stream_map
                .write()
                .unwrap()
                .remove(&conn.stream.as_raw_fd());
            self.local_port_set
                .write()
                .unwrap()
                .remove(&conn.local_port);
            EpollHelpers::epoll_unregister(conn.epoll_fd, conn.stream.as_raw_fd()).unwrap_or_else(
                |err| {
                    warn!(
                        "Could not remove epoll listener for fd {:?}: {:?}",
                        conn.stream.as_raw_fd(),
                        err
                    )
                },
            );

            // Initialize the packet header to contain a VSOCK_OP_RST operation
            pkt.set_op(VSOCK_OP_RST)
                .set_src_cid(VSOCK_HOST_CID)
                .set_dst_cid(conn.guest_cid)
                .set_src_port(conn.local_port)
                .set_dst_port(conn.peer_port)
                .set_len(0)
                .set_type(VSOCK_TYPE_STREAM)
                .set_flags(0)
                .set_buf_alloc(0)
                .set_fwd_cnt(0);

            return Ok(());
        }

        // Handle other packet types per connection
        conn.recv_pkt(pkt)?;

        Ok(())
    }

    /// Deliver a guest generated packet to its destination in the backend.
    ///
    /// Absorbs unexpected packets, handles rest to respective connection
    /// object.
    ///
    /// Returns:
    /// - always `Ok(())` if packet has been consumed correctly
    pub fn send_pkt<B: BitmapSlice>(&self, pkt: &VsockPacket<B>) -> Result<()> {
        let key = ConnMapKey::new(pkt.dst_port(), pkt.src_port());

        // TODO: Rst if packet has unsupported type
        if pkt.type_() != VSOCK_TYPE_STREAM {
            info!("vsock: dropping packet of unknown type");
            return Ok(());
        }

        // TODO: Handle packets to other CIDs as well
        if pkt.dst_cid() != VSOCK_HOST_CID {
            info!(
                "vsock: dropping packet for cid other than host: {:?}",
                pkt.dst_cid()
            );

            return Ok(());
        }

        // TODO: Handle cases where connection does not exist and packet op
        // is not VSOCK_OP_REQUEST
        if !self.conn_map.read().unwrap().contains_key(&key) {
            // The packet contains a new connection request
            if pkt.op() == VSOCK_OP_REQUEST {
                self.handle_new_guest_conn(pkt);
            } else {
                // TODO: send back RST
            }
            return Ok(());
        }

        if pkt.op() == VSOCK_OP_RST {
            // Handle an RST packet from the guest here
            let conn_mutex = self.conn_map.read().unwrap().get(&key).unwrap().clone();
            let conn = conn_mutex.lock().unwrap();
            if conn.rx_queue.contains(RxOps::Reset.bitmask()) {
                return Ok(());
            }
            self.conn_map.write().unwrap().remove(&key).unwrap();
            self.listener_map
                .write()
                .unwrap()
                .remove(&conn.stream.as_raw_fd());
            self.stream_map
                .write()
                .unwrap()
                .remove(&conn.stream.as_raw_fd());
            self.local_port_set
                .write()
                .unwrap()
                .remove(&conn.local_port);
            EpollHelpers::epoll_unregister(conn.epoll_fd, conn.stream.as_raw_fd()).unwrap_or_else(
                |err| {
                    warn!(
                        "Could not remove epoll listener for fd {:?}: {:?}",
                        conn.stream.as_raw_fd(),
                        err
                    )
                },
            );
            return Ok(());
        }

        // Forward this packet to its listening connection
        let conn_mutex = self.conn_map.read().unwrap().get(&key).unwrap().clone();
        let mut conn = conn_mutex.lock().unwrap();
        conn.send_pkt(pkt)?;

        if conn.rx_queue.pending_rx() {
            // Required if the connection object adds new rx operations
            self.backend_rxq.write().unwrap().push_back(key);
        }

        Ok(())
    }

    /// Process a BACKEND_EVENT received by VhostUserVsockBackend.
    pub fn process_backend_event(&self, _evset: EventSet) {
        let mut epoll_events = vec![epoll::Event::new(epoll::Events::empty(), 0); 32];
        'epoll: loop {
            match epoll::wait(self.epoll_fd, 0, epoll_events.as_mut_slice()) {
                Ok(ev_cnt) => {
                    for evt in epoll_events.iter().take(ev_cnt) {
                        self.handle_backend_event(
                            evt.data as RawFd,
                            epoll::Events::from_bits(evt.events).unwrap(),
                        );
                    }
                }
                Err(e) => {
                    if e.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    warn!("failed to consume new epoll event");
                }
            }
            break 'epoll;
        }
    }

    /// Handle a BACKEND_EVENT by either accepting a new connection or
    /// forwarding a request to the appropriate connection object.
    fn handle_backend_event(&self, fd: RawFd, evset: epoll::Events) {
        if fd == self.host_sock {
            // This is a new connection initiated by an application running on the host
            self.host_listener
                .accept()
                .map_err(Error::UnixAccept)
                .and_then(|(stream, _)| {
                    stream
                        .set_nonblocking(true)
                        .map(|_| stream)
                        .map_err(Error::UnixAccept)
                })
                .and_then(|stream| self.add_stream_listener(stream))
                .unwrap_or_else(|err| {
                    warn!("Unable to accept new local connection: {:?}", err);
                });
        } else {
            // Check if the stream represented by fd has already established a
            // connection with the application running in the guest
            if !self.listener_map.read().unwrap().contains_key(&fd) {
                // New connection from the host
                if evset != epoll::Events::EPOLLIN {
                    // Has to be EPOLLIN as it was not connected previously
                    return;
                }
                let mut unix_stream = match self.stream_map.write().unwrap().remove(&fd) {
                    Some(uds) => uds,
                    None => {
                        warn!("Error while searching fd in the stream map");
                        return;
                    }
                };

                // Local peer is sending a "connect PORT\n" command
                let peer_port = match Self::read_local_stream_port(&mut unix_stream) {
                    Ok(port) => port,
                    Err(err) => {
                        warn!("Error while parsing \"connect PORT\n\" command: {:?}", err);
                        return;
                    }
                };

                // Allocate a local port number
                let local_port = match self.allocate_local_port() {
                    Ok(lp) => lp,
                    Err(err) => {
                        warn!("Error while allocating local port: {:?}", err);
                        return;
                    }
                };

                // Insert the fd into the backend's maps
                self.listener_map
                    .write()
                    .unwrap()
                    .insert(fd, ConnMapKey::new(local_port, peer_port));

                // Create a new connection object an enqueue a connection request
                // packet to be sent to the guest
                let conn_map_key = ConnMapKey::new(local_port, peer_port);
                let mut new_conn = VsockConnection::new_local_init(
                    unix_stream,
                    VSOCK_HOST_CID,
                    local_port,
                    self.guest_cid,
                    peer_port,
                    self.epoll_fd,
                );
                new_conn.rx_queue.enqueue(RxOps::Request);
                new_conn.set_peer_port(peer_port);

                // Add connection object into the backend's maps
                self.conn_map
                    .write()
                    .unwrap()
                    .insert(conn_map_key, Arc::new(Mutex::new(new_conn)));

                self.backend_rxq
                    .write()
                    .unwrap()
                    .push_back(ConnMapKey::new(local_port, peer_port));

                // Re-register the fd to listen for EPOLLIN and EPOLLOUT events
                EpollHelpers::epoll_modify(
                    self.epoll_fd,
                    fd,
                    epoll::Events::EPOLLIN | epoll::Events::EPOLLOUT,
                )
                .unwrap();
            } else {
                // Previously connected connection
                let key = (*self.listener_map.read().unwrap().get(&fd).unwrap()).clone();
                let conn_mutex = self.conn_map.read().unwrap().get(&key).unwrap().clone();
                let mut conn_lock = conn_mutex.lock().unwrap();
                let conn = conn_lock.deref_mut();

                if evset == epoll::Events::EPOLLOUT {
                    // Flush any remaining data from the tx buffer
                    match conn.tx_buf.flush_to(&mut conn.stream) {
                        Ok(cnt) => {
                            if cnt > 0 {
                                conn.fwd_cnt += Wrapping(cnt as u32);
                                conn.rx_queue.enqueue(RxOps::CreditUpdate);
                            }
                            self.backend_rxq
                                .write()
                                .unwrap()
                                .push_back(ConnMapKey::new(conn.local_port, conn.peer_port));
                        }
                        Err(e) => {
                            dbg!("Error: {:?}", e);
                        }
                    }
                    return;
                }

                // Unregister stream from the epoll, register when connection is
                // established with the guest
                EpollHelpers::epoll_unregister(self.epoll_fd, fd).unwrap();

                // Enqueue a read request
                conn.rx_queue.enqueue(RxOps::Rw);
                self.backend_rxq
                    .write()
                    .unwrap()
                    .push_back(ConnMapKey::new(conn.local_port, conn.peer_port));
            }
        }
    }

    /// Allocate a new local port number.
    fn allocate_local_port(&self) -> Result<u32> {
        // TODO: Improve space efficiency of this operation
        // TODO: Reuse the conn_map HashMap
        // TODO: Test this.
        let mut local_port = self.local_port.lock().unwrap();
        let mut alloc_local_port = local_port.0;
        loop {
            if !self
                .local_port_set
                .read()
                .unwrap()
                .contains(&alloc_local_port)
            {
                // The port set doesn't contain the newly allocated port number.
                *local_port = Wrapping(alloc_local_port + 1);
                self.local_port_set
                    .write()
                    .unwrap()
                    .insert(alloc_local_port);
                return Ok(alloc_local_port);
            } else {
                if alloc_local_port == local_port.0 {
                    // We have exhausted our search and wrapped back to the current port number
                    return Err(Error::NoFreeLocalPort);
                }
                alloc_local_port += 1;
            }
        }
    }

    /// Read `CONNECT PORT_NUM\n` from the connected stream.
    fn read_local_stream_port(stream: &mut UnixStream) -> Result<u32> {
        let mut buf = [0u8; 32];

        // Minimum number of bytes we should be able to read
        // Corresponds to 'CONNECT 0\n'
        const MIN_READ_LEN: usize = 10;

        // Read in the minimum number of bytes we can read
        stream
            .read_exact(&mut buf[..MIN_READ_LEN])
            .map_err(Error::UnixRead)?;

        let mut read_len = MIN_READ_LEN;
        while buf[read_len - 1] != b'\n' && read_len < buf.len() {
            stream
                .read_exact(&mut buf[read_len..read_len + 1])
                .map_err(Error::UnixRead)?;
            read_len += 1;
        }

        let mut word_iter = std::str::from_utf8(&buf[..read_len])
            .map_err(Error::ConvertFromUtf8)?
            .split_whitespace();

        word_iter
            .next()
            .ok_or(Error::InvalidPortRequest)
            .and_then(|word| {
                if word.to_lowercase() == "connect" {
                    Ok(())
                } else {
                    Err(Error::InvalidPortRequest)
                }
            })
            .and_then(|_| word_iter.next().ok_or(Error::InvalidPortRequest))
            .and_then(|word| word.parse::<u32>().map_err(Error::ParseInteger))
            .map_err(|e| Error::ReadStreamPort(Box::new(e)))
    }

    /// Add a stream to epoll to listen for EPOLLIN events.
    fn add_stream_listener(&self, stream: UnixStream) -> Result<()> {
        let stream_fd = stream.as_raw_fd();
        self.stream_map.write().unwrap().insert(stream_fd, stream);
        EpollHelpers::epoll_register(self.epoll_fd, stream_fd, epoll::Events::EPOLLIN)?;

        Ok(())
    }

    /// Handle a new guest initiated connection, i.e from the peer, the guest driver.
    ///
    /// Attempts to connect to a host side unix socket listening on a path
    /// corresponding to the destination port as follows:
    /// - "{self.host_sock_path}_{local_port}""
    fn handle_new_guest_conn<B: BitmapSlice>(&self, pkt: &VsockPacket<B>) {
        let port_path = format!("{}_{}", self.host_socket_path, pkt.dst_port());

        UnixStream::connect(port_path)
            .and_then(|stream| stream.set_nonblocking(true).map(|_| stream))
            .map_err(Error::UnixConnect)
            .and_then(|stream| self.add_new_guest_conn(stream, pkt))
            .unwrap_or_else(|_| self.enq_rst());
    }

    /// Wrapper to add new connection to relevant HashMaps.
    fn add_new_guest_conn<B: BitmapSlice>(
        &self,
        stream: UnixStream,
        pkt: &VsockPacket<B>,
    ) -> Result<()> {
        let stream_fd = stream.as_raw_fd();
        self.listener_map
            .write()
            .unwrap()
            .insert(stream_fd, ConnMapKey::new(pkt.dst_port(), pkt.src_port()));

        let conn = Arc::new(Mutex::new(VsockConnection::new_peer_init(
            stream,
            pkt.dst_cid(),
            pkt.dst_port(),
            pkt.src_cid(),
            pkt.src_port(),
            self.epoll_fd,
            pkt.buf_alloc(),
        )));

        self.conn_map
            .write()
            .unwrap()
            .insert(ConnMapKey::new(pkt.dst_port(), pkt.src_port()), conn);
        self.backend_rxq
            .write()
            .unwrap()
            .push_back(ConnMapKey::new(pkt.dst_port(), pkt.src_port()));

        self.stream_map.write().unwrap().insert(
            stream_fd,
            // SAFETY: Safe as the file descriptor is guaranteed to be valid.
            unsafe { UnixStream::from_raw_fd(stream_fd) },
        );
        self.local_port_set.write().unwrap().insert(pkt.dst_port());

        EpollHelpers::epoll_register(
            self.epoll_fd,
            stream_fd,
            epoll::Events::EPOLLIN | epoll::Events::EPOLLOUT,
        )?;
        Ok(())
    }

    /// Enqueue RST packets to be sent to guest.
    fn enq_rst(&self) {
        // TODO
        dbg!("New guest conn error: Enqueue RST");
    }
}

impl Drop for VsockThreadBackend {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.host_socket_path);
    }
}

/*
#[cfg(test)]
mod tests {
    use super::*;
    use crate::vhu_vsock::VSOCK_OP_RW;
    use serial_test::serial;
    use std::os::unix::net::UnixListener;
    use virtio_vsock::packet::{VsockPacket, PKT_HEADER_SIZE};

    const DATA_LEN: usize = 16;

    #[test]
    #[serial]
    fn test_vsock_thread_backend() {
        const VSOCK_SOCKET_PATH: &str = "test_vsock_thread_backend.vsock";
        const VSOCK_PEER_PORT: u32 = 1234;
        const VSOCK_PEER_PATH: &str = "test_vsock_thread_backend.vsock_1234";

        let _ = std::fs::remove_file(VSOCK_PEER_PATH);
        let _listener = UnixListener::bind(VSOCK_PEER_PATH).unwrap();

        let epoll_fd = epoll::create(false).unwrap();
        let mut vtp = VsockThreadBackend::new(VSOCK_SOCKET_PATH.to_string(), epoll_fd);

        assert!(!vtp.pending_rx());

        let mut pkt_raw = [0u8; PKT_HEADER_SIZE + DATA_LEN];
        let (hdr_raw, data_raw) = pkt_raw.split_at_mut(PKT_HEADER_SIZE);

        // SAFETY: Safe as hdr_raw and data_raw are guaranteed to be valid.
        let mut packet = unsafe { VsockPacket::new(hdr_raw, Some(data_raw)).unwrap() };

        assert_eq!(
            vtp.recv_pkt(&mut packet).unwrap_err().to_string(),
            Error::EmptyBackendRxQ.to_string()
        );

        assert!(vtp.send_pkt(&packet).is_ok());

        packet.set_type(VSOCK_TYPE_STREAM);
        assert!(vtp.send_pkt(&packet).is_ok());

        packet.set_dst_cid(VSOCK_HOST_CID);
        packet.set_dst_port(VSOCK_PEER_PORT);
        assert!(vtp.send_pkt(&packet).is_ok());

        packet.set_op(VSOCK_OP_REQUEST);
        assert!(vtp.send_pkt(&packet).is_ok());

        packet.set_op(VSOCK_OP_RW);
        assert!(vtp.send_pkt(&packet).is_ok());

        packet.set_op(VSOCK_OP_RST);
        assert!(vtp.send_pkt(&packet).is_ok());

        assert!(vtp.recv_pkt(&mut packet).is_ok());

        // cleanup
        let _ = std::fs::remove_file(VSOCK_PEER_PATH);
    }
}
*/
