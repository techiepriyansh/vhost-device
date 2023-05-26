// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{
    ops::Deref,
    os::unix::prelude::RawFd,
    sync::Arc,
};

use futures::executor::{ThreadPool, ThreadPoolBuilder};
use log::warn;
use vhost_user_backend::{VringEpollHandler, VringRwLock, VringT};
use virtio_queue::QueueOwnedT;
use virtio_vsock::packet::{VsockPacket, PKT_HEADER_SIZE};
use vm_memory::{GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap};
use vmm_sys_util::epoll::EventSet;

use crate::{
    thread_backend::*,
    vhu_vsock::{Error, Result, VhostUserVsockBackend, CONN_TX_BUF_SIZE},
};

type ArcVhostBknd = Arc<VhostUserVsockBackend>;

// New descriptors pending on the rx queue
// const RX_QUEUE_EVENT: u16 = 0;
// New descriptors are pending on the tx queue.
// const TX_QUEUE_EVENT: u16 = 1;
// New descriptors are pending on the event queue.
const EVT_QUEUE_EVENT: u16 = 2;

/// New descriptors pending on the Tx or Rx queue for which the thread is registered.
/// For example, if the thread is registered for the Rx queue, then this event will
/// be triggered when new descriptors are pending on the Rx queue.
const THREAD_SPECIFIC_TX_OR_RX_QUEUE_EVENT: u16 = 0;

/// Notification coming from the backend.
pub(crate) const BACKEND_EVENT: u16 = 3;

pub(crate) struct EpollHelpers;

impl EpollHelpers {
    /// Register a file with an epoll to listen for events in evset.
    pub fn epoll_register(epoll_fd: RawFd, fd: RawFd, evset: epoll::Events) -> Result<()> {
        epoll::ctl(
            epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            fd,
            epoll::Event::new(evset, fd as u64),
        )
        .map_err(Error::EpollAdd)?;

        Ok(())
    }

    /// Remove a file from the epoll.
    pub fn epoll_unregister(epoll_fd: RawFd, fd: RawFd) -> Result<()> {
        epoll::ctl(
            epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_DEL,
            fd,
            epoll::Event::new(epoll::Events::empty(), 0),
        )
        .map_err(Error::EpollRemove)?;

        Ok(())
    }

    /// Modify the events we listen to for the fd in the epoll.
    pub fn epoll_modify(epoll_fd: RawFd, fd: RawFd, evset: epoll::Events) -> Result<()> {
        epoll::ctl(
            epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_MOD,
            fd,
            epoll::Event::new(evset, fd as u64),
        )
        .map_err(Error::EpollModify)?;

        Ok(())
    }
}

pub(crate) trait VhostUserVsockThread: Send {
    fn set_event_idx(&mut self, enabled: bool);

    fn update_memory(&mut self, atomic_mem: GuestMemoryAtomic<GuestMemoryMmap>);

    /// Set self's VringWorker.
    fn set_vring_worker(
        &mut self,
        vring_worker: Option<Arc<VringEpollHandler<ArcVhostBknd, VringRwLock, ()>>>,
    );

    fn handle_event(
        &mut self,
        device_event: u16,
        evset: EventSet,
        vrings: &[VringRwLock],
    ) -> Result<bool>;
}

pub(crate) struct VhostUserVsockRxThread {
    /// Guest memory map.
    pub mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    /// VIRTIO_RING_F_EVENT_IDX.
    pub event_idx: bool,
    /// Instance of VringWorker.
    vring_worker: Option<Arc<VringEpollHandler<ArcVhostBknd, VringRwLock, ()>>>,
    /// VsockThreadBackend instance.
    pub thread_backend: Arc<VsockThreadBackend>,
    /// Thread pool to handle event idx.
    pool: ThreadPool,
}

impl VhostUserVsockRxThread {
    /// Create a new instance of VhostUserTxVsockThread.
    pub fn new(thread_backend: Arc<VsockThreadBackend>) -> Result<Self> {
        let thread = VhostUserVsockRxThread {
            mem: None,
            event_idx: false,
            vring_worker: None,
            thread_backend,
            pool: ThreadPoolBuilder::new()
                .pool_size(1)
                .create()
                .map_err(Error::CreateThreadPool)?,
        };

        Ok(thread)
    }

    /// Iterate over the rx queue and process rx requests.
    fn process_rx_queue(&mut self, vring: &VringRwLock) -> Result<bool> {
        let mut used_any = false;
        let atomic_mem = match &self.mem {
            Some(m) => m,
            None => return Err(Error::NoMemoryConfigured),
        };

        let mut vring_mut = vring.get_mut();

        let queue = vring_mut.get_queue_mut();

        while let Some(mut avail_desc) = queue
            .iter(atomic_mem.memory())
            .map_err(|_| Error::IterateQueue)?
            .next()
        {
            used_any = true;
            let mem = atomic_mem.clone().memory();

            let head_idx = avail_desc.head_index();
            let used_len = match VsockPacket::from_rx_virtq_chain(
                mem.deref(),
                &mut avail_desc,
                CONN_TX_BUF_SIZE,
            ) {
                Ok(mut pkt) => {
                    if self.thread_backend.recv_pkt(&mut pkt).is_ok() {
                        PKT_HEADER_SIZE + pkt.len() as usize
                    } else {
                        queue.iter(mem).unwrap().go_to_previous_position();
                        break;
                    }
                }
                Err(e) => {
                    warn!("vsock: RX queue error: {:?}", e);
                    0
                }
            };

            let vring = vring.clone();
            let event_idx = self.event_idx;

            self.pool.spawn_ok(async move {
                // TODO: Understand why doing the following in the pool works
                if event_idx {
                    if vring.add_used(head_idx, used_len as u32).is_err() {
                        warn!("Could not return used descriptors to ring");
                    }
                    match vring.needs_notification() {
                        Err(_) => {
                            warn!("Could not check if queue needs to be notified");
                            vring.signal_used_queue().unwrap();
                        }
                        Ok(needs_notification) => {
                            if needs_notification {
                                vring.signal_used_queue().unwrap();
                            }
                        }
                    }
                } else {
                    if vring.add_used(head_idx, used_len as u32).is_err() {
                        warn!("Could not return used descriptors to ring");
                    }
                    vring.signal_used_queue().unwrap();
                }
            });

            if !self.thread_backend.pending_rx() {
                break;
            }
        }
        Ok(used_any)
    }

    /// Wrapper to process rx queue based on whether event idx is enabled or not.
    pub fn process_rx(&mut self, vring: &VringRwLock, event_idx: bool) -> Result<bool> {
        if event_idx {
            // To properly handle EVENT_IDX we need to keep calling
            // process_rx_queue until it stops finding new requests
            // on the queue, as vm-virtio's Queue implementation
            // only checks avail_index once
            loop {
                if !self.thread_backend.pending_rx() {
                    break;
                }
                vring.disable_notification().unwrap();

                self.process_rx_queue(vring)?;
                if !vring.enable_notification().unwrap() {
                    break;
                }
            }
        } else {
            self.process_rx_queue(vring)?;
        }
        Ok(false)
    }
}

impl VhostUserVsockThread for VhostUserVsockRxThread {
    fn set_event_idx(&mut self, enabled: bool) {
        self.event_idx = enabled;
    }

    fn update_memory(&mut self, atomic_mem: GuestMemoryAtomic<GuestMemoryMmap>) {
        self.mem = Some(atomic_mem);
    }

    fn set_vring_worker(
        &mut self,
        vring_worker: Option<Arc<VringEpollHandler<ArcVhostBknd, VringRwLock, ()>>>,
    ) {
        self.vring_worker = vring_worker;
        self.vring_worker
            .as_ref()
            .unwrap()
            .register_listener(
                self.thread_backend.epoll_fd,
                EventSet::IN,
                u64::from(BACKEND_EVENT),
            )
            .unwrap();
    }

    fn handle_event(
        &mut self,
        device_event: u16,
        evset: EventSet,
        vrings: &[VringRwLock],
    ) -> Result<bool> {
        let vring = &vrings[0];

        if evset != EventSet::IN {
            return Err(Error::HandleEventNotEpollIn);
        }

        match device_event {
            THREAD_SPECIFIC_TX_OR_RX_QUEUE_EVENT => {
                if self.thread_backend.pending_rx() {
                    self.process_rx(vring, self.event_idx)?;
                }
            }
            BACKEND_EVENT => {
                self.thread_backend.process_backend_event(evset);
                if self.thread_backend.pending_rx() {
                    self.process_rx(vring, self.event_idx)?;
                }
            }
            EVT_QUEUE_EVENT => {}
            _ => {
                return Err(Error::HandleUnknownEvent);
            }
        }

        Ok(false)
    }
}

pub(crate) struct VhostUserVsockTxThread {
    /// Guest memory map.
    pub mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    /// VIRTIO_RING_F_EVENT_IDX.
    pub event_idx: bool,
    /// Instance of VringWorker.
    vring_worker: Option<Arc<VringEpollHandler<ArcVhostBknd, VringRwLock, ()>>>,
    /// VsockThreadBackend instance.
    pub thread_backend: Arc<VsockThreadBackend>,
    /// Thread pool to handle event idx.
    pool: ThreadPool,
}

impl VhostUserVsockTxThread {
    pub fn new(thread_backend: Arc<VsockThreadBackend>) -> Result<Self> {
        let thread = VhostUserVsockTxThread {
            mem: None,
            event_idx: false,
            vring_worker: None,
            thread_backend,
            pool: ThreadPoolBuilder::new()
                .pool_size(1)
                .create()
                .map_err(Error::CreateThreadPool)?,
        };

        Ok(thread)
    }

    /// Process tx queue and send requests to the backend for processing.
    fn process_tx_queue(&mut self, vring: &VringRwLock) -> Result<bool> {
        let mut used_any = false;

        let atomic_mem = match &self.mem {
            Some(m) => m,
            None => return Err(Error::NoMemoryConfigured),
        };

        while let Some(mut avail_desc) = vring
            .get_mut()
            .get_queue_mut()
            .iter(atomic_mem.memory())
            .map_err(|_| Error::IterateQueue)?
            .next()
        {
            used_any = true;
            let mem = atomic_mem.clone().memory();

            let head_idx = avail_desc.head_index();
            let pkt = match VsockPacket::from_tx_virtq_chain(
                mem.deref(),
                &mut avail_desc,
                CONN_TX_BUF_SIZE,
            ) {
                Ok(pkt) => pkt,
                Err(e) => {
                    dbg!("vsock: error reading TX packet: {:?}", e);
                    continue;
                }
            };

            if self.thread_backend.send_pkt(&pkt).is_err() {
                vring
                    .get_mut()
                    .get_queue_mut()
                    .iter(mem)
                    .unwrap()
                    .go_to_previous_position();
                break;
            }

            // TODO: Check if the protocol requires read length to be correct
            let used_len = 0;

            let vring = vring.clone();
            let event_idx = self.event_idx;

            self.pool.spawn_ok(async move {
                if event_idx {
                    if vring.add_used(head_idx, used_len as u32).is_err() {
                        warn!("Could not return used descriptors to ring");
                    }
                    match vring.needs_notification() {
                        Err(_) => {
                            warn!("Could not check if queue needs to be notified");
                            vring.signal_used_queue().unwrap();
                        }
                        Ok(needs_notification) => {
                            if needs_notification {
                                vring.signal_used_queue().unwrap();
                            }
                        }
                    }
                } else {
                    if vring.add_used(head_idx, used_len as u32).is_err() {
                        warn!("Could not return used descriptors to ring");
                    }
                    vring.signal_used_queue().unwrap();
                }
            });
        }

        Ok(used_any)
    }

    /// Wrapper to process tx queue based on whether event idx is enabled or not.
    pub fn process_tx(&mut self, vring_lock: &VringRwLock, event_idx: bool) -> Result<bool> {
        if event_idx {
            // To properly handle EVENT_IDX we need to keep calling
            // process_rx_queue until it stops finding new requests
            // on the queue, as vm-virtio's Queue implementation
            // only checks avail_index once
            loop {
                vring_lock.disable_notification().unwrap();
                self.process_tx_queue(vring_lock)?;
                if !vring_lock.enable_notification().unwrap() {
                    break;
                }
            }
        } else {
            self.process_tx_queue(vring_lock)?;
        }
        Ok(false)
    }
}

impl VhostUserVsockThread for VhostUserVsockTxThread {
    fn set_event_idx(&mut self, enabled: bool) {
        self.event_idx = enabled;
    }

    fn update_memory(&mut self, atomic_mem: GuestMemoryAtomic<GuestMemoryMmap>) {
        self.mem = Some(atomic_mem);
    }

    fn set_vring_worker(
        &mut self,
        vring_worker: Option<Arc<VringEpollHandler<ArcVhostBknd, VringRwLock, ()>>>,
    ) {
        self.vring_worker = vring_worker;
    }

    fn handle_event(
        &mut self,
        device_event: u16,
        evset: EventSet,
        vrings: &[VringRwLock],
    ) -> Result<bool> {
        let vring = &vrings[0];

        if evset != EventSet::IN {
            return Err(Error::HandleEventNotEpollIn);
        }

        match device_event {
            THREAD_SPECIFIC_TX_OR_RX_QUEUE_EVENT => {
                self.process_tx(vring, self.event_idx)?;
            }
            EVT_QUEUE_EVENT => {}
            _ => {
                return Err(Error::HandleUnknownEvent);
            }
        }

        Ok(false)
    }
}

/*
#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use vm_memory::GuestAddress;
    use vmm_sys_util::eventfd::EventFd;

    impl VhostUserVsockTxThread {
        fn get_epoll_file(&self) -> &File {
            &self.epoll_file
        }
    }

    #[test]
    #[serial]
    fn test_vsock_thread() {
        let t = VhostUserVsockThread::new("test_vsock_thread.vsock".to_string(), 3);
        assert!(t.is_ok());

        let mut t = t.unwrap();
        let epoll_fd = t.get_epoll_file().as_raw_fd();

        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
        );

        t.mem = Some(mem.clone());

        let dummy_fd = EventFd::new(0).unwrap();

        assert!(VhostUserVsockThread::epoll_register(
            epoll_fd,
            dummy_fd.as_raw_fd(),
            epoll::Events::EPOLLOUT
        )
        .is_ok());
        assert!(VhostUserVsockThread::epoll_modify(
            epoll_fd,
            dummy_fd.as_raw_fd(),
            epoll::Events::EPOLLIN
        )
        .is_ok());
        assert!(VhostUserVsockThread::epoll_unregister(epoll_fd, dummy_fd.as_raw_fd()).is_ok());
        assert!(VhostUserVsockThread::epoll_register(
            epoll_fd,
            dummy_fd.as_raw_fd(),
            epoll::Events::EPOLLIN
        )
        .is_ok());

        let vring = VringRwLock::new(mem, 0x1000).unwrap();
        vring.set_queue_info(0x100, 0x200, 0x300).unwrap();
        vring.set_queue_ready(true);

        assert!(t.process_tx(&vring, false).is_ok());
        assert!(t.process_tx(&vring, true).is_ok());
        // add backend_rxq to avoid that RX processing is skipped
        t.thread_backend
            .backend_rxq
            .push_back(ConnMapKey::new(0, 0));
        assert!(t.process_rx(&vring, false).is_ok());
        assert!(t.process_rx(&vring, true).is_ok());

        dummy_fd.write(1).unwrap();

        t.process_backend_evt(EventSet::empty());
    }

    #[test]
    #[serial]
    fn test_vsock_thread_failures() {
        let t = VhostUserVsockThread::new("/sys/not_allowed.vsock".to_string(), 3);
        assert!(t.is_err());

        let mut t =
            VhostUserVsockThread::new("test_vsock_thread_failures.vsock".to_string(), 3).unwrap();
        assert!(VhostUserVsockThread::epoll_register(-1, -1, epoll::Events::EPOLLIN).is_err());
        assert!(VhostUserVsockThread::epoll_modify(-1, -1, epoll::Events::EPOLLIN).is_err());
        assert!(VhostUserVsockThread::epoll_unregister(-1, -1).is_err());

        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
        );

        let vring = VringRwLock::new(mem, 0x1000).unwrap();

        // memory is not configured, so processing TX should fail
        assert!(t.process_tx(&vring, false).is_err());
        assert!(t.process_tx(&vring, true).is_err());

        // add backend_rxq to avoid that RX processing is skipped
        t.thread_backend
            .backend_rxq
            .push_back(ConnMapKey::new(0, 0));
        assert!(t.process_rx(&vring, false).is_err());
        assert!(t.process_rx(&vring, true).is_err());
    }
}
*/
