use std::{
    collections::{HashMap, VecDeque},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use smoltcp::{
    iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet},
    socket::tcp,
    time::Instant,
    wire::{
        HardwareAddress, IpAddress, IpCidr, IpProtocol, Ipv4Address, Ipv4Packet, Ipv6Address,
        Ipv6Packet, TcpPacket,
    },
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
};

use crate::{
    connector::socks5::{Socks5Connector, Socks5Target},
    core::{address::Endpoint, session::TcpFlowKey},
    stack::{adaptor::QueueDevice, domain::detect_domain},
};

const TCP_RX_BUFFER: usize = 128 * 1024;
const TCP_TX_BUFFER: usize = 128 * 1024;

const MAX_DOMAIN_BUFFER: usize = 32 * 1024;

const MAX_PENDING_TO_REMOTE: usize = 512 * 1024;
const MAX_PENDING_FROM_REMOTE: usize = 512 * 1024;

const REMOTE_CHANNEL_SIZE: usize = 32;
const REMOTE_READ_SIZE: usize = 16 * 1024;

const DOMAIN_DETECTION_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug)]
pub enum RemoteEvent {
    Data { key: TcpFlowKey, data: Vec<u8> },

    Closed { key: TcpFlowKey },

    Failed { key: TcpFlowKey, error: String },
}

enum RemoteCommand {
    Write(Vec<u8>),
    Close,
}

struct Flow {
    key: TcpFlowKey,
    socket: SocketHandle,

    domain_buffer: Vec<u8>,
    domain_deadline: std::time::Instant,
    target_started: bool,

    remote_tx: Option<mpsc::Sender<RemoteCommand>>,
    remote_closed: bool,
    remote_close_sent: bool,

    pending_to_remote: VecDeque<Vec<u8>>,
    pending_to_remote_bytes: usize,

    pending_from_remote: VecDeque<Vec<u8>>,
    pending_from_remote_bytes: usize,

    client_fin: bool,
    failed: bool,
}

pub struct ProxyStack {
    device: QueueDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    flows: HashMap<TcpFlowKey, Flow>,

    socks5: Arc<Socks5Connector>,
    remote_event_tx: mpsc::Sender<RemoteEvent>,

    _tun_ipv4: Ipv4Addr,
    _tun_ipv6: Ipv6Addr,
    mtu: usize,
}

impl ProxyStack {
    pub fn new(
        tun_ipv4: Ipv4Addr,
        tun_netmask: Ipv4Addr,
        tun_ipv6: Ipv6Addr,
        tun_ipv6_prefix: u8,
        mtu: usize,
        socks5: Arc<Socks5Connector>,
        remote_event_tx: mpsc::Sender<RemoteEvent>,
    ) -> io::Result<Self> {
        let mut device = QueueDevice::new(mtu);

        let mut iface_config = InterfaceConfig::new(HardwareAddress::Ip);

        iface_config.random_seed = random_seed();

        let now = Instant::now();

        let mut iface = Interface::new(iface_config, &mut device, now);

        configure_interface(&mut iface, tun_ipv4, tun_netmask, tun_ipv6, tun_ipv6_prefix)?;

        Ok(Self {
            device,
            iface,
            sockets: SocketSet::new(vec![]),
            flows: HashMap::new(),
            socks5,
            remote_event_tx,
            _tun_ipv4: tun_ipv4,
            _tun_ipv6: tun_ipv6,
            mtu,
        })
    }

    pub fn ingest_packet(&mut self, packet: Vec<u8>) {
        if let Some(key) = inspect_initial_syn(&packet) {
            self.ensure_flow(key);
        }

        self.device.push_rx(packet);
    }

    pub fn process(&mut self, debug: bool) {
        let now = Instant::now();

        self.process_ingress(now);
        self.iface.poll_maintenance(now);

        self.service_flows(debug);

        self.process_egress(now);

        self.cleanup_closed_flows();
    }

    pub fn handle_remote_event(&mut self, event: RemoteEvent) {
        let key = remote_event_key(&event);

        let Some(flow) = self.flows.get_mut(&key) else {
            return;
        };

        match event {
            RemoteEvent::Data { data, .. } => {
                enqueue_from_remote(flow, data);
            }

            RemoteEvent::Closed { .. } => {
                flow.remote_closed = true;
            }

            RemoteEvent::Failed { error, .. } => {
                eprintln!(
                    "SOCKS5 flow {:?} -> {:?} failed: {}",
                    flow.key.source, flow.key.destination, error
                );

                flow.failed = true;
                flow.remote_closed = true;
            }
        }
    }

    pub fn drain_tx(&mut self) -> Vec<Vec<u8>> {
        let mut packets = Vec::new();

        while let Some(packet) = self.device.pop_tx() {
            packets.push(packet);
        }

        packets
    }

    fn process_ingress(&mut self, now: Instant) {
        loop {
            match self
                .iface
                .poll_ingress_single(now, &mut self.device, &mut self.sockets)
            {
                smoltcp::iface::PollIngressSingleResult::None => {
                    break;
                }

                smoltcp::iface::PollIngressSingleResult::PacketProcessed
                | smoltcp::iface::PollIngressSingleResult::SocketStateChanged => {}
            }
        }
    }

    fn process_egress(&mut self, now: Instant) {
        let _ = self
            .iface
            .poll_egress(now, &mut self.device, &mut self.sockets);
    }

    fn ensure_flow(&mut self, key: TcpFlowKey) {
        if self.flows.contains_key(&key) {
            return;
        }

        self.create_flow(key);
    }

    fn create_flow(&mut self, key: TcpFlowKey) {
        let socket = create_tcp_socket();

        let local_ip = to_smol_ip(key.destination.address);

        let mut socket = socket;

        if let Err(error) = socket.listen((local_ip, key.destination.port)) {
            eprintln!(
                "failed to listen for {:?} -> {:?}: {error:?}",
                key.source, key.destination
            );

            return;
        }

        let handle = self.sockets.add(socket);

        self.flows.insert(
            key,
            Flow {
                key,
                socket: handle,

                domain_buffer: Vec::new(),
                domain_deadline: std::time::Instant::now() + DOMAIN_DETECTION_TIMEOUT,
                target_started: false,

                remote_tx: None,
                remote_closed: false,
                remote_close_sent: false,

                pending_to_remote: VecDeque::new(),
                pending_to_remote_bytes: 0,

                pending_from_remote: VecDeque::new(),
                pending_from_remote_bytes: 0,

                client_fin: false,
                failed: false,
            },
        );
    }

    fn service_flows(&mut self, debug: bool) {
        let keys: Vec<TcpFlowKey> = self.flows.keys().copied().collect();

        for key in keys {
            self.service_flow(key, debug);
        }
    }

    fn service_flow(&mut self, key: TcpFlowKey, debug: bool) {
        let Some(flow) = self.flows.get(&key) else {
            return;
        };

        let socket_handle = flow.socket;

        let (client_data, client_finished) = self.read_client_data(socket_handle);

        self.handle_client_data(key, client_data, client_finished);

        self.maybe_start_remote(key, debug);
        self.flush_to_remote(key);
        self.flush_from_remote(key);

        self.maybe_close_remote(key);
        self.maybe_close_local(key);
        self.abort_failed_flow(key);
    }

    fn read_client_data(&mut self, handle: SocketHandle) -> (Vec<u8>, bool) {
        let mut data = Vec::new();
        let mut finished = false;

        let socket = self.sockets.get_mut::<tcp::Socket>(handle);

        let mut buffer = vec![0u8; REMOTE_READ_SIZE];

        while socket.can_recv() {
            match socket.recv_slice(&mut buffer) {
                Ok(0) => break,

                Ok(n) => {
                    data.extend_from_slice(&buffer[..n]);

                    if data.len() >= MAX_PENDING_TO_REMOTE {
                        break;
                    }
                }

                Err(tcp::RecvError::Finished) => {
                    finished = true;
                    break;
                }

                Err(_) => {
                    break;
                }
            }
        }

        if matches!(
            socket.state(),
            tcp::State::CloseWait | tcp::State::LastAck | tcp::State::Closing
        ) {
            finished = true;
        }

        (data, finished)
    }

    fn handle_client_data(&mut self, key: TcpFlowKey, data: Vec<u8>, finished: bool) {
        if !data.is_empty() {
            let Some(flow) = self.flows.get_mut(&key) else {
                return;
            };

            if flow.target_started {
                enqueue_to_remote(flow, data);
            } else if flow.domain_buffer.len().saturating_add(data.len()) <= MAX_DOMAIN_BUFFER {
                flow.domain_buffer.extend_from_slice(&data);
            } else {
                flow.failed = true;
            }
        }

        if finished {
            if let Some(flow) = self.flows.get_mut(&key) {
                flow.client_fin = true;
            }
        }
    }

    fn maybe_start_remote(&mut self, key: TcpFlowKey, debug: bool) {
        let Some(flow) = self.flows.get(&key) else {
            return;
        };

        if flow.target_started || flow.domain_buffer.is_empty() {
            return;
        }

        let target = self.determine_target(key, flow);

        let Some(target) = target else {
            return;
        };
        if debug {
            eprintln!(
                "SOCKS5 CONNECT {:?} for {:?} -> {:?}",
                target, key.source, key.destination
            );
        }

        self.start_remote(key, target);
    }

    fn determine_target(&self, key: TcpFlowKey, flow: &Flow) -> Option<Socks5Target> {
        if let Some(domain) = detect_domain(&flow.domain_buffer) {
            return Some(Socks5Target::Domain {
                host: domain,
                port: key.destination.port,
            });
        }

        if flow.domain_detection_expired() || flow.client_fin {
            return Some(Socks5Target::for_endpoint(key.destination));
        }

        None
    }

    fn start_remote(&mut self, key: TcpFlowKey, target: Socks5Target) {
        let (cmd_tx, cmd_rx) = mpsc::channel(REMOTE_CHANNEL_SIZE);

        let buffered = {
            let Some(flow) = self.flows.get_mut(&key) else {
                return;
            };

            if flow.target_started {
                return;
            }

            flow.target_started = true;
            flow.remote_tx = Some(cmd_tx);

            std::mem::take(&mut flow.domain_buffer)
        };

        if !buffered.is_empty() {
            if let Some(flow) = self.flows.get_mut(&key) {
                enqueue_to_remote(flow, buffered);
            }
        }

        let socks5 = Arc::clone(&self.socks5);

        let events = self.remote_event_tx.clone();

        tokio::spawn(async move {
            remote_task(key, target, socks5, cmd_rx, events).await;
        });
    }

    fn flush_to_remote(&mut self, key: TcpFlowKey) {
        let Some(flow) = self.flows.get_mut(&key) else {
            return;
        };

        let Some(tx) = flow.remote_tx.clone() else {
            return;
        };

        loop {
            let Some(chunk) = flow.pending_to_remote.front() else {
                break;
            };

            match tx.try_send(RemoteCommand::Write(chunk.clone())) {
                Ok(()) => {
                    let sent = flow
                        .pending_to_remote
                        .pop_front()
                        .expect("front existed before pop");

                    flow.pending_to_remote_bytes =
                        flow.pending_to_remote_bytes.saturating_sub(sent.len());
                }

                Err(mpsc::error::TrySendError::Full(_)) => {
                    break;
                }

                Err(mpsc::error::TrySendError::Closed(_)) => {
                    flow.failed = true;
                    break;
                }
            }
        }
    }

    fn flush_from_remote(&mut self, key: TcpFlowKey) {
        let Some(flow) = self.flows.get(&key) else {
            return;
        };

        let handle = flow.socket;

        loop {
            let chunk = {
                let Some(flow) = self.flows.get_mut(&key) else {
                    return;
                };

                flow.pending_from_remote.pop_front()
            };

            let Some(mut chunk) = chunk else {
                break;
            };

            let result = {
                let socket = self.sockets.get_mut::<tcp::Socket>(handle);

                if !socket.can_send() {
                    None
                } else {
                    Some(socket.send_slice(&chunk))
                }
            };

            match result {
                None => {
                    self.return_remote_chunk(key, chunk);

                    break;
                }

                Some(Ok(n)) => {
                    if let Some(flow) = self.flows.get_mut(&key) {
                        flow.pending_from_remote_bytes =
                            flow.pending_from_remote_bytes.saturating_sub(n);
                    }

                    if n < chunk.len() {
                        chunk.drain(..n);

                        self.return_remote_chunk(key, chunk);

                        break;
                    }
                }

                Some(Err(_)) => {
                    self.return_remote_chunk(key, chunk);

                    break;
                }
            }
        }
    }

    fn return_remote_chunk(&mut self, key: TcpFlowKey, chunk: Vec<u8>) {
        if let Some(flow) = self.flows.get_mut(&key) {
            flow.pending_from_remote.push_front(chunk);
        }
    }

    fn maybe_close_remote(&mut self, key: TcpFlowKey) {
        let should_close = self
            .flows
            .get(&key)
            .map(|flow| flow.client_fin && flow.remote_tx.is_some() && !flow.remote_close_sent)
            .unwrap_or(false);

        if !should_close {
            return;
        }

        let Some(flow) = self.flows.get_mut(&key) else {
            return;
        };

        let Some(tx) = flow.remote_tx.as_ref() else {
            return;
        };

        if tx.try_send(RemoteCommand::Close).is_ok() {
            flow.remote_close_sent = true;
        }
    }

    fn maybe_close_local(&mut self, key: TcpFlowKey) {
        let Some(flow) = self.flows.get(&key) else {
            return;
        };

        if !flow.remote_closed || flow.pending_from_remote_bytes != 0 || !flow.target_started {
            return;
        }

        let socket = self.sockets.get_mut::<tcp::Socket>(flow.socket);

        socket.close();
    }

    fn abort_failed_flow(&mut self, key: TcpFlowKey) {
        let Some(flow) = self.flows.get(&key) else {
            return;
        };

        if !flow.failed {
            return;
        }

        let socket = self.sockets.get_mut::<tcp::Socket>(flow.socket);

        socket.abort();
    }

    fn cleanup_closed_flows(&mut self) {
        let keys: Vec<TcpFlowKey> = self.flows.keys().copied().collect();

        for key in keys {
            if self.flow_closed(key) {
                self.remove_flow(key);
            }
        }
    }

    fn flow_closed(&self, key: TcpFlowKey) -> bool {
        let Some(flow) = self.flows.get(&key) else {
            return true;
        };

        let socket_closed =
            self.sockets.get::<tcp::Socket>(flow.socket).state() == tcp::State::Closed;

        socket_closed && (flow.remote_closed || flow.failed)
    }

    fn remove_flow(&mut self, key: TcpFlowKey) {
        let Some(flow) = self.flows.remove(&key) else {
            return;
        };

        let _ = self.sockets.remove(flow.socket);
    }
}

impl Flow {
    fn domain_detection_expired(&self) -> bool {
        self.domain_deadline.elapsed() >= DOMAIN_DETECTION_TIMEOUT
            || self.domain_buffer.len() >= MAX_DOMAIN_BUFFER
    }
}

fn configure_interface(
    iface: &mut Interface,
    tun_ipv4: Ipv4Addr,
    tun_netmask: Ipv4Addr,
    tun_ipv6: Ipv6Addr,
    tun_ipv6_prefix: u8,
) -> io::Result<()> {
    let ipv4_prefix = netmask_prefix(tun_netmask)?;

    let smol_ipv4 = to_smol_ipv4(tun_ipv4);

    let smol_ipv6 = to_smol_ipv6(tun_ipv6);

    iface.update_ip_addrs(|addrs| {
        addrs
            .push(IpCidr::new(IpAddress::Ipv4(smol_ipv4), ipv4_prefix))
            .expect("smoltcp IPv4 address capacity exceeded");

        addrs
            .push(IpCidr::new(IpAddress::Ipv6(smol_ipv6), tun_ipv6_prefix))
            .expect("smoltcp IPv6 address capacity exceeded");
    });

    iface.set_any_ip(true);

    iface
        .routes_mut()
        .add_default_ipv4_route(smol_ipv4)
        .map_err(|error| {
            io::Error::other(format!(
                "failed to add smoltcp IPv4 default route: {error:?}"
            ))
        })?;

    iface
        .routes_mut()
        .add_default_ipv6_route(smol_ipv6)
        .map_err(|error| {
            io::Error::other(format!(
                "failed to add smoltcp IPv6 default route: {error:?}"
            ))
        })?;

    Ok(())
}

fn create_tcp_socket() -> tcp::Socket<'static> {
    let rx_buffer = tcp::SocketBuffer::new(vec![0u8; TCP_RX_BUFFER]);

    let tx_buffer = tcp::SocketBuffer::new(vec![0u8; TCP_TX_BUFFER]);

    let mut socket = tcp::Socket::new(rx_buffer, tx_buffer);

    socket.set_congestion_control(tcp::CongestionControl::Reno);

    socket
}

fn enqueue_to_remote(flow: &mut Flow, data: Vec<u8>) {
    let new_size = flow.pending_to_remote_bytes.saturating_add(data.len());

    if new_size > MAX_PENDING_TO_REMOTE {
        flow.failed = true;
        return;
    }

    flow.pending_to_remote_bytes = new_size;

    flow.pending_to_remote.push_back(data);
}

fn enqueue_from_remote(flow: &mut Flow, data: Vec<u8>) {
    let new_size = flow.pending_from_remote_bytes.saturating_add(data.len());

    if new_size > MAX_PENDING_FROM_REMOTE {
        flow.failed = true;
        return;
    }

    flow.pending_from_remote_bytes = new_size;

    flow.pending_from_remote.push_back(data);
}

fn remote_event_key(event: &RemoteEvent) -> TcpFlowKey {
    match event {
        RemoteEvent::Data { key, .. }
        | RemoteEvent::Closed { key }
        | RemoteEvent::Failed { key, .. } => *key,
    }
}

async fn remote_task(
    key: TcpFlowKey,
    target: Socks5Target,
    socks5: Arc<Socks5Connector>,
    mut cmd_rx: mpsc::Receiver<RemoteCommand>,
    events: mpsc::Sender<RemoteEvent>,
) {
    let stream = match socks5.connect(target).await {
        Ok(stream) => stream,

        Err(error) => {
            let _ = events
                .send(RemoteEvent::Failed {
                    key,
                    error: error.to_string(),
                })
                .await;

            return;
        }
    };

    let (mut reader, mut writer) = stream.into_split();

    let mut buffer = vec![0u8; REMOTE_READ_SIZE];

    let mut write_closed = false;

    loop {
        tokio::select! {
            read_result =
                reader.read(&mut buffer) =>
            {
                match read_result {
                    Ok(0) => {
                        let _ = events
                            .send(
                                RemoteEvent::Closed { key }
                            )
                            .await;

                        return;
                    }

                    Ok(n) => {
                        if events
                            .send(
                                RemoteEvent::Data {
                                    key,
                                    data: buffer[..n]
                                        .to_vec(),
                                },
                            )
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }

                    Err(error) => {
                        let _ = events
                            .send(
                                RemoteEvent::Failed {
                                    key,
                                    error: error
                                        .to_string(),
                                },
                            )
                            .await;

                        return;
                    }
                }
            }

            command = cmd_rx.recv(),
            if !write_closed =>
            {
                match command {
                    Some(RemoteCommand::Write(data)) => {
                        if let Err(error) =
                            writer.write_all(&data).await
                        {
                            let _ = events
                                .send(
                                    RemoteEvent::Failed {
                                        key,
                                        error: error
                                            .to_string(),
                                    },
                                )
                                .await;

                            return;
                        }
                    }

                    Some(RemoteCommand::Close) => {
                        if let Err(error) =
                            writer.shutdown().await
                        {
                            let _ = events
                                .send(
                                    RemoteEvent::Failed {
                                        key,
                                        error: error
                                            .to_string(),
                                    },
                                )
                                .await;

                            return;
                        }

                        write_closed = true;
                    }

                    None => {
                        let _ =
                            writer.shutdown().await;

                        write_closed = true;
                    }
                }
            }
        }
    }
}

fn inspect_initial_syn(packet: &[u8]) -> Option<TcpFlowKey> {
    match packet.first().copied()? >> 4 {
        4 => inspect_ipv4_syn(packet),
        6 => inspect_ipv6_syn(packet),
        _ => None,
    }
}

fn inspect_ipv4_syn(packet: &[u8]) -> Option<TcpFlowKey> {
    let ip = Ipv4Packet::new_checked(packet).ok()?;

    if ip.next_header() != IpProtocol::Tcp {
        return None;
    }

    let tcp = TcpPacket::new_checked(ip.payload()).ok()?;

    if !tcp.syn() || tcp.ack() {
        return None;
    }

    let source = Endpoint::new(IpAddr::V4(ip.src_addr().into()), tcp.src_port());

    let destination = Endpoint::new(IpAddr::V4(ip.dst_addr().into()), tcp.dst_port());

    Some(TcpFlowKey::new(source, destination))
}

fn inspect_ipv6_syn(packet: &[u8]) -> Option<TcpFlowKey> {
    let ip = Ipv6Packet::new_checked(packet).ok()?;

    if ip.next_header() != IpProtocol::Tcp {
        return None;
    }

    let tcp = TcpPacket::new_checked(ip.payload()).ok()?;

    if !tcp.syn() || tcp.ack() {
        return None;
    }

    let source = Endpoint::new(IpAddr::V6(ip.src_addr().into()), tcp.src_port());

    let destination = Endpoint::new(IpAddr::V6(ip.dst_addr().into()), tcp.dst_port());

    Some(TcpFlowKey::new(source, destination))
}

fn to_smol_ipv4(address: Ipv4Addr) -> Ipv4Address {
    let octets = address.octets();

    Ipv4Address::new(octets[0], octets[1], octets[2], octets[3])
}

fn to_smol_ipv6(address: Ipv6Addr) -> Ipv6Address {
    Ipv6Address::from(address.octets())
}

fn to_smol_ip(address: IpAddr) -> IpAddress {
    match address {
        IpAddr::V4(address) => IpAddress::Ipv4(to_smol_ipv4(address)),

        IpAddr::V6(address) => IpAddress::Ipv6(to_smol_ipv6(address)),
    }
}

fn netmask_prefix(netmask: Ipv4Addr) -> io::Result<u8> {
    let value = u32::from(netmask);

    let prefix = value.count_ones() as u8;

    let expected = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };

    if value != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("non-contiguous IPv4 netmask: {netmask}"),
        ));
    }

    Ok(prefix)
}

fn random_seed() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);

    let pid = u64::from(std::process::id());

    (nanos as u64) ^ pid.wrapping_mul(2_654_435_761)
}
