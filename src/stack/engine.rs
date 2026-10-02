use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    thread,
    time::Duration,
};

use tokio::sync::mpsc;

use crate::{
    config::Config,
    connector::socks5::Socks5Connector,
    policies::linux::RoutingPolicy,
    stack::proxy_stack::{ProxyStack, RemoteEvent},
    tun::device::Device,
};

const PACKET_CHANNEL_CAPACITY: usize = 1024;
const REMOTE_EVENT_CHANNEL_CAPACITY: usize = 4096;
const PROCESS_INTERVAL: Duration = Duration::from_millis(10);
const MIN_TUN_BUFFER_SIZE: usize = 65_536;

const TUN_NAME: &str = "tunctl";

const TUN_IPV4: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 1);

const TUN_NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);

const TUN_IPV4_PREFIX: u8 = 24;

const TUN_IPV6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x0200, 0x0000, 0x0001, 0, 0, 0, 1);

const TUN_IPV6_PREFIX: u8 = 64;

const TUN_MTU: usize = 1500;

const ROUTE_TABLE: u32 = 51820;
const RULE_PRIORITY: u32 = 12000;

pub async fn run(config: Config) -> io::Result<()> {
    let mut tun = Device::new(TUN_NAME)?;

    let proxy_addr = resolve_proxy_address(&config.socks5).await?;

    print_proxy_info(&config.socks5, proxy_addr);

    let socks5 = create_socks5(&config, proxy_addr)?;

    let _routing = install_routing(&tun, proxy_addr, config.auto_route)?;

    let (packet_tx, mut packet_rx) = mpsc::channel(PACKET_CHANNEL_CAPACITY);

    let tun_reader = tun.try_clone()?;

    spawn_tun_reader(tun_reader, packet_tx);

    let (remote_event_tx, mut remote_event_rx) = mpsc::channel(REMOTE_EVENT_CHANNEL_CAPACITY);

    let mut stack = ProxyStack::new(
        TUN_IPV4,
        TUN_NETMASK,
        TUN_IPV6,
        TUN_IPV6_PREFIX,
        TUN_MTU,
        socks5,
        remote_event_tx,
    )?;

    print_runtime_info(tun.name(), config.auto_route);

    run_event_loop(&mut tun, &mut stack, &mut packet_rx, &mut remote_event_rx).await
}

fn create_socks5(
    config: &Config,
    proxy_addr: SocketAddr,
) -> io::Result<std::sync::Arc<Socks5Connector>> {
    let socks5 =
        Socks5Connector::new(proxy_addr, config.username.clone(), config.password.clone())?;

    Ok(std::sync::Arc::new(socks5))
}

fn install_routing(
    tun: &Device,
    proxy_addr: SocketAddr,
    auto_route: bool,
) -> io::Result<Option<RoutingPolicy>> {
    if !auto_route {
        return Ok(None);
    }

    let routing = RoutingPolicy::install(
        tun.name(),
        TUN_IPV4,
        TUN_IPV4_PREFIX,
        TUN_IPV6,
        TUN_IPV6_PREFIX,
        ROUTE_TABLE,
        RULE_PRIORITY,
        proxy_addr,
    )?;

    Ok(Some(routing))
}

fn spawn_tun_reader(mut tun: Device, packet_tx: mpsc::Sender<Vec<u8>>) {
    thread::spawn(move || {
        let mut buffer = vec![0u8; TUN_MTU.max(MIN_TUN_BUFFER_SIZE)];

        loop {
            match tun.recv(&mut buffer) {
                Ok(size) => {
                    if size == 0 {
                        continue;
                    }

                    if packet_tx.blocking_send(buffer[..size].to_vec()).is_err() {
                        break;
                    }
                }

                Err(error) => {
                    eprintln!("TUN read error: {}", error);
                    break;
                }
            }
        }
    });
}

fn print_proxy_info(configured_address: &str, resolved_address: SocketAddr) {
    println!("SOCKS5: {} -> {}", configured_address, resolved_address);
}

fn print_runtime_info(tun_name: &str, auto_route: bool) {
    println!("TUN device: {}", tun_name);

    println!("auto route: {}", auto_route);

    println!("TCP stack: smoltcp 0.14");
}

async fn run_event_loop(
    tun: &mut Device,
    stack: &mut ProxyStack,
    packet_rx: &mut mpsc::Receiver<Vec<u8>>,
    remote_event_rx: &mut mpsc::Receiver<RemoteEvent>,
) -> io::Result<()> {
    let mut ticker = tokio::time::interval(PROCESS_INTERVAL);

    let mut shutdown = Box::pin(tokio::signal::ctrl_c());

    loop {
        tokio::select! {
            result = &mut shutdown => {
                match result {
                    Ok(()) => {
                        println!("shutting down");
                        return Ok(());
                    }

                    Err(error) => {
                        return Err(
                            io::Error::new(
                                io::ErrorKind::Interrupted,
                                format!(
                                    "failed to listen for shutdown signal: {}",
                                    error
                                ),
                            )
                        );
                    }
                }
            }

            packet = packet_rx.recv() => {
                match packet {
                    Some(packet) => {
                        stack.ingest_packet(packet);
                    }

                    None => {
                        return Err(
                            io::Error::new(
                                io::ErrorKind::BrokenPipe,
                                "TUN reader stopped",
                            )
                        );
                    }
                }
            }

            event = remote_event_rx.recv() => {
                match event {
                    Some(event) => {
                        stack.handle_remote_event(event);
                    }

                    None => {
                        return Err(
                            io::Error::new(
                                io::ErrorKind::BrokenPipe,
                                "remote event channel closed",
                            )
                        );
                    }
                }
            }

            _ = ticker.tick() => {}
        }

        stack.process();

        send_pending_packets(tun, stack)?;
    }
}

fn send_pending_packets(tun: &mut Device, stack: &mut ProxyStack) -> io::Result<()> {
    for packet in stack.drain_tx() {
        if packet.is_empty() {
            continue;
        }

        tun.send_all(&packet)?;
    }

    Ok(())
}

async fn resolve_proxy_address(value: &str) -> io::Result<SocketAddr> {
    if let Ok(address) = value.parse::<SocketAddr>() {
        return Ok(address);
    }

    let mut addresses = tokio::net::lookup_host(value).await.map_err(|error| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("failed to resolve SOCKS5 proxy `{}`: {}", value, error),
        )
    })?;

    addresses.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("SOCKS5 proxy `{}` resolved to no addresses", value),
        )
    })
}
