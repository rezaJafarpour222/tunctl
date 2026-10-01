use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use tokio::sync::mpsc;

const PACKET_CHANNEL_CAPACITY: usize = 1024;
const REMOTE_EVENT_CHANNEL_CAPACITY: usize = 4096;
const PROCESS_INTERVAL: Duration = Duration::from_millis(10);
const MIN_TUN_BUFFER_SIZE: usize = 65_536;

pub async fn run(config: Config) -> io::Result<()> {
    let tun = create_tun(&config)?;

    let proxy_addr = resolve_proxy_address(&config.socks5_addr).await?;

    print_proxy_info(&config.socks5_addr, proxy_addr);

    let socks5 = create_socks5(&config, proxy_addr)?;

    let _routing = install_routing(&config, &tun, proxy_addr)?;

    let (packet_tx, mut packet_rx) = mpsc::channel(PACKET_CHANNEL_CAPACITY);

    spawn_tun_reader(Arc::clone(&tun), packet_tx, config.tun_mtu);

    let (remote_event_tx, mut remote_event_rx) = mpsc::channel(REMOTE_EVENT_CHANNEL_CAPACITY);

    let mut stack = ProxyStack::new(
        config.tun_ipv4,
        config.tun_netmask,
        config.tun_ipv6,
        config.tun_ipv6_prefix,
        config.tun_mtu,
        socks5,
        config.domain_mode,
        remote_event_tx,
    )?;

    print_runtime_info(tun.name(), config.auto_route);

    run_event_loop(&tun, &mut stack, &mut packet_rx, &mut remote_event_rx).await
}

fn create_tun(config: &Config) -> io::Result<Arc<TunDevice>> {
    let tun = TunDevice::new(
        &config.tun_name,
        config.tun_ipv4,
        config.tun_netmask,
        config.tun_mtu,
    )?;

    Ok(Arc::new(tun))
}

fn create_socks5(config: &Config, proxy_addr: SocketAddr) -> io::Result<Arc<Socks5Connector>> {
    let socks5 = Socks5Connector::new(
        proxy_addr,
        config.socks5_username.clone(),
        config.socks5_password.clone(),
    )?;

    Ok(Arc::new(socks5))
}

fn install_routing(
    config: &Config,
    tun: &TunDevice,
    proxy_addr: SocketAddr,
) -> io::Result<Option<RoutingPolicy>> {
    if !config.auto_route {
        return Ok(None);
    }

    let routing = RoutingPolicy::install(
        tun.name(),
        config.tun_ipv6,
        config.tun_ipv6_prefix,
        config.route_table,
        config.rule_priority,
        config.bypass_uid,
        proxy_addr,
    )?;

    Ok(Some(routing))
}

fn spawn_tun_reader(tun: Arc<TunDevice>, packet_tx: mpsc::Sender<Vec<u8>>, tun_mtu: usize) {
    tokio::spawn(async move {
        let mut buffer = vec![0u8; tun_mtu.max(MIN_TUN_BUFFER_SIZE)];

        loop {
            match tun.recv(&mut buffer).await {
                Ok(size) => {
                    if packet_tx.send(buffer[..size].to_vec()).await.is_err() {
                        break;
                    }
                }

                Err(error) => {
                    eprintln!("TUN read error: {error}");
                    break;
                }
            }
        }
    });
}

fn print_proxy_info(configured_address: &str, resolved_address: SocketAddr) {
    println!("SOCKS5: {configured_address} -> {resolved_address}");
}

fn print_runtime_info(tun_name: &str, auto_route: bool) {
    println!("TUN device: {tun_name}");
    println!("auto route: {auto_route}");
    println!("TCP stack: smoltcp 0.14");
}

async fn run_event_loop(
    tun: &TunDevice,
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
                        return Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            format!(
                                "failed to listen for shutdown signal: {error}"
                            ),
                        ));
                    }
                }
            }

            Some(packet) = packet_rx.recv() => {
                stack.ingest_packet(packet);
            }

            Some(event) = remote_event_rx.recv() => {
                stack.handle_remote_event(event);
            }

            _ = ticker.tick() => {}
        }

        stack.process();

        send_pending_packets(tun, stack).await?;
    }
}

async fn send_pending_packets(tun: &TunDevice, stack: &mut ProxyStack) -> io::Result<()> {
    for packet in stack.drain_tx() {
        tun.send_all(&packet).await?;
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
            format!("failed to resolve SOCKS5 proxy `{value}`: {error}"),
        )
    })?;

    addresses.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("SOCKS5 proxy `{value}` resolved to no addresses"),
        )
    })
}
