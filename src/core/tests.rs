use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::core::{address::Endpoint, session::TcpFlowKey};

// SECTION: address.rs

#[test]
fn new_stores_address_and_port() {
    let address = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
    let endpoint = Endpoint::new(address, 8080);
    assert_eq!(endpoint.address, address);
    assert_eq!(endpoint.port, 8080)
}
#[test]
fn converts_ipv4_endpoint_to_socket_addr() {
    let endpoint = Endpoint::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 8080);

    let socket_addr: SocketAddr = endpoint.into();

    assert_eq!(
        socket_addr,
        SocketAddr::new(endpoint.address, endpoint.port)
    );
}

#[test]
fn converts_ipv6_endpoint_to_socket_addr() {
    let endpoint = Endpoint::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443);

    let socket_addr: SocketAddr = endpoint.into();

    assert_eq!(
        socket_addr,
        SocketAddr::new(endpoint.address, endpoint.port)
    );
}

// SECTION: session.rs
#[test]
fn new_store_source_and_destination() {
    let source = Endpoint::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443);
    let destination = Endpoint::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 8080);

    let tcp_flow_key = TcpFlowKey::new(source, destination);
    assert_eq!(tcp_flow_key.destination, destination);
    assert_eq!(tcp_flow_key.source, source);
}
