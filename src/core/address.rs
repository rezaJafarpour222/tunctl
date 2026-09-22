use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Endpoint {
    pub address: IpAddr,
    pub port: u16,
}

impl Endpoint {
    pub const fn new(address: IpAddr, port: u16) -> Self {
        Self { address, port }
    }
}
impl From<Endpoint> for SocketAddr {
    fn from(endpoint: Endpoint) -> Self {
        SocketAddr::new(endpoint.address, endpoint.port)
    }
}
