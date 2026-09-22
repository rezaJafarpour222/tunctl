use crate::core::address::Endpoint;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TcpFlowKey {
    pub source: Endpoint,
    pub destination: Endpoint,
}

impl TcpFlowKey {
    pub const fn new(source: Endpoint, destination: Endpoint) -> Self {
        Self {
            source,
            destination,
        }
    }
}
