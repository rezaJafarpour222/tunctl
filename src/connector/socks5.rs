use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::core::address::Endpoint;

//SECTION: SOCKS5 protocol constants

const SOCKS_VERSION: u8 = 0x05;

const AUTH_VERSION: u8 = 0x01;

const AUTH_METHOD_USER_PASS: u8 = 0x02;

const COMMAND_CONNECT: u8 = 0x01;
const RESERVED: u8 = 0x00;

const ADDRESS_TYPE_IPV4: u8 = 0x01;
const ADDRESS_TYPE_DOMAIN: u8 = 0x03;
const ADDRESS_TYPE_IPV6: u8 = 0x04;

const AUTH_SUCCESS: u8 = 0x00;
const CONNECT_SUCCESS: u8 = 0x00;

const MAX_CREDENTIAL_LENGTH: usize = u8::MAX as usize;
const MAX_DOMAIN_LENGTH: usize = u8::MAX as usize;

#[derive(Debug, Clone)]
pub enum Socks5Target {
    Ip(SocketAddr),
    Domain { host: String, port: u16 },
}

impl Socks5Target {
    pub fn for_endpoint(endpoint: Endpoint) -> Self {
        Self::Ip(endpoint.into())
    }
}

pub struct Socks5Connector {
    proxy_addr: SocketAddr,
    username: String,
    password: String,
}

impl Socks5Connector {
    pub fn new(proxy_addr: SocketAddr, username: String, password: String) -> io::Result<Self> {
        validate_credential("username", &username)?;
        validate_credential("password", &password)?;

        Ok(Self {
            proxy_addr,
            username,
            password,
        })
    }

    pub fn proxy_addr(&self) -> SocketAddr {
        self.proxy_addr
    }

    pub async fn connect(&self, target: Socks5Target) -> io::Result<TcpStream> {
        let mut stream = TcpStream::connect(self.proxy_addr).await?;

        self.negotiate_authentication(&mut stream).await?;
        self.authenticate(&mut stream).await?;
        self.request_connect(&mut stream, &target).await?;

        Ok(stream)
    }

    async fn negotiate_authentication(&self, stream: &mut TcpStream) -> io::Result<()> {
        let greeting = [SOCKS_VERSION, 1, AUTH_METHOD_USER_PASS];

        stream.write_all(&greeting).await?;

        let mut reply = [0u8; 2];
        stream.read_exact(&mut reply).await?;

        if reply[0] != SOCKS_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "invalid SOCKS5 version in method response: 0x{:02x}",
                    reply[0]
                ),
            ));
        }

        if reply[1] != AUTH_METHOD_USER_PASS {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "SOCKS5 proxy selected unsupported authentication method: \
                     0x{:02x}",
                    reply[1]
                ),
            ));
        }

        Ok(())
    }

    async fn authenticate(&self, stream: &mut TcpStream) -> io::Result<()> {
        let username = self.username.as_bytes();
        let password = self.password.as_bytes();

        let mut request = Vec::with_capacity(3 + username.len() + password.len());

        request.push(AUTH_VERSION);
        request.push(username.len() as u8);
        request.extend_from_slice(username);
        request.push(password.len() as u8);
        request.extend_from_slice(password);

        stream.write_all(&request).await?;

        let mut reply = [0u8; 2];
        stream.read_exact(&mut reply).await?;

        if reply[0] != AUTH_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid SOCKS5 authentication version: 0x{:02x}", reply[0]),
            ));
        }

        if reply[1] != AUTH_SUCCESS {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SOCKS5 username/password authentication failed",
            ));
        }

        Ok(())
    }

    async fn request_connect(
        &self,
        stream: &mut TcpStream,
        target: &Socks5Target,
    ) -> io::Result<()> {
        let mut request = Vec::new();

        request.push(SOCKS_VERSION);
        request.push(COMMAND_CONNECT);
        request.push(RESERVED);

        encode_target(&mut request, target)?;

        stream.write_all(&request).await?;

        self.read_connect_reply(stream).await
    }

    async fn read_connect_reply(&self, stream: &mut TcpStream) -> io::Result<()> {
        let mut header = [0u8; 4];
        stream.read_exact(&mut header).await?;

        let version = header[0];
        let reply = header[1];
        let reserved = header[2];
        let address_type = header[3];

        if version != SOCKS_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid SOCKS5 version in CONNECT response: 0x{version:02x}"),
            ));
        }

        if reserved != RESERVED {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid SOCKS5 reserved field: 0x{reserved:02x}"),
            ));
        }

        if reply != CONNECT_SUCCESS {
            return Err(io::Error::other(format!(
                "SOCKS5 CONNECT failed with reply code 0x{reply:02x}"
            )));
        }

        consume_bound_address(stream, address_type).await?;

        Ok(())
    }
}

fn validate_credential(name: &str, value: &str) -> io::Result<()> {
    if value.is_empty() || value.len() > MAX_CREDENTIAL_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("SOCKS5 {name} must be 1-{} bytes", MAX_CREDENTIAL_LENGTH),
        ));
    }

    Ok(())
}

fn encode_target(request: &mut Vec<u8>, target: &Socks5Target) -> io::Result<()> {
    match target {
        Socks5Target::Ip(SocketAddr::V4(addr)) => {
            encode_ipv4(request, *addr.ip(), addr.port());
        }

        Socks5Target::Ip(SocketAddr::V6(addr)) => {
            encode_ipv6(request, *addr.ip(), addr.port());
        }

        Socks5Target::Domain { host, port } => {
            encode_domain(request, host, *port)?;
        }
    }

    Ok(())
}

fn encode_ipv4(request: &mut Vec<u8>, ip: Ipv4Addr, port: u16) {
    request.push(ADDRESS_TYPE_IPV4);
    request.extend_from_slice(&ip.octets());
    request.extend_from_slice(&port.to_be_bytes());
}

fn encode_ipv6(request: &mut Vec<u8>, ip: Ipv6Addr, port: u16) {
    request.push(ADDRESS_TYPE_IPV6);
    request.extend_from_slice(&ip.octets());
    request.extend_from_slice(&port.to_be_bytes());
}

fn encode_domain(request: &mut Vec<u8>, host: &str, port: u16) -> io::Result<()> {
    let host = host.as_bytes();

    if host.is_empty() || host.len() > MAX_DOMAIN_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("SOCKS5 domain must be 1-{} bytes", MAX_DOMAIN_LENGTH),
        ));
    }

    request.push(ADDRESS_TYPE_DOMAIN);
    request.push(host.len() as u8);
    request.extend_from_slice(host);
    request.extend_from_slice(&port.to_be_bytes());

    Ok(())
}

async fn consume_bound_address<S>(stream: &mut S, address_type: u8) -> io::Result<()>
where
    S: AsyncRead + Unpin,
{
    match address_type {
        ADDRESS_TYPE_IPV4 => {
            let mut address = [0u8; 4];
            stream.read_exact(&mut address).await?;

            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
        }

        ADDRESS_TYPE_IPV6 => {
            let mut address = [0u8; 16];
            stream.read_exact(&mut address).await?;

            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
        }

        ADDRESS_TYPE_DOMAIN => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await?;

            let mut domain = vec![0u8; usize::from(length[0])];
            stream.read_exact(&mut domain).await?;

            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
        }

        address_type => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid SOCKS5 address type: 0x{address_type:02x}"),
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn rejects_empty_username() {
        let result = Socks5Connector::new(
            "127.0.0.1:1080".parse().unwrap(),
            String::new(),
            "password".into(),
        );

        assert!(matches!(
            result,
            Err(error) if error.kind() == io::ErrorKind::InvalidInput
        ));
    }

    #[test]
    fn rejects_empty_password() {
        let result = Socks5Connector::new(
            "127.0.0.1:1080".parse().unwrap(),
            "user".into(),
            String::new(),
        );

        assert!(matches!(
            result,
            Err(error) if error.kind() == io::ErrorKind::InvalidInput
        ));
    }

    #[test]
    fn encodes_ipv4_target() {
        let mut request = Vec::new();

        encode_target(
            &mut request,
            &Socks5Target::Ip("1.2.3.4:443".parse().unwrap()),
        )
        .unwrap();

        assert_eq!(request, [ADDRESS_TYPE_IPV4, 1, 2, 3, 4, 0x01, 0xbb,]);
    }

    #[test]
    fn encodes_domain_target() {
        let mut request = Vec::new();

        encode_target(
            &mut request,
            &Socks5Target::Domain {
                host: "example.com".into(),
                port: 80,
            },
        )
        .unwrap();

        assert_eq!(request[0], ADDRESS_TYPE_DOMAIN);
        assert_eq!(request[1], 11);
        assert_eq!(&request[2..13], b"example.com");
        assert_eq!(&request[13..15], &80u16.to_be_bytes());
    }

    #[tokio::test]
    async fn supports_domain_targets() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();

        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();

            let mut greeting = [0u8; 3];
            socket.read_exact(&mut greeting).await.unwrap();

            assert_eq!(greeting, [SOCKS_VERSION, 1, AUTH_METHOD_USER_PASS,]);

            socket
                .write_all(&[SOCKS_VERSION, AUTH_METHOD_USER_PASS])
                .await
                .unwrap();

            let mut auth_version = [0u8; 1];
            socket.read_exact(&mut auth_version).await.unwrap();

            assert_eq!(auth_version[0], AUTH_VERSION);

            let mut username_len = [0u8; 1];
            socket.read_exact(&mut username_len).await.unwrap();

            let mut username = vec![0u8; usize::from(username_len[0])];

            socket.read_exact(&mut username).await.unwrap();

            let mut password_len = [0u8; 1];
            socket.read_exact(&mut password_len).await.unwrap();

            let mut password = vec![0u8; usize::from(password_len[0])];

            socket.read_exact(&mut password).await.unwrap();

            assert_eq!(username, b"user");
            assert_eq!(password, b"password");

            socket
                .write_all(&[AUTH_VERSION, AUTH_SUCCESS])
                .await
                .unwrap();

            let mut head = [0u8; 5];
            socket.read_exact(&mut head).await.unwrap();

            assert_eq!(
                &head[..4],
                &[
                    SOCKS_VERSION,
                    COMMAND_CONNECT,
                    RESERVED,
                    ADDRESS_TYPE_DOMAIN,
                ]
            );

            let host_len = usize::from(head[4]);

            let mut host_and_port = vec![0u8; host_len + 2];
            socket.read_exact(&mut host_and_port).await.unwrap();

            assert_eq!(&host_and_port[..host_len], b"example.com");

            assert_eq!(
                u16::from_be_bytes([host_and_port[host_len], host_and_port[host_len + 1],]),
                80,
            );

            socket
                .write_all(&[
                    SOCKS_VERSION,
                    CONNECT_SUCCESS,
                    RESERVED,
                    ADDRESS_TYPE_IPV4,
                    127,
                    0,
                    0,
                    1,
                    0,
                    80,
                ])
                .await
                .unwrap();
        });

        let client = Socks5Connector::new(addr, "user".into(), "password".into()).unwrap();

        let stream = client
            .connect(Socks5Target::Domain {
                host: "example.com".into(),
                port: 80,
            })
            .await
            .unwrap();

        drop(stream);

        server.await.unwrap();
    }
}
