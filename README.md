# tunctl

A Linux TUN-based proxy client that routes system traffic through a SOCKS5 server.

`tunctl` creates a virtual network interface and forwards TCP traffic through a SOCKS5 proxy, allowing applications to use the proxy without configuring each application individually.

## Features

- Linux TUN virtual network interface
- SOCKS5 proxy support
- IPv4 and IPv6 support
- Domain name resolution through SOCKS5
- Username and password authentication
- Automatic route configuration
- TCP traffic forwarding
- Lightweight command-line interface

## Requirements

- Linux
- Root privileges or appropriate network capabilities
- A reachable SOCKS5 server

## Installation

### Build from source

```bash
git clone https://github.com/rezaJafarpour222/tunctl.git
cd tunctl
cargo build --release
```

The compiled binary will be available at:

```text
target/release/tunctl
```

## Usage

### Basic usage

```bash
sudo tunctl --socks5 HOST:PORT --auto-route
```

### SOCKS5 authentication

```bash
sudo tunctl \
  --socks5 HOST:PORT \
  --username USERNAME \
  --password PASSWORD \
  --auto-route
```

Replace the host, port, username, and password with your SOCKS5 server credentials.

## How It Works

```text
Applications
     |
     v
Linux Network Stack
     |
     v
TUN Virtual Interface
     |
     v
tunctl (Userspace)
     |
     v
SOCKS5 Proxy
     |
     v
Internet
```

The Linux routing table directs selected traffic into the TUN interface. `tunctl` reads IP packets from the interface, handles the supported TCP traffic, and forwards connections through the configured SOCKS5 server.

## Limitations

- UDP forwarding is not currently supported.
- Requires Linux TUN support.
- Automatic route configuration modifies system networking settings.

## Security

SOCKS5 credentials are supplied through command-line arguments. Avoid sharing terminal output or process information containing credentials.
