use std::{
    io::{self, Write},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    process::{Command, Stdio},
};

const POLICY_MARK: &str = "0x1";
const POLICY_FWMARK: &str = "0x1/0x1";

const NFT_FAMILY: &str = "inet";
const NFT_CHAIN: &str = "output";

pub struct RoutingPolicy {
    interface: String,
    table: u32,
    priority: u32,
    nft_table: String,

    ipv4: Ipv4Addr,
    ipv4_prefix: u8,

    ipv6: Ipv6Addr,
    ipv6_prefix: u8,

    installed: bool,
}

impl RoutingPolicy {
    pub fn install(
        interface: &str,
        ipv4: Ipv4Addr,
        ipv4_prefix: u8,
        ipv6: Ipv6Addr,
        ipv6_prefix: u8,
        table: u32,
        priority: u32,
        proxy_addr: SocketAddr,
    ) -> io::Result<Self> {
        require_command("nft", &["--version"])?;
        require_command("ip", &["-V"])?;

        if ipv4_prefix > 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid IPv4 prefix: {ipv4_prefix}"),
            ));
        }

        if ipv6_prefix > 128 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid IPv6 prefix: {ipv6_prefix}"),
            ));
        }

        let nft_table = nft_table_name();

        if nft_table_exists(&nft_table)?
            || route_table_exists(table)?
            || rule_priority_exists(priority)?
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "routing policy configuration already exists",
            ));
        }

        if let Err(error) = add_ipv4_address(interface, ipv4, ipv4_prefix) {
            return Err(error);
        }

        if let Err(error) = add_ipv6_address(interface, ipv6, ipv6_prefix) {
            let _ = delete_ipv4_address(interface, ipv4, ipv4_prefix);
            return Err(error);
        }

        if let Err(error) = add_default_route(false, interface, table) {
            let _ = Self::cleanup(
                table,
                priority,
                interface,
                ipv4,
                ipv4_prefix,
                ipv6,
                ipv6_prefix,
                &nft_table,
            );

            return Err(error);
        }

        if let Err(error) = add_default_route(true, interface, table) {
            let _ = Self::cleanup(
                table,
                priority,
                interface,
                ipv4,
                ipv4_prefix,
                ipv6,
                ipv6_prefix,
                &nft_table,
            );

            return Err(error);
        }

        let script = build_nft_script(&nft_table, proxy_addr);

        if let Err(error) = run_nft_script(&script) {
            let _ = Self::cleanup(
                table,
                priority,
                interface,
                ipv4,
                ipv4_prefix,
                ipv6,
                ipv6_prefix,
                &nft_table,
            );

            return Err(error);
        }

        if let Err(error) = add_rule(false, priority, table) {
            let _ = Self::cleanup(
                table,
                priority,
                interface,
                ipv4,
                ipv4_prefix,
                ipv6,
                ipv6_prefix,
                &nft_table,
            );

            return Err(error);
        }

        if let Err(error) = add_rule(true, priority, table) {
            let _ = Self::cleanup(
                table,
                priority,
                interface,
                ipv4,
                ipv4_prefix,
                ipv6,
                ipv6_prefix,
                &nft_table,
            );

            return Err(error);
        }

        Ok(Self {
            interface: interface.to_owned(),
            table,
            priority,
            nft_table,
            ipv4,
            ipv4_prefix,
            ipv6,
            ipv6_prefix,
            installed: true,
        })
    }

    fn cleanup(
        table: u32,
        priority: u32,
        interface: &str,
        ipv4: Ipv4Addr,
        ipv4_prefix: u8,
        ipv6: Ipv6Addr,
        ipv6_prefix: u8,
        nft_table: &str,
    ) -> io::Result<()> {
        let _ = delete_nft_table(nft_table);

        let _ = delete_rule(false, priority);

        let _ = delete_rule(true, priority);

        let _ = delete_default_route(false, interface, table);

        let _ = delete_default_route(true, interface, table);

        let _ = delete_ipv4_address(interface, ipv4, ipv4_prefix);

        let _ = delete_ipv6_address(interface, ipv6, ipv6_prefix);

        Ok(())
    }
}

impl Drop for RoutingPolicy {
    fn drop(&mut self) {
        if !self.installed {
            return;
        }

        let _ = Self::cleanup(
            self.table,
            self.priority,
            &self.interface,
            self.ipv4,
            self.ipv4_prefix,
            self.ipv6,
            self.ipv6_prefix,
            &self.nft_table,
        );
    }
}

fn nft_table_name() -> String {
    format!("tun_{}", std::process::id())
}

fn nft_table_exists(nft_table: &str) -> io::Result<bool> {
    let output = Command::new("nft")
        .args(["list", "table", NFT_FAMILY, nft_table])
        .output()?;

    Ok(output.status.success())
}

fn route_table_exists(table: u32) -> io::Result<bool> {
    Ok(!route_table_empty(false, table)? || !route_table_empty(true, table)?)
}

fn rule_priority_exists(priority: u32) -> io::Result<bool> {
    Ok(rule_exists(false, priority)? || rule_exists(true, priority)?)
}

fn add_ipv4_address(interface: &str, ipv4: Ipv4Addr, prefix: u8) -> io::Result<()> {
    let address = format!("{ipv4}/{prefix}");

    run("ip", &["-4", "addr", "add", &address, "dev", interface])
}

fn delete_ipv4_address(interface: &str, ipv4: Ipv4Addr, prefix: u8) -> io::Result<()> {
    let address = format!("{ipv4}/{prefix}");

    run("ip", &["-4", "addr", "del", &address, "dev", interface])
}

fn add_ipv6_address(interface: &str, ipv6: Ipv6Addr, prefix: u8) -> io::Result<()> {
    let address = format!("{ipv6}/{prefix}");

    run("ip", &["-6", "addr", "add", &address, "dev", interface])
}

fn delete_ipv6_address(interface: &str, ipv6: Ipv6Addr, prefix: u8) -> io::Result<()> {
    let address = format!("{ipv6}/{prefix}");

    run("ip", &["-6", "addr", "del", &address, "dev", interface])
}

fn add_default_route(ipv6: bool, interface: &str, table: u32) -> io::Result<()> {
    let table = table.to_string();

    if ipv6 {
        run(
            "ip",
            &[
                "-6", "route", "replace", "default", "dev", interface, "table", &table,
            ],
        )
    } else {
        run(
            "ip",
            &[
                "-4", "route", "replace", "default", "dev", interface, "table", &table,
            ],
        )
    }
}

fn delete_default_route(ipv6: bool, interface: &str, table: u32) -> io::Result<()> {
    let table = table.to_string();

    if ipv6 {
        run(
            "ip",
            &[
                "-6", "route", "del", "default", "dev", interface, "table", &table,
            ],
        )
    } else {
        run(
            "ip",
            &[
                "-4", "route", "del", "default", "dev", interface, "table", &table,
            ],
        )
    }
}

fn add_rule(ipv6: bool, priority: u32, table: u32) -> io::Result<()> {
    let priority = priority.to_string();
    let table = table.to_string();

    if ipv6 {
        run(
            "ip",
            &[
                "-6",
                "rule",
                "add",
                "pref",
                &priority,
                "fwmark",
                POLICY_FWMARK,
                "lookup",
                &table,
            ],
        )
    } else {
        run(
            "ip",
            &[
                "-4",
                "rule",
                "add",
                "pref",
                &priority,
                "fwmark",
                POLICY_FWMARK,
                "lookup",
                &table,
            ],
        )
    }
}

fn delete_rule(ipv6: bool, priority: u32) -> io::Result<()> {
    let priority = priority.to_string();

    if ipv6 {
        run("ip", &["-6", "rule", "del", "pref", &priority])
    } else {
        run("ip", &["-4", "rule", "del", "pref", &priority])
    }
}

fn delete_nft_table(nft_table: &str) -> io::Result<()> {
    run("nft", &["delete", "table", NFT_FAMILY, nft_table])
}

fn build_nft_script(nft_table: &str, proxy_addr: SocketAddr) -> String {
    let mut script = String::new();

    script.push_str(&format!("add table {NFT_FAMILY} {nft_table}\n"));

    script.push_str(&format!(
        "add chain {NFT_FAMILY} {nft_table} {NFT_CHAIN} {{ \
         type route hook output priority mangle; policy accept; \
         }}\n"
    ));

    match proxy_addr {
        SocketAddr::V4(address) => {
            script.push_str(&format!(
                "add rule {NFT_FAMILY} {nft_table} {NFT_CHAIN} \
                 ip daddr {} tcp dport {} counter return\n",
                address.ip(),
                address.port(),
            ));
        }

        SocketAddr::V6(address) => {
            script.push_str(&format!(
                "add rule {NFT_FAMILY} {nft_table} {NFT_CHAIN} \
                 ip6 daddr {} tcp dport {} counter return\n",
                address.ip(),
                address.port(),
            ));
        }
    }

    script.push_str(&format!(
        "add rule {NFT_FAMILY} {nft_table} {NFT_CHAIN} \
         meta l4proto tcp counter meta mark set {POLICY_MARK}\n"
    ));

    script
}

fn run_nft_script(script: &str) -> io::Result<()> {
    let output = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            let stdin = child
                .stdin
                .as_mut()
                .ok_or_else(|| io::Error::other("failed to open nft stdin"))?;

            stdin.write_all(script.as_bytes())?;

            child.wait_with_output()
        })?;

    if output.status.success() {
        return Ok(());
    }

    Err(io::Error::other(format!(
        "failed to install nftables policy: {}",
        String::from_utf8_lossy(&output.stderr)
    )))
}

fn require_command(program: &str, args: &[&str]) -> io::Result<()> {
    if command_ok(program, args) {
        return Ok(());
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("{program} is required"),
    ))
}

fn command_ok(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn route_table_empty(ipv6: bool, table: u32) -> io::Result<bool> {
    let table = table.to_string();

    let args = if ipv6 {
        vec!["-6", "route", "show", "table", &table]
    } else {
        vec!["-4", "route", "show", "table", &table]
    };

    let output = Command::new("ip").args(args).output()?;

    if output.status.success() {
        return Ok(output.stdout.is_empty());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);

    if stderr.contains("FIB table does not exist") {
        return Ok(true);
    }

    Err(io::Error::other(format!(
        "failed to inspect routing table {}: {}",
        table, stderr
    )))
}

fn rule_exists(ipv6: bool, priority: u32) -> io::Result<bool> {
    let priority = priority.to_string();

    let args = if ipv6 {
        vec!["-6", "rule", "show", "pref", &priority]
    } else {
        vec!["-4", "rule", "show", "pref", &priority]
    };

    let output = Command::new("ip").args(args).output()?;

    Ok(output.status.success() && !output.stdout.is_empty())
}

fn run(program: &str, args: &[&str]) -> io::Result<()> {
    let output = Command::new(program).args(args).output()?;

    if output.status.success() {
        return Ok(());
    }

    Err(io::Error::other(format!(
        "{program} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    )))
}
