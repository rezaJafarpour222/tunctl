use std::{
    io::{self, Write},
    net::{Ipv6Addr, SocketAddr},
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
    ipv6: Ipv6Addr,
    prefix: u8,
    installed: bool,
}

impl RoutingPolicy {
    pub fn install(
        interface: &str,
        ipv6: Ipv6Addr,
        prefix: u8,
        table: u32,
        priority: u32,
        bypass_uid: u32,
        proxy_addr: SocketAddr,
    ) -> io::Result<Self> {
        require_command("nft", &["--version"])?;
        require_command("ip", &["-V"])?;

        let nft_table = nft_table_name();

        if nft_table_exists(&nft_table)?
            || route_table_exists(table)?
            || rule_priority_exists(priority)?
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "routing policy configuration already exists.",
            ));
        }

        add_ipv6_address(interface, ipv6, prefix)?;

        if let Err(error) = add_default_route(false, interface, table) {
            let _ = Self::cleanup(table, priority, interface, ipv6, prefix, &nft_table);

            return Err(error);
        }

        if let Err(error) = add_default_route(true, interface, table) {
            let _ = Self::cleanup(table, priority, interface, ipv6, prefix, &nft_table);

            return Err(error);
        }

        let script = build_nft_script(&nft_table, bypass_uid, proxy_addr);

        if let Err(error) = run_nft_script(&script) {
            let _ = Self::cleanup(table, priority, interface, ipv6, prefix, &nft_table);

            return Err(error);
        }

        if let Err(error) = add_rule(false, priority, table) {
            let _ = Self::cleanup(table, priority, interface, ipv6, prefix, &nft_table);

            return Err(error);
        }

        if let Err(error) = add_rule(true, priority, table) {
            let _ = Self::cleanup(table, priority, interface, ipv6, prefix, &nft_table);

            return Err(error);
        }

        Ok(Self {
            interface: interface.to_string(),
            table,
            priority,
            nft_table,
            ipv6,
            prefix,
            installed: true,
        })
    }

    fn cleanup(
        table: u32,
        priority: u32,
        interface: &str,
        ipv6: Ipv6Addr,
        prefix: u8,
        nft_table: &str,
    ) -> io::Result<()> {
        let _ = delete_nft_table(nft_table);
        let _ = delete_rule(false, priority);
        let _ = delete_rule(true, priority);
        let _ = delete_default_route(false, interface, table);
        let _ = delete_default_route(true, interface, table);
        let _ = delete_ipv6_address(interface, ipv6, prefix);

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
            self.ipv6,
            self.prefix,
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
                "route", "replace", "default", "dev", interface, "table", &table,
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
            &["route", "del", "default", "dev", interface, "table", &table],
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
        run("ip", &["rule", "del", "pref", &priority])
    }
}

fn delete_nft_table(nft_table: &str) -> io::Result<()> {
    run("nft", &["delete", "table", NFT_FAMILY, nft_table])
}

fn build_nft_script(nft_table: &str, bypass_uid: u32, proxy_addr: SocketAddr) -> String {
    let mut script = String::new();

    script.push_str(&format!("add table {NFT_FAMILY} {nft_table}\n"));

    script.push_str(&format!(
        "add chain {NFT_FAMILY} {nft_table} {NFT_CHAIN} {{ \
         type route hook output priority mangle; policy accept; \
         }}\n"
    ));

    // Never intercept sockets created by the proxy process itself.
    script.push_str(&format!(
        "add rule {NFT_FAMILY} {nft_table} {NFT_CHAIN} \
         meta skuid {bypass_uid} return\n"
    ));

    // Never intercept the TCP connection to the SOCKS5 server.
    match proxy_addr {
        SocketAddr::V4(address) => {
            script.push_str(&format!(
                "add rule {NFT_FAMILY} {nft_table} {NFT_CHAIN} \
                 ip daddr {} tcp dport {} return\n",
                address.ip(),
                address.port(),
            ));
        }

        SocketAddr::V6(address) => {
            script.push_str(&format!(
                "add rule {NFT_FAMILY} {nft_table} {NFT_CHAIN} \
                 ip6 daddr {} tcp dport {} return\n",
                address.ip(),
                address.port(),
            ));
        }
    }

    // This proxy currently handles TCP only.
    // Prevent HTTPS over QUIC/HTTP3 from escaping directly.
    script.push_str(&format!(
        "add rule {NFT_FAMILY} {nft_table} {NFT_CHAIN} \
         udp dport 443 drop\n"
    ));

    // Mark all TCP traffic for policy routing.
    //
    // IMPORTANT:
    // `meta l4proto tcp` is the protocol match.
    // `meta mark set 0x1` is the mark assignment.
    //
    // The `/0x1` mask belongs to the fwmark lookup rule,
    // not to the mark assignment.
    script.push_str(&format!(
        "add rule {NFT_FAMILY} {nft_table} {NFT_CHAIN} \
         meta l4proto tcp meta mark set {POLICY_MARK}\n"
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
        vec!["route", "show", "table", &table]
    };

    let output = Command::new("ip").args(args).output()?;

    if !output.status.success() {
        return Err(io::Error::other(format!(
            "failed to inspect routing table {table}: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok(output.stdout.is_empty())
}

fn rule_exists(ipv6: bool, priority: u32) -> io::Result<bool> {
    let priority = priority.to_string();

    let args = if ipv6 {
        vec!["-6", "rule", "show", "pref", &priority]
    } else {
        vec!["rule", "show", "pref", &priority]
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn test_proxy_addr_v4() -> SocketAddr {
        SocketAddr::from((Ipv4Addr::new(192, 0, 2, 10), 1080))
    }

    fn test_proxy_addr_v6() -> SocketAddr {
        SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10), 1080))
    }

    #[test]
    fn nft_table_name_uses_process_id() {
        assert_eq!(nft_table_name(), format!("tun_{}", std::process::id()));
    }

    #[test]
    fn nft_script_creates_table() {
        let script = build_nft_script("tun_test", 1000, test_proxy_addr_v4());

        assert!(script.contains("add table inet tun_test"));
    }

    #[test]
    fn nft_script_creates_output_chain() {
        let script = build_nft_script("tun_test", 1000, test_proxy_addr_v4());

        assert!(script.contains(
            "add chain inet tun_test output { \
             type route hook output priority mangle; policy accept; \
             }"
        ));
    }

    #[test]
    fn nft_script_bypasses_proxy_uid() {
        let script = build_nft_script("tun_test", 4242, test_proxy_addr_v4());

        assert!(script.contains(
            "add rule inet tun_test output \
             meta skuid 4242 return"
        ));
    }

    #[test]
    fn nft_script_bypasses_ipv4_proxy() {
        let script = build_nft_script("tun_test", 1000, test_proxy_addr_v4());

        assert!(script.contains(
            "add rule inet tun_test output \
             ip daddr 192.0.2.10 tcp dport 1080 return"
        ));
    }

    #[test]
    fn nft_script_bypasses_ipv6_proxy() {
        let script = build_nft_script("tun_test", 1000, test_proxy_addr_v6());

        assert!(script.contains(
            "add rule inet tun_test output \
             ip6 daddr 2001:db8::10 tcp dport 1080 return"
        ));
    }

    #[test]
    fn nft_script_drops_udp_443() {
        let script = build_nft_script("tun_test", 1000, test_proxy_addr_v4());

        assert!(script.contains(
            "add rule inet tun_test output \
             udp dport 443 drop"
        ));
    }

    #[test]
    fn nft_script_marks_tcp() {
        let script = build_nft_script("tun_test", 1000, test_proxy_addr_v4());

        assert!(script.contains(
            "add rule inet tun_test output \
             meta l4proto tcp meta mark set 0x1"
        ));
    }

    #[test]
    fn nft_script_does_not_use_mask_when_setting_mark() {
        let script = build_nft_script("tun_test", 1000, test_proxy_addr_v4());

        assert!(!script.contains("meta mark set 0x1/0x1"));
    }

    #[test]
    fn nft_script_rules_are_ordered() {
        let script = build_nft_script("tun_test", 1000, test_proxy_addr_v4());

        let uid = script.find("meta skuid 1000 return").unwrap();

        let proxy = script
            .find("ip daddr 192.0.2.10 tcp dport 1080 return")
            .unwrap();

        let udp = script.find("udp dport 443 drop").unwrap();

        let mark = script.find("meta l4proto tcp meta mark set 0x1").unwrap();

        assert!(uid < proxy);
        assert!(proxy < udp);
        assert!(udp < mark);
    }

    #[test]
    fn command_ok_succeeds_for_successful_command() {
        assert!(command_ok("true", &[]));
    }

    #[test]
    fn command_ok_fails_for_failed_command() {
        assert!(!command_ok("false", &[]));
    }

    #[test]
    fn command_ok_fails_for_missing_command() {
        assert!(!command_ok("this_command_definitely_does_not_exist", &[],));
    }

    #[test]
    fn require_command_succeeds_for_existing_command() {
        assert!(require_command("true", &[]).is_ok());
    }

    #[test]
    fn require_command_returns_not_found_for_missing_command() {
        let error = require_command("this_command_definitely_does_not_exist", &[]).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn run_succeeds_for_successful_command() {
        assert!(run("true", &[]).is_ok());
    }

    #[test]
    fn run_returns_error_for_failed_command() {
        let error = run("false", &[]).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::Other);

        assert!(error.to_string().contains("false failed"));
    }
}
