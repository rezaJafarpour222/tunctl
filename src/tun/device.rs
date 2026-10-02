use std::{
    fs::File,
    io::{self, Read, Write},
    process::{Command, Stdio},
};

use crate::tun::linux::create_tun;

const RP_FILTER_MODE: u8 = 2;
const UDEV_SETTLE_TIMEOUT_SECONDS: &str = "5";

pub struct Device {
    name: String,
    tun: File,
}

impl Device {
    pub fn new(name: &str) -> io::Result<Self> {
        let tun = create_tun(name)?;

        wait_for_udev()?;

        let device = Self {
            name: name.to_owned(),
            tun,
        };

        device.set_rp_filter(RP_FILTER_MODE)?;

        Ok(device)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            name: self.name.clone(),
            tun: self.tun.try_clone()?,
        })
    }

    pub fn recv(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.tun.read(buffer)
    }

    pub fn send_all(&mut self, packet: &[u8]) -> io::Result<()> {
        self.tun.write_all(packet)
    }

    fn set_rp_filter(&self, value: u8) -> io::Result<()> {
        if value > 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid rp_filter value: {value}"),
            ));
        }

        let interface_path = format!("/proc/sys/net/ipv4/conf/{}/rp_filter", self.name);

        let all_path = "/proc/sys/net/ipv4/conf/all/rp_filter";

        let before_interface = read_rp_filter(&interface_path)?;
        let before_all = read_rp_filter(all_path)?;

        std::fs::write(&interface_path, value.to_string())?;

        let after_interface = read_rp_filter(&interface_path)?;
        let after_all = read_rp_filter(all_path)?;

        if after_interface != value {
            return Err(io::Error::other(format!(
                "failed to set rp_filter for {}: expected {}, got {}",
                self.name, value, after_interface
            )));
        }

        let effective = after_all.max(after_interface);

        eprintln!("TUN rp_filter: {} -> {}", before_interface, after_interface);

        Ok(())
    }
}

fn wait_for_udev() -> io::Result<()> {
    let output = Command::new("udevadm")
        .args(["settle", "--timeout", UDEV_SETTLE_TIMEOUT_SECONDS])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()?;

    if output.status.success() {
        return Ok(());
    }

    Err(io::Error::other(format!(
        "udevadm settle failed: {}",
        String::from_utf8_lossy(&output.stderr)
    )))
}

fn read_rp_filter(path: &str) -> io::Result<u8> {
    std::fs::read_to_string(path)?
        .trim()
        .parse::<u8>()
        .map_err(|error| io::Error::other(format!("invalid rp_filter value in {path}: {error}")))
}
