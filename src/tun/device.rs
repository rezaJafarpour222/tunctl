use std::{
    fs::File,
    io::{self, Read, Write},
    process::{Command, Stdio},
};

use crate::tun::linux::create_tun;

const RP_FILTER_DISABLED: u8 = 0;
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

        device.set_rp_filter(RP_FILTER_DISABLED)?;

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

        let path = format!("/proc/sys/net/ipv4/conf/{}/rp_filter", self.name);

        let before = read_rp_filter(&path)?;

        std::fs::write(&path, value.to_string())?;

        let after = read_rp_filter(&path)?;

        if after != value {
            return Err(io::Error::other(format!(
                "failed to set rp_filter for {}: \
                 expected {}, got {}",
                self.name, value, after
            )));
        }

        eprintln!("TUN rp_filter: {before} -> {after}");

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
