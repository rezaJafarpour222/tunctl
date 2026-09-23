use std::{
    io::{self, Read},
    os::fd::AsRawFd,
};

use tun::tun::linux::create_tun;

fn main() -> io::Result<()> {
    let mut tun = create_tun("tun0")?;

    println!("created tun0");
    println!("fd = {}", tun.as_raw_fd());

    let mut packet = [0u8; 1500];

    loop {
        let n = tun.read(&mut packet)?;

        if n == 0 {
            continue;
        }

        let version = packet[0] >> 4;

        match version {
            4 => println!("IPv4 packet: {n} bytes"),
            6 => println!("IPv6 packet: {n} bytes"),
            version => println!("Unknown IP version: {version}"),
        }
    }
}
