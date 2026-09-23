use std::{
    fs::File,
    io::{self, Read, Write},
};

use crate::tun::linux::create_tun;

pub struct Device {
    tun: File,
}
impl Device {
    pub fn new(name: &str) -> io::Result<Self> {
        let tun = create_tun(name)?;
        Ok(Self { tun })
    }
    pub fn recv(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.tun.read(buffer)
    }
    pub fn send_all(&mut self, packet: &[u8]) -> io::Result<()> {
        self.tun.write_all(packet)
    }
}
