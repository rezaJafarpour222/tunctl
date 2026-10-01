use std::{
    fs::File,
    io::{self, Read, Write},
};

use crate::tun::linux::create_tun;

pub struct Device {
    name: String,
    tun: File,
}

impl Device {
    pub fn new(name: &str) -> io::Result<Self> {
        let tun = create_tun(name)?;

        Ok(Self {
            name: name.to_owned(),
            tun,
        })
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
}
