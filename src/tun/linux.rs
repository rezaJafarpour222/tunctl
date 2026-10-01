use std::{io, net::UdpSocket, os::fd::AsRawFd};

unsafe extern "C" {
    fn ioctl(fd: i32, request: u64, ...) -> i32;
}

// Maximum size of an interface name on Linux, including the terminating NUL.
const IFNAMSIZ: usize = 16;

// Create/use a TUN device with no Ethernet header.
const IFF_TUN: u16 = 0x0001;

// Disable the extra packet-information header.
const IFF_NO_PI: u16 = 0x1000;

// Bring the network interface administratively up.
const IFF_UP: i16 = 0x0001;

// Linux TUNSETIFF ioctl request.
const TUNSETIFF: u64 = 0x4004_54CA;

// Get interface flags.
const SIOCGIFFLAGS: u64 = 0x8913;

// Set interface flags.
const SIOCSIFFLAGS: u64 = 0x8914;

// Represent the union part of Linux struct ifreq.
#[repr(C)]
union IfReqData {
    flags: i16,
    _raw: [u64; 3],
}

// Represent Linux struct ifreq.
#[repr(C)]
struct IfReq {
    name: [u8; IFNAMSIZ],
    data: IfReqData,
}

impl IfReq {
    fn new(name: &str) -> io::Result<Self> {
        let name = name.as_bytes();

        if name.len() >= IFNAMSIZ {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface name must be at most 15 bytes",
            ));
        }

        let mut ifreq = Self {
            name: [0; IFNAMSIZ],
            data: IfReqData {
                flags: (IFF_TUN | IFF_NO_PI) as i16,
            },
        };

        ifreq.name[..name.len()].copy_from_slice(name);

        Ok(ifreq)
    }
}

fn new_tun_file_descriptor() -> io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")
}

fn set_interface_up(name: &str) -> io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    let fd = socket.as_raw_fd();

    let mut ifreq = IfReq::new(name)?;

    let result = unsafe { ioctl(fd, SIOCGIFFLAGS, &mut ifreq as *mut IfReq) };

    if result < 0 {
        return Err(io::Error::last_os_error());
    }

    let flags = unsafe { ifreq.data.flags };

    if flags & IFF_UP != 0 {
        return Ok(());
    }

    ifreq.data.flags = flags | IFF_UP;

    let result = unsafe { ioctl(fd, SIOCSIFFLAGS, &mut ifreq as *mut IfReq) };

    if result < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

pub fn create_tun(name: &str) -> io::Result<std::fs::File> {
    let tun_fd = new_tun_file_descriptor()?;
    let mut ifreq = IfReq::new(name)?;

    let result = unsafe { ioctl(tun_fd.as_raw_fd(), TUNSETIFF, &mut ifreq as *mut IfReq) };

    if result < 0 {
        return Err(io::Error::last_os_error());
    }

    set_interface_up(name)?;

    Ok(tun_fd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    #[test]
    fn ifreq_data_has_expected_size() {
        assert_eq!(size_of::<IfReqData>(), 24);
    }

    #[test]
    fn ifreq_has_expected_size() {
        assert_eq!(size_of::<IfReq>(), 40);
    }

    #[test]
    fn creates_ifreq_with_correct_name() {
        let ifreq = IfReq::new("tun0").unwrap();

        assert_eq!(&ifreq.name[..4], b"tun0");
        assert_eq!(ifreq.name[4], 0);
        assert_eq!(ifreq.name[15], 0);
    }

    #[test]
    fn creates_ifreq_with_correct_flags() {
        let ifreq = IfReq::new("tun0").unwrap();

        let expected = (IFF_TUN | IFF_NO_PI) as i16;
        let actual = unsafe { ifreq.data.flags };

        assert_eq!(actual, expected);
    }

    #[test]
    fn accepts_15_byte_interface_name() {
        let name = "abcdefghijklmno";

        assert_eq!(name.len(), 15);

        let ifreq = IfReq::new(name).unwrap();

        assert_eq!(&ifreq.name[..15], name.as_bytes());
        assert_eq!(ifreq.name[15], 0);
    }

    #[test]
    fn rejects_16_byte_interface_name() {
        let name = "abcdefghijklmnop";

        assert_eq!(name.len(), 16);

        let result = IfReq::new(name);

        assert!(matches!(
            result,
            Err(error) if error.kind() == io::ErrorKind::InvalidInput
        ));
    }
}
