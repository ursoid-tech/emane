use libc::{ifreq, IFF_NOARP, IFF_NO_PI, IFF_TAP, IFF_UP};
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

// TUNSETIFF is 0x400454ca on Linux
const TUNSETIFF: u64 = 0x400454ca;
const SIOCGIFINDEX: u64 = 0x8933;
const SIOCSIFHWADDR: u64 = 0x8924;
const SIOCGIFFLAGS: u64 = 0x8913;
const SIOCSIFFLAGS: u64 = 0x8914;

pub struct TunTap {
    pub fd: RawFd,
    pub name: String,
    pub index: i32,
}

impl TunTap {
    pub fn new(path: &str, name: &str) -> std::io::Result<Self> {
        let path_c = std::ffi::CString::new(path).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "device path contains NUL")
        })?;
        let fd = unsafe { libc::open(path_c.as_ptr(), libc::O_RDWR) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }

        let mut ifr: ifreq = unsafe { std::mem::zeroed() };
        let name_bytes = name.as_bytes();
        let len = std::cmp::min(name_bytes.len(), 15);
        for (index, byte) in name_bytes.iter().copied().enumerate().take(len) {
            ifr.ifr_name[index] = byte as libc::c_char;
        }
        ifr.ifr_ifru.ifru_flags = (IFF_NO_PI | IFF_TAP) as libc::c_short;

        if unsafe { libc::ioctl(fd, TUNSETIFF, &mut ifr) } < 0 {
            let err = std::io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(err);
        }

        let ctrl_sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if ctrl_sock < 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err);
        }
        if unsafe { libc::ioctl(ctrl_sock, SIOCGIFINDEX, &mut ifr) } < 0 {
            let err = std::io::Error::last_os_error();
            unsafe {
                libc::close(ctrl_sock);
                libc::close(fd);
            }
            return Err(err);
        }
        let index = unsafe { ifr.ifr_ifru.ifru_ifindex };
        unsafe {
            libc::close(ctrl_sock);
        }

        Ok(Self {
            fd,
            name: name.to_string(),
            index,
        })
    }

    pub fn activate(&self, arp_enabled: bool) -> std::io::Result<()> {
        let mut flags = IFF_UP;
        if !arp_enabled {
            flags |= IFF_NOARP;
        }
        self.set_flags(flags, 1)
    }

    pub fn deactivate(&self) -> std::io::Result<()> {
        self.set_flags(IFF_UP, -1)
    }

    pub fn set_addr(&self, address: IpAddr, mask: IpAddr) -> std::io::Result<()> {
        let family = if address.is_ipv4() {
            libc::AF_INET
        } else {
            libc::AF_INET6
        };
        let fd = unsafe { libc::socket(family, libc::SOCK_DGRAM, 0) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let socket = unsafe { OwnedFd::from_raw_fd(fd) };
        match (address, mask) {
            (IpAddr::V4(address), mask) => {
                // The original reads the IPv4 mask from sockaddr offset 4.
                // For an IPv6 configuration value this is its zero flowinfo.
                let mask = match mask {
                    IpAddr::V4(mask) => mask,
                    IpAddr::V6(_) => std::net::Ipv4Addr::UNSPECIFIED,
                };
                for (request, value) in [(libc::SIOCSIFADDR, address), (libc::SIOCSIFNETMASK, mask)]
                {
                    let mut ifr: ifreq = unsafe { std::mem::zeroed() };
                    for (index, byte) in self.name.bytes().take(libc::IFNAMSIZ - 1).enumerate() {
                        ifr.ifr_name[index] = byte as libc::c_char;
                    }
                    let mut sockaddr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
                    sockaddr.sin_family = libc::AF_INET as libc::sa_family_t;
                    sockaddr.sin_addr.s_addr = u32::from_ne_bytes(value.octets());
                    // Linux ifreq stores sockaddr_in in its sockaddr union member.
                    ifr.ifr_ifru.ifru_addr = unsafe {
                        std::mem::transmute::<libc::sockaddr_in, libc::sockaddr>(sockaddr)
                    };
                    if unsafe { libc::ioctl(socket.as_raw_fd(), request, &ifr) } < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
            }
            (IpAddr::V6(address), IpAddr::V6(mask)) => {
                #[repr(C)]
                struct In6Ifreq {
                    address: libc::in6_addr,
                    prefix_len: u32,
                    index: i32,
                }
                // Match the original get_prefixlen, including noncontiguous masks:
                // count full bytes, then through the final set bit of the next byte.
                let mut prefix_len = 0;
                for byte in mask.octets() {
                    if byte == 255 {
                        prefix_len += 8;
                    } else {
                        if byte != 0 {
                            prefix_len += 8 - byte.trailing_zeros();
                        }
                        break;
                    }
                }
                let request = In6Ifreq {
                    address: libc::in6_addr {
                        s6_addr: address.octets(),
                    },
                    prefix_len,
                    index: self.index,
                };
                if unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCSIFADDR, &request) } < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "address and mask families differ",
                ))
            }
        }
        Ok(())
    }

    fn get_flags(&self) -> std::io::Result<i32> {
        let ctrl_sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if ctrl_sock < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut ifr: ifreq = unsafe { std::mem::zeroed() };
        let name_bytes = self.name.as_bytes();
        let len = std::cmp::min(name_bytes.len(), 15);
        for (index, byte) in name_bytes.iter().copied().enumerate().take(len) {
            ifr.ifr_name[index] = byte as libc::c_char;
        }
        if unsafe { libc::ioctl(ctrl_sock, SIOCGIFFLAGS, &mut ifr) } < 0 {
            let err = std::io::Error::last_os_error();
            unsafe {
                libc::close(ctrl_sock);
            }
            return Err(err);
        }
        unsafe {
            libc::close(ctrl_sock);
        }
        Ok(unsafe { ifr.ifr_ifru.ifru_flags } as i32)
    }

    fn set_flags(&self, newflags: i32, cmd: i32) -> std::io::Result<()> {
        let ctrl_sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if ctrl_sock < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut ifr: ifreq = unsafe { std::mem::zeroed() };
        let name_bytes = self.name.as_bytes();
        let len = std::cmp::min(name_bytes.len(), 15);
        for (index, byte) in name_bytes.iter().copied().enumerate().take(len) {
            ifr.ifr_name[index] = byte as libc::c_char;
        }
        let current_flags = match self.get_flags() {
            Ok(flags) => flags,
            Err(error) => {
                unsafe { libc::close(ctrl_sock) };
                return Err(error);
            }
        };
        ifr.ifr_ifru.ifru_flags = if cmd > 0 {
            (current_flags | newflags) as libc::c_short
        } else if cmd < 0 {
            (current_flags & !newflags) as libc::c_short
        } else {
            newflags as libc::c_short
        };

        if unsafe { libc::ioctl(ctrl_sock, SIOCSIFFLAGS, &ifr) } < 0 {
            let err = std::io::Error::last_os_error();
            unsafe {
                libc::close(ctrl_sock);
            }
            return Err(err);
        }
        unsafe {
            libc::close(ctrl_sock);
        }
        Ok(())
    }

    pub fn set_ethaddr(&self, id: u16) -> std::io::Result<()> {
        let mut ifr: ifreq = unsafe { std::mem::zeroed() };
        let name_bytes = self.name.as_bytes();
        let len = std::cmp::min(name_bytes.len(), 15);
        for (index, byte) in name_bytes.iter().copied().enumerate().take(len) {
            ifr.ifr_name[index] = byte as libc::c_char;
        }

        let mut hwaddr = [0u8; 14];
        hwaddr[0] = 0x02;
        hwaddr[1] = 0x02;
        hwaddr[2] = 0x00;
        hwaddr[3] = 0x00;
        hwaddr[4] = (id >> 8) as u8;
        hwaddr[5] = (id & 0xFF) as u8;

        unsafe {
            ifr.ifr_ifru.ifru_hwaddr.sa_family = 1; // ARPHRD_ETHER
            for (index, byte) in hwaddr.iter().copied().enumerate() {
                ifr.ifr_ifru.ifru_hwaddr.sa_data[index] = byte as libc::c_char;
            }
        }

        let ctrl_sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if ctrl_sock < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if unsafe { libc::ioctl(ctrl_sock, SIOCSIFHWADDR, &ifr) } < 0 {
            let err = std::io::Error::last_os_error();
            unsafe {
                libc::close(ctrl_sock);
            }
            return Err(err);
        }
        unsafe {
            libc::close(ctrl_sock);
        }
        Ok(())
    }
}

impl Drop for TunTap {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_tuntap_new_ffi(
    path: *const libc::c_char,
    name: *const libc::c_char,
) -> *mut TunTap {
    if path.is_null() || name.is_null() {
        return std::ptr::null_mut();
    }
    let Ok(p) = (unsafe { std::ffi::CStr::from_ptr(path) }).to_str() else {
        return std::ptr::null_mut();
    };
    let Ok(n) = (unsafe { std::ffi::CStr::from_ptr(name) }).to_str() else {
        return std::ptr::null_mut();
    };
    match TunTap::new(p, n) {
        Ok(t) => Box::into_raw(Box::new(t)),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_tuntap_free_ffi(ptr: *mut TunTap) {
    if !ptr.is_null() {
        unsafe {
            let _ = Box::from_raw(ptr);
        }
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_tuntap_activate_ffi(ptr: *mut TunTap, arp_enabled: bool) -> libc::c_int {
    if ptr.is_null() {
        return -1;
    }
    let tt = unsafe { &*ptr };
    match tt.activate(arp_enabled) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_tuntap_deactivate_ffi(ptr: *mut TunTap) -> libc::c_int {
    if ptr.is_null() {
        return -1;
    }
    let tt = unsafe { &*ptr };
    match tt.deactivate() {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_tuntap_get_handle_ffi(ptr: *mut TunTap) -> libc::c_int {
    if ptr.is_null() {
        return -1;
    }
    let tt = unsafe { &*ptr };
    tt.fd
}

#[no_mangle]
pub extern "C" fn emane_rs_tuntap_set_ethaddr_ffi(ptr: *mut TunTap, id: u16) -> libc::c_int {
    if ptr.is_null() {
        return -1;
    }
    let tt = unsafe { &*ptr };
    match tt.set_ethaddr(id) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_tuntap_readv_ffi(
    ptr: *mut TunTap,
    iov: *mut libc::iovec,
    iov_len: libc::size_t,
) -> libc::c_int {
    if ptr.is_null() || (iov_len != 0 && iov.is_null()) {
        return -1;
    }
    let tt = unsafe { &*ptr };
    unsafe { libc::readv(tt.fd, iov, iov_len as libc::c_int) as libc::c_int }
}

#[no_mangle]
pub extern "C" fn emane_rs_tuntap_writev_ffi(
    ptr: *mut TunTap,
    iov: *const libc::iovec,
    iov_len: libc::size_t,
) -> libc::c_int {
    if ptr.is_null() || (iov_len != 0 && iov.is_null()) {
        return -1;
    }
    let tt = unsafe { &*ptr };
    unsafe { libc::writev(tt.fd, iov, iov_len as libc::c_int) as libc::c_int }
}
