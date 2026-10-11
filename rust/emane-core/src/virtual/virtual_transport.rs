use crate::r#virtual::tuntap::TunTap;
use libc::{c_void, iovec, readv, writev};
use std::ffi::CStr;
use std::os::raw::c_char;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;

unsafe impl Send for VirtualTransport {}
unsafe impl Sync for VirtualTransport {}
pub struct VirtualTransport {
    id: u16,
    address: Option<(std::net::IpAddr, std::net::IpAddr)>,
    tun_tap: Option<Arc<TunTap>>,
    thread: Option<thread::JoinHandle<()>>,
    canceled: Arc<AtomicBool>,
    cpp_obj: *mut c_void,
    cb: extern "C" fn(*mut c_void, *const u8, usize),
}

#[no_mangle]
pub extern "C" fn emane_rs_virtual_transport_new(
    id: u16,
    cpp_obj: *mut c_void,
    cb: extern "C" fn(*mut c_void, *const u8, usize),
) -> *mut VirtualTransport {
    let vt = Box::new(VirtualTransport {
        id,
        address: None,
        tun_tap: None,
        thread: None,
        canceled: Arc::new(AtomicBool::new(false)),
        cpp_obj,
        cb,
    });
    Box::into_raw(vt)
}

#[no_mangle]
pub extern "C" fn emane_rs_virtual_transport_free(ptr: *mut VirtualTransport) {
    if !ptr.is_null() {
        unsafe {
            let mut vt = Box::from_raw(ptr);
            vt.stop();
        }
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_virtual_transport_start(
    ptr: *mut VirtualTransport,
    device_path: *const c_char,
    device_name: *const c_char,
    arp_mode: bool,
) -> i32 {
    if ptr.is_null() || device_path.is_null() || device_name.is_null() {
        return -1;
    }
    let vt = unsafe { &mut *ptr };
    if vt.thread.is_some() {
        return -1;
    }
    let Ok(path) = (unsafe { CStr::from_ptr(device_path) }).to_str() else {
        return -1;
    };
    let Ok(name) = (unsafe { CStr::from_ptr(device_name) }).to_str() else {
        return -1;
    };

    match TunTap::new(path, name) {
        Ok(tun) => {
            if tun.set_ethaddr(vt.id).is_err() {
                return -1;
            }
            if tun.activate(arp_mode).is_err() {
                return -1;
            }
            if let Some((address, mask)) = vt.address {
                if !address.is_unspecified() && tun.set_addr(address, mask).is_err() {
                    return -1;
                }
            }
            vt.canceled.store(false, Ordering::SeqCst);
            let tun_arc = Arc::new(tun);
            vt.tun_tap = Some(tun_arc.clone());

            let canceled = vt.canceled.clone();
            let cpp_obj_usize = vt.cpp_obj as usize;
            let cb = vt.cb;

            vt.thread = Some(thread::spawn(move || {
                let mut buf = [0u8; 65535];
                while !canceled.load(Ordering::SeqCst) {
                    let mut descriptor = libc::pollfd {
                        fd: tun_arc.fd,
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    let ready = unsafe { libc::poll(&mut descriptor, 1, 100) };
                    if ready == 0 {
                        continue;
                    }
                    if ready < 0 || descriptor.revents & libc::POLLIN == 0 {
                        break;
                    }
                    let iov = iovec {
                        iov_base: buf.as_mut_ptr() as *mut c_void,
                        iov_len: buf.len(),
                    };
                    let len = unsafe { readv(tun_arc.fd, &iov, 1) };
                    if len > 0 {
                        let cpp_obj = cpp_obj_usize as *mut c_void;
                        cb(cpp_obj, buf.as_ptr(), len as usize);
                    } else if len < 0 {
                        break;
                    }
                }
            }));

            0
        }
        Err(_) => -1,
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_virtual_transport_stop(ptr: *mut VirtualTransport) {
    if ptr.is_null() {
        return;
    }
    let vt = unsafe { &mut *ptr };
    vt.stop();
}

impl VirtualTransport {
    pub fn set_address(&mut self, address: std::net::IpAddr, mask: std::net::IpAddr) {
        self.address = Some((address, mask));
    }

    fn stop(&mut self) {
        self.canceled.store(true, Ordering::SeqCst);
        if let Some(tun) = &self.tun_tap {
            let _ = tun.deactivate();
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        self.tun_tap.take();
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_virtual_transport_process_upstream_packet(
    ptr: *mut VirtualTransport,
    buf: *const u8,
    len: usize,
) -> i32 {
    if ptr.is_null() || (len != 0 && buf.is_null()) {
        return -1;
    }
    let vt = unsafe { &*ptr };
    if let Some(tun) = &vt.tun_tap {
        let iov = iovec {
            iov_base: buf as *const _ as *mut c_void,
            iov_len: len,
        };
        let ret = unsafe { writev(tun.fd, &iov, 1) };
        if ret < 0 || usize::try_from(ret).ok() != Some(len) {
            return -1;
        }
        return 0;
    }
    -1
}
