use libc::{c_int, size_t};
use std::collections::HashMap;
use std::os::raw::c_void;
use std::sync::Mutex;

pub const ETH_ALEN: usize = 6;
pub const ETH_HEADER_LEN: usize = 14;
pub const IPV4_HEADER_LEN: usize = 20;
pub const IPV6_HEADER_LEN: usize = 40;
pub const ETHARP_HEADER_LEN: usize = 28;

pub const ETH_P_IPV4: u16 = 0x0800;
pub const ETH_P_ARP: u16 = 0x0806;
pub const ETH_P_IPV6: u16 = 0x86DD;

pub const ETH_ARPOP_REQUEST: u16 = 1;
pub const ETH_ARPOP_REPLY: u16 = 2;

pub const IPV6_P_ICMP: u8 = 58;
pub const IP6_ICMP_NEIGH_SOLICIT: u8 = 135;
pub const IP6_ICMP_NEIGH_ADVERT: u8 = 136;

pub const NEM_BROADCAST_MAC_ADDRESS: u16 = 65535;

pub struct EthernetTransportState {
    pub mac_cache: Mutex<HashMap<[u8; 6], u16>>,
}

impl Default for EthernetTransportState {
    fn default() -> Self {
        Self::new()
    }
}

impl EthernetTransportState {
    pub fn new() -> Self {
        Self {
            mac_cache: Mutex::new(HashMap::new()),
        }
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_ethernet_transport_new() -> *mut EthernetTransportState {
    Box::into_raw(Box::new(EthernetTransportState::new()))
}

#[no_mangle]
pub extern "C" fn emane_rs_ethernet_transport_free(state: *mut EthernetTransportState) {
    if !state.is_null() {
        unsafe {
            drop(Box::from_raw(state));
        }
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_ethernet_transport_verify_frame(
    buf: *const c_void,
    len: size_t,
) -> c_int {
    if buf.is_null() || len < ETH_HEADER_LEN {
        return -1;
    }

    let buf_slice = unsafe { std::slice::from_raw_parts(buf as *const u8, len) };
    let eth_protocol = u16::from_be_bytes([buf_slice[12], buf_slice[13]]);
    let payload_len = len - ETH_HEADER_LEN;

    match eth_protocol {
        ETH_P_IPV4 => {
            if payload_len < IPV4_HEADER_LEN {
                -1
            } else {
                0
            }
        }
        ETH_P_IPV6 => {
            if payload_len < IPV6_HEADER_LEN {
                -1
            } else {
                0
            }
        }
        ETH_P_ARP => {
            if payload_len < ETHARP_HEADER_LEN {
                -1
            } else {
                0
            }
        }
        _ => 1,
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_ethernet_transport_add_entry(
    state_ptr: *const EthernetTransportState,
    mac_bytes: *const u8,
    nem_id: u16,
) {
    if state_ptr.is_null() || mac_bytes.is_null() {
        return;
    }
    let state = unsafe { &*state_ptr };
    let mac: [u8; 6] = unsafe { std::slice::from_raw_parts(mac_bytes, 6) }
        .try_into()
        .unwrap();

    if let Ok(mut cache) = state.mac_cache.lock() {
        cache.insert(mac, nem_id);
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_ethernet_transport_lookup_arp_cache(
    state_ptr: *const EthernetTransportState,
    mac_bytes: *const u8,
    found_nem: *mut u16,
) -> bool {
    if state_ptr.is_null() || mac_bytes.is_null() || found_nem.is_null() {
        return false;
    }
    let state = unsafe { &*state_ptr };
    let mac: [u8; 6] = unsafe { std::slice::from_raw_parts(mac_bytes, 6) }
        .try_into()
        .unwrap();

    if let Ok(cache) = state.mac_cache.lock() {
        if let Some(nem_id) = cache.get(&mac) {
            unsafe {
                *found_nem = *nem_id;
            }
            return true;
        }
    }
    false
}

// To support C++'s map `unknownEtherTypePriorityMap_`, we can pass a C callback to query it.
#[no_mangle]
pub extern "C" fn emane_rs_ethernet_transport_parse_frame(
    state_ptr: *const EthernetTransportState,
    buf: *const c_void,
    len: size_t,
    broadcast_mode: bool,
    arp_cache_mode: bool,
    eth_type_arp_priority: u8,
    cpp_obj: *const c_void,
    query_unknown_cb: extern "C" fn(*const c_void, u16, *mut u8) -> bool,
    nem_dest: *mut u16,
    dscp: *mut u8,
) -> c_int {
    if state_ptr.is_null()
        || buf.is_null()
        || nem_dest.is_null()
        || dscp.is_null()
        || len < ETH_HEADER_LEN
    {
        return -1;
    }

    let state = unsafe { &*state_ptr };
    let buf_slice = unsafe { std::slice::from_raw_parts(buf as *const u8, len) };

    let dest_mac: [u8; 6] = buf_slice[0..6].try_into().unwrap();
    let eth_protocol = u16::from_be_bytes([buf_slice[12], buf_slice[13]]);

    let resolve_nem = || -> u16 {
        if broadcast_mode
            || (eth_protocol == ETH_P_IPV4 && dest_mac[..3] == [0x01, 0x00, 0x5e])
            || (eth_protocol == ETH_P_IPV6 && dest_mac[..2] == [0x33, 0x33])
        {
            NEM_BROADCAST_MAC_ADDRESS
        } else if arp_cache_mode {
            if let Ok(cache) = state.mac_cache.lock() {
                if let Some(nem_id) = cache.get(&dest_mac) {
                    return *nem_id;
                }
            }
            NEM_BROADCAST_MAC_ADDRESS
        } else {
            u16::from_be_bytes([dest_mac[4], dest_mac[5]])
        }
    };

    match eth_protocol {
        ETH_P_IPV4 => {
            unsafe {
                *nem_dest = resolve_nem();
                if len >= ETH_HEADER_LEN + IPV4_HEADER_LEN {
                    let tos = buf_slice[ETH_HEADER_LEN + 1];
                    *dscp = tos >> 2;
                } else {
                    *dscp = 0;
                }
            }
            0
        }
        ETH_P_IPV6 => {
            unsafe {
                *nem_dest = resolve_nem();
                if len >= ETH_HEADER_LEN + IPV6_HEADER_LEN {
                    let tc1 = buf_slice[ETH_HEADER_LEN] & 0x0F;
                    let tc2 = buf_slice[ETH_HEADER_LEN + 1] & 0xF0;
                    let tc = (tc1 << 4) | (tc2 >> 4);
                    *dscp = tc >> 2;
                } else {
                    *dscp = 0;
                }
            }
            0
        }
        ETH_P_ARP => {
            unsafe {
                *nem_dest = resolve_nem();
                *dscp = eth_type_arp_priority;
            }
            0
        }
        _ => {
            unsafe {
                if broadcast_mode {
                    *nem_dest = NEM_BROADCAST_MAC_ADDRESS;
                } else if arp_cache_mode {
                    if let Ok(cache) = state.mac_cache.lock() {
                        if let Some(nem_id) = cache.get(&dest_mac) {
                            *nem_dest = *nem_id;
                        } else {
                            *nem_dest = NEM_BROADCAST_MAC_ADDRESS;
                        }
                    } else {
                        *nem_dest = NEM_BROADCAST_MAC_ADDRESS;
                    }
                } else {
                    *nem_dest = u16::from_be_bytes([dest_mac[4], dest_mac[5]]);
                }

                let mut prio = 0;
                if query_unknown_cb(cpp_obj, eth_protocol, &mut prio) {
                    *dscp = prio;
                } else {
                    *dscp = 0;
                }
            }
            1
        }
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_ethernet_transport_update_arp_cache(
    state_ptr: *const EthernetTransportState,
    buf: *const c_void,
    len: size_t,
    nem_id: u16,
    broadcast_mode: bool,
    arp_cache_mode: bool,
) {
    if state_ptr.is_null() || buf.is_null() || len < ETH_HEADER_LEN {
        return;
    }

    if broadcast_mode || !arp_cache_mode {
        return;
    }

    let state = unsafe { &*state_ptr };
    let buf_slice = unsafe { std::slice::from_raw_parts(buf as *const u8, len) };
    let src_mac: [u8; 6] = buf_slice[6..12].try_into().unwrap();
    let eth_protocol = u16::from_be_bytes([buf_slice[12], buf_slice[13]]);

    match eth_protocol {
        ETH_P_ARP => {
            if len >= ETH_HEADER_LEN + ETHARP_HEADER_LEN {
                let arp_op = u16::from_be_bytes([
                    buf_slice[ETH_HEADER_LEN + 6],
                    buf_slice[ETH_HEADER_LEN + 7],
                ]);
                if arp_op == ETH_ARPOP_REPLY || arp_op == ETH_ARPOP_REQUEST {
                    let sender_mac: [u8; 6] = buf_slice[ETH_HEADER_LEN + 8..ETH_HEADER_LEN + 14]
                        .try_into()
                        .unwrap();
                    if let Ok(mut cache) = state.mac_cache.lock() {
                        cache.insert(sender_mac, nem_id);
                    }
                }
            }
        }
        ETH_P_IPV6 if len >= ETH_HEADER_LEN + IPV6_HEADER_LEN + 8 => {
            // +8 for ICMPv6 min
            let next_header = buf_slice[ETH_HEADER_LEN + 6];
            if next_header == IPV6_P_ICMP {
                let icmp_type = buf_slice[ETH_HEADER_LEN + IPV6_HEADER_LEN];
                if icmp_type == IP6_ICMP_NEIGH_SOLICIT || icmp_type == IP6_ICMP_NEIGH_ADVERT {
                    if let Ok(mut cache) = state.mac_cache.lock() {
                        cache.insert(src_mac, nem_id);
                    }
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod multicast_regressions {
    use super::*;
    extern "C" fn unknown(_: *const c_void, _: u16, _: *mut u8) -> bool {
        false
    }
    #[test]
    fn no_arp_cache_multicast_uses_broadcast_nem() {
        let state = EthernetTransportState::new();
        for (mac, proto, expected) in [
            ([1, 0, 0x5e, 0, 0, 1], ETH_P_IPV4, u16::MAX),
            ([0x33, 0x33, 0, 0, 0, 1], ETH_P_IPV6, u16::MAX),
            ([2, 2, 0, 0, 0, 7], ETH_P_IPV4, 7),
        ] {
            let mut frame = [0; 64];
            frame[..6].copy_from_slice(&mac);
            frame[12..14].copy_from_slice(&proto.to_be_bytes());
            let (mut destination, mut priority) = (0, 0);
            assert_eq!(
                emane_rs_ethernet_transport_parse_frame(
                    &state,
                    frame.as_ptr().cast(),
                    frame.len(),
                    false,
                    false,
                    0,
                    std::ptr::null(),
                    unknown,
                    &mut destination,
                    &mut priority
                ),
                0
            );
            assert_eq!(destination, expected);
        }
    }
}
