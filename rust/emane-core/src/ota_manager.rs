use prost::Message;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::{BTreeMap, HashMap};
use std::ffi::CStr;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::os::raw::{c_char, c_void};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime};

use crate::application_runtime::format_uuid;
use crate::common::multicast;
use crate::statistics::{
    increment_native_counter, native_table_generation, register_native_counter,
    register_native_table, set_native_table_row, NativeTableValue,
};

pub use crate::protobufs::emane_message as ota;

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
struct PartInfo {
    u8_more: u8,
    u32_offset: u32,
    u32_size: u32,
}

#[derive(Hash, Eq, PartialEq, Clone, Copy)]
struct PartKey {
    uuid: [u8; 16],
    source: u16,
    sequence: u64,
}

struct PartsData {
    has_info: bool,
    end_offset: Option<usize>,
    total_size: usize,
    events_size: usize,
    controls_size: usize,
    data_size: usize,
    parts: BTreeMap<usize, Vec<u8>>,
    last_part_time: SystemTime,
    uuid: [u8; 16],
}

impl PartsData {
    /// Continuations may precede offset zero and omit PayloadInfo (the C++ format).
    fn insert(
        &mut self,
        info: Option<&ota::ota_header::PayloadInfo>,
        offset: usize,
        more: bool,
        bytes: &[u8],
        now: SystemTime,
    ) -> Result<Option<Vec<u8>>, ()> {
        let end = offset.checked_add(bytes.len()).ok_or(())?;
        if bytes.is_empty() || end > MAX_OTA_PAYLOAD {
            return Err(());
        }
        if let Some(info) = info {
            let sizes = (
                info.event_length as usize,
                info.control_length as usize,
                info.data_length as usize,
            );
            if self.has_info && sizes != (self.events_size, self.controls_size, self.data_size) {
                return Err(());
            }
            (self.events_size, self.controls_size, self.data_size) = sizes;
            self.has_info = true;
        }
        if !more {
            if self.end_offset.is_some_and(|previous| previous != end) {
                return Err(());
            }
            self.end_offset = Some(end);
        }
        if let Some(previous) = self.parts.get(&offset) {
            if previous != bytes {
                return Err(());
            }
        } else {
            // Reject overlaps, but accept identical retransmissions without double counting.
            if self
                .parts
                .iter()
                .any(|(start, part)| *start < end && start + part.len() > offset)
            {
                return Err(());
            }
            self.total_size = self.total_size.checked_add(bytes.len()).ok_or(())?;
            if self.total_size > MAX_OTA_PAYLOAD {
                return Err(());
            }
            self.parts.insert(offset, bytes.to_vec());
        }
        self.last_part_time = now;
        if !self.has_info {
            return Ok(None);
        }
        let total = self
            .events_size
            .checked_add(self.controls_size)
            .and_then(|n| n.checked_add(self.data_size))
            .ok_or(())?;
        if total > MAX_OTA_PAYLOAD
            || self.end_offset.is_some_and(|end| end != total)
            || self
                .parts
                .iter()
                .any(|(offset, part)| offset + part.len() > total)
        {
            return Err(());
        }
        if self.total_size != total || self.end_offset != Some(total) {
            return Ok(None);
        }
        let mut payload = Vec::with_capacity(total);
        for (offset, part) in &self.parts {
            if *offset != payload.len() {
                return Ok(None);
            }
            payload.extend_from_slice(part);
        }
        Ok(Some(payload))
    }
}

#[derive(Hash, Eq, PartialEq, Clone, Copy)]
struct PacketStatisticKey {
    uuid: [u8; 16],
    source: u16,
}

#[derive(Hash, Eq, PartialEq, Clone, Copy)]
struct EventStatisticKey {
    uuid: [u8; 16],
    event_id: u16,
}

struct OtaStatistics {
    downstream_packets: u64,
    upstream_packets: u64,
    missing_parts: u64,
    packet_table: u64,
    event_tx: u64,
    event_rx: u64,
    event_table: u64,
    packet_row_limit: usize,
    event_row_limit: usize,
    packet_generation: u64,
    event_generation: u64,
    packet_rows: HashMap<PacketStatisticKey, [u64; 3]>,
    event_rows: HashMap<EventStatisticKey, [u64; 2]>,
}

impl OtaStatistics {
    fn register() -> Self {
        let downstream_packets = register_native_counter(
            0,
            "numOTAChannelDownstreamPackets",
            "Number of downstream OTA channel packets.",
            true,
        )
        .unwrap_or(0);
        let upstream_packets = register_native_counter(
            0,
            "numOTAChannelUpstreamPackets",
            "Number of upstream OTA channel packets.",
            true,
        )
        .unwrap_or(0);
        let missing_parts = register_native_counter(
            0,
            "numOTAChannelUpstreamPacketsDroppedMissingPart",
            "Number of upstream OTA channel packets dropped due to a missing part.",
            true,
        )
        .unwrap_or(0);
        let packet_table = register_native_table(
            0,
            "OTAChannelPacketCountTable",
            &[
                "Src",
                "Emulator UUID",
                "Num Pkts Tx",
                "Num Pkts Rx",
                "Pkts Rx Drop Miss Part",
            ],
            "OTA packet count table.",
            true,
        )
        .unwrap_or(0);
        let event_tx = register_native_counter(
            0,
            "numOTAChannelEventsTx",
            "Number of events transmitted over the OTA channel.",
            true,
        )
        .unwrap_or(0);
        let event_rx = register_native_counter(
            0,
            "numOTAChannelEventsRx",
            "Number of events received over the OTA channel.",
            true,
        )
        .unwrap_or(0);
        let event_table = register_native_table(
            0,
            "OTAChannelEventCountTable",
            &["Src", "Emulator UUID", "Num Events Tx", "Num Events Rx"],
            "OTA Event count table.",
            true,
        )
        .unwrap_or(0);
        Self {
            downstream_packets,
            upstream_packets,
            missing_parts,
            packet_table,
            event_tx,
            event_rx,
            event_table,
            packet_row_limit: 0,
            event_row_limit: 0,
            packet_generation: native_table_generation(packet_table).unwrap_or(0),
            event_generation: native_table_generation(event_table).unwrap_or(0),
            packet_rows: HashMap::new(),
            event_rows: HashMap::new(),
        }
    }

    fn packet(&mut self, key: PacketStatisticKey, column: usize) {
        let counter = [
            self.downstream_packets,
            self.upstream_packets,
            self.missing_parts,
        ][column];
        let _ = increment_native_counter(counter, 1);
        let generation =
            native_table_generation(self.packet_table).unwrap_or(self.packet_generation);
        if generation != self.packet_generation {
            self.packet_rows.clear();
            self.packet_generation = generation;
        }
        if !self.packet_rows.contains_key(&key) && self.packet_rows.len() >= self.packet_row_limit {
            return;
        }
        let counts = self.packet_rows.entry(key).or_default();
        counts[column] = counts[column].saturating_add(1);
        let _ = set_native_table_row(
            self.packet_table,
            statistic_key(key.uuid, key.source),
            vec![
                NativeTableValue::UInt16(key.source),
                NativeTableValue::String(format_uuid(key.uuid)),
                NativeTableValue::UInt64(counts[0]),
                NativeTableValue::UInt64(counts[1]),
                NativeTableValue::UInt64(counts[2]),
            ],
        );
    }

    fn event(&mut self, key: EventStatisticKey, receive: bool) {
        let _ = increment_native_counter(
            if receive {
                self.event_rx
            } else {
                self.event_tx
            },
            1,
        );
        let generation = native_table_generation(self.event_table).unwrap_or(self.event_generation);
        if generation != self.event_generation {
            self.event_rows.clear();
            self.event_generation = generation;
        }
        if !self.event_rows.contains_key(&key) && self.event_rows.len() >= self.event_row_limit {
            return;
        }
        let counts = self.event_rows.entry(key).or_default();
        counts[usize::from(receive)] = counts[usize::from(receive)].saturating_add(1);
        let _ = set_native_table_row(
            self.event_table,
            statistic_key(key.uuid, key.event_id),
            vec![
                NativeTableValue::UInt16(key.event_id),
                NativeTableValue::String(format_uuid(key.uuid)),
                NativeTableValue::UInt64(counts[0]),
                NativeTableValue::UInt64(counts[1]),
            ],
        );
    }
}

fn statistic_key(uuid: [u8; 16], id: u16) -> Vec<u64> {
    vec![
        u64::from_be_bytes(uuid[..8].try_into().unwrap()),
        u64::from_be_bytes(uuid[8..].try_into().unwrap()),
        u64::from(id),
    ]
}

pub struct OtaManager {
    socket: Option<UdpSocket>,
    uuid: [u8; 16],
    ota_mtu: usize,
    part_check_threshold: Duration,
    part_timeout_threshold: Duration,
    u64_sequence_number: u64,
    part_store: HashMap<PartKey, PartsData>,
    last_part_check_time: SystemTime,
    pub nem_users: HashMap<u16, Vec<OtaUser>>,
    group_addr: Option<std::net::SocketAddr>,
    running: bool,
    upstream_packets: u64,
    reassembly_timeouts: u64,
    statistics: OtaStatistics,
}

pub type OtaPacketCallback = extern "C" fn(
    context: *mut c_void,
    source: u16,
    destination: u16,
    priority: u8,
    uuid: *const u8,
    data: *const u8,
    data_len: usize,
    controls: *const u8,
    controls_len: usize,
);

#[derive(Clone, Copy)]
pub struct OtaUser {
    context: usize,
    callback: Option<OtaPacketCallback>,
}

impl Default for OtaManager {
    fn default() -> Self {
        Self::new()
    }
}

impl OtaManager {
    pub fn new() -> Self {
        Self {
            socket: None,
            uuid: [0; 16],
            ota_mtu: 0,
            part_check_threshold: Duration::from_secs(2),
            part_timeout_threshold: Duration::from_secs(5),
            u64_sequence_number: 0,
            part_store: HashMap::new(),
            last_part_check_time: SystemTime::now(),
            nem_users: HashMap::new(),
            group_addr: None,
            running: false,
            upstream_packets: 0,
            reassembly_timeouts: 0,
            statistics: OtaStatistics::register(),
        }
    }
}

static OTA_MANAGER: OnceLock<Mutex<OtaManager>> = OnceLock::new();

pub fn get_ota_manager() -> &'static Mutex<OtaManager> {
    OTA_MANAGER.get_or_init(|| Mutex::new(OtaManager::new()))
}

pub fn configure_statistics(packet_row_limit: u32, event_row_limit: u32) {
    let mut manager = get_ota_manager().lock().unwrap();
    manager.statistics.packet_row_limit = packet_row_limit as usize;
    manager.statistics.event_row_limit = event_row_limit as usize;
}

#[no_mangle]
pub extern "C" fn emane_rs_ota_manager_register_user(id: u16, p_user: *mut c_void) {
    let mut manager = get_ota_manager().lock().unwrap();
    manager.nem_users.entry(id).or_default().push(OtaUser {
        context: p_user as usize,
        callback: None,
    });
}

pub fn register_native_user(id: u16, context: *mut c_void, callback: OtaPacketCallback) {
    let mut manager = get_ota_manager().lock().unwrap();
    let users = manager.nem_users.entry(id).or_default();
    users.retain(|user| user.context != context as usize);
    users.push(OtaUser {
        context: context as usize,
        callback: Some(callback),
    });
}

pub fn unregister_native_user(id: u16, context: *mut c_void) {
    let mut manager = get_ota_manager().lock().unwrap();
    if let Some(users) = manager.nem_users.get_mut(&id) {
        users.retain(|user| user.context != context as usize);
        if users.is_empty() {
            manager.nem_users.remove(&id);
        }
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_ota_manager_unregister_user(id: u16) {
    let mut manager = get_ota_manager().lock().unwrap();
    manager.nem_users.remove(&id);
}

#[no_mangle]
pub extern "C" fn emane_rs_ota_manager_open(
    group_addr_str: *const c_char,
    device_str: *const c_char,
    ttl: u8,
    loopback: bool,
    uuid: *const u8,
    ota_mtu: usize,
    part_check_threshold_secs: u16,
    part_timeout_threshold_secs: u16,
) -> bool {
    if group_addr_str.is_null() || uuid.is_null() {
        return false;
    }
    if get_ota_manager().lock().unwrap().running {
        return false;
    }
    let group_addr_c = unsafe { CStr::from_ptr(group_addr_str) }
        .to_string_lossy()
        .into_owned();
    let device_c = if device_str.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(device_str) }
            .to_string_lossy()
            .into_owned()
    };

    let mut uuid_arr = [0u8; 16];
    unsafe {
        uuid_arr.copy_from_slice(std::slice::from_raw_parts(uuid, 16));
    }

    let Ok(group_addr) = group_addr_c.parse::<SocketAddr>() else {
        return false;
    };
    let domain = if group_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let Ok(socket) = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)) else {
        return false;
    };
    if socket.set_reuse_address(true).is_err() {
        return false;
    }

    match group_addr {
        SocketAddr::V4(group) => {
            let bind = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), group.port());
            if socket.bind(&bind.into()).is_err()
                || multicast::configure(
                    &socket,
                    (*group.ip()).into(),
                    &device_c,
                    u32::from(ttl),
                    loopback,
                )
                .is_err()
            {
                return false;
            }
        }
        SocketAddr::V6(group) => {
            let bind = SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), group.port());
            if socket.bind(&bind.into()).is_err()
                || multicast::configure(
                    &socket,
                    (*group.ip()).into(),
                    &device_c,
                    u32::from(ttl),
                    loopback,
                )
                .is_err()
            {
                return false;
            }
        }
    }

    let mut manager = get_ota_manager().lock().unwrap();
    if manager.running {
        return false;
    }
    manager.socket = Some(socket.into());
    manager.uuid = uuid_arr;
    manager.ota_mtu = ota_mtu;
    manager.part_check_threshold = Duration::from_secs(part_check_threshold_secs as u64);
    manager.part_timeout_threshold = Duration::from_secs(part_timeout_threshold_secs as u64);
    manager.group_addr = Some(group_addr);
    manager.part_store.clear();
    manager.running = true;
    true
}

#[no_mangle]
pub extern "C" fn emane_rs_ota_manager_close() {
    let mut manager = get_ota_manager().lock().unwrap();
    manager.running = false;
    manager.socket.take();
    manager.part_store.clear();
}

#[no_mangle]
pub extern "C" fn emane_rs_ota_manager_process_loop() {
    let socket = {
        let manager = get_ota_manager().lock().unwrap();
        let Some(socket) = manager.socket.as_ref() else {
            return;
        };
        let Ok(socket) = socket.try_clone() else {
            return;
        };
        socket
    };
    if socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .is_err()
    {
        return;
    }

    let mut buf = vec![0u8; 65536];

    loop {
        match socket.recv_from(&mut buf) {
            Ok((len, _)) => {
                let now = SystemTime::now();
                if len >= 2 {
                    let header_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;

                    if len >= 2 + header_len + std::mem::size_of::<PartInfo>() {
                        if let Ok(ota_header) = ota::OtaHeader::decode(&buf[2..2 + header_len]) {
                            if ota_header.source > u16::MAX as u32
                                || ota_header.destination > u16::MAX as u32
                            {
                                continue;
                            }
                            let part_info_offset = 2 + header_len;
                            let part_info = unsafe {
                                std::ptr::read_unaligned(
                                    buf.as_ptr().add(part_info_offset) as *const PartInfo
                                )
                            };

                            let u32_offset = u32::from_be(part_info.u32_offset) as usize;
                            let u32_size = u32::from_be(part_info.u32_size) as usize;
                            let u8_more = part_info.u8_more;
                            if u8_more > 1 {
                                continue;
                            }

                            let Some(remote_uuid) = parse_uuid(&ota_header.uuid) else {
                                continue;
                            };

                            let local_uuid = get_ota_manager().lock().unwrap().uuid;
                            if remote_uuid != local_uuid {
                                let payload_index =
                                    part_info_offset + std::mem::size_of::<PartInfo>();

                                if payload_index.checked_add(u32_size) == Some(len) {
                                    if u8_more == 0 && u32_offset == 0 {
                                        // Single part message
                                        let payload_info =
                                            ota_header.payload_info.unwrap_or_default();
                                        let _ = handle_ota_message(
                                            ota_header.source as u16,
                                            ota_header.destination as u16,
                                            &remote_uuid,
                                            payload_info.event_length as usize,
                                            payload_info.control_length as usize,
                                            payload_info.data_length as usize,
                                            &buf[payload_index..payload_index + u32_size],
                                        );
                                    } else {
                                        // Fragmented message
                                        let mut manager = get_ota_manager().lock().unwrap();
                                        let key = PartKey {
                                            uuid: remote_uuid,
                                            source: ota_header.source as u16,
                                            sequence: ota_header.sequence,
                                        };

                                        let entry =
                                            manager.part_store.entry(key).or_insert_with(|| {
                                                PartsData {
                                                    has_info: false,
                                                    end_offset: None,
                                                    total_size: 0,
                                                    events_size: 0,
                                                    controls_size: 0,
                                                    data_size: 0,
                                                    parts: BTreeMap::new(),
                                                    last_part_time: now,
                                                    uuid: remote_uuid,
                                                }
                                            });
                                        match entry.insert(
                                            ota_header.payload_info.as_ref(),
                                            u32_offset,
                                            u8_more != 0,
                                            &buf[payload_index..payload_index + u32_size],
                                            now,
                                        ) {
                                            Err(()) => {
                                                manager.part_store.remove(&key);
                                            }
                                            Ok(None) => {}
                                            Ok(Some(full_payload)) => {
                                                let entry =
                                                    manager.part_store.remove(&key).unwrap();
                                                drop(manager);
                                                let _ = handle_ota_message(
                                                    ota_header.source as u16,
                                                    ota_header.destination as u16,
                                                    &remote_uuid,
                                                    entry.events_size,
                                                    entry.controls_size,
                                                    entry.data_size,
                                                    &full_payload,
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Cleanup old parts
                let expired = {
                    let mut manager = get_ota_manager().lock().unwrap();
                    let mut expired = Vec::new();
                    if now
                        .duration_since(manager.last_part_check_time)
                        .unwrap_or(Duration::ZERO)
                        >= manager.part_check_threshold
                    {
                        let threshold = manager.part_timeout_threshold;
                        manager.part_store.retain(|key, value| {
                            let remove = now
                                .duration_since(value.last_part_time)
                                .unwrap_or(Duration::ZERO)
                                >= threshold;
                            if remove {
                                expired.push((value.uuid, key.source));
                            }
                            !remove
                        });
                        manager.last_part_check_time = now;
                    }
                    expired
                };
                if !expired.is_empty() {
                    let mut manager = get_ota_manager().lock().unwrap();
                    manager.reassembly_timeouts = manager
                        .reassembly_timeouts
                        .saturating_add(expired.len() as u64);
                    for (uuid, source) in expired {
                        manager
                            .statistics
                            .packet(PacketStatisticKey { uuid, source }, 2);
                    }
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => break,
        }
        if !get_ota_manager().lock().unwrap().running {
            break;
        }
    }
}

const MAX_OTA_PAYLOAD: usize = 64 * 1024 * 1024;

fn parse_uuid(bytes: &[u8]) -> Option<[u8; 16]> {
    bytes.try_into().ok()
}

fn handle_ota_message(
    source: u16,
    destination: u16,
    remote_uuid: &[u8; 16],
    events_size: usize,
    controls_size: usize,
    data_size: usize,
    payload: &[u8],
) -> bool {
    let Some(expected_size) = events_size
        .checked_add(controls_size)
        .and_then(|size| size.checked_add(data_size))
    else {
        return false;
    };
    if expected_size != payload.len() || expected_size > MAX_OTA_PAYLOAD {
        return false;
    }
    let mut offset = 0;

    if events_size > 0 {
        if let Ok(data) = ota::event::Data::decode(&payload[offset..offset + events_size]) {
            for serialization in data.serializations {
                let (Ok(nem_id), Ok(event_id)) = (
                    u16::try_from(serialization.nem_id),
                    u16::try_from(serialization.event_id),
                ) else {
                    continue;
                };
                crate::event_service::route_serialized_event(
                    nem_id,
                    event_id,
                    &serialization.data,
                    0,
                );
                get_ota_manager().lock().unwrap().statistics.event(
                    EventStatisticKey {
                        uuid: *remote_uuid,
                        event_id,
                    },
                    true,
                );
            }
        }
        offset += events_size;
    }

    let controls_ptr = if controls_size > 0 {
        payload[offset..offset + controls_size].as_ptr()
    } else {
        std::ptr::null()
    };

    offset += controls_size;

    let data_ptr = if data_size > 0 {
        payload[offset..offset + data_size].as_ptr()
    } else {
        std::ptr::null()
    };

    if data_size > 0 {
        let users: Vec<OtaUser> = {
            let mut manager = get_ota_manager().lock().unwrap();
            manager.upstream_packets = manager.upstream_packets.saturating_add(1);
            manager.statistics.packet(
                PacketStatisticKey {
                    uuid: *remote_uuid,
                    source,
                },
                1,
            );
            manager.nem_users.values().flatten().copied().collect()
        };

        for user in users {
            if let Some(callback) = user.callback {
                callback(
                    user.context as *mut c_void,
                    source,
                    destination,
                    0, // Priority is set to 0 as in original
                    remote_uuid.as_ptr(),
                    data_ptr,
                    data_size,
                    controls_ptr,
                    controls_size,
                );
            }
        }
    }
    true
}

#[no_mangle]
pub extern "C" fn emane_rs_ota_manager_send_ota_packet(
    source: u16,
    destination: u16,
    packet_data: *const u8,
    packet_len: usize,
    controls_data: *const u8,
    controls_len: usize,
    events_data: *const u8,
    events_len: usize,
) -> bool {
    if (packet_len != 0 && packet_data.is_null())
        || (controls_len != 0 && controls_data.is_null())
        || (events_len != 0 && events_data.is_null())
        || packet_len > u32::MAX as usize
        || controls_len > u32::MAX as usize
        || events_len > u32::MAX as usize
    {
        return false;
    }
    let Some(total_payload_size) = events_len
        .checked_add(controls_len)
        .and_then(|size| size.checked_add(packet_len))
    else {
        return false;
    };
    if total_payload_size > MAX_OTA_PAYLOAD {
        return false;
    }
    let mut manager = get_ota_manager().lock().unwrap();
    let uuid = manager.uuid;
    let ota_mtu = manager.ota_mtu;

    if manager.socket.is_none() {
        return false;
    }

    manager.u64_sequence_number = manager.u64_sequence_number.wrapping_add(1);
    let seq = manager.u64_sequence_number;

    let Ok(socket) = manager.socket.as_ref().unwrap().try_clone() else {
        return false;
    };
    let Some(group_addr) = manager.group_addr else {
        return false;
    };
    drop(manager);

    let mut ota_header = ota::OtaHeader {
        source: source as u32,
        destination: destination as u32,
        sequence: seq,
        uuid: uuid.to_vec(),
        payload_info: Some(ota::ota_header::PayloadInfo {
            data_length: packet_len as u32,
            control_length: controls_len as u32,
            event_length: events_len as u32,
        }),
    };

    let mut sent_bytes = 0;

    let events_slice = if events_data.is_null() {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(events_data, events_len) }
    };
    let controls_slice = if controls_data.is_null() {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(controls_data, controls_len) }
    };
    let packet_slice = if packet_data.is_null() {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(packet_data, packet_len) }
    };

    while sent_bytes < total_payload_size {
        if sent_bytes != 0 {
            ota_header.payload_info = None;
        }
        let ota_header_bytes = ota_header.encode_to_vec();
        let header_len = ota_header_bytes.len();
        if header_len > u16::MAX as usize {
            return false;
        }
        let u16_header_length = (header_len as u16).to_be_bytes();

        let overhead = 2 + header_len + std::mem::size_of::<PartInfo>();
        if ota_mtu != 0 && ota_mtu <= overhead {
            return false;
        }
        let total_wire_size =
            total_payload_size - sent_bytes + header_len + 2 + std::mem::size_of::<PartInfo>();

        let mut part_info = PartInfo {
            u8_more: 0,
            u32_offset: (sent_bytes as u32).to_be(),
            u32_size: 0,
        };

        let payload_size = if ota_mtu != 0 && total_wire_size > ota_mtu {
            part_info.u8_more = 1;
            ota_mtu - overhead
        } else {
            total_payload_size - sent_bytes
        };
        if payload_size == 0 || payload_size > u32::MAX as usize {
            return false;
        }

        part_info.u32_size = (payload_size as u32).to_be();

        let mut message =
            Vec::with_capacity(2 + header_len + std::mem::size_of::<PartInfo>() + payload_size);
        message.extend_from_slice(&u16_header_length);
        message.extend_from_slice(&ota_header_bytes);

        let part_info_bytes = unsafe {
            std::slice::from_raw_parts(
                &part_info as *const PartInfo as *const u8,
                std::mem::size_of::<PartInfo>(),
            )
        };
        message.extend_from_slice(part_info_bytes);

        // Append payload parts based on sent_bytes and payload_size
        let mut p_size = payload_size;
        let mut p_offset = sent_bytes;

        if p_offset < events_len && p_size > 0 {
            let take = p_size.min(events_len - p_offset);
            message.extend_from_slice(&events_slice[p_offset..p_offset + take]);
            p_size -= take;
            p_offset += take;
        }

        let c_start = events_len;
        if p_offset >= c_start && p_offset < c_start + controls_len && p_size > 0 {
            let offset_in_controls = p_offset - c_start;
            let take = p_size.min(controls_len - offset_in_controls);
            message
                .extend_from_slice(&controls_slice[offset_in_controls..offset_in_controls + take]);
            p_size -= take;
            p_offset += take;
        }

        let d_start = c_start + controls_len;
        if p_offset >= d_start && p_offset < d_start + packet_len && p_size > 0 {
            let offset_in_packet = p_offset - d_start;
            let take = p_size.min(packet_len - offset_in_packet);
            message.extend_from_slice(&packet_slice[offset_in_packet..offset_in_packet + take]);
        }

        if message.len() != overhead + payload_size {
            return false;
        }

        if socket.send_to(&message, group_addr).is_err() {
            return false;
        }

        sent_bytes += payload_size;
    }

    let mut manager = get_ota_manager().lock().unwrap();
    manager
        .statistics
        .packet(PacketStatisticKey { uuid, source }, 0);
    if events_len > 0 {
        if let Ok(data) = ota::event::Data::decode(events_slice) {
            for serialization in data.serializations {
                if let Ok(event_id) = u16::try_from(serialization.event_id) {
                    manager
                        .statistics
                        .event(EventStatisticKey { uuid, event_id }, false);
                }
            }
        }
    }

    true
}
#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;
    use std::ffi::CString;
    use std::net::UdpSocket;
    use std::os::raw::c_void;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static EVENTS_DELIVERED: AtomicUsize = AtomicUsize::new(0);
    static PACKETS_PROCESSED: AtomicUsize = AtomicUsize::new(0);
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn test_guard() -> std::sync::MutexGuard<'static, ()> {
        TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner())
    }

    extern "C" fn event_callback(
        _context: *mut c_void,
        _event_id: u16,
        _data: *const u8,
        _len: usize,
    ) {
        EVENTS_DELIVERED.fetch_add(1, Ordering::SeqCst);
    }

    extern "C" fn packet_callback(
        _context: *mut c_void,
        _src: u16,
        _dst: u16,
        _pri: u8,
        _uuid: *const u8,
        _data: *const u8,
        _len: usize,
        _ctrl: *const u8,
        _clen: usize,
    ) {
        PACKETS_PROCESSED.fetch_add(1, Ordering::SeqCst);
    }

    fn reset_mocks() {
        EVENTS_DELIVERED.store(0, Ordering::SeqCst);
        PACKETS_PROCESSED.store(0, Ordering::SeqCst);
    }

    #[test]
    fn test_ota_nem_states() {
        let _guard = test_guard();
        let manager = get_ota_manager();
        let id = 123;
        let p_user = 456 as *mut c_void;
        emane_rs_ota_manager_register_user(id, p_user);
        assert_eq!(
            manager.lock().unwrap().nem_users.get(&id).unwrap()[0].context,
            p_user as usize
        );
        emane_rs_ota_manager_unregister_user(id);
        assert!(!manager.lock().unwrap().nem_users.contains_key(&id));
    }

    #[test]
    fn test_handle_ota_message() {
        let _guard = test_guard();
        reset_mocks();
        let uuid = [0u8; 16];
        // event data: mock an event
        let mut evt = ota::event::Data::default();
        let test_nem = 60_001;
        let ser = ota::event::data::Serialization {
            nem_id: u32::from(test_nem),
            event_id: 2,
            data: vec![1, 2, 3],
        };
        evt.serializations.push(ser);
        let evt_bytes = evt.encode_to_vec();

        let controls = vec![4, 5, 6];
        let data = vec![7, 8, 9];

        let mut payload = Vec::new();
        payload.extend_from_slice(&evt_bytes);
        payload.extend_from_slice(&controls);
        payload.extend_from_slice(&data);

        // register a user so packet gets processed
        register_native_user(test_nem, std::ptr::null_mut(), packet_callback);
        crate::event_service::register_native_user(
            99,
            test_nem,
            std::ptr::null_mut(),
            event_callback,
        );
        assert!(crate::event_service::emane_rs_event_service_register_event(
            99, 2
        ));

        handle_ota_message(
            1,
            2,
            &uuid,
            evt_bytes.len(),
            controls.len(),
            data.len(),
            &payload,
        );

        assert_eq!(EVENTS_DELIVERED.load(Ordering::SeqCst), 1);
        assert_eq!(PACKETS_PROCESSED.load(Ordering::SeqCst), 1);
        emane_rs_ota_manager_unregister_user(test_nem);
        crate::event_service::unregister_user(99);
    }

    #[test]
    fn test_ota_open_and_send() {
        let _guard = test_guard();
        reset_mocks();
        let Ok(reservation) = UdpSocket::bind("127.0.0.1:0") else {
            // Some hermetic test runners prohibit even loopback sockets.
            return;
        };
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let group_addr = CString::new(format!("127.0.0.1:{port}")).unwrap();
        let device = CString::new("").unwrap();
        let uuid = [0u8; 16];

        let success = emane_rs_ota_manager_open(
            group_addr.as_ptr(),
            device.as_ptr(),
            1,
            true,
            uuid.as_ptr(),
            0,
            2,
            5,
        );
        assert!(success);
        let packet_data = [1, 2, 3];
        let empty: Vec<u8> = vec![];
        let sent = emane_rs_ota_manager_send_ota_packet(
            1,
            2,
            packet_data.as_ptr(),
            packet_data.len(),
            empty.as_ptr(),
            0,
            empty.as_ptr(),
            0,
        );
        assert!(sent);
        emane_rs_ota_manager_close();
    }

    #[test]
    fn test_ota_ipv6_open_and_send() {
        let _guard = test_guard();
        let Ok(reservation) = UdpSocket::bind("[::1]:0") else {
            return;
        };
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let group_addr = CString::new(format!("[::1]:{port}")).unwrap();
        let device = CString::new("").unwrap();
        let uuid = [0u8; 16];
        assert!(emane_rs_ota_manager_open(
            group_addr.as_ptr(),
            device.as_ptr(),
            1,
            true,
            uuid.as_ptr(),
            0,
            2,
            5,
        ));
        let packet_data = [1, 2, 3];
        assert!(emane_rs_ota_manager_send_ota_packet(
            1,
            2,
            packet_data.as_ptr(),
            packet_data.len(),
            std::ptr::null(),
            0,
            std::ptr::null(),
            0,
        ));
        emane_rs_ota_manager_close();
    }

    #[test]
    fn ota_statistic_row_limits_match_the_legacy_contract() {
        let _guard = test_guard();
        let mut manager = get_ota_manager().lock().unwrap();
        manager.statistics.packet_rows.clear();
        manager.statistics.packet_row_limit = 1;
        manager.statistics.packet(
            PacketStatisticKey {
                uuid: [1; 16],
                source: 1,
            },
            0,
        );
        manager.statistics.packet(
            PacketStatisticKey {
                uuid: [2; 16],
                source: 2,
            },
            1,
        );
        assert_eq!(manager.statistics.packet_rows.len(), 1);
        assert_eq!(
            manager.statistics.packet_rows.values().next(),
            Some(&[1, 0, 0])
        );
        manager.statistics.packet_row_limit = 0;
        manager.statistics.packet_rows.clear();
    }

    #[test]
    fn rejects_malformed_payload_lengths_and_null_inputs() {
        let _guard = test_guard();
        reset_mocks();
        let uuid = [1u8; 16];
        assert!(!handle_ota_message(1, 2, &uuid, 4, 0, 0, &[1, 2, 3]));
        assert_eq!(EVENTS_DELIVERED.load(Ordering::SeqCst), 0);
        assert_eq!(PACKETS_PROCESSED.load(Ordering::SeqCst), 0);

        assert!(!emane_rs_ota_manager_send_ota_packet(
            1,
            2,
            std::ptr::null(),
            1,
            std::ptr::null(),
            0,
            std::ptr::null(),
            0,
        ));
    }

    #[test]
    fn rejects_datagram_with_non_uuid_identifier() {
        let _guard = test_guard();
        let header = ota::OtaHeader {
            source: 1,
            destination: 2,
            uuid: vec![1, 2, 3],
            payload_info: Some(ota::ota_header::PayloadInfo {
                data_length: 1,
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(parse_uuid(&header.uuid).is_none());
    }
}

#[cfg(test)]
mod fragment_regressions {
    use super::*;
    fn parts() -> PartsData {
        PartsData {
            has_info: false,
            end_offset: None,
            total_size: 0,
            events_size: 0,
            controls_size: 0,
            data_size: 0,
            parts: BTreeMap::new(),
            last_part_time: SystemTime::now(),
            uuid: [1; 16],
        }
    }
    #[test]
    fn cpp_continuations_reassemble_in_any_order() {
        let info = ota::ota_header::PayloadInfo {
            event_length: 1,
            control_length: 1,
            data_length: 4,
        };
        for order in [
            [0, 1, 2],
            [2, 1, 0],
            [1, 0, 2],
            [1, 2, 0],
            [0, 2, 1],
            [2, 0, 1],
        ] {
            let mut parts = parts();
            let mut result = None;
            for index in order {
                result = parts
                    .insert(
                        (index == 0).then_some(&info),
                        index * 2,
                        index != 2,
                        &b"abcdef"[index * 2..index * 2 + 2],
                        SystemTime::now(),
                    )
                    .unwrap();
            }
            assert_eq!(result.as_deref(), Some(&b"abcdef"[..]));
        }
    }
    #[test]
    fn duplicate_is_idempotent_and_overlaps_are_rejected() {
        let mut parts = parts();
        assert!(parts
            .insert(None, 2, true, b"cd", SystemTime::now())
            .unwrap()
            .is_none());
        assert!(parts
            .insert(None, 2, true, b"cd", SystemTime::now())
            .unwrap()
            .is_none());
        assert_eq!(parts.total_size, 2);
        assert!(parts
            .insert(None, 3, false, b"ef", SystemTime::now())
            .is_err());
    }
}
