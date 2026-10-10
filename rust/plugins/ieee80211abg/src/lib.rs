use emane_plugin_api::random::LegacyRandom;
mod pcr_manager;

use emane_plugin_api::{
    CommonLayerCounters, FfiConfigRequest, FfiControlMessage, FfiFrameworkService, FfiPacket,
    FfiPacketInfo, FfiSlice, FfiSpectrumQuery, FfiStatisticValue, FlowControlToken, ModelHeader,
    PluginApi, RxFrequencySegments, RxProperties, TxProperties, CONTROL_FLOW_CONTROL_TOKEN,
    CONTROL_MODEL_HEADER, CONTROL_RX_FREQUENCY_SEGMENTS, CONTROL_RX_PROPERTIES,
    CONTROL_TX_PROPERTIES, MAC_REGISTRATION_IEEE80211ABG, PLUGIN_ABI_VERSION, STATISTIC_VALUE_U64,
};
use pcr_manager::PCRManager;
use prost::Message;
use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::{c_void, CStr, CString};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

const EVENT_TRANSMIT: u32 = 1;
const EVENT_RECEIVE: u32 = 2;
const EVENT_R2RI_REPORT: u32 = 3;
const EVENT_CHANNEL_ESTIMATE: u32 = 4;
const ONE_HOP_NEIGHBORS_EVENT_ID: u16 = 104;
const BROADCAST_NEM: u16 = u16::MAX;
const MSG_TYPE_BROADCAST_DATA: u8 = 1;
const MSG_TYPE_UNICAST_DATA: u8 = 2;
const MSG_TYPE_UNICAST_RTS_CTS_DATA: u8 = 4;
const MSG_TYPE_UNICAST_CTS_CTRL: u8 = 8;
const DUPLICATE_HISTORY_SIZE: usize = 16;
const DUPLICATE_VALIDITY_US: i64 = 5_000_000;
const DATA_RATES_KBPS: [u32; 13] = [
    0, 1_000, 2_000, 5_500, 11_000, 6_000, 9_000, 12_000, 18_000, 24_000, 36_000, 48_000, 54_000,
];

#[derive(Clone, PartialEq, Message)]
struct IeeeMacHeader {
    #[prost(enumeration = "IeeeWireMessageType", required, tag = "1")]
    message_type: i32,
    #[prost(uint32, required, tag = "2")]
    num_retries: u32,
    #[prost(uint32, required, tag = "3")]
    data_rate_index: u32,
    #[prost(uint32, required, tag = "4")]
    sequence_number: u32,
    #[prost(uint32, required, tag = "5")]
    source: u32,
    #[prost(uint32, required, tag = "6")]
    destination: u32,
    #[prost(uint64, required, tag = "7")]
    duration_microseconds: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
enum IeeeWireMessageType {
    None = 0,
    BroadcastData = 1,
    UnicastData = 2,
    UnicastRtsCtsData = 3,
    UnicastCtsCtrl = 4,
}

fn wire_message_type(message_type: u8) -> Option<IeeeWireMessageType> {
    match message_type {
        MSG_TYPE_BROADCAST_DATA => Some(IeeeWireMessageType::BroadcastData),
        MSG_TYPE_UNICAST_DATA => Some(IeeeWireMessageType::UnicastData),
        MSG_TYPE_UNICAST_RTS_CTS_DATA => Some(IeeeWireMessageType::UnicastRtsCtsData),
        MSG_TYPE_UNICAST_CTS_CTRL => Some(IeeeWireMessageType::UnicastCtsCtrl),
        _ => None,
    }
}

fn internal_message_type(message_type: i32) -> Option<u8> {
    match IeeeWireMessageType::try_from(message_type).ok()? {
        IeeeWireMessageType::BroadcastData => Some(MSG_TYPE_BROADCAST_DATA),
        IeeeWireMessageType::UnicastData => Some(MSG_TYPE_UNICAST_DATA),
        IeeeWireMessageType::UnicastRtsCtsData => Some(MSG_TYPE_UNICAST_RTS_CTS_DATA),
        IeeeWireMessageType::UnicastCtsCtrl => Some(MSG_TYPE_UNICAST_CTS_CTRL),
        IeeeWireMessageType::None => None,
    }
}

#[derive(Clone)]
struct OwnedControl {
    msg_type: u32,
    payload: Vec<u8>,
}

#[derive(Clone)]
struct OwnedPacket {
    info: FfiPacketInfo,
    payload: Vec<u8>,
    controls: Vec<OwnedControl>,
}

#[derive(Clone)]
struct PendingTx {
    packet: OwnedPacket,
    category: usize,
    acquired_at: i64,
    txop_microseconds: u64,
    ready_at: i64,
    post_delay_microseconds: u64,
    collision: bool,
    retries: u8,
    max_retries: u8,
    rts_cts: bool,
    sequence: Option<u64>,
    phase: TxPhase,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TxPhase {
    Idle,
    Pre,
    Post,
}

#[derive(Clone, Copy, Default)]
struct NeighborActivity {
    last_activity: i64,
    utilization_microseconds: u64,
    packets: u64,
    rx_power_milliwatts: f64,
    previous_utilization_microseconds: u64,
    previous_packets: u64,
    previous_rx_power_milliwatts: f64,
    category_utilization_microseconds: [u64; 4],
    previous_category_utilization_microseconds: [u64; 4],
}

struct NeighborList {
    last_update: i64,
    neighbors: HashSet<u16>,
}

struct PendingRx {
    packet: OwnedPacket,
    source: u16,
    sequence: u64,
    spectrum_query: FfiSpectrumQuery,
    rx_power_dbm: f64,
    retries: u8,
    rate_index: u8,
    category: usize,
    duration_microseconds: u64,
    data_rate_bps: u64,
    message_type: u8,
    deliverable: bool,
    cts_required: bool,
    end_of_reception: i64,
    acquired_at: i64,
}

#[derive(Clone, Default)]
struct PacketAcceptInfo {
    tx_bytes: u64,
    rx_bytes: u64,
}

#[derive(Clone, Default)]
struct PacketDropInfo {
    bytes: [u64; 10],
}

#[allow(dead_code)]
#[derive(Clone, Copy)]
enum PacketDropReason {
    Sinr = 0,
    RegistrationId = 1,
    Destination = 2,
    QueueOverflow = 3,
    BadControl = 4,
    BadSpectrumQuery = 5,
    FlowControl = 6,
    Duplicate = 7,
    RxDuringTx = 8,
    HiddenBusy = 9,
}

#[derive(Clone, Copy)]
struct CategoryConfig {
    queue_size: usize,
    max_entry_size: usize,
    cw_min: u16,
    cw_max: u16,
    aifs_us: u64,
    retry_limit: u8,
    txop_microseconds: u64,
}

struct State {
    local_id: u16,
    promiscuous: bool,
    wmm: bool,
    mode: u8,
    unicast_rate_index: u8,
    multicast_rate_index: u8,
    rts_threshold: u16,
    max_distance_meters: u32,
    flow_control: bool,
    flow_tokens: u16,
    available_tokens: u16,
    categories: [CategoryConfig; 4],
    queues: [VecDeque<PendingTx>; 4],
    active_tx: Option<PendingTx>,
    pcr_uri: String,
    pcr: Option<PCRManager>,
    sequence: u64,
    current_eot: i64,
    channel_activity_interval_microseconds: u64,
    neighbor_timeout_microseconds: u64,
    channel_activity: HashMap<u16, NeighborActivity>,
    two_hop_activity: HashMap<u16, NeighborActivity>,
    estimated_one_hop_neighbors: f64,
    estimated_two_hop_neighbors: f64,
    neighbor_lists: HashMap<u16, NeighborList>,
    channel_utilization: f64,
    total_one_hop_utilization_microseconds: u64,
    total_two_hop_utilization_microseconds: u64,
    local_node_tx: f64,
    average_message_duration_microseconds: u64,
    next_wakeup: i64,
    pending_rx: HashMap<u64, PendingRx>,
    next_rx_id: u64,
    radiometric_enabled: bool,
    radiometric_report_interval_microseconds: u64,
    neighbor_metric_delete_microseconds: u64,
    queue_discards: [u32; 4],
    broadcast_accept: [HashMap<u16, PacketAcceptInfo>; 4],
    broadcast_drop: [HashMap<u16, PacketDropInfo>; 4],
    unicast_accept: [HashMap<u16, PacketAcceptInfo>; 4],
    unicast_drop: [HashMap<u16, PacketDropInfo>; 4],
    table_generations: HashMap<String, u64>,
    duplicate_history: HashMap<u16, VecDeque<(u64, i64)>>,
    timers: HashSet<u64>,
    random_state: LegacyRandom,
    started: bool,
}

struct Ieee80211Mac {
    id: u16,
    framework: FfiFrameworkService,
    counters: [CommonLayerCounters; 4],
    model_counters: HashMap<String, u64>,
    one_hop_neighbor_table: u64,
    two_hop_neighbor_table: u64,
    packet_tables: HashMap<String, u64>,
    state: Mutex<State>,
}

impl Ieee80211Mac {
    fn new(id: u16, framework: FfiFrameworkService) -> Self {
        let mut model_counters = HashMap::new();
        let mut names = vec![
            "numUnicastPacketsUnsupported".to_string(),
            "numUnicastBytesUnsupported".to_string(),
            "numBroadcastPacketsUnsupported".to_string(),
            "numBroadcastBytesUnsupported".to_string(),
            "numDownstreamUnicastDataDiscardDueToRetries".to_string(),
            "numDownstreamUnicastRtsCtsDataDiscardDueToRetries".to_string(),
            "numUpstreamUnicastDataDiscardDueToSinr".to_string(),
            "numUpstreamBroadcastDataDiscardDueToSinr".to_string(),
            "numUpstreamUnicastDataDiscardDueToClobberRxDuringTx".to_string(),
            "numUpstreamBroadcastDataDiscardDueToClobberRxDuringTx".to_string(),
            "numUpstreamUnicastDataDiscardDueToClobberRxHiddenBusy".to_string(),
            "numUpstreamBroadcastDataDiscardDueToClobberRxHiddenBusy".to_string(),
            "numDownstreamUnicastDataDiscardDueToTxop".to_string(),
            "numDownstreamBroadcastDataDiscardDueToTxop".to_string(),
            "numUpstreamUnicastDataNoiseHiddenRx".to_string(),
            "numUpstreamBroadcastDataNoiseHiddenRx".to_string(),
            "numUpstreamUnicastDataNoiseRxCommon".to_string(),
            "numUpstreamBroadcastDataNoiseRxCommon".to_string(),
            "numUpstreamUnicastRtsCtsDataRxFromPhy".to_string(),
            "numUpstreamUnicastRtsCtsRxFromPhy".to_string(),
            "numOneHopNbrHighWaterMark".to_string(),
            "numTwoHopNbrHighWaterMark".to_string(),
            "numRxOneHopNbrListEvents".to_string(),
            "numRxOneHopNbrListInvalidEvents".to_string(),
            "numTxOneHopNbrListEvents".to_string(),
        ];
        for category in 0..4 {
            for prefix in [
                "numUnicastPacketsTooLarge",
                "numUnicastBytesTooLarge",
                "numBroadcastPacketsTooLarge",
                "numBroadcastBytesTooLarge",
                "numHighWaterMark",
                "numHighWaterMax",
            ] {
                names.push(format!("{prefix}{category}"));
            }
        }
        for name in names {
            let c_name = CString::new(name.as_str()).unwrap();
            let handle = (framework.register_counter32)(
                framework.framework_ctx,
                c_name.as_ptr(),
                c"".as_ptr(),
                true,
            );
            model_counters.insert(name, handle);
        }
        let label = c"NEM Id".as_ptr();
        let one_hop_neighbor_table = (framework.register_table)(
            framework.framework_ctx,
            c"OneHopNeighborTable".as_ptr(),
            &label,
            1,
            c"Current One Hop Neighbors".as_ptr(),
            false,
        );
        let two_hop_neighbor_table = (framework.register_table)(
            framework.framework_ctx,
            c"TwoHopNeighborTable".as_ptr(),
            &label,
            1,
            c"Current Two Hop Neighbors".as_ptr(),
            false,
        );
        let mut packet_tables = HashMap::new();
        for category in 0..4 {
            for (prefix, labels) in [
                (
                    "BroadcastByteAcceptTable",
                    &["NEM", "Num Bytes Tx", "Num Bytes Rx"][..],
                ),
                (
                    "UnicastByteAcceptTable",
                    &["NEM", "Num Bytes Tx", "Num Bytes Rx"][..],
                ),
                (
                    "BroadcastByteDropTable",
                    &[
                        "NEM",
                        "SINR",
                        "Reg Id",
                        "Dst MAC",
                        "Queue Overflow",
                        "Bad Control",
                        "Bad Spectrum Query",
                        "Flow Control",
                        "Duplicate",
                        "Rx During Tx",
                        "Hidden Busy",
                    ][..],
                ),
                (
                    "UnicastByteDropTable",
                    &[
                        "NEM",
                        "SINR",
                        "Reg Id",
                        "Dst MAC",
                        "Queue Overflow",
                        "Bad Control",
                        "Bad Spectrum Query",
                        "Flow Control",
                        "Duplicate",
                        "Rx During Tx",
                        "Hidden Busy",
                    ][..],
                ),
            ] {
                let name = format!("{prefix}{category}");
                let name_value = CString::new(name.as_str()).unwrap();
                let labels = labels
                    .iter()
                    .map(|label| CString::new(*label).unwrap())
                    .collect::<Vec<_>>();
                let pointers = labels
                    .iter()
                    .map(|label| label.as_ptr())
                    .collect::<Vec<_>>();
                let handle = (framework.register_table)(
                    framework.framework_ctx,
                    name_value.as_ptr(),
                    pointers.as_ptr(),
                    pointers.len(),
                    c"IEEE 802.11 packet status".as_ptr(),
                    true,
                );
                if handle != 0 {
                    packet_tables.insert(name, handle);
                }
            }
        }
        let categories = [
            CategoryConfig {
                queue_size: 255,
                max_entry_size: u16::MAX as usize,
                cw_min: 32,
                cw_max: 1024,
                aifs_us: 2,
                retry_limit: 2,
                txop_microseconds: 0,
            },
            CategoryConfig {
                queue_size: 255,
                max_entry_size: u16::MAX as usize,
                cw_min: 32,
                cw_max: 1024,
                aifs_us: 2,
                retry_limit: 2,
                txop_microseconds: 0,
            },
            CategoryConfig {
                queue_size: 255,
                max_entry_size: u16::MAX as usize,
                cw_min: 16,
                cw_max: 64,
                aifs_us: 2,
                retry_limit: 2,
                txop_microseconds: 0,
            },
            CategoryConfig {
                queue_size: 255,
                max_entry_size: u16::MAX as usize,
                cw_min: 8,
                cw_max: 16,
                aifs_us: 1,
                retry_limit: 2,
                txop_microseconds: 0,
            },
        ];
        Self {
            id,
            framework,
            counters: std::array::from_fn(|category| {
                CommonLayerCounters::register_with_drop_labels(
                    framework,
                    &category.to_string(),
                    &[
                        "SINR",
                        "Reg Id",
                        "Dst MAC",
                        "Queue Overflow",
                        "Bad Control",
                        "Bad Spectrum Query",
                        "Flow Control",
                        "Duplicate",
                        "Rx During Tx",
                        "Hidden Busy",
                    ],
                    &[],
                )
            }),
            model_counters,
            one_hop_neighbor_table,
            two_hop_neighbor_table,
            packet_tables,
            state: Mutex::new(State {
                local_id: id,
                promiscuous: false,
                wmm: false,
                mode: 0,
                unicast_rate_index: 4,
                multicast_rate_index: 1,
                rts_threshold: 255,
                max_distance_meters: 1_000,
                flow_control: false,
                flow_tokens: 10,
                available_tokens: 10,
                categories,
                queues: std::array::from_fn(|_| VecDeque::new()),
                active_tx: None,
                pcr_uri: String::new(),
                pcr: None,
                sequence: 0,
                current_eot: 0,
                channel_activity_interval_microseconds: 100_000,
                neighbor_timeout_microseconds: 30_000_000,
                channel_activity: HashMap::new(),
                two_hop_activity: HashMap::new(),
                estimated_one_hop_neighbors: 0.0,
                estimated_two_hop_neighbors: 0.0,
                neighbor_lists: HashMap::new(),
                channel_utilization: 0.0,
                total_one_hop_utilization_microseconds: 0,
                total_two_hop_utilization_microseconds: 0,
                local_node_tx: 0.0,
                average_message_duration_microseconds: 0,
                next_wakeup: 0,
                pending_rx: HashMap::new(),
                next_rx_id: 0,
                radiometric_enabled: false,
                radiometric_report_interval_microseconds: 1_000_000,
                neighbor_metric_delete_microseconds: 60_000_000,
                queue_discards: [0; 4],
                broadcast_accept: std::array::from_fn(|_| HashMap::new()),
                broadcast_drop: std::array::from_fn(|_| HashMap::new()),
                unicast_accept: std::array::from_fn(|_| HashMap::new()),
                unicast_drop: std::array::from_fn(|_| HashMap::new()),
                table_generations: HashMap::new(),
                duplicate_history: HashMap::new(),
                timers: HashSet::new(),
                random_state: LegacyRandom::from_clock(),
                started: false,
            }),
        }
    }

    fn increment(&self, name: &str, amount: u64) {
        if let Some(handle) = self.model_counters.get(name) {
            (self.framework.increment_counter)(self.framework.framework_ctx, *handle, amount);
        }
    }

    fn maximize(&self, name: &str, value: u64) {
        if let Some(handle) = self.model_counters.get(name) {
            (self.framework.maximize_counter)(self.framework.framework_ctx, *handle, value);
        }
    }

    fn set_neighbor_row(&self, table: u64, nem_id: u16) {
        let key = [u64::from(nem_id)];
        let values = [FfiStatisticValue {
            value_type: STATISTIC_VALUE_U64,
            u64_value: u64::from(nem_id),
            f64_value: 0.0,
            string_value: std::ptr::null(),
        }];
        (self.framework.set_table_row)(
            self.framework.framework_ctx,
            table,
            key.as_ptr(),
            key.len(),
            values.as_ptr(),
            values.len(),
        );
    }

    fn remove_neighbor_row(&self, table: u64, nem_id: u16) {
        let key = [u64::from(nem_id)];
        (self.framework.remove_table_row)(
            self.framework.framework_ctx,
            table,
            key.as_ptr(),
            key.len(),
        );
    }

    fn set_packet_table_row(&self, name: &str, key: &[u64], values: &[FfiStatisticValue]) {
        if let Some(handle) = self.packet_tables.get(name).copied() {
            (self.framework.set_table_row)(
                self.framework.framework_ctx,
                handle,
                key.as_ptr(),
                key.len(),
                values.as_ptr(),
                values.len(),
            );
        }
    }

    fn packet_table_generation(&self, name: &str) -> u64 {
        self.packet_tables.get(name).copied().map_or(0, |handle| {
            (self.framework.table_generation)(self.framework.framework_ctx, handle)
        })
    }
}

fn statistic_u64(value: u64) -> FfiStatisticValue {
    FfiStatisticValue {
        value_type: STATISTIC_VALUE_U64,
        u64_value: value,
        f64_value: 0.0,
        string_value: std::ptr::null(),
    }
}

#[allow(clippy::too_many_arguments)]
fn record_packet_accept(
    mac: &Ieee80211Mac,
    state: &mut State,
    category: usize,
    source: u16,
    destination: u16,
    size: usize,
    inbound: bool,
    processing_delay_microseconds: u64,
) {
    let broadcast = destination == BROADCAST_NEM;
    let name = format!(
        "{}ByteAcceptTable{category}",
        if broadcast { "Broadcast" } else { "Unicast" }
    );
    let generation = mac.packet_table_generation(&name);
    let reset = state
        .table_generations
        .insert(name.clone(), generation)
        .is_some_and(|previous| previous != generation);
    let infos = if broadcast {
        &mut state.broadcast_accept[category]
    } else {
        &mut state.unicast_accept[category]
    };
    if reset {
        infos.clear();
    }
    let info = infos.entry(source).or_default();
    if inbound {
        info.rx_bytes = info.rx_bytes.saturating_add(size as u64);
    } else {
        info.tx_bytes = info.tx_bytes.saturating_add(size as u64);
    }
    mac.set_packet_table_row(
        &name,
        &[u64::from(source)],
        &[
            statistic_u64(u64::from(source)),
            statistic_u64(info.tx_bytes),
            statistic_u64(info.rx_bytes),
        ],
    );
    let _ = processing_delay_microseconds;
}

#[allow(clippy::too_many_arguments)]
fn record_packet_drop(
    mac: &Ieee80211Mac,
    state: &mut State,
    category: usize,
    source: u16,
    destination: u16,
    size: usize,
    reason: PacketDropReason,
    inbound: bool,
) {
    let broadcast = destination == BROADCAST_NEM;
    let name = format!(
        "{}ByteDropTable{category}",
        if broadcast { "Broadcast" } else { "Unicast" }
    );
    let generation = mac.packet_table_generation(&name);
    let reset = state
        .table_generations
        .insert(name.clone(), generation)
        .is_some_and(|previous| previous != generation);
    let infos = if broadcast {
        &mut state.broadcast_drop[category]
    } else {
        &mut state.unicast_drop[category]
    };
    if reset {
        infos.clear();
    }
    let nem_id = if inbound { source } else { destination };
    let info = infos.entry(nem_id).or_default();
    info.bytes[reason as usize] = info.bytes[reason as usize].saturating_add(size as u64);
    let mut row = Vec::with_capacity(11);
    row.push(statistic_u64(u64::from(nem_id)));
    row.extend(info.bytes.iter().copied().map(statistic_u64));
    mac.set_packet_table_row(&name, &[u64::from(nem_id)], &row);
    if inbound {
        mac.counters[category].upstream_drop_packet(
            mac.framework,
            source,
            destination,
            reason as usize + 1,
        );
    } else {
        mac.counters[category].downstream_drop_packet(
            mac.framework,
            source,
            destination,
            reason as usize + 1,
        );
    }
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "on" | "true" | "yes" => Some(true),
        "0" | "off" | "false" | "no" => Some(false),
        _ => None,
    }
}

fn seconds_to_us(value: &str) -> Option<u64> {
    let value = value.parse::<f64>().ok()? * 1_000_000.0;
    (value.is_finite() && value >= 0.0 && value <= u64::MAX as f64).then_some(value.round() as u64)
}

fn config_items(request: *const c_void) -> Option<Vec<(String, String)>> {
    let request = unsafe { (request as *const FfiConfigRequest).as_ref() }?;
    if request.len > 4096 || (request.len != 0 && request.data.is_null()) {
        return None;
    }
    let items = if request.len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(request.data, request.len) }
    };
    let mut result = Vec::with_capacity(items.len());
    for item in items {
        if item.name.is_null() || item.values.len != 1 || item.values.data.is_null() {
            return None;
        }
        let value = unsafe { *item.values.data };
        if value.is_null() {
            return None;
        }
        result.push((
            unsafe { CStr::from_ptr(item.name) }
                .to_str()
                .ok()?
                .to_string(),
            unsafe { CStr::from_ptr(value) }.to_str().ok()?.to_string(),
        ));
    }
    Some(result)
}

fn controls(ptr: *const FfiControlMessage, len: usize) -> Option<&'static [FfiControlMessage]> {
    if len > 4096 || (len != 0 && ptr.is_null()) {
        None
    } else if len == 0 {
        Some(&[])
    } else {
        Some(unsafe { std::slice::from_raw_parts(ptr, len) })
    }
}

fn own_packet(
    packet: *const FfiPacket,
    messages: *const FfiControlMessage,
    count: usize,
) -> Option<OwnedPacket> {
    let packet = unsafe { packet.as_ref() }?;
    if packet.payload.len > 64 << 20 || (packet.payload.len != 0 && packet.payload.data.is_null()) {
        return None;
    }
    let payload = if packet.payload.len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(packet.payload.data, packet.payload.len) }.to_vec()
    };
    let controls = controls(messages, count)?
        .iter()
        .map(|message| {
            if message.payload.len > 16 << 20
                || (message.payload.len != 0 && message.payload.data.is_null())
            {
                return None;
            }
            Some(OwnedControl {
                msg_type: message.msg_type,
                payload: if message.payload.len == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(message.payload.data, message.payload.len) }
                        .to_vec()
                },
            })
        })
        .collect::<Option<_>>()?;
    Some(OwnedPacket {
        info: packet.info,
        payload,
        controls,
    })
}

fn packet_metadata(packet: *const FfiPacket) -> Option<(FfiPacketInfo, usize)> {
    let packet = unsafe { packet.as_ref() }?;
    if packet.payload.len > 64 << 20 || (packet.payload.len != 0 && packet.payload.data.is_null()) {
        None
    } else {
        Some((packet.info, packet.payload.len))
    }
}

fn record_upstream_drop(
    mac: &Ieee80211Mac,
    info: FfiPacketInfo,
    size: usize,
    reason: PacketDropReason,
) {
    let mut state = mac.state.lock().unwrap();
    let category = dscp_to_category(info.priority, state.wmm);
    record_packet_drop(
        mac,
        &mut state,
        category,
        info.source,
        info.destination,
        size,
        reason,
        true,
    );
}

fn find_control(messages: &[FfiControlMessage], kind: u32) -> Option<&[u8]> {
    messages.iter().find_map(|message| {
        if message.msg_type != kind || (message.payload.len != 0 && message.payload.data.is_null())
        {
            None
        } else if message.payload.len == 0 {
            Some(&[] as &[u8])
        } else {
            Some(unsafe { std::slice::from_raw_parts(message.payload.data, message.payload.len) })
        }
    })
}

fn now_us() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros(),
    )
    .unwrap_or(i64::MAX)
}

fn mode_parameters(mode: u8) -> (u64, u64, u64) {
    match mode {
        1 => (9, 16, 20),
        2 => (20, 10, 192),
        3 => (20, 16, 192),
        _ => (9, 10, 192),
    }
}

fn slot_size_microseconds(mode: u8, distance_meters: u32) -> u64 {
    let (base, _, _) = mode_parameters(mode);
    let numerator = u64::from(distance_meters).saturating_mul(1_000_000);
    let propagation = numerator / 299_792_458;
    base.saturating_add(propagation)
}

fn dscp_to_category(dscp: u8, wmm: bool) -> usize {
    if !wmm {
        0
    } else {
        match dscp {
            8..=23 => 1,
            32..=47 => 2,
            48..=63 => 3,
            _ => 0,
        }
    }
}

fn packet_duration(mode: u8, length: usize, rate_index: u8, broadcast: bool, rts_cts: bool) -> u64 {
    let (_, sifs, preamble) = mode_parameters(mode);
    let rate = DATA_RATES_KBPS[rate_index as usize] as u64;
    let acknowledgement_bits = if broadcast { 0 } else { 112 };
    let data = ((length as u64)
        .saturating_mul(8)
        .saturating_add(272 + acknowledgement_bits))
    .saturating_mul(1_000)
        / rate;
    let mut duration = if broadcast {
        preamble.saturating_add(data)
    } else {
        2_u64
            .saturating_mul(preamble)
            .saturating_add(sifs)
            .saturating_add(data)
    };
    if rts_cts {
        // C++ truncates each RTS and CTS duration separately.
        duration = duration.saturating_add(2 * cts_duration(mode, rate_index));
    }
    duration.max(1)
}

fn cts_duration(mode: u8, rate_index: u8) -> u64 {
    let (_, _, preamble) = mode_parameters(mode);
    let rate = u64::from(DATA_RATES_KBPS[usize::from(rate_index)]);
    preamble.saturating_add(160_000_u64 / rate)
}

fn encode_flags(rate_index: u8, retries: u8) -> u16 {
    u16::from(rate_index) | (u16::from(retries) << 8)
}

fn decode_flags(flags: u16) -> Option<(u8, u8)> {
    let rate_index = flags as u8;
    (1..=12)
        .contains(&rate_index)
        .then_some((rate_index, (flags >> 8) as u8))
}

fn is_duplicate(state: &mut State, source: u16, sequence: u64, now: i64) -> bool {
    let history = state.duplicate_history.entry(source).or_default();
    history.retain(|(_, received)| received.saturating_add(DUPLICATE_VALIDITY_US) >= now);
    if history.iter().any(|(seen, _)| *seen == sequence) {
        return true;
    }
    if history.len() == DUPLICATE_HISTORY_SIZE {
        history.pop_front();
    }
    history.push_back((sequence, now));
    false
}

fn random_unit(state: &mut State) -> f32 {
    state.random_state.unit()
}

fn record_channel_activity(
    state: &mut State,
    source: u16,
    now: i64,
    duration_microseconds: u64,
    rx_power_dbm: Option<f64>,
    category: usize,
) -> bool {
    let inserted = !state.channel_activity.contains_key(&source);
    let activity = state.channel_activity.entry(source).or_default();
    activity.last_activity = now;
    activity.utilization_microseconds = activity
        .utilization_microseconds
        .saturating_add(duration_microseconds);
    activity.packets = activity.packets.saturating_add(1);
    if let Some(utilization) = activity.category_utilization_microseconds.get_mut(category) {
        *utilization = utilization.saturating_add(duration_microseconds);
    }
    if let Some(power) = rx_power_dbm {
        activity.rx_power_milliwatts += 10.0f64.powf(power / 10.0);
    }
    inserted
}

fn record_two_hop_activity(
    state: &mut State,
    source: u16,
    now: i64,
    duration_microseconds: u64,
) -> bool {
    if source == state.local_id || state.channel_activity.contains_key(&source) {
        return false;
    }
    let inserted = !state.two_hop_activity.contains_key(&source);
    let activity = state.two_hop_activity.entry(source).or_default();
    activity.last_activity = now;
    activity.utilization_microseconds = activity
        .utilization_microseconds
        .saturating_add(duration_microseconds);
    activity.packets = activity.packets.saturating_add(1);
    inserted
}

fn push_varint(data: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        data.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    data.push(value as u8);
}

fn read_varint(data: &[u8], offset: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    for index in 0..10 {
        let byte = *data.get(*offset)?;
        *offset += 1;
        if index == 9 && byte > 1 {
            return None;
        }
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

fn encode_one_hop_neighbors(source: u16, neighbors: impl IntoIterator<Item = u16>) -> Vec<u8> {
    let mut data = Vec::new();
    data.push(0x08);
    push_varint(&mut data, u64::from(source));
    for neighbor in neighbors {
        let mut entry = vec![0x08];
        push_varint(&mut entry, u64::from(neighbor));
        data.push(0x12);
        push_varint(&mut data, entry.len() as u64);
        data.extend_from_slice(&entry);
    }
    data
}

fn decode_one_hop_neighbors(data: &[u8]) -> Option<(u16, HashSet<u16>)> {
    let mut offset = 0usize;
    let mut source = None;
    let mut neighbors = HashSet::new();
    while offset < data.len() {
        let tag = read_varint(data, &mut offset)?;
        match tag {
            0x08 => source = Some(u16::try_from(read_varint(data, &mut offset)?).ok()?),
            0x12 => {
                let len = usize::try_from(read_varint(data, &mut offset)?).ok()?;
                let end = offset.checked_add(len)?;
                if end > data.len() {
                    return None;
                }
                let mut entry_offset = offset;
                if read_varint(data, &mut entry_offset)? != 0x08 {
                    return None;
                }
                let neighbor = u16::try_from(read_varint(data, &mut entry_offset)?).ok()?;
                if entry_offset != end {
                    return None;
                }
                neighbors.insert(neighbor);
                offset = end;
            }
            _ => return None,
        }
    }
    Some((source?, neighbors))
}

fn publish_one_hop_neighbors(mac: &Ieee80211Mac, state: &State) {
    let mut neighbors = state.channel_activity.keys().copied().collect::<Vec<_>>();
    neighbors.sort_unstable();
    let data = encode_one_hop_neighbors(mac.id, neighbors);
    if (mac.framework.publish_event)(
        mac.framework.framework_ctx,
        ONE_HOP_NEIGHBORS_EVENT_ID,
        data.as_ptr(),
        data.len(),
    ) {
        mac.increment("numTxOneHopNbrListEvents", 1);
    }
}

fn estimate_channel_activity(state: &mut State, now: i64) -> (Vec<u16>, Vec<u16>) {
    let mut removed_one_hop = Vec::new();
    let mut removed_two_hop = Vec::new();
    if state.neighbor_timeout_microseconds != 0 {
        let timeout = i64::try_from(state.neighbor_timeout_microseconds).unwrap_or(i64::MAX);
        removed_one_hop.extend(
            state
                .channel_activity
                .iter()
                .filter_map(|(source, activity)| {
                    (now.saturating_sub(activity.last_activity) > timeout).then_some(*source)
                }),
        );
        removed_two_hop.extend(
            state
                .two_hop_activity
                .iter()
                .filter_map(|(source, activity)| {
                    (now.saturating_sub(activity.last_activity) > timeout).then_some(*source)
                }),
        );
        state
            .channel_activity
            .retain(|_, activity| now.saturating_sub(activity.last_activity) <= timeout);
        state
            .neighbor_lists
            .retain(|_, list| now.saturating_sub(list.last_update) <= timeout);
        state
            .two_hop_activity
            .retain(|_, activity| now.saturating_sub(activity.last_activity) <= timeout);
    }
    let interval = state.channel_activity_interval_microseconds.max(1) as f64;
    let active_one_hop = state
        .channel_activity
        .values()
        .filter(|activity| activity.utilization_microseconds != 0)
        .collect::<Vec<_>>();
    let total_duration = active_one_hop
        .iter()
        .map(|activity| activity.utilization_microseconds)
        .sum::<u64>();
    let local_utilization = state
        .channel_activity
        .get(&state.local_id)
        .map_or(0, |activity| activity.utilization_microseconds);
    let remote_packets = state
        .channel_activity
        .iter()
        .filter(|(source, _)| **source != state.local_id)
        .map(|(_, activity)| activity.packets)
        .sum::<u64>();
    let average_one_hop = total_duration
        .checked_div(active_one_hop.len() as u64)
        .unwrap_or(0);
    state.estimated_one_hop_neighbors = if average_one_hop == 0 {
        0.0
    } else {
        active_one_hop
            .iter()
            .map(|activity| {
                (activity.utilization_microseconds as f64 / average_one_hop as f64)
                    .min(1.0)
                    .powi(2)
            })
            .sum::<f64>()
            .round()
    };

    let active_two_hop = state
        .two_hop_activity
        .values()
        .filter(|activity| activity.utilization_microseconds != 0)
        .collect::<Vec<_>>();
    let total_two_hop = active_two_hop
        .iter()
        .map(|activity| activity.utilization_microseconds)
        .sum::<u64>();
    let average_two_hop = total_two_hop
        .checked_div(active_two_hop.len() as u64)
        .unwrap_or(0);
    state.estimated_two_hop_neighbors = if average_two_hop == 0 {
        0.0
    } else {
        active_two_hop
            .iter()
            .map(|activity| {
                (activity.utilization_microseconds as f64 / average_two_hop as f64)
                    .min(1.0)
                    .powi(2)
            })
            .sum::<f64>()
            .round()
    };
    state.channel_utilization = (total_duration as f64 / interval).clamp(0.0, 1.0);
    state.total_one_hop_utilization_microseconds = total_duration;
    state.total_two_hop_utilization_microseconds = total_two_hop;
    state.local_node_tx = if total_duration == 0 {
        0.0
    } else {
        local_utilization as f64 / total_duration as f64
    };
    state.average_message_duration_microseconds = total_duration
        .saturating_sub(local_utilization)
        .checked_div(remote_packets)
        .unwrap_or(0);
    for activity in state.channel_activity.values_mut() {
        activity.previous_utilization_microseconds = activity.utilization_microseconds;
        activity.previous_packets = activity.packets;
        activity.previous_rx_power_milliwatts = activity.rx_power_milliwatts;
        activity.previous_category_utilization_microseconds =
            activity.category_utilization_microseconds;
        activity.utilization_microseconds = 0;
        activity.packets = 0;
        activity.rx_power_milliwatts = 0.0;
        activity.category_utilization_microseconds = [0; 4];
    }
    for activity in state.two_hop_activity.values_mut() {
        activity.previous_utilization_microseconds = activity.utilization_microseconds;
        activity.previous_packets = activity.packets;
        activity.utilization_microseconds = 0;
        activity.packets = 0;
    }
    (removed_one_hop, removed_two_hop)
}

fn txop_expired(acquired_at: i64, txop_microseconds: u64, now: i64) -> bool {
    txop_microseconds != 0
        && acquired_at.saturating_add(i64::try_from(txop_microseconds).unwrap_or(i64::MAX)) < now
}

fn previous_utilization(state: &State, source: u16) -> u64 {
    state
        .channel_activity
        .get(&source)
        .map_or(0, |activity| activity.previous_utilization_microseconds)
}

fn hidden_channel_activity(state: &State, destination: u16) -> f64 {
    let Some(remote) = state.neighbor_lists.get(&destination) else {
        return 0.0;
    };
    let hidden = state
        .channel_activity
        .iter()
        .filter(|(source, _)| {
            **source != state.local_id
                && **source != destination
                && !remote.neighbors.contains(source)
        })
        .map(|(_, activity)| activity.previous_utilization_microseconds)
        .sum::<u64>();
    (hidden as f64 / state.channel_activity_interval_microseconds.max(1) as f64).clamp(0.0, 1.0)
}

fn contention_window(config: CategoryConfig, retries: u8) -> u64 {
    u64::from(config.cw_min)
        .saturating_mul(1_u64.checked_shl(u32::from(retries)).unwrap_or(u64::MAX))
        .min(u64::from(config.cw_max))
        .max(1)
}

fn calculate_tx_delay(state: &mut State, pending: &PendingTx, now: i64) -> (i64, u64, bool) {
    let config = state.categories[pending.category];
    let estimated_neighbors = state.estimated_one_hop_neighbors + state.estimated_two_hop_neighbors;
    let total_utilization = state
        .total_one_hop_utilization_microseconds
        .saturating_add(state.total_two_hop_utilization_microseconds);
    let interval = state.channel_activity_interval_microseconds.max(1) as f64;
    let delay_factor = (total_utilization as f64 / interval).clamp(0.0, 1.0);
    let average_duration = state.average_message_duration_microseconds;
    let slot = slot_size_microseconds(state.mode, state.max_distance_meters);
    let cw = contention_window(config, pending.retries);

    let mut pre_delay = 0_u64;
    let mut post_delay = 0_u64;
    let random_node_delay = f64::from(random_unit(state));
    if estimated_neighbors > 1.0 {
        let overhead = ((estimated_neighbors - 2.0).max(0.0) * (cw * slot) as f64 / 2.0)
            .clamp(0.0, u64::MAX as f64) as u64;
        if f64::from(random_unit(state)) <= delay_factor {
            let nodes = (random_node_delay * estimated_neighbors).floor() as u64;
            pre_delay = nodes.saturating_mul(average_duration);
            if pre_delay > overhead {
                pre_delay -= overhead;
            }
        }
        post_delay = (delay_factor.powi(2) * (estimated_neighbors - 1.0) * average_duration as f64)
            .clamp(0.0, u64::MAX as f64) as u64;
        post_delay = post_delay
            .saturating_sub(pre_delay)
            .saturating_add(average_duration);
    }
    let (_, sifs, _) = mode_parameters(state.mode);
    pre_delay = pre_delay
        .saturating_add(config.aifs_us.saturating_mul(slot))
        .saturating_add(sifs);

    let destination = pending.packet.info.destination;
    let total_one_hop = state.total_one_hop_utilization_microseconds;
    let adjusted = total_one_hop
        .saturating_sub(previous_utilization(state, state.local_id))
        .saturating_sub(previous_utilization(state, destination));
    let utilization_adjusted = (adjusted as f64 / interval).clamp(0.0, 1.0);
    let primary_probability = utilization_adjusted.powi(2)
        * (1.0 - state.local_node_tx)
        * (state.estimated_one_hop_neighbors / cw as f64);
    let collision = f64::from(random_unit(state)) < primary_probability
        || f64::from(random_unit(state))
            < (hidden_channel_activity(state, destination) - 0.1).clamp(0.0, 0.9);

    (
        now.saturating_add(i64::try_from(pre_delay).unwrap_or(i64::MAX)),
        post_delay,
        collision,
    )
}

const COLLISION_CLOBBER_RX_DURING_TX: u8 = 0x01;
const COLLISION_CLOBBER_RX_HIDDEN_BUSY: u8 = 0x02;
const COLLISION_NOISE_HIDDEN_RX: u8 = 0x04;
const COLLISION_NOISE_COMMON_RX: u8 = 0x08;

fn estimated_common_neighbors(state: &State, source: u16) -> f64 {
    let Some(remote) = state.neighbor_lists.get(&source) else {
        return 0.0;
    };
    let active = state
        .channel_activity
        .values()
        .filter(|activity| activity.previous_utilization_microseconds != 0)
        .count();
    let average = state
        .total_one_hop_utilization_microseconds
        .checked_div(active as u64)
        .unwrap_or(0);
    if average == 0 {
        return 0.0;
    }
    state
        .channel_activity
        .iter()
        .filter(|(neighbor, _)| **neighbor != source && remote.neighbors.contains(neighbor))
        .map(|(_, activity)| {
            (activity.previous_utilization_microseconds as f64 / average as f64)
                .min(1.0)
                .powi(2)
        })
        .sum::<f64>()
        .round()
}

fn collision_noise_power(state: &mut State, source: u16, common: bool) -> f64 {
    let draw = f64::from(random_unit(state));
    let Some(remote) = state.neighbor_lists.get(&source) else {
        return 0.0;
    };
    let mut neighbors: Vec<_> = state
        .channel_activity
        .iter()
        .filter(|(neighbor, activity)| {
            **neighbor != source
                && **neighbor != state.local_id
                && activity.previous_utilization_microseconds != 0
                && (remote.neighbors.contains(neighbor) == common)
        })
        .collect();
    // C++ uses a map ordered by NEM ID for the cumulative distribution.
    neighbors.sort_unstable_by_key(|(neighbor, _)| **neighbor);
    let total = neighbors
        .iter()
        .map(|(_, activity)| activity.previous_utilization_microseconds as f64)
        .sum::<f64>();
    let mut cumulative = 0.0;
    for (index, (_, activity)) in neighbors.iter().enumerate() {
        cumulative += activity.previous_utilization_microseconds as f64 / total;
        if draw <= cumulative || index + 1 == neighbors.len() {
            return if activity.previous_packets == 0 {
                0.0
            } else {
                activity.previous_rx_power_milliwatts / activity.previous_packets as f64
            };
        }
    }
    0.0
}

fn check_rx_collision(state: &mut State, source: u16, category: usize, retries: u8) -> u8 {
    let total = state.total_one_hop_utilization_microseconds;
    let local = previous_utilization(state, state.local_id);
    let remote = previous_utilization(state, source);
    let interval = state.channel_activity_interval_microseconds.max(1) as f64;
    let adjusted_factor =
        (total.saturating_sub(local).saturating_sub(remote) as f64 / interval).clamp(0.0, 1.0);
    let actual_factor = (total as f64 / interval).clamp(0.0, 1.0);
    let estimated_one_hop = state.estimated_one_hop_neighbors;
    let estimated_common = estimated_common_neighbors(state, source);
    let hidden_activity = hidden_channel_activity(state, source);
    let cw = contention_window(state.categories[category], retries) as f64;
    let x1 = f64::from(random_unit(state));
    let x2 = f64::from(random_unit(state));
    let x3 = f64::from(random_unit(state));

    if estimated_one_hop > 0.0
        && x1 < adjusted_factor.powi(2) * state.local_node_tx * (estimated_one_hop / cw)
    {
        return COLLISION_CLOBBER_RX_DURING_TX;
    }

    if estimated_one_hop > 0.0 {
        let categories = if state.wmm { 4 } else { 1 };
        let received_cw_min = f64::from(state.categories[category].cw_min);
        let mut weighted_local = 0.0;
        for index in 0..categories {
            let category_total = state
                .channel_activity
                .values()
                .map(|activity| activity.previous_category_utilization_microseconds[index])
                .sum::<u64>();
            if category_total == 0 {
                continue;
            }
            let local_category = state
                .channel_activity
                .get(&state.local_id)
                .map_or(0, |activity| {
                    activity.previous_category_utilization_microseconds[index]
                });
            let local_ratio = local_category as f64 / category_total as f64;
            let cw_ratio = (received_cw_min / f64::from(state.categories[index].cw_min)).min(1.0);
            weighted_local +=
                local_ratio * cw_ratio / f64::from(state.categories[index].cw_min.max(1));
        }
        if x1 < actual_factor.powi(2) * weighted_local {
            return COLLISION_CLOBBER_RX_DURING_TX;
        }
    }

    let mut collision = 0;
    if hidden_activity > 0.0 && actual_factor > 0.0 {
        let transformed = 1.0 + actual_factor.log10();
        let bandwidth_delta = (transformed - 2.0 * hidden_activity).max(0.0);
        let threshold = 1.0 - transformed + bandwidth_delta;
        if x2 > threshold {
            if x3 < 0.5 {
                collision |= COLLISION_NOISE_HIDDEN_RX;
            } else {
                return COLLISION_CLOBBER_RX_HIDDEN_BUSY;
            }
        }
    }

    if estimated_common > 2.0 {
        let common_probability = if cw > estimated_common {
            let categories = if state.wmm { 4 } else { 1 };
            let received_cw_min = f64::from(state.categories[category].cw_min);
            let mut weighted_total = 0.0;
            for index in 0..categories {
                let category_total = state
                    .channel_activity
                    .values()
                    .map(|activity| activity.previous_category_utilization_microseconds[index])
                    .sum::<u64>();
                let total_ratio = if total == 0 {
                    0.0
                } else {
                    (category_total as f64 / total as f64) * actual_factor
                };
                let cw_ratio =
                    (received_cw_min / f64::from(state.categories[index].cw_min)).min(1.0);
                weighted_total +=
                    total_ratio * cw_ratio / f64::from(state.categories[index].cw_min.max(1));
            }
            adjusted_factor.powi(2) * (estimated_common - 2.0) * weighted_total
        } else {
            1.0
        };
        if common_probability >= x1 {
            collision |= COLLISION_NOISE_COMMON_RX;
        }
    }
    collision
}

fn schedule(mac: &Ieee80211Mac, when: i64, event: u32, data: &[u8]) -> u64 {
    let when = when.max(0) as u64;
    (mac.framework.schedule_timed_event)(
        mac.framework.framework_ctx,
        mac.id,
        when / 1_000_000,
        (when % 1_000_000) as u32,
        event,
        data.as_ptr(),
        data.len(),
    )
}

fn schedule_transmit(mac: &Ieee80211Mac, when: i64) {
    let should_schedule = {
        let mut state = mac.state.lock().unwrap();
        if !state.started || (state.next_wakeup != 0 && state.next_wakeup <= when) {
            false
        } else {
            state.next_wakeup = when;
            true
        }
    };
    if should_schedule {
        let timer = schedule(mac, when, EVENT_TRANSMIT, &when.to_be_bytes());
        if timer != 0 {
            mac.state.lock().unwrap().timers.insert(timer);
        }
    }
}

fn send_downstream(
    mac: &Ieee80211Mac,
    pending: &PendingTx,
    header: ModelHeader,
    wire_destination: u16,
    duration: u64,
) {
    let Some((rate_index, retries)) = decode_flags(header.flags) else {
        return;
    };
    let Some(message_type) = wire_message_type(header.message_type) else {
        return;
    };
    let serialization = IeeeMacHeader {
        message_type: message_type as i32,
        num_retries: u32::from(retries),
        data_rate_index: u32::from(rate_index),
        sequence_number: header.sequence as u32,
        source: u32::from(mac.id),
        destination: u32::from(wire_destination),
        duration_microseconds: duration,
    }
    .encode_to_vec();
    let Ok(serialization_len) = u16::try_from(serialization.len()) else {
        return;
    };
    let mut payload = Vec::with_capacity(serialization.len() + 2 + pending.packet.payload.len());
    payload.extend_from_slice(&serialization_len.to_be_bytes());
    payload.extend_from_slice(&serialization);
    payload.extend_from_slice(&pending.packet.payload);
    let header_bytes = header.encode();
    let tx_bytes = TxProperties {
        frequency_hz: 0,
        bandwidth_hz: 0,
        tx_power_dbm: f64::NAN,
        duration_microseconds: duration,
        offset_microseconds: 0,
        tx_time_microseconds: now_us(),
        antenna_index: 0,
        spectral_mask_index: 0,
        sub_id: 0,
    }
    .encode();
    let mut messages: Vec<_> = pending
        .packet
        .controls
        .iter()
        .filter(|control| {
            control.msg_type != CONTROL_MODEL_HEADER && control.msg_type != CONTROL_TX_PROPERTIES
        })
        .map(|control| FfiControlMessage {
            msg_type: control.msg_type,
            payload: FfiSlice {
                data: control.payload.as_ptr(),
                len: control.payload.len(),
            },
        })
        .collect();
    messages.push(FfiControlMessage {
        msg_type: CONTROL_MODEL_HEADER,
        payload: FfiSlice {
            data: header_bytes.as_ptr(),
            len: header_bytes.len(),
        },
    });
    messages.push(FfiControlMessage {
        msg_type: CONTROL_TX_PROPERTIES,
        payload: FfiSlice {
            data: tx_bytes.as_ptr(),
            len: tx_bytes.len(),
        },
    });
    let packet = FfiPacket {
        info: pending.packet.info,
        payload: FfiSlice {
            data: payload.as_ptr(),
            len: payload.len(),
        },
    };
    let (capacity, depth, discards) = {
        let mut state = mac.state.lock().unwrap();
        let category = pending.category;
        (
            state.categories[category].queue_size,
            state.queues[category].len(),
            std::mem::take(&mut state.queue_discards[category]),
        )
    };
    (mac.framework.update_queue_metric)(
        mac.framework.framework_ctx,
        pending.category as u16,
        capacity as u32,
        depth as u32,
        discards,
        now_us().saturating_sub(pending.acquired_at).max(0) as u64,
    );
    mac.counters[pending.category].downstream_tx_packet(
        mac.framework,
        pending.packet.info.source,
        pending.packet.info.destination,
        payload.len(),
        now_us().saturating_sub(pending.acquired_at).max(0) as u64,
        header.message_type == MSG_TYPE_UNICAST_CTS_CTRL,
    );
    (mac.framework.send_downstream_packet)(
        mac.framework.framework_ctx,
        mac.id,
        &packet,
        messages.as_ptr(),
        messages.len(),
    );
    (mac.framework.update_neighbor_tx)(
        mac.framework.framework_ctx,
        pending.packet.info.destination,
        header.data_rate_bps,
        now_us().max(0) as u64,
    );
}

fn send_cts(
    mac: &Ieee80211Mac,
    destination: u16,
    sequence: u64,
    rate_index: u8,
    data_duration: u64,
) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let pending = PendingTx {
        packet: OwnedPacket {
            info: FfiPacketInfo {
                uuid: [0; 16],
                source: mac.id,
                destination: BROADCAST_NEM,
                priority: 0,
                creation_time_sec: now.as_secs(),
                creation_time_usec: now.subsec_micros(),
            },
            payload: Vec::new(),
            controls: Vec::new(),
        },
        category: 0,
        acquired_at: now_us(),
        txop_microseconds: 0,
        ready_at: now_us(),
        post_delay_microseconds: 0,
        collision: false,
        retries: 0,
        max_retries: 0,
        rts_cts: false,
        sequence: Some(sequence),
        phase: TxPhase::Idle,
    };
    send_downstream(
        mac,
        &pending,
        ModelHeader {
            registration_id: MAC_REGISTRATION_IEEE80211ABG,
            sequence,
            data_rate_bps: u64::from(DATA_RATES_KBPS[rate_index as usize]) * 1_000,
            category: 0,
            message_type: MSG_TYPE_UNICAST_CTS_CTRL,
            flags: encode_flags(rate_index, 0),
        },
        destination,
        data_duration,
    );
}

fn send_flow_update(mac: &Ieee80211Mac, tokens: u16) {
    let bytes = FlowControlToken { tokens }.encode();
    let control = FfiControlMessage {
        msg_type: CONTROL_FLOW_CONTROL_TOKEN,
        payload: FfiSlice {
            data: bytes.as_ptr(),
            len: bytes.len(),
        },
    };
    (mac.framework.send_upstream_control)(mac.framework.framework_ctx, mac.id, &control, 1);
}

fn drive(mac: &Ieee80211Mac, now: i64) {
    let (transmission, next, flow_update) = {
        let mut state = mac.state.lock().unwrap();
        if !state.started {
            return;
        }
        let mut flow_update = None;
        for category in 0..state.queues.len() {
            loop {
                let expired = state.queues[category].front().is_some_and(|entry| {
                    txop_expired(entry.acquired_at, entry.txop_microseconds, now)
                });
                if !expired {
                    break;
                }
                if let Some(expired) = state.queues[category].pop_front() {
                    mac.increment(
                        if expired.packet.info.destination == BROADCAST_NEM {
                            "numDownstreamBroadcastDataDiscardDueToTxop"
                        } else {
                            "numDownstreamUnicastDataDiscardDueToTxop"
                        },
                        1,
                    );
                    state.queue_discards[category] =
                        state.queue_discards[category].saturating_add(1);
                    if state.flow_control {
                        state.available_tokens = state
                            .available_tokens
                            .saturating_add(1)
                            .min(state.flow_tokens);
                        flow_update = Some(state.available_tokens);
                    }
                }
            }
        }
        let mut transmission = None;
        loop {
            if state.active_tx.is_none() {
                let selected = (0..state.queues.len())
                    .rev()
                    .find(|category| !state.queues[*category].is_empty());
                let Some(category) = selected else {
                    break;
                };
                state.active_tx = state.queues[category].pop_front();
            }

            let mut pending = state.active_tx.take().expect("active transmission");
            match pending.phase {
                TxPhase::Idle => {
                    if txop_expired(pending.acquired_at, pending.txop_microseconds, now) {
                        mac.increment(
                            if pending.packet.info.destination == BROADCAST_NEM {
                                "numDownstreamBroadcastDataDiscardDueToTxop"
                            } else {
                                "numDownstreamUnicastDataDiscardDueToTxop"
                            },
                            1,
                        );
                        state.queue_discards[pending.category] =
                            state.queue_discards[pending.category].saturating_add(1);
                        if state.flow_control {
                            state.available_tokens = state
                                .available_tokens
                                .saturating_add(1)
                                .min(state.flow_tokens);
                            flow_update = Some(state.available_tokens);
                        }
                        continue;
                    }
                    let (ready_at, post_delay, collision) =
                        calculate_tx_delay(&mut state, &pending, now);
                    pending.ready_at = ready_at;
                    pending.post_delay_microseconds = post_delay;
                    pending.collision =
                        collision && pending.packet.info.destination != BROADCAST_NEM;
                    pending.phase = TxPhase::Pre;
                    state.active_tx = Some(pending);
                }
                TxPhase::Pre => {
                    if pending.ready_at > now {
                        state.active_tx = Some(pending);
                        break;
                    }
                    let broadcast = pending.packet.info.destination == BROADCAST_NEM;
                    let rate_index = if broadcast {
                        state.multicast_rate_index
                    } else {
                        state.unicast_rate_index
                    };
                    let sequence = *pending.sequence.get_or_insert_with(|| {
                        let sequence = state.sequence;
                        state.sequence = state.sequence.wrapping_add(1);
                        sequence
                    });
                    let duration = packet_duration(
                        state.mode,
                        pending.packet.payload.len(),
                        rate_index,
                        broadcast,
                        pending.rts_cts,
                    );
                    let header = ModelHeader {
                        registration_id: MAC_REGISTRATION_IEEE80211ABG,
                        sequence,
                        data_rate_bps: u64::from(DATA_RATES_KBPS[rate_index as usize]) * 1_000,
                        category: pending.category as u8,
                        message_type: if broadcast {
                            MSG_TYPE_BROADCAST_DATA
                        } else if pending.rts_cts {
                            MSG_TYPE_UNICAST_RTS_CTS_DATA
                        } else {
                            MSG_TYPE_UNICAST_DATA
                        },
                        // ENABLE_TX_RETRY is false in the legacy model. The
                        // receiver therefore simulates all configured tries.
                        flags: encode_flags(
                            rate_index,
                            if broadcast { 0 } else { pending.max_retries },
                        ),
                    };
                    state.current_eot = now.saturating_add(duration as i64);
                    let local_id = state.local_id;
                    if record_channel_activity(
                        &mut state,
                        local_id,
                        now,
                        duration,
                        None,
                        pending.category,
                    ) {
                        mac.set_neighbor_row(mac.one_hop_neighbor_table, local_id);
                        mac.maximize(
                            "numOneHopNbrHighWaterMark",
                            state.channel_activity.len() as u64,
                        );
                        publish_one_hop_neighbors(mac, &state);
                    }
                    record_packet_accept(
                        mac,
                        &mut state,
                        pending.category,
                        mac.id,
                        pending.packet.info.destination,
                        pending.packet.payload.len(),
                        false,
                        now.saturating_sub(pending.acquired_at).max(0) as u64,
                    );
                    pending.ready_at = state.current_eot.saturating_add(
                        i64::try_from(pending.post_delay_microseconds).unwrap_or(i64::MAX),
                    );
                    pending.phase = TxPhase::Post;
                    transmission = Some((
                        pending.clone(),
                        header,
                        pending.packet.info.destination,
                        duration,
                    ));
                    state.active_tx = Some(pending);
                    break;
                }
                TxPhase::Post => {
                    if pending.ready_at > now {
                        state.active_tx = Some(pending);
                        break;
                    }
                    if pending.collision && pending.packet.info.destination != BROADCAST_NEM {
                        if pending.retries >= pending.max_retries {
                            mac.increment(
                                if pending.rts_cts {
                                    "numDownstreamUnicastRtsCtsDataDiscardDueToRetries"
                                } else {
                                    "numDownstreamUnicastDataDiscardDueToRetries"
                                },
                                1,
                            );
                        } else {
                            pending.retries = pending.retries.saturating_add(1);
                            pending.phase = TxPhase::Idle;
                            state.active_tx = Some(pending);
                            continue;
                        }
                    }
                    if state.flow_control {
                        state.available_tokens = state
                            .available_tokens
                            .saturating_add(1)
                            .min(state.flow_tokens);
                        flow_update = Some(state.available_tokens);
                    }
                }
            }
        }
        let next = state
            .active_tx
            .as_ref()
            .map(|pending| pending.ready_at)
            .or_else(|| {
                state
                    .queues
                    .iter()
                    .any(|queue| !queue.is_empty())
                    .then_some(now)
            });
        (transmission, next, flow_update)
    };
    if let Some((pending, header, destination, duration)) = transmission {
        send_downstream(mac, &pending, header, destination, duration);
    }
    if let Some(tokens) = flow_update {
        send_flow_update(mac, tokens);
    }
    if let Some(next) = next {
        schedule_transmit(mac, next);
    }
}

fn send_upstream(mac: &Ieee80211Mac, packet: OwnedPacket, category: usize, acquired_at: i64) {
    let messages: Vec<_> = packet
        .controls
        .iter()
        .map(|control| FfiControlMessage {
            msg_type: control.msg_type,
            payload: FfiSlice {
                data: control.payload.as_ptr(),
                len: control.payload.len(),
            },
        })
        .collect();
    let view = FfiPacket {
        info: packet.info,
        payload: FfiSlice {
            data: packet.payload.as_ptr(),
            len: packet.payload.len(),
        },
    };
    mac.counters[category].upstream_tx_packet(
        mac.framework,
        packet.info.source,
        packet.info.destination,
        packet.payload.len(),
        now_us().saturating_sub(acquired_at).max(0) as u64,
    );
    (mac.framework.send_upstream_packet)(
        mac.framework.framework_ctx,
        mac.id,
        &view,
        messages.as_ptr(),
        messages.len(),
    );
}

fn complete_receive(mac: &Ieee80211Mac, id: u64) {
    let (packet, cts, neighbor_metric) = {
        let mut state = mac.state.lock().unwrap();
        let Some(pending) = state.pending_rx.remove(&id) else {
            return;
        };
        if !state.started {
            return;
        }
        let Some(spectrum) = mac.framework.reception_noise(&pending.spectrum_query) else {
            record_packet_drop(
                mac,
                &mut state,
                pending.category,
                pending.source,
                pending.packet.info.destination,
                pending.packet.payload.len(),
                PacketDropReason::BadSpectrumQuery,
                true,
            );
            return;
        };
        if spectrum.signal_in_noise {
            record_packet_drop(
                mac,
                &mut state,
                pending.category,
                pending.source,
                pending.packet.info.destination,
                pending.packet.payload.len(),
                PacketDropReason::BadControl,
                true,
            );
            return;
        }
        let noise_floor_dbm = spectrum.noise_floor_dbm;
        let now = pending.acquired_at;
        if pending.message_type == MSG_TYPE_UNICAST_CTS_CTRL {
            if record_channel_activity(
                &mut state,
                pending.source,
                now,
                0,
                Some(pending.rx_power_dbm),
                pending.category,
            ) {
                mac.set_neighbor_row(mac.one_hop_neighbor_table, pending.source);
                mac.maximize(
                    "numOneHopNbrHighWaterMark",
                    state.channel_activity.len() as u64,
                );
                publish_one_hop_neighbors(mac, &state);
            }
            if record_two_hop_activity(
                &mut state,
                pending.packet.info.destination,
                now,
                pending.duration_microseconds,
            ) {
                mac.set_neighbor_row(mac.two_hop_neighbor_table, pending.packet.info.destination);
                mac.maximize(
                    "numTwoHopNbrHighWaterMark",
                    state.two_hop_activity.len() as u64,
                );
            }
        } else {
            if record_channel_activity(
                &mut state,
                pending.source,
                now,
                pending.duration_microseconds,
                Some(pending.rx_power_dbm),
                pending.category,
            ) {
                mac.set_neighbor_row(mac.one_hop_neighbor_table, pending.source);
                mac.maximize(
                    "numOneHopNbrHighWaterMark",
                    state.channel_activity.len() as u64,
                );
                publish_one_hop_neighbors(mac, &state);
            }
        }
        if pending.message_type == MSG_TYPE_UNICAST_CTS_CTRL {
            return;
        }

        let cts = pending.cts_required.then(|| {
            let sequence = state.sequence;
            state.sequence = state.sequence.wrapping_add(1);
            state.current_eot = state.current_eot.max(now_us().saturating_add(1));
            (
                pending.source,
                sequence,
                state.unicast_rate_index,
                pending.duration_microseconds,
            )
        });

        let duplicate = is_duplicate(
            &mut state,
            pending.source,
            pending.sequence,
            pending.end_of_reception,
        );
        let mut reception_ok = false;
        let mut accepted_sinr = 0.0;
        let mut accepted_noise = noise_floor_dbm;
        let mut drop_reason = duplicate.then_some(PacketDropReason::Duplicate);
        if !duplicate {
            for attempt in 0..=pending.retries {
                let collision =
                    check_rx_collision(&mut state, pending.source, pending.category, attempt);
                let broadcast = pending.packet.info.destination == BROADCAST_NEM;
                if collision & COLLISION_CLOBBER_RX_DURING_TX != 0 {
                    drop_reason = Some(PacketDropReason::RxDuringTx);
                    mac.increment(
                        if broadcast {
                            "numUpstreamBroadcastDataDiscardDueToClobberRxDuringTx"
                        } else {
                            "numUpstreamUnicastDataDiscardDueToClobberRxDuringTx"
                        },
                        1,
                    );
                    continue;
                }
                if collision & COLLISION_CLOBBER_RX_HIDDEN_BUSY != 0 {
                    drop_reason = Some(PacketDropReason::HiddenBusy);
                    mac.increment(
                        if broadcast {
                            "numUpstreamBroadcastDataDiscardDueToClobberRxHiddenBusy"
                        } else {
                            "numUpstreamUnicastDataDiscardDueToClobberRxHiddenBusy"
                        },
                        1,
                    );
                    continue;
                }

                let mut noise_milliwatts = 10.0f64.powf(noise_floor_dbm / 10.0);
                if collision & COLLISION_NOISE_COMMON_RX != 0 {
                    noise_milliwatts += collision_noise_power(&mut state, pending.source, true);
                    mac.increment(
                        if broadcast {
                            "numUpstreamBroadcastDataNoiseRxCommon"
                        } else {
                            "numUpstreamUnicastDataNoiseRxCommon"
                        },
                        1,
                    );
                }
                if collision & COLLISION_NOISE_HIDDEN_RX != 0 {
                    noise_milliwatts += collision_noise_power(&mut state, pending.source, false);
                    mac.increment(
                        if broadcast {
                            "numUpstreamBroadcastDataNoiseHiddenRx"
                        } else {
                            "numUpstreamUnicastDataNoiseHiddenRx"
                        },
                        1,
                    );
                }
                let adjusted_noise_dbm = if noise_milliwatts > 0.0 {
                    10.0 * noise_milliwatts.log10()
                } else {
                    f64::NEG_INFINITY
                };
                let probability = state.pcr.as_ref().map_or(0.0, |pcr| {
                    pcr.get_pcr(
                        (pending.rx_power_dbm - adjusted_noise_dbm) as f32,
                        pending.packet.payload.len(),
                        pending.rate_index.into(),
                    )
                });
                if probability >= random_unit(&mut state) {
                    reception_ok = true;
                    accepted_noise = adjusted_noise_dbm;
                    accepted_sinr = pending.rx_power_dbm - adjusted_noise_dbm;
                    break;
                }
                mac.increment(
                    if broadcast {
                        "numUpstreamBroadcastDataDiscardDueToSinr"
                    } else {
                        "numUpstreamUnicastDataDiscardDueToSinr"
                    },
                    1,
                );
                drop_reason = Some(PacketDropReason::Sinr);
            }
        }
        let accepted = !duplicate && reception_ok && pending.deliverable;
        if accepted {
            record_packet_accept(
                mac,
                &mut state,
                pending.category,
                pending.source,
                pending.packet.info.destination,
                pending.packet.payload.len(),
                true,
                now_us().saturating_sub(pending.acquired_at).max(0) as u64,
            );
        } else {
            record_packet_drop(
                mac,
                &mut state,
                pending.category,
                pending.source,
                pending.packet.info.destination,
                pending.packet.payload.len(),
                if reception_ok {
                    PacketDropReason::Destination
                } else {
                    drop_reason.unwrap_or(PacketDropReason::Sinr)
                },
                true,
            );
        }
        let neighbor_metric = reception_ok.then_some((
            pending.packet.info.uuid,
            pending.source,
            pending.sequence,
            accepted_sinr,
            accepted_noise,
            pending.duration_microseconds,
            pending.data_rate_bps,
        ));
        (
            accepted.then_some((pending.packet, pending.category, pending.acquired_at)),
            cts,
            neighbor_metric,
        )
    };
    if let Some((destination, sequence, rate_index, duration)) = cts {
        send_cts(mac, destination, sequence, rate_index, duration);
    }
    if let Some((packet, category, acquired_at)) = packet {
        send_upstream(mac, packet, category, acquired_at);
    }
    if let Some((uuid, source, sequence, sinr, noise, duration, data_rate)) = neighbor_metric {
        (mac.framework.update_neighbor_rx)(
            mac.framework.framework_ctx,
            source,
            sequence,
            uuid.as_ptr(),
            sinr,
            noise,
            now_us().max(0) as u64,
            duration,
            data_rate,
        );
    }
}

extern "C" fn init(id: u16, framework: *const FfiFrameworkService) -> *mut c_void {
    let Some(framework) = (unsafe { framework.as_ref() }) else {
        return std::ptr::null_mut();
    };
    Box::into_raw(Box::new(Ieee80211Mac::new(id, *framework))).cast()
}

extern "C" fn configure(plugin: *mut c_void, request: *const c_void) -> bool {
    let Some(mac) = (unsafe { (plugin as *mut Ieee80211Mac).as_ref() }) else {
        return false;
    };
    let Some(items) = config_items(request) else {
        return false;
    };
    let mut state = mac.state.lock().unwrap();
    for (name, value) in items {
        match name.as_str() {
            "enablepromiscuousmode" | "promiscuousmode" => {
                state.promiscuous = match parse_bool(&value) {
                    Some(value) => value,
                    None => return false,
                }
            }
            "wmmenable" => {
                state.wmm = match parse_bool(&value) {
                    Some(value) => value,
                    None => return false,
                }
            }
            "mode" => {
                state.mode = match value.parse::<u8>() {
                    Ok(value) if value <= 3 => value,
                    _ => return false,
                }
            }
            "unicastrate" => {
                state.unicast_rate_index = match value.parse::<u8>() {
                    Ok(value @ 1..=12) => value,
                    _ => return false,
                }
            }
            "multicastrate" => {
                state.multicast_rate_index = match value.parse::<u8>() {
                    Ok(value @ 1..=12) => value,
                    _ => return false,
                }
            }
            "rtsthreshold" => {
                state.rts_threshold = match value.parse() {
                    Ok(value) => value,
                    Err(_) => return false,
                }
            }
            "distance" => {
                state.max_distance_meters = match value.parse::<u32>() {
                    Ok(value) => value,
                    Err(_) => return false,
                }
            }
            "flowcontrolenable" => {
                state.flow_control = match parse_bool(&value) {
                    Some(value) => value,
                    None => return false,
                };
            }
            "flowcontroltokens" => {
                state.flow_tokens = match value.parse::<u16>() {
                    Ok(value) if value != 0 => value,
                    _ => return false,
                };
                state.available_tokens = state.flow_tokens;
            }
            "pcrcurveuri" => state.pcr_uri = value,
            "channelactivityestimationtimer" => {
                state.channel_activity_interval_microseconds = match seconds_to_us(&value) {
                    Some(value @ 1_000..=1_000_000) => value,
                    _ => return false,
                };
            }
            "neighbortimeout" => {
                state.neighbor_timeout_microseconds = match seconds_to_us(&value) {
                    Some(value @ 0..=3_600_000_000) => value,
                    _ => return false,
                };
            }
            "radiometricenable" => {
                let Some(value) = parse_bool(&value) else {
                    return false;
                };
                state.radiometric_enabled = value;
            }
            "radiometricreportinterval" => {
                state.radiometric_report_interval_microseconds = match seconds_to_us(&value) {
                    Some(value @ 100_000..=60_000_000) => value,
                    _ => return false,
                };
            }
            "neighbormetricdeletetime" => {
                state.neighbor_metric_delete_microseconds = match seconds_to_us(&value) {
                    Some(value @ 1_000_000..=3_660_000_000) => value,
                    _ => return false,
                };
            }
            _ => {
                let Some(index) = name
                    .chars()
                    .last()
                    .and_then(|value| value.to_digit(10))
                    .map(|value| value as usize)
                else {
                    return false;
                };
                if index > 3 {
                    return false;
                }
                let prefix = &name[..name.len() - 1];
                match prefix {
                    "queuesize" => {
                        state.categories[index].queue_size = match value.parse::<usize>() {
                            Ok(value @ ..=255) => value,
                            _ => return false,
                        }
                    }
                    "msdu" => {
                        state.categories[index].max_entry_size = match value.parse::<usize>() {
                            Ok(value @ 1..=65_535) => value,
                            _ => return false,
                        }
                    }
                    "cwmin" => {
                        state.categories[index].cw_min = match value.parse::<u16>() {
                            Ok(value) if value != 0 => value,
                            _ => return false,
                        }
                    }
                    "cwmax" => {
                        state.categories[index].cw_max = match value.parse::<u16>() {
                            Ok(value) if value != 0 => value,
                            _ => return false,
                        }
                    }
                    "aifs" => {
                        state.categories[index].aifs_us = match seconds_to_us(&value) {
                            Some(value @ 0..=255) => value,
                            _ => return false,
                        }
                    }
                    "txop" => {
                        state.categories[index].txop_microseconds = match seconds_to_us(&value) {
                            Some(value @ 0..=1_000_000) => value,
                            _ => return false,
                        };
                    }
                    "retrylimit" => {
                        state.categories[index].retry_limit = match value.parse::<u8>() {
                            Ok(value) => value,
                            Err(_) => return false,
                        };
                    }
                    _ => return false,
                }
            }
        }
    }
    if state
        .categories
        .iter()
        .any(|category| category.cw_min > category.cw_max)
    {
        return false;
    }
    let valid_rate = |rate: u8| match state.mode {
        0 | 2 => (1..=4).contains(&rate),
        1 => (5..=12).contains(&rate),
        3 => (1..=12).contains(&rate),
        _ => false,
    };
    if !valid_rate(state.unicast_rate_index) || !valid_rate(state.multicast_rate_index) {
        return false;
    }
    true
}

extern "C" fn start(plugin: *mut c_void) -> bool {
    let Some(mac) = (unsafe { (plugin as *mut Ieee80211Mac).as_ref() }) else {
        return false;
    };
    let (flow_update, report, channel_interval) = {
        let mut state = mac.state.lock().unwrap();
        if state.pcr_uri.is_empty() {
            return false;
        }
        let mut pcr = PCRManager::new();
        if pcr.load(&state.pcr_uri).is_err()
            || !pcr.contains_rate(state.unicast_rate_index.into())
            || !pcr.contains_rate(state.multicast_rate_index.into())
        {
            return false;
        }
        state.pcr = Some(pcr);
        state.available_tokens = state.flow_tokens;
        state.channel_activity.clear();
        state.neighbor_lists.clear();
        state.estimated_one_hop_neighbors = 0.0;
        state.estimated_two_hop_neighbors = 0.0;
        state.channel_utilization = 0.0;
        state.started = true;
        (
            state.flow_control.then_some(state.available_tokens),
            state
                .radiometric_enabled
                .then_some(state.radiometric_report_interval_microseconds),
            state.channel_activity_interval_microseconds,
        )
    };
    if let Some(tokens) = flow_update {
        send_flow_update(mac, tokens);
    }
    if let Some(interval) = report {
        let when = now_us().saturating_add(interval as i64);
        let timer = schedule(mac, when, EVENT_R2RI_REPORT, &when.to_be_bytes());
        if timer != 0 {
            mac.state.lock().unwrap().timers.insert(timer);
        }
    }
    let when = now_us().saturating_add(channel_interval as i64);
    let timer = schedule(mac, when, EVENT_CHANNEL_ESTIMATE, &when.to_be_bytes());
    if timer != 0 {
        mac.state.lock().unwrap().timers.insert(timer);
    }
    true
}

extern "C" fn lifecycle(_: *mut c_void) {}

extern "C" fn stop(plugin: *mut c_void) {
    let Some(mac) = (unsafe { (plugin as *mut Ieee80211Mac).as_ref() }) else {
        return;
    };
    let timers = {
        let mut state = mac.state.lock().unwrap();
        state.started = false;
        for queue in &mut state.queues {
            queue.clear();
        }
        state.active_tx = None;
        state.pending_rx.clear();
        state.next_wakeup = 0;
        state.timers.drain().collect::<Vec<_>>()
    };
    for timer in timers {
        (mac.framework.cancel_timed_event)(mac.framework.framework_ctx, mac.id, timer);
    }
}

extern "C" fn destroy(plugin: *mut c_void) {
    if !plugin.is_null() {
        unsafe { drop(Box::from_raw(plugin as *mut Ieee80211Mac)) };
    }
}

extern "C" fn process_downstream(
    plugin: *mut c_void,
    packet: *const FfiPacket,
    messages: *const FfiControlMessage,
    count: usize,
) {
    let Some(mac) = (unsafe { (plugin as *mut Ieee80211Mac).as_ref() }) else {
        return;
    };
    if packet.is_null() {
        (mac.framework.send_downstream_control)(
            mac.framework.framework_ctx,
            mac.id,
            messages,
            count,
        );
        return;
    }
    let Some(packet) = own_packet(packet, messages, count) else {
        return;
    };
    let now = now_us();
    {
        let mut state = mac.state.lock().unwrap();
        let category = dscp_to_category(packet.info.priority, state.wmm);
        mac.counters[category].downstream_rx_packet(
            mac.framework,
            packet.info.source,
            packet.info.destination,
            packet.payload.len(),
        );
        if !state.started || (state.flow_control && state.available_tokens == 0) {
            record_packet_drop(
                mac,
                &mut state,
                category,
                packet.info.source,
                packet.info.destination,
                packet.payload.len(),
                PacketDropReason::FlowControl,
                false,
            );
            return;
        }
        let config = state.categories[category];
        if packet.payload.len() > config.max_entry_size {
            let broadcast = packet.info.destination == BROADCAST_NEM;
            mac.increment(
                &format!(
                    "num{}PacketsTooLarge{category}",
                    if broadcast { "Broadcast" } else { "Unicast" }
                ),
                1,
            );
            mac.increment(
                &format!(
                    "num{}BytesTooLarge{category}",
                    if broadcast { "Broadcast" } else { "Unicast" }
                ),
                packet.payload.len() as u64,
            );
            record_packet_drop(
                mac,
                &mut state,
                category,
                packet.info.source,
                packet.info.destination,
                packet.payload.len(),
                PacketDropReason::QueueOverflow,
                false,
            );
            let update = state.flow_control.then_some(state.available_tokens);
            drop(state);
            if let Some(tokens) = update {
                send_flow_update(mac, tokens);
            }
            return;
        }
        if config.queue_size == 0 {
            record_packet_drop(
                mac,
                &mut state,
                category,
                packet.info.source,
                packet.info.destination,
                packet.payload.len(),
                PacketDropReason::QueueOverflow,
                false,
            );
            state.queue_discards[category] = state.queue_discards[category].saturating_add(1);
            let update = state.flow_control.then_some(state.available_tokens);
            drop(state);
            if let Some(tokens) = update {
                send_flow_update(mac, tokens);
            }
            return;
        }
        if state.flow_control {
            state.available_tokens -= 1;
        }
        while state.queues[category].len() >= config.queue_size {
            if let Some(dropped) = state.queues[category].pop_front() {
                record_packet_drop(
                    mac,
                    &mut state,
                    category,
                    dropped.packet.info.source,
                    dropped.packet.info.destination,
                    dropped.packet.payload.len(),
                    PacketDropReason::QueueOverflow,
                    false,
                );
            }
            state.queue_discards[category] = state.queue_discards[category].saturating_add(1);
            if state.flow_control {
                state.available_tokens = state
                    .available_tokens
                    .saturating_add(1)
                    .min(state.flow_tokens);
            }
        }
        let broadcast = packet.info.destination == BROADCAST_NEM;
        let rts_cts = !broadcast
            && state.rts_threshold != 0
            && packet.payload.len() >= usize::from(state.rts_threshold);
        state.queues[category].push_back(PendingTx {
            packet,
            category,
            acquired_at: now,
            txop_microseconds: config.txop_microseconds,
            ready_at: now,
            post_delay_microseconds: 0,
            collision: false,
            retries: 0,
            max_retries: if broadcast { 0 } else { config.retry_limit },
            rts_cts,
            sequence: None,
            phase: TxPhase::Idle,
        });
        mac.maximize(
            &format!("numHighWaterMark{category}"),
            state.queues[category].len() as u64,
        );
        mac.maximize(
            &format!("numHighWaterMax{category}"),
            config.queue_size as u64,
        );
    }
    drive(mac, now);
}

extern "C" fn process_upstream(
    plugin: *mut c_void,
    packet: *const FfiPacket,
    messages: *const FfiControlMessage,
    count: usize,
) {
    let Some(mac) = (unsafe { (plugin as *mut Ieee80211Mac).as_ref() }) else {
        return;
    };
    if packet.is_null() {
        (mac.framework.send_upstream_control)(mac.framework.framework_ctx, mac.id, messages, count);
        return;
    }
    let Some((raw_info, raw_size)) = packet_metadata(packet) else {
        return;
    };
    let received_at = now_us();
    let category = {
        let state = mac.state.lock().unwrap();
        dscp_to_category(raw_info.priority, state.wmm)
    };
    mac.counters[category].upstream_rx_packet(
        mac.framework,
        raw_info.source,
        raw_info.destination,
        raw_size,
    );
    let Some(message_views) = controls(messages, count) else {
        record_upstream_drop(mac, raw_info, raw_size, PacketDropReason::BadControl);
        return;
    };
    let Some(header) =
        find_control(message_views, CONTROL_MODEL_HEADER).and_then(ModelHeader::decode)
    else {
        record_upstream_drop(mac, raw_info, raw_size, PacketDropReason::BadControl);
        return;
    };
    if header.registration_id != MAC_REGISTRATION_IEEE80211ABG {
        record_upstream_drop(mac, raw_info, raw_size, PacketDropReason::RegistrationId);
        return;
    }
    let Some(rx) =
        find_control(message_views, CONTROL_RX_PROPERTIES).and_then(RxProperties::decode)
    else {
        record_upstream_drop(mac, raw_info, raw_size, PacketDropReason::BadControl);
        return;
    };
    let Some(mut packet) = own_packet(packet, messages, count) else {
        record_upstream_drop(mac, raw_info, raw_size, PacketDropReason::BadControl);
        return;
    };
    if packet.payload.len() < 2 {
        return;
    }
    let serialization_len = u16::from_be_bytes([packet.payload[0], packet.payload[1]]) as usize;
    if serialization_len == 0 || packet.payload.len() < serialization_len + 2 {
        return;
    }
    let Ok(wire_header) = IeeeMacHeader::decode(&packet.payload[2..2 + serialization_len]) else {
        return;
    };
    let (Ok(source), Ok(destination), Ok(rate_index), Ok(retries)) = (
        u16::try_from(wire_header.source),
        u16::try_from(wire_header.destination),
        u8::try_from(wire_header.data_rate_index),
        u8::try_from(wire_header.num_retries),
    ) else {
        return;
    };
    let Some(message_type) = internal_message_type(wire_header.message_type) else {
        return;
    };
    if rate_index == 0 || usize::from(rate_index) >= DATA_RATES_KBPS.len() {
        return;
    }
    packet.info.source = source;
    packet.info.destination = destination;
    packet.payload.drain(..serialization_len + 2);
    let header = ModelHeader {
        registration_id: MAC_REGISTRATION_IEEE80211ABG,
        sequence: u64::from(wire_header.sequence_number),
        data_rate_bps: u64::from(DATA_RATES_KBPS[usize::from(rate_index)]) * 1_000,
        category: 0,
        message_type,
        flags: encode_flags(rate_index, retries),
    };
    let segments = find_control(message_views, CONTROL_RX_FREQUENCY_SEGMENTS)
        .and_then(RxFrequencySegments::decode);
    let spectrum_query = FfiSpectrumQuery::from_rx(
        rx,
        segments.as_ref().and_then(|value| value.segments.first()),
    );
    let now = now_us();
    let (id, when) = {
        let mut state = mac.state.lock().unwrap();
        let rx_category = dscp_to_category(packet.info.priority, state.wmm);
        if !state.started {
            return;
        }
        let start_of_reception = spectrum_query.start_time_microseconds;
        let end_of_reception = start_of_reception
            .saturating_add(i64::try_from(rx.duration_microseconds).unwrap_or(i64::MAX));
        if header.message_type == MSG_TYPE_UNICAST_RTS_CTS_DATA {
            mac.increment("numUpstreamUnicastRtsCtsDataRxFromPhy", 1);
        } else if header.message_type == MSG_TYPE_UNICAST_CTS_CTRL {
            mac.increment("numUpstreamUnicastRtsCtsRxFromPhy", 1);
        }
        state.next_rx_id = state.next_rx_id.wrapping_add(1).max(1);
        let id = state.next_rx_id;
        let destination = packet.info.destination;
        let deliverable =
            state.promiscuous || destination == mac.id || destination == BROADCAST_NEM;
        state.pending_rx.insert(
            id,
            PendingRx {
                source: packet.info.source,
                packet,
                sequence: header.sequence,
                spectrum_query,
                rx_power_dbm: spectrum_query.rx_power_dbm,
                retries,
                rate_index,
                category: rx_category,
                duration_microseconds: wire_header.duration_microseconds,
                data_rate_bps: header.data_rate_bps,
                message_type: header.message_type,
                deliverable,
                cts_required: header.message_type == MSG_TYPE_UNICAST_RTS_CTS_DATA
                    && destination == mac.id,
                end_of_reception,
                acquired_at: received_at,
            },
        );
        (id, end_of_reception.max(now))
    };
    let timer = schedule(mac, when, EVENT_RECEIVE, &id.to_be_bytes());
    if timer == 0 {
        complete_receive(mac, id);
    } else {
        mac.state.lock().unwrap().timers.insert(timer);
    }
}

extern "C" fn timed(plugin: *mut c_void, timer_id: u64, event: u32, data: *const u8, len: usize) {
    let Some(mac) = (unsafe { (plugin as *mut Ieee80211Mac).as_ref() }) else {
        return;
    };
    mac.state.lock().unwrap().timers.remove(&timer_id);
    if len != 8 || data.is_null() {
        return;
    }
    let value = u64::from_be_bytes(
        unsafe { std::slice::from_raw_parts(data, 8) }
            .try_into()
            .unwrap(),
    );
    match event {
        EVENT_TRANSMIT => {
            let expected = value as i64;
            {
                let mut state = mac.state.lock().unwrap();
                if state.next_wakeup != expected {
                    return;
                }
                state.next_wakeup = 0;
            }
            drive(mac, now_us());
        }
        EVENT_RECEIVE => {
            complete_receive(mac, value);
        }
        EVENT_R2RI_REPORT => {
            let report = {
                let state = mac.state.lock().unwrap();
                (state.started && state.radiometric_enabled).then_some((
                    u64::from(DATA_RATES_KBPS[state.multicast_rate_index as usize]) * 1_000,
                    u64::from(
                        DATA_RATES_KBPS[state.unicast_rate_index as usize]
                            .max(DATA_RATES_KBPS[state.multicast_rate_index as usize]),
                    ) * 1_000,
                    state.radiometric_report_interval_microseconds,
                    state.neighbor_metric_delete_microseconds,
                ))
            };
            if let Some((broadcast_rate, max_rate, interval, delete_time)) = report {
                (mac.framework.publish_r2ri)(
                    mac.framework.framework_ctx,
                    broadcast_rate,
                    max_rate,
                    interval,
                    delete_time,
                );
                let when = now_us().saturating_add(interval as i64);
                let timer = schedule(mac, when, EVENT_R2RI_REPORT, &when.to_be_bytes());
                if timer != 0 {
                    mac.state.lock().unwrap().timers.insert(timer);
                }
            }
        }
        EVENT_CHANNEL_ESTIMATE => {
            let (interval, removed_one_hop, removed_two_hop) = {
                let mut state = mac.state.lock().unwrap();
                if !state.started {
                    return;
                }
                let (removed_one_hop, removed_two_hop) =
                    estimate_channel_activity(&mut state, now_us());
                (
                    state.channel_activity_interval_microseconds,
                    removed_one_hop,
                    removed_two_hop,
                )
            };
            let one_hop_changed = !removed_one_hop.is_empty();
            for neighbor in removed_one_hop {
                mac.remove_neighbor_row(mac.one_hop_neighbor_table, neighbor);
            }
            for neighbor in removed_two_hop {
                mac.remove_neighbor_row(mac.two_hop_neighbor_table, neighbor);
            }
            if one_hop_changed {
                let state = mac.state.lock().unwrap();
                publish_one_hop_neighbors(mac, &state);
            }
            let state = mac.state.lock().unwrap();
            mac.maximize(
                "numOneHopNbrHighWaterMark",
                state.estimated_one_hop_neighbors as u64,
            );
            mac.maximize(
                "numTwoHopNbrHighWaterMark",
                state.estimated_two_hop_neighbors as u64,
            );
            drop(state);
            let when = now_us().saturating_add(interval as i64);
            let timer = schedule(mac, when, EVENT_CHANNEL_ESTIMATE, &when.to_be_bytes());
            if timer != 0 {
                mac.state.lock().unwrap().timers.insert(timer);
            }
        }
        _ => {}
    }
}

extern "C" fn process_event(plugin: *mut c_void, event_id: u16, data: *const u8, len: usize) {
    let Some(mac) = (unsafe { (plugin as *mut Ieee80211Mac).as_ref() }) else {
        return;
    };
    if event_id != ONE_HOP_NEIGHBORS_EVENT_ID || len > 1 << 20 || (len != 0 && data.is_null()) {
        return;
    }
    let bytes = if len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(data, len) }
    };
    let Some((source, neighbors)) = decode_one_hop_neighbors(bytes) else {
        mac.increment("numRxOneHopNbrListInvalidEvents", 1);
        return;
    };
    if source == mac.id || source == 0 {
        return;
    }
    mac.state.lock().unwrap().neighbor_lists.insert(
        source,
        NeighborList {
            last_update: now_us(),
            neighbors,
        },
    );
    mac.increment("numRxOneHopNbrListEvents", 1);
}

#[no_mangle]
pub extern "C" fn emane_plugin_create() -> *const PluginApi {
    static API: OnceLock<PluginApi> = OnceLock::new();
    API.get_or_init(|| PluginApi {
        abi_version: PLUGIN_ABI_VERSION,
        struct_size: std::mem::size_of::<PluginApi>(),
        name: c"ieee80211abgmaclayer".as_ptr(),
        plugin_type: 1,
        init,
        configure,
        start,
        post_start: lifecycle,
        stop,
        destroy,
        process_upstream,
        process_downstream,
        process_timed_event: timed,
        process_event,
    })
}

#[cfg(test)]
mod tests {
    extern "C" fn spectrum_unavailable(
        _: *mut c_void,
        _: *const emane_plugin_api::FfiSpectrumQuery,
        _: *mut emane_plugin_api::FfiSpectrumResult,
    ) -> bool {
        false
    }

    use super::*;
    use std::sync::Mutex;

    static EVENT_CAPTURE: Mutex<(u16, Vec<u8>)> = Mutex::new((0, Vec::new()));

    extern "C" fn packet_callback(
        _: *mut c_void,
        _: u16,
        _: *const FfiPacket,
        _: *const FfiControlMessage,
        _: usize,
    ) {
    }

    extern "C" fn control_callback(_: *mut c_void, _: u16, _: *const FfiControlMessage, _: usize) {}

    extern "C" fn schedule_callback(
        _: *mut c_void,
        _: u16,
        _: u64,
        _: u32,
        _: u32,
        _: *const u8,
        _: usize,
    ) -> u64 {
        0
    }

    extern "C" fn cancel_callback(_: *mut c_void, _: u16, _: u64) {}

    extern "C" fn log_callback(_: *mut c_void, _: u32, _: *const std::ffi::c_char) {}

    extern "C" fn register_callback(
        _: *mut c_void,
        _: *const std::ffi::c_char,
        _: *const std::ffi::c_char,
        _: bool,
    ) -> u64 {
        0
    }

    extern "C" fn increment_callback(_: *mut c_void, _: u64, _: u64) -> bool {
        false
    }
    extern "C" fn register_double_callback(
        _: *mut c_void,
        _: *const std::ffi::c_char,
        _: *const std::ffi::c_char,
        _: bool,
    ) -> u64 {
        0
    }
    extern "C" fn set_double_callback(_: *mut c_void, _: u64, _: f64) -> bool {
        false
    }
    extern "C" fn register_table_callback(
        _: *mut c_void,
        _: *const std::os::raw::c_char,
        _: *const *const std::os::raw::c_char,
        _: usize,
        _: *const std::os::raw::c_char,
        _: bool,
    ) -> u64 {
        0
    }
    extern "C" fn set_table_row_callback(
        _: *mut c_void,
        _: u64,
        _: *const u64,
        _: usize,
        _: *const emane_plugin_api::FfiStatisticValue,
        _: usize,
    ) -> bool {
        false
    }

    extern "C" fn neighbor_tx_callback(_: *mut c_void, _: u16, _: u64, _: u64) {}
    extern "C" fn neighbor_status_callback(_: *mut c_void) {}
    extern "C" fn neighbor_rx_callback(
        _: *mut c_void,
        _: u16,
        _: u64,
        _: *const u8,
        _: f64,
        _: f64,
        _: u64,
        _: u64,
        _: u64,
    ) {
    }
    extern "C" fn queue_callback(_: *mut c_void, _: u16, _: u32, _: u32, _: u32, _: u64) {}
    extern "C" fn publish_callback(_: *mut c_void, _: u64, _: u64, _: u64, _: u64) {}
    extern "C" fn register_rf_callback(_: *mut c_void, _: u16) -> u64 {
        1
    }
    extern "C" fn configure_rf_callback(_: *mut c_void, _: u64, _: bool, _: bool) -> bool {
        true
    }
    extern "C" fn update_rf_callback(
        _: *mut c_void,
        _: u64,
        _: u16,
        _: u16,
        _: u64,
        _: f64,
        _: f64,
        _: f64,
        _: f64,
    ) -> bool {
        true
    }
    extern "C" fn publish_event_callback(_: *mut c_void, _: u16, _: *const u8, _: usize) -> bool {
        true
    }
    extern "C" fn register_descriptor_callback(
        _: *mut c_void,
        _: i32,
        _: u32,
        _: *mut c_void,
        _: emane_plugin_api::FfiFileDescriptorCallback,
    ) -> u64 {
        0
    }
    extern "C" fn unregister_descriptor_callback(_: *mut c_void, _: u64) -> bool {
        false
    }
    extern "C" fn table_generation_callback(_: *mut c_void, _: u64) -> u64 {
        0
    }
    extern "C" fn remove_table_row_callback(
        _: *mut c_void,
        _: u64,
        _: *const u64,
        _: usize,
    ) -> bool {
        true
    }

    extern "C" fn capture_event_callback(
        _: *mut c_void,
        event_id: u16,
        data: *const u8,
        len: usize,
    ) -> bool {
        let data = if len == 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(data, len) }.to_vec()
        };
        *EVENT_CAPTURE.lock().unwrap() = (event_id, data);
        true
    }

    pub(super) fn test_mac() -> Ieee80211Mac {
        Ieee80211Mac::new(
            1,
            FfiFrameworkService {
                framework_ctx: std::ptr::null_mut(),
                send_downstream_packet: packet_callback,
                send_upstream_packet: packet_callback,
                send_downstream_control: control_callback,
                send_upstream_control: control_callback,
                schedule_timed_event: schedule_callback,
                cancel_timed_event: cancel_callback,
                log: log_callback,
                register_counter: register_callback,
                register_counter32: register_callback,
                increment_counter: increment_callback,
                maximize_counter: increment_callback,
                register_double: register_double_callback,
                set_double: set_double_callback,
                register_average: register_double_callback,
                sample_average: set_double_callback,
                register_table: register_table_callback,
                set_table_row: set_table_row_callback,
                clear_table: unregister_descriptor_callback,
                remove_table_row: remove_table_row_callback,
                table_generation: table_generation_callback,
                update_neighbor_tx: neighbor_tx_callback,
                update_neighbor_rx: neighbor_rx_callback,
                update_neighbor_status: neighbor_status_callback,
                update_queue_metric: queue_callback,
                publish_r2ri: publish_callback,
                register_rf_signal_table: register_rf_callback,
                configure_rf_signal_table: configure_rf_callback,
                update_rf_signal_table: update_rf_callback,
                publish_event: publish_event_callback,
                register_file_descriptor: register_descriptor_callback,
                unregister_file_descriptor: unregister_descriptor_callback,
                query_spectrum_filter: emane_plugin_api::spectrum::unavailable_filter,
                query_spectrum: spectrum_unavailable,
            },
        )
    }

    fn test_mac_with_event_capture(id: u16) -> Ieee80211Mac {
        let mut mac = test_mac();
        mac.id = id;
        mac.framework.publish_event = capture_event_callback;
        mac.state.get_mut().unwrap().local_id = id;
        mac
    }

    #[test]
    fn timing_matches_legacy_rate_table() {
        assert_eq!(DATA_RATES_KBPS[4], 11_000);
        assert!(
            packet_duration(2, 1_500, 4, false, true) > packet_duration(2, 1_500, 4, false, false)
        );
        assert_eq!(seconds_to_us("0.000002"), Some(2));
    }

    #[test]
    fn wmm_uses_the_legacy_dscp_category_ranges() {
        assert_eq!(dscp_to_category(0, true), 0);
        assert_eq!(dscp_to_category(3, true), 0);
        assert_eq!(dscp_to_category(8, true), 1);
        assert_eq!(dscp_to_category(23, true), 1);
        assert_eq!(dscp_to_category(32, true), 2);
        assert_eq!(dscp_to_category(47, true), 2);
        assert_eq!(dscp_to_category(48, true), 3);
        assert_eq!(dscp_to_category(63, true), 3);
        assert_eq!(dscp_to_category(63, false), 0);
    }

    #[test]
    fn native_header_preserves_legacy_rate_and_retry_fields() {
        assert_eq!(decode_flags(encode_flags(4, 2)), Some((4, 2)));
        assert_eq!(decode_flags(encode_flags(12, u8::MAX)), Some((12, u8::MAX)));
        assert_eq!(decode_flags(encode_flags(0, 2)), None);
        assert_eq!(MSG_TYPE_UNICAST_RTS_CTS_DATA, 4);
        assert_eq!(MSG_TYPE_UNICAST_CTS_CTRL, 8);
    }

    #[test]
    fn txop_matches_legacy_strict_queue_lifetime_boundary() {
        assert!(!txop_expired(1_000, 0, i64::MAX));
        assert!(!txop_expired(1_000, 500, 1_500));
        assert!(txop_expired(1_000, 500, 1_501));
    }

    #[test]
    fn drive_discards_a_packet_after_its_nonzero_txop() {
        let mac = test_mac();
        {
            let mut state = mac.state.lock().unwrap();
            state.started = true;
            state.queues[0].push_back(PendingTx {
                packet: OwnedPacket {
                    info: FfiPacketInfo {
                        uuid: [0; 16],
                        source: 1,
                        destination: 2,
                        priority: 0,
                        creation_time_sec: 0,
                        creation_time_usec: 0,
                    },
                    payload: vec![1, 2, 3],
                    controls: Vec::new(),
                },
                category: 0,
                acquired_at: 1_000,
                txop_microseconds: 500,
                ready_at: i64::MAX,
                post_delay_microseconds: 0,
                collision: false,
                retries: 0,
                max_retries: 2,
                rts_cts: false,
                sequence: None,
                phase: TxPhase::Idle,
            });
        }
        drive(&mac, 1_501);
        let state = mac.state.lock().unwrap();
        assert!(state.queues[0].is_empty());
        assert_eq!(state.queue_discards[0], 1);
    }

    #[test]
    fn channel_estimation_rolls_activity_and_expires_neighbors() {
        let mac = test_mac();
        let mut state = mac.state.lock().unwrap();
        state.channel_activity_interval_microseconds = 100;
        state.neighbor_timeout_microseconds = 200;
        record_channel_activity(&mut state, 2, 900, 25, Some(-50.0), 0);
        record_channel_activity(&mut state, 3, 950, 50, Some(-60.0), 0);
        state.neighbor_lists.insert(
            2,
            NeighborList {
                last_update: 950,
                neighbors: HashSet::from([1, 3, 4]),
            },
        );
        let _ = estimate_channel_activity(&mut state, 1_000);
        // The legacy estimator sums squared, average-normalized activity;
        // unequal utilization can therefore estimate fewer nodes than the
        // number of active entries.
        assert_eq!(state.estimated_one_hop_neighbors, 1.0);
        assert_eq!(state.estimated_two_hop_neighbors, 0.0);
        assert_eq!(state.channel_utilization, 0.75);
        assert_eq!(state.average_message_duration_microseconds, 37);
        assert!(state
            .channel_activity
            .values()
            .all(|activity| activity.packets == 0));
        let _ = estimate_channel_activity(&mut state, 1_201);
        assert!(state.channel_activity.is_empty());
        assert_eq!(state.estimated_one_hop_neighbors, 0.0);
        assert_eq!(state.estimated_two_hop_neighbors, 0.0);
    }

    #[test]
    fn one_hop_neighbor_event_matches_legacy_protobuf_shape() {
        let data = encode_one_hop_neighbors(7, [2, 9]);
        assert_eq!(
            decode_one_hop_neighbors(&data),
            Some((7, HashSet::from([2, 9])))
        );
        assert!(decode_one_hop_neighbors(&[0x12, 0xff]).is_none());
    }

    #[test]
    fn neighbor_change_event_is_published_and_consumed_by_a_peer() {
        *EVENT_CAPTURE.lock().unwrap() = (0, Vec::new());
        let source = test_mac_with_event_capture(7);
        {
            let mut state = source.state.lock().unwrap();
            state.started = true;
            state.channel_activity_interval_microseconds = 100;
            assert!(record_channel_activity(
                &mut state,
                9,
                now_us(),
                25,
                Some(-50.0),
                0,
            ));
            publish_one_hop_neighbors(&source, &state);
        }
        let (event_id, payload) = EVENT_CAPTURE.lock().unwrap().clone();
        assert_eq!(event_id, ONE_HOP_NEIGHBORS_EVENT_ID);
        assert_eq!(
            decode_one_hop_neighbors(&payload),
            Some((7, HashSet::from([9])))
        );

        let peer = test_mac_with_event_capture(8);
        process_event(
            &peer as *const Ieee80211Mac as *mut c_void,
            event_id,
            payload.as_ptr(),
            payload.len(),
        );
        let peer_state = peer.state.lock().unwrap();
        assert_eq!(peer_state.neighbor_lists[&7].neighbors, HashSet::from([9]));
    }

    #[test]
    fn duplicate_history_matches_legacy_size_and_validity_window() {
        let mac = test_mac();
        let mut state = mac.state.into_inner().unwrap();
        assert!(!is_duplicate(&mut state, 2, 7, 10));
        assert!(is_duplicate(&mut state, 2, 7, 11));
        assert!(!is_duplicate(
            &mut state,
            2,
            7,
            10 + DUPLICATE_VALIDITY_US + 1
        ));
    }
}

#[cfg(test)]
mod regression_tests;
