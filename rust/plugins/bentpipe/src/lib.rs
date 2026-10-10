use emane_plugin_api::random::LegacyRandom;
mod pcr_manager;

use emane_plugin_api::{
    AntennaPattern, FfiConfigRequest, FfiControlMessage, FfiFrameworkService, FfiPacket,
    FfiPacketInfo, FfiSlice, FfiSpectrumQuery, FfiStatisticValue, MimoRxProperties, MimoTxAntenna,
    MimoTxFrequencySegment, MimoTxProperties, ModelHeader, PluginApi, RxAntennaAdd,
    RxAntennaRemove, RxProperties, TxAntennaProfile, TxProperties, CONTROL_MIMO_RX_PROPERTIES,
    CONTROL_MIMO_TX_PROPERTIES, CONTROL_MODEL_HEADER, CONTROL_RX_ANTENNA_ADD,
    CONTROL_RX_ANTENNA_REMOVE, CONTROL_RX_PROPERTIES, CONTROL_TX_PROPERTIES,
    MAC_REGISTRATION_BENTPIPE, PLUGIN_ABI_VERSION, STATISTIC_VALUE_F64, STATISTIC_VALUE_STRING,
    STATISTIC_VALUE_U64,
};
use pcr_manager::PCRManager;
use prost::Message;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::ffi::{c_void, CStr};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

const EVENT_TRANSMIT: u32 = 1;
const EVENT_REASSEMBLY_CHECK: u32 = 2;
const EVENT_RECEIVE: u32 = 3;
const EVENT_RECEPTION_CHECK: u32 = 4;
const DEFAULT_QUEUE_DEPTH: usize = 256;
const BENTPIPE_MESSAGE_TYPE: u8 = 1;
const BROADCAST_NEM: u16 = u16::MAX;

#[derive(Clone, PartialEq, Message)]
struct BentPipeMessage {
    #[prost(uint64, required, tag = "1")]
    start_of_transmission_microseconds: u64,
    #[prost(uint32, required, tag = "2")]
    curve_index: u32,
    #[prost(message, repeated, tag = "3")]
    messages: Vec<BentPipeComponent>,
}

#[derive(Clone, PartialEq, Message)]
struct BentPipeComponent {
    #[prost(uint32, required, tag = "2")]
    destination: u32,
    #[prost(bytes = "vec", required, tag = "4")]
    data: Vec<u8>,
    #[prost(message, optional, tag = "5")]
    fragment: Option<BentPipeFragment>,
}

#[derive(Clone, PartialEq, Message)]
struct BentPipeFragment {
    #[prost(bool, required, tag = "1")]
    more: bool,
    #[prost(uint32, required, tag = "2")]
    index: u32,
    #[prost(uint32, required, tag = "3")]
    offset: u32,
    #[prost(uint64, required, tag = "4")]
    sequence: u64,
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReceiveAction {
    Unknown,
    Ubend,
    Process,
}

#[derive(Clone)]
struct Transponder {
    receive_frequency_hz: u64,
    receive_bandwidth_hz: u64,
    receive_antenna_index: u16,
    receive_action: ReceiveAction,
    receive_enable: bool,
    curve_index: u16,
    transmit_frequency_hz: u64,
    transmit_bandwidth_hz: u64,
    transmit_data_rate_bps: u64,
    transmit_mtu_bytes: usize,
    transmit_antenna_index: u16,
    transmit_power_dbm: f64,
    transmit_delay_us: u64,
    transmit_slots_per_frame: u16,
    transmit_slot_size_us: u64,
    transmit_slots: Vec<u16>,
    transmit_enable: bool,
    tos: HashSet<u8>,
    all_tos: bool,
}

impl Default for Transponder {
    fn default() -> Self {
        Self {
            receive_frequency_hz: 0,
            receive_bandwidth_hz: 0,
            receive_antenna_index: 0,
            receive_action: ReceiveAction::Unknown,
            receive_enable: false,
            curve_index: 0,
            transmit_frequency_hz: 0,
            transmit_bandwidth_hz: 0,
            transmit_data_rate_bps: 0,
            transmit_mtu_bytes: 0,
            transmit_antenna_index: 0,
            transmit_power_dbm: 0.0,
            transmit_delay_us: 0,
            transmit_slots_per_frame: 0,
            transmit_slot_size_us: 0,
            transmit_slots: Vec::new(),
            transmit_enable: false,
            tos: HashSet::new(),
            all_tos: false,
        }
    }
}

struct PendingTx {
    packet: OwnedPacket,
    sequence: u64,
    offset: usize,
    fragment_index: u32,
    ready_at: i64,
}

struct TxComponent {
    packet: OwnedPacket,
    sequence: u64,
    offset: usize,
    fragment_index: u32,
    more: bool,
    fragmented: bool,
}

struct Reassembly {
    info: FfiPacketInfo,
    controls: Vec<OwnedControl>,
    destination: u16,
    parts: BTreeMap<usize, (u32, Vec<u8>)>,
    last_fragment_index: Option<u32>,
    last_update: i64,
}

#[derive(Default)]
struct QueueStatistics {
    enqueued: u64,
    dequeued: u64,
    overflow: u64,
    too_big: u64,
    high_water: u64,
    fragment_histogram: [u64; 10],
    aggregate_histogram: [u64; 10],
}

#[derive(Default)]
struct SlotStatistics {
    valid: u64,
    missed: u64,
    quantiles: [u64; 8],
}

#[derive(Default)]
struct NeighborStatistics {
    samples: u64,
    sinr_sum: f64,
    noise_floor_sum: f64,
    sinr_window: VecDeque<f64>,
    noise_floor_window: VecDeque<f64>,
}

#[derive(Clone, Default)]
struct PacketAcceptInfo {
    tx_bytes: u64,
    rx_bytes: u64,
}

#[derive(Clone, Default)]
struct PacketDropInfo {
    bytes: [u64; 13],
}

#[derive(Clone, Copy)]
enum PacketDropReason {
    Sinr = 0,
    RegistrationId = 1,
    Destination = 2,
    QueueOverflow = 3,
    BadControl = 4,
    Spectrum = 5,
    TooBig = 6,
    MissingFragment = 8,
    BadCurve = 9,
    Lock = 10,
    RxOff = 11,
    TxOff = 12,
}

#[derive(Clone, Copy)]
struct AntennaDefinition {
    pattern: AntennaPattern,
    spectral_mask_index: u16,
}

struct PendingReception {
    info: FfiPacketInfo,
    controls: Vec<OwnedControl>,
    wire: BentPipeMessage,
    length: usize,
    index: u16,
    action: ReceiveAction,
    delay: u64,
    query: FfiSpectrumQuery,
}

struct State {
    transponders: BTreeMap<u16, Transponder>,
    configured_transponder_fields: HashMap<u16, u32>,
    queues: HashMap<u16, VecDeque<PendingTx>>,
    queue_statistics: HashMap<u16, QueueStatistics>,
    slot_statistics: HashMap<u16, SlotStatistics>,
    neighbor_statistics: HashMap<(u16, u16), NeighborStatistics>,
    broadcast_accept: HashMap<u16, PacketAcceptInfo>,
    broadcast_drop: HashMap<u16, PacketDropInfo>,
    unicast_accept: HashMap<u16, PacketAcceptInfo>,
    unicast_drop: HashMap<u16, PacketDropInfo>,
    table_generations: HashMap<String, u64>,
    queue_depth: usize,
    aggregation_enable: bool,
    fragmentation_enable: bool,
    antennas: HashMap<u16, AntennaDefinition>,
    fragment_check_us: i64,
    fragment_timeout_us: i64,
    pcr_uri: String,
    pcr: PCRManager,
    packet_sequence: u64,
    frame_sequence: u64,
    current_eot: HashMap<u16, i64>,
    receive_end: HashMap<u16, i64>,
    wakeups: HashMap<u16, i64>,
    timers: HashSet<u64>,
    next_receive_id: u64,
    pending_receptions: HashMap<u64, OwnedPacket>,
    receive_candidates: BTreeMap<(u16, i64, u64), PendingReception>,
    reassembly: HashMap<(u16, u64), Reassembly>,
    receive_random: HashMap<u16, LegacyRandom>,
    started: bool,
}

struct BentpipeMac {
    id: u16,
    framework: FfiFrameworkService,
    tables: HashMap<String, u64>,
    state: Mutex<State>,
}

impl BentpipeMac {
    fn new(id: u16, framework: FfiFrameworkService) -> Self {
        let mut tables: HashMap<String, u64> = [
            (
                "AntennaStatusTable",
                &[
                    "Index",
                    "Profile",
                    "Bandwidth",
                    "Rx Frequency",
                    "Fixed Gain",
                    "Azimuth",
                    "Elevation",
                    "Mask",
                ][..],
            ),
            (
                "NeighborStatusTable",
                &[
                    "NEM",
                    "Transponder",
                    "SINR_wma",
                    "NF_wma",
                    "Samples",
                    "SINR_avg",
                    "NF_avg",
                    "Timestamp",
                ],
            ),
            (
                "QueueStatusTable",
                &[
                    "Transponder",
                    "Enqueued",
                    "Dequeued",
                    "Overflow",
                    "Too Big",
                    "Depth",
                    "High Water",
                ],
            ),
            (
                "QueueFragmentHistogram",
                &[
                    "Transponder",
                    "1",
                    "2",
                    "3",
                    "4",
                    "5",
                    "6",
                    "7",
                    "8",
                    "9",
                    ">9",
                ],
            ),
            (
                "QueueAggregateHistogram",
                &[
                    "Transponder",
                    "1",
                    "2",
                    "3",
                    "4",
                    "5",
                    "6",
                    "7",
                    "8",
                    "9",
                    ">9",
                ],
            ),
            (
                "TxSlotStatusTable",
                &[
                    "Transponder",
                    "Valid",
                    "Missed",
                    ".25",
                    ".50",
                    ".75",
                    "1.0",
                    "1.25",
                    "1.50",
                    "1.75",
                    ">1.75",
                ],
            ),
            (
                "TransponderStatusTable",
                &[
                    "Idx",
                    "Rx Hz",
                    "Rx Bw",
                    "Rx Ant",
                    "Rx Enable",
                    "Action",
                    "Tx Hz",
                    "Tx Bw",
                    "Tx Bps",
                    "Tx Ant",
                    "Tx dBm",
                    "Tx Enable",
                ],
            ),
            (
                "TransponderStatusExTable",
                &["Idx", "Tx U_Delay", "Tx Slots/Frame", "Tx Slot Size", "MTU"],
            ),
        ]
        .into_iter()
        .filter_map(|(name, labels)| {
            let c_name = std::ffi::CString::new(name).ok()?;
            let c_labels = labels
                .iter()
                .map(|label| std::ffi::CString::new(*label))
                .collect::<Result<Vec<_>, _>>()
                .ok()?;
            let pointers = c_labels
                .iter()
                .map(|label| label.as_ptr())
                .collect::<Vec<_>>();
            let handle = (framework.register_table)(
                framework.framework_ctx,
                c_name.as_ptr(),
                pointers.as_ptr(),
                pointers.len(),
                c"BentPipe model status".as_ptr(),
                false,
            );
            (handle != 0).then(|| (name.to_string(), handle))
        })
        .collect();
        let mut register_packet_table = |name: &str, labels: &[&str]| {
            let Ok(c_name) = std::ffi::CString::new(name) else {
                return;
            };
            let Ok(c_labels) = labels
                .iter()
                .map(|label| std::ffi::CString::new(*label))
                .collect::<Result<Vec<_>, _>>()
            else {
                return;
            };
            let pointers = c_labels
                .iter()
                .map(|label| label.as_ptr())
                .collect::<Vec<_>>();
            let handle = (framework.register_table)(
                framework.framework_ctx,
                c_name.as_ptr(),
                pointers.as_ptr(),
                pointers.len(),
                c"BentPipe packet status".as_ptr(),
                true,
            );
            if handle != 0 {
                tables.insert(name.to_string(), handle);
            }
        };
        for name in ["BroadcastByteAcceptTable0", "UnicastByteAcceptTable0"] {
            register_packet_table(name, &["NEM", "Num Bytes Tx", "Num Bytes Rx"]);
        }
        for name in ["BroadcastByteDropTable0", "UnicastByteDropTable0"] {
            register_packet_table(
                name,
                &[
                    "NEM",
                    "SINR",
                    "Reg Id",
                    "Dst MAC",
                    "Queue Overflow",
                    "Bad Control",
                    "Bad Spectrum Query",
                    "Big",
                    "Long",
                    "Miss Fragment",
                    "Bad Curve",
                    "Lock",
                    "Rx Off",
                    "Tx off",
                ],
            );
        }
        Self {
            id,
            framework,
            tables,
            state: Mutex::new(State {
                transponders: BTreeMap::new(),
                configured_transponder_fields: HashMap::new(),
                queues: HashMap::new(),
                queue_statistics: HashMap::new(),
                slot_statistics: HashMap::new(),
                neighbor_statistics: HashMap::new(),
                broadcast_accept: HashMap::new(),
                broadcast_drop: HashMap::new(),
                unicast_accept: HashMap::new(),
                unicast_drop: HashMap::new(),
                table_generations: HashMap::new(),
                queue_depth: DEFAULT_QUEUE_DEPTH,
                aggregation_enable: true,
                fragmentation_enable: true,
                antennas: HashMap::new(),
                fragment_check_us: 2_000_000,
                fragment_timeout_us: 5_000_000,
                pcr_uri: String::new(),
                pcr: PCRManager::new(),
                packet_sequence: 0,
                frame_sequence: 0,
                current_eot: HashMap::new(),
                receive_end: HashMap::new(),
                wakeups: HashMap::new(),
                timers: HashSet::new(),
                next_receive_id: 0,
                pending_receptions: HashMap::new(),
                receive_candidates: BTreeMap::new(),
                reassembly: HashMap::new(),
                receive_random: HashMap::new(),
                started: false,
            }),
        }
    }

    fn set_table_row(&self, name: &str, key: &[u64], values: &[FfiStatisticValue]) {
        if let Some(handle) = self.tables.get(name).copied() {
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

    fn table_generation(&self, name: &str) -> u64 {
        self.tables.get(name).copied().map_or(0, |handle| {
            (self.framework.table_generation)(self.framework.framework_ctx, handle)
        })
    }
}

fn stat_u64(value: u64) -> FfiStatisticValue {
    FfiStatisticValue {
        value_type: STATISTIC_VALUE_U64,
        u64_value: value,
        f64_value: 0.0,
        string_value: std::ptr::null(),
    }
}

fn stat_f64(value: f64) -> FfiStatisticValue {
    FfiStatisticValue {
        value_type: STATISTIC_VALUE_F64,
        u64_value: 0,
        f64_value: value,
        string_value: std::ptr::null(),
    }
}

fn stat_string(value: &CStr) -> FfiStatisticValue {
    FfiStatisticValue {
        value_type: STATISTIC_VALUE_STRING,
        u64_value: 0,
        f64_value: 0.0,
        string_value: value.as_ptr(),
    }
}

fn publish_configuration_tables(mac: &BentpipeMac, state: &State) {
    for (index, transponder) in &state.transponders {
        let enabled_rx = if transponder.receive_enable {
            c"on"
        } else {
            c"off"
        };
        let enabled_tx = if transponder.transmit_enable {
            c"on"
        } else {
            c"off"
        };
        let action = match transponder.receive_action {
            ReceiveAction::Ubend => c"ubend",
            ReceiveAction::Process => c"process",
            ReceiveAction::Unknown => c"unknown",
        };
        mac.set_table_row(
            "TransponderStatusTable",
            &[u64::from(*index)],
            &[
                stat_u64(u64::from(*index)),
                stat_u64(transponder.receive_frequency_hz),
                stat_u64(transponder.receive_bandwidth_hz),
                stat_u64(u64::from(transponder.receive_antenna_index)),
                stat_string(enabled_rx),
                stat_string(action),
                stat_u64(transponder.transmit_frequency_hz),
                stat_u64(transponder.transmit_bandwidth_hz),
                stat_u64(transponder.transmit_data_rate_bps),
                stat_u64(u64::from(transponder.transmit_antenna_index)),
                stat_f64(transponder.transmit_power_dbm),
                stat_string(enabled_tx),
            ],
        );
        mac.set_table_row(
            "TransponderStatusExTable",
            &[u64::from(*index)],
            &[
                stat_u64(u64::from(*index)),
                stat_u64(transponder.transmit_delay_us),
                stat_u64(u64::from(transponder.transmit_slots_per_frame)),
                stat_u64(transponder.transmit_slot_size_us),
                stat_u64(effective_mtu(transponder) as u64),
            ],
        );
    }

    for (antenna_index, antenna) in &state.antennas {
        for transponder in state
            .transponders
            .values()
            .filter(|transponder| transponder.receive_antenna_index == *antenna_index)
        {
            let (profile, fixed_gain, azimuth, elevation) = match antenna.pattern {
                AntennaPattern::Profile(profile) => (
                    stat_u64(u64::from(profile.profile_id)),
                    stat_string(c"NA"),
                    stat_f64(profile.azimuth_degrees),
                    stat_f64(profile.elevation_degrees),
                ),
                AntennaPattern::IdealOmni { gain_db } => (
                    stat_string(c"NA"),
                    stat_f64(gain_db),
                    stat_string(c"NA"),
                    stat_string(c"NA"),
                ),
                AntennaPattern::Default => continue,
            };
            mac.set_table_row(
                "AntennaStatusTable",
                &[u64::from(*antenna_index), transponder.receive_frequency_hz],
                &[
                    stat_u64(u64::from(*antenna_index)),
                    profile,
                    stat_u64(transponder.receive_bandwidth_hz),
                    stat_u64(transponder.receive_frequency_hz),
                    fixed_gain,
                    azimuth,
                    elevation,
                    stat_u64(u64::from(antenna.spectral_mask_index)),
                ],
            );
        }
    }
}

fn publish_queue_tables(mac: &BentpipeMac, state: &State, index: u16) {
    let Some(statistics) = state.queue_statistics.get(&index) else {
        return;
    };
    let depth = state.queues.get(&index).map_or(0, VecDeque::len) as u64;
    mac.set_table_row(
        "QueueStatusTable",
        &[u64::from(index)],
        &[
            stat_u64(u64::from(index)),
            stat_u64(statistics.enqueued),
            stat_u64(statistics.dequeued),
            stat_u64(statistics.overflow),
            stat_u64(statistics.too_big),
            stat_u64(depth),
            stat_u64(statistics.high_water),
        ],
    );
    for (name, histogram) in [
        ("QueueFragmentHistogram", &statistics.fragment_histogram),
        ("QueueAggregateHistogram", &statistics.aggregate_histogram),
    ] {
        let mut values = Vec::with_capacity(11);
        values.push(stat_u64(u64::from(index)));
        values.extend(histogram.iter().copied().map(stat_u64));
        mac.set_table_row(name, &[u64::from(index)], &values);
    }
}

fn update_slot_statistics(
    mac: &BentpipeMac,
    state: &mut State,
    index: u16,
    valid: bool,
    ratio: f64,
) {
    let statistics = state.slot_statistics.entry(index).or_default();
    if valid {
        statistics.valid += 1;
    } else {
        statistics.missed += 1;
    }
    let quantile = if ratio <= 0.25 {
        0
    } else if ratio <= 0.50 {
        1
    } else if ratio <= 0.75 {
        2
    } else if ratio <= 1.0 {
        3
    } else if ratio <= 1.25 {
        4
    } else if ratio <= 1.50 {
        5
    } else if ratio <= 1.75 {
        6
    } else {
        7
    };
    statistics.quantiles[quantile] += 1;
    let mut values = vec![
        stat_u64(u64::from(index)),
        stat_u64(statistics.valid),
        stat_u64(statistics.missed),
    ];
    values.extend(statistics.quantiles.iter().copied().map(stat_u64));
    mac.set_table_row("TxSlotStatusTable", &[u64::from(index)], &values);
}

fn weighted_moving_average(samples: &VecDeque<f64>) -> f64 {
    let denominator = samples.len() * (samples.len() + 1) / 2;
    if denominator == 0 {
        0.0
    } else {
        samples
            .iter()
            .enumerate()
            .map(|(index, sample)| *sample * (index + 1) as f64)
            .sum::<f64>()
            / denominator as f64
    }
}

fn update_neighbor_statistics(
    mac: &BentpipeMac,
    state: &mut State,
    remote: u16,
    transponder: u16,
    sinr: f64,
    noise_floor: f64,
    timestamp: u64,
) {
    let statistics = state
        .neighbor_statistics
        .entry((remote, transponder))
        .or_default();
    statistics.samples += 1;
    statistics.sinr_sum += sinr;
    statistics.noise_floor_sum += noise_floor;
    for (window, sample) in [
        (&mut statistics.sinr_window, sinr),
        (&mut statistics.noise_floor_window, noise_floor),
    ] {
        if window.len() == 20 {
            window.pop_front();
        }
        window.push_back(sample);
    }
    mac.set_table_row(
        "NeighborStatusTable",
        &[u64::from(remote), u64::from(transponder)],
        &[
            stat_u64(u64::from(remote)),
            stat_u64(u64::from(transponder)),
            stat_f64(weighted_moving_average(&statistics.sinr_window)),
            stat_f64(weighted_moving_average(&statistics.noise_floor_window)),
            stat_u64(statistics.samples),
            stat_f64(statistics.sinr_sum / statistics.samples as f64),
            stat_f64(statistics.noise_floor_sum / statistics.samples as f64),
            stat_u64(timestamp),
        ],
    );
}

fn record_packet_accept(
    mac: &BentpipeMac,
    state: &mut State,
    source: u16,
    destination: u16,
    size: usize,
    inbound: bool,
) {
    let broadcast = destination == BROADCAST_NEM;
    let name = if broadcast {
        "BroadcastByteAcceptTable0"
    } else {
        "UnicastByteAcceptTable0"
    };
    let generation = mac.table_generation(name);
    let reset = state
        .table_generations
        .insert(name.to_string(), generation)
        .is_some_and(|previous| previous != generation);
    let infos = if broadcast {
        &mut state.broadcast_accept
    } else {
        &mut state.unicast_accept
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
    mac.set_table_row(
        name,
        &[u64::from(source)],
        &[
            stat_u64(u64::from(source)),
            stat_u64(info.tx_bytes),
            stat_u64(info.rx_bytes),
        ],
    );
}

fn record_packet_drop(
    mac: &BentpipeMac,
    state: &mut State,
    source: u16,
    destination: u16,
    size: usize,
    reason: PacketDropReason,
) {
    let broadcast = destination == BROADCAST_NEM;
    let name = if broadcast {
        "BroadcastByteDropTable0"
    } else {
        "UnicastByteDropTable0"
    };
    let generation = mac.table_generation(name);
    let reset = state
        .table_generations
        .insert(name.to_string(), generation)
        .is_some_and(|previous| previous != generation);
    let infos = if broadcast {
        &mut state.broadcast_drop
    } else {
        &mut state.unicast_drop
    };
    if reset {
        infos.clear();
    }
    let info = infos.entry(source).or_default();
    info.bytes[reason as usize] = info.bytes[reason as usize].saturating_add(size as u64);
    let mut row = Vec::with_capacity(14);
    row.push(stat_u64(u64::from(source)));
    row.extend(info.bytes.iter().copied().map(stat_u64));
    mac.set_table_row(name, &[u64::from(source)], &row);
}

fn record_component_drops(
    mac: &BentpipeMac,
    state: &mut State,
    source: u16,
    components: &[BentPipeComponent],
    reason: PacketDropReason,
) {
    for component in components {
        if let Ok(destination) = u16::try_from(component.destination) {
            record_packet_drop(
                mac,
                state,
                source,
                destination,
                component.data.len(),
                reason,
            );
        }
    }
}

fn expire_reassembly(mac: &BentpipeMac, state: &mut State, now: i64) {
    let timeout = state.fragment_timeout_us;
    let expired = state
        .reassembly
        .iter()
        .filter_map(|(key, entry)| {
            (now.saturating_sub(entry.last_update) >= timeout).then_some(*key)
        })
        .collect::<Vec<_>>();
    for key in expired {
        if let Some(entry) = state.reassembly.remove(&key) {
            let size = entry.parts.values().map(|(_, data)| data.len()).sum();
            record_packet_drop(
                mac,
                state,
                key.0,
                entry.destination,
                size,
                PacketDropReason::MissingFragment,
            );
        }
    }
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "on" | "yes" | "true" => Some(true),
        "0" | "off" | "no" | "false" => Some(false),
        _ => None,
    }
}

fn parse_scaled_u64(value: &str) -> Option<u64> {
    let (number, multiplier) = match value.as_bytes().last().copied() {
        Some(b'K' | b'k') => (&value[..value.len() - 1], 1_000.0),
        Some(b'M' | b'm') => (&value[..value.len() - 1], 1_000_000.0),
        Some(b'G' | b'g') => (&value[..value.len() - 1], 1_000_000_000.0),
        _ => (value, 1.0),
    };
    let value = number.parse::<f64>().ok()? * multiplier;
    (value.is_finite() && value >= 0.0 && value <= u64::MAX as f64).then_some(value.round() as u64)
}

fn split_index(value: &str) -> Option<(u16, &str)> {
    let (index, value) = value.split_once(':')?;
    Some((index.parse().ok()?, value))
}

fn transponder_config_bit(name: &str) -> Option<u32> {
    const NAMES: [&str; 18] = [
        "transponder.receive.frequency",
        "transponder.receive.bandwidth",
        "transponder.receive.antenna",
        "transponder.receive.action",
        "transponder.receive.enable",
        "transponder.transmit.pcrcurveindex",
        "transponder.transmit.frequency",
        "transponder.transmit.bandwidth",
        "transponder.transmit.antenna",
        "transponder.transmit.ubend.delay",
        "transponder.transmit.datarate",
        "transponder.transmit.power",
        "transponder.transmit.tosmap",
        "transponder.transmit.slotperframe",
        "transponder.transmit.slotsize",
        "transponder.transmit.txslots",
        "transponder.transmit.mtu",
        "transponder.transmit.enable",
    ];
    NAMES
        .iter()
        .position(|candidate| *candidate == name)
        .map(|index| 1u32 << index)
}

const TRANSPONDER_REQUIRED_FIELDS: u32 = (1 << 18) - 1;
const TRANSPONDER_TOSMAP_FIELD: u32 = 1 << 12;

fn required_transponder_fields(action: ReceiveAction) -> u32 {
    if action == ReceiveAction::Ubend {
        // U-bend transponders relay received frames and never classify locally
        // originated traffic, so the guide does not define a TOS map for each
        // one.
        TRANSPONDER_REQUIRED_FIELDS & !TRANSPONDER_TOSMAP_FIELD
    } else {
        TRANSPONDER_REQUIRED_FIELDS
    }
}

fn parse_antenna(value: &str) -> Option<(u16, AntennaDefinition)> {
    let (index, definition) = split_index(value)?;
    let fields: Vec<_> = definition.split(';').collect();
    let (pattern, spectral_mask_index) = match fields.as_slice() {
        ["omni", gain, mask] => {
            let gain_db = gain.parse::<f64>().ok()?;
            if !gain_db.is_finite() {
                return None;
            }
            (AntennaPattern::IdealOmni { gain_db }, mask.parse().ok()?)
        }
        [profile, azimuth, elevation, mask] => {
            let profile = TxAntennaProfile {
                profile_id: profile.parse().ok()?,
                azimuth_degrees: azimuth.parse().ok()?,
                elevation_degrees: elevation.parse().ok()?,
            };
            profile.encode()?;
            (AntennaPattern::Profile(profile), mask.parse().ok()?)
        }
        _ => return None,
    };
    Some((
        index,
        AntennaDefinition {
            pattern,
            spectral_mask_index,
        },
    ))
}

fn parse_ranges(value: &str) -> Option<HashSet<u8>> {
    let mut result = HashSet::new();
    if value == "na" {
        return Some(result);
    }
    for item in value.split(';') {
        if let Some((start, end)) = item.split_once('-') {
            let (start, end) = (start.parse::<u8>().ok()?, end.parse::<u8>().ok()?);
            if start > end {
                return None;
            }
            result.extend(start..=end);
        } else {
            result.insert(item.parse().ok()?);
        }
    }
    Some(result)
}

fn parse_slots(value: &str) -> Option<Vec<u16>> {
    if value == "na" {
        return Some(Vec::new());
    }
    let mut result = Vec::new();
    for item in value.split(';') {
        if let Some((start, end)) = item.split_once('-') {
            let (start, end) = (start.parse::<u16>().ok()?, end.parse::<u16>().ok()?);
            if start > end {
                return None;
            }
            result.extend(start..=end);
        } else {
            result.push(item.parse().ok()?);
        }
    }
    result.sort_unstable();
    result.dedup();
    Some(result)
}

fn configuration(request: *const c_void) -> Option<Vec<(String, Vec<String>)>> {
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
        if item.name.is_null()
            || item.values.len > 4096
            || (item.values.len != 0 && item.values.data.is_null())
        {
            return None;
        }
        let name = unsafe { CStr::from_ptr(item.name) }
            .to_str()
            .ok()?
            .to_string();
        let pointers = if item.values.len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(item.values.data, item.values.len) }
        };
        let mut values = Vec::with_capacity(pointers.len());
        for pointer in pointers {
            if pointer.is_null() {
                return None;
            }
            values.push(
                unsafe { CStr::from_ptr(*pointer) }
                    .to_str()
                    .ok()?
                    .to_string(),
            );
        }
        result.push((name, values));
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

fn airtime(bytes: usize, rate: u64) -> u64 {
    (bytes as u64)
        .saturating_mul(8_000_000)
        .saturating_add(rate.saturating_sub(1))
        .checked_div(rate)
        .unwrap_or(0)
}

fn next_slot(transponder: &Transponder, now: i64) -> i64 {
    if transponder.transmit_slots.is_empty()
        || transponder.transmit_slots_per_frame == 0
        || transponder.transmit_slot_size_us == 0
    {
        return now;
    }
    let size = transponder.transmit_slot_size_us as i64;
    let absolute_slot = now.div_euclid(size);
    let current = absolute_slot.rem_euclid(i64::from(transponder.transmit_slots_per_frame)) as u16;
    for slot in &transponder.transmit_slots {
        if *slot > current || (*slot == current && now % size == 0) {
            return (absolute_slot + i64::from(*slot) - i64::from(current)) * size;
        }
    }
    let first = i64::from(transponder.transmit_slots[0]);
    (absolute_slot + i64::from(transponder.transmit_slots_per_frame) - i64::from(current) + first)
        * size
}

fn effective_mtu(transponder: &Transponder) -> usize {
    if transponder.transmit_mtu_bytes != 0 {
        transponder.transmit_mtu_bytes
    } else if transponder.transmit_slot_size_us != 0 {
        ((transponder.transmit_data_rate_bps as u128 * transponder.transmit_slot_size_us as u128)
            / 8_000_000) as usize
    } else {
        0
    }
}

fn enqueue(
    mac: &BentpipeMac,
    state: &mut State,
    index: u16,
    packet: OwnedPacket,
    ready_at: i64,
) -> bool {
    let Some(transponder) = state.transponders.get(&index) else {
        return false;
    };
    if !transponder.transmit_enable {
        return false;
    }
    let mtu = effective_mtu(transponder);
    if mtu == 0 {
        return false;
    }
    if state.queue_depth == 0 {
        state.queue_statistics.entry(index).or_default().overflow += 1;
        record_packet_drop(
            mac,
            state,
            packet.info.source,
            packet.info.destination,
            packet.payload.len(),
            PacketDropReason::QueueOverflow,
        );
        publish_queue_tables(mac, state, index);
        return true;
    }
    let sequence = state.packet_sequence;
    state.packet_sequence = state.packet_sequence.wrapping_add(1);
    let (dropped_packets, depth) = {
        let queue = state.queues.entry(index).or_default();
        let mut dropped_packets = Vec::new();
        while queue.len() >= state.queue_depth {
            let position = queue
                .iter()
                .position(|entry| entry.offset == 0)
                .unwrap_or(0);
            dropped_packets.push(
                queue
                    .remove(position)
                    .expect("a full BentPipe queue must contain a packet"),
            );
        }
        queue.push_back(PendingTx {
            packet,
            sequence,
            offset: 0,
            fragment_index: 0,
            ready_at,
        });
        (dropped_packets, queue.len() as u64)
    };
    state.queue_statistics.entry(index).or_default().overflow += dropped_packets.len() as u64;
    for dropped in dropped_packets {
        record_packet_drop(
            mac,
            state,
            dropped.packet.info.source,
            dropped.packet.info.destination,
            dropped.packet.payload.len(),
            PacketDropReason::QueueOverflow,
        );
    }
    let statistics = state.queue_statistics.entry(index).or_default();
    statistics.enqueued += 1;
    statistics.high_water = statistics.high_water.max(depth);
    publish_queue_tables(mac, state, index);
    true
}

fn dequeue_components(
    mac: &BentpipeMac,
    state: &mut State,
    index: u16,
    mtu: usize,
    now: i64,
) -> Vec<TxComponent> {
    let aggregate = state.aggregation_enable;
    let fragment = state.fragmentation_enable;
    let Some(queue) = state.queues.get_mut(&index) else {
        return Vec::new();
    };
    let mut components = Vec::new();
    let mut dropped_packets = Vec::new();
    let mut used = 0usize;

    while used < mtu {
        let Some(front) = queue.front() else { break };
        if front.ready_at > now {
            break;
        }
        let remaining = front.packet.payload.len().saturating_sub(front.offset);
        if remaining == 0 {
            queue.pop_front();
            continue;
        }
        let available = mtu - used;
        if remaining <= available {
            let pending = queue.pop_front().expect("queue front");
            let mut packet = pending.packet;
            packet.payload = packet.payload[pending.offset..].to_vec();
            used += remaining;
            components.push(TxComponent {
                packet,
                sequence: pending.sequence,
                offset: pending.offset,
                fragment_index: pending.fragment_index,
                more: false,
                fragmented: pending.offset != 0,
            });
            if !aggregate {
                break;
            }
        } else if fragment {
            let pending = queue.front_mut().expect("queue front");
            let end = pending.offset + available;
            let mut packet = pending.packet.clone();
            packet.payload = packet.payload[pending.offset..end].to_vec();
            components.push(TxComponent {
                packet,
                sequence: pending.sequence,
                offset: pending.offset,
                fragment_index: pending.fragment_index,
                more: true,
                fragmented: true,
            });
            pending.offset = end;
            pending.fragment_index = pending.fragment_index.saturating_add(1);
            break;
        } else {
            // Legacy strict dequeue drops an oversized head packet so it cannot
            // permanently block smaller packets behind it.
            let dropped = queue.pop_front().expect("queue front");
            dropped_packets.push(dropped);
        }
    }
    state.queue_statistics.entry(index).or_default().too_big += dropped_packets.len() as u64;
    for dropped in dropped_packets {
        record_packet_drop(
            mac,
            state,
            dropped.packet.info.source,
            dropped.packet.info.destination,
            dropped.packet.payload.len(),
            PacketDropReason::TooBig,
        );
    }
    if !components.is_empty() {
        let statistics = state.queue_statistics.entry(index).or_default();
        let completed = components
            .iter()
            .filter(|component| !component.more)
            .count() as u64;
        statistics.dequeued += completed;
        for component in &components {
            if !component.more {
                let parts = usize::try_from(component.fragment_index)
                    .unwrap_or(usize::MAX)
                    .saturating_add(1);
                statistics.fragment_histogram[parts.saturating_sub(1).min(9)] += 1;
            }
        }
        statistics.aggregate_histogram[components.len().saturating_sub(1).min(9)] += 1;
    }
    publish_queue_tables(mac, state, index);
    components
}

fn schedule_transmit(mac: &BentpipeMac, index: u16, when: i64) {
    let schedule = {
        let mut state = mac.state.lock().unwrap();
        if !state.started || state.wakeups.get(&index).is_some_and(|old| *old <= when) {
            false
        } else {
            state.wakeups.insert(index, when);
            true
        }
    };
    if !schedule {
        return;
    }
    let mut data = Vec::with_capacity(10);
    data.extend_from_slice(&index.to_be_bytes());
    data.extend_from_slice(&when.to_be_bytes());
    let when = when.max(0) as u64;
    let timer = (mac.framework.schedule_timed_event)(
        mac.framework.framework_ctx,
        mac.id,
        when / 1_000_000,
        (when % 1_000_000) as u32,
        EVENT_TRANSMIT,
        data.as_ptr(),
        data.len(),
    );
    if timer != 0 {
        mac.state.lock().unwrap().timers.insert(timer);
    }
}

fn schedule_reassembly_check(mac: &BentpipeMac) {
    let when = {
        let state = mac.state.lock().unwrap();
        if !state.started {
            return;
        }
        now_us().saturating_add(state.fragment_check_us)
    };
    let when_u64 = when.max(0) as u64;
    let timer = (mac.framework.schedule_timed_event)(
        mac.framework.framework_ctx,
        mac.id,
        when_u64 / 1_000_000,
        (when_u64 % 1_000_000) as u32,
        EVENT_REASSEMBLY_CHECK,
        std::ptr::null(),
        0,
    );
    if timer != 0 {
        mac.state.lock().unwrap().timers.insert(timer);
    }
}

fn schedule_receive(mac: &BentpipeMac, packet: OwnedPacket, when: i64) {
    let id = {
        let mut state = mac.state.lock().unwrap();
        state.next_receive_id = state.next_receive_id.wrapping_add(1).max(1);
        let id = state.next_receive_id;
        state.pending_receptions.insert(id, packet);
        id
    };
    let when = when.max(0) as u64;
    let data = id.to_be_bytes();
    let timer = (mac.framework.schedule_timed_event)(
        mac.framework.framework_ctx,
        mac.id,
        when / 1_000_000,
        (when % 1_000_000) as u32,
        EVENT_RECEIVE,
        data.as_ptr(),
        data.len(),
    );
    if timer == 0 {
        if let Some(packet) = mac.state.lock().unwrap().pending_receptions.remove(&id) {
            send_upstream(mac, packet);
        }
    } else {
        mac.state.lock().unwrap().timers.insert(timer);
    }
}

fn send_downstream(
    mac: &BentpipeMac,
    components: Vec<TxComponent>,
    frame_sequence: u64,
    transponder: &Transponder,
    antenna: AntennaDefinition,
) {
    {
        let mut state = mac.state.lock().unwrap();
        for component in &components {
            record_packet_accept(
                mac,
                &mut state,
                mac.id,
                component.packet.info.destination,
                component.packet.payload.len(),
                false,
            );
        }
    }
    let start_of_transmission = now_us();
    let wire = BentPipeMessage {
        start_of_transmission_microseconds: start_of_transmission.max(0) as u64,
        curve_index: u32::from(transponder.curve_index),
        messages: components
            .iter()
            .map(|component| BentPipeComponent {
                destination: u32::from(component.packet.info.destination),
                data: component.packet.payload.clone(),
                fragment: component.fragmented.then_some(BentPipeFragment {
                    more: component.more,
                    index: component.fragment_index,
                    offset: u32::try_from(component.offset).unwrap_or(u32::MAX),
                    sequence: component.sequence,
                }),
            })
            .collect(),
    };
    let serialization = wire.encode_to_vec();
    let Ok(serialization_len) = u16::try_from(serialization.len()) else {
        return;
    };
    let mut payload = Vec::with_capacity(serialization.len() + 2);
    payload.extend_from_slice(&serialization_len.to_be_bytes());
    payload.extend_from_slice(&serialization);
    let destination = components
        .first()
        .map(|component| component.packet.info.destination)
        .filter(|destination| {
            components
                .iter()
                .all(|component| component.packet.info.destination == *destination)
        })
        .unwrap_or(BROADCAST_NEM);
    let total_data_bytes = components
        .iter()
        .map(|component| component.packet.payload.len())
        .sum::<usize>();
    let header = ModelHeader {
        registration_id: MAC_REGISTRATION_BENTPIPE,
        sequence: frame_sequence,
        data_rate_bps: transponder.transmit_data_rate_bps,
        category: 0,
        message_type: BENTPIPE_MESSAGE_TYPE,
        flags: transponder.curve_index,
    };
    let header_bytes = header.encode();
    let duration = airtime(total_data_bytes, transponder.transmit_data_rate_bps).max(1);
    let tx_bytes = TxProperties {
        frequency_hz: transponder.transmit_frequency_hz,
        bandwidth_hz: transponder.transmit_bandwidth_hz,
        tx_power_dbm: transponder.transmit_power_dbm
            + match antenna.pattern {
                AntennaPattern::IdealOmni { gain_db } => gain_db,
                _ => 0.0,
            },
        duration_microseconds: duration,
        offset_microseconds: 0,
        tx_time_microseconds: start_of_transmission,
        antenna_index: transponder.transmit_antenna_index,
        spectral_mask_index: antenna.spectral_mask_index,
        sub_id: 0,
    }
    .encode();
    let mimo_bytes = MimoTxProperties {
        frequency_groups: vec![vec![MimoTxFrequencySegment {
            frequency_hz: transponder.transmit_frequency_hz,
            tx_power_dbm: Some(transponder.transmit_power_dbm),
            duration_microseconds: duration,
            offset_microseconds: 0,
        }]],
        transmit_antennas: vec![MimoTxAntenna {
            frequency_group_index: 0,
            antenna_index: transponder.transmit_antenna_index,
            bandwidth_hz: transponder.transmit_bandwidth_hz,
            spectral_mask_index: antenna.spectral_mask_index,
            pattern: antenna.pattern,
        }],
    }
    .encode()
    .expect("validated BentPipe antenna");
    let mut messages: Vec<_> = components
        .first()
        .map(|component| component.packet.controls.as_slice())
        .unwrap_or_default()
        .iter()
        .filter(|control| {
            control.msg_type != CONTROL_MODEL_HEADER
                && control.msg_type != CONTROL_TX_PROPERTIES
                && control.msg_type != CONTROL_MIMO_TX_PROPERTIES
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
        msg_type: CONTROL_MIMO_TX_PROPERTIES,
        payload: FfiSlice {
            data: mimo_bytes.as_ptr(),
            len: mimo_bytes.len(),
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
        info: FfiPacketInfo {
            uuid: [0; 16],
            source: mac.id,
            destination,
            priority: 0,
            creation_time_sec: start_of_transmission.max(0) as u64 / 1_000_000,
            creation_time_usec: start_of_transmission.rem_euclid(1_000_000) as u32,
        },
        payload: FfiSlice {
            data: payload.as_ptr(),
            len: payload.len(),
        },
    };
    (mac.framework.send_downstream_packet)(
        mac.framework.framework_ctx,
        mac.id,
        &packet,
        messages.as_ptr(),
        messages.len(),
    );
}

fn drive(mac: &BentpipeMac, index: u16, now: i64, expected: Option<i64>) {
    let (components, frame_sequence, transponder, antenna, next) = 'decision: {
        let mut state = mac.state.lock().unwrap();
        let Some(transponder) = state.transponders.get(&index).cloned() else {
            return;
        };
        let Some(antenna) = state
            .antennas
            .get(&transponder.transmit_antenna_index)
            .copied()
        else {
            return;
        };
        let slotted = transponder.transmit_slot_size_us != 0
            && transponder.transmit_slots_per_frame != 0
            && !transponder.transmit_slots.is_empty();
        let allowed = expected
            .filter(|_| slotted)
            .unwrap_or_else(|| next_slot(&transponder, now));
        if let Some(expected) = expected.filter(|_| slotted) {
            let ratio = now.saturating_sub(expected) as f64
                / transponder.transmit_slot_size_us.max(1) as f64;
            let valid = now < expected.saturating_add(transponder.transmit_slot_size_us as i64);
            update_slot_statistics(mac, &mut state, index, valid, ratio);
            if !valid {
                let next = next_slot(&transponder, now);
                break 'decision (
                    Vec::new(),
                    state.frame_sequence,
                    transponder,
                    antenna,
                    Some(next),
                );
            }
        }
        let eot = state.current_eot.get(&index).copied().unwrap_or(0);
        let ready = state
            .queues
            .get(&index)
            .and_then(VecDeque::front)
            .map(|item| item.ready_at);
        let can_send = ready.is_some_and(|ready| ready <= now) && eot <= now && allowed <= now;
        let components = if can_send {
            let mtu = effective_mtu(&transponder);
            let components = dequeue_components(mac, &mut state, index, mtu, now);
            if !components.is_empty() {
                let bytes = components
                    .iter()
                    .map(|component| component.packet.payload.len())
                    .sum();
                state.current_eot.insert(
                    index,
                    now.saturating_add(airtime(bytes, transponder.transmit_data_rate_bps) as i64),
                );
            }
            components
        } else {
            Vec::new()
        };
        let frame_sequence = state.frame_sequence;
        if !components.is_empty() {
            state.frame_sequence = state.frame_sequence.wrapping_add(1);
        }
        let next = state
            .queues
            .get(&index)
            .and_then(VecDeque::front)
            .map(|item| {
                next_slot(
                    &transponder,
                    item.ready_at
                        .max(*state.current_eot.get(&index).unwrap_or(&0))
                        .max(now),
                )
            });
        (components, frame_sequence, transponder, antenna, next)
    };
    if !components.is_empty() {
        send_downstream(mac, components, frame_sequence, &transponder, antenna);
    }
    if let Some(next) = next {
        schedule_transmit(mac, index, next);
    }
}

fn send_upstream(mac: &BentpipeMac, packet: OwnedPacket) {
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
    (mac.framework.send_upstream_packet)(
        mac.framework.framework_ctx,
        mac.id,
        &view,
        messages.as_ptr(),
        messages.len(),
    );
}

extern "C" fn init(id: u16, framework: *const FfiFrameworkService) -> *mut c_void {
    let Some(framework) = (unsafe { framework.as_ref() }) else {
        return std::ptr::null_mut();
    };
    Box::into_raw(Box::new(BentpipeMac::new(id, *framework))).cast()
}

extern "C" fn configure(plugin: *mut c_void, request: *const c_void) -> bool {
    let Some(mac) = (unsafe { (plugin as *mut BentpipeMac).as_ref() }) else {
        return false;
    };
    let Some(items) = configuration(request) else {
        return false;
    };
    let mut state = mac.state.lock().unwrap();
    let mut refresh_receive_antennas = false;
    for (name, values) in items {
        match name.as_str() {
            "pcrcurveuri" => {
                let Some(value) = values.first() else {
                    return false;
                };
                state.pcr_uri.clone_from(value);
                continue;
            }
            "queue.depth" => {
                let Some(Ok(value)) = values.first().map(|value| value.parse::<usize>()) else {
                    return false;
                };
                if value > u16::MAX as usize {
                    return false;
                }
                state.queue_depth = value;
                continue;
            }
            "queue.fragmentationenable" => {
                let Some(value) = values.first().and_then(|value| parse_bool(value)) else {
                    return false;
                };
                state.fragmentation_enable = value;
                continue;
            }
            "queue.aggregationenable" => {
                let Some(value) = values.first().and_then(|value| parse_bool(value)) else {
                    return false;
                };
                state.aggregation_enable = value;
                continue;
            }
            "antenna.defines" => {
                let mut antennas = if state.started {
                    state.antennas.clone()
                } else {
                    HashMap::new()
                };
                for value in values {
                    let Some((index, antenna)) = parse_antenna(&value) else {
                        return false;
                    };
                    if state.started && !state.antennas.contains_key(&index) {
                        return false;
                    }
                    if !state.started && antennas.contains_key(&index) {
                        return false;
                    }
                    antennas.insert(index, antenna);
                }
                state.antennas = antennas;
                refresh_receive_antennas = true;
                continue;
            }
            "reassembly.fragmentcheckthreshold" => {
                let Some(Ok(value)) = values.first().map(|value| value.parse::<u16>()) else {
                    return false;
                };
                state.fragment_check_us = i64::from(value) * 1_000_000;
                continue;
            }
            "reassembly.fragmenttimeoutthreshold" => {
                let Some(Ok(value)) = values.first().map(|value| value.parse::<u16>()) else {
                    return false;
                };
                state.fragment_timeout_us = i64::from(value) * 1_000_000;
                continue;
            }
            _ => {}
        }
        for entry in values {
            let Some((index, value)) = split_index(&entry) else {
                return false;
            };
            let Some(field) = transponder_config_bit(&name) else {
                return false;
            };
            if state.started && !state.transponders.contains_key(&index) {
                return false;
            }
            *state
                .configured_transponder_fields
                .entry(index)
                .or_default() |= field;
            let transponder = state.transponders.entry(index).or_default();
            match name.as_str() {
                "transponder.receive.frequency" => {
                    transponder.receive_frequency_hz = match parse_scaled_u64(value) {
                        Some(value) => value,
                        None => return false,
                    };
                    refresh_receive_antennas = true;
                }
                "transponder.receive.bandwidth" => {
                    transponder.receive_bandwidth_hz = match parse_scaled_u64(value) {
                        Some(value) => value,
                        None => return false,
                    }
                }
                "transponder.receive.antenna" => {
                    transponder.receive_antenna_index = match value.parse() {
                        Ok(value) => value,
                        Err(_) => return false,
                    }
                }
                "transponder.receive.action" => {
                    transponder.receive_action = match value {
                        "ubend" => ReceiveAction::Ubend,
                        "process" => ReceiveAction::Process,
                        _ => return false,
                    }
                }
                "transponder.receive.enable" => {
                    transponder.receive_enable = match parse_bool(value) {
                        Some(value) => value,
                        None => return false,
                    }
                }
                "transponder.transmit.pcrcurveindex" => {
                    transponder.curve_index = match value.parse() {
                        Ok(value) => value,
                        Err(_) => return false,
                    }
                }
                "transponder.transmit.frequency" => {
                    transponder.transmit_frequency_hz = match parse_scaled_u64(value) {
                        Some(value) => value,
                        None => return false,
                    }
                }
                "transponder.transmit.bandwidth" => {
                    transponder.transmit_bandwidth_hz = match parse_scaled_u64(value) {
                        Some(value) => value,
                        None => return false,
                    }
                }
                "transponder.transmit.datarate" => {
                    transponder.transmit_data_rate_bps = match parse_scaled_u64(value) {
                        Some(value) => value,
                        None => return false,
                    }
                }
                "transponder.transmit.mtu" => {
                    if value != "na" {
                        transponder.transmit_mtu_bytes = match value.parse() {
                            Ok(value) => value,
                            Err(_) => return false,
                        }
                    }
                }
                "transponder.transmit.antenna" => {
                    transponder.transmit_antenna_index = match value.parse() {
                        Ok(value) => value,
                        Err(_) => return false,
                    }
                }
                "transponder.transmit.power" => {
                    transponder.transmit_power_dbm = match value.parse::<f64>() {
                        Ok(value) if value.is_finite() => value,
                        _ => return false,
                    }
                }
                "transponder.transmit.ubend.delay" => {
                    if value != "na" {
                        transponder.transmit_delay_us = match value.parse() {
                            Ok(value) => value,
                            Err(_) => return false,
                        }
                    }
                }
                "transponder.transmit.slotperframe" => {
                    if value != "na" {
                        transponder.transmit_slots_per_frame = match value.parse() {
                            Ok(value) => value,
                            Err(_) => return false,
                        }
                    }
                }
                "transponder.transmit.slotsize" => {
                    if value != "na" {
                        transponder.transmit_slot_size_us = match value.parse() {
                            Ok(value) => value,
                            Err(_) => return false,
                        }
                    }
                }
                "transponder.transmit.txslots" => {
                    transponder.transmit_slots = match parse_slots(value) {
                        Some(value) => value,
                        None => return false,
                    }
                }
                "transponder.transmit.tosmap" => {
                    if value == "all" {
                        transponder.all_tos = true
                    } else {
                        transponder.tos = match parse_ranges(value) {
                            Some(value) => value,
                            None => return false,
                        }
                    }
                }
                "transponder.transmit.enable" => {
                    transponder.transmit_enable = match parse_bool(value) {
                        Some(value) => value,
                        None => return false,
                    }
                }
                _ => return false,
            }
        }
    }
    if state.started {
        let mut receive_antennas: HashMap<u16, (u64, Vec<u64>)> = HashMap::new();
        let mut receive_channels = HashSet::new();
        for (index, transponder) in &state.transponders {
            let slotted = transponder.transmit_slots_per_frame != 0
                || transponder.transmit_slot_size_us != 0
                || !transponder.transmit_slots.is_empty();
            if transponder.receive_frequency_hz == 0
                || transponder.receive_bandwidth_hz == 0
                || transponder.receive_action == ReceiveAction::Unknown
                || transponder.transmit_frequency_hz == 0
                || transponder.transmit_bandwidth_hz == 0
                || transponder.transmit_data_rate_bps == 0
                || effective_mtu(transponder) == 0
                || !state
                    .antennas
                    .contains_key(&transponder.receive_antenna_index)
                || !state
                    .antennas
                    .contains_key(&transponder.transmit_antenna_index)
                || state
                    .configured_transponder_fields
                    .get(index)
                    .copied()
                    .unwrap_or_default()
                    & required_transponder_fields(transponder.receive_action)
                    != required_transponder_fields(transponder.receive_action)
                || !state.pcr.contains_curve(transponder.curve_index)
                || !receive_channels.insert((
                    transponder.receive_antenna_index,
                    transponder.receive_frequency_hz,
                ))
                || (slotted
                    && (transponder.transmit_slots_per_frame == 0
                        || transponder.transmit_slot_size_us == 0
                        || transponder.transmit_slots.is_empty()))
                || transponder
                    .transmit_slots
                    .iter()
                    .any(|slot| *slot >= transponder.transmit_slots_per_frame)
            {
                return false;
            }
            let receive = receive_antennas
                .entry(transponder.receive_antenna_index)
                .or_insert_with(|| (transponder.receive_bandwidth_hz, Vec::new()));
            if receive.0 != transponder.receive_bandwidth_hz {
                return false;
            }
            receive.1.push(transponder.receive_frequency_hz);
        }
        let definitions = if refresh_receive_antennas {
            let definitions = receive_antennas
                .into_iter()
                .map(|(antenna_index, (bandwidth_hz, mut frequencies_hz))| {
                    frequencies_hz.sort_unstable();
                    frequencies_hz.dedup();
                    let definition = *state.antennas.get(&antenna_index)?;
                    Some(RxAntennaAdd {
                        antenna: MimoTxAntenna {
                            frequency_group_index: 0,
                            antenna_index,
                            bandwidth_hz,
                            spectral_mask_index: definition.spectral_mask_index,
                            pattern: definition.pattern,
                        },
                        frequencies_hz,
                    })
                })
                .collect::<Option<Vec<_>>>();
            let Some(definitions) = definitions else {
                return false;
            };
            Some(definitions)
        } else {
            None
        };
        publish_configuration_tables(mac, &state);
        drop(state);
        if let Some(definitions) = definitions {
            for definition in definitions {
                let remove = RxAntennaRemove {
                    antenna_index: definition.antenna.antenna_index,
                }
                .encode();
                let Some(add) = definition.encode() else {
                    return false;
                };
                let messages = [
                    FfiControlMessage {
                        msg_type: CONTROL_RX_ANTENNA_REMOVE,
                        payload: FfiSlice {
                            data: remove.as_ptr(),
                            len: remove.len(),
                        },
                    },
                    FfiControlMessage {
                        msg_type: CONTROL_RX_ANTENNA_ADD,
                        payload: FfiSlice {
                            data: add.as_ptr(),
                            len: add.len(),
                        },
                    },
                ];
                (mac.framework.send_downstream_control)(
                    mac.framework.framework_ctx,
                    mac.id,
                    messages.as_ptr(),
                    messages.len(),
                );
            }
        }
    }
    true
}

extern "C" fn start(plugin: *mut c_void) -> bool {
    let Some(mac) = (unsafe { (plugin as *mut BentpipeMac).as_ref() }) else {
        return false;
    };
    let mut state = mac.state.lock().unwrap();
    if state.antennas.is_empty() || state.transponders.is_empty() {
        return false;
    }
    if state.pcr_uri.is_empty() {
        return false;
    }
    let uri = state.pcr_uri.clone();
    if state.pcr.load(&uri).is_err() {
        return false;
    }
    let mut receive_channels = HashSet::new();
    let mut receive_antennas: HashMap<u16, (u64, Vec<u64>)> = HashMap::new();
    for (index, transponder) in &state.transponders {
        let slotted = transponder.transmit_slots_per_frame != 0
            || transponder.transmit_slot_size_us != 0
            || !transponder.transmit_slots.is_empty();
        if transponder.receive_frequency_hz == 0
            || transponder.receive_bandwidth_hz == 0
            || transponder.receive_action == ReceiveAction::Unknown
            || transponder.transmit_frequency_hz == 0
            || transponder.transmit_bandwidth_hz == 0
            || transponder.transmit_data_rate_bps == 0
            || effective_mtu(transponder) == 0
            || !state
                .antennas
                .contains_key(&transponder.receive_antenna_index)
            || !state
                .antennas
                .contains_key(&transponder.transmit_antenna_index)
            || state
                .configured_transponder_fields
                .get(index)
                .copied()
                .unwrap_or_default()
                & required_transponder_fields(transponder.receive_action)
                != required_transponder_fields(transponder.receive_action)
            || !state.pcr.contains_curve(transponder.curve_index)
            || !receive_channels.insert((
                transponder.receive_antenna_index,
                transponder.receive_frequency_hz,
            ))
            || (slotted
                && (transponder.transmit_slots_per_frame == 0
                    || transponder.transmit_slot_size_us == 0
                    || transponder.transmit_slots.is_empty()))
            || transponder
                .transmit_slots
                .iter()
                .any(|slot| *slot >= transponder.transmit_slots_per_frame)
        {
            return false;
        }
        let receive = receive_antennas
            .entry(transponder.receive_antenna_index)
            .or_insert_with(|| (transponder.receive_bandwidth_hz, Vec::new()));
        if receive.0 != transponder.receive_bandwidth_hz {
            return false;
        }
        receive.1.push(transponder.receive_frequency_hz);
    }
    state.started = true;
    let definitions = receive_antennas
        .into_iter()
        .map(|(antenna_index, (bandwidth_hz, mut frequencies_hz))| {
            frequencies_hz.sort_unstable();
            frequencies_hz.dedup();
            let definition = *state.antennas.get(&antenna_index)?;
            Some(RxAntennaAdd {
                antenna: MimoTxAntenna {
                    frequency_group_index: 0,
                    antenna_index,
                    bandwidth_hz,
                    spectral_mask_index: definition.spectral_mask_index,
                    pattern: definition.pattern,
                },
                frequencies_hz,
            })
        })
        .collect::<Option<Vec<_>>>();
    let Some(definitions) = definitions else {
        state.started = false;
        return false;
    };
    publish_configuration_tables(mac, &state);
    drop(state);
    let payloads = definitions
        .iter()
        .map(RxAntennaAdd::encode)
        .collect::<Option<Vec<_>>>();
    let Some(payloads) = payloads else {
        return false;
    };
    let messages = payloads
        .iter()
        .map(|payload| FfiControlMessage {
            msg_type: CONTROL_RX_ANTENNA_ADD,
            payload: FfiSlice {
                data: payload.as_ptr(),
                len: payload.len(),
            },
        })
        .collect::<Vec<_>>();
    (mac.framework.send_downstream_control)(
        mac.framework.framework_ctx,
        mac.id,
        messages.as_ptr(),
        messages.len(),
    );
    schedule_reassembly_check(mac);
    true
}

extern "C" fn post_start(_: *mut c_void) {}

extern "C" fn stop(plugin: *mut c_void) {
    let Some(mac) = (unsafe { (plugin as *mut BentpipeMac).as_ref() }) else {
        return;
    };
    let timers = {
        let mut state = mac.state.lock().unwrap();
        state.started = false;
        state.queues.clear();
        state.pending_receptions.clear();
        state.receive_candidates.clear();
        state.reassembly.clear();
        state.receive_end.clear();
        state.wakeups.clear();
        state.timers.drain().collect::<Vec<_>>()
    };
    for timer in timers {
        (mac.framework.cancel_timed_event)(mac.framework.framework_ctx, mac.id, timer);
    }
}

extern "C" fn destroy(plugin: *mut c_void) {
    if !plugin.is_null() {
        unsafe { drop(Box::from_raw(plugin as *mut BentpipeMac)) };
    }
}

extern "C" fn upstream(
    plugin: *mut c_void,
    packet: *const FfiPacket,
    messages: *const FfiControlMessage,
    count: usize,
) {
    let Some(mac) = (unsafe { (plugin as *mut BentpipeMac).as_ref() }) else {
        return;
    };
    if packet.is_null() {
        (mac.framework.send_upstream_control)(mac.framework.framework_ctx, mac.id, messages, count);
        return;
    }
    let Some(message_views) = controls(messages, count) else {
        return;
    };
    let packet_ref = unsafe { &*packet };
    if packet_ref.payload.len > 64 << 20
        || (packet_ref.payload.len != 0 && packet_ref.payload.data.is_null())
    {
        return;
    }
    let payload = if packet_ref.payload.len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(packet_ref.payload.data, packet_ref.payload.len) }
    };
    if payload.len() < 2 {
        return;
    }
    let serialization_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
    if serialization_len == 0 || payload.len() < serialization_len + 2 {
        return;
    }
    let Ok(wire) = BentPipeMessage::decode(&payload[2..2 + serialization_len]) else {
        return;
    };
    let header = find_control(message_views, CONTROL_MODEL_HEADER).and_then(ModelHeader::decode);
    let Some(header) = header else {
        let mut state = mac.state.lock().unwrap();
        record_component_drops(
            mac,
            &mut state,
            packet_ref.info.source,
            &wire.messages,
            PacketDropReason::BadControl,
        );
        return;
    };
    if header.registration_id != MAC_REGISTRATION_BENTPIPE
        || header.message_type != BENTPIPE_MESSAGE_TYPE
    {
        record_packet_drop(
            mac,
            &mut mac.state.lock().unwrap(),
            packet_ref.info.source,
            packet_ref.info.destination,
            packet_ref.payload.len,
            PacketDropReason::RegistrationId,
        );
        return;
    }
    let Ok(_curve_index) = u16::try_from(wire.curve_index) else {
        record_component_drops(
            mac,
            &mut mac.state.lock().unwrap(),
            packet_ref.info.source,
            &wire.messages,
            PacketDropReason::BadCurve,
        );
        return;
    };
    let mimo_rx =
        find_control(message_views, CONTROL_MIMO_RX_PROPERTIES).and_then(MimoRxProperties::decode);
    let legacy_rx =
        find_control(message_views, CONTROL_RX_PROPERTIES).and_then(RxProperties::decode);
    let decision = {
        let mut state = mac.state.lock().unwrap();
        let observation = mimo_rx
            .as_ref()
            .and_then(|mimo| {
                mimo.antenna_infos.iter().find_map(|info| {
                    info.segments.iter().find_map(|segment| {
                        state
                            .transponders
                            .iter()
                            .find(|(_, transponder)| {
                                transponder.receive_antenna_index == info.receive_antenna_index
                                    && transponder.receive_frequency_hz == segment.frequency_hz
                            })
                            .map(|(index, transponder)| {
                                (
                                    *index,
                                    transponder.receive_enable,
                                    transponder.receive_action,
                                    transponder.transmit_delay_us,
                                    segment.rx_power_dbm,
                                    info.noise_floor_dbm,
                                    mimo.tx_time_microseconds
                                        .saturating_add(
                                            i64::try_from(mimo.propagation_microseconds)
                                                .unwrap_or(i64::MAX),
                                        )
                                        .saturating_add(
                                            i64::try_from(segment.offset_microseconds)
                                                .unwrap_or(i64::MAX),
                                        ),
                                    info.span_microseconds,
                                )
                            })
                    })
                })
            })
            .or_else(|| {
                let rx = legacy_rx?;
                state
                    .transponders
                    .iter()
                    .find(|(_, transponder)| {
                        transponder.receive_frequency_hz == rx.frequency_hz
                            && transponder.receive_antenna_index == rx.antenna_index
                    })
                    .map(|(index, transponder)| {
                        (
                            *index,
                            transponder.receive_enable,
                            transponder.receive_action,
                            transponder.transmit_delay_us,
                            rx.rx_power_dbm
                                + state
                                    .antennas
                                    .get(&transponder.receive_antenna_index)
                                    .map_or(0.0, |antenna| match antenna.pattern {
                                        AntennaPattern::IdealOmni { gain_db } => gain_db,
                                        _ => 0.0,
                                    }),
                            rx.noise_floor_dbm,
                            rx.tx_time_microseconds.saturating_add(
                                i64::try_from(rx.propagation_microseconds).unwrap_or(i64::MAX),
                            ),
                            rx.duration_microseconds,
                        )
                    })
            });
        let Some((
            index,
            receive_enable,
            receive_action,
            transmit_delay_us,
            rx_power_dbm,
            _noise_floor_dbm,
            start_of_reception,
            span_microseconds,
        )) = observation
        else {
            return;
        };
        if !receive_enable {
            record_component_drops(
                mac,
                &mut state,
                packet_ref.info.source,
                &wire.messages,
                PacketDropReason::RxOff,
            );
            return;
        }
        if start_of_reception < state.receive_end.get(&index).copied().unwrap_or(0) {
            record_component_drops(
                mac,
                &mut state,
                packet_ref.info.source,
                &wire.messages,
                PacketDropReason::Lock,
            );
            return;
        }
        let transponder = &state.transponders[&index];
        let query = FfiSpectrumQuery {
            frequency_hz: transponder.receive_frequency_hz,
            antenna_index: transponder.receive_antenna_index,
            rx_power_dbm,
            start_time_microseconds: start_of_reception,
            duration_microseconds: span_microseconds,
        };
        (index, receive_action, transmit_delay_us, query)
    };
    let controls = message_views
        .iter()
        .filter_map(|message| {
            let bytes = if message.payload.len == 0 {
                Vec::new()
            } else if message.payload.data.is_null() || message.payload.len > 16 << 20 {
                return None;
            } else {
                unsafe { std::slice::from_raw_parts(message.payload.data, message.payload.len) }
                    .to_vec()
            };
            Some(OwnedControl {
                msg_type: message.msg_type,
                payload: bytes,
            })
        })
        .collect::<Vec<_>>();
    let end = decision
        .3
        .start_time_microseconds
        .saturating_add(i64::try_from(decision.3.duration_microseconds).unwrap_or(i64::MAX));
    let key = {
        let mut state = mac.state.lock().unwrap();
        state.next_receive_id = state.next_receive_id.wrapping_add(1);
        let key = (
            decision.0,
            decision.3.start_time_microseconds,
            state.next_receive_id,
        );
        state.receive_candidates.insert(
            key,
            PendingReception {
                info: packet_ref.info,
                controls,
                wire,
                length: packet_ref.payload.len - 2,
                index: decision.0,
                action: decision.1,
                delay: decision.2,
                query: decision.3,
            },
        );
        key
    };
    if end <= now_us() {
        complete_receptions(mac, now_us());
    } else {
        let when = end.max(0) as u64;
        let timer = (mac.framework.schedule_timed_event)(
            mac.framework.framework_ctx,
            mac.id,
            when / 1_000_000,
            (when % 1_000_000) as u32,
            EVENT_RECEPTION_CHECK,
            std::ptr::null(),
            0,
        );
        let mut state = mac.state.lock().unwrap();
        if timer != 0 {
            state.timers.insert(timer);
        } else {
            state.receive_candidates.remove(&key);
        }
    }
}

fn complete_receptions(mac: &BentpipeMac, now: i64) {
    loop {
        let next = {
            let mut state = mac.state.lock().unwrap();
            let mut seen = HashSet::new();
            let key = state
                .receive_candidates
                .iter()
                .find_map(|(key, candidate)| {
                    if !seen.insert(key.0) {
                        return None;
                    }
                    let end = candidate.query.start_time_microseconds.saturating_add(
                        i64::try_from(candidate.query.duration_microseconds).unwrap_or(i64::MAX),
                    );
                    (end <= now).then_some(*key)
                });
            key.and_then(|key| state.receive_candidates.remove(&key))
        };
        let Some(candidate) = next else { break };
        complete_reception(mac, candidate);
    }
}

fn complete_reception(mac: &BentpipeMac, candidate: PendingReception) {
    let PendingReception {
        info,
        controls,
        wire,
        length,
        index,
        action,
        delay,
        query,
    } = candidate;
    let end = query
        .start_time_microseconds
        .saturating_add(i64::try_from(query.duration_microseconds).unwrap_or(i64::MAX));
    {
        let mut state = mac.state.lock().unwrap();
        if query.start_time_microseconds < state.receive_end.get(&index).copied().unwrap_or(0) {
            record_component_drops(
                mac,
                &mut state,
                info.source,
                &wire.messages,
                PacketDropReason::Lock,
            );
            return;
        }
    }
    let Some(spectrum) = mac.framework.reception_noise(&query) else {
        record_component_drops(
            mac,
            &mut mac.state.lock().unwrap(),
            info.source,
            &wire.messages,
            PacketDropReason::Spectrum,
        );
        return;
    };
    {
        let mut state = mac.state.lock().unwrap();
        let sinr = query.rx_power_dbm - spectrum.noise_floor_dbm;
        let Some(probability) = state
            .pcr
            .get_por(wire.curve_index as u16, sinr as f32, length)
        else {
            record_component_drops(
                mac,
                &mut state,
                info.source,
                &wire.messages,
                PacketDropReason::BadCurve,
            );
            return;
        };
        if probability
            < state
                .receive_random
                .entry(index)
                .or_insert_with(LegacyRandom::from_clock)
                .unit()
        {
            record_component_drops(
                mac,
                &mut state,
                info.source,
                &wire.messages,
                PacketDropReason::Sinr,
            );
            return;
        }
        update_neighbor_statistics(
            mac,
            &mut state,
            info.source,
            index,
            sinr,
            spectrum.noise_floor_dbm,
            query.start_time_microseconds.max(0) as u64,
        );
    }
    let decision = (index, action, delay, end);
    for component in wire.messages {
        let Ok(destination) = u16::try_from(component.destination) else {
            continue;
        };
        let accepted = match decision.1 {
            ReceiveAction::Process => destination == mac.id || destination == BROADCAST_NEM,
            ReceiveAction::Ubend => destination != mac.id,
            ReceiveAction::Unknown => false,
        };
        if !accepted {
            record_packet_drop(
                mac,
                &mut mac.state.lock().unwrap(),
                info.source,
                destination,
                component.data.len(),
                PacketDropReason::Destination,
            );
            continue;
        }
        let info = FfiPacketInfo {
            destination,
            ..info
        };
        let completed = if let Some(fragment) = component.fragment {
            let mut state = mac.state.lock().unwrap();
            let now = now_us();
            expire_reassembly(mac, &mut state, now);
            let key = (info.source, fragment.sequence);
            let entry = state.reassembly.entry(key).or_insert_with(|| Reassembly {
                info,
                controls: controls.clone(),
                destination,
                parts: BTreeMap::new(),
                last_fragment_index: None,
                last_update: now,
            });
            if entry.destination != destination
                || entry
                    .parts
                    .values()
                    .any(|(index, _)| *index == fragment.index)
            {
                continue;
            }
            entry
                .parts
                .insert(fragment.offset as usize, (fragment.index, component.data));
            if !fragment.more {
                entry.last_fragment_index = Some(fragment.index);
            }
            entry.last_update = now;
            let complete = entry.last_fragment_index.is_some_and(|last| {
                entry.parts.len() == last as usize + 1
                    && (0..=last).all(|index| {
                        entry
                            .parts
                            .values()
                            .any(|(fragment_index, _)| *fragment_index == index)
                    })
                    && {
                        let mut offset = 0usize;
                        entry.parts.iter().all(|(part_offset, (_, data))| {
                            if *part_offset != offset {
                                false
                            } else {
                                offset = offset.saturating_add(data.len());
                                true
                            }
                        })
                    }
            });
            complete.then(|| {
                let entry = state.reassembly.remove(&key).expect("reassembly entry");
                let payload = entry
                    .parts
                    .into_values()
                    .flat_map(|(_, data)| data)
                    .collect();
                OwnedPacket {
                    info: entry.info,
                    payload,
                    controls: entry.controls,
                }
            })
        } else {
            mac.state
                .lock()
                .unwrap()
                .receive_end
                .insert(decision.0, decision.3);
            Some(OwnedPacket {
                info,
                payload: component.data,
                controls: controls.clone(),
            })
        };
        let Some(packet) = completed else { continue };
        record_packet_accept(
            mac,
            &mut mac.state.lock().unwrap(),
            info.source,
            packet.info.destination,
            packet.payload.len(),
            true,
        );
        match decision.1 {
            ReceiveAction::Process => {
                schedule_receive(mac, packet, decision.3.max(now_us()));
            }
            ReceiveAction::Ubend => {
                let now = now_us();
                let when = decision
                    .3
                    .max(now)
                    .saturating_add(i64::try_from(decision.2).unwrap_or(i64::MAX));
                let destination = packet.info.destination;
                let size = packet.payload.len();
                let queued = enqueue(
                    mac,
                    &mut mac.state.lock().unwrap(),
                    decision.0,
                    packet,
                    when,
                );
                if queued {
                    if when <= now {
                        drive(mac, decision.0, now, None);
                    } else {
                        schedule_transmit(mac, decision.0, when);
                    }
                } else {
                    record_packet_drop(
                        mac,
                        &mut mac.state.lock().unwrap(),
                        mac.id,
                        destination,
                        size,
                        PacketDropReason::TxOff,
                    );
                }
            }
            ReceiveAction::Unknown => {}
        }
    }
}

extern "C" fn downstream(
    plugin: *mut c_void,
    packet: *const FfiPacket,
    messages: *const FfiControlMessage,
    count: usize,
) {
    let Some(mac) = (unsafe { (plugin as *mut BentpipeMac).as_ref() }) else {
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
    let index = {
        let state = mac.state.lock().unwrap();
        state
            .transponders
            .iter()
            .find(|(_, transponder)| {
                transponder.transmit_enable
                    && (transponder.all_tos || transponder.tos.contains(&packet.info.priority))
            })
            .map(|(index, _)| *index)
    };
    let Some(index) = index else { return };
    let now = now_us();
    if enqueue(mac, &mut mac.state.lock().unwrap(), index, packet, now) {
        drive(mac, index, now, None);
    }
}

extern "C" fn timed(
    plugin: *mut c_void,
    timer_id: u64,
    event_id: u32,
    data: *const u8,
    len: usize,
) {
    let Some(mac) = (unsafe { (plugin as *mut BentpipeMac).as_ref() }) else {
        return;
    };
    mac.state.lock().unwrap().timers.remove(&timer_id);
    if event_id == EVENT_RECEPTION_CHECK {
        complete_receptions(mac, now_us());
        return;
    }
    if event_id == EVENT_REASSEMBLY_CHECK {
        let mut state = mac.state.lock().unwrap();
        if !state.started {
            return;
        }
        let now = now_us();
        expire_reassembly(mac, &mut state, now);
        drop(state);
        schedule_reassembly_check(mac);
        return;
    }
    if event_id == EVENT_RECEIVE {
        if len != 8 || data.is_null() {
            return;
        }
        let id = u64::from_be_bytes(
            unsafe { std::slice::from_raw_parts(data, len) }
                .try_into()
                .unwrap(),
        );
        if let Some(packet) = mac.state.lock().unwrap().pending_receptions.remove(&id) {
            send_upstream(mac, packet);
        }
        return;
    }
    if event_id != EVENT_TRANSMIT || len != 10 || data.is_null() {
        return;
    }
    let data = unsafe { std::slice::from_raw_parts(data, len) };
    let index = u16::from_be_bytes(data[..2].try_into().unwrap());
    let expected = i64::from_be_bytes(data[2..].try_into().unwrap());
    {
        let mut state = mac.state.lock().unwrap();
        if state.wakeups.get(&index) != Some(&expected) {
            return;
        }
        state.wakeups.remove(&index);
    }
    drive(mac, index, now_us(), Some(expected));
}

extern "C" fn process_event(_: *mut c_void, _: u16, _: *const u8, _: usize) {}

#[no_mangle]
pub extern "C" fn emane_plugin_create() -> *const PluginApi {
    static API: OnceLock<PluginApi> = OnceLock::new();
    API.get_or_init(|| PluginApi {
        abi_version: PLUGIN_ABI_VERSION,
        struct_size: std::mem::size_of::<PluginApi>(),
        name: c"bentpipemaclayer".as_ptr(),
        plugin_type: 1,
        init,
        configure,
        start,
        post_start,
        stop,
        destroy,
        process_upstream: upstream,
        process_downstream: downstream,
        process_timed_event: timed,
        process_event,
    })
}

#[cfg(test)]
mod tests {
    extern "C" fn spectrum_unavailable(
        _: *mut c_void,
        _: *const emane_plugin_api::FfiSpectrumQuery,
        result: *mut emane_plugin_api::FfiSpectrumResult,
    ) -> bool {
        unsafe {
            *result = emane_plugin_api::FfiSpectrumResult {
                noise_floor_dbm: -90.0,
                receiver_sensitivity_dbm: -100.0,
                signal_in_noise: false,
            };
        }
        true
    }

    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Capture {
        packet: Vec<u8>,
        controls: Vec<(u32, Vec<u8>)>,
    }

    static CAPTURE: Mutex<Capture> = Mutex::new(Capture {
        packet: Vec::new(),
        controls: Vec::new(),
    });
    static UPSTREAM_CAPTURE: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());

    extern "C" fn capture_packet(
        _: *mut c_void,
        _: u16,
        packet: *const FfiPacket,
        messages: *const FfiControlMessage,
        count: usize,
    ) {
        let packet = unsafe { &*packet };
        let mut capture = CAPTURE.lock().unwrap();
        capture.packet = if packet.payload.len == 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(packet.payload.data, packet.payload.len) }.to_vec()
        };
        capture.controls = controls(messages, count)
            .unwrap()
            .iter()
            .map(|message| {
                let payload = if message.payload.len == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(message.payload.data, message.payload.len) }
                        .to_vec()
                };
                (message.msg_type, payload)
            })
            .collect();
    }

    extern "C" fn packet_noop(
        _: *mut c_void,
        _: u16,
        _: *const FfiPacket,
        _: *const FfiControlMessage,
        _: usize,
    ) {
    }
    extern "C" fn capture_upstream_packet(
        _: *mut c_void,
        _: u16,
        packet: *const FfiPacket,
        _: *const FfiControlMessage,
        _: usize,
    ) {
        let packet = unsafe { &*packet };
        let payload = if packet.payload.len == 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(packet.payload.data, packet.payload.len) }.to_vec()
        };
        UPSTREAM_CAPTURE.lock().unwrap().push(payload);
    }
    extern "C" fn control_noop(_: *mut c_void, _: u16, _: *const FfiControlMessage, _: usize) {}
    extern "C" fn schedule_noop(
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
    extern "C" fn cancel_noop(_: *mut c_void, _: u16, _: u64) {}
    extern "C" fn log_noop(_: *mut c_void, _: u32, _: *const std::os::raw::c_char) {}
    extern "C" fn register_noop(
        _: *mut c_void,
        _: *const std::os::raw::c_char,
        _: *const std::os::raw::c_char,
        _: bool,
    ) -> u64 {
        0
    }
    extern "C" fn increment_noop(_: *mut c_void, _: u64, _: u64) -> bool {
        true
    }
    extern "C" fn register_double_noop(
        _: *mut c_void,
        _: *const std::os::raw::c_char,
        _: *const std::os::raw::c_char,
        _: bool,
    ) -> u64 {
        0
    }
    extern "C" fn set_double_noop(_: *mut c_void, _: u64, _: f64) -> bool {
        true
    }
    extern "C" fn register_table_noop(
        _: *mut c_void,
        _: *const std::os::raw::c_char,
        _: *const *const std::os::raw::c_char,
        _: usize,
        _: *const std::os::raw::c_char,
        _: bool,
    ) -> u64 {
        0
    }
    extern "C" fn set_table_row_noop(
        _: *mut c_void,
        _: u64,
        _: *const u64,
        _: usize,
        _: *const emane_plugin_api::FfiStatisticValue,
        _: usize,
    ) -> bool {
        true
    }
    extern "C" fn neighbor_tx_noop(_: *mut c_void, _: u16, _: u64, _: u64) {}
    extern "C" fn neighbor_status_noop(_: *mut c_void) {}
    extern "C" fn neighbor_rx_noop(
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
    extern "C" fn queue_noop(_: *mut c_void, _: u16, _: u32, _: u32, _: u32, _: u64) {}
    extern "C" fn publish_noop(_: *mut c_void, _: u64, _: u64, _: u64, _: u64) {}
    extern "C" fn register_rf_noop(_: *mut c_void, _: u16) -> u64 {
        1
    }
    extern "C" fn configure_rf_noop(_: *mut c_void, _: u64, _: bool, _: bool) -> bool {
        true
    }
    extern "C" fn update_rf_noop(
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
    extern "C" fn publish_event_noop(_: *mut c_void, _: u16, _: *const u8, _: usize) -> bool {
        true
    }
    extern "C" fn register_descriptor_noop(
        _: *mut c_void,
        _: i32,
        _: u32,
        _: *mut c_void,
        _: emane_plugin_api::FfiFileDescriptorCallback,
    ) -> u64 {
        0
    }
    extern "C" fn unregister_descriptor_noop(_: *mut c_void, _: u64) -> bool {
        false
    }
    extern "C" fn table_generation_noop(_: *mut c_void, _: u64) -> u64 {
        0
    }
    extern "C" fn remove_table_row_noop(_: *mut c_void, _: u64, _: *const u64, _: usize) -> bool {
        true
    }

    fn framework(capture: bool) -> FfiFrameworkService {
        FfiFrameworkService {
            framework_ctx: std::ptr::null_mut(),
            send_downstream_packet: if capture { capture_packet } else { packet_noop },
            send_upstream_packet: capture_upstream_packet,
            send_downstream_control: control_noop,
            send_upstream_control: control_noop,
            schedule_timed_event: schedule_noop,
            cancel_timed_event: cancel_noop,
            log: log_noop,
            register_counter: register_noop,
            register_counter32: register_noop,
            increment_counter: increment_noop,
            maximize_counter: increment_noop,
            register_double: register_double_noop,
            set_double: set_double_noop,
            register_average: register_double_noop,
            sample_average: set_double_noop,
            register_table: register_table_noop,
            set_table_row: set_table_row_noop,
            clear_table: unregister_descriptor_noop,
            remove_table_row: remove_table_row_noop,
            table_generation: table_generation_noop,
            update_neighbor_tx: neighbor_tx_noop,
            update_neighbor_rx: neighbor_rx_noop,
            update_neighbor_status: neighbor_status_noop,
            update_queue_metric: queue_noop,
            publish_r2ri: publish_noop,
            register_rf_signal_table: register_rf_noop,
            configure_rf_signal_table: configure_rf_noop,
            update_rf_signal_table: update_rf_noop,
            publish_event: publish_event_noop,
            register_file_descriptor: register_descriptor_noop,
            unregister_file_descriptor: unregister_descriptor_noop,
            query_spectrum_filter: emane_plugin_api::spectrum::unavailable_filter,
            query_spectrum: spectrum_unavailable,
        }
    }

    fn packet(destination: u16, data: &[u8]) -> OwnedPacket {
        OwnedPacket {
            info: FfiPacketInfo {
                uuid: [0; 16],
                source: 1,
                destination,
                priority: 0,
                creation_time_sec: 0,
                creation_time_usec: 0,
            },
            payload: data.to_vec(),
            controls: Vec::new(),
        }
    }

    #[test]
    fn parses_ranges_units_and_slots() {
        assert_eq!(parse_scaled_u64("2.5M"), Some(2_500_000));
        assert_eq!(parse_ranges("1-3;8").unwrap().len(), 4);
        assert_eq!(parse_slots("1-2;4").unwrap(), vec![1, 2, 4]);
        let (index, antenna) = parse_antenna("7:omni;3.5;2").unwrap();
        assert_eq!(index, 7);
        assert_eq!(antenna.pattern, AntennaPattern::IdealOmni { gain_db: 3.5 });
        assert_eq!(antenna.spectral_mask_index, 2);
        assert_eq!(
            parse_antenna("7:42;20;-5;2").unwrap().1.pattern,
            AntennaPattern::Profile(TxAntennaProfile {
                profile_id: 42,
                azimuth_degrees: 20.0,
                elevation_degrees: -5.0,
            })
        );
        assert!(parse_antenna("7:0;0;0;2").is_none());
        assert_eq!(
            required_transponder_fields(ReceiveAction::Process),
            TRANSPONDER_REQUIRED_FIELDS
        );
        assert_eq!(
            required_transponder_fields(ReceiveAction::Ubend),
            TRANSPONDER_REQUIRED_FIELDS & !TRANSPONDER_TOSMAP_FIELD
        );
    }

    #[test]
    fn legacy_aggregation_combines_components_and_respects_disable() {
        let mac = BentpipeMac::new(1, framework(false));
        let mut state = mac.state.lock().unwrap();
        state.transponders.insert(
            1,
            Transponder {
                transmit_enable: true,
                transmit_mtu_bytes: 10,
                transmit_data_rate_bps: 1_000_000,
                ..Transponder::default()
            },
        );
        assert!(enqueue(&mac, &mut state, 1, packet(2, b"abc"), 10));
        assert!(enqueue(&mac, &mut state, 1, packet(3, b"defg"), 10));
        let components = dequeue_components(&mac, &mut state, 1, 10, 10);
        assert_eq!(components.len(), 2);
        assert_eq!(components[0].packet.payload, b"abc");
        assert_eq!(components[1].packet.payload, b"defg");

        state.aggregation_enable = false;
        assert!(enqueue(&mac, &mut state, 1, packet(2, b"a"), 10));
        assert!(enqueue(&mac, &mut state, 1, packet(2, b"b"), 10));
        assert_eq!(dequeue_components(&mac, &mut state, 1, 10, 10).len(), 1);
        assert_eq!(state.queues[&1].len(), 1);
    }

    #[test]
    fn aggregation_wire_frame_preserves_profile_and_component_destinations() {
        *CAPTURE.lock().unwrap() = Capture::default();
        let mac = BentpipeMac::new(1, framework(true));
        let transponder = Transponder {
            curve_index: 4,
            transmit_frequency_hz: 2_400_000_000,
            transmit_bandwidth_hz: 1_000_000,
            transmit_data_rate_bps: 1_000_000,
            transmit_antenna_index: 7,
            transmit_power_dbm: 5.0,
            ..Transponder::default()
        };
        let component = |destination, data: &[u8], sequence| TxComponent {
            packet: packet(destination, data),
            sequence,
            offset: 0,
            fragment_index: 0,
            more: false,
            fragmented: false,
        };
        send_downstream(
            &mac,
            vec![component(2, b"one", 10), component(3, b"two", 11)],
            9,
            &transponder,
            AntennaDefinition {
                pattern: AntennaPattern::Profile(TxAntennaProfile {
                    profile_id: 42,
                    azimuth_degrees: 20.0,
                    elevation_degrees: -5.0,
                }),
                spectral_mask_index: 3,
            },
        );
        let capture = CAPTURE.lock().unwrap();
        let length = u16::from_be_bytes(capture.packet[..2].try_into().unwrap()) as usize;
        let wire = BentPipeMessage::decode(&capture.packet[2..2 + length]).unwrap();
        assert_eq!(wire.curve_index, 4);
        assert_eq!(wire.messages.len(), 2);
        assert_eq!(wire.messages[0].destination, 2);
        assert_eq!(wire.messages[1].destination, 3);
        let mimo = capture
            .controls
            .iter()
            .find(|(kind, _)| *kind == CONTROL_MIMO_TX_PROPERTIES)
            .and_then(|(_, payload)| MimoTxProperties::decode(payload))
            .unwrap();
        assert_eq!(
            mimo.transmit_antennas[0].pattern,
            AntennaPattern::Profile(TxAntennaProfile {
                profile_id: 42,
                azimuth_degrees: 20.0,
                elevation_degrees: -5.0,
            })
        );
    }

    #[test]
    fn fragmentation_is_reassembled_by_index_and_offset() {
        let mac = BentpipeMac::new(1, framework(false));
        let mut state = mac.state.lock().unwrap();
        state.transponders.insert(
            1,
            Transponder {
                transmit_enable: true,
                transmit_mtu_bytes: 4,
                transmit_data_rate_bps: 1_000_000,
                ..Transponder::default()
            },
        );
        assert!(enqueue(&mac, &mut state, 1, packet(2, b"abcdefgh"), 0));
        let first = dequeue_components(&mac, &mut state, 1, 4, 0);
        let second = dequeue_components(&mac, &mut state, 1, 4, 0);
        assert_eq!(first[0].packet.payload, b"abcd");
        assert!(first[0].more);
        assert_eq!(first[0].fragment_index, 0);
        assert_eq!(second[0].packet.payload, b"efgh");
        assert!(!second[0].more);
        assert_eq!(second[0].offset, 4);
        assert_eq!(second[0].fragment_index, 1);
    }

    #[test]
    fn aggregated_wire_frame_delivers_each_component_through_receive_path() {
        *UPSTREAM_CAPTURE.lock().unwrap() = Vec::new();
        let receiver = BentpipeMac::new(2, framework(false));
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let pcr_path = std::env::temp_dir().join(format!("emane-bentpipe-pcr-{unique}.xml"));
        std::fs::write(
            &pcr_path,
            r#"<bentpipe-model-pcr packetsize="1024"><curve index="0"><entry sinr="-10" por="0"/><entry sinr="10" por="100"/></curve></bentpipe-model-pcr>"#,
        )
        .unwrap();
        {
            let mut state = receiver.state.lock().unwrap();
            state.pcr.load(pcr_path.to_str().unwrap()).unwrap();
            state.transponders.insert(
                1,
                Transponder {
                    receive_frequency_hz: 2_400_000_000,
                    receive_bandwidth_hz: 1_000_000,
                    receive_antenna_index: 7,
                    receive_action: ReceiveAction::Process,
                    receive_enable: true,
                    ..Transponder::default()
                },
            );
        }
        let serialization = BentPipeMessage {
            start_of_transmission_microseconds: 0,
            curve_index: 0,
            messages: vec![
                BentPipeComponent {
                    destination: 2,
                    data: b"one".to_vec(),
                    fragment: None,
                },
                BentPipeComponent {
                    destination: 2,
                    data: b"two".to_vec(),
                    fragment: None,
                },
            ],
        }
        .encode_to_vec();
        let mut wire = Vec::with_capacity(serialization.len() + 2);
        wire.extend_from_slice(&(serialization.len() as u16).to_be_bytes());
        wire.extend_from_slice(&serialization);
        let header = ModelHeader {
            registration_id: MAC_REGISTRATION_BENTPIPE,
            sequence: 1,
            data_rate_bps: 1_000_000,
            category: 0,
            message_type: BENTPIPE_MESSAGE_TYPE,
            flags: 0,
        }
        .encode();
        let mimo = MimoRxProperties {
            tx_time_microseconds: 0,
            propagation_microseconds: 0,
            antenna_infos: vec![emane_plugin_api::MimoRxAntennaInfo {
                receive_antenna_index: 7,
                transmit_antenna_index: 7,
                span_microseconds: 10,
                receiver_sensitivity_dbm: -100.0,
                noise_floor_dbm: -90.0,
                segments: vec![emane_plugin_api::RxFrequencySegment {
                    frequency_hz: 2_400_000_000,
                    rx_power_dbm: -70.0,
                    duration_microseconds: 10,
                    offset_microseconds: 0,
                }],
            }],
            doppler_shifts_hz: Vec::new(),
        }
        .encode()
        .unwrap();
        let controls = [
            FfiControlMessage {
                msg_type: CONTROL_MODEL_HEADER,
                payload: FfiSlice {
                    data: header.as_ptr(),
                    len: header.len(),
                },
            },
            FfiControlMessage {
                msg_type: CONTROL_MIMO_RX_PROPERTIES,
                payload: FfiSlice {
                    data: mimo.as_ptr(),
                    len: mimo.len(),
                },
            },
        ];
        let packet = FfiPacket {
            info: FfiPacketInfo {
                uuid: [0; 16],
                source: 1,
                destination: 2,
                priority: 0,
                creation_time_sec: 0,
                creation_time_usec: 0,
            },
            payload: FfiSlice {
                data: wire.as_ptr(),
                len: wire.len(),
            },
        };
        upstream(
            &receiver as *const BentpipeMac as *mut c_void,
            &packet,
            controls.as_ptr(),
            controls.len(),
        );
        assert_eq!(
            *UPSTREAM_CAPTURE.lock().unwrap(),
            vec![b"one".to_vec(), b"two".to_vec()]
        );

        *UPSTREAM_CAPTURE.lock().unwrap() = Vec::new();
        for (index, offset, more, data) in [
            (0, 0, true, b"abc".as_slice()),
            (1, 3, false, b"def".as_slice()),
        ] {
            let fragment_mimo = MimoRxProperties {
                tx_time_microseconds: 20 + i64::from(index) * 20,
                propagation_microseconds: 0,
                antenna_infos: vec![emane_plugin_api::MimoRxAntennaInfo {
                    receive_antenna_index: 7,
                    transmit_antenna_index: 7,
                    span_microseconds: 10,
                    receiver_sensitivity_dbm: -100.0,
                    noise_floor_dbm: -90.0,
                    segments: vec![emane_plugin_api::RxFrequencySegment {
                        frequency_hz: 2_400_000_000,
                        rx_power_dbm: -70.0,
                        duration_microseconds: 10,
                        offset_microseconds: 0,
                    }],
                }],
                doppler_shifts_hz: Vec::new(),
            }
            .encode()
            .unwrap();
            let fragment_controls = [
                FfiControlMessage {
                    msg_type: CONTROL_MODEL_HEADER,
                    payload: FfiSlice {
                        data: header.as_ptr(),
                        len: header.len(),
                    },
                },
                FfiControlMessage {
                    msg_type: CONTROL_MIMO_RX_PROPERTIES,
                    payload: FfiSlice {
                        data: fragment_mimo.as_ptr(),
                        len: fragment_mimo.len(),
                    },
                },
            ];
            let serialization = BentPipeMessage {
                start_of_transmission_microseconds: 0,
                curve_index: 0,
                messages: vec![BentPipeComponent {
                    destination: 2,
                    data: data.to_vec(),
                    fragment: Some(BentPipeFragment {
                        more,
                        index,
                        offset,
                        sequence: 77,
                    }),
                }],
            }
            .encode_to_vec();
            let mut wire = Vec::with_capacity(serialization.len() + 2);
            wire.extend_from_slice(&(serialization.len() as u16).to_be_bytes());
            wire.extend_from_slice(&serialization);
            let packet = FfiPacket {
                info: FfiPacketInfo {
                    uuid: [0; 16],
                    source: 1,
                    destination: 2,
                    priority: 0,
                    creation_time_sec: 0,
                    creation_time_usec: 0,
                },
                payload: FfiSlice {
                    data: wire.as_ptr(),
                    len: wire.len(),
                },
            };
            upstream(
                &receiver as *const BentpipeMac as *mut c_void,
                &packet,
                fragment_controls.as_ptr(),
                fragment_controls.len(),
            );
            if more {
                assert!(UPSTREAM_CAPTURE.lock().unwrap().is_empty());
            }
        }
        assert_eq!(*UPSTREAM_CAPTURE.lock().unwrap(), vec![b"abcdef".to_vec()]);
        std::fs::remove_file(pcr_path).unwrap();
    }
    mod reception_regressions {
        use super::*;
        use emane_plugin_api::FfiSpectrumResult;
        #[derive(Default)]
        struct Probe {
            noise: f64,
            queries: usize,
            sources: Vec<u16>,
        }
        extern "C" fn capture(
            ctx: *mut c_void,
            _: u16,
            p: *const FfiPacket,
            _: *const FfiControlMessage,
            _: usize,
        ) {
            unsafe {
                (&mut *(ctx as *mut Probe)).sources.push((*p).info.source);
            }
        }
        extern "C" fn spectrum(
            ctx: *mut c_void,
            q: *const FfiSpectrumQuery,
            r: *mut FfiSpectrumResult,
        ) -> bool {
            let probe = unsafe { &mut *(ctx as *mut Probe) };
            assert_eq!(unsafe { (*q).antenna_index }, 7);
            probe.queries += 1;
            unsafe {
                *r = FfiSpectrumResult {
                    noise_floor_dbm: probe.noise,
                    receiver_sensitivity_dbm: -100.0,
                    signal_in_noise: false,
                };
            }
            true
        }
        extern "C" fn schedule(
            _: *mut c_void,
            _: u16,
            _: u64,
            _: u32,
            event: u32,
            _: *const u8,
            _: usize,
        ) -> u64 {
            if event == EVENT_RECEPTION_CHECK {
                1
            } else {
                0
            }
        }
        fn receiver(probe: &mut Probe) -> BentpipeMac {
            let mut fw = framework(false);
            fw.framework_ctx = probe as *mut _ as *mut c_void;
            fw.query_spectrum = spectrum;
            fw.send_upstream_packet = capture;
            fw.schedule_timed_event = schedule;
            let mac = BentpipeMac::new(2, fw);
            let path = std::env::temp_dir().join(format!(
                "bentpipe-regression-{}-{:?}.xml",
                std::process::id(),
                std::thread::current().id()
            ));
            std::fs::write(&path,r#"<bentpipe-model-pcr packetsize="0"><curve index="0"><entry sinr="-10" por="0"/><entry sinr="10" por="100"/></curve></bentpipe-model-pcr>"#).unwrap();
            {
                let mut state = mac.state.lock().unwrap();
                state.pcr.load(path.to_str().unwrap()).unwrap();
                state.transponders.insert(
                    1,
                    Transponder {
                        receive_frequency_hz: 2_400_000_000,
                        receive_antenna_index: 7,
                        receive_enable: true,
                        receive_action: ReceiveAction::Process,
                        ..Transponder::default()
                    },
                );
            }
            std::fs::remove_file(path).unwrap();
            mac
        }
        fn receive(mac: &BentpipeMac, source: u16, start: i64, power: f64) {
            let body = BentPipeMessage {
                start_of_transmission_microseconds: start as u64,
                curve_index: 0,
                messages: vec![BentPipeComponent {
                    destination: 2,
                    data: vec![42],
                    fragment: None,
                }],
            }
            .encode_to_vec();
            let mut payload = (body.len() as u16).to_be_bytes().to_vec();
            payload.extend(body);
            let header = ModelHeader {
                registration_id: MAC_REGISTRATION_BENTPIPE,
                sequence: 1,
                data_rate_bps: 1_000_000,
                category: 0,
                message_type: BENTPIPE_MESSAGE_TYPE,
                flags: 0,
            }
            .encode();
            let rx = RxProperties {
                frequency_hz: 2_400_000_000,
                bandwidth_hz: 1_000_000,
                rx_power_dbm: power,
                noise_floor_dbm: -100.0,
                tx_time_microseconds: start,
                propagation_microseconds: 0,
                duration_microseconds: 100_000,
                antenna_index: 7,
                sub_id: 1,
                signal_in_noise: false,
            }
            .encode();
            let messages = [
                FfiControlMessage {
                    msg_type: CONTROL_MODEL_HEADER,
                    payload: FfiSlice {
                        data: header.as_ptr(),
                        len: header.len(),
                    },
                },
                FfiControlMessage {
                    msg_type: CONTROL_RX_PROPERTIES,
                    payload: FfiSlice {
                        data: rx.as_ptr(),
                        len: rx.len(),
                    },
                },
            ];
            let packet = FfiPacket {
                info: FfiPacketInfo {
                    uuid: [1; 16],
                    source,
                    destination: 2,
                    priority: 0,
                    creation_time_sec: 0,
                    creation_time_usec: 0,
                },
                payload: FfiSlice {
                    data: payload.as_ptr(),
                    len: payload.len(),
                },
            };
            upstream(
                mac as *const _ as *mut c_void,
                &packet,
                messages.as_ptr(),
                messages.len(),
            );
        }
        #[test]
        fn earlier_start_wins_even_when_its_callback_arrives_later() {
            let mut probe = Probe {
                noise: -100.0,
                ..Probe::default()
            };
            let mac = receiver(&mut probe);
            let start = now_us() + 1_000_000;
            receive(&mac, 3, start + 20_000, -50.0);
            receive(&mac, 1, start + 10_000, -50.0);
            assert_eq!(mac.state.lock().unwrap().receive_candidates.len(), 2);
            assert_eq!(probe.queries, 0);
            complete_receptions(&mac, start + 120_000);
            assert_eq!(probe.sources, vec![1]);
            assert_eq!(probe.queries, 1);
        }
        #[test]
        fn failed_reception_does_not_reserve_the_channel() {
            let mut probe = Probe {
                noise: -50.0,
                ..Probe::default()
            };
            let mac = receiver(&mut probe);
            let start = now_us() + 1_000_000;
            receive(&mac, 3, start + 20_000, -30.0);
            receive(&mac, 1, start + 10_000, -70.0);
            complete_receptions(&mac, start + 120_000);
            assert_eq!(probe.sources, vec![3]);
            assert_eq!(probe.queries, 2);
        }
        #[test]
        fn late_interference_changes_the_completed_reception() {
            let mut probe = Probe {
                noise: -100.0,
                ..Probe::default()
            };
            let mac = receiver(&mut probe);
            let start = now_us() + 1_000_000;
            receive(&mac, 1, start, -70.0);
            assert_eq!(probe.queries, 0);
            probe.noise = -50.0;
            complete_receptions(&mac, start + 100_000);
            assert!(probe.sources.is_empty());
            assert_eq!(probe.queries, 1);
            assert!(mac.state.lock().unwrap().receive_end.is_empty());
        }
        #[test]
        fn pcr_length_excludes_prefix() {
            let mut probe = Probe {
                noise: -100.0,
                ..Probe::default()
            };
            let mac = receiver(&mut probe);
            receive(&mac, 1, now_us() + 1_000_000, -50.0);
            let mut state = mac.state.lock().unwrap();
            let path =
                std::env::temp_dir().join(format!("bentpipe-length-{}.xml", std::process::id()));
            std::fs::write(&path, r#"<bentpipe-model-pcr packetsize="128"><curve index="0"><entry sinr="0" por="25"/><entry sinr="100" por="75"/></curve></bentpipe-model-pcr>"#).unwrap();
            state.pcr.load(path.to_str().unwrap()).unwrap();
            std::fs::remove_file(path).unwrap();
            let candidate = state.receive_candidates.values().next().unwrap();
            assert_eq!(
                candidate.length,
                candidate.wire.encoded_len(),
                "C++ strips the two-byte prefix before passing length to PCR"
            );
            let expected = 0.5f32.powf(candidate.wire.encoded_len() as f32 / 128.0);
            assert_eq!(state.pcr.get_por(0, 50.0, candidate.length), Some(expected));
            assert_ne!(
                state.pcr.get_por(0, 50.0, candidate.length + 2),
                Some(expected)
            );
        }
    }
}
