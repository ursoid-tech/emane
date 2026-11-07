use emane_plugin_api::flow_control::FlowControlManager;
use emane_plugin_api::random::LegacyRandom;
mod pcr;

use emane_plugin_api::{
    FfiConfigRequest, FfiControlMessage, FfiFrameworkService, FfiPacket, FfiPacketInfo, FfiSlice,
    FfiSpectrumQuery, FfiStatisticValue, FlowControlToken, FrequencyOfInterest, ModelHeader,
    PluginApi, RxFrequencySegments, RxProperties, TxProperties, CONTROL_FLOW_CONTROL_TOKEN,
    CONTROL_FREQUENCY_INTEREST, CONTROL_MODEL_HEADER, CONTROL_RX_FREQUENCY_SEGMENTS,
    CONTROL_RX_PROPERTIES, CONTROL_TX_PROPERTIES, MAC_REGISTRATION_TDMA, PLUGIN_ABI_VERSION,
    STATISTIC_VALUE_F64, STATISTIC_VALUE_I64, STATISTIC_VALUE_STRING, STATISTIC_VALUE_U16,
    STATISTIC_VALUE_U32, STATISTIC_VALUE_U64, STATISTIC_VALUE_U8,
};
use pcr::PcrManager;
use prost::Message;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::ffi::{c_void, CStr};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

const EVENT_TDMA_SCHEDULE: u16 = 105;
const TIMER_TX_SLOT: u32 = 1;
const TIMER_RX_COMPLETE: u32 = 2;
const TIMER_NEIGHBOR_STATUS: u32 = 4;
const BROADCAST_NEM: u16 = u16::MAX;
// Diagnostic estimate of the outer PHY envelope; never charged to slot capacity.
const PHY_ENVELOPE_BYTES: usize = 64;

#[derive(Clone, PartialEq, Message)]
struct ScheduleEvent {
    #[prost(message, repeated, tag = "1")]
    frames: Vec<ScheduleFrame>,
    #[prost(message, optional, tag = "2")]
    structure: Option<ScheduleStructure>,
    #[prost(uint64, optional, tag = "3")]
    frequency_hz: Option<u64>,
    #[prost(uint64, optional, tag = "4")]
    data_rate_bps: Option<u64>,
    #[prost(uint32, optional, tag = "5")]
    service_class: Option<u32>,
    #[prost(double, optional, tag = "6")]
    power_dbm: Option<f64>,
}

#[derive(Clone, PartialEq, Message)]
struct ScheduleFrame {
    #[prost(uint32, required, tag = "1")]
    index: u32,
    #[prost(uint64, optional, tag = "2")]
    frequency_hz: Option<u64>,
    #[prost(uint64, optional, tag = "3")]
    data_rate_bps: Option<u64>,
    #[prost(uint32, optional, tag = "4")]
    service_class: Option<u32>,
    #[prost(double, optional, tag = "5")]
    power_dbm: Option<f64>,
    #[prost(message, repeated, tag = "6")]
    slots: Vec<ScheduleSlot>,
}

#[derive(Clone, PartialEq, Message)]
struct ScheduleSlot {
    #[prost(uint32, required, tag = "1")]
    index: u32,
    #[prost(enumeration = "SlotType", required, tag = "2")]
    slot_type: i32,
    #[prost(message, optional, tag = "3")]
    tx: Option<ScheduleTx>,
    #[prost(message, optional, tag = "4")]
    rx: Option<ScheduleRx>,
}

#[derive(Clone, PartialEq, Message)]
struct ScheduleTx {
    #[prost(uint64, optional, tag = "1")]
    frequency_hz: Option<u64>,
    #[prost(uint64, optional, tag = "2")]
    data_rate_bps: Option<u64>,
    #[prost(uint32, optional, tag = "3")]
    service_class: Option<u32>,
    #[prost(double, optional, tag = "4")]
    power_dbm: Option<f64>,
    #[prost(uint32, optional, tag = "5")]
    destination: Option<u32>,
}

#[derive(Clone, PartialEq, Message)]
struct ScheduleRx {
    #[prost(uint64, optional, tag = "1")]
    frequency_hz: Option<u64>,
}

#[derive(Clone, PartialEq, Message)]
struct ScheduleStructure {
    #[prost(uint32, required, tag = "1")]
    slots_per_frame: u32,
    #[prost(uint32, required, tag = "2")]
    frames_per_multiframe: u32,
    #[prost(uint64, required, tag = "3")]
    slot_duration_microseconds: u64,
    #[prost(uint64, required, tag = "4")]
    slot_overhead_microseconds: u64,
    #[prost(uint64, required, tag = "5")]
    bandwidth_hz: u64,
}

#[derive(Clone, PartialEq, Message)]
struct TdmaBaseModelMessage {
    #[prost(uint64, required, tag = "1")]
    absolute_slot_index: u64,
    #[prost(uint64, required, tag = "2")]
    data_rate_bps: u64,
    #[prost(message, repeated, tag = "3")]
    messages: Vec<TdmaMessage>,
}

#[derive(Clone, PartialEq, Message)]
struct TdmaMessage {
    #[prost(enumeration = "TdmaMessageType", required, tag = "1")]
    message_type: i32,
    #[prost(uint32, required, tag = "2")]
    destination: u32,
    #[prost(uint32, required, tag = "3")]
    priority: u32,
    #[prost(bytes = "vec", required, tag = "4")]
    data: Vec<u8>,
    #[prost(message, optional, tag = "5")]
    fragment: Option<TdmaFragment>,
}

#[derive(Clone, PartialEq, Message)]
struct TdmaFragment {
    #[prost(bool, required, tag = "1")]
    more: bool,
    #[prost(uint32, required, tag = "2")]
    index: u32,
    #[prost(uint32, required, tag = "3")]
    offset: u32,
    #[prost(uint64, required, tag = "4")]
    sequence: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
enum TdmaMessageType {
    Data = 1,
    Control = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
enum SlotType {
    Tx = 1,
    Rx = 2,
    Idle = 3,
}

#[derive(Clone)]
enum Slot {
    Tx {
        frequency_hz: u64,
        data_rate_bps: u64,
        service_class: u8,
        power_dbm: f64,
        destination: u16,
    },
    Rx {
        frequency_hz: u64,
    },
    Idle,
}

#[derive(Clone)]
struct Schedule {
    slots_per_frame: u32,
    frames_per_multiframe: u32,
    slot_duration_us: u64,
    overhead_us: u64,
    bandwidth_hz: u64,
    slots: Vec<Slot>,
}

impl Schedule {
    fn cycle_slots(&self) -> u64 {
        u64::from(self.slots_per_frame) * u64::from(self.frames_per_multiframe)
    }

    fn slot(&self, absolute: u64) -> &Slot {
        &self.slots[(absolute % self.cycle_slots()) as usize]
    }

    fn absolute_slot(&self, time_us: i64) -> u64 {
        (time_us.max(0) as u64) / self.slot_duration_us
    }

    fn slot_start(&self, absolute: u64) -> i64 {
        i64::try_from(absolute.saturating_mul(self.slot_duration_us)).unwrap_or(i64::MAX)
    }

    fn next_tx(&self, after_absolute: u64) -> Option<u64> {
        (1..=self.cycle_slots())
            .map(|offset| after_absolute.saturating_add(offset))
            .find(|index| matches!(self.slot(*index), Slot::Tx { .. }))
    }
}

struct OwnedPacket {
    info: FfiPacketInfo,
    payload: Vec<u8>,
}

struct QueuedPacket {
    packet: OwnedPacket,
    sequence: u64,
    offset: usize,
    fragment_index: u16,
}

struct PendingReception {
    info: FfiPacketInfo,
    wire: TdmaBaseModelMessage,
    model_sequence: u64,
    packet_len: usize,
    spectrum_query: FfiSpectrumQuery,
}

struct Reassembly {
    info: FfiPacketInfo,
    total_fragments: Option<u64>,
    pieces: BTreeMap<usize, Vec<u8>>,
    fragment_indices: HashSet<u32>,
    last_update_us: i64,
}

#[derive(Default)]
struct QueueStatistics {
    enqueued: u64,
    dequeued: u64,
    overflow: u64,
    too_big: u64,
    classes: [u64; 5],
    fragment_histogram: [u64; 10],
}

#[derive(Clone, Default)]
struct PacketAcceptInfo {
    tx_bytes: u64,
    rx_bytes: u64,
    tx_seen: bool,
    rx_seen: bool,
}

#[derive(Clone, Default)]
struct PacketDropInfo {
    bytes: [u64; 12],
    seen: [bool; 12],
}

#[derive(Clone, Copy)]
enum PacketDropReason {
    Sinr = 0,
    RegistrationId = 1,
    Destination = 2,
    QueueOverflow = 3,
    BadControl = 4,
    BadSpectrumQuery = 5,
    FlowControl = 6,
    TooBig = 7,
    TooLong = 8,
    Frequency = 9,
    SlotError = 10,
    MissingFragment = 11,
}

#[derive(Default)]
struct TxSlotStatistics {
    valid: u64,
    missed: u64,
    too_big: u64,
    quantiles: [u64; 8],
}

#[derive(Default)]
struct RxSlotStatistics {
    status: [u64; 7],
    quantiles: [u64; 8],
}

struct State {
    promiscuous: bool,
    flow_control_enable: bool,
    flow_control_tokens: u16,
    flow_manager: FlowControlManager,
    pcr_uri: String,
    pcr: Option<PcrManager>,
    queue_depth: usize,
    aggregation_enable: bool,
    aggregation_threshold: f64,
    fragmentation_enable: bool,
    strict_dequeue: bool,
    fragment_timeout_us: i64,
    fragment_check_us: i64,
    last_fragment_check_us: i64,
    neighbor_metric_delete_us: u64,
    neighbor_metric_update_us: i64,
    schedule: Option<Schedule>,
    schedule_frequencies: std::collections::BTreeSet<u64>,
    queues: [VecDeque<QueuedPacket>; 5],
    queue_statistics: [QueueStatistics; 5],
    broadcast_accept: [HashMap<u16, PacketAcceptInfo>; 5],
    broadcast_drop: [HashMap<u16, PacketDropInfo>; 5],
    unicast_accept: [HashMap<u16, PacketAcceptInfo>; 5],
    unicast_drop: [HashMap<u16, PacketDropInfo>; 5],
    tx_slot_statistics: HashMap<u32, TxSlotStatistics>,
    rx_slot_statistics: HashMap<u32, RxSlotStatistics>,
    aggregation_histogram: HashMap<u64, u64>,
    table_generations: HashMap<String, u64>,
    sequence: u64,
    frame_sequence: u64,
    next_tx_slot: Option<u64>,
    reassembly: HashMap<(u16, u8, u64), Reassembly>,
    pending_rx: BTreeMap<u64, PendingReception>,
    timers: HashMap<u64, u32>,
    random_state: LegacyRandom,
    started: bool,
}

struct TdmaMac {
    id: u16,
    framework: FfiFrameworkService,
    model_counters: HashMap<String, u64>,
    tables: HashMap<String, u64>,
    state: Mutex<State>,
}

impl TdmaMac {
    fn new(id: u16, framework: FfiFrameworkService) -> Self {
        let mut model_counters = HashMap::new();
        for name in [
            "scheduler.scheduleRejectSlotIndexRange",
            "scheduler.scheduleRejectFrameIndexRange",
            "scheduler.scheduleRejectUpdateBeforeFull",
            "scheduler.scheduleRejectOther",
            "scheduler.scheduleAcceptFull",
            "scheduler.scheduleAcceptUpdate",
            "numTxSlotValid",
            "numTxSlotErrorMissed",
            "numTxSlotErrorTooBig",
            "TxFrameSent",
            "TxComponentBytes",
            "TxWireBytes",
            "TxAirtimeMicroseconds",
            "TxQueueOverflowPackets",
            "TxQueueOverflowBytes",
            "numRxSlotValid",
            "numRxSlotErrorMissed",
            "numRxSlotErrorRxDuringIdle",
            "numRxSlotErrorRxDuringTx",
            "numRxSlotErrorRxTooLong",
            "numRxSlotErrorRxWrongFrequency",
            "numRxSlotErrorRxLock",
            "highWaterMarkQueue0",
            "highWaterMarkQueue1",
            "highWaterMarkQueue2",
            "highWaterMarkQueue3",
            "highWaterMarkQueue4",
        ] {
            let handle = (framework.register_counter)(
                framework.framework_ctx,
                std::ffi::CString::new(name).unwrap().as_ptr(),
                c"TDMA model statistic".as_ptr(),
                !name.starts_with("numTxSlot") && !name.starts_with("numRxSlot"),
            );
            model_counters.insert(name.to_string(), handle);
        }
        let mut tables: HashMap<String, u64> = [
            (
                "scheduler.ScheduleInfoTable",
                &[
                    "Index",
                    "Frame",
                    "Slot",
                    "Type",
                    "Frequency",
                    "Data Rate",
                    "Power",
                    "Class",
                    "Destination",
                ][..],
            ),
            ("scheduler.StructureInfoTable", &["Name", "Value"]),
            (
                "QueueStatusTable",
                &[
                    "Queue", "Enqueued", "Dequeued", "Overflow", "Too Big", "0", "1", "2", "3", "4",
                ],
            ),
            (
                "QueueFragmentHistogram",
                &["Queue", "1", "2", "3", "4", "5", "6", "7", "8", "9", ">9"],
            ),
        ]
        .into_iter()
        .filter_map(|(name, labels)| {
            let name_value = std::ffi::CString::new(name).ok()?;
            let labels = labels
                .iter()
                .map(|label| std::ffi::CString::new(*label))
                .collect::<Result<Vec<_>, _>>()
                .ok()?;
            let pointers = labels
                .iter()
                .map(|label| label.as_ptr())
                .collect::<Vec<_>>();
            let handle = (framework.register_table)(
                framework.framework_ctx,
                name_value.as_ptr(),
                pointers.as_ptr(),
                pointers.len(),
                c"TDMA model status".as_ptr(),
                false,
            );
            (handle != 0).then(|| (name.to_string(), handle))
        })
        .collect();
        let mut register_table = |name: &str, labels: &[&str], clearable: bool| {
            let Ok(name_value) = std::ffi::CString::new(name) else {
                return;
            };
            let Ok(labels) = labels
                .iter()
                .map(|label| std::ffi::CString::new(*label))
                .collect::<Result<Vec<_>, _>>()
            else {
                return;
            };
            let pointers = labels
                .iter()
                .map(|label| label.as_ptr())
                .collect::<Vec<_>>();
            let handle = (framework.register_table)(
                framework.framework_ctx,
                name_value.as_ptr(),
                pointers.as_ptr(),
                pointers.len(),
                c"TDMA model status".as_ptr(),
                clearable,
            );
            if handle != 0 {
                tables.insert(name.to_string(), handle);
            }
        };
        register_table(
            "PacketComponentAggregationHistogram",
            &["Components", "Count"],
            false,
        );
        register_table(
            "TxSlotStatusTable",
            &[
                "Index", "Frame", "Slot", "Valid", "Missed", "Big", ".25", ".50", ".75", "1.0",
                "1.25", "1.50", "1.75", ">1.75",
            ],
            false,
        );
        register_table(
            "RxSlotStatusTable",
            &[
                "Index", "Frame", "Slot", "Valid", "Missed", "Idle", "Tx", "Long", "Freq", "Lock",
                ".25", ".50", ".75", "1.0", "1.25", "1.50", "1.75", ">1.75",
            ],
            false,
        );
        for queue in 0..5 {
            for prefix in ["BroadcastByteAcceptTable", "UnicastByteAcceptTable"] {
                register_table(
                    &format!("{prefix}{queue}"),
                    &["NEM", "Num Bytes Tx", "Num Bytes Rx"],
                    true,
                );
            }
            for prefix in ["BroadcastByteDropTable", "UnicastByteDropTable"] {
                register_table(
                    &format!("{prefix}{queue}"),
                    &[
                        "NEM",
                        "SINR",
                        "Reg Id",
                        "Dst MAC",
                        "Queue Overflow",
                        "Bad Control",
                        "Bad Spectrum Query",
                        "Flow Control",
                        "Big",
                        "Long",
                        "Freq",
                        "Slot Error",
                        "Miss Fragment",
                    ],
                    true,
                );
            }
        }
        let mac = Self {
            id,
            framework,
            model_counters,
            tables,
            state: Mutex::new(State {
                promiscuous: false,
                flow_control_enable: false,
                flow_control_tokens: 10,
                flow_manager: FlowControlManager::new(),
                pcr_uri: String::new(),
                pcr: None,
                queue_depth: 256,
                aggregation_enable: true,
                aggregation_threshold: 90.0,
                fragmentation_enable: true,
                strict_dequeue: false,
                fragment_timeout_us: 5_000_000,
                fragment_check_us: 2_000_000,
                last_fragment_check_us: 0,
                neighbor_metric_delete_us: 60_000_000,
                neighbor_metric_update_us: 1_000_000,
                schedule: None,
                schedule_frequencies: std::collections::BTreeSet::new(),
                queues: std::array::from_fn(|_| VecDeque::new()),
                queue_statistics: std::array::from_fn(|_| QueueStatistics::default()),
                broadcast_accept: std::array::from_fn(|_| HashMap::new()),
                broadcast_drop: std::array::from_fn(|_| HashMap::new()),
                unicast_accept: std::array::from_fn(|_| HashMap::new()),
                unicast_drop: std::array::from_fn(|_| HashMap::new()),
                tx_slot_statistics: HashMap::new(),
                rx_slot_statistics: HashMap::new(),
                aggregation_histogram: HashMap::new(),
                table_generations: HashMap::new(),
                sequence: 0,
                frame_sequence: 0,
                next_tx_slot: None,
                reassembly: HashMap::new(),
                pending_rx: BTreeMap::new(),
                timers: HashMap::new(),
                random_state: LegacyRandom::from_clock(),
                started: false,
            }),
        };
        {
            let state = mac.state.lock().unwrap();
            for index in 0..5 {
                publish_queue_tables(&mac, &state, index);
            }
        }
        mac
    }

    fn increment(&self, name: &str, amount: u64) {
        if let Some(handle) = self.model_counters.get(name).copied() {
            (self.framework.increment_counter)(self.framework.framework_ctx, handle, amount);
        }
    }

    fn maximize(&self, name: &str, value: u64) {
        if let Some(handle) = self.model_counters.get(name).copied() {
            (self.framework.maximize_counter)(self.framework.framework_ctx, handle, value);
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

    fn clear_table(&self, name: &str) {
        if let Some(handle) = self.tables.get(name).copied() {
            (self.framework.clear_table)(self.framework.framework_ctx, handle);
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

fn stat_u8(value: u8) -> FfiStatisticValue {
    FfiStatisticValue {
        value_type: STATISTIC_VALUE_U8,
        ..stat_u64(u64::from(value))
    }
}
fn stat_u32(value: u32) -> FfiStatisticValue {
    FfiStatisticValue {
        value_type: STATISTIC_VALUE_U32,
        ..stat_u64(u64::from(value))
    }
}

fn stat_u16(value: u16) -> FfiStatisticValue {
    FfiStatisticValue {
        value_type: STATISTIC_VALUE_U16,
        ..stat_u64(u64::from(value))
    }
}

// The original table initializes cells with signed long literals, then replaces
// only the updated cells with unsigned counters.
fn stat_counter(value: u64, updated: bool) -> FfiStatisticValue {
    FfiStatisticValue {
        value_type: if updated {
            STATISTIC_VALUE_U64
        } else {
            STATISTIC_VALUE_I64
        },
        ..stat_u64(value)
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

fn parse_bool(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "on" | "true" | "yes" => Some(true),
        "0" | "off" | "false" | "no" => Some(false),
        _ => None,
    }
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
        let raw = if item.values.len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(item.values.data, item.values.len) }
        };
        let mut values = Vec::with_capacity(raw.len());
        for value in raw {
            if value.is_null() {
                return None;
            }
            values.push(unsafe { CStr::from_ptr(*value) }.to_str().ok()?.to_string());
        }
        result.push((name, values));
    }
    Some(result)
}

fn controls(
    messages: *const FfiControlMessage,
    count: usize,
) -> Option<&'static [FfiControlMessage]> {
    if count > 4096 || (count != 0 && messages.is_null()) {
        None
    } else if count == 0 {
        Some(&[])
    } else {
        Some(unsafe { std::slice::from_raw_parts(messages, count) })
    }
}

fn control_payload(message: &FfiControlMessage) -> Option<&'static [u8]> {
    if message.payload.len != 0 && message.payload.data.is_null() {
        None
    } else if message.payload.len == 0 {
        Some(&[])
    } else {
        Some(unsafe { std::slice::from_raw_parts(message.payload.data, message.payload.len) })
    }
}

fn own_packet(packet: *const FfiPacket) -> Option<OwnedPacket> {
    let packet = unsafe { packet.as_ref() }?;
    if packet.payload.len > 64 << 20 || (packet.payload.len != 0 && packet.payload.data.is_null()) {
        return None;
    }
    let payload = if packet.payload.len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(packet.payload.data, packet.payload.len) }.to_vec()
    };
    Some(OwnedPacket {
        info: packet.info,
        payload,
    })
}

fn now_us() -> i64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    i64::try_from(now.as_micros()).unwrap_or(i64::MAX)
}

fn random_unit(state: &mut LegacyRandom) -> f64 {
    f64::from(state.unit())
}

fn parse_schedule(data: &[u8], current: Option<&Schedule>) -> Result<(Schedule, bool), String> {
    let event =
        ScheduleEvent::decode(data).map_err(|error| format!("invalid schedule: {error}"))?;
    let full = event.structure.is_some();
    let mut schedule = if let Some(structure) = event.structure {
        if structure.slots_per_frame == 0
            || structure.frames_per_multiframe == 0
            || structure.slot_duration_microseconds == 0
            || structure.slot_overhead_microseconds >= structure.slot_duration_microseconds
            || structure.bandwidth_hz == 0
        {
            return Err("invalid TDMA slot structure".into());
        }
        let count = u64::from(structure.slots_per_frame)
            .checked_mul(u64::from(structure.frames_per_multiframe))
            .and_then(|value| usize::try_from(value).ok())
            .filter(|value| *value <= 1_000_000)
            .ok_or_else(|| "TDMA schedule is too large".to_string())?;
        Schedule {
            slots_per_frame: structure.slots_per_frame,
            frames_per_multiframe: structure.frames_per_multiframe,
            slot_duration_us: structure.slot_duration_microseconds,
            overhead_us: structure.slot_overhead_microseconds,
            bandwidth_hz: structure.bandwidth_hz,
            slots: vec![Slot::Idle; count],
        }
    } else {
        current
            .cloned()
            .ok_or_else(|| "schedule update received before full schedule".to_string())?
    };
    for frame in event.frames {
        if frame.index >= schedule.frames_per_multiframe {
            return Err("TDMA frame index is out of range".into());
        }
        let frame_frequency = frame.frequency_hz.or(event.frequency_hz);
        let frame_rate = frame.data_rate_bps.or(event.data_rate_bps);
        let frame_class = frame.service_class.or(event.service_class).unwrap_or(0);
        let frame_power = frame.power_dbm.or(event.power_dbm).unwrap_or(0.0);
        if full {
            let explicit = frame
                .slots
                .iter()
                .map(|slot| slot.index)
                .collect::<HashSet<_>>();
            if explicit.len() < schedule.slots_per_frame as usize {
                let frequency_hz = frame_frequency
                    .filter(|frequency| *frequency != 0)
                    .ok_or_else(|| "undefined TDMA receive slot has no frequency".to_string())?;
                let frame_start = frame.index as usize * schedule.slots_per_frame as usize;
                for slot_index in 0..schedule.slots_per_frame {
                    if !explicit.contains(&slot_index) {
                        schedule.slots[frame_start + slot_index as usize] =
                            Slot::Rx { frequency_hz };
                    }
                }
            }
        }
        for slot in frame.slots {
            if slot.index >= schedule.slots_per_frame {
                return Err("TDMA slot index is out of range".into());
            }
            let index = (frame.index * schedule.slots_per_frame + slot.index) as usize;
            schedule.slots[index] = match SlotType::try_from(slot.slot_type).ok() {
                Some(SlotType::Tx) => {
                    let tx = slot.tx.unwrap_or_default();
                    let frequency_hz = tx.frequency_hz.or(frame_frequency).unwrap_or(0);
                    let data_rate_bps = tx.data_rate_bps.or(frame_rate).unwrap_or(0);
                    let service_class = tx.service_class.unwrap_or(frame_class);
                    let power_dbm = tx.power_dbm.unwrap_or(frame_power);
                    // A zero schedule destination means no destination filter,
                    // matching the legacy queue manager contract.
                    let destination = tx.destination.unwrap_or(0);
                    if frequency_hz == 0
                        || data_rate_bps == 0
                        || service_class > 3
                        || destination > u32::from(u16::MAX)
                        || !power_dbm.is_finite()
                    {
                        return Err("invalid TDMA transmit slot".into());
                    }
                    Slot::Tx {
                        frequency_hz,
                        data_rate_bps,
                        service_class: service_class as u8,
                        power_dbm,
                        destination: destination as u16,
                    }
                }
                Some(SlotType::Rx) => {
                    let frequency_hz = slot
                        .rx
                        .and_then(|rx| rx.frequency_hz)
                        .or(frame_frequency)
                        .unwrap_or(0);
                    if frequency_hz == 0 {
                        return Err("invalid TDMA receive slot".into());
                    }
                    Slot::Rx { frequency_hz }
                }
                Some(SlotType::Idle) => Slot::Idle,
                None => return Err("invalid TDMA slot type".into()),
            };
        }
    }
    Ok((schedule, full))
}

fn publish_schedule_tables(mac: &TdmaMac, schedule: &Schedule) {
    for (key, name, value) in [
        (0, c"bandwidth", stat_u64(schedule.bandwidth_hz)),
        (1, c"frames", stat_u32(schedule.frames_per_multiframe)),
        (2, c"slots", stat_u32(schedule.slots_per_frame)),
        (
            3,
            c"slotduration",
            stat_counter(schedule.slot_duration_us, false),
        ),
        (
            4,
            c"slotoverhead",
            stat_counter(schedule.overhead_us, false),
        ),
    ] {
        mac.set_table_row(
            "scheduler.StructureInfoTable",
            &[key],
            &[stat_string(name), value],
        );
    }
    for (index, slot) in schedule.slots.iter().enumerate() {
        let index = index as u64;
        let frame = index / u64::from(schedule.slots_per_frame);
        let slot_index = index % u64::from(schedule.slots_per_frame);
        let values = match slot {
            Slot::Tx {
                frequency_hz,
                data_rate_bps,
                service_class,
                power_dbm,
                destination,
            } => vec![
                stat_u32(index as u32),
                stat_u32(frame as u32),
                stat_u32(slot_index as u32),
                stat_string(c"TX"),
                stat_u64(*frequency_hz),
                stat_u64(*data_rate_bps),
                stat_f64(*power_dbm),
                stat_u8(*service_class),
                stat_u16(*destination),
            ],
            Slot::Rx { frequency_hz } => vec![
                stat_u32(index as u32),
                stat_u32(frame as u32),
                stat_u32(slot_index as u32),
                stat_string(c"RX"),
                stat_u64(*frequency_hz),
                stat_string(c""),
                stat_string(c""),
                stat_string(c""),
                stat_string(c""),
            ],
            Slot::Idle => vec![
                stat_u32(index as u32),
                stat_u32(frame as u32),
                stat_u32(slot_index as u32),
                stat_string(c"IDLE"),
                stat_string(c""),
                stat_string(c""),
                stat_string(c""),
                stat_string(c""),
                stat_string(c""),
            ],
        };
        mac.set_table_row("scheduler.ScheduleInfoTable", &[index], &values);
    }
}

fn publish_queue_tables(mac: &TdmaMac, state: &State, index: usize) {
    let statistics = &state.queue_statistics[index];
    let mut status = vec![
        stat_u8(index as u8),
        stat_u64(statistics.enqueued),
        stat_u64(statistics.dequeued),
        stat_u64(statistics.overflow),
        stat_u64(statistics.too_big),
    ];
    status.extend(statistics.classes.iter().copied().map(stat_u64));
    mac.set_table_row("QueueStatusTable", &[index as u64], &status);
    let mut histogram = vec![stat_u8(index as u8)];
    histogram.extend(statistics.fragment_histogram.iter().copied().map(stat_u64));
    mac.set_table_row("QueueFragmentHistogram", &[index as u64], &histogram);
}

fn priority_to_queue(priority: u8) -> usize {
    match priority {
        8..=23 => 1,
        32..=47 => 2,
        48..=63 => 3,
        _ => 0,
    }
}

#[allow(clippy::too_many_arguments)]
fn record_packet_accept(
    mac: &TdmaMac,
    state: &mut State,
    queue: usize,
    source: u16,
    destination: u16,
    size: usize,
    inbound: bool,
) {
    let broadcast = destination == BROADCAST_NEM;
    let prefix = if broadcast {
        "BroadcastByteAcceptTable"
    } else {
        "UnicastByteAcceptTable"
    };
    let name = format!("{prefix}{queue}");
    let generation = mac.table_generation(&name);
    let reset = state
        .table_generations
        .insert(name.clone(), generation)
        .is_some_and(|previous| previous != generation);
    let infos = if broadcast {
        &mut state.broadcast_accept[queue]
    } else {
        &mut state.unicast_accept[queue]
    };
    if reset {
        infos.clear();
    }
    let info = infos.entry(source).or_default();
    if inbound {
        info.rx_bytes = info.rx_bytes.saturating_add(size as u64);
        info.rx_seen = true;
    } else {
        info.tx_bytes = info.tx_bytes.saturating_add(size as u64);
        info.tx_seen = true;
    }
    let row = [
        stat_u16(source),
        stat_counter(info.tx_bytes, info.tx_seen),
        stat_counter(info.rx_bytes, info.rx_seen),
    ];
    mac.set_table_row(&name, &[u64::from(source)], &row);
}

#[allow(clippy::too_many_arguments)]
fn record_packet_drop(
    mac: &TdmaMac,
    state: &mut State,
    queue: usize,
    source: u16,
    destination: u16,
    size: usize,
    reason: PacketDropReason,
) {
    let broadcast = destination == BROADCAST_NEM;
    let prefix = if broadcast {
        "BroadcastByteDropTable"
    } else {
        "UnicastByteDropTable"
    };
    let name = format!("{prefix}{queue}");
    let generation = mac.table_generation(&name);
    let reset = state
        .table_generations
        .insert(name.clone(), generation)
        .is_some_and(|previous| previous != generation);
    let infos = if broadcast {
        &mut state.broadcast_drop[queue]
    } else {
        &mut state.unicast_drop[queue]
    };
    if reset {
        infos.clear();
    }
    let info = infos.entry(source).or_default();
    info.bytes[reason as usize] = info.bytes[reason as usize].saturating_add(size as u64);
    info.seen[reason as usize] = true;
    let mut row = Vec::with_capacity(13);
    row.push(stat_u16(source));
    row.extend(
        info.bytes
            .iter()
            .zip(info.seen)
            .map(|(&value, updated)| stat_counter(value, updated)),
    );
    mac.set_table_row(&name, &[u64::from(source)], &row);
}

fn record_message_drop(
    mac: &TdmaMac,
    state: &mut State,
    source: u16,
    message: &TdmaMessage,
    reason: PacketDropReason,
) {
    let destination = message.destination as u16;
    let priority = message.priority as u8;
    if TdmaMessageType::try_from(message.message_type).is_err() {
        return;
    }
    record_packet_drop(
        mac,
        state,
        priority_to_queue(priority),
        source,
        destination,
        message.data.len(),
        reason,
    );
}

fn record_all_message_drops(
    mac: &TdmaMac,
    state: &mut State,
    source: u16,
    messages: &[TdmaMessage],
    reason: PacketDropReason,
) {
    for message in messages {
        record_message_drop(mac, state, source, message, reason);
    }
}

fn quantile(ratio: f64) -> usize {
    if ratio <= 0.25 {
        0
    } else if ratio <= 0.50 {
        1
    } else if ratio <= 0.75 {
        2
    } else if ratio <= 1.00 {
        3
    } else if ratio <= 1.25 {
        4
    } else if ratio <= 1.50 {
        5
    } else if ratio <= 1.75 {
        6
    } else {
        7
    }
}

fn slot_coordinates(schedule: &Schedule, absolute_slot: u64) -> (u32, u32, u32) {
    let relative = (absolute_slot % schedule.cycle_slots()) as u32;
    (
        relative,
        relative / schedule.slots_per_frame,
        relative % schedule.slots_per_frame,
    )
}

fn slot_ratio(schedule: &Schedule, absolute_slot: u64, now: i64) -> f64 {
    now.saturating_sub(schedule.slot_start(absolute_slot)) as f64 / schedule.slot_duration_us as f64
}

#[derive(Clone, Copy)]
enum TxSlotStatus {
    Valid,
    Missed,
}

fn update_tx_slot_status(mac: &TdmaMac, absolute_slot: u64, now: i64, status: TxSlotStatus) {
    let mut state = mac.state.lock().unwrap();
    let Some(schedule) = state.schedule.clone() else {
        return;
    };
    let (relative, frame, slot) = slot_coordinates(&schedule, absolute_slot);
    let q = quantile(slot_ratio(&schedule, absolute_slot, now));
    let info = state.tx_slot_statistics.entry(relative).or_default();
    let counter = match status {
        TxSlotStatus::Valid => {
            info.valid = info.valid.saturating_add(1);
            "numTxSlotValid"
        }
        TxSlotStatus::Missed => {
            info.missed = info.missed.saturating_add(1);
            "numTxSlotErrorMissed"
        }
    };
    info.quantiles[q] = info.quantiles[q].saturating_add(1);
    let mut row = vec![
        stat_u32(relative),
        stat_u32(frame),
        stat_u32(slot),
        stat_counter(info.valid, info.valid != 0),
        stat_counter(info.missed, info.missed != 0),
        stat_counter(info.too_big, info.too_big != 0),
    ];
    row.extend(
        info.quantiles
            .iter()
            .copied()
            .map(|value| stat_counter(value, value != 0)),
    );
    mac.increment(counter, 1);
    mac.set_table_row("TxSlotStatusTable", &[u64::from(relative)], &row);
}

#[derive(Clone, Copy)]
enum RxSlotStatus {
    Valid = 0,
    Missed = 1,
    Idle = 2,
    Tx = 3,
    TooLong = 4,
    WrongFrequency = 5,
    Lock = 6,
}

fn update_rx_slot_status(
    mac: &TdmaMac,
    state: &mut State,
    absolute_slot: u64,
    ratio_slot: u64,
    now: i64,
    status: RxSlotStatus,
) {
    let Some(schedule) = state.schedule.clone() else {
        return;
    };
    let (relative, frame, slot) = slot_coordinates(&schedule, absolute_slot);
    let q = quantile(slot_ratio(&schedule, ratio_slot, now));
    let info = state.rx_slot_statistics.entry(relative).or_default();
    info.status[status as usize] = info.status[status as usize].saturating_add(1);
    info.quantiles[q] = info.quantiles[q].saturating_add(1);
    let counter = match status {
        RxSlotStatus::Valid => "numRxSlotValid",
        RxSlotStatus::Missed => "numRxSlotErrorMissed",
        RxSlotStatus::Idle => "numRxSlotErrorRxDuringIdle",
        RxSlotStatus::Tx => "numRxSlotErrorRxDuringTx",
        RxSlotStatus::TooLong => "numRxSlotErrorRxTooLong",
        RxSlotStatus::WrongFrequency => "numRxSlotErrorRxWrongFrequency",
        RxSlotStatus::Lock => "numRxSlotErrorRxLock",
    };
    let mut row = vec![stat_u32(relative), stat_u32(frame), stat_u32(slot)];
    row.extend(
        info.status
            .iter()
            .copied()
            .map(|value| stat_counter(value, value != 0)),
    );
    row.extend(
        info.quantiles
            .iter()
            .copied()
            .map(|value| stat_counter(value, value != 0)),
    );
    mac.increment(counter, 1);
    mac.set_table_row("RxSlotStatusTable", &[u64::from(relative)], &row);
}

fn update_aggregation_histogram(mac: &TdmaMac, state: &mut State, components: usize) {
    let components = components as u64;
    let count = state.aggregation_histogram.entry(components).or_default();
    *count = count.saturating_add(1);
    mac.set_table_row(
        "PacketComponentAggregationHistogram",
        &[components],
        &[stat_u64(components), stat_counter(*count, *count != 1)],
    );
}

fn expire_reassembly(mac: &TdmaMac, state: &mut State, now: i64) {
    if now
        < state
            .last_fragment_check_us
            .saturating_add(state.fragment_check_us)
    {
        return;
    }
    let timeout = state.fragment_timeout_us;
    let expired = state
        .reassembly
        .iter()
        .filter_map(|(key, entry)| {
            (now.saturating_sub(entry.last_update_us) >= timeout).then_some(*key)
        })
        .collect::<Vec<_>>();
    for key in expired {
        if let Some(entry) = state.reassembly.remove(&key) {
            let bytes = entry.pieces.values().map(Vec::len).sum();
            record_packet_drop(
                mac,
                state,
                priority_to_queue(entry.info.priority),
                key.0,
                entry.info.destination,
                bytes,
                PacketDropReason::MissingFragment,
            );
        }
    }
    state.last_fragment_check_us = now;
}

fn send_flow_update(mac: &TdmaMac, tokens: u16) {
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

extern "C" fn init(id: u16, framework: *const FfiFrameworkService) -> *mut c_void {
    let Some(framework) = (unsafe { framework.as_ref() }) else {
        return std::ptr::null_mut();
    };
    Box::into_raw(Box::new(TdmaMac::new(id, *framework))).cast()
}

extern "C" fn configure(plugin: *mut c_void, request: *const c_void) -> bool {
    let Some(mac) = (unsafe { (plugin as *mut TdmaMac).as_ref() }) else {
        return false;
    };
    let Some(items) = configuration(request) else {
        return false;
    };
    let mut state = mac.state.lock().unwrap();
    for (name, values) in items {
        let Some(value) = values.first() else {
            return false;
        };
        match name.as_str() {
            "enablepromiscuousmode" => {
                let Some(v) = parse_bool(value) else {
                    return false;
                };
                state.promiscuous = v;
            }
            "flowcontrolenable" => {
                state.flow_control_enable = match parse_bool(value) {
                    Some(value) => value,
                    None => return false,
                };
            }
            "flowcontroltokens" => {
                let Ok(v) = value.parse::<u16>() else {
                    return false;
                };
                state.flow_control_tokens = v;
            }
            "pcrcurveuri" => state.pcr_uri.clone_from(value),
            "fragmenttimeoutthreshold" => {
                let Ok(v) = value.parse::<u16>() else {
                    return false;
                };
                state.fragment_timeout_us = i64::from(v).saturating_mul(1_000_000);
            }
            "fragmentcheckthreshold" => {
                let Ok(v) = value.parse::<u16>() else {
                    return false;
                };
                state.fragment_check_us = i64::from(v).saturating_mul(1_000_000);
            }
            "neighbormetricdeletetime" => {
                let Some(seconds) = value
                    .parse::<f64>()
                    .ok()
                    .filter(|v| v.is_finite() && (1.0..=3_660.0).contains(v))
                else {
                    return false;
                };
                state.neighbor_metric_delete_us = (seconds * 1_000_000.0).round() as u64;
            }
            "neighbormetricupdateinterval" => {
                let Some(seconds) = value
                    .parse::<f64>()
                    .ok()
                    .filter(|v| v.is_finite() && (0.1..=60.0).contains(v))
                else {
                    return false;
                };
                state.neighbor_metric_update_us = (seconds * 1_000_000.0).round() as i64;
            }
            "queue.depth" => {
                let Ok(v) = value.parse::<usize>() else {
                    return false;
                };
                if v > 65_535 {
                    return false;
                }
                state.queue_depth = v;
            }
            "queue.aggregationenable" => {
                let Some(v) = parse_bool(value) else {
                    return false;
                };
                state.aggregation_enable = v;
            }
            "queue.aggregationslotthreshold" => {
                let Ok(v) = value.parse::<f64>() else {
                    return false;
                };
                if !v.is_finite() || !(0.0..=100.0).contains(&v) {
                    return false;
                }
                state.aggregation_threshold = v;
            }
            "queue.fragmentationenable" => {
                let Some(v) = parse_bool(value) else {
                    return false;
                };
                state.fragmentation_enable = v;
            }
            "queue.strictdequeueenable" => {
                let Some(v) = parse_bool(value) else {
                    return false;
                };
                state.strict_dequeue = v;
            }
            _ => return false,
        }
    }
    true
}

extern "C" fn start(plugin: *mut c_void) -> bool {
    let Some(mac) = (unsafe { (plugin as *mut TdmaMac).as_ref() }) else {
        return false;
    };
    {
        let mut state = mac.state.lock().unwrap();
        if state.pcr_uri.is_empty() {
            return false;
        }
        let Ok(pcr) = PcrManager::load(&state.pcr_uri) else {
            return false;
        };
        state.pcr = Some(pcr);
        state.started = true;
    }
    true
}

extern "C" fn post_start(plugin: *mut c_void) {
    let Some(mac) = (unsafe { (plugin as *mut TdmaMac).as_ref() }) else {
        return;
    };
    schedule_next_tx(mac, true);
    let flow_update = {
        let mut state = mac.state.lock().unwrap();
        state.flow_control_enable.then(|| {
            let total = state.flow_control_tokens;
            state.flow_manager.start(total)
        })
    };
    if let Some(tokens) = flow_update {
        send_flow_update(mac, tokens);
    }
    schedule_neighbor_status(mac);
}

extern "C" fn stop(plugin: *mut c_void) {
    let Some(mac) = (unsafe { (plugin as *mut TdmaMac).as_ref() }) else {
        return;
    };
    let timers: Vec<_> = {
        let mut state = mac.state.lock().unwrap();
        state.started = false;
        state.flow_manager.stop();
        state.next_tx_slot = None;
        state.pending_rx.clear();
        state.timers.drain().map(|(timer, _)| timer).collect()
    };
    for timer in timers {
        (mac.framework.cancel_timed_event)(mac.framework.framework_ctx, mac.id, timer);
    }
}

extern "C" fn destroy(plugin: *mut c_void) {
    if !plugin.is_null() {
        stop(plugin);
        unsafe { drop(Box::from_raw(plugin as *mut TdmaMac)) };
    }
}

fn schedule_timer(mac: &TdmaMac, when: i64, event: u32, data: &[u8]) -> u64 {
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

fn schedule_neighbor_status(mac: &TdmaMac) {
    let when = {
        let state = mac.state.lock().unwrap();
        if !state.started {
            return;
        }
        now_us().saturating_add(state.neighbor_metric_update_us)
    };
    let timer = schedule_timer(mac, when, TIMER_NEIGHBOR_STATUS, &0u64.to_be_bytes());
    if timer != 0 {
        mac.state
            .lock()
            .unwrap()
            .timers
            .insert(timer, TIMER_NEIGHBOR_STATUS);
    }
}

fn schedule_next_tx(mac: &TdmaMac, first_after_schedule: bool) {
    let now = now_us();
    let next = {
        let state = mac.state.lock().unwrap();
        let Some(schedule) = state.schedule.as_ref().filter(|_| state.started) else {
            return;
        };
        let current = schedule.absolute_slot(now);
        let after = if first_after_schedule {
            let cycle = schedule.cycle_slots();
            current / cycle * cycle + cycle - 1
        } else {
            current
        };
        schedule
            .next_tx(after)
            .map(|slot| (slot, schedule.slot_start(slot)))
    };
    let Some((slot, when)) = next else { return };
    let timer = schedule_timer(mac, when, TIMER_TX_SLOT, &slot.to_be_bytes());
    if timer != 0 {
        let mut state = mac.state.lock().unwrap();
        state.timers.insert(timer, TIMER_TX_SLOT);
        state.next_tx_slot = Some(slot);
    }
}

#[cfg(test)]
fn queue_index(state: &State, requested: u8, destination: u16) -> Option<usize> {
    let eligible = |index: usize| {
        state.queues[index]
            .iter()
            .any(|queued| destination == 0 || queued.packet.info.destination == destination)
    };
    let requested = usize::from(requested.min(4));
    if eligible(requested) {
        Some(requested)
    } else if state.strict_dequeue {
        None
    } else {
        (0..5).rev().find(|index| eligible(*index))
    }
}

struct Transmission {
    info: FfiPacketInfo,
    message: TdmaMessage,
    frequency: u64,
    rate: u64,
    category: u8,
    power: f64,
    bandwidth: u64,
    tx_time: i64,
}

impl Transmission {
    fn more(&self) -> bool {
        self.message
            .fragment
            .as_ref()
            .is_some_and(|fragment| fragment.more)
    }
}

fn component_wire_len(message: &TdmaMessage) -> usize {
    let length = message.encoded_len();
    // The repeated message field has a one-byte tag followed by its varint length.
    1 + prost::length_delimiter_len(length) + length
}

fn tx_properties(
    transmission: &Transmission,
    component_bytes: usize,
    slot_duration_us: u64,
) -> TxProperties {
    TxProperties {
        frequency_hz: transmission.frequency,
        bandwidth_hz: transmission.bandwidth,
        tx_power_dbm: transmission.power,
        // C++ models only component data, not protobuf or PHY framing bytes.
        // Preserve the original float-seconds calculation and duration_cast
        // truncation before applying its slot-boundary mitigation.
        duration_microseconds: ((f64::from(component_bytes as f32 * 8.0 / transmission.rate as f32)
            * 1_000_000.0) as u64)
            .min(slot_duration_us.saturating_sub(1)),
        offset_microseconds: 0,
        tx_time_microseconds: transmission.tx_time,
        antenna_index: 0,
        spectral_mask_index: 0,
        // Zero tells the physical layer to use its configured sub-ID.
        sub_id: 0,
    }
}

#[allow(clippy::too_many_arguments)]
fn take_from_queue(
    mac: &TdmaMac,
    state: &mut State,
    absolute_slot: u64,
    index: usize,
    available: usize,
    wire_available: usize,
    drop_oversized: bool,
    queue_had_component: bool,
) -> Option<Transmission> {
    if available == 0 || wire_available == 0 {
        return None;
    }
    let schedule = state.schedule.clone()?;
    let Slot::Tx {
        frequency_hz,
        data_rate_bps,
        service_class,
        power_dbm,
        destination,
    } = schedule.slot(absolute_slot).clone()
    else {
        return None;
    };
    let position = state.queues[index]
        .iter()
        .position(|queued| destination == 0 || queued.packet.info.destination == destination)?;
    let front = state.queues[index].get_mut(position)?;
    let remaining = front.packet.payload.len().saturating_sub(front.offset);
    let take = remaining.min(available).min(wire_available);
    let fragment = |more| TdmaFragment {
        more,
        index: u32::from(front.fragment_index),
        offset: u32::try_from(front.offset).unwrap_or(u32::MAX),
        sequence: front.sequence,
    };
    let mut message = TdmaMessage {
        message_type: TdmaMessageType::Data as i32,
        destination: u32::from(front.packet.info.destination),
        priority: u32::from(front.packet.info.priority),
        data: front.packet.payload[front.offset..front.offset + take].to_vec(),
        fragment: (front.offset != 0 || take < remaining).then(|| fragment(take < remaining)),
    };
    if !state.fragmentation_enable
        && (take < remaining || component_wire_len(&message) > wire_available)
    {
        if !drop_oversized || queue_had_component {
            return None;
        }
        let dropped = state.queues[index].remove(position)?;
        state.queue_statistics[index].too_big += 1;
        record_packet_drop(
            mac,
            state,
            index,
            dropped.packet.info.source,
            dropped.packet.info.destination,
            dropped.packet.payload.len(),
            PacketDropReason::TooBig,
        );
        publish_queue_tables(mac, state, index);
        return take_from_queue(
            mac,
            state,
            absolute_slot,
            index,
            available,
            wire_available,
            drop_oversized,
            queue_had_component,
        );
    }
    if component_wire_len(&message) > wire_available {
        // Check the complete packet first: fragmentation adds metadata which may
        // make a fitting whole packet appear too large. Only shorten it after
        // including the metadata required by the resulting fragment.
        message.fragment = Some(fragment(true));
        let excess = component_wire_len(&message) - wire_available;
        let take = message.data.len().checked_sub(excess)?;
        if take == 0 {
            return None;
        }
        message.data.truncate(take);
    }
    let take = message.data.len();
    let fragment_index = front.fragment_index;
    let info = front.packet.info;
    let more = take < remaining;
    if more {
        front.offset += take;
        front.fragment_index = front.fragment_index.saturating_add(1);
    } else {
        state.queues[index].remove(position);
    }
    let statistics = &mut state.queue_statistics[index];
    statistics.classes[usize::from(service_class).min(4)] += 1;
    if !more {
        statistics.dequeued += 1;
        let parts = usize::from(fragment_index).saturating_add(1);
        statistics.fragment_histogram[parts.saturating_sub(1).min(9)] += 1;
    }
    let transmission = Transmission {
        info,
        message,
        frequency: frequency_hz,
        rate: data_rate_bps,
        category: service_class,
        power: power_dbm,
        bandwidth: schedule.bandwidth_hz,
        tx_time: schedule.slot_start(absolute_slot),
    };
    publish_queue_tables(mac, state, index);
    Some(transmission)
}

#[cfg(test)]
fn take_transmission(
    mac: &TdmaMac,
    state: &mut State,
    absolute_slot: u64,
    used: usize,
) -> Option<Transmission> {
    let schedule = state.schedule.clone()?;
    let Slot::Tx {
        data_rate_bps,
        service_class,
        destination,
        ..
    } = schedule.slot(absolute_slot).clone()
    else {
        return None;
    };
    let usable_us = schedule
        .slot_duration_us
        .saturating_sub(schedule.overhead_us);
    let capacity = (u128::from(data_rate_bps) * u128::from(usable_us) / 8_000_000)
        .min(usize::MAX as u128) as usize;
    let index = queue_index(state, service_class, destination)?;
    let available = capacity.saturating_sub(used);
    let header_len = TdmaBaseModelMessage {
        absolute_slot_index: absolute_slot,
        data_rate_bps,
        messages: Vec::new(),
    }
    .encoded_len();
    let primary_index = usize::from(service_class.min(4));
    take_from_queue(
        mac,
        state,
        absolute_slot,
        index,
        available,
        usize::from(u16::MAX) - header_len,
        index == primary_index,
        used != 0,
    )
}

fn transmit_slot(mac: &TdmaMac, absolute_slot: u64) {
    let now = now_us();
    let on_time = mac
        .state
        .lock()
        .unwrap()
        .schedule
        .as_ref()
        .is_some_and(|schedule| schedule.absolute_slot(now) == absolute_slot);
    if !on_time {
        update_tx_slot_status(mac, absolute_slot, now, TxSlotStatus::Missed);
        return;
    }
    update_tx_slot_status(mac, absolute_slot, now, TxSlotStatus::Valid);
    let (items, flow_update, frame_sequence, slot_duration_us) = {
        let mut state = mac.state.lock().unwrap();
        let Some(schedule) = state.schedule.as_ref() else {
            return;
        };
        let Slot::Tx {
            data_rate_bps,
            service_class,
            ..
        } = schedule.slot(absolute_slot)
        else {
            return;
        };
        let primary_index = usize::from((*service_class).min(4));
        let capacity = (u128::from(*data_rate_bps)
            * u128::from(
                schedule
                    .slot_duration_us
                    .saturating_sub(schedule.overhead_us),
            )
            / 8_000_000)
            .min(usize::MAX as u128) as usize;
        let slot_duration_us = schedule.slot_duration_us;
        let header_len = TdmaBaseModelMessage {
            absolute_slot_index: absolute_slot,
            data_rate_bps: *data_rate_bps,
            messages: Vec::new(),
        }
        .encoded_len();
        // Wire framing is limited separately from the slot's payload capacity.
        let mut wire_available = usize::from(u16::MAX) - header_len;
        let aggregate = state.aggregation_enable;
        let threshold = state.aggregation_threshold;
        let threshold_bytes = (capacity as f64 * threshold / 100.0) as usize;
        let mut used = 0usize;
        let mut items = Vec::new();
        let mut primary_had = false;
        while used < capacity {
            let Some(item) = take_from_queue(
                mac,
                &mut state,
                absolute_slot,
                primary_index,
                capacity.saturating_sub(used),
                wire_available,
                true,
                primary_had,
            ) else {
                break;
            };
            primary_had = true;
            used = used.saturating_add(item.message.data.len());
            wire_available -= component_wire_len(&item.message);
            let stop = !aggregate || item.more() || used >= capacity;
            items.push(item);
            if stop {
                break;
            }
        }
        if !state.strict_dequeue {
            for secondary_index in (0..5).rev() {
                if !((used == 0 || aggregate) && used <= threshold_bytes) {
                    break;
                }
                if secondary_index == primary_index {
                    continue;
                }
                let mut secondary_had = false;
                while used < capacity {
                    let Some(item) = take_from_queue(
                        mac,
                        &mut state,
                        absolute_slot,
                        secondary_index,
                        capacity.saturating_sub(used),
                        wire_available,
                        false,
                        secondary_had,
                    ) else {
                        break;
                    };
                    secondary_had = true;
                    used = used.saturating_add(item.message.data.len());
                    wire_available -= component_wire_len(&item.message);
                    let stop = !aggregate || item.more() || used >= capacity;
                    items.push(item);
                    if stop {
                        break;
                    }
                }
            }
        }
        if !items.is_empty() {
            update_aggregation_histogram(mac, &mut state, items.len());
            for item in &items {
                record_packet_accept(
                    mac,
                    &mut state,
                    priority_to_queue(item.info.priority),
                    mac.id,
                    item.info.destination,
                    item.message.data.len(),
                    false,
                );
            }
        }
        let completed = items.iter().filter(|item| !item.more()).count() as u16;
        let flow_update = if state.flow_control_enable && completed != 0 {
            state.flow_manager.add_token(completed).2
        } else {
            None
        };
        let frame_sequence = state.frame_sequence;
        if !items.is_empty() {
            state.frame_sequence = state.frame_sequence.wrapping_add(1);
        }
        (items, flow_update, frame_sequence, slot_duration_us)
    };
    if let Some(tokens) = flow_update {
        send_flow_update(mac, tokens);
    }
    let Some(first) = items.first() else { return };
    let wire = TdmaBaseModelMessage {
        absolute_slot_index: absolute_slot,
        data_rate_bps: first.rate,
        messages: items.iter().map(|item| item.message.clone()).collect(),
    };
    let serialization = wire.encode_to_vec();
    let serialization_len =
        u16::try_from(serialization.len()).expect("TDMA wire length was checked before dequeue");
    let mut payload = Vec::with_capacity(serialization.len() + 2);
    payload.extend_from_slice(&serialization_len.to_be_bytes());
    payload.extend_from_slice(&serialization);
    let destination = items
        .iter()
        .map(|item| item.info.destination)
        .reduce(|left, right| if left == right { left } else { BROADCAST_NEM })
        .unwrap_or(BROADCAST_NEM);
    let header = ModelHeader {
        registration_id: MAC_REGISTRATION_TDMA,
        sequence: frame_sequence,
        data_rate_bps: first.rate,
        category: first.category,
        message_type: 1,
        flags: 0,
    }
    .encode();
    let component_bytes = items.iter().map(|item| item.message.data.len()).sum();
    let tx = tx_properties(first, component_bytes, slot_duration_us);
    let tx_data = tx.encode();
    let messages = [
        FfiControlMessage {
            msg_type: CONTROL_MODEL_HEADER,
            payload: FfiSlice {
                data: header.as_ptr(),
                len: header.len(),
            },
        },
        FfiControlMessage {
            msg_type: CONTROL_TX_PROPERTIES,
            payload: FfiSlice {
                data: tx_data.as_ptr(),
                len: tx_data.len(),
            },
        },
    ];
    let packet = FfiPacket {
        info: FfiPacketInfo {
            uuid: [0; 16],
            source: mac.id,
            destination,
            priority: first.info.priority,
            creation_time_sec: first.info.creation_time_sec,
            creation_time_usec: first.info.creation_time_usec,
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
    mac.increment("TxFrameSent", 1);
    mac.increment(
        "TxComponentBytes",
        items.iter().fold(0u64, |total, item| {
            total.saturating_add(u64::try_from(item.message.data.len()).unwrap_or(u64::MAX))
        }),
    );
    mac.increment(
        "TxWireBytes",
        u64::try_from(payload.len().saturating_add(PHY_ENVELOPE_BYTES)).unwrap_or(u64::MAX),
    );
    mac.increment("TxAirtimeMicroseconds", tx.duration_microseconds);
    (mac.framework.update_neighbor_tx)(
        mac.framework.framework_ctx,
        destination,
        first.rate,
        now.max(0) as u64,
    );
}

extern "C" fn downstream(
    plugin: *mut c_void,
    packet: *const FfiPacket,
    messages: *const FfiControlMessage,
    count: usize,
) {
    let Some(mac) = (unsafe { (plugin as *mut TdmaMac).as_ref() }) else {
        return;
    };
    if packet.is_null() {
        if count != 0 && !messages.is_null() {
            for message in unsafe { std::slice::from_raw_parts(messages, count) } {
                if message.msg_type != CONTROL_FLOW_CONTROL_TOKEN || message.payload.data.is_null()
                {
                    continue;
                }
                let data = unsafe {
                    std::slice::from_raw_parts(message.payload.data, message.payload.len)
                };
                if let Some(token) = FlowControlToken::decode(data) {
                    let update = {
                        let mut state = mac.state.lock().unwrap();
                        if state.flow_control_enable {
                            state
                                .flow_manager
                                .process_flow_control_message(token.tokens)
                        } else {
                            None
                        }
                    };
                    if let Some(tokens) = update {
                        send_flow_update(mac, tokens);
                    }
                }
            }
        }
        return;
    }

    let Some(packet) = own_packet(packet) else {
        return;
    };
    let mut state = mac.state.lock().unwrap();
    if state.flow_control_enable && !state.flow_manager.remove_token().1 {
        record_packet_drop(
            mac,
            &mut state,
            priority_to_queue(packet.info.priority),
            packet.info.source,
            packet.info.source,
            packet.payload.len(),
            PacketDropReason::FlowControl,
        );
        return;
    }
    let index = priority_to_queue(packet.info.priority);
    if state.queue_depth == 0 {
        state.queue_statistics[index].overflow += 1;
        mac.increment("TxQueueOverflowPackets", 1);
        mac.increment(
            "TxQueueOverflowBytes",
            u64::try_from(packet.payload.len()).unwrap_or(u64::MAX),
        );
        record_packet_drop(
            mac,
            &mut state,
            index,
            packet.info.source,
            packet.info.destination,
            packet.payload.len(),
            PacketDropReason::QueueOverflow,
        );
        publish_queue_tables(mac, &state, index);
        if state.flow_control_enable {
            if let Some(tokens) = state.flow_manager.add_token(1).2 {
                send_flow_update(mac, tokens);
            }
        }
        return;
    }
    if state.queues[index].len() >= state.queue_depth {
        let dropped_position = state.queues[index]
            .iter()
            .position(|queued| queued.fragment_index == 0)
            .unwrap_or(0);
        let dropped = state.queues[index]
            .remove(dropped_position)
            .expect("a full TDMA queue must contain a packet");
        state.queue_statistics[index].overflow += 1;
        mac.increment("TxQueueOverflowPackets", 1);
        mac.increment(
            "TxQueueOverflowBytes",
            u64::try_from(dropped.packet.payload.len()).unwrap_or(u64::MAX),
        );
        record_packet_drop(
            mac,
            &mut state,
            index,
            dropped.packet.info.source,
            dropped.packet.info.destination,
            dropped.packet.payload.len(),
            PacketDropReason::QueueOverflow,
        );
        publish_queue_tables(mac, &state, index);
        if state.flow_control_enable {
            if let Some(tokens) = state.flow_manager.add_token(1).2 {
                send_flow_update(mac, tokens);
            }
        }
    }
    state.sequence = state.sequence.wrapping_add(1);
    let sequence = state.sequence;
    state.queues[index].push_back(QueuedPacket {
        packet,
        sequence,
        offset: 0,
        fragment_index: 0,
    });
    state.queue_statistics[index].enqueued += 1;
    mac.maximize(
        &format!("highWaterMarkQueue{index}"),
        state.queues[index].len() as u64,
    );
    publish_queue_tables(mac, &state, index);
}

fn send_upstream(mac: &TdmaMac, packet: OwnedPacket) {
    let ffi = FfiPacket {
        info: packet.info,
        payload: FfiSlice {
            data: packet.payload.as_ptr(),
            len: packet.payload.len(),
        },
    };
    (mac.framework.send_upstream_packet)(
        mac.framework.framework_ctx,
        mac.id,
        &ffi,
        std::ptr::null(),
        0,
    );
}

extern "C" fn upstream(
    plugin: *mut c_void,
    packet: *const FfiPacket,
    messages: *const FfiControlMessage,
    count: usize,
) {
    let Some(mac) = (unsafe { (plugin as *mut TdmaMac).as_ref() }) else {
        return;
    };
    let Some(packet) = own_packet(packet) else {
        return;
    };
    let Some(messages) = controls(messages, count) else {
        return;
    };
    if packet.payload.len() < 2 {
        return;
    }
    let serialization_len = u16::from_be_bytes([packet.payload[0], packet.payload[1]]) as usize;
    if serialization_len == 0 || packet.payload.len() < serialization_len + 2 {
        return;
    }
    let Ok(wire) = TdmaBaseModelMessage::decode(&packet.payload[2..2 + serialization_len]) else {
        return;
    };
    let mut header = None;
    let mut rx = None;
    let mut segments = None;
    for message in messages {
        let Some(data) = control_payload(message) else {
            return;
        };
        match message.msg_type {
            CONTROL_MODEL_HEADER => header = ModelHeader::decode(data),
            CONTROL_RX_PROPERTIES => rx = RxProperties::decode(data),
            CONTROL_RX_FREQUENCY_SEGMENTS => segments = RxFrequencySegments::decode(data),
            _ => {}
        }
    }
    let mut state = mac.state.lock().unwrap();
    if !state.started {
        return;
    }
    let Some(model) = header else {
        record_all_message_drops(
            mac,
            &mut state,
            packet.info.source,
            &wire.messages,
            PacketDropReason::BadControl,
        );
        return;
    };
    let Some(rx) = rx else {
        record_all_message_drops(
            mac,
            &mut state,
            packet.info.source,
            &wire.messages,
            PacketDropReason::BadControl,
        );
        return;
    };
    if model.registration_id != MAC_REGISTRATION_TDMA {
        record_all_message_drops(
            mac,
            &mut state,
            packet.info.source,
            &wire.messages,
            PacketDropReason::RegistrationId,
        );
        return;
    }
    if wire.data_rate_bps == 0 {
        record_all_message_drops(
            mac,
            &mut state,
            packet.info.source,
            &wire.messages,
            PacketDropReason::BadControl,
        );
        return;
    }
    let Some(schedule) = state.schedule.clone() else {
        return;
    };
    let now = now_us();
    let spectrum_query = FfiSpectrumQuery::from_rx(
        rx,
        segments.as_ref().and_then(|value| value.segments.first()),
    );
    let start_of_reception = spectrum_query.start_time_microseconds;
    let end_of_reception = start_of_reception
        .saturating_add(i64::try_from(rx.duration_microseconds).unwrap_or(i64::MAX));
    // Legacy TDMA checks the exact EOR slot, including equality at a boundary.
    if schedule.absolute_slot(end_of_reception) != wire.absolute_slot_index {
        let current_slot = schedule.absolute_slot(now);
        update_rx_slot_status(
            mac,
            &mut state,
            current_slot,
            current_slot,
            now,
            RxSlotStatus::TooLong,
        );
        record_all_message_drops(
            mac,
            &mut state,
            packet.info.source,
            &wire.messages,
            PacketDropReason::TooLong,
        );
        return;
    }
    let current_slot = schedule.absolute_slot(now);
    if current_slot != wire.absolute_slot_index {
        let status = match schedule.slot(wire.absolute_slot_index) {
            Slot::Rx { .. } => RxSlotStatus::Missed,
            Slot::Idle => RxSlotStatus::Idle,
            Slot::Tx { .. } => RxSlotStatus::Tx,
        };
        update_rx_slot_status(
            mac,
            &mut state,
            current_slot,
            wire.absolute_slot_index,
            now,
            status,
        );
        record_all_message_drops(
            mac,
            &mut state,
            packet.info.source,
            &wire.messages,
            PacketDropReason::SlotError,
        );
        return;
    }
    let frequency_hz = match schedule.slot(current_slot) {
        Slot::Idle => {
            update_rx_slot_status(
                mac,
                &mut state,
                current_slot,
                current_slot,
                now,
                RxSlotStatus::Idle,
            );
            record_all_message_drops(
                mac,
                &mut state,
                packet.info.source,
                &wire.messages,
                PacketDropReason::SlotError,
            );
            return;
        }
        Slot::Tx { .. } => {
            update_rx_slot_status(
                mac,
                &mut state,
                current_slot,
                current_slot,
                now,
                RxSlotStatus::Tx,
            );
            record_all_message_drops(
                mac,
                &mut state,
                packet.info.source,
                &wire.messages,
                PacketDropReason::SlotError,
            );
            return;
        }
        Slot::Rx { frequency_hz } => *frequency_hz,
    };
    if frequency_hz != spectrum_query.frequency_hz {
        update_rx_slot_status(
            mac,
            &mut state,
            current_slot,
            current_slot,
            now,
            RxSlotStatus::WrongFrequency,
        );
        record_all_message_drops(
            mac,
            &mut state,
            packet.info.source,
            &wire.messages,
            PacketDropReason::Frequency,
        );
        return;
    }
    let pending = PendingReception {
        info: packet.info,
        wire,
        model_sequence: model.sequence,
        packet_len: serialization_len,
        spectrum_query,
    };
    if let Some(previous) = state.pending_rx.get_mut(&current_slot) {
        // Match C++: earliest modeled SOR wins, independent of arrival order or PCR.
        if start_of_reception < previous.spectrum_query.start_time_microseconds {
            *previous = pending;
        }
        update_rx_slot_status(
            mac,
            &mut state,
            current_slot,
            current_slot,
            now,
            RxSlotStatus::Lock,
        );
        return;
    }
    state.pending_rx.insert(current_slot, pending);
    update_rx_slot_status(
        mac,
        &mut state,
        current_slot,
        current_slot,
        now,
        RxSlotStatus::Valid,
    );
    let slot_end = schedule.slot_start(current_slot.saturating_add(1));
    drop(state);
    let timer = schedule_timer(
        mac,
        slot_end,
        TIMER_RX_COMPLETE,
        &current_slot.to_be_bytes(),
    );
    let mut state = mac.state.lock().unwrap();
    if timer != 0 {
        state.timers.insert(timer, TIMER_RX_COMPLETE);
    } else if let Some(pending) = state.pending_rx.remove(&current_slot) {
        record_all_message_drops(
            mac,
            &mut state,
            pending.info.source,
            &pending.wire.messages,
            PacketDropReason::BadControl,
        );
    }
}

fn complete_receive(mac: &TdmaMac, absolute_slot: u64) {
    let mut state = mac.state.lock().unwrap();
    let Some(pending) = state.pending_rx.remove(&absolute_slot) else {
        return;
    };
    if !state.started {
        return;
    }
    let Some(spectrum) = mac.framework.reception_noise(&pending.spectrum_query) else {
        record_all_message_drops(
            mac,
            &mut state,
            pending.info.source,
            &pending.wire.messages,
            PacketDropReason::BadSpectrumQuery,
        );
        return;
    };
    let now = now_us();
    let info = pending.info;
    let spectrum_query = pending.spectrum_query;
    let noise_floor_dbm = spectrum.noise_floor_dbm;
    let wire = pending.wire;
    let sinr = spectrum_query.rx_power_dbm - noise_floor_dbm;
    if let Some(pcr) = &state.pcr {
        let probability = pcr.probability(wire.data_rate_bps, sinr, pending.packet_len);
        if random_unit(&mut state.random_state) > probability {
            record_all_message_drops(
                mac,
                &mut state,
                info.source,
                &wire.messages,
                PacketDropReason::Sinr,
            );
            return;
        }
    }
    let mut deliveries = Vec::new();
    for message in wire.messages {
        let Some(message_type) = TdmaMessageType::try_from(message.message_type).ok() else {
            continue;
        };
        // The original wire decoder narrows the protobuf uint32 fields.
        let destination = message.destination as u16;
        let priority = message.priority as u8;
        if !state.promiscuous && destination != mac.id && destination != BROADCAST_NEM {
            record_packet_drop(
                mac,
                &mut state,
                priority_to_queue(priority),
                info.source,
                destination,
                message.data.len(),
                PacketDropReason::Destination,
            );
            continue;
        }
        let info = FfiPacketInfo {
            destination,
            priority,
            ..info
        };
        let complete = if let Some(fragment) = message
            .fragment
            .filter(|fragment| fragment.more || fragment.offset != 0)
        {
            let offset = fragment.offset as usize;
            let key = (info.source, priority, fragment.sequence);
            let first_fragment = !state.reassembly.contains_key(&key);
            let entry = state.reassembly.entry(key).or_insert_with(|| Reassembly {
                info,
                total_fragments: None,
                pieces: BTreeMap::new(),
                fragment_indices: HashSet::new(),
                last_update_us: now,
            });
            // A retransmitted fragment is not new reassembly progress.
            if !entry.fragment_indices.insert(fragment.index) {
                continue;
            }
            entry.last_update_us = now;
            entry.pieces.entry(offset).or_insert(message.data);
            if !fragment.more {
                entry.total_fragments = Some(u64::from(fragment.index) + 1);
            }
            // Completion counts distinct indices. Offsets only order stored
            // pieces; the original does not require contiguous byte ranges.
            // Its first-fragment insertion never completes an assembly.
            if !first_fragment && entry.total_fragments == Some(entry.fragment_indices.len() as u64)
            {
                let assembled = entry.pieces.values().flatten().copied().collect();
                state.reassembly.remove(&key);
                Some((
                    OwnedPacket {
                        info,
                        payload: assembled,
                    },
                    message_type,
                ))
            } else {
                None
            }
        } else {
            Some((
                OwnedPacket {
                    info,
                    payload: message.data,
                },
                message_type,
            ))
        };
        let Some((complete, message_type)) = complete else {
            continue;
        };
        record_packet_accept(
            mac,
            &mut state,
            priority_to_queue(complete.info.priority),
            info.source,
            complete.info.destination,
            complete.payload.len(),
            true,
        );
        if message_type == TdmaMessageType::Control {
            continue;
        }
        deliveries.push(complete);
    }
    // C++ checks expiry after processing a received frame, not on an idle
    // periodic timer. A late final fragment may therefore finish first.
    expire_reassembly(mac, &mut state, now);
    drop(state);
    (mac.framework.update_neighbor_rx)(
        mac.framework.framework_ctx,
        info.source,
        pending.model_sequence,
        info.uuid.as_ptr(),
        sinr,
        noise_floor_dbm,
        now.max(0) as u64,
        spectrum_query.duration_microseconds,
        wire.data_rate_bps,
    );
    for packet in deliveries {
        send_upstream(mac, packet);
    }
}

extern "C" fn timed(plugin: *mut c_void, timer_id: u64, event: u32, data: *const u8, len: usize) {
    let Some(mac) = (unsafe { (plugin as *mut TdmaMac).as_ref() }) else {
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
        TIMER_TX_SLOT => {
            {
                let mut state = mac.state.lock().unwrap();
                if state.next_tx_slot != Some(value) {
                    return;
                }
                state.next_tx_slot = None;
            }
            transmit_slot(mac, value);
            schedule_next_tx(mac, false);
        }
        TIMER_RX_COMPLETE => complete_receive(mac, value),
        TIMER_NEIGHBOR_STATUS => {
            if !mac.state.lock().unwrap().started {
                return;
            }
            (mac.framework.update_neighbor_status)(mac.framework.framework_ctx);
            schedule_neighbor_status(mac);
        }
        _ => {}
    }
}

fn clear_slot_status(mac: &TdmaMac) {
    for name in ["TxSlotStatusTable", "RxSlotStatusTable"] {
        mac.clear_table(name);
    }
    let mut state = mac.state.lock().unwrap();
    state.tx_slot_statistics.clear();
    state.rx_slot_statistics.clear();
}

fn send_frequency_interest(mac: &TdmaMac, foi: FrequencyOfInterest) {
    if let Some(data) = foi.encode() {
        let message = FfiControlMessage {
            msg_type: CONTROL_FREQUENCY_INTEREST,
            payload: FfiSlice {
                data: data.as_ptr(),
                len: data.len(),
            },
        };
        (mac.framework.send_downstream_control)(mac.framework.framework_ctx, mac.id, &message, 1);
    }
}

fn flush_schedule(mac: &TdmaMac) {
    for name in [
        "scheduler.ScheduleInfoTable",
        "scheduler.StructureInfoTable",
    ] {
        mac.clear_table(name);
    }
    clear_slot_status(mac);
    let (timers, changed) = {
        let mut state = mac.state.lock().unwrap();
        let changed = state.schedule.is_some() || !state.schedule_frequencies.is_empty();
        state.schedule = None;
        state.schedule_frequencies.clear();
        state.next_tx_slot = None;
        let timers = state
            .timers
            .iter()
            .filter_map(|(timer, kind)| (*kind == TIMER_TX_SLOT).then_some(*timer))
            .collect::<Vec<_>>();
        for timer in &timers {
            state.timers.remove(timer);
        }
        (timers, changed)
    };
    for timer in timers {
        (mac.framework.cancel_timed_event)(mac.framework.framework_ctx, mac.id, timer);
    }
    if changed {
        send_frequency_interest(
            mac,
            FrequencyOfInterest {
                bandwidth_hz: 0,
                frequencies_hz: Vec::new(),
            },
        );
    }
}

extern "C" fn process_event(plugin: *mut c_void, event: u16, data: *const u8, len: usize) {
    let Some(mac) = (unsafe { (plugin as *mut TdmaMac).as_ref() }) else {
        return;
    };
    if event != EVENT_TDMA_SCHEDULE {
        return;
    }
    if len != 0 && data.is_null() {
        mac.increment("scheduler.scheduleRejectOther", 1);
        return;
    }
    let bytes = if len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(data, len) }
    };
    let parsed = {
        let state = mac.state.lock().unwrap();
        parse_schedule(bytes, state.schedule.as_ref())
    };
    let (schedule, full) = match parsed {
        Ok(parsed) => parsed,
        Err(error) => {
            let update = ScheduleEvent::decode(bytes).is_ok_and(|event| event.structure.is_none());
            let counter = if update && error.contains("slot index is out of range") {
                "scheduler.scheduleRejectSlotIndexRange"
            } else if update && error.contains("frame index is out of range") {
                "scheduler.scheduleRejectFrameIndexRange"
            } else if error.contains("before full schedule") {
                "scheduler.scheduleRejectUpdateBeforeFull"
            } else {
                "scheduler.scheduleRejectOther"
            };
            mac.increment(counter, 1);
            if !error.contains("before full schedule") {
                flush_schedule(mac);
            }
            return;
        }
    };
    mac.increment(
        if full {
            "scheduler.scheduleAcceptFull"
        } else {
            "scheduler.scheduleAcceptUpdate"
        },
        1,
    );
    if full {
        for name in [
            "scheduler.ScheduleInfoTable",
            "scheduler.StructureInfoTable",
        ] {
            mac.clear_table(name);
        }
    }
    clear_slot_status(mac);
    publish_schedule_tables(mac, &schedule);
    let frequencies = schedule
        .slots
        .iter()
        .filter_map(|slot| match slot {
            Slot::Tx { frequency_hz, .. } | Slot::Rx { frequency_hz } => Some(*frequency_hz),
            Slot::Idle => None,
        })
        .collect::<std::collections::BTreeSet<_>>();
    let (timers, foi) = {
        let mut state = mac.state.lock().unwrap();
        let previous_bandwidth = state
            .schedule
            .as_ref()
            .map_or(0, |value| value.bandwidth_hz);
        let previous_frequencies = state.schedule_frequencies.clone();
        if full {
            state.schedule_frequencies.clear();
        }
        // Partial updates retain the original scheduler's frequency union.
        state.schedule_frequencies.extend(frequencies);
        let foi = (previous_bandwidth != schedule.bandwidth_hz
            || previous_frequencies != state.schedule_frequencies)
            .then(|| FrequencyOfInterest {
                bandwidth_hz: schedule.bandwidth_hz,
                frequencies_hz: state.schedule_frequencies.iter().copied().collect(),
            });
        state.schedule = Some(schedule);
        state.next_tx_slot = None;
        let timers: Vec<_> = state
            .timers
            .iter()
            .filter_map(|(timer, kind)| (*kind == TIMER_TX_SLOT).then_some(*timer))
            .collect();
        for timer in &timers {
            state.timers.remove(timer);
        }
        (timers, foi)
    };
    for timer in timers {
        (mac.framework.cancel_timed_event)(mac.framework.framework_ctx, mac.id, timer);
    }
    if let Some(foi) = foi {
        send_frequency_interest(mac, foi);
    }
    schedule_next_tx(mac, full);
}

#[no_mangle]
pub extern "C" fn emane_plugin_create() -> *const PluginApi {
    static API: OnceLock<PluginApi> = OnceLock::new();
    API.get_or_init(|| PluginApi {
        abi_version: PLUGIN_ABI_VERSION,
        struct_size: std::mem::size_of::<PluginApi>(),
        name: c"tdmaeventschedulerradiomodel".as_ptr(),
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
    use super::*;

    #[test]
    fn transmit_properties_defer_sub_id_to_phy_configuration() {
        let transmission = Transmission {
            info: FfiPacketInfo {
                uuid: [0; 16],
                source: 1,
                destination: 2,
                priority: 0,
                creation_time_sec: 0,
                creation_time_usec: 0,
            },
            message: TdmaMessage::default(),
            frequency: 1_200_000_000,
            rate: 9_000_000,
            category: 0,
            power: 50.0,
            bandwidth: 5_000_000,
            tx_time: 123,
        };

        let properties = tx_properties(&transmission, 128, 1_000);

        assert_eq!(properties.sub_id, 0);
        assert_eq!(properties.frequency_hz, transmission.frequency);
        assert_eq!(properties.bandwidth_hz, transmission.bandwidth);
        assert_eq!(properties.tx_power_dbm, transmission.power);
        assert_eq!(properties.tx_time_microseconds, transmission.tx_time);
        assert_eq!(properties.duration_microseconds, 113);
        let transmission = Transmission {
            rate: 1_000_000,
            ..transmission
        };
        // Measured in the original full TDMA platform, not integer division.
        assert_eq!(
            tx_properties(&transmission, 4096, 100_000).duration_microseconds,
            32_767
        );
    }

    #[test]
    fn full_schedule_and_update_are_validated() {
        let event = ScheduleEvent {
            frames: vec![ScheduleFrame {
                index: 0,
                slots: vec![ScheduleSlot {
                    index: 0,
                    slot_type: SlotType::Tx as i32,
                    tx: Some(ScheduleTx {
                        frequency_hz: Some(1_000_000),
                        data_rate_bps: Some(1_000_000),
                        ..Default::default()
                    }),
                    rx: None,
                }],
                ..Default::default()
            }],
            structure: Some(ScheduleStructure {
                slots_per_frame: 2,
                frames_per_multiframe: 1,
                slot_duration_microseconds: 1_000,
                slot_overhead_microseconds: 100,
                bandwidth_hz: 1_000_000,
            }),
            frequency_hz: Some(1_000_000),
            ..Default::default()
        };
        let (schedule, full) = parse_schedule(&event.encode_to_vec(), None).unwrap();
        assert!(full);
        assert!(matches!(schedule.slots[0], Slot::Tx { .. }));
        assert!(matches!(
            schedule.slots[1],
            Slot::Rx {
                frequency_hz: 1_000_000
            }
        ));
        assert_eq!(schedule.next_tx(0), Some(2));
    }

    #[test]
    fn undefined_frames_stay_idle_and_updates_preserve_unspecified_slots() {
        let full_event = ScheduleEvent {
            frames: vec![ScheduleFrame {
                index: 0,
                slots: vec![ScheduleSlot {
                    index: 0,
                    slot_type: SlotType::Tx as i32,
                    tx: Some(ScheduleTx {
                        frequency_hz: Some(1_000_000),
                        data_rate_bps: Some(1_000_000),
                        ..Default::default()
                    }),
                    rx: None,
                }],
                ..Default::default()
            }],
            structure: Some(ScheduleStructure {
                slots_per_frame: 2,
                frames_per_multiframe: 2,
                slot_duration_microseconds: 1_000,
                slot_overhead_microseconds: 100,
                bandwidth_hz: 1_000_000,
            }),
            frequency_hz: Some(1_000_000),
            ..Default::default()
        };
        let (schedule, _) = parse_schedule(&full_event.encode_to_vec(), None).unwrap();
        assert!(matches!(schedule.slots[0], Slot::Tx { .. }));
        assert!(matches!(schedule.slots[1], Slot::Rx { .. }));
        assert!(matches!(schedule.slots[2], Slot::Idle));
        assert!(matches!(schedule.slots[3], Slot::Idle));

        let update = ScheduleEvent {
            frames: vec![ScheduleFrame {
                index: 0,
                slots: vec![ScheduleSlot {
                    index: 0,
                    slot_type: SlotType::Idle as i32,
                    tx: None,
                    rx: None,
                }],
                ..Default::default()
            }],
            ..Default::default()
        };
        let (updated, full) = parse_schedule(&update.encode_to_vec(), Some(&schedule)).unwrap();
        assert!(!full);
        assert!(matches!(updated.slots[0], Slot::Idle));
        assert!(matches!(updated.slots[1], Slot::Rx { .. }));
        assert!(matches!(updated.slots[2], Slot::Idle));
        assert!(matches!(updated.slots[3], Slot::Idle));
    }

    #[test]
    fn legacy_aggregate_wire_message_round_trips() {
        let message = TdmaBaseModelMessage {
            absolute_slot_index: 99,
            data_rate_bps: 2_000_000,
            messages: vec![TdmaMessage {
                message_type: TdmaMessageType::Data as i32,
                destination: 7,
                priority: 3,
                data: vec![1, 2, 3],
                fragment: Some(TdmaFragment {
                    more: true,
                    index: 2,
                    offset: 12,
                    sequence: 40,
                }),
            }],
        };
        let decoded = TdmaBaseModelMessage::decode(message.encode_to_vec().as_slice()).unwrap();
        assert_eq!(decoded, message);
    }
}

#[cfg(test)]
mod regression_tests;
