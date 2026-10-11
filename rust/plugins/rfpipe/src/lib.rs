use emane_plugin_api::flow_control::FlowControlManager;
use emane_plugin_api::random::LegacyRandom;
mod pcr;

use emane_plugin_api::{
    CommonLayerCounters, FfiConfigRequest, FfiControlMessage, FfiFrameworkService, FfiPacket,
    FfiPacketInfo, FfiSlice, FfiSpectrumQuery, FlowControlToken, ModelHeader, PluginApi,
    RxFrequencySegments, RxProperties, TxProperties, CONTROL_FLOW_CONTROL_TOKEN,
    CONTROL_MODEL_HEADER, CONTROL_RX_FREQUENCY_SEGMENTS, CONTROL_RX_PROPERTIES,
    CONTROL_TX_PROPERTIES, MAC_REGISTRATION_RFPIPE, PLUGIN_ABI_VERSION,
};
use pcr::PcrCurve;
use prost::Message;
use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::{c_void, CStr};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

const EVENT_TRANSMIT: u32 = 1;
const EVENT_RECEIVE: u32 = 2;
const EVENT_R2RI_REPORT: u32 = 3;
const EVENT_DELAY_COMPLETE: u32 = 4;
const QUEUE_CAPACITY: usize = 255;
const BROADCAST_NEM: u16 = u16::MAX;

#[derive(Clone, PartialEq, Message)]
struct RfPipeMacHeader {
    #[prost(uint64, required, tag = "1")]
    data_rate_bps: u64,
}

struct OwnedControl {
    msg_type: u32,
    payload: Vec<u8>,
}

struct OwnedPacket {
    info: FfiPacketInfo,
    payload: Vec<u8>,
    controls: Vec<OwnedControl>,
}

struct PendingTx {
    packet: OwnedPacket,
    acquired_at: i64,
    ready_at: i64,
    duration: u64,
    data_rate: u64,
}

struct PendingReception {
    packet: OwnedPacket,
    received_at: i64,
    query: FfiSpectrumQuery,
    sequence: u64,
    data_rate: u64,
}

struct State {
    promiscuous_mode: bool,
    data_rate_bps: u64,
    delay_microseconds: i64,
    jitter_microseconds: i64,
    flow_control_enable: bool,
    flow_control_tokens: u16,
    flow_manager: FlowControlManager,
    pcr_curve_uri: String,
    pcr_curve: Option<PcrCurve>,
    sequence: u64,
    queue: VecDeque<PendingTx>,
    active_tx: Option<PendingTx>,
    delayed_tx: HashMap<u64, PendingTx>,
    next_delayed_id: u64,
    current_end_of_transmission: i64,
    next_transmit_wakeup: i64,
    pending_receptions: HashMap<u64, PendingReception>,
    next_reception_id: u64,
    radiometric_enabled: bool,
    radiometric_report_interval_microseconds: u64,
    neighbor_metric_delete_microseconds: u64,
    rf_signal_table_handle: u64,
    rf_signal_average_all_antennas: bool,
    rf_signal_average_all_frequencies: bool,
    queue_discards: u32,
    timers: HashSet<u64>,
    random_state: LegacyRandom,
    jitter_random: LegacyRandom,
    started: bool,
}

struct RfpipeMac {
    id: u16,
    framework: FfiFrameworkService,
    counters: CommonLayerCounters,
    queue_delay_counter: u64,
    average_queue_delay: u64,
    queue_high_water_counter: u64,
    state: Mutex<State>,
}

impl RfpipeMac {
    fn new(id: u16, framework: FfiFrameworkService) -> Self {
        let queue_delay_counter = (framework.register_counter)(
            framework.framework_ctx,
            c"numDownstreamQueueDelay".as_ptr(),
            c"Accumulation of downstream queue delay in microseconds".as_ptr(),
            true,
        );
        let average_queue_delay = (framework.register_average)(
            framework.framework_ctx,
            c"avgDownstreamQueueDelay".as_ptr(),
            c"Average downstream queue delay in microseconds".as_ptr(),
            true,
        );
        let queue_high_water_counter = (framework.register_counter32)(
            framework.framework_ctx,
            c"numHighWaterMark".as_ptr(),
            c"Downstream queue high water mark in packets".as_ptr(),
            true,
        );
        Self {
            id,
            framework,
            counters: CommonLayerCounters::register_with_drop_labels(
                framework,
                "0",
                &[
                    "SINR",
                    "Reg Id",
                    "Dst MAC",
                    "Queue Overflow",
                    "Bad Control",
                    "Bad Spectrum Query",
                    "Flow Control",
                ],
                &[],
            ),
            queue_delay_counter,
            average_queue_delay,
            queue_high_water_counter,
            state: Mutex::new(State {
                promiscuous_mode: false,
                data_rate_bps: 1_000_000,
                delay_microseconds: 0,
                jitter_microseconds: 0,
                flow_control_enable: false,
                flow_control_tokens: 10,
                flow_manager: FlowControlManager::new(),
                pcr_curve_uri: String::new(),
                pcr_curve: None,
                sequence: 0,
                queue: VecDeque::new(),
                active_tx: None,
                delayed_tx: HashMap::new(),
                next_delayed_id: 0,
                current_end_of_transmission: 0,
                next_transmit_wakeup: 0,
                pending_receptions: HashMap::new(),
                next_reception_id: 0,
                radiometric_enabled: false,
                radiometric_report_interval_microseconds: 1_000_000,
                neighbor_metric_delete_microseconds: 60_000_000,
                rf_signal_table_handle: (framework.register_rf_signal_table)(
                    framework.framework_ctx,
                    id,
                ),
                rf_signal_average_all_antennas: false,
                rf_signal_average_all_frequencies: false,
                queue_discards: 0,
                timers: HashSet::new(),
                random_state: LegacyRandom::from_clock(),
                jitter_random: LegacyRandom::from_clock(),
                started: false,
            }),
        }
    }
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "on" | "true" | "yes" => Some(true),
        "0" | "off" | "false" | "no" => Some(false),
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
    let number = number.parse::<f64>().ok()?;
    let scaled = number * multiplier;
    (number >= 0.0 && scaled.is_finite() && scaled <= u64::MAX as f64)
        .then_some(scaled.round() as u64)
}

fn seconds_to_microseconds(value: &str) -> Option<i64> {
    let seconds = value.parse::<f64>().ok()?;
    let microseconds = seconds * 1_000_000.0;
    (seconds >= 0.0 && microseconds.is_finite() && microseconds <= i64::MAX as f64)
        .then_some(microseconds.round() as i64)
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
        let values = if item.values.len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(item.values.data, item.values.len) }
        };
        let mut parsed = Vec::with_capacity(values.len());
        for value in values {
            if value.is_null() {
                return None;
            }
            parsed.push(unsafe { CStr::from_ptr(*value) }.to_str().ok()?.to_string());
        }
        result.push((name, parsed));
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

fn own_packet(
    packet: *const FfiPacket,
    messages: *const FfiControlMessage,
    count: usize,
) -> Option<OwnedPacket> {
    let packet = unsafe { packet.as_ref() }?;
    if (packet.payload.len != 0 && packet.payload.data.is_null()) || packet.payload.len > 64 << 20 {
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
            let payload = if message.payload.len == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(message.payload.data, message.payload.len) }
                    .to_vec()
            };
            Some(OwnedControl {
                msg_type: message.msg_type,
                payload,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    Some(OwnedPacket {
        info: packet.info,
        payload,
        controls,
    })
}

fn find_header(messages: &[FfiControlMessage]) -> Option<ModelHeader> {
    messages.iter().find_map(|message| {
        (message.msg_type == CONTROL_MODEL_HEADER
            && message.payload.len == ModelHeader::ENCODED_LEN
            && !message.payload.data.is_null())
        .then(|| unsafe { std::slice::from_raw_parts(message.payload.data, message.payload.len) })
        .and_then(ModelHeader::decode)
    })
}

fn find_rx_properties(messages: &[FfiControlMessage]) -> Option<RxProperties> {
    messages.iter().find_map(|message| {
        (message.msg_type == CONTROL_RX_PROPERTIES
            && message.payload.len == RxProperties::ENCODED_LEN
            && !message.payload.data.is_null())
        .then(|| unsafe { std::slice::from_raw_parts(message.payload.data, message.payload.len) })
        .and_then(RxProperties::decode)
    })
}

fn now_microseconds() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros(),
    )
    .unwrap_or(i64::MAX)
}

fn duration_microseconds(length: usize, data_rate: u64) -> u64 {
    if data_rate == 0 {
        0
    } else {
        // C++ computes float seconds, then converts DoubleSeconds to integer
        // microseconds. Preserve its truncation, including just-below-integer
        // results (4096 bytes at 2 Mbps is 16383, not 16384 microseconds).
        (f64::from(length as f32 * 8.0 / data_rate as f32) * 1_000_000.0) as u64
    }
}

fn random_unit(state: &mut State) -> f64 {
    f64::from(state.random_state.unit())
}

fn schedule(mac: &RfpipeMac, when: i64, event_id: u32, data: &[u8]) -> u64 {
    let when = when.max(0) as u64;
    (mac.framework.schedule_timed_event)(
        mac.framework.framework_ctx,
        mac.id,
        when / 1_000_000,
        (when % 1_000_000) as u32,
        event_id,
        data.as_ptr(),
        data.len(),
    )
}

fn schedule_transmit(mac: &RfpipeMac, when: i64) {
    let should_schedule = {
        let mut state = mac.state.lock().unwrap();
        if !state.started || (state.next_transmit_wakeup != 0 && state.next_transmit_wakeup <= when)
        {
            false
        } else {
            state.next_transmit_wakeup = when;
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

fn send_packet(
    mac: &RfpipeMac,
    packet: OwnedPacket,
    header: ModelHeader,
    duration: u64,
    acquired_at: i64,
    transmit_at: i64,
) {
    let serialization = RfPipeMacHeader {
        data_rate_bps: header.data_rate_bps,
    }
    .encode_to_vec();
    let Ok(serialization_len) = u16::try_from(serialization.len()) else {
        return;
    };
    let mut payload = Vec::with_capacity(serialization.len() + 2 + packet.payload.len());
    payload.extend_from_slice(&serialization_len.to_be_bytes());
    payload.extend_from_slice(&serialization);
    payload.extend_from_slice(&packet.payload);
    let header_bytes = header.encode();
    let tx_bytes = TxProperties {
        frequency_hz: 0,
        bandwidth_hz: 0,
        tx_power_dbm: f64::NAN,
        duration_microseconds: duration,
        offset_microseconds: 0,
        tx_time_microseconds: transmit_at,
        antenna_index: 0,
        spectral_mask_index: 0,
        sub_id: 0,
    }
    .encode();
    let mut message_views: Vec<_> = packet
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
    message_views.push(FfiControlMessage {
        msg_type: CONTROL_MODEL_HEADER,
        payload: FfiSlice {
            data: header_bytes.as_ptr(),
            len: header_bytes.len(),
        },
    });
    message_views.push(FfiControlMessage {
        msg_type: CONTROL_TX_PROPERTIES,
        payload: FfiSlice {
            data: tx_bytes.as_ptr(),
            len: tx_bytes.len(),
        },
    });
    let packet_view = FfiPacket {
        info: packet.info,
        payload: FfiSlice {
            data: payload.as_ptr(),
            len: payload.len(),
        },
    };
    mac.counters.downstream_tx_packet(
        mac.framework,
        packet.info.source,
        packet.info.destination,
        payload.len(),
        transmit_at.saturating_sub(acquired_at).max(0) as u64,
        false,
    );
    (mac.framework.send_downstream_packet)(
        mac.framework.framework_ctx,
        mac.id,
        &packet_view,
        message_views.as_ptr(),
        message_views.len(),
    );
    (mac.framework.update_neighbor_tx)(
        mac.framework.framework_ctx,
        packet.info.destination,
        header.data_rate_bps,
        transmit_at.max(0) as u64,
    );
}

fn send_flow_update(mac: &RfpipeMac, tokens: u16) {
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

fn drive_transmit(mac: &RfpipeMac, now: i64) {
    let (transmission, next_wakeup, flow_update) = {
        let mut state = mac.state.lock().unwrap();
        if !state.started {
            return;
        }
        let can_send = state.current_end_of_transmission <= now && state.active_tx.is_some();
        let mut flow_update = Vec::new();
        let transmission = if can_send {
            let pending = state.active_tx.take().unwrap();
            let queue_delay = now.saturating_sub(pending.acquired_at).max(0) as u64;
            (mac.framework.update_queue_metric)(
                mac.framework.framework_ctx,
                0,
                QUEUE_CAPACITY as u32,
                state.queue.len().min(u32::MAX as usize) as u32,
                std::mem::take(&mut state.queue_discards),
                queue_delay,
            );
            (mac.framework.increment_counter)(
                mac.framework.framework_ctx,
                mac.queue_delay_counter,
                queue_delay,
            );
            (mac.framework.sample_average)(
                mac.framework.framework_ctx,
                mac.average_queue_delay,
                queue_delay as f64,
            );
            if state.flow_control_enable {
                if let Some(tokens) = state.flow_manager.add_token(1).2 {
                    flow_update.push(tokens);
                }
            }
            let header = ModelHeader {
                registration_id: MAC_REGISTRATION_RFPIPE,
                sequence: state.sequence,
                data_rate_bps: pending.data_rate,
                category: 0,
                message_type: 0,
                flags: 0,
            };
            state.sequence = state.sequence.wrapping_add(1);
            state.current_end_of_transmission = now.saturating_add(pending.duration as i64);
            state.active_tx = state.queue.pop_front();
            Some((
                pending.packet,
                header,
                pending.duration,
                pending.acquired_at,
            ))
        } else {
            None
        };
        let next_wakeup = state
            .active_tx
            .as_ref()
            .map(|_| state.current_end_of_transmission.max(now));
        (transmission, next_wakeup, flow_update)
    };
    for tokens in flow_update {
        send_flow_update(mac, tokens);
    }
    if let Some((packet, header, duration, acquired_at)) = transmission {
        // Use the same timestamp as current_end_of_transmission. Sampling the
        // clock again after queue/statistics work can overlap consecutive frames.
        send_packet(mac, packet, header, duration, acquired_at, now);
    }
    if let Some(when) = next_wakeup {
        schedule_transmit(mac, when);
    }
}

fn complete_receive(mac: &RfpipeMac, pending: PendingReception) {
    let PendingReception {
        packet,
        received_at,
        query,
        sequence,
        data_rate,
    } = pending;
    let Some(spectrum) = mac.framework.reception_noise(&query) else {
        mac.counters.upstream_drop_packet(
            mac.framework,
            packet.info.source,
            packet.info.destination,
            6,
        );
        return;
    };
    let sinr = query.rx_power_dbm - spectrum.noise_floor_dbm;
    let (accepted, destination, table) = {
        let mut state = mac.state.lock().unwrap();
        let probability = state
            .pcr_curve
            .as_ref()
            .map_or(1.0, |curve| curve.probability(sinr, packet.payload.len()));
        (
            probability >= random_unit(&mut state),
            state.promiscuous_mode
                || packet.info.destination == mac.id
                || packet.info.destination == BROADCAST_NEM,
            state.rf_signal_table_handle,
        )
    };
    if !accepted {
        mac.counters.upstream_drop_packet(
            mac.framework,
            packet.info.source,
            packet.info.destination,
            1,
        );
        return;
    }
    (mac.framework.update_neighbor_rx)(
        mac.framework.framework_ctx,
        packet.info.source,
        sequence,
        packet.info.uuid.as_ptr(),
        sinr,
        spectrum.noise_floor_dbm,
        query.start_time_microseconds.max(0) as u64,
        query.duration_microseconds,
        data_rate,
    );
    (mac.framework.update_rf_signal_table)(
        mac.framework.framework_ctx,
        table,
        packet.info.source,
        0,
        query.frequency_hz,
        query.rx_power_dbm,
        sinr,
        spectrum.noise_floor_dbm,
        spectrum.receiver_sensitivity_dbm,
    );
    if destination {
        send_upstream(mac, packet, received_at);
    } else {
        mac.counters.upstream_drop_packet(
            mac.framework,
            packet.info.source,
            packet.info.destination,
            3,
        );
    }
}

fn send_upstream(mac: &RfpipeMac, packet: OwnedPacket, received_at: i64) {
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
    let packet_view = FfiPacket {
        info: packet.info,
        payload: FfiSlice {
            data: packet.payload.as_ptr(),
            len: packet.payload.len(),
        },
    };
    mac.counters.upstream_tx_packet(
        mac.framework,
        packet.info.source,
        packet.info.destination,
        packet.payload.len(),
        now_microseconds().saturating_sub(received_at) as u64,
    );
    (mac.framework.send_upstream_packet)(
        mac.framework.framework_ctx,
        mac.id,
        &packet_view,
        messages.as_ptr(),
        messages.len(),
    );
}

extern "C" fn init(id: u16, framework: *const FfiFrameworkService) -> *mut c_void {
    let Some(framework) = (unsafe { framework.as_ref() }) else {
        return std::ptr::null_mut();
    };
    Box::into_raw(Box::new(RfpipeMac::new(id, *framework))).cast()
}

extern "C" fn configure(plugin: *mut c_void, request: *const c_void) -> bool {
    let Some(mac) = (unsafe { (plugin as *mut RfpipeMac).as_ref() }) else {
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
            "enablepromiscuousmode" | "promiscuousmode" => {
                let Some(value) = parse_bool(value) else {
                    return false;
                };
                state.promiscuous_mode = value;
            }
            "datarate" => {
                let Some(value) = parse_scaled_u64(value) else {
                    return false;
                };
                if value == 0 {
                    return false;
                }
                state.data_rate_bps = value;
            }
            "delay" => {
                let Some(value) = seconds_to_microseconds(value) else {
                    return false;
                };
                state.delay_microseconds = value;
            }
            "jitter" => {
                let Some(value) = seconds_to_microseconds(value) else {
                    return false;
                };
                state.jitter_microseconds = value;
            }
            "flowcontrolenable" => {
                state.flow_control_enable = match parse_bool(value) {
                    Some(value) => value,
                    None => return false,
                };
            }
            "flowcontroltokens" => {
                let Ok(value) = value.parse::<u16>() else {
                    return false;
                };
                state.flow_control_tokens = value;
            }
            "pcrcurveuri" => state.pcr_curve_uri.clone_from(value),
            "radiometricenable" => {
                let Some(value) = parse_bool(value) else {
                    return false;
                };
                state.radiometric_enabled = value;
            }
            "radiometricreportinterval" => {
                state.radiometric_report_interval_microseconds =
                    match seconds_to_microseconds(value) {
                        Some(value @ 100_000..=60_000_000) => value as u64,
                        _ => return false,
                    };
            }
            "neighbormetricdeletetime" => {
                state.neighbor_metric_delete_microseconds = match seconds_to_microseconds(value) {
                    Some(value @ 1_000_000..=3_660_000_000) => value as u64,
                    _ => return false,
                };
            }
            "rfsignaltable.averageallantennas" => {
                let Some(value) = parse_bool(value) else {
                    return false;
                };
                state.rf_signal_average_all_antennas = value;
            }
            "rfsignaltable.averageallfrequencies" => {
                let Some(value) = parse_bool(value) else {
                    return false;
                };
                state.rf_signal_average_all_frequencies = value;
            }
            _ => return false,
        }
    }
    state.rf_signal_table_handle != 0
        && (mac.framework.configure_rf_signal_table)(
            mac.framework.framework_ctx,
            state.rf_signal_table_handle,
            state.rf_signal_average_all_antennas,
            state.rf_signal_average_all_frequencies,
        )
}

extern "C" fn start(plugin: *mut c_void) -> bool {
    let Some(mac) = (unsafe { (plugin as *mut RfpipeMac).as_ref() }) else {
        return false;
    };
    {
        let mut state = mac.state.lock().unwrap();
        if state.pcr_curve_uri.is_empty() {
            return false;
        }
        state.pcr_curve = match PcrCurve::load(&state.pcr_curve_uri) {
            Ok(curve) => Some(curve),
            Err(_) => return false,
        };
        (mac.framework.register_queue_metric)(
            mac.framework.framework_ctx,
            0,
            QUEUE_CAPACITY as u32,
        );
        state.started = true;
    }
    true
}

extern "C" fn post_start(plugin: *mut c_void) {
    let Some(mac) = (unsafe { (plugin as *mut RfpipeMac).as_ref() }) else {
        return;
    };
    let (flow_update, report) = {
        let mut state = mac.state.lock().unwrap();
        (
            state.flow_control_enable.then(|| {
                let total = state.flow_control_tokens;
                state.flow_manager.start(total)
            }),
            state.radiometric_report_interval_microseconds,
        )
    };
    if let Some(tokens) = flow_update {
        send_flow_update(mac, tokens);
    }
    let when = now_microseconds().saturating_add(report as i64);
    let timer = schedule(mac, when, EVENT_R2RI_REPORT, &when.to_be_bytes());
    if timer != 0 {
        mac.state.lock().unwrap().timers.insert(timer);
    }
}

extern "C" fn stop(plugin: *mut c_void) {
    let Some(mac) = (unsafe { (plugin as *mut RfpipeMac).as_ref() }) else {
        return;
    };
    let timers = {
        let mut state = mac.state.lock().unwrap();
        state.started = false;
        state.flow_manager.stop();
        state.queue.clear();
        state.active_tx = None;
        state.delayed_tx.clear();
        state.pending_receptions.clear();
        state.next_transmit_wakeup = 0;
        state.timers.drain().collect::<Vec<_>>()
    };
    for timer in timers {
        (mac.framework.cancel_timed_event)(mac.framework.framework_ctx, mac.id, timer);
    }
}

extern "C" fn destroy(plugin: *mut c_void) {
    if !plugin.is_null() {
        unsafe { drop(Box::from_raw(plugin as *mut RfpipeMac)) };
    }
}

extern "C" fn process_upstream(
    plugin: *mut c_void,
    packet: *const FfiPacket,
    messages: *const FfiControlMessage,
    count: usize,
) {
    let Some(mac) = (unsafe { (plugin as *mut RfpipeMac).as_ref() }) else {
        return;
    };
    if packet.is_null() {
        (mac.framework.send_upstream_control)(mac.framework.framework_ctx, mac.id, messages, count);
        return;
    }
    let Some(packet_ref) = (unsafe { packet.as_ref() }) else {
        return;
    };
    let received_at = now_microseconds();
    mac.counters.upstream_rx_packet(
        mac.framework,
        packet_ref.info.source,
        packet_ref.info.destination,
        packet_ref.payload.len,
    );
    let Some(message_views) = controls(messages, count) else {
        mac.counters.upstream_drop_packet(
            mac.framework,
            packet_ref.info.source,
            packet_ref.info.destination,
            5,
        );
        return;
    };
    let (Some(header), Some(rx)) = (
        find_header(message_views),
        find_rx_properties(message_views),
    ) else {
        mac.counters.upstream_drop_packet(
            mac.framework,
            packet_ref.info.source,
            packet_ref.info.destination,
            5,
        );
        return;
    };
    if header.registration_id != MAC_REGISTRATION_RFPIPE {
        mac.counters.upstream_drop_packet(
            mac.framework,
            packet_ref.info.source,
            packet_ref.info.destination,
            2,
        );
        return;
    }
    let Some(mut packet) = own_packet(packet, messages, count) else {
        return;
    };
    if packet.payload.len() < 2 {
        return;
    }
    let serialization_len = u16::from_be_bytes([packet.payload[0], packet.payload[1]]) as usize;
    if serialization_len == 0 || packet.payload.len() < serialization_len + 2 {
        return;
    }
    let Ok(wire_header) = RfPipeMacHeader::decode(&packet.payload[2..2 + serialization_len]) else {
        return;
    };
    if wire_header.data_rate_bps == 0 {
        return;
    }
    packet.payload.drain(..serialization_len + 2);
    let first_segment = message_views
        .iter()
        .find(|m| m.msg_type == CONTROL_RX_FREQUENCY_SEGMENTS)
        .and_then(|m| {
            if m.payload.data.is_null() {
                None
            } else {
                RxFrequencySegments::decode(unsafe {
                    std::slice::from_raw_parts(m.payload.data, m.payload.len)
                })
            }
        })
        .and_then(|segments| segments.segments.first().copied());
    let (frequency_hz, rx_power_dbm, offset, duration) = first_segment.map_or(
        (
            rx.frequency_hz,
            rx.rx_power_dbm,
            0,
            rx.duration_microseconds,
        ),
        |s| {
            (
                s.frequency_hz,
                s.rx_power_dbm,
                s.offset_microseconds,
                s.duration_microseconds,
            )
        },
    );
    let query = FfiSpectrumQuery {
        frequency_hz,
        rx_power_dbm,
        antenna_index: 0,
        start_time_microseconds: rx
            .tx_time_microseconds
            .saturating_add(i64::try_from(rx.propagation_microseconds).unwrap_or(i64::MAX))
            .saturating_add(i64::try_from(offset).unwrap_or(i64::MAX)),
        duration_microseconds: duration,
    };
    let end = query
        .start_time_microseconds
        .saturating_add(i64::try_from(duration).unwrap_or(i64::MAX));
    let pending = PendingReception {
        packet,
        received_at,
        query,
        sequence: header.sequence,
        data_rate: wire_header.data_rate_bps,
    };
    if end <= now_microseconds() {
        complete_receive(mac, pending);
        return;
    }
    let (reception_id, when) = {
        let mut state = mac.state.lock().unwrap();
        state.next_reception_id = state.next_reception_id.wrapping_add(1).max(1);
        let reception_id = state.next_reception_id;
        state.pending_receptions.insert(reception_id, pending);
        (reception_id, end)
    };
    let timer = schedule(mac, when, EVENT_RECEIVE, &reception_id.to_be_bytes());
    if timer == 0 {
        // Do not deliver early when scheduling fails.
        mac.state
            .lock()
            .unwrap()
            .pending_receptions
            .remove(&reception_id);
    } else {
        mac.state.lock().unwrap().timers.insert(timer);
    }
}

extern "C" fn process_downstream(
    plugin: *mut c_void,
    packet: *const FfiPacket,
    messages: *const FfiControlMessage,
    count: usize,
) {
    let Some(mac) = (unsafe { (plugin as *mut RfpipeMac).as_ref() }) else {
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

    let Some(packet) = own_packet(packet, messages, count) else {
        return;
    };
    mac.counters.downstream_rx_packet(
        mac.framework,
        packet.info.source,
        packet.info.destination,
        packet.payload.len(),
    );
    let now = now_microseconds();
    let pending = {
        let mut state = mac.state.lock().unwrap();
        if !state.started || (state.flow_control_enable && !state.flow_manager.remove_token().1) {
            mac.counters.downstream_drop_packet(
                mac.framework,
                packet.info.source,
                packet.info.destination,
                7,
            );
            return;
        }
        let data_rate = state.data_rate_bps;
        let duration = duration_microseconds(packet.payload.len(), data_rate);
        let jitter = if state.jitter_microseconds == 0 {
            0
        } else {
            ((f64::from(state.jitter_random.unit()) - 0.5) * state.jitter_microseconds as f64)
                .trunc() as i64
        };
        let ready_at = now
            .saturating_add(state.delay_microseconds)
            .saturating_add(jitter)
            .max(now);
        PendingTx {
            packet,
            acquired_at: now,
            ready_at,
            duration,
            data_rate,
        }
    };
    if pending.ready_at > now {
        let (id, ready_at) = {
            let mut state = mac.state.lock().unwrap();
            state.next_delayed_id = state.next_delayed_id.wrapping_add(1);
            let id = state.next_delayed_id;
            let ready_at = pending.ready_at;
            state.delayed_tx.insert(id, pending);
            (id, ready_at)
        };
        let timer = schedule(mac, ready_at, EVENT_DELAY_COMPLETE, &id.to_be_bytes());
        if timer != 0 {
            mac.state.lock().unwrap().timers.insert(timer);
        }
    } else {
        pend_or_enqueue(mac, pending, now);
    }
}

fn pend_or_enqueue(mac: &RfpipeMac, pending: PendingTx, now: i64) {
    {
        let mut state = mac.state.lock().unwrap();
        if !state.started {
            return;
        }
        if state.active_tx.is_none() {
            state.active_tx = Some(pending);
        } else {
            while state.queue.len() >= QUEUE_CAPACITY {
                if let Some(dropped) = state.queue.pop_front() {
                    mac.counters.downstream_drop_packet(
                        mac.framework,
                        dropped.packet.info.source,
                        dropped.packet.info.destination,
                        4,
                    );
                }
                state.queue_discards = state.queue_discards.saturating_add(1);
                if state.flow_control_enable {
                    if let Some(tokens) = state.flow_manager.add_token(1).2 {
                        send_flow_update(mac, tokens);
                    }
                }
            }
            state.queue.push_back(pending);
            (mac.framework.maximize_counter)(
                mac.framework.framework_ctx,
                mac.queue_high_water_counter,
                state.queue.len() as u64,
            );
        }
    }
    drive_transmit(mac, now);
}

extern "C" fn process_timed_event(
    plugin: *mut c_void,
    timer_id: u64,
    event_id: u32,
    data: *const u8,
    data_len: usize,
) {
    let Some(mac) = (unsafe { (plugin as *mut RfpipeMac).as_ref() }) else {
        return;
    };
    mac.state.lock().unwrap().timers.remove(&timer_id);
    if data_len != 8 || data.is_null() {
        return;
    }
    let value = u64::from_be_bytes(
        unsafe { std::slice::from_raw_parts(data, 8) }
            .try_into()
            .unwrap(),
    );
    match event_id {
        EVENT_DELAY_COMPLETE => {
            let pending = mac.state.lock().unwrap().delayed_tx.remove(&value);
            if let Some(pending) = pending {
                pend_or_enqueue(mac, pending, now_microseconds());
            }
        }
        EVENT_TRANSMIT => {
            let expected = value as i64;
            {
                let mut state = mac.state.lock().unwrap();
                if state.next_transmit_wakeup != expected {
                    return;
                }
                state.next_transmit_wakeup = 0;
            }
            drive_transmit(mac, now_microseconds());
        }
        EVENT_RECEIVE => {
            let packet = mac.state.lock().unwrap().pending_receptions.remove(&value);
            if let Some(pending) = packet {
                complete_receive(mac, pending);
            }
        }
        EVENT_R2RI_REPORT => {
            let report = {
                let state = mac.state.lock().unwrap();
                state.started.then_some((
                    state.radiometric_enabled,
                    state.data_rate_bps,
                    state.radiometric_report_interval_microseconds,
                    state.neighbor_metric_delete_microseconds,
                ))
            };
            if let Some((enabled, data_rate, interval, delete_time)) = report {
                if enabled {
                    (mac.framework.publish_r2ri)(
                        mac.framework.framework_ctx,
                        data_rate,
                        data_rate,
                        interval,
                        delete_time,
                    );
                } else {
                    (mac.framework.update_neighbor_status)(mac.framework.framework_ctx);
                }
                let when = now_microseconds().saturating_add(interval as i64);
                let timer = schedule(mac, when, EVENT_R2RI_REPORT, &when.to_be_bytes());
                if timer != 0 {
                    mac.state.lock().unwrap().timers.insert(timer);
                }
            }
        }
        _ => {}
    }
}

extern "C" fn process_event(_: *mut c_void, _: u16, _: *const u8, _: usize) {}

#[no_mangle]
pub extern "C" fn emane_plugin_create() -> *const PluginApi {
    static API: OnceLock<PluginApi> = OnceLock::new();
    API.get_or_init(|| PluginApi {
        abi_version: PLUGIN_ABI_VERSION,
        struct_size: std::mem::size_of::<PluginApi>(),
        name: c"rfpipemaclayer".as_ptr(),
        plugin_type: 1,
        init,
        configure,
        start,
        post_start,
        stop,
        destroy,
        process_upstream,
        process_downstream,
        process_timed_event,
        process_event,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_legacy_units_and_airtime() {
        assert_eq!(parse_scaled_u64("1M"), Some(1_000_000));
        assert_eq!(seconds_to_microseconds("0.25"), Some(250_000));
        assert_eq!(duration_microseconds(125, 1_000_000), 1_000);
    }
}

#[cfg(test)]
mod regression_tests;
