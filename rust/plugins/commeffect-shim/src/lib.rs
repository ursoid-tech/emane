use emane_plugin_api::{
    CommEffectHeader, CommonLayerCounters, FfiConfigItem, FfiConfigRequest, FfiControlMessage,
    FfiFrameworkService, FfiPacket, FfiPacketInfo, FfiSlice, FfiStatisticValue, PluginApi,
    CONTROL_COMM_EFFECT_HEADER, PLUGIN_ABI_VERSION, STATISTIC_VALUE_U64,
};
use prost::Message;
use rand::{rngs::StdRng, Rng, SeedableRng};
use roxmltree::{Document, Node};
use std::collections::HashMap;
use std::ffi::{c_void, CStr};
use std::net::Ipv4Addr;
use std::sync::OnceLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

fn elapsed_microseconds(begin: Instant) -> u64 {
    begin.elapsed().as_micros().min(u128::from(u64::MAX)) as u64
}

const EVENT_COMM_EFFECT: u16 = 103;
const TIMER_UPSTREAM_PACKET: u32 = 1;
const BROADCAST_NEM: u16 = u16::MAX;

#[derive(Clone, PartialEq, Message)]
struct CommEffectEvent {
    #[prost(message, repeated, tag = "1")]
    effects: Vec<CommEffectMessage>,
}

#[derive(Clone, PartialEq, Message)]
struct CommEffectMessage {
    #[prost(uint32, required, tag = "1")]
    nem_id: u32,
    #[prost(float, required, tag = "2")]
    latency_seconds: f32,
    #[prost(float, required, tag = "3")]
    jitter_seconds: f32,
    #[prost(float, required, tag = "4")]
    probability_loss: f32,
    #[prost(float, required, tag = "5")]
    probability_duplicate: f32,
    #[prost(uint64, required, tag = "6")]
    unicast_bit_rate_bps: u64,
    #[prost(uint64, required, tag = "7")]
    broadcast_bit_rate_bps: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct Effect {
    latency_microseconds: u64,
    jitter_microseconds: u64,
    probability_loss: f32,
    probability_duplicate: f32,
    unicast_bit_rate_bps: u64,
    broadcast_bit_rate_bps: u64,
}

impl Effect {
    fn from_message(message: &CommEffectMessage) -> Option<Self> {
        let latency = seconds_to_microseconds(message.latency_seconds)?;
        let jitter = seconds_to_microseconds(message.jitter_seconds)?;
        (message.nem_id <= u16::MAX as u32
            && message.probability_loss.is_finite()
            && (0.0..=100.0).contains(&message.probability_loss)
            && message.probability_duplicate.is_finite()
            && (0.0..=u16::MAX as f32).contains(&message.probability_duplicate))
        .then_some(Self {
            latency_microseconds: latency,
            jitter_microseconds: jitter,
            probability_loss: message.probability_loss,
            probability_duplicate: message.probability_duplicate,
            unicast_bit_rate_bps: message.unicast_bit_rate_bps,
            broadcast_bit_rate_bps: message.broadcast_bit_rate_bps,
        })
    }
}

fn seconds_to_microseconds(seconds: f32) -> Option<u64> {
    let value = f64::from(seconds) * 1_000_000.0;
    (seconds.is_finite() && seconds >= 0.0 && value <= u64::MAX as f64)
        .then_some(value.round() as u64)
}

#[derive(Clone, Debug)]
struct Filter {
    target: Target,
    effect: Effect,
}

#[derive(Clone, Debug, Default)]
struct Target {
    ipv4: Option<Ipv4Rule>,
}

#[derive(Clone, Debug, Default)]
struct Ipv4Rule {
    source: Option<[u8; 4]>,
    destination: Option<[u8; 4]>,
    total_length: Option<u16>,
    tos: Option<u8>,
    ttl: Option<u8>,
    protocols: Vec<ProtocolRule>,
}

#[derive(Clone, Debug)]
enum ProtocolRule {
    Udp {
        source: Option<u16>,
        destination: Option<u16>,
    },
    Number(u8),
}

impl Target {
    fn matches(&self, frame: &[u8]) -> bool {
        let Some(rule) = &self.ipv4 else { return true };
        if frame.len() < 34 || u16::from_be_bytes([frame[12], frame[13]]) != 0x0800 {
            return false;
        }
        let ip = &frame[14..];
        let header_len = usize::from(ip[0] & 0x0f) * 4;
        if ip[0] >> 4 != 4 || header_len < 20 || ip.len() < header_len {
            return false;
        }
        if rule.source.is_some_and(|value| ip[12..16] != value)
            || rule.destination.is_some_and(|value| ip[16..20] != value)
            || rule
                .total_length
                .is_some_and(|value| u16::from_be_bytes([ip[2], ip[3]]) != value)
            || rule.tos.is_some_and(|value| ip[1] != value)
            || rule.ttl.is_some_and(|value| ip[8] != value)
        {
            return false;
        }
        if rule.protocols.is_empty() {
            return true;
        }
        rule.protocols.iter().any(|protocol| match protocol {
            ProtocolRule::Number(value) => ip[9] == *value,
            ProtocolRule::Udp {
                source,
                destination,
            } => {
                if ip[9] != 17 || ip.len() < header_len + 8 {
                    return false;
                }
                let udp = &ip[header_len..];
                !source.is_some_and(|value| u16::from_be_bytes([udp[0], udp[1]]) != value)
                    && !destination
                        .is_some_and(|value| u16::from_be_bytes([udp[2], udp[3]]) != value)
            }
        })
    }
}

struct CommEffectShim {
    id: u16,
    framework: FfiFrameworkService,
    counters: CommonLayerCounters,
    default_connectivity: bool,
    promiscuous: bool,
    group_id: u32,
    receive_buffer_period_microseconds: u64,
    filter_file: Option<String>,
    filters: Vec<Filter>,
    profiles: HashMap<u16, Effect>,
    broadcast_accept: HashMap<u16, PacketAcceptInfo>,
    broadcast_drop: HashMap<u16, PacketDropInfo>,
    unicast_accept: HashMap<u16, PacketAcceptInfo>,
    unicast_drop: HashMap<u16, PacketDropInfo>,
    packet_tables: HashMap<String, u64>,
    table_generations: HashMap<String, u64>,
    end_of_reception: HashMap<u16, u64>,
    sequence: u32,
    rng: StdRng,
}

#[derive(Default)]
struct PacketAcceptInfo {
    tx_bytes: u64,
    rx_bytes: u64,
}

#[derive(Default)]
struct PacketDropInfo {
    bytes: [u64; 8],
}

#[derive(Clone, Copy)]
enum PacketDropReason {
    Effect = 0,
    GroupId = 1,
    RegistrationId = 2,
    Destination = 3,
    BadMessage = 4,
    NoProfile = 5,
    ReceiveBuffer = 6,
    Timer = 7,
}

fn statistic_u64(value: u64) -> FfiStatisticValue {
    FfiStatisticValue {
        value_type: STATISTIC_VALUE_U64,
        u64_value: value,
        f64_value: 0.0,
        string_value: std::ptr::null(),
    }
}

fn packet_table_generation(state: &CommEffectShim, name: &str) -> u64 {
    state.packet_tables.get(name).copied().map_or(0, |handle| {
        (state.framework.table_generation)(state.framework.framework_ctx, handle)
    })
}

fn set_packet_row(state: &CommEffectShim, name: &str, nem_id: u16, values: &[FfiStatisticValue]) {
    if let Some(handle) = state.packet_tables.get(name).copied() {
        let key = [u64::from(nem_id)];
        (state.framework.set_table_row)(
            state.framework.framework_ctx,
            handle,
            key.as_ptr(),
            key.len(),
            values.as_ptr(),
            values.len(),
        );
    }
}

fn record_accept(state: &mut CommEffectShim, info: FfiPacketInfo, size: usize, inbound: bool) {
    let broadcast = info.destination == BROADCAST_NEM;
    let name = format!(
        "{}ByteAcceptTable0",
        if broadcast { "Broadcast" } else { "Unicast" }
    );
    let generation = packet_table_generation(state, &name);
    let reset = state
        .table_generations
        .insert(name.clone(), generation)
        .is_some_and(|previous| previous != generation);
    let infos = if broadcast {
        &mut state.broadcast_accept
    } else {
        &mut state.unicast_accept
    };
    if reset {
        infos.clear();
    }
    let entry = infos.entry(info.source).or_default();
    if inbound {
        entry.rx_bytes = entry.rx_bytes.saturating_add(size as u64);
    } else {
        entry.tx_bytes = entry.tx_bytes.saturating_add(size as u64);
    }
    let values = [
        statistic_u64(u64::from(info.source)),
        statistic_u64(entry.tx_bytes),
        statistic_u64(entry.rx_bytes),
    ];
    set_packet_row(state, &name, info.source, &values);
}

fn record_drop(
    state: &mut CommEffectShim,
    info: FfiPacketInfo,
    size: usize,
    reason: PacketDropReason,
) {
    let broadcast = info.destination == BROADCAST_NEM;
    let name = format!(
        "{}ByteDropTable0",
        if broadcast { "Broadcast" } else { "Unicast" }
    );
    let generation = packet_table_generation(state, &name);
    let reset = state
        .table_generations
        .insert(name.clone(), generation)
        .is_some_and(|previous| previous != generation);
    let infos = if broadcast {
        &mut state.broadcast_drop
    } else {
        &mut state.unicast_drop
    };
    if reset {
        infos.clear();
    }
    let entry = infos.entry(info.source).or_default();
    entry.bytes[reason as usize] = entry.bytes[reason as usize].saturating_add(size as u64);
    let mut values = Vec::with_capacity(9);
    values.push(statistic_u64(u64::from(info.source)));
    values.extend(entry.bytes.iter().copied().map(statistic_u64));
    set_packet_row(state, &name, info.source, &values);
    state.counters.upstream_drop_packet(
        state.framework,
        info.source,
        info.destination,
        reason as usize + 1,
    );
}

fn unix_microseconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros()
        .min(u128::from(u64::MAX)) as u64
}

fn controls<'a>(
    messages: *const FfiControlMessage,
    count: usize,
) -> Option<&'a [FfiControlMessage]> {
    if count > 4096 || (count != 0 && messages.is_null()) {
        None
    } else if count == 0 {
        Some(&[])
    } else {
        Some(unsafe { std::slice::from_raw_parts(messages, count) })
    }
}

unsafe fn config_items(request: *const c_void) -> Option<Vec<(String, Vec<String>)>> {
    let request = (request as *const FfiConfigRequest).as_ref()?;
    if request.len > 4096 || (request.len != 0 && request.data.is_null()) {
        return None;
    }
    let items: &[FfiConfigItem] = if request.len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(request.data, request.len)
    };
    items
        .iter()
        .map(|item| {
            let name = CStr::from_ptr(item.name).to_str().ok()?.to_string();
            if item.values.len > 4096 || (item.values.len != 0 && item.values.data.is_null()) {
                return None;
            }
            let values = if item.values.len == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(item.values.data, item.values.len)
            };
            let values = values
                .iter()
                .map(|value| {
                    if value.is_null() {
                        None
                    } else {
                        Some(CStr::from_ptr(*value).to_str().ok()?.to_string())
                    }
                })
                .collect::<Option<Vec<_>>>()?;
            Some((name, values))
        })
        .collect()
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "true" | "on" | "yes" | "1" => Some(true),
        "false" | "off" | "no" | "0" => Some(false),
        _ => None,
    }
}

fn register_packet_table(
    framework: FfiFrameworkService,
    name: &'static CStr,
    labels: &[&CStr],
    description: &'static CStr,
) -> u64 {
    let pointers = labels
        .iter()
        .map(|label| label.as_ptr())
        .collect::<Vec<_>>();
    (framework.register_table)(
        framework.framework_ctx,
        name.as_ptr(),
        pointers.as_ptr(),
        pointers.len(),
        description.as_ptr(),
        true,
    )
}

extern "C" fn init(id: u16, framework: *const FfiFrameworkService) -> *mut c_void {
    let Some(framework) = (unsafe { framework.as_ref() }) else {
        return std::ptr::null_mut();
    };
    let framework = *framework;
    let accept_labels = [c"NEM", c"Num Bytes Tx", c"Num Bytes Rx"];
    let drop_labels = [
        c"NEM",
        c"Effect",
        c"Grp Id",
        c"Reg Id",
        c"Dst MAC",
        c"Bad Msg",
        c"No Profile",
        c"Rx Buff",
        c"Timer",
    ];
    let mut packet_tables = HashMap::new();
    for (name, handle) in [
        (
            "BroadcastByteAcceptTable0",
            register_packet_table(
                framework,
                c"BroadcastByteAcceptTable0",
                &accept_labels,
                c"Broadcast bytes accepted",
            ),
        ),
        (
            "UnicastByteAcceptTable0",
            register_packet_table(
                framework,
                c"UnicastByteAcceptTable0",
                &accept_labels,
                c"Unicast bytes accepted",
            ),
        ),
        (
            "BroadcastByteDropTable0",
            register_packet_table(
                framework,
                c"BroadcastByteDropTable0",
                &drop_labels,
                c"Broadcast bytes dropped by reason",
            ),
        ),
        (
            "UnicastByteDropTable0",
            register_packet_table(
                framework,
                c"UnicastByteDropTable0",
                &drop_labels,
                c"Unicast bytes dropped by reason",
            ),
        ),
    ] {
        if handle != 0 {
            packet_tables.insert(name.to_string(), handle);
        }
    }
    Box::into_raw(Box::new(CommEffectShim {
        id,
        framework,
        counters: CommonLayerCounters::register_with_drop_labels(
            framework,
            "0",
            &[
                "Effect",
                "Grp Id",
                "Reg Id",
                "Dst MAC",
                "Bad Msg",
                "No Profile",
                "Rx Buff",
                "Timer",
            ],
            &[],
        ),
        default_connectivity: true,
        promiscuous: false,
        group_id: 0,
        receive_buffer_period_microseconds: 1_000_000,
        filter_file: None,
        filters: Vec::new(),
        profiles: HashMap::new(),
        broadcast_accept: HashMap::new(),
        broadcast_drop: HashMap::new(),
        unicast_accept: HashMap::new(),
        unicast_drop: HashMap::new(),
        packet_tables,
        table_generations: HashMap::new(),
        end_of_reception: HashMap::new(),
        sequence: 0,
        rng: StdRng::from_entropy(),
    }))
    .cast()
}

extern "C" fn configure(plugin: *mut c_void, request: *const c_void) -> bool {
    let Some(state) = (unsafe { (plugin as *mut CommEffectShim).as_mut() }) else {
        return false;
    };
    let Some(items) = (unsafe { config_items(request) }) else {
        return false;
    };
    let mut connectivity_seen = false;
    for (name, values) in items {
        if values.len() != 1 {
            return false;
        }
        let value = &values[0];
        match name.as_str() {
            "defaultconnectivitymode" | "defaultconnectivity" if !connectivity_seen => {
                let Some(parsed) = parse_bool(value) else {
                    return false;
                };
                state.default_connectivity = parsed;
                connectivity_seen = true;
            }
            "enablepromiscuousmode" => {
                let Some(parsed) = parse_bool(value) else {
                    return false;
                };
                state.promiscuous = parsed;
            }
            "groupid" => {
                let Ok(parsed) = value.parse() else {
                    return false;
                };
                state.group_id = parsed;
            }
            "receivebufferperiod" => {
                let Ok(seconds) = value.parse::<f64>() else {
                    return false;
                };
                let microseconds = seconds * 1_000_000.0;
                if !seconds.is_finite() || seconds < 0.0 || microseconds > u64::MAX as f64 {
                    return false;
                }
                state.receive_buffer_period_microseconds = microseconds.round() as u64;
            }
            "filterfile" if !value.is_empty() => state.filter_file = Some(value.clone()),
            _ => return false,
        }
    }
    true
}

extern "C" fn start(plugin: *mut c_void) -> bool {
    let Some(state) = (unsafe { (plugin as *mut CommEffectShim).as_mut() }) else {
        return false;
    };
    if let Some(path) = &state.filter_file {
        let path = path.strip_prefix("file://").unwrap_or(path);
        let Ok(filters) = load_filters(path) else {
            return false;
        };
        state.filters = filters;
    }
    true
}

extern "C" fn post_start(_: *mut c_void) {}

extern "C" fn stop(plugin: *mut c_void) {
    if let Some(state) = unsafe { (plugin as *mut CommEffectShim).as_mut() } {
        state.end_of_reception.clear();
    }
}

extern "C" fn destroy(plugin: *mut c_void) {
    if !plugin.is_null() {
        unsafe { drop(Box::from_raw(plugin as *mut CommEffectShim)) };
    }
}

extern "C" fn downstream(
    plugin: *mut c_void,
    packet: *const FfiPacket,
    messages: *const FfiControlMessage,
    count: usize,
) {
    let Some(state) = (unsafe { (plugin as *mut CommEffectShim).as_mut() }) else {
        return;
    };
    let begin = Instant::now();
    let Some(incoming) = controls(messages, count) else {
        return;
    };
    if packet.is_null() {
        (state.framework.send_downstream_control)(
            state.framework.framework_ctx,
            state.id,
            messages,
            count,
        );
        return;
    }
    let header = CommEffectHeader {
        group_id: state.group_id,
        sequence: state.sequence,
        tx_time_microseconds: unix_microseconds() as i64,
    };
    let packet_ref = unsafe { &*packet };
    state.counters.downstream_rx_packet(
        state.framework,
        packet_ref.info.source,
        packet_ref.info.destination,
        packet_ref.payload.len,
    );
    state.sequence = state.sequence.wrapping_add(1);
    let encoded = header.encode();
    let mut outgoing: Vec<_> = incoming
        .iter()
        .copied()
        .filter(|message| message.msg_type != CONTROL_COMM_EFFECT_HEADER)
        .collect();
    outgoing.push(FfiControlMessage {
        msg_type: CONTROL_COMM_EFFECT_HEADER,
        payload: FfiSlice {
            data: encoded.as_ptr(),
            len: encoded.len(),
        },
    });
    state.counters.downstream_tx_packet(
        state.framework,
        packet_ref.info.source,
        packet_ref.info.destination,
        packet_ref.payload.len,
        elapsed_microseconds(begin),
        false,
    );
    (state.framework.send_downstream_packet)(
        state.framework.framework_ctx,
        state.id,
        packet,
        outgoing.as_ptr(),
        outgoing.len(),
    );
    record_accept(state, packet_ref.info, packet_ref.payload.len, false);
}

extern "C" fn upstream(
    plugin: *mut c_void,
    packet: *const FfiPacket,
    messages: *const FfiControlMessage,
    count: usize,
) {
    let Some(state) = (unsafe { (plugin as *mut CommEffectShim).as_mut() }) else {
        return;
    };
    let begin = Instant::now();
    let Some(incoming) = controls(messages, count) else {
        return;
    };
    if packet.is_null() {
        (state.framework.send_upstream_control)(
            state.framework.framework_ctx,
            state.id,
            messages,
            count,
        );
        return;
    }
    let packet = unsafe { &*packet };
    state.counters.upstream_rx_packet(
        state.framework,
        packet.info.source,
        packet.info.destination,
        packet.payload.len,
    );
    if packet.payload.len != 0 && packet.payload.data.is_null() {
        record_drop(
            state,
            packet.info,
            packet.payload.len,
            PacketDropReason::BadMessage,
        );
        return;
    }
    let Some(header_message) = incoming
        .iter()
        .find(|message| message.msg_type == CONTROL_COMM_EFFECT_HEADER)
    else {
        record_drop(
            state,
            packet.info,
            packet.payload.len,
            PacketDropReason::RegistrationId,
        );
        return;
    };
    if header_message.payload.data.is_null() && header_message.payload.len != 0 {
        record_drop(
            state,
            packet.info,
            packet.payload.len,
            PacketDropReason::BadMessage,
        );
        return;
    }
    let header_data = if header_message.payload.len == 0 {
        &[][..]
    } else {
        unsafe {
            std::slice::from_raw_parts(header_message.payload.data, header_message.payload.len)
        }
    };
    let Some(header) = CommEffectHeader::decode(header_data) else {
        record_drop(
            state,
            packet.info,
            packet.payload.len,
            PacketDropReason::BadMessage,
        );
        return;
    };
    if !state.promiscuous
        && packet.info.destination != BROADCAST_NEM
        && packet.info.destination != state.id
    {
        record_drop(
            state,
            packet.info,
            packet.payload.len,
            PacketDropReason::Destination,
        );
        return;
    }
    if header.group_id != state.group_id {
        record_drop(
            state,
            packet.info,
            packet.payload.len,
            PacketDropReason::GroupId,
        );
        return;
    }
    let payload = if packet.payload.len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(packet.payload.data, packet.payload.len) }
    };
    let effect = state
        .filters
        .iter()
        .find(|filter| filter.target.matches(payload))
        .map(|filter| filter.effect)
        .or_else(|| state.profiles.get(&packet.info.source).copied());
    let Some(effect) = effect else {
        if state.default_connectivity {
            send_upstream_now(state, packet, incoming, elapsed_microseconds(begin));
        } else {
            record_drop(
                state,
                packet.info,
                packet.payload.len,
                PacketDropReason::NoProfile,
            );
        }
        return;
    };
    let now = unix_microseconds();
    let bitrate = if packet.info.destination == BROADCAST_NEM {
        effect.broadcast_bit_rate_bps
    } else {
        effect.unicast_bit_rate_bps
    };
    let reception = if bitrate == 0 {
        0
    } else {
        ((payload.len() as u128 * 8 * 1_000_000) / u128::from(bitrate)).min(u128::from(u64::MAX))
            as u64
    };
    let previous = state.end_of_reception.get(&packet.info.source).copied();
    if state.receive_buffer_period_microseconds != 0
        && previous
            .is_some_and(|end| end.saturating_sub(now) > state.receive_buffer_period_microseconds)
    {
        record_drop(
            state,
            packet.info,
            packet.payload.len,
            PacketDropReason::ReceiveBuffer,
        );
        return;
    }
    let end = previous.unwrap_or(now).max(now).saturating_add(reception);
    state.end_of_reception.insert(packet.info.source, end);
    let copies = task_count(
        &mut state.rng,
        effect.probability_loss,
        effect.probability_duplicate,
    );
    if copies == 0 {
        record_drop(
            state,
            packet.info,
            packet.payload.len,
            PacketDropReason::Effect,
        );
        return;
    }
    let mut timer_failure = false;
    for _ in 0..copies {
        let jitter = if effect.jitter_microseconds == 0 {
            0
        } else {
            state.rng.gen_range(
                -(effect.jitter_microseconds as i128)..(effect.jitter_microseconds as i128),
            )
        };
        let base = end.saturating_add(effect.latency_microseconds);
        let expiration = if jitter < 0 {
            base.saturating_sub((-jitter) as u64).max(now)
        } else {
            base.saturating_add(jitter as u64)
        };
        let mut data = encode_pending(packet, incoming, 0);
        data[17..25].copy_from_slice(&elapsed_microseconds(begin).to_be_bytes());
        if (state.framework.schedule_timed_event)(
            state.framework.framework_ctx,
            state.id,
            expiration / 1_000_000,
            (expiration % 1_000_000) as u32,
            TIMER_UPSTREAM_PACKET,
            data.as_ptr(),
            data.len(),
        ) == 0
        {
            timer_failure = true;
        }
    }
    if timer_failure {
        record_drop(
            state,
            packet.info,
            packet.payload.len,
            PacketDropReason::Timer,
        );
    }
}

fn send_upstream_now(
    state: &mut CommEffectShim,
    packet: &FfiPacket,
    incoming: &[FfiControlMessage],
    processing_delay_microseconds: u64,
) {
    let outgoing: Vec<_> = incoming
        .iter()
        .copied()
        .filter(|message| message.msg_type != CONTROL_COMM_EFFECT_HEADER)
        .collect();
    state.counters.upstream_tx_packet(
        state.framework,
        packet.info.source,
        packet.info.destination,
        packet.payload.len,
        processing_delay_microseconds,
    );
    (state.framework.send_upstream_packet)(
        state.framework.framework_ctx,
        state.id,
        packet,
        outgoing.as_ptr(),
        outgoing.len(),
    );
    record_accept(state, packet.info, packet.payload.len, true);
}

fn task_count(rng: &mut StdRng, loss: f32, duplicate: f32) -> usize {
    if loss >= 100.0 || (loss > 0.0 && rng.gen_range(0.0..100.0) < loss) {
        return 0;
    }
    let whole = (duplicate / 100.0).floor() as usize;
    let remainder = duplicate % 100.0;
    1usize.saturating_add(whole).saturating_add(usize::from(
        remainder > 0.0 && rng.gen_range(0.0..100.0) <= remainder,
    ))
}

fn encode_pending(
    packet: &FfiPacket,
    messages: &[FfiControlMessage],
    processing_delay_microseconds: u64,
) -> Vec<u8> {
    let payload = if packet.payload.len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(packet.payload.data, packet.payload.len) }
    };
    let outgoing: Vec<_> = messages
        .iter()
        .filter(|message| message.msg_type != CONTROL_COMM_EFFECT_HEADER)
        .collect();
    let mut data = Vec::new();
    data.extend_from_slice(&packet.info.source.to_be_bytes());
    data.extend_from_slice(&packet.info.destination.to_be_bytes());
    data.push(packet.info.priority);
    data.extend_from_slice(&packet.info.creation_time_sec.to_be_bytes());
    data.extend_from_slice(&packet.info.creation_time_usec.to_be_bytes());
    data.extend_from_slice(&processing_delay_microseconds.to_be_bytes());
    data.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    data.extend_from_slice(payload);
    data.extend_from_slice(&(outgoing.len() as u16).to_be_bytes());
    for message in outgoing {
        let body = if message.payload.len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(message.payload.data, message.payload.len) }
        };
        data.extend_from_slice(&message.msg_type.to_be_bytes());
        data.extend_from_slice(&(body.len() as u32).to_be_bytes());
        data.extend_from_slice(body);
    }
    data
}

extern "C" fn timed(plugin: *mut c_void, _: u64, event_id: u32, data: *const u8, data_len: usize) {
    let Some(state) = (unsafe { (plugin as *mut CommEffectShim).as_mut() }) else {
        return;
    };
    if event_id != TIMER_UPSTREAM_PACKET || data.is_null() {
        return;
    }
    let data = unsafe { std::slice::from_raw_parts(data, data_len) };
    let Some(pending) = decode_pending(data) else {
        return;
    };
    state.counters.upstream_tx_packet(
        state.framework,
        pending.packet.info.source,
        pending.packet.info.destination,
        pending.packet.payload.len,
        pending.processing_delay_microseconds,
    );
    (state.framework.send_upstream_packet)(
        state.framework.framework_ctx,
        state.id,
        &pending.packet,
        pending.messages.as_ptr(),
        pending.messages.len(),
    );
    record_accept(state, pending.packet.info, pending.packet.payload.len, true);
}

struct Pending {
    _payload: Vec<u8>,
    _control_payloads: Vec<Vec<u8>>,
    packet: FfiPacket,
    messages: Vec<FfiControlMessage>,
    processing_delay_microseconds: u64,
}

fn decode_pending(data: &[u8]) -> Option<Pending> {
    if data.len() < 31 {
        return None;
    }
    let source = u16::from_be_bytes(data[0..2].try_into().ok()?);
    let destination = u16::from_be_bytes(data[2..4].try_into().ok()?);
    let priority = data[4];
    let creation_time_sec = u64::from_be_bytes(data[5..13].try_into().ok()?);
    let creation_time_usec = u32::from_be_bytes(data[13..17].try_into().ok()?);
    let processing_delay_microseconds = u64::from_be_bytes(data[17..25].try_into().ok()?);
    let payload_len = u32::from_be_bytes(data[25..29].try_into().ok()?) as usize;
    let mut offset = 29usize;
    let payload_end = offset.checked_add(payload_len)?;
    if payload_end.checked_add(2)? > data.len() {
        return None;
    }
    let payload = data[offset..payload_end].to_vec();
    offset = payload_end;
    let count = u16::from_be_bytes(data[offset..offset + 2].try_into().ok()?) as usize;
    offset += 2;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        if offset.checked_add(8)? > data.len() {
            return None;
        }
        let kind = u32::from_be_bytes(data[offset..offset + 4].try_into().ok()?);
        let len = u32::from_be_bytes(data[offset + 4..offset + 8].try_into().ok()?) as usize;
        offset += 8;
        let end = offset.checked_add(len)?;
        if end > data.len() {
            return None;
        }
        entries.push((kind, data[offset..end].to_vec()));
        offset = end;
    }
    if offset != data.len() {
        return None;
    }
    let control_payloads: Vec<_> = entries.iter().map(|(_, body)| body.clone()).collect();
    let messages = entries
        .iter()
        .zip(&control_payloads)
        .map(|((kind, _), body)| FfiControlMessage {
            msg_type: *kind,
            payload: FfiSlice {
                data: body.as_ptr(),
                len: body.len(),
            },
        })
        .collect();
    let packet = FfiPacket {
        info: FfiPacketInfo {
            uuid: [0; 16],
            source,
            destination,
            priority,
            creation_time_sec,
            creation_time_usec,
        },
        payload: FfiSlice {
            data: payload.as_ptr(),
            len: payload.len(),
        },
    };
    Some(Pending {
        _payload: payload,
        _control_payloads: control_payloads,
        packet,
        messages,
        processing_delay_microseconds,
    })
}

extern "C" fn event(plugin: *mut c_void, event_id: u16, data: *const u8, data_len: usize) {
    let Some(state) = (unsafe { (plugin as *mut CommEffectShim).as_mut() }) else {
        return;
    };
    if event_id != EVENT_COMM_EFFECT || data.is_null() {
        return;
    }
    let Ok(event) = CommEffectEvent::decode(unsafe { std::slice::from_raw_parts(data, data_len) })
    else {
        return;
    };
    if event
        .effects
        .iter()
        .any(|message| Effect::from_message(message).is_none())
    {
        return;
    }
    for message in event.effects {
        if message.nem_id != 0 {
            state.profiles.insert(
                message.nem_id as u16,
                Effect::from_message(&message).unwrap(),
            );
        }
    }
    state.default_connectivity = false;
}

fn parse_optional<T: std::str::FromStr + PartialEq + Default>(
    node: Node<'_, '_>,
    name: &str,
) -> Result<Option<T>, String> {
    match node.attribute(name) {
        None => Ok(None),
        Some(value) => value
            .parse::<T>()
            .map(|value| (value != T::default()).then_some(value))
            .map_err(|_| format!("invalid {name}")),
    }
}

fn parse_ipv4(value: Option<&str>) -> Result<Option<[u8; 4]>, String> {
    let Some(value) = value else { return Ok(None) };
    let address: Ipv4Addr = value
        .parse()
        .map_err(|_| "invalid IPv4 address".to_string())?;
    Ok((address != Ipv4Addr::UNSPECIFIED).then_some(address.octets()))
}

fn parse_duration(node: Option<Node<'_, '_>>) -> Result<u64, String> {
    let Some(node) = node else { return Ok(0) };
    let seconds = node
        .attribute("sec")
        .unwrap_or("0")
        .parse::<u64>()
        .map_err(|_| "invalid duration seconds")?;
    let microseconds = node
        .attribute("usec")
        .unwrap_or("0")
        .parse::<u64>()
        .map_err(|_| "invalid duration microseconds")?;
    seconds
        .checked_mul(1_000_000)
        .and_then(|value| value.checked_add(microseconds))
        .ok_or_else(|| "duration overflow".to_string())
}

fn text_value<T: std::str::FromStr + Default>(
    parent: Node<'_, '_>,
    name: &str,
) -> Result<T, String> {
    parent
        .children()
        .find(|node| node.is_element() && node.tag_name().name() == name)
        .map_or(Ok(T::default()), |node| {
            node.text()
                .unwrap_or("0")
                .trim()
                .parse()
                .map_err(|_| format!("invalid {name}"))
        })
}

fn load_filters(path: &str) -> Result<Vec<Filter>, String> {
    let xml = emane_plugin_api::xml_document::read(path).map_err(|error| error.to_string())?;
    let document = Document::parse_with_options(
        &xml,
        roxmltree::ParsingOptions {
            allow_dtd: true,
            ..Default::default()
        },
    )
    .map_err(|error| error.to_string())?;
    let root = document.root_element();
    if root.tag_name().name() != "commeffect" {
        return Err("invalid CommEffect filter root".into());
    }
    let mut filters = Vec::new();
    for node in root.children().filter(|node| node.is_element()) {
        if node.tag_name().name() != "filter" {
            return Err("unexpected CommEffect filter element".into());
        }
        let target_node = node
            .children()
            .find(|child| child.has_tag_name("target"))
            .ok_or("filter missing target")?;
        let effect_node = node
            .children()
            .find(|child| child.has_tag_name("effect"))
            .ok_or("filter missing effect")?;
        let ipv4 = target_node
            .children()
            .find(|child| child.has_tag_name("ipv4"))
            .map(|ipv4| {
                let mut protocols = Vec::new();
                for child in ipv4.children().filter(|child| child.is_element()) {
                    match child.tag_name().name() {
                        "udp" => protocols.push(ProtocolRule::Udp {
                            source: parse_optional(child, "sport")?,
                            destination: parse_optional(child, "dport")?,
                        }),
                        "protocol" => protocols.push(ProtocolRule::Number(
                            child
                                .attribute("type")
                                .unwrap_or("0")
                                .parse()
                                .map_err(|_| "invalid protocol type")?,
                        )),
                        _ => return Err("unexpected IPv4 rule".to_string()),
                    }
                }
                Ok(Ipv4Rule {
                    source: parse_ipv4(ipv4.attribute("src"))?,
                    destination: parse_ipv4(ipv4.attribute("dst"))?,
                    total_length: parse_optional(ipv4, "len")?,
                    tos: parse_optional(ipv4, "tos")?,
                    ttl: parse_optional(ipv4, "ttl")?,
                    protocols,
                })
            })
            .transpose()?;
        let loss = text_value::<f32>(effect_node, "loss")?;
        let duplicate = text_value::<f32>(effect_node, "duplicate")?;
        if !loss.is_finite()
            || !(0.0..=100.0).contains(&loss)
            || !duplicate.is_finite()
            || !(0.0..=u16::MAX as f32).contains(&duplicate)
        {
            return Err("invalid effect probability".into());
        }
        filters.push(Filter {
            target: Target { ipv4 },
            effect: Effect {
                latency_microseconds: parse_duration(
                    effect_node
                        .children()
                        .find(|node| node.has_tag_name("latency")),
                )?,
                jitter_microseconds: parse_duration(
                    effect_node
                        .children()
                        .find(|node| node.has_tag_name("jitter")),
                )?,
                probability_loss: loss,
                probability_duplicate: duplicate,
                unicast_bit_rate_bps: text_value(effect_node, "unicastbitrate")?,
                broadcast_bit_rate_bps: text_value(effect_node, "broadcastbitrate")?,
            },
        });
    }
    if filters.is_empty() {
        return Err("CommEffect filter file contains no filters".into());
    }
    Ok(filters)
}

#[no_mangle]
pub extern "C" fn emane_plugin_create() -> *const PluginApi {
    static API: OnceLock<PluginApi> = OnceLock::new();
    API.get_or_init(|| PluginApi {
        abi_version: PLUGIN_ABI_VERSION,
        struct_size: std::mem::size_of::<PluginApi>(),
        name: c"commeffectshim".as_ptr(),
        plugin_type: 3,
        init,
        configure,
        start,
        post_start,
        stop,
        destroy,
        process_upstream: upstream,
        process_downstream: downstream,
        process_timed_event: timed,
        process_event: event,
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
    use std::ffi::c_char;

    #[derive(Default)]
    struct Harness {
        downstream_controls: Vec<(u32, Vec<u8>)>,
        upstream_payloads: Vec<Vec<u8>>,
        upstream_control_types: Vec<u32>,
        scheduled: Vec<(u32, Vec<u8>)>,
    }

    fn copy_controls(messages: *const FfiControlMessage, count: usize) -> Vec<(u32, Vec<u8>)> {
        if count == 0 {
            return Vec::new();
        }
        unsafe { std::slice::from_raw_parts(messages, count) }
            .iter()
            .map(|message| {
                let body = if message.payload.len == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(message.payload.data, message.payload.len) }
                        .to_vec()
                };
                (message.msg_type, body)
            })
            .collect()
    }

    extern "C" fn capture_downstream(
        context: *mut c_void,
        _: u16,
        _: *const FfiPacket,
        messages: *const FfiControlMessage,
        count: usize,
    ) {
        let harness = unsafe { &mut *(context as *mut Harness) };
        harness.downstream_controls = copy_controls(messages, count);
    }

    extern "C" fn capture_upstream(
        context: *mut c_void,
        _: u16,
        packet: *const FfiPacket,
        messages: *const FfiControlMessage,
        count: usize,
    ) {
        let harness = unsafe { &mut *(context as *mut Harness) };
        let packet = unsafe { &*packet };
        harness.upstream_payloads.push(
            unsafe { std::slice::from_raw_parts(packet.payload.data, packet.payload.len) }.to_vec(),
        );
        harness.upstream_control_types = copy_controls(messages, count)
            .into_iter()
            .map(|(kind, _)| kind)
            .collect();
    }

    extern "C" fn capture_control(_: *mut c_void, _: u16, _: *const FfiControlMessage, _: usize) {}

    extern "C" fn capture_schedule(
        context: *mut c_void,
        _: u16,
        _: u64,
        _: u32,
        event_id: u32,
        data: *const u8,
        data_len: usize,
    ) -> u64 {
        let harness = unsafe { &mut *(context as *mut Harness) };
        let body = if data_len == 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(data, data_len) }.to_vec()
        };
        harness.scheduled.push((event_id, body));
        harness.scheduled.len() as u64
    }

    extern "C" fn capture_cancel(_: *mut c_void, _: u16, _: u64) {}
    extern "C" fn capture_log(_: *mut c_void, _: u32, _: *const c_char) {}
    extern "C" fn capture_register(
        _: *mut c_void,
        _: *const c_char,
        _: *const c_char,
        _: bool,
    ) -> u64 {
        0
    }
    extern "C" fn capture_increment(_: *mut c_void, _: u64, _: u64) -> bool {
        false
    }
    extern "C" fn capture_register_double(
        _: *mut c_void,
        _: *const c_char,
        _: *const c_char,
        _: bool,
    ) -> u64 {
        0
    }
    extern "C" fn capture_set_double(_: *mut c_void, _: u64, _: f64) -> bool {
        false
    }
    extern "C" fn capture_register_table(
        _: *mut c_void,
        _: *const c_char,
        _: *const *const c_char,
        _: usize,
        _: *const c_char,
        _: bool,
    ) -> u64 {
        0
    }
    extern "C" fn capture_set_table_row(
        _: *mut c_void,
        _: u64,
        _: *const u64,
        _: usize,
        _: *const emane_plugin_api::FfiStatisticValue,
        _: usize,
    ) -> bool {
        false
    }
    extern "C" fn capture_neighbor_tx(_: *mut c_void, _: u16, _: u64, _: u64) {}
    extern "C" fn capture_neighbor_status(_: *mut c_void) {}
    extern "C" fn capture_neighbor_rx(
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
    extern "C" fn capture_queue(_: *mut c_void, _: u16, _: u32, _: u32, _: u32, _: u64) {}
    extern "C" fn capture_publish(_: *mut c_void, _: u64, _: u64, _: u64, _: u64) {}
    extern "C" fn capture_register_rf(_: *mut c_void, _: u16) -> u64 {
        1
    }
    extern "C" fn capture_configure_rf(_: *mut c_void, _: u64, _: bool, _: bool) -> bool {
        true
    }
    extern "C" fn capture_update_rf(
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
    extern "C" fn capture_publish_event(_: *mut c_void, _: u16, _: *const u8, _: usize) -> bool {
        true
    }
    extern "C" fn capture_register_descriptor(
        _: *mut c_void,
        _: i32,
        _: u32,
        _: *mut c_void,
        _: emane_plugin_api::FfiFileDescriptorCallback,
    ) -> u64 {
        0
    }
    extern "C" fn capture_unregister_descriptor(_: *mut c_void, _: u64) -> bool {
        false
    }
    extern "C" fn capture_table_generation(_: *mut c_void, _: u64) -> u64 {
        0
    }
    extern "C" fn capture_remove_table_row(
        _: *mut c_void,
        _: u64,
        _: *const u64,
        _: usize,
    ) -> bool {
        true
    }

    #[test]
    fn header_and_event_round_trip() {
        let event = CommEffectEvent {
            effects: vec![CommEffectMessage {
                nem_id: 7,
                latency_seconds: 0.25,
                jitter_seconds: 0.1,
                probability_loss: 2.0,
                probability_duplicate: 150.0,
                unicast_bit_rate_bps: 1000,
                broadcast_bit_rate_bps: 2000,
            }],
        };
        let decoded = CommEffectEvent::decode(event.encode_to_vec().as_slice()).unwrap();
        assert_eq!(
            Effect::from_message(&decoded.effects[0])
                .unwrap()
                .latency_microseconds,
            250_000
        );
        let header = CommEffectHeader {
            group_id: 4,
            sequence: 9,
            tx_time_microseconds: -2,
        };
        assert_eq!(CommEffectHeader::decode(&header.encode()), Some(header));
    }

    #[test]
    fn ipv4_udp_filter_matches_without_unaligned_reads() {
        let target = Target {
            ipv4: Some(Ipv4Rule {
                protocols: vec![ProtocolRule::Udp {
                    source: Some(10),
                    destination: Some(20),
                }],
                ..Default::default()
            }),
        };
        let mut frame = vec![0u8; 42];
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        frame[14] = 0x45;
        frame[23] = 17;
        frame[34..36].copy_from_slice(&10u16.to_be_bytes());
        frame[36..38].copy_from_slice(&20u16.to_be_bytes());
        assert!(target.matches(&frame));
    }

    #[test]
    fn loss_and_duplicate_contract_matches_legacy_behavior() {
        let mut rng = StdRng::seed_from_u64(1);
        assert_eq!(task_count(&mut rng, 100.0, 500.0), 0);
        assert_eq!(task_count(&mut rng, 0.0, 200.0), 3);
    }

    #[test]
    fn event_profile_schedules_delivery_and_strips_private_header() {
        let mut harness = Harness::default();
        let framework = FfiFrameworkService {
            framework_ctx: (&mut harness as *mut Harness).cast(),
            send_downstream_packet: capture_downstream,
            send_upstream_packet: capture_upstream,
            send_downstream_control: capture_control,
            send_upstream_control: capture_control,
            schedule_timed_event: capture_schedule,
            cancel_timed_event: capture_cancel,
            log: capture_log,
            register_counter: capture_register,
            register_counter32: capture_register,
            increment_counter: capture_increment,
            maximize_counter: capture_increment,
            register_double: capture_register_double,
            set_double: capture_set_double,
            register_average: capture_register_double,
            sample_average: capture_set_double,
            register_table: capture_register_table,
            set_table_row: capture_set_table_row,
            clear_table: capture_unregister_descriptor,
            remove_table_row: capture_remove_table_row,
            table_generation: capture_table_generation,
            update_neighbor_tx: capture_neighbor_tx,
            update_neighbor_rx: capture_neighbor_rx,
            update_neighbor_status: capture_neighbor_status,
            update_queue_metric: capture_queue,
            publish_r2ri: capture_publish,
            register_rf_signal_table: capture_register_rf,
            configure_rf_signal_table: capture_configure_rf,
            update_rf_signal_table: capture_update_rf,
            publish_event: capture_publish_event,
            register_file_descriptor: capture_register_descriptor,
            unregister_file_descriptor: capture_unregister_descriptor,
            query_spectrum_filter: emane_plugin_api::spectrum::unavailable_filter,
            query_spectrum: spectrum_unavailable,
        };
        let plugin = init(1, &framework);
        let request = FfiConfigRequest {
            data: std::ptr::null(),
            len: 0,
        };
        assert!(configure(
            plugin,
            (&request as *const FfiConfigRequest).cast()
        ));
        assert!(start(plugin));

        let payload = [1u8, 2, 3];
        let outgoing = FfiPacket {
            info: FfiPacketInfo {
                uuid: [0; 16],
                source: 1,
                destination: 2,
                priority: 0,
                creation_time_sec: 1,
                creation_time_usec: 2,
            },
            payload: FfiSlice {
                data: payload.as_ptr(),
                len: payload.len(),
            },
        };
        downstream(plugin, &outgoing, std::ptr::null(), 0);
        let header = harness
            .downstream_controls
            .iter()
            .find(|(kind, _)| *kind == CONTROL_COMM_EFFECT_HEADER)
            .unwrap()
            .1
            .clone();

        let profile = CommEffectEvent {
            effects: vec![CommEffectMessage {
                nem_id: 2,
                latency_seconds: 0.0,
                jitter_seconds: 0.0,
                probability_loss: 0.0,
                probability_duplicate: 0.0,
                unicast_bit_rate_bps: 0,
                broadcast_bit_rate_bps: 0,
            }],
        }
        .encode_to_vec();
        event(plugin, EVENT_COMM_EFFECT, profile.as_ptr(), profile.len());
        let header_control = FfiControlMessage {
            msg_type: CONTROL_COMM_EFFECT_HEADER,
            payload: FfiSlice {
                data: header.as_ptr(),
                len: header.len(),
            },
        };
        let incoming = FfiPacket {
            info: FfiPacketInfo {
                source: 2,
                destination: 1,
                ..outgoing.info
            },
            ..outgoing
        };
        upstream(plugin, &incoming, &header_control, 1);
        assert_eq!(harness.scheduled.len(), 1);
        let (event_id, pending) = harness.scheduled.pop().unwrap();
        timed(plugin, 1, event_id, pending.as_ptr(), pending.len());
        assert_eq!(harness.upstream_payloads, vec![payload.to_vec()]);
        assert!(!harness
            .upstream_control_types
            .contains(&CONTROL_COMM_EFFECT_HEADER));
        let state = unsafe { &*(plugin as *const CommEffectShim) };
        assert_eq!(state.unicast_accept.get(&1).unwrap().tx_bytes, 3);
        assert_eq!(state.unicast_accept.get(&2).unwrap().rx_bytes, 3);

        upstream(plugin, &incoming, std::ptr::null(), 0);
        let state = unsafe { &*(plugin as *const CommEffectShim) };
        assert_eq!(
            state.unicast_drop.get(&2).unwrap().bytes[PacketDropReason::RegistrationId as usize],
            3
        );
        destroy(plugin);
    }
}
