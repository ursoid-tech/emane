use emane_plugin_api::{
    FfiConfigItem, FfiConfigRequest, FfiControlMessage, FfiFrameworkService, FfiPacket, FfiSlice,
    PluginApi, TimingAnalysisHeader, CONTROL_TIMING_ANALYSIS_HEADER, PLUGIN_ABI_VERSION,
};
use prost::Message;
use std::collections::VecDeque;
use std::ffi::{c_void, CStr};
use std::fs::File;
use std::io::Write;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

// Wire schema: rust/protos/shimheader.proto.
#[derive(Clone, PartialEq, Message)]
struct WireHeader {
    #[prost(uint64, required, tag = "1")]
    tx_time_microseconds: u64,
    #[prost(uint32, required, tag = "2")]
    source: u32,
    #[prost(uint32, required, tag = "3")]
    packet_id: u32,
}

fn frame(header: TimingAnalysisHeader, payload: &[u8]) -> Vec<u8> {
    let body = WireHeader {
        tx_time_microseconds: header.tx_time_microseconds,
        source: u32::from(header.source),
        packet_id: u32::from(header.packet_id),
    }
    .encode_to_vec();
    let mut bytes = Vec::with_capacity(2 + body.len() + payload.len());
    bytes.extend_from_slice(&(body.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&body);
    bytes.extend_from_slice(payload);
    bytes
}

fn unframe(bytes: &[u8]) -> Option<(TimingAnalysisHeader, &[u8])> {
    let len = usize::from(u16::from_be_bytes(bytes.get(..2)?.try_into().ok()?));
    let header = WireHeader::decode(bytes.get(2..2 + len)?).ok()?;
    Some((
        TimingAnalysisHeader {
            tx_time_microseconds: header.tx_time_microseconds,
            source: header.source.try_into().ok()?,
            packet_id: header.packet_id.try_into().ok()?,
        },
        &bytes[2 + len..],
    ))
}

#[derive(Clone, Copy)]
struct Entry {
    source: u16,
    packet_id: u16,
    tx_microseconds: u64,
    rx_microseconds: u64,
}

struct TimingAnalysis {
    id: u16,
    framework: FfiFrameworkService,
    max_queue_size: u32,
    packet_id: u16,
    entries: VecDeque<Entry>,
}

fn now_microseconds() -> u64 {
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

extern "C" fn init(id: u16, framework: *const FfiFrameworkService) -> *mut c_void {
    let Some(framework) = (unsafe { framework.as_ref() }) else {
        return std::ptr::null_mut();
    };
    let framework = *framework;
    Box::into_raw(Box::new(TimingAnalysis {
        id,
        framework,
        max_queue_size: 0,
        packet_id: 0,
        entries: VecDeque::new(),
    }))
    .cast()
}

extern "C" fn configure(plugin: *mut c_void, request: *const c_void) -> bool {
    let Some(state) = (unsafe { (plugin as *mut TimingAnalysis).as_mut() }) else {
        return false;
    };
    let Some(request) = (unsafe { (request as *const FfiConfigRequest).as_ref() }) else {
        return false;
    };
    if request.len > 1 || (request.len != 0 && request.data.is_null()) {
        return false;
    }
    if request.len == 0 {
        return true;
    }
    let item: &FfiConfigItem = unsafe { &*request.data };
    if item.name.is_null() || item.values.len != 1 || item.values.data.is_null() {
        return false;
    }
    let name = unsafe { CStr::from_ptr(item.name) }.to_bytes();
    let value = unsafe { *item.values.data };
    if name != b"maxqueuesize" || value.is_null() {
        return false;
    }
    let Ok(value) = unsafe { CStr::from_ptr(value) }.to_str() else {
        return false;
    };
    let Ok(value) = value.parse() else {
        return false;
    };
    state.max_queue_size = value;
    true
}

extern "C" fn start(plugin: *mut c_void) -> bool {
    !plugin.is_null()
}
extern "C" fn post_start(_: *mut c_void) {}

extern "C" fn stop(plugin: *mut c_void) {
    let Some(state) = (unsafe { (plugin as *mut TimingAnalysis).as_mut() }) else {
        return;
    };
    if state.entries.is_empty() {
        return;
    }
    let path = format!("/tmp/timinganalysis{}.txt", state.id);
    let Ok(mut output) = File::create(path) else {
        return;
    };
    while let Some(entry) = state.entries.pop_front() {
        let _ = writeln!(
            output,
            "{} {} {:.6} {:.6}",
            entry.source,
            entry.packet_id,
            entry.tx_microseconds as f64 / 1_000_000.0,
            entry.rx_microseconds as f64 / 1_000_000.0
        );
    }
}

extern "C" fn destroy(plugin: *mut c_void) {
    if !plugin.is_null() {
        unsafe { drop(Box::from_raw(plugin as *mut TimingAnalysis)) };
    }
}

extern "C" fn upstream(
    plugin: *mut c_void,
    packet: *const FfiPacket,
    messages: *const FfiControlMessage,
    count: usize,
) {
    let Some(state) = (unsafe { (plugin as *mut TimingAnalysis).as_mut() }) else {
        return;
    };
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
    let packet_ref = unsafe { &*packet };
    if packet_ref.payload.data.is_null() {
        return;
    }
    let bytes =
        unsafe { std::slice::from_raw_parts(packet_ref.payload.data, packet_ref.payload.len) };
    let Some((header, payload)) = unframe(bytes) else {
        return;
    };
    {
        if state.max_queue_size != 0 && state.entries.len() >= state.max_queue_size as usize {
            state.entries.pop_front();
        }
        state.entries.push_back(Entry {
            source: header.source,
            packet_id: header.packet_id,
            tx_microseconds: header.tx_time_microseconds,
            rx_microseconds: now_microseconds(),
        });
    }
    let outgoing: Vec<_> = incoming
        .iter()
        .copied()
        .filter(|message| message.msg_type != CONTROL_TIMING_ANALYSIS_HEADER)
        .collect();
    let packet = FfiPacket {
        info: packet_ref.info,
        payload: FfiSlice {
            data: payload.as_ptr(),
            len: payload.len(),
        },
    };
    (state.framework.send_upstream_packet)(
        state.framework.framework_ctx,
        state.id,
        &packet,
        outgoing.as_ptr(),
        outgoing.len(),
    );
}

extern "C" fn downstream(
    plugin: *mut c_void,
    packet: *const FfiPacket,
    messages: *const FfiControlMessage,
    count: usize,
) {
    let Some(state) = (unsafe { (plugin as *mut TimingAnalysis).as_mut() }) else {
        return;
    };
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
    let header = TimingAnalysisHeader {
        tx_time_microseconds: now_microseconds(),
        source: state.id,
        packet_id: state.packet_id,
    };
    state.packet_id = state.packet_id.wrapping_add(1);
    let packet_ref = unsafe { &*packet };
    if packet_ref.payload.len != 0 && packet_ref.payload.data.is_null() {
        return;
    }
    let payload = if packet_ref.payload.len == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(packet_ref.payload.data, packet_ref.payload.len) }
    };
    let bytes = frame(header, payload);
    let packet = FfiPacket {
        info: packet_ref.info,
        payload: FfiSlice {
            data: bytes.as_ptr(),
            len: bytes.len(),
        },
    };
    (state.framework.send_downstream_packet)(
        state.framework.framework_ctx,
        state.id,
        &packet,
        incoming.as_ptr(),
        incoming.len(),
    );
}

extern "C" fn timed(_: *mut c_void, _: u64, _: u32, _: *const u8, _: usize) {}
extern "C" fn event(_: *mut c_void, _: u16, _: *const u8, _: usize) {}

#[no_mangle]
pub extern "C" fn emane_plugin_create() -> *const PluginApi {
    static API: OnceLock<PluginApi> = OnceLock::new();
    API.get_or_init(|| PluginApi {
        abi_version: PLUGIN_ABI_VERSION,
        struct_size: std::mem::size_of::<PluginApi>(),
        name: c"timinganalysisshim".as_ptr(),
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
    use super::*;

    #[test]
    fn timing_header_round_trips() {
        let header = TimingAnalysisHeader {
            tx_time_microseconds: 99,
            source: 2,
            packet_id: 7,
        };
        let bytes = frame(header, b"abc");
        // Original shimheader.proto: fields 1, 2, 3 as varints after a u16 length.
        assert_eq!(bytes, [0, 6, 8, 99, 16, 2, 24, 7, b'a', b'b', b'c']);
        assert_eq!(unframe(&bytes), Some((header, &b"abc"[..])));
    }
}
