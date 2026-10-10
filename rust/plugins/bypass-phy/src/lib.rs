use emane_plugin_api::{
    CommonLayerCounters, FfiConfigRequest, FfiControlMessage, FfiFrameworkService, FfiPacket,
    FfiSlice, PluginApi, CONTROL_BYPASS_PHY, PLUGIN_ABI_VERSION,
};
use std::ffi::c_void;
use std::sync::OnceLock;
use std::time::Instant;

fn elapsed_microseconds(begin: Instant) -> u64 {
    begin.elapsed().as_micros().min(u128::from(u64::MAX)) as u64
}

struct BypassPhy {
    id: u16,
    framework: FfiFrameworkService,
    counters: CommonLayerCounters,
}

extern "C" fn init(id: u16, framework: *const FfiFrameworkService) -> *mut c_void {
    let Some(framework) = (unsafe { framework.as_ref() }) else {
        return std::ptr::null_mut();
    };
    let framework = *framework;
    Box::into_raw(Box::new(BypassPhy {
        id,
        framework,
        counters: CommonLayerCounters::register(framework),
    }))
    .cast()
}

extern "C" fn configure(_: *mut c_void, request: *const c_void) -> bool {
    let Some(request) = (unsafe { (request as *const FfiConfigRequest).as_ref() }) else {
        return false;
    };
    request.len == 0
}

extern "C" fn start(plugin: *mut c_void) -> bool {
    !plugin.is_null()
}

extern "C" fn lifecycle(_: *mut c_void) {}

extern "C" fn destroy(plugin: *mut c_void) {
    if !plugin.is_null() {
        unsafe { drop(Box::from_raw(plugin as *mut BypassPhy)) };
    }
}

extern "C" fn upstream(
    plugin: *mut c_void,
    packet: *const FfiPacket,
    messages: *const FfiControlMessage,
    count: usize,
) {
    let Some(phy) = (unsafe { (plugin as *mut BypassPhy).as_ref() }) else {
        return;
    };
    let begin = Instant::now();
    if packet.is_null() {
        (phy.framework.send_upstream_control)(phy.framework.framework_ctx, phy.id, messages, count);
    } else {
        let packet_ref = unsafe { &*packet };
        phy.counters.upstream_rx_packet(
            phy.framework,
            packet_ref.info.source,
            packet_ref.info.destination,
            packet_ref.payload.len,
        );
        phy.counters.upstream_tx_packet(
            phy.framework,
            packet_ref.info.source,
            packet_ref.info.destination,
            packet_ref.payload.len,
            elapsed_microseconds(begin),
        );
        (phy.framework.send_upstream_packet)(
            phy.framework.framework_ctx,
            phy.id,
            packet,
            messages,
            count,
        );
    }
}

extern "C" fn downstream(
    plugin: *mut c_void,
    packet: *const FfiPacket,
    messages: *const FfiControlMessage,
    count: usize,
) {
    let Some(phy) = (unsafe { (plugin as *mut BypassPhy).as_ref() }) else {
        return;
    };
    let begin = Instant::now();
    if packet.is_null() {
        (phy.framework.send_downstream_control)(
            phy.framework.framework_ctx,
            phy.id,
            messages,
            count,
        );
    } else {
        let packet_ref = unsafe { &*packet };
        phy.counters.downstream_rx_packet(
            phy.framework,
            packet_ref.info.source,
            packet_ref.info.destination,
            packet_ref.payload.len,
        );
        phy.counters.downstream_tx_packet(
            phy.framework,
            packet_ref.info.source,
            packet_ref.info.destination,
            packet_ref.payload.len,
            elapsed_microseconds(begin),
            false,
        );
        if count != 0 && messages.is_null() {
            return;
        }
        let mut controls = if count == 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(messages, count) }.to_vec()
        };
        controls.push(FfiControlMessage {
            msg_type: CONTROL_BYPASS_PHY,
            payload: FfiSlice {
                data: std::ptr::null(),
                len: 0,
            },
        });
        (phy.framework.send_downstream_packet)(
            phy.framework.framework_ctx,
            phy.id,
            packet,
            controls.as_ptr(),
            controls.len(),
        );
    }
}

extern "C" fn timed(_: *mut c_void, _: u64, _: u32, _: *const u8, _: usize) {}
extern "C" fn event(_: *mut c_void, _: u16, _: *const u8, _: usize) {}

#[no_mangle]
pub extern "C" fn emane_plugin_create() -> *const PluginApi {
    static API: OnceLock<PluginApi> = OnceLock::new();
    API.get_or_init(|| PluginApi {
        abi_version: PLUGIN_ABI_VERSION,
        struct_size: std::mem::size_of::<PluginApi>(),
        name: c"bypassphylayer".as_ptr(),
        plugin_type: 2,
        init,
        configure,
        start,
        post_start: lifecycle,
        stop: lifecycle,
        destroy,
        process_upstream: upstream,
        process_downstream: downstream,
        process_timed_event: timed,
        process_event: event,
    })
}
