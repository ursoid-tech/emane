use emane_core::nem_manager::resolve_plugin_path;
use emane_core::plugin_interface::{
    FfiConfigItem, FfiConfigRequest, FfiConfigStringArray, FfiControlMessage, FfiFrameworkService,
    FfiPacket, FfiStatisticValue, PluginApi, PluginEntryFunc, PLUGIN_ABI_VERSION,
};
use libloading::{Library, Symbol};
use std::ffi::{c_void, CStr, CString};

extern "C" fn packet(
    _: *mut c_void,
    _: u16,
    _: *const FfiPacket,
    _: *const FfiControlMessage,
    _: usize,
) {
}
extern "C" fn control(_: *mut c_void, _: u16, _: *const FfiControlMessage, _: usize) {}
extern "C" fn schedule(
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
extern "C" fn cancel(_: *mut c_void, _: u16, _: u64) {}
extern "C" fn log(_: *mut c_void, _: u32, _: *const std::os::raw::c_char) {}
extern "C" fn register_counter(
    _: *mut c_void,
    _: *const std::os::raw::c_char,
    _: *const std::os::raw::c_char,
    _: bool,
) -> u64 {
    0
}
extern "C" fn increment_counter(_: *mut c_void, _: u64, _: u64) -> bool {
    false
}
extern "C" fn register_double(
    _: *mut c_void,
    _: *const std::os::raw::c_char,
    _: *const std::os::raw::c_char,
    _: bool,
) -> u64 {
    0
}
extern "C" fn set_double(_: *mut c_void, _: u64, _: f64) -> bool {
    false
}
extern "C" fn register_table(
    _: *mut c_void,
    _: *const std::os::raw::c_char,
    _: *const *const std::os::raw::c_char,
    _: usize,
    _: *const std::os::raw::c_char,
    _: bool,
) -> u64 {
    0
}
extern "C" fn set_table_row(
    _: *mut c_void,
    _: u64,
    _: *const u64,
    _: usize,
    _: *const FfiStatisticValue,
    _: usize,
) -> bool {
    false
}
extern "C" fn neighbor_tx(_: *mut c_void, _: u16, _: u64, _: u64) {}
extern "C" fn neighbor_status(_: *mut c_void) {}
extern "C" fn neighbor_rx(
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
extern "C" fn queue(_: *mut c_void, _: u16, _: u32, _: u32, _: u32, _: u64) {}
extern "C" fn publish(_: *mut c_void, _: u64, _: u64, _: u64, _: u64) {}
extern "C" fn register_rf(_: *mut c_void, _: u16) -> u64 {
    1
}
extern "C" fn configure_rf(_: *mut c_void, _: u64, _: bool, _: bool) -> bool {
    true
}
extern "C" fn update_rf(
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
extern "C" fn publish_event(_: *mut c_void, _: u16, _: *const u8, _: usize) -> bool {
    true
}
extern "C" fn register_descriptor(
    _: *mut c_void,
    _: i32,
    _: u32,
    _: *mut c_void,
    _: emane_core::plugin_interface::FfiFileDescriptorCallback,
) -> u64 {
    0
}
extern "C" fn unregister_descriptor(_: *mut c_void, _: u64) -> bool {
    false
}
extern "C" fn remove_table_row(_: *mut c_void, _: u64, _: *const u64, _: usize) -> bool {
    false
}
extern "C" fn table_generation_noop(_: *mut c_void, _: u64) -> u64 {
    0
}

fn main() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let plugin = args
        .first()
        .cloned()
        .unwrap_or_else(|| "dummy-mac".to_string());
    let path = resolve_plugin_path(&plugin)?;
    let library = unsafe { Library::new(&path) }
        .map_err(|error| format!("failed to load {}: {error}", path.display()))?;
    let create: Symbol<PluginEntryFunc> = unsafe { library.get(b"emane_plugin_create") }
        .map_err(|error| format!("missing plugin entry point: {error}"))?;
    let api_ptr = create();
    let Some(api) = (unsafe { api_ptr.as_ref() }) else {
        return Err("plugin returned null API".to_string());
    };
    if api.abi_version != PLUGIN_ABI_VERSION || api.struct_size != std::mem::size_of::<PluginApi>()
    {
        return Err("plugin ABI mismatch".to_string());
    }
    let framework = FfiFrameworkService {
        framework_ctx: std::ptr::null_mut(),
        send_downstream_packet: packet,
        send_upstream_packet: packet,
        send_downstream_control: control,
        send_upstream_control: control,
        schedule_timed_event: schedule,
        cancel_timed_event: cancel,
        log,
        register_counter,
        register_counter32: register_counter,
        increment_counter,
        maximize_counter: increment_counter,
        register_double,
        set_double,
        register_average: register_double,
        sample_average: set_double,
        register_table,
        set_table_row,
        clear_table: unregister_descriptor,
        remove_table_row,
        table_generation: table_generation_noop,
        update_neighbor_tx: neighbor_tx,
        update_neighbor_rx: neighbor_rx,
        update_neighbor_status: neighbor_status,
        register_queue_metric: {
            extern "C" fn register(_: *mut c_void, _: u16, _: u32) -> bool {
                true
            }
            register
        },
        update_queue_metric: queue,
        publish_r2ri: publish,
        register_rf_signal_table: register_rf,
        configure_rf_signal_table: configure_rf,
        update_rf_signal_table: update_rf,
        publish_event,
        register_file_descriptor: register_descriptor,
        unregister_file_descriptor: unregister_descriptor,
        query_spectrum_filter: emane_plugin_api::spectrum::unavailable_filter,
        query_spectrum: spectrum_unavailable,
    };
    let instance = (api.init)(42, &framework);
    if instance.is_null() {
        return Err("plugin failed to initialize".to_string());
    }
    let config: Vec<_> = args
        .iter()
        .skip(1)
        .map(|argument| {
            let (name, value) = argument
                .split_once('=')
                .ok_or_else(|| format!("invalid configuration argument: {argument}"))?;
            Ok((
                CString::new(name).map_err(|_| "configuration name contains NUL")?,
                CString::new(value).map_err(|_| "configuration value contains NUL")?,
            ))
        })
        .collect::<Result<_, String>>()?;
    let value_pointers: Vec<_> = config
        .iter()
        .map(|(_, value)| vec![value.as_ptr()])
        .collect();
    let items: Vec<_> = config
        .iter()
        .zip(&value_pointers)
        .map(|((name, _), values)| FfiConfigItem {
            name: name.as_ptr(),
            values: FfiConfigStringArray {
                data: values.as_ptr(),
                len: values.len(),
            },
        })
        .collect();
    let request = FfiConfigRequest {
        data: items.as_ptr(),
        len: items.len(),
    };
    if !(api.configure)(
        instance,
        &request as *const FfiConfigRequest as *const c_void,
    ) {
        (api.destroy)(instance);
        return Err("plugin rejected its configuration".to_string());
    }
    if !(api.start)(instance) {
        (api.destroy)(instance);
        return Err("plugin failed to start".to_string());
    }
    (api.post_start)(instance);
    (api.stop)(instance);
    (api.destroy)(instance);
    let name = if api.name.is_null() {
        "<unnamed>".into()
    } else {
        unsafe { CStr::from_ptr(api.name) }.to_string_lossy()
    };
    println!("loaded {name} from {}", path.display());
    Ok(())
}

#[allow(dead_code)]
extern "C" fn spectrum_unavailable(
    _: *mut c_void,
    _: *const emane_plugin_api::FfiSpectrumQuery,
    _: *mut emane_plugin_api::FfiSpectrumResult,
) -> bool {
    false
}
