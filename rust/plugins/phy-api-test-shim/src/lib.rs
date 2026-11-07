use emane_plugin_api::{
    FfiConfigItem, FfiConfigRequest, FfiControlMessage, FfiFrameworkService, FfiPacket,
    FfiPacketInfo, FfiSlice, PluginApi, TxAntennaProfile, TxFrequencySegment, TxFrequencySegments,
    TxProperties, TxTransmitter, TxTransmitters, CONTROL_TX_ANTENNA_PROFILE,
    CONTROL_TX_FREQUENCY_SEGMENTS, CONTROL_TX_PROPERTIES, CONTROL_TX_TRANSMITTERS,
    PLUGIN_ABI_VERSION,
};
use std::ffi::{c_void, CStr};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

const TIMER_TRANSMIT: u32 = 1;
const BROADCAST_NEM: u16 = u16::MAX;

#[derive(Clone, Copy, Default)]
struct FrequencySegment {
    frequency_hz: u64,
    duration_microseconds: u64,
    offset_microseconds: u64,
}

struct PhyApiTest {
    id: u16,
    framework: FfiFrameworkService,
    packet_size: u16,
    interval_microseconds: u64,
    destination: u16,
    bandwidth_hz: u64,
    frequencies: Vec<FrequencySegment>,
    transmitters: Vec<TxTransmitter>,
    antenna_profile: Option<TxAntennaProfile>,
    tx_power_dbm: f64,
    timer_id: u64,
    bandwidth_configured: bool,
}

fn now_microseconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros()
        .min(u128::from(u64::MAX)) as u64
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
            if item.name.is_null()
                || item.values.len > 255
                || (item.values.len != 0 && item.values.data.is_null())
            {
                return None;
            }
            let name = CStr::from_ptr(item.name).to_str().ok()?.to_string();
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

fn parse_scaled_u64(value: &str) -> Option<u64> {
    let value = value.trim();
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

fn seconds_to_microseconds(value: &str) -> Option<u64> {
    let seconds = value.parse::<f64>().ok()?;
    let microseconds = seconds * 1_000_000.0;
    (seconds.is_finite() && seconds >= 0.0 && microseconds <= u64::MAX as f64)
        .then_some(microseconds.round() as u64)
}

fn parse_frequency(value: &str) -> Option<FrequencySegment> {
    let mut fields = value.split(':');
    let result = FrequencySegment {
        frequency_hz: parse_scaled_u64(fields.next()?)?,
        duration_microseconds: seconds_to_microseconds(fields.next()?)?,
        offset_microseconds: seconds_to_microseconds(fields.next()?)?,
    };
    fields.next().is_none().then_some(result)
}

extern "C" fn init(id: u16, framework: *const FfiFrameworkService) -> *mut c_void {
    let Some(framework) = (unsafe { framework.as_ref() }) else {
        return std::ptr::null_mut();
    };
    let framework = *framework;
    Box::into_raw(Box::new(PhyApiTest {
        id,
        framework,
        packet_size: 128,
        interval_microseconds: 1_000_000,
        destination: BROADCAST_NEM,
        bandwidth_hz: 0,
        frequencies: Vec::new(),
        transmitters: Vec::new(),
        antenna_profile: None,
        tx_power_dbm: 0.0,
        timer_id: 0,
        bandwidth_configured: false,
    }))
    .cast()
}

extern "C" fn configure(plugin: *mut c_void, request: *const c_void) -> bool {
    let Some(state) = (unsafe { (plugin as *mut PhyApiTest).as_mut() }) else {
        return false;
    };
    let Some(items) = (unsafe { config_items(request) }) else {
        return false;
    };
    for (name, values) in items {
        match name.as_str() {
            "packetsize" if values.len() == 1 => {
                let Ok(value) = values[0].parse::<u16>() else {
                    return false;
                };
                if value == 0 {
                    return false;
                }
                state.packet_size = value;
            }
            "packetrate" if values.len() == 1 => {
                let Ok(value) = values[0].parse::<f64>() else {
                    return false;
                };
                if !value.is_finite() || value < 0.0 {
                    return false;
                }
                state.interval_microseconds = if value == 0.0 {
                    0
                } else {
                    let interval = 1_000_000.0 / value;
                    if interval > u64::MAX as f64 {
                        return false;
                    }
                    interval.max(1.0).round() as u64
                };
            }
            "destination" if values.len() == 1 => {
                let Ok(value) = values[0].parse() else {
                    return false;
                };
                state.destination = value;
            }
            "bandwidth" if values.len() == 1 => {
                let Some(value) = parse_scaled_u64(&values[0]) else {
                    return false;
                };
                if value == 0 {
                    return false;
                }
                state.bandwidth_hz = value;
                state.bandwidth_configured = true;
            }
            "frequency" if values.len() <= 255 => {
                state.frequencies.clear();
                for value in values {
                    let Some(segment) = parse_frequency(&value) else {
                        return false;
                    };
                    state.frequencies.push(segment);
                }
            }
            "txpower" if values.len() == 1 => {
                let Ok(value) = values[0].parse::<f64>() else {
                    return false;
                };
                if !value.is_finite() {
                    return false;
                }
                state.tx_power_dbm = value;
            }
            "transmitter" if values.len() <= 255 => {
                state.transmitters.clear();
                for value in values {
                    let mut fields = value.split(':');
                    let (Some(nem_id), Some(tx_power_dbm), None) =
                        (fields.next(), fields.next(), fields.next())
                    else {
                        return false;
                    };
                    let (Ok(nem_id), Ok(tx_power_dbm)) =
                        (nem_id.parse::<u16>(), tx_power_dbm.parse::<f64>())
                    else {
                        return false;
                    };
                    if nem_id == 0 || !tx_power_dbm.is_finite() {
                        return false;
                    }
                    state.transmitters.push(TxTransmitter {
                        nem_id,
                        tx_power_dbm,
                    });
                }
            }
            "antennaprofileid" if values.len() == 1 => {
                let Ok(profile_id) = values[0].parse::<u16>() else {
                    return false;
                };
                if profile_id == 0 {
                    return false;
                }
                state
                    .antenna_profile
                    .get_or_insert(TxAntennaProfile {
                        profile_id,
                        azimuth_degrees: 0.0,
                        elevation_degrees: 0.0,
                    })
                    .profile_id = profile_id;
            }
            "antennaazimuth" if values.len() == 1 => {
                let Ok(azimuth_degrees) = values[0].parse::<f64>() else {
                    return false;
                };
                if !azimuth_degrees.is_finite() || !(0.0..=360.0).contains(&azimuth_degrees) {
                    return false;
                }
                state
                    .antenna_profile
                    .get_or_insert(TxAntennaProfile {
                        profile_id: 0,
                        azimuth_degrees,
                        elevation_degrees: 0.0,
                    })
                    .azimuth_degrees = azimuth_degrees;
            }
            "antennaelevation" if values.len() == 1 => {
                let Ok(elevation_degrees) = values[0].parse::<f64>() else {
                    return false;
                };
                if !elevation_degrees.is_finite() || !(-90.0..=90.0).contains(&elevation_degrees) {
                    return false;
                }
                state
                    .antenna_profile
                    .get_or_insert(TxAntennaProfile {
                        profile_id: 0,
                        azimuth_degrees: 0.0,
                        elevation_degrees,
                    })
                    .elevation_degrees = elevation_degrees;
            }
            _ => return false,
        }
    }
    true
}

extern "C" fn start(plugin: *mut c_void) -> bool {
    unsafe { (plugin as *const PhyApiTest).as_ref() }
        .is_some_and(|state| state.bandwidth_configured)
}

fn schedule_next(state: &mut PhyApiTest) {
    if state.interval_microseconds == 0 {
        return;
    }
    state.timer_id = (state.framework.schedule_timed_event)(
        state.framework.framework_ctx,
        state.id,
        state.interval_microseconds / 1_000_000,
        (state.interval_microseconds % 1_000_000) as u32,
        TIMER_TRANSMIT,
        std::ptr::null(),
        0,
    );
}

extern "C" fn post_start(plugin: *mut c_void) {
    if let Some(state) = unsafe { (plugin as *mut PhyApiTest).as_mut() } {
        schedule_next(state);
    }
}

extern "C" fn stop(plugin: *mut c_void) {
    let Some(state) = (unsafe { (plugin as *mut PhyApiTest).as_mut() }) else {
        return;
    };
    if state.timer_id != 0 {
        (state.framework.cancel_timed_event)(
            state.framework.framework_ctx,
            state.id,
            state.timer_id,
        );
        state.timer_id = 0;
    }
}

extern "C" fn destroy(plugin: *mut c_void) {
    if !plugin.is_null() {
        unsafe { drop(Box::from_raw(plugin as *mut PhyApiTest)) };
    }
}

extern "C" fn upstream(_: *mut c_void, _: *const FfiPacket, _: *const FfiControlMessage, _: usize) {
}
extern "C" fn downstream(
    _: *mut c_void,
    _: *const FfiPacket,
    _: *const FfiControlMessage,
    _: usize,
) {
}

extern "C" fn timed(plugin: *mut c_void, _: u64, event_id: u32, _: *const u8, _: usize) {
    let Some(state) = (unsafe { (plugin as *mut PhyApiTest).as_mut() }) else {
        return;
    };
    if event_id != TIMER_TRANSMIT {
        return;
    }
    let mut payload = vec![0u8; usize::from(state.packet_size)];
    payload[0] = 0xbe;
    let now = now_microseconds();
    let packet = FfiPacket {
        info: FfiPacketInfo {
            uuid: [0; 16],
            source: state.id,
            destination: state.destination,
            priority: 0,
            creation_time_sec: now / 1_000_000,
            creation_time_usec: (now % 1_000_000) as u32,
        },
        payload: FfiSlice {
            data: payload.as_ptr(),
            len: payload.len(),
        },
    };
    let first_segment = state.frequencies.first().copied().unwrap_or_default();
    let properties = TxProperties {
        frequency_hz: first_segment.frequency_hz,
        bandwidth_hz: state.bandwidth_hz,
        tx_power_dbm: state.tx_power_dbm,
        duration_microseconds: first_segment.duration_microseconds,
        offset_microseconds: first_segment.offset_microseconds,
        tx_time_microseconds: now as i64,
        antenna_index: 0,
        spectral_mask_index: 0,
        sub_id: 0,
    }
    .encode();
    let mut controls = vec![FfiControlMessage {
        msg_type: CONTROL_TX_PROPERTIES,
        payload: FfiSlice {
            data: properties.as_ptr(),
            len: properties.len(),
        },
    }];
    let segment_bytes = (state.frequencies.len() > 1)
        .then(|| TxFrequencySegments {
            segments: state
                .frequencies
                .iter()
                .map(|segment| TxFrequencySegment {
                    frequency_hz: segment.frequency_hz,
                    duration_microseconds: segment.duration_microseconds,
                    offset_microseconds: segment.offset_microseconds,
                })
                .collect(),
        })
        .and_then(|segments| segments.encode());
    if let Some(bytes) = &segment_bytes {
        controls.push(FfiControlMessage {
            msg_type: CONTROL_TX_FREQUENCY_SEGMENTS,
            payload: FfiSlice {
                data: bytes.as_ptr(),
                len: bytes.len(),
            },
        });
    }
    let transmitter_bytes = (!state.transmitters.is_empty())
        .then(|| TxTransmitters {
            transmitters: state.transmitters.clone(),
        })
        .and_then(|transmitters| transmitters.encode());
    if let Some(bytes) = &transmitter_bytes {
        controls.push(FfiControlMessage {
            msg_type: CONTROL_TX_TRANSMITTERS,
            payload: FfiSlice {
                data: bytes.as_ptr(),
                len: bytes.len(),
            },
        });
    }
    let antenna_bytes = state.antenna_profile.and_then(TxAntennaProfile::encode);
    if let Some(bytes) = &antenna_bytes {
        controls.push(FfiControlMessage {
            msg_type: CONTROL_TX_ANTENNA_PROFILE,
            payload: FfiSlice {
                data: bytes.as_ptr(),
                len: bytes.len(),
            },
        });
    }
    (state.framework.send_downstream_packet)(
        state.framework.framework_ctx,
        state.id,
        &packet,
        controls.as_ptr(),
        controls.len(),
    );
    schedule_next(state);
}

extern "C" fn event(_: *mut c_void, _: u16, _: *const u8, _: usize) {}

#[no_mangle]
pub extern "C" fn emane_plugin_create() -> *const PluginApi {
    static API: OnceLock<PluginApi> = OnceLock::new();
    API.get_or_init(|| PluginApi {
        abi_version: PLUGIN_ABI_VERSION,
        struct_size: std::mem::size_of::<PluginApi>(),
        name: c"phyapitestshim".as_ptr(),
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
    fn parses_scaled_frequency_segments() {
        let segment = parse_frequency("2.4G:0.001:0.00025").unwrap();
        assert_eq!(segment.frequency_hz, 2_400_000_000);
        assert_eq!(segment.duration_microseconds, 1_000);
        assert_eq!(segment.offset_microseconds, 250);
        assert_eq!(parse_frequency("0:1:0").unwrap().frequency_hz, 0);
    }
}
