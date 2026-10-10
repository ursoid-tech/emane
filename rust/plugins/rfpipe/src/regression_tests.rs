extern "C" fn spectrum_unavailable(
    _: *mut c_void,
    _: *const emane_plugin_api::FfiSpectrumQuery,
    _: *mut emane_plugin_api::FfiSpectrumResult,
) -> bool {
    false
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

static TEST_LOCK: Mutex<()> = Mutex::new(());
static WHEN: Mutex<u64> = Mutex::new(0);
static QUERIES: Mutex<u32> = Mutex::new(0);
static COMPLETED_NOISE: Mutex<Option<f64>> = Mutex::new(None);
extern "C" fn schedule_capture(
    _: *mut c_void,
    _: u16,
    sec: u64,
    usec: u32,
    _: u32,
    _: *const u8,
    _: usize,
) -> u64 {
    *WHEN.lock().unwrap() = sec * 1_000_000 + u64::from(usec);
    1
}
extern "C" fn query_capture(
    _: *mut c_void,
    _: *const emane_plugin_api::FfiSpectrumQuery,
    result: *mut emane_plugin_api::FfiSpectrumResult,
) -> bool {
    *QUERIES.lock().unwrap() += 1;
    if let Some(noise) = *COMPLETED_NOISE.lock().unwrap() {
        unsafe {
            *result = emane_plugin_api::FfiSpectrumResult {
                receiver_sensitivity_dbm: -110.0,
                noise_floor_dbm: noise,
                signal_in_noise: false,
            };
        }
        true
    } else {
        false
    }
}
fn receive() -> (RfpipeMac, i64) {
    *WHEN.lock().unwrap() = 0;
    *QUERIES.lock().unwrap() = 0;
    *COMPLETED_NOISE.lock().unwrap() = None;
    let mut fw = framework(false);
    fw.schedule_timed_event = schedule_capture;
    fw.query_spectrum = query_capture;
    let mac = RfpipeMac::new(2, fw);
    let tx = now_microseconds();
    let rx = RxProperties {
        frequency_hz: 2_347_000_000,
        bandwidth_hz: 1_000_000,
        rx_power_dbm: -50.0,
        noise_floor_dbm: -100.0,
        tx_time_microseconds: tx,
        propagation_microseconds: 200_000,
        duration_microseconds: 100_000,
        antenna_index: 0,
        sub_id: 1,
        signal_in_noise: false,
    }
    .encode();
    let mh = ModelHeader {
        registration_id: MAC_REGISTRATION_RFPIPE,
        sequence: 1,
        data_rate_bps: 1_000_000,
        category: 0,
        message_type: 0,
        flags: 0,
    }
    .encode();
    let hdr = RfPipeMacHeader {
        data_rate_bps: 1_000_000,
    }
    .encode_to_vec();
    let mut bytes = (hdr.len() as u16).to_be_bytes().to_vec();
    bytes.extend(hdr);
    bytes.extend([42; 100]);
    let packet = FfiPacket {
        info: FfiPacketInfo {
            uuid: [1; 16],
            source: 1,
            destination: 2,
            priority: 0,
            creation_time_sec: 0,
            creation_time_usec: 0,
        },
        payload: FfiSlice {
            data: bytes.as_ptr(),
            len: bytes.len(),
        },
    };
    let msgs = [
        FfiControlMessage {
            msg_type: CONTROL_MODEL_HEADER,
            payload: FfiSlice {
                data: mh.as_ptr(),
                len: mh.len(),
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
    process_upstream(
        &mac as *const _ as *mut c_void,
        &packet,
        msgs.as_ptr(),
        msgs.len(),
    );
    (mac, tx + 300_000)
}
#[test]
fn propagation_delays_completion() {
    let _guard = TEST_LOCK.lock().unwrap();
    let (_mac, eor) = receive();
    let when = *WHEN.lock().unwrap();
    println!(
        "Rust scheduled receive {} us before modeled EOR",
        eor - when as i64
    );
    assert!(
        when >= eor as u64,
        "C++ schedules at tx + propagation + duration"
    );
}
#[test]
fn completion_queries_spectrum() {
    let _guard = TEST_LOCK.lock().unwrap();
    let (mac, _) = receive();
    let id = 1u64.to_be_bytes();
    process_timed_event(
        &mac as *const _ as *mut c_void,
        1,
        EVENT_RECEIVE,
        id.as_ptr(),
        id.len(),
    );
    assert_eq!(
        *QUERIES.lock().unwrap(),
        1,
        "C++ queries the completed spectrum window"
    );
}

#[test]
fn interference_after_ingress_changes_reception() {
    let _guard = TEST_LOCK.lock().unwrap();
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rfpipe-pcr.xml");
    for (noise, expected_packets) in [(-100.0, 1), (-40.0, 0)] {
        UPSTREAM_CAPTURE.lock().unwrap().clear();
        let (mac, _) = receive();
        mac.state.lock().unwrap().pcr_curve = Some(PcrCurve::load(path.to_str().unwrap()).unwrap());
        // Both packets arrived with -100 dBm cached noise. Only the spectrum
        // window at completion knows whether interference arrived afterwards.
        *COMPLETED_NOISE.lock().unwrap() = Some(noise);
        let id = 1u64.to_be_bytes();
        process_timed_event(
            &mac as *const _ as *mut c_void,
            1,
            EVENT_RECEIVE,
            id.as_ptr(),
            id.len(),
        );
        assert_eq!(UPSTREAM_CAPTURE.lock().unwrap().len(), expected_packets);
    }
}
static QUEUE_SAMPLES: Mutex<Vec<u64>> = Mutex::new(Vec::new());
extern "C" fn sample_queue(_: *mut c_void, _: u16, _: u32, _: u32, _: u32, delay: u64) {
    QUEUE_SAMPLES.lock().unwrap().push(delay);
}
#[test]
fn dequeue_samples_delay() {
    let _guard = TEST_LOCK.lock().unwrap();
    QUEUE_SAMPLES.lock().unwrap().clear();
    let mut fw = framework(false);
    fw.update_queue_metric = sample_queue;
    let mac = RfpipeMac::new(1, fw);
    let now = now_microseconds();
    {
        let mut state = mac.state.lock().unwrap();
        state.started = true;
        state.queue.push_back(PendingTx {
            packet: OwnedPacket {
                info: FfiPacketInfo {
                    uuid: [1; 16],
                    source: 1,
                    destination: 2,
                    priority: 0,
                    creation_time_sec: 0,
                    creation_time_usec: 0,
                },
                payload: vec![1; 100],
                controls: vec![],
            },
            acquired_at: now - 20_000,
            ready_at: now,
            duration: 1000,
            data_rate: 1_000_000,
        });
    }
    drive_transmit(&mac, now);
    let samples = QUEUE_SAMPLES.lock().unwrap().clone();
    assert_eq!(samples, vec![20_000]);
    assert_eq!(
        samples.len(),
        1,
        "C++ samples queue metrics on dequeue; Rust samples {:?}",
        samples
    );
}
