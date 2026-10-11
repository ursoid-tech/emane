use super::*;
use emane_plugin_api::FfiSpectrumResult;

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
extern "C" fn remove_table_row_callback(_: *mut c_void, _: u64, _: *const u64, _: usize) -> bool {
    true
}

fn test_mac() -> TdmaMac {
    TdmaMac::new(
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
            register_queue_metric: {
                extern "C" fn register(_: *mut c_void, _: u16, _: u32) -> bool {
                    true
                }
                register
            },
            update_queue_metric: queue_callback,
            publish_r2ri: publish_callback,
            register_rf_signal_table: register_rf_callback,
            configure_rf_signal_table: configure_rf_callback,
            update_rf_signal_table: update_rf_callback,
            publish_event: publish_event_callback,
            register_file_descriptor: register_descriptor_callback,
            unregister_file_descriptor: unregister_descriptor_callback,
            query_spectrum_filter: emane_plugin_api::spectrum::unavailable_filter,
            query_spectrum: capture_spectrum,
        },
    )
}

#[derive(Default)]
struct Capture {
    timers: Vec<(u64, u32, Vec<u8>)>,
    upstream: Vec<OwnedPacket>,
    queries: Vec<FfiSpectrumQuery>,
    noise: Option<f64>,
}
fn capture(ctx: *mut c_void) -> &'static Mutex<Capture> {
    unsafe { &*(ctx as *const Mutex<Capture>) }
}
extern "C" fn capture_upstream(
    ctx: *mut c_void,
    _: u16,
    packet: *const FfiPacket,
    _: *const FfiControlMessage,
    _: usize,
) {
    if let Some(packet) = own_packet(packet) {
        capture(ctx).lock().unwrap().upstream.push(packet);
    }
}
extern "C" fn capture_schedule(
    ctx: *mut c_void,
    _: u16,
    sec: u64,
    usec: u32,
    event: u32,
    data: *const u8,
    len: usize,
) -> u64 {
    let data = unsafe { std::slice::from_raw_parts(data, len) }.to_vec();
    let mut capture = capture(ctx).lock().unwrap();
    capture
        .timers
        .push((sec * 1_000_000 + u64::from(usec), event, data));
    capture.timers.len() as u64
}
extern "C" fn capture_spectrum(
    ctx: *mut c_void,
    query: *const FfiSpectrumQuery,
    result: *mut FfiSpectrumResult,
) -> bool {
    let mut capture = capture(ctx).lock().unwrap();
    capture.queries.push(unsafe { *query });
    if let Some(noise) = capture.noise {
        unsafe {
            *result = FfiSpectrumResult {
                receiver_sensitivity_dbm: -100.0,
                noise_floor_dbm: noise,
                signal_in_noise: false,
            };
        }
        true
    } else {
        false
    }
}
fn mac(capture: &Mutex<Capture>) -> TdmaMac {
    let mut mac = test_mac();
    mac.framework.framework_ctx = capture as *const _ as *mut c_void;
    mac.framework.schedule_timed_event = capture_schedule;
    mac.framework.send_upstream_packet = capture_upstream;
    mac.state.get_mut().unwrap().started = true;
    mac
}
fn info(source: u16) -> FfiPacketInfo {
    FfiPacketInfo {
        uuid: [0; 16],
        source,
        destination: 1,
        priority: 0,
        creation_time_sec: 0,
        creation_time_usec: 0,
    }
}
fn schedule(duration: u64, overhead: u64, tx: bool) -> Schedule {
    Schedule {
        slots_per_frame: 1,
        frames_per_multiframe: 1,
        slot_duration_us: duration,
        overhead_us: overhead,
        bandwidth_hz: 1_000_000,
        slots: vec![if tx {
            Slot::Tx {
                frequency_hz: 1_000_000,
                data_rate_bps: 1_000_000,
                service_class: 0,
                power_dbm: 0.0,
                destination: 0,
            }
        } else {
            Slot::Rx {
                frequency_hz: 1_000_000,
            }
        }],
    }
}
#[test]
fn small_slots_use_component_capacity_and_airtime() {
    let capture = Mutex::new(Capture::default());
    let mac = mac(&capture);
    let mut state = mac.state.lock().unwrap();
    state.schedule = Some(schedule(1_000, 100, true));
    for len in [100, 20] {
        state.queues[0].push_back(QueuedPacket {
            packet: OwnedPacket {
                info: info(1),
                payload: vec![0; len],
            },
            sequence: 1,
            offset: 0,
            fragment_index: 0,
        });
    }
    let first = take_transmission(&mac, &mut state, 0, 0).unwrap();
    assert_eq!(first.bytes.len(), 100);
    // Original float-seconds conversion truncates 100 bytes at 1 Mbps to 799 us.
    assert_eq!(tx_properties(&first, 100, 1_000).duration_microseconds, 799);
    let second = take_transmission(&mac, &mut state, 0, 100).unwrap();
    assert_eq!(second.bytes.len(), 12);
    assert!(second.more);
    assert_eq!(tx_properties(&first, 112, 1_000).duration_microseconds, 896);
    assert!(take_transmission(&mac, &mut state, 0, 112).is_none());
    assert_eq!(state.queues[0][0].offset, 12);
    // Preserve the C++ end-of-slot guard when overhead is zero.
    assert_eq!(tx_properties(&first, 125, 1_000).duration_microseconds, 999);
}
fn receive(mac: &mut TdmaMac, source: u16, offset: u64, fragment: Option<TdmaFragment>) -> u64 {
    let (slot, tx_time) = {
        let state = mac.state.lock().unwrap();
        let schedule = state.schedule.as_ref().unwrap();
        let slot = schedule.absolute_slot(now_us());
        (slot, schedule.slot_start(slot) + offset as i64)
    };
    let body = TdmaBaseModelMessage {
        absolute_slot_index: slot,
        data_rate_bps: 1_000_000,
        messages: vec![TdmaMessage {
            message_type: TdmaMessageType::Data as i32,
            destination: 1,
            priority: 0,
            data: vec![source as u8; 10],
            fragment,
        }],
    }
    .encode_to_vec();
    let mut payload = (body.len() as u16).to_be_bytes().to_vec();
    payload.extend(body);
    let packet = FfiPacket {
        info: info(source),
        payload: FfiSlice {
            data: payload.as_ptr(),
            len: payload.len(),
        },
    };
    let model = ModelHeader {
        registration_id: MAC_REGISTRATION_TDMA,
        sequence: u64::from(source),
        data_rate_bps: 1_000_000,
        category: 0,
        message_type: 1,
        flags: 0,
    }
    .encode();
    let rx = RxProperties {
        frequency_hz: 1_000_000,
        bandwidth_hz: 1_000_000,
        rx_power_dbm: -50.0,
        noise_floor_dbm: -100.0,
        tx_time_microseconds: tx_time,
        duration_microseconds: 100,
        propagation_microseconds: 0,
        antenna_index: 0,
        sub_id: 7,
        signal_in_noise: false,
    }
    .encode();
    let controls: Vec<_> = [
        (CONTROL_MODEL_HEADER, model.as_slice()),
        (CONTROL_RX_PROPERTIES, rx.as_slice()),
    ]
    .into_iter()
    .map(|(msg_type, data)| FfiControlMessage {
        msg_type,
        payload: FfiSlice {
            data: data.as_ptr(),
            len: data.len(),
        },
    })
    .collect();
    upstream(
        mac as *mut _ as *mut c_void,
        &packet,
        controls.as_ptr(),
        controls.len(),
    );
    slot
}
#[test]
fn rx_locks_until_slot_end_and_selects_earliest_sor() {
    let capture = Mutex::new(Capture {
        noise: Some(-100.0),
        ..Default::default()
    });
    let mut mac = mac(&capture);
    mac.state.lock().unwrap().schedule = Some(schedule(60_000_000, 100, false));
    let slot = receive(&mut mac, 2, 1_000, None);
    assert_eq!(receive(&mut mac, 3, 100, None), slot);
    assert_eq!(receive(&mut mac, 4, 2_000, None), slot);
    assert!(capture.lock().unwrap().upstream.is_empty());
    assert!(capture.lock().unwrap().queries.is_empty());
    assert_eq!(capture.lock().unwrap().timers.len(), 1);
    assert_eq!(capture.lock().unwrap().timers[0].0, (slot + 1) * 60_000_000);
    assert_eq!(mac.state.lock().unwrap().pending_rx[&slot].info.source, 3);
    complete_receive(&mac, slot);
    complete_receive(&mac, slot); // Duplicate timer is inert.
    assert_eq!(capture.lock().unwrap().upstream.len(), 1);
    assert_eq!(capture.lock().unwrap().upstream[0].info.source, 3);
    assert_eq!(capture.lock().unwrap().queries.len(), 1);
}
#[test]
fn incomplete_fragments_hold_the_slot_lock() {
    let capture = Mutex::new(Capture {
        noise: Some(-100.0),
        ..Default::default()
    });
    let mut mac = mac(&capture);
    mac.state.lock().unwrap().schedule = Some(schedule(60_000_000, 100, false));
    let slot = receive(
        &mut mac,
        2,
        100,
        Some(TdmaFragment {
            more: true,
            index: 0,
            offset: 0,
            sequence: 10,
        }),
    );
    receive(&mut mac, 3, 200, None);
    assert!(mac.state.lock().unwrap().reassembly.is_empty());
    complete_receive(&mac, slot);
    assert!(capture.lock().unwrap().upstream.is_empty());
    assert_eq!(mac.state.lock().unwrap().reassembly.len(), 1);
}
#[test]
fn slot_end_pcr_uses_late_interference_and_failed_candidates_stay_locked() {
    let capture = Mutex::new(Capture {
        noise: Some(-100.0),
        ..Default::default()
    });
    let mut mac = mac(&capture);
    let path =
        std::env::temp_dir().join(format!("emane-tdma-regression-{}.xml", std::process::id()));
    std::fs::write(&path,r#"<tdmabasemodel-pcr packetsize="0"><datarate bps="1M"><entry sinr="20" por="0"/><entry sinr="30" por="100"/></datarate></tdmabasemodel-pcr>"#).unwrap();
    mac.state.lock().unwrap().pcr = Some(PcrManager::load(path.to_str().unwrap()).unwrap());
    std::fs::remove_file(path).unwrap();
    mac.state.lock().unwrap().schedule = Some(schedule(60_000_000, 100, false));
    let slot = receive(&mut mac, 2, 100, None);
    receive(&mut mac, 3, 200, None);
    capture.lock().unwrap().noise = Some(-60.0);
    complete_receive(&mac, slot);
    assert_eq!(capture.lock().unwrap().queries.len(), 1);
    assert!(capture.lock().unwrap().upstream.is_empty());
    // An unavailable spectrum window must also fail closed.
    let slot = receive(&mut mac, 2, 100, None);
    capture.lock().unwrap().noise = None;
    complete_receive(&mac, slot);
    assert!(capture.lock().unwrap().upstream.is_empty());
}

// Appended to the existing private test fixture in an isolated plugin copy.
#[test]
fn duplicate_fragments_do_not_extend_reassembly_lifetime() {
    let capture = Mutex::new(Capture {
        noise: Some(-100.0),
        ..Default::default()
    });
    let mut mac = mac(&capture);
    mac.state.lock().unwrap().schedule = Some(schedule(60_000_000, 100, false));
    let slot = receive(
        &mut mac,
        2,
        100,
        Some(TdmaFragment {
            more: true,
            index: 0,
            offset: 0,
            sequence: 10,
        }),
    );
    let duplicate = {
        let state = mac.state.lock().unwrap();
        let p = &state.pending_rx[&slot];
        PendingReception {
            info: p.info,
            wire: p.wire.clone(),
            model_sequence: p.model_sequence,
            packet_len: p.packet_len,
            spectrum_query: p.spectrum_query,
        }
    };
    complete_receive(&mac, slot);
    let previous = now_us() - 4_000_000;
    {
        let mut state = mac.state.lock().unwrap();
        state
            .reassembly
            .get_mut(&(2, 0, 10))
            .unwrap()
            .last_update_us = previous;
        state.pending_rx.insert(slot + 1, duplicate);
    }
    complete_receive(&mac, slot + 1);
    let mut state = mac.state.lock().unwrap();
    let refreshed = state.reassembly[&(2, 0, 10)].last_update_us > previous;
    expire_reassembly(&mac, &mut state, previous + 6_000_001);
    assert!(!refreshed);
    assert!(state.reassembly.is_empty());
}

fn finish_component(mac: &mut TdmaMac, message: TdmaMessage, creation_usec: u32) {
    let slot = receive(mac, 2, 100, None);
    {
        let mut state = mac.state.lock().unwrap();
        let pending = state.pending_rx.get_mut(&slot).unwrap();
        pending.wire.messages = vec![message];
        pending.info.creation_time_usec = creation_usec;
    }
    complete_receive(mac, slot);
}

fn fragment_component(index: u32, offset: u32, more: bool, data: &[u8]) -> TdmaMessage {
    TdmaMessage {
        message_type: TdmaMessageType::Data as i32,
        destination: 1,
        priority: 0,
        data: data.to_vec(),
        fragment: Some(TdmaFragment {
            index,
            offset,
            more,
            sequence: 123,
        }),
    }
}

#[test]
fn reassembly_counts_indices_orders_offsets_and_uses_completion_metadata() {
    let capture = Mutex::new(Capture {
        noise: Some(-100.0),
        ..Default::default()
    });
    let mut mac = mac(&capture);
    mac.state.lock().unwrap().schedule = Some(schedule(60_000_000, 100, false));
    finish_component(&mut mac, fragment_component(0, u32::MAX, true, b"A"), 1);
    finish_component(&mut mac, fragment_component(0, 2, true, b"duplicate"), 2);
    assert!(capture.lock().unwrap().upstream.is_empty());
    let mut tail = fragment_component(1, 1, false, b"B");
    tail.destination = u32::from(BROADCAST_NEM);
    finish_component(&mut mac, tail, 3);
    let capture = capture.lock().unwrap();
    assert_eq!(capture.upstream.len(), 1);
    assert_eq!(capture.upstream[0].payload, b"BA");
    assert_eq!(capture.upstream[0].info.destination, BROADCAST_NEM);
    assert_eq!(capture.upstream[0].info.creation_time_usec, 3);
}

#[test]
fn zero_offset_terminal_is_whole_and_wire_identifiers_are_narrowed() {
    let capture = Mutex::new(Capture {
        noise: Some(-100.0),
        ..Default::default()
    });
    let mut mac = mac(&capture);
    mac.state.lock().unwrap().schedule = Some(schedule(60_000_000, 100, false));
    let mut message = fragment_component(17, 0, false, b"whole");
    message.destination = 65_537;
    message.priority = 300;
    finish_component(&mut mac, message, 4);
    let capture = capture.lock().unwrap();
    assert_eq!(capture.upstream.len(), 1);
    assert_eq!(capture.upstream[0].payload, b"whole");
    assert_eq!(capture.upstream[0].info.destination, 1);
    assert_eq!(capture.upstream[0].info.priority, 44);
    assert!(mac.state.lock().unwrap().reassembly.is_empty());
}

#[test]
fn expiry_requires_both_check_and_fragment_deadlines_inclusively() {
    let capture = Mutex::new(Capture {
        noise: Some(-100.0),
        ..Default::default()
    });
    let mut mac = mac(&capture);
    mac.state.lock().unwrap().schedule = Some(schedule(60_000_000, 100, false));
    finish_component(&mut mac, fragment_component(0, 0, true, b"pending"), 1);
    let mut state = mac.state.lock().unwrap();
    state.fragment_check_us = 2_000_000;
    state.fragment_timeout_us = 1_000_000;
    state.last_fragment_check_us = 100;
    state
        .reassembly
        .get_mut(&(2, 0, 123))
        .unwrap()
        .last_update_us = 100;
    expire_reassembly(&mac, &mut state, 2_000_099);
    assert_eq!(state.reassembly.len(), 1);
    expire_reassembly(&mac, &mut state, 2_000_100);
    assert!(state.reassembly.is_empty());
}

#[test]
fn expired_but_unchecked_assembly_can_complete_before_cleanup() {
    let capture = Mutex::new(Capture {
        noise: Some(-100.0),
        ..Default::default()
    });
    let mut mac = mac(&capture);
    mac.state.lock().unwrap().schedule = Some(schedule(60_000_000, 100, false));
    finish_component(&mut mac, fragment_component(0, 0, true, b"late"), 1);
    {
        let mut state = mac.state.lock().unwrap();
        state.fragment_check_us = 0;
        state
            .reassembly
            .get_mut(&(2, 0, 123))
            .unwrap()
            .last_update_us = now_us() - 10_000_000;
    }
    finish_component(&mut mac, fragment_component(1, 4, false, b"-tail"), 2);
    assert_eq!(capture.lock().unwrap().upstream[0].payload, b"late-tail");
    assert!(mac.state.lock().unwrap().reassembly.is_empty());
}

#[test]
fn schedule_replacement_and_rejection_preserve_fragment_state() {
    let capture = Mutex::new(Capture {
        noise: Some(-100.0),
        ..Default::default()
    });
    let mut mac = mac(&capture);
    mac.state.lock().unwrap().schedule = Some(schedule(60_000_000, 100, false));
    finish_component(&mut mac, fragment_component(0, 0, true, b"head"), 1);
    let full = ScheduleEvent {
        structure: Some(ScheduleStructure {
            slots_per_frame: 2,
            frames_per_multiframe: 1,
            slot_duration_microseconds: 60_000_000,
            slot_overhead_microseconds: 100,
            bandwidth_hz: 1_000_000,
        }),
        frames: vec![ScheduleFrame {
            index: 0,
            ..Default::default()
        }],
        frequency_hz: Some(1_000_000),
        ..Default::default()
    }
    .encode_to_vec();
    process_event(
        &mut mac as *mut _ as *mut c_void,
        EVENT_TDMA_SCHEDULE,
        full.as_ptr(),
        full.len(),
    );
    assert_eq!(mac.state.lock().unwrap().reassembly.len(), 1);
    let invalid = ScheduleEvent {
        frames: vec![ScheduleFrame {
            index: 9,
            slots: vec![ScheduleSlot {
                index: 0,
                slot_type: SlotType::Rx as i32,
                rx: Some(ScheduleRx {
                    frequency_hz: Some(1_000_000),
                }),
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    }
    .encode_to_vec();
    process_event(
        &mut mac as *mut _ as *mut c_void,
        EVENT_TDMA_SCHEDULE,
        invalid.as_ptr(),
        invalid.len(),
    );
    let state = mac.state.lock().unwrap();
    assert!(state.schedule.is_none());
    assert!(state.schedule_frequencies.is_empty());
    assert_eq!(state.reassembly.len(), 1);
}

#[test]
fn startup_announcements_wait_for_post_start() {
    extern "C" fn control(
        ctx: *mut c_void,
        _: u16,
        messages: *const FfiControlMessage,
        count: usize,
    ) {
        let counts = unsafe { &*(ctx as *const Mutex<[usize; 2]>) };
        for message in unsafe { std::slice::from_raw_parts(messages, count) } {
            if message.msg_type == CONTROL_FLOW_CONTROL_TOKEN {
                counts.lock().unwrap()[0] += 1;
            }
        }
    }
    extern "C" fn timer(
        ctx: *mut c_void,
        _: u16,
        _: u64,
        _: u32,
        _: u32,
        _: *const u8,
        _: usize,
    ) -> u64 {
        let counts = unsafe { &*(ctx as *const Mutex<[usize; 2]>) };
        let mut counts = counts.lock().unwrap();
        counts[1] += 1;
        counts[1] as u64
    }
    let counts = Mutex::new([0usize; 2]);
    let mut mac = test_mac();
    mac.framework.framework_ctx = &counts as *const _ as *mut c_void;
    mac.framework.send_upstream_control = control;
    mac.framework.schedule_timed_event = timer;
    {
        let mut state = mac.state.lock().unwrap();
        state.pcr_uri = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../validation/guide-samples/tdma-pcr.xml"
        )
        .into();
        state.flow_control_enable = true;
        state.flow_control_tokens = 3;
    }
    let plugin = &mut mac as *mut _ as *mut c_void;
    // Original models announce grants and arm recurring timers in postStart.
    assert!(start(plugin));
    assert_eq!(*counts.lock().unwrap(), [0, 0]);
    post_start(plugin);
    assert_eq!(*counts.lock().unwrap(), [1, 1]);
    stop(plugin);
}
