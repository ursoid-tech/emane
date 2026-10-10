use super::*;
use emane_plugin_api::{FfiSpectrumResult, RxFrequencySegment};

#[derive(Default)]
struct Capture {
    downstream: Vec<OwnedPacket>,
    upstream: Vec<OwnedPacket>,
    timers: Vec<(u64, u32, Vec<u8>)>,
    queries: Vec<FfiSpectrumQuery>,
    noise: Option<f64>,
    signal_in_noise: bool,
    queue_metrics: Vec<(u32, u32, u64)>,
}

fn capture(ctx: *mut c_void) -> &'static Mutex<Capture> {
    unsafe { &*(ctx as *const Mutex<Capture>) }
}
extern "C" fn capture_downstream(
    ctx: *mut c_void,
    _: u16,
    packet: *const FfiPacket,
    messages: *const FfiControlMessage,
    len: usize,
) {
    if let Some(packet) = own_packet(packet, messages, len) {
        capture(ctx).lock().unwrap().downstream.push(packet);
    }
}
extern "C" fn capture_upstream(
    ctx: *mut c_void,
    _: u16,
    packet: *const FfiPacket,
    messages: *const FfiControlMessage,
    len: usize,
) {
    if let Some(packet) = own_packet(packet, messages, len) {
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
    let bytes = unsafe { std::slice::from_raw_parts(data, len) }.to_vec();
    let mut capture = capture(ctx).lock().unwrap();
    capture
        .timers
        .push((sec * 1_000_000 + u64::from(usec), event, bytes));
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
                signal_in_noise: capture.signal_in_noise,
            };
        }
        true
    } else {
        false
    }
}
extern "C" fn capture_queue(
    ctx: *mut c_void,
    _: u16,
    _: u32,
    depth: u32,
    discards: u32,
    delay: u64,
) {
    capture(ctx)
        .lock()
        .unwrap()
        .queue_metrics
        .push((depth, discards, delay));
}
fn mac(capture: &Mutex<Capture>) -> Ieee80211Mac {
    let mut mac = super::tests::test_mac();
    mac.framework.framework_ctx = capture as *const _ as *mut c_void;
    mac.framework.send_downstream_packet = capture_downstream;
    mac.framework.send_upstream_packet = capture_upstream;
    mac.framework.schedule_timed_event = capture_schedule;
    mac.framework.query_spectrum = capture_spectrum;
    mac.framework.update_queue_metric = capture_queue;
    let state = mac.state.get_mut().unwrap();
    state.started = true;
    state.mode = 1;
    state.unicast_rate_index = 12;
    state.multicast_rate_index = 12;
    let mut pcr = PCRManager::new();
    pcr.load(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/ieee80211abg-pcr.xml"
    ))
    .unwrap();
    state.pcr = Some(pcr);
    mac
}
fn packet_info(source: u16, destination: u16) -> FfiPacketInfo {
    FfiPacketInfo {
        uuid: [0; 16],
        source,
        destination,
        priority: 0,
        creation_time_sec: 0,
        creation_time_usec: 0,
    }
}
fn receive(mac: &mut Ieee80211Mac, sequence: u32, rts: bool) -> u64 {
    let header = IeeeMacHeader {
        message_type: if rts {
            IeeeWireMessageType::UnicastRtsCtsData as i32
        } else {
            IeeeWireMessageType::UnicastData as i32
        },
        num_retries: 0,
        data_rate_index: 12,
        sequence_number: sequence,
        source: 2,
        destination: 1,
        duration_microseconds: 2_000,
    }
    .encode_to_vec();
    let mut payload = (header.len() as u16).to_be_bytes().to_vec();
    payload.extend(header);
    payload.extend([42; 100]);
    let packet = FfiPacket {
        info: packet_info(2, 1),
        payload: FfiSlice {
            data: payload.as_ptr(),
            len: payload.len(),
        },
    };
    let model = ModelHeader {
        registration_id: MAC_REGISTRATION_IEEE80211ABG,
        sequence: u64::from(sequence),
        data_rate_bps: 54_000_000,
        category: 0,
        message_type: 2,
        flags: 0,
    }
    .encode();
    let rx = RxProperties {
        frequency_hz: 2_400_000_000,
        bandwidth_hz: 20_000_000,
        rx_power_dbm: -50.0,
        noise_floor_dbm: -100.0,
        tx_time_microseconds: now_us(),
        propagation_microseconds: 100,
        duration_microseconds: 2_000,
        antenna_index: 0,
        sub_id: 7,
        signal_in_noise: false,
    }
    .encode();
    let segments = RxFrequencySegments {
        segments: vec![RxFrequencySegment {
            frequency_hz: 2_400_000_000,
            rx_power_dbm: -50.0,
            duration_microseconds: 2_000,
            offset_microseconds: 50,
        }],
    }
    .encode()
    .unwrap();
    let controls: Vec<_> = [
        (CONTROL_MODEL_HEADER, model.as_slice()),
        (CONTROL_RX_PROPERTIES, rx.as_slice()),
        (CONTROL_RX_FREQUENCY_SEGMENTS, segments.as_slice()),
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
    process_upstream(
        mac as *mut _ as *mut c_void,
        &packet,
        controls.as_ptr(),
        controls.len(),
    );
    let id = mac.state.lock().unwrap().next_rx_id;
    let pending = &mac.state.lock().unwrap().pending_rx[&id];
    let rx = RxProperties::decode(&rx).unwrap();
    assert_eq!(
        pending.spectrum_query.start_time_microseconds,
        rx.tx_time_microseconds + 150
    );
    id
}

#[test]
fn reception_uses_completed_noise_and_preserves_cts_duration() {
    let capture = Mutex::new(Capture {
        noise: Some(-100.0),
        ..Default::default()
    });
    let mut mac = mac(&capture);
    let id = receive(&mut mac, 1, true);
    assert!(capture.lock().unwrap().queries.is_empty());
    complete_receive(&mac, id);
    let recorded = capture.lock().unwrap();
    assert_eq!(recorded.upstream.len(), 1);
    assert_eq!(recorded.downstream.len(), 1);
    let bytes = &recorded.downstream[0].payload;
    let len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
    let header = IeeeMacHeader::decode(&bytes[2..2 + len]).unwrap();
    assert_eq!(header.duration_microseconds, 2_000);
    assert_eq!(
        header.message_type,
        IeeeWireMessageType::UnicastCtsCtrl as i32
    );
    drop(recorded);
    let id = receive(&mut mac, 2, false);
    // A jammer starts after ingress, before the EOR callback.
    capture.lock().unwrap().noise = Some(-60.0);
    complete_receive(&mac, id);
    assert_eq!(capture.lock().unwrap().upstream.len(), 1);
    assert_eq!(capture.lock().unwrap().queries.len(), 2);
}

#[test]
fn invalid_spectrum_windows_and_noise_all_are_dropped() {
    let capture = Mutex::new(Capture::default());
    let mut mac = mac(&capture);
    let id = receive(&mut mac, 1, true);
    complete_receive(&mac, id);
    assert!(capture.lock().unwrap().upstream.is_empty());
    assert!(capture.lock().unwrap().downstream.is_empty());
    capture.lock().unwrap().noise = Some(-100.0);
    capture.lock().unwrap().signal_in_noise = true;
    let id = receive(&mut mac, 2, true);
    complete_receive(&mac, id);
    assert!(capture.lock().unwrap().upstream.is_empty());
    assert!(capture.lock().unwrap().downstream.is_empty());
}

#[test]
fn collision_power_is_sampled_by_utilization_not_packet_count() {
    let capture = Mutex::new(Capture::default());
    let mac = mac(&capture);
    let mut state = mac.state.lock().unwrap();
    state.neighbor_lists.insert(
        9,
        NeighborList {
            last_update: 0,
            neighbors: [2, 3, 1].into_iter().collect(),
        },
    );
    for (source, power, utilization, packets) in [
        (1, 1e9, 100_000, 1),
        (2, 1.0, 100, 10),
        (3, 0.001, 300, 1),
        (4, 0.01, 100, 1),
    ] {
        state.channel_activity.insert(
            source,
            NeighborActivity {
                previous_rx_power_milliwatts: power * packets as f64,
                previous_packets: packets,
                previous_utilization_microseconds: utilization,
                ..Default::default()
            },
        );
    }
    let mut strong = 0;
    for _ in 0..10_000 {
        match collision_noise_power(&mut state, 9, true) {
            1.0 => strong += 1,
            0.001 => (),
            power => panic!("unexpected sampled power: {power}"),
        }
        assert_eq!(collision_noise_power(&mut state, 9, false), 0.01);
    }
    assert!((2_300..=2_700).contains(&strong), "{strong}");
}

fn pending(acquired_at: i64) -> PendingTx {
    PendingTx {
        packet: OwnedPacket {
            info: packet_info(1, 2),
            payload: vec![0; 100],
            controls: Vec::new(),
        },
        category: 0,
        acquired_at,
        txop_microseconds: 0,
        ready_at: 0,
        post_delay_microseconds: 0,
        collision: false,
        retries: 0,
        max_retries: 2,
        rts_cts: false,
        sequence: None,
        phase: TxPhase::Idle,
    }
}
#[test]
fn pre_delay_matches_legacy_conditional_overhead_subtraction() {
    let capture = Mutex::new(Capture::default());
    let mac = mac(&capture);
    let mut state = mac.state.lock().unwrap();
    state.max_distance_meters = 0;
    state.estimated_one_hop_neighbors = 10.0;
    state.total_one_hop_utilization_microseconds = 100_000;
    state.channel_activity_interval_microseconds = 100_000;
    state.random_state = LegacyRandom::seeded(11);
    // A fixed draw selects one node; cover below, equal and above overhead (1152us).
    let seed = state.random_state.clone();
    assert_eq!((f64::from(random_unit(&mut state)) * 10.0).floor(), 1.0);
    for average in [10, 1152, 2000] {
        state.random_state = seed.clone();
        state.average_message_duration_microseconds = average;
        let expected = if average > 1152 {
            average - 1152
        } else {
            average
        } + 34;
        assert_eq!(
            calculate_tx_delay(&mut state, &pending(0), 0).0,
            expected as i64
        );
    }
}

#[test]
fn queue_samples_transmission_delay_and_clears_discard_interval() {
    let capture = Mutex::new(Capture::default());
    let mac = mac(&capture);
    mac.state.lock().unwrap().queue_discards[0] = 3;
    let header = ModelHeader {
        registration_id: MAC_REGISTRATION_IEEE80211ABG,
        sequence: 1,
        data_rate_bps: 54_000_000,
        category: 0,
        message_type: MSG_TYPE_UNICAST_DATA,
        flags: encode_flags(12, 2),
    };
    send_downstream(&mac, &pending(now_us() - 10_000), header, 2, 100);
    send_downstream(&mac, &pending(now_us() - 20_000), header, 2, 100);
    let recorded = capture.lock().unwrap();
    assert_eq!(recorded.queue_metrics.len(), 2);
    assert_eq!(recorded.queue_metrics[0].1, 3);
    assert_eq!(recorded.queue_metrics[1].1, 0);
    assert!(recorded.queue_metrics[0].2 >= 10_000);
    assert!(recorded.queue_metrics[1].2 >= 20_000);
}

#[test]
fn airtime_and_distance_truncate_like_cpp() {
    assert_eq!(packet_duration(1, 1500, 12, false, false), 285);
    assert_eq!(packet_duration(1, 1500, 12, false, true), 329);
    assert_eq!(packet_duration(1, 1500, 12, true, false), 247);
    assert_eq!(cts_duration(1, 12), 22);
    assert_eq!(slot_size_microseconds(1, 1000), 12);
    assert_eq!(slot_size_microseconds(1, 1), 9);
}
