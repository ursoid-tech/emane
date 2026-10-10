use super::*;
static RECEIVED: Mutex<Vec<f64>> = Mutex::new(Vec::new());
extern "C" fn capture(
    _: *mut c_void,
    _: u16,
    packet: *const FfiPacket,
    messages: *const FfiControlMessage,
    count: usize,
) {
    if packet.is_null() {
        return;
    }
    let messages = unsafe { std::slice::from_raw_parts(messages, count) };
    let mut values = RECEIVED.lock().unwrap();
    if let Some(p) =
        control_payload(messages, CONTROL_MIMO_RX_PROPERTIES).and_then(MimoRxProperties::decode)
    {
        for antenna in p.antenna_infos {
            values.extend(antenna.segments.iter().map(|s| s.rx_power_dbm));
        }
    } else if let Some(p) = control_payload(messages, CONTROL_RX_FREQUENCY_SEGMENTS)
        .and_then(RxFrequencySegments::decode)
    {
        values.extend(p.segments.iter().map(|s| s.rx_power_dbm));
    }
}
fn antenna_control(inv: Invocation, kind: u32, bandwidth: u64, frequencies: Vec<u64>, gain: f64) {
    let data = RxAntennaAdd {
        antenna: MimoTxAntenna {
            antenna_index: 7,
            frequency_group_index: 0,
            bandwidth_hz: bandwidth,
            spectral_mask_index: 0,
            pattern: AntennaPattern::IdealOmni { gain_db: gain },
        },
        frequencies_hz: frequencies,
    }
    .encode();
    let Some(data) = data else {
        return;
    };
    let message = FfiControlMessage {
        msg_type: kind,
        payload: FfiSlice {
            data: data.as_ptr(),
            len: data.len(),
        },
    };
    builtin_downstream(inv.plugin_ctx as *mut c_void, std::ptr::null(), &message, 1);
}
fn wire(name: &str, start: i64) -> Vec<u8> {
    let frequency = if matches!(name, "not-foi" | "second-tx-in-band") {
        2_500_000_000
    } else {
        2_400_000_000
    };
    let mut segments = vec![common_phy_header::frequency_group::FrequencySegment {
        frequency_hz: frequency,
        offset_microseconds: 0,
        duration_microseconds: if matches!(name, "clamp" | "fading-after-clamp") {
            1_000_001
        } else {
            1000
        },
        powerd_bm: if matches!(name, "collaborator-fallback" | "collaborator-sensitivity") {
            None
        } else {
            Some(0.0)
        },
    }];
    if name == "segment-power" {
        segments.push(common_phy_header::frequency_group::FrequencySegment {
            frequency_hz: frequency,
            offset_microseconds: 1000,
            duration_microseconds: 1000,
            powerd_bm: Some(-20.0),
        });
    }
    let mut transmitters = vec![common_phy_header::Transmitter {
        nem_id: 2,
        powerd_bm: 0.0,
    }];
    if matches!(
        name,
        "collaborator-fallback"
            | "collaborator-sensitivity"
            | "collaborator-explicit"
            | "missing-fading"
    ) {
        transmitters.push(common_phy_header::Transmitter {
            nem_id: 3,
            powerd_bm: -20.0,
        });
    }
    let antenna = common_phy_header::TransmitAntenna {
        antenna_index: 0,
        frequency_group_index: 0,
        bandwidth_hz: if name == "overlap" {
            2_000_000
        } else {
            1_000_000
        },
        fixed_gaind_bi: Some(0.0),
        pointing: None,
        spectral_mask_index: None,
    };
    let mut antennas = vec![antenna.clone()];
    let mut groups = vec![common_phy_header::FrequencyGroup {
        frequency_segments: segments,
    }];
    if name == "second-tx-in-band" {
        antennas.push(common_phy_header::TransmitAntenna {
            antenna_index: 1,
            frequency_group_index: 1,
            ..antenna.clone()
        });
        groups.push(common_phy_header::FrequencyGroup {
            frequency_segments: vec![common_phy_header::frequency_group::FrequencySegment {
                frequency_hz: 2_400_000_000,
                offset_microseconds: 0,
                duration_microseconds: 1000,
                powerd_bm: Some(0.0),
            }],
        });
    }
    if name == "fading-after-clamp" {
        antennas.push(common_phy_header::TransmitAntenna {
            antenna_index: 1,
            ..antenna
        });
    }
    let phy = CommonPhyHeader {
        registration_id: PHY_FRAMEWORK_REGISTRATION,
        sub_id: 7,
        sequence_number: 1,
        tx_time_microseconds: start as u64,
        transmitters,
        frequency_groups: groups,
        transmit_antennas: antennas,
        filter_data: None,
    }
    .encode_to_vec();
    let mac = CommonMacHeader {
        registration_id: 1,
        sequence_number: 1,
    }
    .encode_to_vec();
    let mut result = (phy.len() as u16).to_be_bytes().to_vec();
    result.extend(phy);
    result.extend((mac.len() as u16).to_be_bytes());
    result.extend(mac);
    result.push(1);
    result
}
#[test]
fn wire_receive_results_match_original_cpp() {
    for mode in [1, 2] {
        for pool in [0, 2] {
            for name in [
                "baseline",
                "segment-power",
                "collaborator-fallback",
                "overlap",
                "collaborator-explicit",
                "missing-fading",
                "not-foi",
                "clamp",
                "fading-after-clamp",
                "antenna-update",
                "empty-foi",
                "zero-bandwidth",
                "second-tx-in-band",
                "collaborator-sensitivity",
            ] {
                if mode == 1 && matches!(name, "antenna-update" | "empty-foi" | "zero-bandwidth") {
                    continue;
                }
                RECEIVED.lock().unwrap().clear();
                let mut manager = NemManager::new([7; 16]);
                manager
                    .add_layer_configured(
                        1,
                        "emanephy",
                        2,
                        &[
                            ("subid".into(), vec!["7".into()]),
                            ("compatibilitymode".into(), vec![mode.to_string()]),
                            ("processingpoolsize".into(), vec![pool.to_string()]),
                            ("noisemode".into(), vec!["all".into()]),
                            ("frequency".into(), vec!["2.4G".into()]),
                            ("frequencyofinterest".into(), vec!["2.4G".into()]),
                            ("bandwidth".into(), vec!["1M".into()]),
                            ("stats.receivepowertableenable".into(), vec!["yes".into()]),
                            ("stats.observedpowertableenable".into(), vec!["yes".into()]),
                        ],
                    )
                    .unwrap();
                let inv = manager.layers[&1][0].invocation;
                assert!(builtin_start(inv.plugin_ctx as *mut c_void));
                let state = unsafe { &mut *(inv.plugin_ctx as *mut BuiltinState) };
                state.framework.send_upstream_packet = capture;
                for id in [2, 3] {
                    state.phy.pathloss.insert(
                        id,
                        HashMap::from([(
                            0,
                            if name == "collaborator-sensitivity" {
                                112.0
                            } else {
                                50.0
                            },
                        )]),
                    );
                }
                if name == "missing-fading" {
                    state.phy.fading_mode = FadingMode::Event;
                    state.phy.fading_selections.insert(2, FadingMode::None);
                }
                if name == "fading-after-clamp" {
                    state.phy.fading_mode = FadingMode::Nakagami;
                    for id in [1, 2] {
                        state.phy.update_location(id, 0.0, 0.0, 0.0, None, None);
                    }
                }
                if mode == 2 {
                    antenna_control(
                        inv,
                        CONTROL_RX_ANTENNA_ADD,
                        if name == "zero-bandwidth" {
                            0
                        } else {
                            1_000_000
                        },
                        if name == "empty-foi" {
                            vec![]
                        } else {
                            vec![2_400_000_000]
                        },
                        0.0,
                    );
                }
                let packet = FfiPacket {
                    info: FfiPacketInfo {
                        uuid: [1; 16],
                        source: 2,
                        destination: 1,
                        priority: 0,
                        creation_time_sec: 0,
                        creation_time_usec: 0,
                    },
                    payload: FfiSlice {
                        data: [1u8].as_ptr(),
                        len: 1,
                    },
                };
                let start = unix_time_microseconds() - 2000;
                let decoded = decode_legacy_ota_payload(&wire(name, start), 2).unwrap();
                builtin_upstream(
                    inv.plugin_ctx as *mut c_void,
                    &packet,
                    decoded.controls().as_ptr(),
                    decoded.controls().len(),
                );
                if name == "fading-after-clamp" {
                    let decoded = decode_legacy_ota_payload(&wire("baseline", start), 2).unwrap();
                    builtin_upstream(
                        inv.plugin_ctx as *mut c_void,
                        &packet,
                        decoded.controls().as_ptr(),
                        decoded.controls().len(),
                    );
                }
                let state = unsafe { &mut *(inv.plugin_ctx as *mut BuiltinState) };
                let monitor = if mode == 2 {
                    state
                        .phy
                        .receive_antennas
                        .get(&7)
                        .map(|a| a.monitor.clone())
                        .unwrap_or_else(|| state.phy.monitor.clone())
                } else {
                    state.phy.monitor.clone()
                };
                let before = monitor
                    .lock()
                    .unwrap()
                    .dump(2_400_000_000)
                    .iter()
                    .sum::<f64>();
                let previous_monitor = monitor.clone();
                if name == "antenna-update" {
                    monitor.lock().unwrap().initialize_filter(
                        23,
                        2_400_000_000,
                        1_000_000,
                        100_000,
                        std::ptr::null(),
                    );
                    antenna_control(
                        inv,
                        CONTROL_RX_ANTENNA_UPDATE,
                        1_000_000,
                        vec![2_400_000_000],
                        3.0,
                    );
                }
                let monitor = if mode == 2 {
                    state
                        .phy
                        .receive_antennas
                        .get(&7)
                        .map(|a| a.monitor.clone())
                        .unwrap_or_else(|| state.phy.monitor.clone())
                } else {
                    state.phy.monitor.clone()
                };
                let after = monitor
                    .lock()
                    .unwrap()
                    .dump(2_400_000_000)
                    .iter()
                    .sum::<f64>();
                let mut receive_rows = 0;
                let mut observed_rows = 0;
                let mut observed = Vec::new();
                let query = crate::statistics::emane_rs_statistic_query_table(
                    manager.layer_build_ids(1)[0],
                    crate::statistics::FfiStringArray {
                        data: std::ptr::null(),
                        len: 0,
                    },
                    std::ptr::null_mut(),
                    0,
                );
                for table in unsafe { std::slice::from_raw_parts(query.data, query.len) } {
                    let table_name = unsafe { std::ffi::CStr::from_ptr(table.name) }
                        .to_str()
                        .unwrap();
                    if table_name == "ReceivePowerTable" {
                        receive_rows = table.rows_len;
                    }
                    if table_name == "ObservedPowerTable" {
                        observed_rows = table.rows_len;
                        for row in unsafe { std::slice::from_raw_parts(table.rows, table.rows_len) }
                        {
                            let values = unsafe {
                                std::slice::from_raw_parts(row.values.data, row.values.len)
                            };
                            observed.push(values[5].d_value);
                        }
                    }
                }
                crate::statistics::emane_rs_statistic_free_table_query_result(query);
                let powers = RECEIVED.lock().unwrap();
                let (expected_powers, expected_receive, expected_observed) = original_result(name);
                assert_eq!(
                    powers.len(),
                    expected_powers.len(),
                    "{name} mode={mode} pool={pool}"
                );
                for (actual, expected) in powers.iter().zip(expected_powers) {
                    assert!(
                        (actual - expected).abs() < 1e-9,
                        "{name}: {actual} != {expected}"
                    );
                }
                assert_eq!(receive_rows, expected_receive, "{name}");
                observed.sort_by(f64::total_cmp);
                let mut expected_observed = expected_observed.to_vec();
                expected_observed.sort_by(f64::total_cmp);
                assert_eq!(observed_rows, expected_observed.len(), "{name}");
                for (actual, expected) in observed.iter().zip(expected_observed) {
                    assert!(
                        (actual - expected).abs() < 1e-9,
                        "{name}: {actual} != {expected}"
                    );
                }
                if name == "antenna-update" {
                    assert!(before > 0.0);
                    assert_eq!(before, after);
                    assert!(Arc::ptr_eq(&previous_monitor, &monitor));
                    // The filter remains registered on the same monitor.
                    let (_, bins) = monitor.lock().unwrap().dump_filter(23);
                    assert!(bins > 0);
                }
            }
        }
    }
}
#[test]
fn eel_float_inputs_match_original_cpp() {
    for value in ["50", "0x1p2", "1e-320", "1e-400", "nan(foo)"] {
        let accepted = crate::generators::eel::loaders::pathloss::PathlossLoader::new()
            .load("nem", 1, "pathloss", &[format!("nem:2,{value}")])
            .is_ok();
        assert_eq!(accepted, !matches!(value, "1e-320" | "1e-400"), "{value}");
    }
}

// Golden values from the original C++ ReceiveProcessor audit.
fn original_result(name: &str) -> (&'static [f64], usize, &'static [f64]) {
    match name {
        "baseline" => (&[-50.0], 1, &[-50.0]),
        "segment-power" => (&[-50.0, -70.0], 1, &[-70.0]),
        "collaborator-fallback" => (&[-49.956786262173566], 2, &[-49.956786262173566]),
        "overlap" => (&[-53.01029995663981], 1, &[-53.01029995663981]),
        "collaborator-explicit" => (&[-46.98970004336019], 2, &[-46.98970004336019]),
        "missing-fading" => (&[], 0, &[]),
        "not-foi" => (&[], 0, &[]),
        "clamp" => (&[], 0, &[]),
        "fading-after-clamp" => (&[-51.27447860814372], 1, &[-51.27447860814372]),
        "second-tx-in-band" => (&[-50.0], 2, &[-50.0]),
        "collaborator-sensitivity" => (&[], 2, &[]),
        "antenna-update" => (&[-50.0], 1, &[-50.0]),
        "empty-foi" => (&[-50.0], 1, &[-50.0]),
        "zero-bandwidth" => (&[-50.0], 1, &[-50.0]),
        _ => panic!("unknown reference case {name}"),
    }
}
