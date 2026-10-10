use super::*;
#[test]
fn mimo_records_out_of_band_noise() {
    for pool_size in [0, 2] {
        let mut manager = NemManager::new([7; 16]);
        manager
            .add_layer_configured(
                1,
                "emanephy",
                2,
                &[
                    ("subid".into(), vec!["7".into()]),
                    ("processingpoolsize".into(), vec![pool_size.to_string()]),
                    ("timesyncthreshold".into(), vec!["1000000".into()]),
                    ("compatibilitymode".into(), vec!["2".into()]),
                    ("noisemode".into(), vec!["outofband".into()]),
                    ("frequency".into(), vec!["2.4G".into()]),
                    ("frequencyofinterest".into(), vec!["2.4G".into()]),
                ],
            )
            .unwrap();
        let inv = manager.layers[&1][0].invocation;
        assert!(builtin_start(inv.plugin_ctx as *mut c_void));
        let state = unsafe { &mut *(inv.plugin_ctx as *mut BuiltinState) };
        state.phy.pathloss.insert(2, HashMap::from([(0, 50.0)]));
        let antenna = MimoTxAntenna {
            frequency_group_index: 0,
            antenna_index: 7,
            bandwidth_hz: 1_000_000,
            spectral_mask_index: 0,
            pattern: AntennaPattern::IdealOmni { gain_db: 0.0 },
        };
        for antenna_index in [7, 8, 9] {
            let add = RxAntennaAdd {
                antenna: MimoTxAntenna {
                    antenna_index,
                    pattern: if antenna_index == 9 {
                        AntennaPattern::Profile(TxAntennaProfile {
                            profile_id: 65535,
                            azimuth_degrees: 0.0,
                            elevation_degrees: 0.0,
                        })
                    } else {
                        AntennaPattern::IdealOmni {
                            gain_db: if antenna_index == 7 { 0.0 } else { 3.0 },
                        }
                    },
                    ..antenna
                },
                frequencies_hz: vec![2_400_000_000],
            }
            .encode()
            .unwrap();
            let control = FfiControlMessage {
                msg_type: CONTROL_RX_ANTENNA_ADD,
                payload: FfiSlice {
                    data: add.as_ptr(),
                    len: add.len(),
                },
            };
            builtin_downstream(inv.plugin_ctx as *mut c_void, std::ptr::null(), &control, 1);
        }
        let start = unix_time_microseconds() - 2000;
        let tx = TxProperties {
            frequency_hz: 2_400_000_000,
            bandwidth_hz: 1_000_000,
            tx_power_dbm: 0.0,
            duration_microseconds: 1000,
            offset_microseconds: 0,
            tx_time_microseconds: start,
            antenna_index: 0,
            spectral_mask_index: 0,
            sub_id: 9,
        }
        .encode();
        let mimo = MimoTxProperties {
            frequency_groups: vec![vec![MimoTxFrequencySegment {
                frequency_hz: 2_400_000_000,
                tx_power_dbm: Some(0.0),
                duration_microseconds: 1000,
                offset_microseconds: 0,
            }]],
            transmit_antennas: vec![MimoTxAntenna {
                antenna_index: 0,
                ..antenna
            }],
        }
        .encode()
        .unwrap();
        let messages = [
            FfiControlMessage {
                msg_type: CONTROL_TX_PROPERTIES,
                payload: FfiSlice {
                    data: tx.as_ptr(),
                    len: tx.len(),
                },
            },
            FfiControlMessage {
                msg_type: CONTROL_MIMO_TX_PROPERTIES,
                payload: FfiSlice {
                    data: mimo.as_ptr(),
                    len: mimo.len(),
                },
            },
        ];
        let bytes = [1];
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
                data: bytes.as_ptr(),
                len: bytes.len(),
            },
        };
        builtin_upstream(
            inv.plugin_ctx as *mut c_void,
            &packet,
            messages.as_ptr(),
            messages.len(),
        );
        let ctx =
            &*manager.layers[&1][0]._framework_context as *const FrameworkContext as *mut c_void;
        for antenna_index in [7, 8] {
            let query = FfiSpectrumQuery {
                frequency_hz: 2_400_000_000,
                start_time_microseconds: start,
                duration_microseconds: 1000,
                rx_power_dbm: -20.0,
                antenna_index,
            };
            let mut result = FfiSpectrumResult::default();
            assert!(query_spectrum(ctx, &query, &mut result));
            println!(
                "MIMO antenna 7 noise={} dBm; expected jammer about -50 dBm",
                result.noise_floor_dbm
            );
            let expected = if antenna_index == 7 { -50.0 } else { -47.0 };
            assert!(
                (result.noise_floor_dbm - expected).abs() < 0.01,
                "pool={pool_size}, antenna={antenna_index}: {}",
                result.noise_floor_dbm
            );
        }
    }
}
#[test]
fn txpower_update_preserves_noise() {
    let mut manager = NemManager::new([7; 16]);
    manager
        .add_layer_configured(
            1,
            "emanephy",
            2,
            &[
                ("subid".into(), vec!["7".into()]),
                ("noisemode".into(), vec!["outofband".into()]),
                ("frequency".into(), vec!["2.4G".into()]),
                ("frequencyofinterest".into(), vec!["2.4G".into()]),
            ],
        )
        .unwrap();
    let monitor = manager.runtime.spectrum_monitors.read().unwrap()[&(1, 0)]
        .upgrade()
        .unwrap();
    let start = unix_time_microseconds() - 2000;
    let segment = FfiFrequencySegment {
        frequency_hz: 2_400_000_000,
        rx_power_dbm: -60.0,
        duration_microsec: 1000,
        offset_microsec: 0,
    };
    monitor.lock().unwrap().update(
        start,
        start,
        0,
        0.0,
        &[segment],
        1_000_000,
        &[1e-6],
        false,
        &[3],
        9,
        0,
        0,
        std::ptr::null(),
        0,
    );
    let ctx = &*manager.layers[&1][0]._framework_context as *const FrameworkContext as *mut c_void;
    let query = FfiSpectrumQuery {
        frequency_hz: 2_400_000_000,
        start_time_microseconds: start,
        duration_microseconds: 1000,
        rx_power_dbm: -20.0,
        antenna_index: 0,
    };
    let mut before = FfiSpectrumResult::default();
    assert!(query_spectrum(ctx, &query, &mut before));
    crate::native_configuration::update(
        manager.layer_build_ids(1)[0],
        vec![(
            "txpower".into(),
            vec![crate::native_configuration::ConfigurationValue::Double(
                10.0,
            )],
        )],
    )
    .unwrap();
    let mut after = FfiSpectrumResult::default();
    assert!(query_spectrum(ctx, &query, &mut after));
    println!(
        "txpower noise before={} after={}",
        before.noise_floor_dbm, after.noise_floor_dbm
    );
    assert!(
        (after.noise_floor_dbm - before.noise_floor_dbm).abs() < 0.01,
        "runtime txpower must preserve receive noise history"
    );
}

#[test]
fn configuration_uses_declared_types_and_scalar_cardinality() {
    use crate::native_configuration::{self, ConfigurationValue as V};
    let mut manager = NemManager::new([44; 16]);
    assert!(manager
        .add_layer_configured(
            901,
            "emanephy",
            2,
            &[
                ("subid".into(), vec!["7".into()]),
                ("txpower".into(), vec!["1".into(), "2".into()])
            ]
        )
        .is_err());
    manager
        .add_layer_configured(901, "emanephy", 2, &[("subid".into(), vec!["7".into()])])
        .unwrap();
    let id = manager.layer_build_ids(901)[0];
    assert_eq!(
        native_configuration::query(id, &["subid".into()]).unwrap()[0].1,
        vec![V::UInt16(7)]
    );
    assert!(native_configuration::update(
        id,
        vec![("txpower".into(), vec![V::Double(1.0), V::Double(2.0)])]
    )
    .is_err());
    let mut schema = component_configuration_schema("bentpipe");
    schema.retain(|name, _| name == "transponder.transmit.power");
    let parsed = native_configuration::parse_initial(
        &schema,
        &[("transponder.transmit.power".into(), vec!["1:20".into()])],
    )
    .unwrap();
    assert_eq!(parsed[0].1, vec![V::String("1:20".into())]);
}

#[test]
fn neighbor_metrics_preserve_sender_restart_identity() {
    let mut manager = NemManager::new([45; 16]);
    manager
        .add_layer_configured(902, "emanephy", 2, &[("subid".into(), vec!["7".into()])])
        .unwrap();
    let ctx = &*manager.layers[&902][0]._framework_context;
    let pointer = ctx as *const FrameworkContext as *mut c_void;
    update_neighbor_rx(
        pointer,
        2,
        100,
        [1; 16].as_ptr(),
        20.0,
        -90.0,
        1_000_000,
        100,
        1_000_000,
    );
    update_neighbor_rx(
        pointer,
        2,
        1,
        [2; 16].as_ptr(),
        20.0,
        -90.0,
        1_100_000,
        100,
        1_000_000,
    );
    assert_eq!(
        ctx.neighbor_metrics
            .lock()
            .unwrap()
            .get_neighbor_metric_status(2)
            .unwrap()
            .num_rx_missed_frames,
        0
    );
}

#[test]
fn bypass_phy_uses_legacy_header_without_transmit_antennas() {
    let data = b"payload";
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
            data: data.as_ptr(),
            len: data.len(),
        },
    };
    let header = ModelHeader {
        registration_id: emane_plugin_api::MAC_REGISTRATION_BYPASS,
        sequence: 3,
        data_rate_bps: 0,
        category: 0,
        message_type: 0,
        flags: 0,
    }
    .encode();
    let controls = [
        FfiControlMessage {
            msg_type: emane_plugin_api::CONTROL_BYPASS_PHY,
            payload: FfiSlice {
                data: std::ptr::null(),
                len: 0,
            },
        },
        FfiControlMessage {
            msg_type: CONTROL_MODEL_HEADER,
            payload: FfiSlice {
                data: header.as_ptr(),
                len: header.len(),
            },
        },
    ];
    let encoded = encode_legacy_ota_payload(&packet, controls.as_ptr(), controls.len(), 9).unwrap();
    let len = u16::from_be_bytes(encoded[..2].try_into().unwrap()) as usize;
    let phy = CommonPhyHeader::decode(&encoded[2..2 + len]).unwrap();
    assert_eq!(phy.registration_id, 1);
    assert!(phy.transmit_antennas.is_empty());
    let decoded = decode_legacy_ota_payload(&encoded, 1).unwrap();
    assert_eq!(decoded.payload, data);
    assert_eq!(
        control_payload(decoded.controls(), CONTROL_MODEL_HEADER)
            .and_then(ModelHeader::decode)
            .unwrap()
            .sequence,
        3
    );
}

#[test]
fn configuration_matches_cpp_scaled_values_ranges_and_runtime_rejection() {
    use crate::native_configuration::{self, ConfigurationValue as V};
    let mut manager = NemManager::new([81; 16]);
    manager
        .add_layer_configured(
            903,
            "emanephy",
            2,
            &[
                ("subid".into(), vec!["1K".into()]),
                ("txpower".into(), vec!["-1K".into()]),
                ("frequencyofinterest".into(), vec!["0".into()]),
            ],
        )
        .unwrap();
    let id = manager.layer_build_ids(903)[0];
    assert_eq!(
        native_configuration::query(id, &["subid".into()]).unwrap()[0].1,
        vec![V::UInt16(1000)]
    );
    assert_eq!(
        native_configuration::query(id, &["txpower".into()]).unwrap()[0].1,
        vec![V::Double(-1000.0)]
    );
    assert!(native_configuration::update(
        id,
        vec![("fading.nakagami.m0".into(), vec![V::Double(0.0)])]
    )
    .is_err());
    assert_eq!(
        native_configuration::query(id, &["fading.nakagami.m0".into()]).unwrap()[0].1,
        vec![V::Double(0.75)]
    );
    let schema = component_configuration_schema("emanephy");
    for name in [
        "noisemaxsegmentoffset",
        "noisemaxsegmentduration",
        "noisemaxmessagepropagation",
        "timesyncthreshold",
    ] {
        assert!(native_configuration::parse_initial(
            &schema,
            &[
                ("subid".into(), vec!["1".into()]),
                (name.into(), vec!["0".into()])
            ]
        )
        .is_err());
    }
    assert!(schema["frequencyofinterest"].max_occurs > 255);
    assert_eq!(
        component_configuration_schema("bentpipe")["antenna.defines"].max_occurs,
        65535
    );
    assert!(matches!(
        component_configuration_schema("virtualtransport")["address"].prototype,
        V::InetAddr(_)
    ));
}

#[test]
fn model_filters_self_interference_and_cpp_wire_data() {
    use emane_plugin_api::{AntennaInterference, FilterCriterion};
    let mut manager = NemManager::new([93; 16]);
    manager
        .add_layer_configured(
            904,
            "emanephy",
            2,
            &[
                ("subid".into(), vec!["7".into()]),
                ("noisemode".into(), vec!["all".into()]),
                ("frequency".into(), vec!["2.4G".into()]),
                ("frequencyofinterest".into(), vec!["2.4G".into()]),
                (
                    "excludesamesubidfromfilterenable".into(),
                    vec!["off".into()],
                ),
                ("processingpoolsize".into(), vec!["2".into()]),
            ],
        )
        .unwrap();
    let invocation = manager.layers[&904][0].invocation;
    let state = invocation.plugin_ctx as *mut c_void;
    assert!(builtin_start(state));
    let spec = SpectrumFilterAdd {
        antenna_index: 0,
        filter_index: 9,
        frequency_hz: 2_400_000_000,
        bandwidth_hz: 1_000_000,
        sub_band_hz: 250_000,
        criterion: FilterCriterion::And(vec![
            FilterCriterion::Numeric {
                field: 2,
                comparison: 0,
                value: 0,
            },
            FilterCriterion::Data {
                comparison: 0,
                value: b"probe".to_vec(),
            },
        ]),
    };
    let add = spec.encode().unwrap();
    assert_eq!(SpectrumFilterAdd::decode(&add), Some(spec));
    let message = |kind, bytes: &[u8]| FfiControlMessage {
        msg_type: kind,
        payload: FfiSlice {
            data: bytes.as_ptr(),
            len: bytes.len(),
        },
    };
    builtin_downstream(
        state,
        std::ptr::null(),
        &message(CONTROL_SPECTRUM_FILTER_ADD, &add),
        1,
    );
    // A duplicate add must not replace the existing monitor or unwind across FFI.
    builtin_downstream(
        state,
        std::ptr::null(),
        &message(CONTROL_SPECTRUM_FILTER_ADD, &add),
        1,
    );
    let start = unix_time_microseconds() - 4000;
    let tx = TxProperties {
        frequency_hz: 2_400_000_000,
        bandwidth_hz: 1_000_000,
        tx_power_dbm: 0.0,
        duration_microseconds: 1000,
        offset_microseconds: 0,
        tx_time_microseconds: start,
        antenna_index: 0,
        spectral_mask_index: 0,
        sub_id: 7,
    }
    .encode();
    let interference = SelfInterference {
        antennas: vec![AntennaInterference {
            antenna_index: 0,
            groups: vec![(0, vec![1e-6])],
        }],
    }
    .encode()
    .unwrap();
    let controls = [
        message(CONTROL_TX_PROPERTIES, &tx),
        message(CONTROL_SELF_INTERFERENCE, &interference),
        message(CONTROL_SPECTRUM_FILTER_DATA, b"probe"),
    ];
    let packet = FfiPacket {
        info: FfiPacketInfo {
            uuid: [93; 16],
            source: 904,
            destination: 905,
            priority: 0,
            creation_time_sec: 0,
            creation_time_usec: 0,
        },
        payload: FfiSlice {
            data: std::ptr::null(),
            len: 0,
        },
    };
    builtin_downstream(state, &packet, controls.as_ptr(), controls.len());
    let ctx = manager.layers[&904][0]._framework_context.as_ref() as *const FrameworkContext
        as *mut c_void;
    let query = FfiFilterQuery {
        antenna_index: 0,
        filter_index: 9,
        start_time_microseconds: start,
        duration_microseconds: 1000,
    };
    let mut bins = vec![0.0; 10000];
    let mut result = FfiFilterResult {
        data: bins.as_mut_ptr(),
        capacity: bins.len(),
        length: 0,
        start_time_microseconds: 0,
        bin_size_microseconds: 0,
        sensitivity_mw: 0.0,
        sub_band_count: 0,
    };
    assert!(query_spectrum_filter(ctx, &query, &mut result));
    assert_eq!(result.sub_band_count, 5);
    assert!(bins[..result.length].iter().any(|p| *p > 1e-8));
    let mut spectrum = FfiSpectrumResult::default();
    assert!(query_spectrum(
        ctx,
        &FfiSpectrumQuery {
            frequency_hz: 2_400_000_000,
            start_time_microseconds: start,
            duration_microseconds: 1000,
            rx_power_dbm: -120.0,
            antenna_index: 0
        },
        &mut spectrum
    ));
    assert!((spectrum.noise_floor_dbm + 60.0).abs() < 0.01);
    let model = ModelHeader {
        registration_id: MAC_REGISTRATION_BENTPIPE,
        sequence: 1,
        data_rate_bps: 1,
        category: 0,
        message_type: 1,
        flags: 0,
    }
    .encode();
    let controls = [
        message(CONTROL_TX_PROPERTIES, &tx),
        message(CONTROL_MODEL_HEADER, &model),
        message(CONTROL_SPECTRUM_FILTER_DATA, b"probe"),
    ];
    let wire = encode_legacy_ota_payload(&packet, controls.as_ptr(), controls.len(), 0).unwrap();
    let decoded = decode_legacy_ota_payload(&wire, 904).unwrap();
    assert_eq!(filter_data(decoded.controls()), Some(b"probe".to_vec()));
    let remove = emane_plugin_api::SpectrumFilterRemove {
        antenna_index: 0,
        filter_index: 9,
    }
    .encode();
    builtin_downstream(
        state,
        std::ptr::null(),
        &message(CONTROL_SPECTRUM_FILTER_REMOVE, &remove),
        1,
    );
    assert!(!query_spectrum_filter(ctx, &query, &mut result));
    builtin_stop(state);
    assert!(unsafe { &*(state as *const BuiltinState) }
        .phy
        .processing_pool
        .is_none());
    assert!(builtin_start(state));
    assert!(unsafe { &*(state as *const BuiltinState) }
        .phy
        .processing_pool
        .is_some());
    builtin_stop(state);
}

#[test]
fn fading_state_is_owned_by_receive_antenna_not_transmitter() {
    let mut phy = PhyState::new();
    phy.fading_mode = FadingMode::Lognormal;
    assert_eq!(
        phy.apply_fading_on_antenna(7, 1, 2, -50.0, 100),
        Err(PhyPathError::FadeLocation)
    );
    for id in [1, 2, 3] {
        phy.update_location(id, 0.0, 0.0, 1.0, None, None);
    }
    let a = phy.apply_fading_on_antenna(7, 1, 2, -50.0, 100).unwrap();
    let b = phy.apply_fading_on_antenna(7, 1, 3, -50.0, 100).unwrap();
    assert_eq!(
        a, b,
        "one coherent fade covers transmitters on the same receive processor"
    );
    assert_eq!(phy.lognormal_states.len(), 1);
    let c = phy.apply_fading_on_antenna(8, 1, 2, -50.0, 100).unwrap();
    assert_eq!(
        a, c,
        "new antenna starts its own default-seeded distribution"
    );
    assert_eq!(phy.lognormal_states.len(), 2);
}
