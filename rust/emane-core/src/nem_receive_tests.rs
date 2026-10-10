use super::*;
#[test]
fn antenna_results_match_original_delivery_and_counters() {
    for pool_size in [0, 2] {
        for case in [
            "baseline",
            "siso-segments",
            "independent-foi",
            "lognormal-no-location",
            "missing-collaborator-fading",
            "mixed-bandwidth",
            "invalid-secondary-antenna",
        ] {
            FINAL_DELIVERIES.store(0, std::sync::atomic::Ordering::SeqCst);
            let frequency = if case == "independent-foi" {
                2_500_000_000
            } else {
                2_400_000_000
            };
            let mut manager = NemManager::new([7; 16]);
            manager
                .add_layer_configured(
                    1,
                    "emanephy",
                    2,
                    &[
                        ("subid".into(), vec!["7".into()]),
                        ("processingpoolsize".into(), vec![pool_size.to_string()]),
                        (
                            "compatibilitymode".into(),
                            vec![if case == "siso-segments" {
                                "1".into()
                            } else {
                                "2".into()
                            }],
                        ),
                        ("noisemode".into(), vec!["all".into()]),
                        ("frequency".into(), vec!["2.4G".into()]),
                        ("frequencyofinterest".into(), vec!["2.4G".into()]),
                    ],
                )
                .unwrap();
            let inv = manager.layers[&1][0].invocation;
            assert!(builtin_start(inv.plugin_ctx as *mut c_void));
            let state = unsafe { &mut *(inv.plugin_ctx as *mut BuiltinState) };
            state.phy.pathloss.insert(
                2,
                HashMap::from([(
                    0,
                    if case == "mixed-bandwidth" {
                        105.0
                    } else {
                        50.0
                    },
                )]),
            );
            state.framework.send_upstream_packet = final_capture;
            state.phy.pathloss.insert(3, HashMap::from([(0, 50.0)]));
            if case == "lognormal-no-location" {
                state.phy.fading_mode = FadingMode::Lognormal;
            }
            if case == "missing-collaborator-fading" {
                state.phy.fading_mode = FadingMode::Event;
                state.phy.fading_selections.insert(2, FadingMode::None);
            }
            let antenna = MimoTxAntenna {
                frequency_group_index: 0,
                antenna_index: 7,
                bandwidth_hz: 1_000_000,
                spectral_mask_index: 0,
                pattern: AntennaPattern::IdealOmni { gain_db: 0.0 },
            };
            for antenna_index in if case == "siso-segments" {
                vec![]
            } else if case == "mixed-bandwidth" {
                vec![7, 8]
            } else if case == "invalid-secondary-antenna" {
                vec![7, 9]
            } else {
                vec![7]
            } {
                let add = RxAntennaAdd {
                    antenna: MimoTxAntenna {
                        antenna_index,
                        bandwidth_hz: if antenna_index == 8 {
                            100_000_000
                        } else {
                            1_000_000
                        },
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
                    frequencies_hz: vec![if antenna_index == 8 {
                        2_500_000_000
                    } else {
                        frequency
                    }],
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
                frequency_hz: frequency,
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
            let mimo = MimoTxProperties {
                frequency_groups: vec![vec![MimoTxFrequencySegment {
                    frequency_hz: frequency,
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
            let transmitters = TxTransmitters {
                transmitters: if case == "missing-collaborator-fading" {
                    vec![
                        TxTransmitter {
                            nem_id: 2,
                            tx_power_dbm: 0.0,
                        },
                        TxTransmitter {
                            nem_id: 3,
                            tx_power_dbm: 0.0,
                        },
                    ]
                } else {
                    vec![TxTransmitter {
                        nem_id: 2,
                        tx_power_dbm: 0.0,
                    }]
                },
            }
            .encode()
            .unwrap();
            let segments = TxFrequencySegments {
                segments: vec![
                    TxFrequencySegment {
                        frequency_hz: frequency,
                        duration_microseconds: 1000,
                        offset_microseconds: 0,
                    },
                    TxFrequencySegment {
                        frequency_hz: frequency,
                        duration_microseconds: 1000,
                        offset_microseconds: 2000,
                    },
                ],
            }
            .encode()
            .unwrap();
            let messages = [
                FfiControlMessage {
                    msg_type: CONTROL_TX_FREQUENCY_SEGMENTS,
                    payload: FfiSlice {
                        data: segments.as_ptr(),
                        len: segments.len(),
                    },
                },
                FfiControlMessage {
                    msg_type: CONTROL_TX_TRANSMITTERS,
                    payload: FfiSlice {
                        data: transmitters.as_ptr(),
                        len: transmitters.len(),
                    },
                },
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
            let query = crate::statistics::emane_rs_statistic_query(
                manager.layer_build_ids(1)[0],
                crate::statistics::FfiStringArray {
                    data: std::ptr::null(),
                    len: 0,
                },
                std::ptr::null_mut(),
                0,
            );
            let total: u64 = unsafe { std::slice::from_raw_parts(query.data, query.len) }
                .iter()
                .filter(|item| {
                    let name = unsafe { std::ffi::CStr::from_ptr(item.name) }
                        .to_str()
                        .unwrap();
                    name == "numGainCacheHit" || name == "numGainCacheMiss"
                })
                .map(|item| item.value.u64_value)
                .sum();
            crate::statistics::emane_rs_statistic_free_query_result(query);
            let expected = usize::from(matches!(
                case,
                "baseline" | "siso-segments" | "independent-foi" | "mixed-bandwidth"
            ));
            assert_eq!(
                FINAL_DELIVERIES.load(std::sync::atomic::Ordering::SeqCst),
                expected,
                "{case}, pool={pool_size}"
            );
            if matches!(case, "baseline" | "siso-segments") {
                assert_eq!(total, 1, "one gain-cache result per antenna");
                builtin_upstream(
                    inv.plugin_ctx as *mut c_void,
                    &packet,
                    messages.as_ptr(),
                    messages.len(),
                );
                let query = crate::statistics::emane_rs_statistic_query(
                    manager.layer_build_ids(1)[0],
                    crate::statistics::FfiStringArray {
                        data: std::ptr::null(),
                        len: 0,
                    },
                    std::ptr::null_mut(),
                    0,
                );
                for item in unsafe { std::slice::from_raw_parts(query.data, query.len) } {
                    let name = unsafe { std::ffi::CStr::from_ptr(item.name) }
                        .to_str()
                        .unwrap();
                    if name == "numGainCacheHit" || name == "numGainCacheMiss" {
                        assert_eq!(item.value.u64_value, 1, "{name} after two packets");
                    }
                }
                crate::statistics::emane_rs_statistic_free_query_result(query);
                assert_eq!(
                    FINAL_DELIVERIES.load(std::sync::atomic::Ordering::SeqCst),
                    2
                );
            }
        }
    }
}
static FINAL_DELIVERIES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
extern "C" fn final_capture(
    _: *mut c_void,
    _: u16,
    packet: *const FfiPacket,
    _: *const FfiControlMessage,
    _: usize,
) {
    if !packet.is_null() {
        FINAL_DELIVERIES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}
#[test]
fn bundled_eel_loaders_accept_legacy_numeric_syntax() {
    use crate::generators::eel::loaders::{commeffect::CommEffectLoader, pathloss::PathlossLoader};
    for value in ["nem:2,50", "nem:0x2,50", "nem:2,1K", "nem:2,NaN"] {
        let accepted = PathlossLoader::new()
            .load("nem", 1, "pathloss", &[value.into()])
            .is_ok();
        assert!(accepted, "{value}");
    }
    for value in ["nem:2,0,0,0,0,1000000,1000000", "nem:2,0,0,0,0,1M,1M"] {
        let accepted = CommEffectLoader::new().load("nem", 1, &[value]).is_ok();
        assert!(accepted, "{value}");
    }
}
