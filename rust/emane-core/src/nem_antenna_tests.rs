use super::*;
use crate::protobufs::emane_message::{antenna_profile_event, AntennaProfileEvent};

fn configured_phy(compatibility_mode: u8, fixed_gain_enabled: bool) -> NemManager {
    let mut manager = NemManager::new([93; 16]);
    manager
        .add_layer_configured(
            1,
            "emanephy",
            2,
            &[
                ("fixedantennagain".into(), vec!["0".into()]),
                (
                    "fixedantennagainenable".into(),
                    vec![fixed_gain_enabled.to_string()],
                ),
                ("subid".into(), vec!["1".into()]),
                (
                    "compatibilitymode".into(),
                    vec![compatibility_mode.to_string()],
                ),
            ],
        )
        .unwrap();
    manager.start().unwrap();
    manager
}

fn add_receive_antenna(invocation: Invocation, index: u16, pattern: AntennaPattern) {
    let payload = RxAntennaAdd {
        antenna: MimoTxAntenna {
            antenna_index: index,
            frequency_group_index: 0,
            bandwidth_hz: 1_000_000,
            spectral_mask_index: 0,
            pattern,
        },
        frequencies_hz: vec![2_347_000_000],
    }
    .encode()
    .unwrap();
    let message = FfiControlMessage {
        msg_type: CONTROL_RX_ANTENNA_ADD,
        payload: FfiSlice {
            data: payload.as_ptr(),
            len: payload.len(),
        },
    };
    builtin_downstream(invocation.context(), std::ptr::null(), &message, 1);
}

fn local_profile_event(invocation: Invocation) {
    let payload = AntennaProfileEvent {
        profiles: vec![antenna_profile_event::Profile {
            nem_id: 1,
            profile_id: 42,
            antenna_azimuth_degrees: 0.0,
            antenna_elevation_degrees: 0.0,
        }],
    }
    .encode_to_vec();
    builtin_event(invocation.context(), 102, payload.as_ptr(), payload.len());
}

fn pair_gains(
    invocation: Invocation,
    receive_index: u16,
) -> Result<(f64, f64, bool), PhyPathError> {
    let state = unsafe { &mut *invocation.context().cast::<BuiltinState>() };
    state.phy.antenna_pair_gains_for(
        1,
        2,
        receive_index,
        0,
        AntennaPattern::Default,
        AntennaPattern::IdealOmni { gain_db: 2.0 },
    )
}

#[test]
fn fixed_gain_update_after_local_profile_event_restores_default_antenna() {
    for compatibility_mode in [1, 2] {
        let manager = configured_phy(compatibility_mode, true);
        let invocation = manager.layers[&1][0].invocation;
        let monitor = if compatibility_mode == 2 {
            add_receive_antenna(invocation, 0, AntennaPattern::Default);
            add_receive_antenna(invocation, 7, AntennaPattern::IdealOmni { gain_db: 11.0 });
            assert_eq!(pair_gains(invocation, 7), Ok((11.0, 2.0, false)));
            let state = unsafe { &*invocation.context().cast::<BuiltinState>() };
            Some(state.phy.receive_antennas[&0].monitor.clone())
        } else {
            None
        };

        // Reapplying the same numeric value must also replace a profile selected
        // by an intervening event. No location or manifest is needed for omni.
        for gain in [0.0, 7.0] {
            local_profile_event(invocation);
            assert_eq!(pair_gains(invocation, 0), Err(PhyPathError::GainLocation));
            invocation
                .configure_running(vec![("fixedantennagain".into(), vec![gain.to_string()])])
                .unwrap();
            assert_eq!(pair_gains(invocation, 0), Ok((gain, 2.0, false)));
            assert_eq!(pair_gains(invocation, 0), Ok((gain, 2.0, true)));

            if let Some(monitor) = &monitor {
                let state = unsafe { &*invocation.context().cast::<BuiltinState>() };
                let receiver = &state.phy.receive_antennas[&0];
                assert_eq!(
                    receiver.antenna.pattern,
                    AntennaPattern::IdealOmni { gain_db: gain }
                );
                assert_eq!(receiver.antenna.bandwidth_hz, 1_000_000);
                assert!(Arc::ptr_eq(&receiver.monitor, monitor));
                // Updating the default antenna leaves other MIMO gains cached.
                assert_eq!(pair_gains(invocation, 7), Ok((11.0, 2.0, true)));
            }
        }
    }
}

#[test]
fn fixed_gain_update_preserves_profiles_when_fixed_gain_is_disabled() {
    let manager = configured_phy(2, false);
    let invocation = manager.layers[&1][0].invocation;
    let state = unsafe { &*invocation.context().cast::<BuiltinState>() };
    // The initial gain value precedes the enable flag in configuration.
    assert!(!state.phy.gain_antennas.contains_key(&(1, 0)));
    add_receive_antenna(invocation, 0, AntennaPattern::Default);
    local_profile_event(invocation);
    let original = unsafe { &*invocation.context().cast::<BuiltinState>() }
        .phy
        .gain_antennas[&(1, 0)];
    invocation
        .configure_running(vec![("fixedantennagain".into(), vec!["7".into()])])
        .unwrap();
    let state = unsafe { &*invocation.context().cast::<BuiltinState>() };
    assert_eq!(state.phy.fixed_antenna_gain_db, 7.0);
    assert_eq!(state.phy.gain_antennas[&(1, 0)], original);
    assert_eq!(
        state.phy.receive_antennas[&0].antenna.pattern,
        original.pattern
    );
    assert_eq!(pair_gains(invocation, 0), Err(PhyPathError::GainLocation));
}
