//! Shared receive processing for both compatibility modes. Each transmit path
//! completes fading and spectrum processing before the next path consumes state.
use super::*;
use std::collections::BTreeMap;

type PowerKey = (u16, u16, u16, u64);
type ReceivePower = (f64, f64, f64, f64, f64, f64);
struct PreparedReception {
    monitor: Arc<Mutex<SpectrumMonitor>>,
    now: i64,
    tx: TxProperties,
    propagation: i64,
    doppler: f64,
    segments: Vec<FfiFrequencySegment>,
    powers: Vec<f64>,
    in_band: bool,
    transmitters: Vec<u16>,
    filter_data: Vec<u8>,
    transmit_antenna: MimoTxAntenna,
    receive_index: u16,
    cache_hit: bool,
    receive_powers: BTreeMap<PowerKey, ReceivePower>,
    doppler_shifts: BTreeMap<u64, f64>,
}

#[derive(Default)]
struct AntennaReception {
    infos: Vec<MimoRxAntennaInfo>,
    timing: Option<(i64, i64)>,
    error: Option<usize>,
    out_of_band: Option<usize>,
    cache_hit: bool,
    receive_powers: BTreeMap<PowerKey, ReceivePower>,
    observed_powers: BTreeMap<PowerKey, (u16, f64)>,
    doppler_shifts: BTreeMap<u64, f64>,
}

fn process_antenna(
    reception: Result<PreparedReception, usize>,
    mut result: AntennaReception,
) -> AntennaReception {
    let reception = match reception {
        Ok(value) => value,
        Err(code) => {
            result.error = Some(code);
            return result;
        }
    };
    result.cache_hit = reception.cache_hit;
    result.receive_powers.extend(reception.receive_powers);
    result.doppler_shifts.extend(reception.doppler_shifts);
    let mut monitor = reception.monitor.lock().unwrap();
    let (time, propagation, span, report, in_band, sensitivity) = monitor.update(
        reception.now,
        reception.tx.tx_time_microseconds,
        reception.propagation,
        reception.doppler,
        &reception.segments,
        reception.transmit_antenna.bandwidth_hz,
        &reception.powers,
        reception.in_band,
        &reception.transmitters,
        reception.tx.sub_id,
        reception.transmit_antenna.antenna_index,
        reception.transmit_antenna.spectral_mask_index,
        reception.filter_data.as_ptr(),
        reception.filter_data.len(),
    );
    if monitor.last_update_had_clamp_error() {
        result.error = Some(8);
        return result;
    }
    if !in_band {
        result.out_of_band = Some(if reception.in_band { 7 } else { 1 });
        return result;
    }
    if report.is_empty() {
        return result;
    }
    if result
        .timing
        .is_some_and(|value| value != (time, propagation))
    {
        result.error = Some(8);
        return result;
    }
    result.timing = Some((time, propagation));
    let noise =
        reception_noise_floor_dbm(&monitor, reception.now, time, propagation, span, &report[0]);
    for segment in &report {
        result.observed_powers.insert(
            (
                reception.transmitters[0],
                reception.receive_index,
                reception.transmit_antenna.antenna_index,
                segment.frequency_hz,
            ),
            (
                reception.transmit_antenna.spectral_mask_index,
                segment.rx_power_dbm,
            ),
        );
    }
    result.infos.push(MimoRxAntennaInfo {
        receive_antenna_index: reception.receive_index,
        transmit_antenna_index: reception.transmit_antenna.antenna_index,
        span_microseconds: span.max(0) as u64,
        receiver_sensitivity_dbm: 10.0 * sensitivity.log10(),
        noise_floor_dbm: noise,
        segments: report
            .into_iter()
            .map(|s| RxFrequencySegment {
                frequency_hz: s.frequency_hz,
                rx_power_dbm: s.rx_power_dbm,
                duration_microseconds: s.duration_microsec.max(0) as u64,
                offset_microseconds: s.offset_microsec.max(0) as u64,
            })
            .collect(),
    });
    result
}

pub(super) fn receive(
    state: &mut BuiltinState,
    packet: &FfiPacket,
    tx: TxProperties,
    mimo: &MimoTxProperties,
    incoming: &[FfiControlMessage],
    now: i64,
) -> Result<MimoRxProperties, usize> {
    // With noise disabled, the original framework rejects another sub-ID
    // before antenna, gain, fading or spectrum state can be changed.
    if tx.sub_id != state.phy.sub_id && state.phy.noise_mode == NoiseMode::None {
        return Err(1);
    }
    let transmitters = find_tx_transmitters(incoming).unwrap_or(TxTransmitters {
        transmitters: vec![TxTransmitter {
            nem_id: packet.info.source,
            tx_power_dbm: tx.tx_power_dbm,
        }],
    });
    let transmitter_ids = transmitters
        .transmitters
        .iter()
        .map(|t| t.nem_id)
        .collect::<Vec<_>>();
    // The original framework updates every transmitter antenna before any
    // propagation/fading path can fail. Preserve those cache invalidations.
    for transmitter in &transmitters.transmitters {
        for antenna in &mimo.transmit_antennas {
            state.phy.update_gain_antenna(transmitter.nem_id, *antenna);
        }
    }
    let filter_data = filter_data(incoming).unwrap_or_default();
    // Spectrum overlap uses the first physical transmitter, independently of
    // the packet's logical source. Per-frequency controls use the last one.
    let doppler = transmitter_ids
        .first()
        .map_or(0.0, |source| state.phy.doppler_fraction(state.id, *source));
    let mut antennas = if state.phy.compatibility_mode == 1 {
        vec![(
            0,
            MimoTxAntenna {
                antenna_index: 0,
                frequency_group_index: 0,
                bandwidth_hz: state.phy.bandwidth_hz,
                spectral_mask_index: 0,
                pattern: state
                    .phy
                    .default_antenna_pattern(state.id)
                    .unwrap_or(AntennaPattern::Default),
            },
            state.phy.monitor.clone(),
        )]
    } else {
        state
            .phy
            .receive_antennas
            .iter()
            .map(|(index, entry)| (*index, entry.antenna, entry.monitor.clone()))
            .collect::<Vec<_>>()
    };
    antennas.sort_unstable_by_key(|entry| entry.0);
    let mut results = antennas
        .iter()
        .map(|_| AntennaReception::default())
        .collect::<Vec<_>>();
    // A barrier between transmit paths retains per-antenna RNG/failure order.
    // Antennas still run their spectrum work on the persistent worker pool.
    for transmit_antenna in &mimo.transmit_antennas {
        let mut jobs: Vec<Box<dyn FnOnce() -> AntennaReception + Send>> = Vec::new();
        for ((receive_index, receive_antenna, monitor), result) in antennas.iter().zip(results) {
            if result.error.is_some() {
                jobs.push(Box::new(move || result));
                continue;
            }
            let receive_index = *receive_index;
            let reception = (|| {
                let group = mimo
                    .frequency_groups
                    .get(usize::from(transmit_antenna.frequency_group_index))
                    .ok_or(12usize)?;
                let mut powers = vec![0.0; group.len()];
                let mut propagation = None;
                let mut cache_hit = false;
                let mut receive_powers = BTreeMap::new();
                let mut doppler_shifts = BTreeMap::new();
                for transmitter in &transmitters.transmitters {
                    // Resolve all path loss before gain/fading, as ReceiveProcessor does.
                    let paths = group
                        .iter()
                        .map(|segment| {
                            state
                                .phy
                                .propagation_detailed(
                                    state.id,
                                    transmitter.nem_id,
                                    segment.frequency_hz,
                                )
                                .map_err(PhyPathError::drop_code)
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    let (receive_gain, transmit_gain, hit) = state
                        .phy
                        .antenna_pair_gains_for(
                            state.id,
                            transmitter.nem_id,
                            receive_index,
                            transmit_antenna.antenna_index,
                            receive_antenna.pattern,
                            transmit_antenna.pattern,
                        )
                        .map_err(PhyPathError::drop_code)?;
                    cache_hit = hit;
                    let factor = 1.0 + state.phy.doppler_fraction(state.id, transmitter.nem_id);
                    for (index, (segment, (pathloss, delay))) in group.iter().zip(paths).enumerate()
                    {
                        let power = state
                            .phy
                            .apply_fading_on_antenna(
                                receive_index,
                                state.id,
                                transmitter.nem_id,
                                segment.tx_power_dbm.unwrap_or(transmitter.tx_power_dbm) - pathloss
                                    + receive_gain
                                    + transmit_gain,
                                now.max(0) as u64,
                            )
                            .map_err(PhyPathError::drop_code)?;
                        powers[index] += 10.0f64.powf(power / 10.0);
                        let frequency = segment.frequency_hz as f64;
                        let shift = frequency * factor - frequency;
                        if state.phy.doppler_shift_enabled {
                            doppler_shifts.insert(segment.frequency_hz, shift);
                        }
                        receive_powers.insert(
                            (
                                transmitter.nem_id,
                                receive_index,
                                transmit_antenna.antenna_index,
                                segment.frequency_hz,
                            ),
                            (
                                power,
                                transmit_gain,
                                receive_gain,
                                segment.tx_power_dbm.unwrap_or(transmitter.tx_power_dbm),
                                pathloss,
                                shift,
                            ),
                        );
                        if propagation.is_none()
                            && state.phy.distance(state.id, transmitter.nem_id).is_some()
                        {
                            propagation = Some(delay);
                        }
                    }
                }
                Ok(PreparedReception {
                    monitor: monitor.clone(),
                    now,
                    tx,
                    propagation: propagation.unwrap_or(0),
                    doppler,
                    segments: group
                        .iter()
                        .zip(&powers)
                        .map(|(s, power)| FfiFrequencySegment {
                            frequency_hz: s.frequency_hz,
                            rx_power_dbm: 10.0 * power.log10(),
                            duration_microsec: i64::try_from(s.duration_microseconds)
                                .unwrap_or(i64::MAX),
                            offset_microsec: i64::try_from(s.offset_microseconds)
                                .unwrap_or(i64::MAX),
                        })
                        .collect(),
                    powers,
                    in_band: tx.sub_id == state.phy.sub_id,
                    transmitters: transmitter_ids.clone(),
                    filter_data: filter_data.clone(),
                    transmit_antenna: *transmit_antenna,
                    receive_index,
                    cache_hit,
                    receive_powers,
                    doppler_shifts,
                })
            })();
            jobs.push(Box::new(move || process_antenna(reception, result)));
        }
        results = if let Some(pool) = &state.phy.processing_pool {
            pool.run(jobs).map_err(|_| 14usize)?
        } else {
            jobs.into_iter().map(|job| job()).collect()
        };
    }
    let mut not_foi = false;
    let mut timing = None;
    let mut infos = Vec::new();
    let mut doppler_shifts = BTreeMap::new();
    for mut result in results {
        if result.error.is_none() && result.infos.is_empty() {
            result.error = result.out_of_band;
        }
        if let Some(code) = result.error {
            if code == 7 {
                not_foi = true;
            } else {
                // Preserve the original framework's accumulated NOT_FOI flag.
                if !not_foi {
                    return Err(code);
                }
                state.counters.upstream_drop_packet(
                    state.framework,
                    packet.info.source,
                    packet.info.destination,
                    code,
                );
            }
            continue;
        }
        for (
            (source, rx, tx_index, frequency),
            (power, tx_gain, rx_gain, tx_power, pathloss, doppler),
        ) in result.receive_powers
        {
            state.phy.publish_receive_power(
                source,
                rx,
                tx_index,
                frequency,
                power,
                tx_gain,
                rx_gain,
                tx_power,
                pathloss,
                doppler,
                tx.tx_time_microseconds as f64 / 1_000_000.0,
            );
        }
        for ((source, rx, tx_index, frequency), (mask, power)) in result.observed_powers {
            state.phy.publish_observed_power(
                source,
                rx,
                tx_index,
                frequency,
                mask,
                power,
                tx.tx_time_microseconds as f64 / 1_000_000.0,
            );
        }
        (state.framework.increment_counter)(
            state.framework.framework_ctx,
            if result.cache_hit {
                state.phy.gain_cache_hit_counter
            } else {
                state.phy.gain_cache_miss_counter
            },
            1,
        );
        if let Some((time, propagation)) = result.timing {
            timing = Some(timing.map_or((time, propagation), |(a, b): (i64, i64)| {
                (a.min(time), b.min(propagation))
            }));
        }
        for (frequency, shift) in result.doppler_shifts {
            doppler_shifts.entry(frequency).or_insert(shift);
        }
        infos.extend(result.infos);
    }
    if infos.is_empty() {
        return Err(if not_foi { 7 } else { 2 });
    }
    let (time, propagation) = timing.unwrap();
    Ok(MimoRxProperties {
        tx_time_microseconds: time,
        propagation_microseconds: propagation.max(0) as u64,
        antenna_infos: infos,
        doppler_shifts_hz: doppler_shifts.into_iter().collect(),
    })
}
