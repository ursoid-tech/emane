//! Serialization at the C++ transport boundary. Layer-local controls are consumed
//! inside the NEM; only serializable transport controls cross this boundary.
use crate::protobufs::emane_message as wire;
use emane_plugin_api::*;
use prost::Message;

pub(crate) fn encode(id: u32, data: &[u8]) -> Result<Option<(u16, Vec<u8>)>, String> {
    let invalid = || format!("invalid native control {id}");
    let value = match id {
        CONTROL_FLOW_CONTROL_TOKEN => {
            let v = FlowControlToken::decode(data).ok_or_else(invalid)?;
            (
                104,
                wire::FlowControlControlMessage {
                    tokens: u32::from(v.tokens),
                }
                .encode_to_vec(),
            )
        }
        CONTROL_R2RI_SELF_METRIC => {
            let v = R2riSelfMetric::decode(data).ok_or_else(invalid)?;
            (
                107,
                wire::RadioToRouterSelfMetric {
                    broadcast_data_ratebps: v.broadcast_data_rate_bps,
                    max_data_ratebps: v.max_data_rate_bps,
                    report_interval: v.report_interval_microseconds as f64 / 1e6,
                }
                .encode_to_vec(),
            )
        }
        CONTROL_R2RI_QUEUE_METRIC => {
            let v = R2riQueueMetrics::decode(data).ok_or_else(invalid)?;
            (
                106,
                wire::RadioToRouterQueueMetrics {
                    metrics: v
                        .metrics
                        .into_iter()
                        .map(|m| wire::radio_to_router_queue_metrics::QueueMetric {
                            queue_id: u32::from(m.queue_id),
                            max_size: m.max_size,
                            current_depth: m.current_depth_high_water,
                            num_discards: m.num_discards_high_water,
                            avg_delay: m.average_delay_microseconds as f64 / 1e6,
                        })
                        .collect(),
                }
                .encode_to_vec(),
            )
        }
        CONTROL_R2RI_NEIGHBOR_METRIC => {
            let v = R2riNeighborMetrics::decode(data).ok_or_else(invalid)?;
            (
                105,
                wire::RadioToRouterNeighborMetrics {
                    metrics: v
                        .metrics
                        .into_iter()
                        .map(|m| wire::radio_to_router_neighbor_metrics::NeighborMetric {
                            neighbor_id: u32::from(m.nem_id),
                            num_rx_frames: m.num_rx_frames,
                            num_tx_frames: m.num_tx_frames,
                            num_missed_frames: m.num_missed_frames,
                            bandwidth_consumption: m.bandwidth_consumption_microseconds as f64
                                / 1e6,
                            sinr_average: m.sinr_average_db,
                            sinr_stddev: m.sinr_stddev,
                            noise_floor_avg: m.noise_floor_average_dbm,
                            noise_floor_stddev: m.noise_floor_stddev,
                            rx_avg_data_ratebps: m.rx_average_data_rate_bps,
                            tx_avg_data_ratebps: m.tx_average_data_rate_bps,
                        })
                        .collect(),
                }
                .encode_to_vec(),
            )
        }
        CONTROL_BYPASS_PHY
        | CONTROL_TX_PROPERTIES
        | CONTROL_RX_PROPERTIES
        | CONTROL_MODEL_HEADER
        | CONTROL_FREQUENCY_INTEREST
        | CONTROL_COMM_EFFECT_HEADER
        | CONTROL_TIMING_ANALYSIS_HEADER
        | CONTROL_TX_FREQUENCY_SEGMENTS
        | CONTROL_TX_TRANSMITTERS
        | CONTROL_TX_ANTENNA_PROFILE
        | CONTROL_RX_FREQUENCY_SEGMENTS
        | CONTROL_MIMO_TX_PROPERTIES
        | CONTROL_MIMO_RX_PROPERTIES
        | CONTROL_RX_ANTENNA_ADD
        | CONTROL_RX_ANTENNA_UPDATE
        | CONTROL_RX_ANTENNA_REMOVE
        | CONTROL_SPECTRUM_FILTER_ADD
        | CONTROL_SPECTRUM_FILTER_REMOVE
        | CONTROL_SPECTRUM_FILTER_DATA
        | CONTROL_SELF_INTERFERENCE => return Ok(None),
        _ => (
            u16::try_from(id).map_err(|_| format!("unsupported boundary control {id}"))?,
            data.to_vec(),
        ),
    };
    Ok(Some(value))
}

pub(crate) fn decode(id: u16, data: &[u8]) -> Option<(u32, Vec<u8>)> {
    fn micros(seconds: f64) -> Option<u64> {
        (seconds.is_finite() && seconds >= 0.0 && seconds < u64::MAX as f64 / 1e6)
            .then_some((seconds * 1e6).round() as u64)
    }
    Some(match id {
        104 => {
            // prost's scalar `required` decoding supplies zero for an absent
            // field. Track presence to match C++ proto2 ParseFromString.
            #[derive(prost::Message)]
            struct Tokens {
                #[prost(uint32, optional, tag = "1")]
                tokens: Option<u32>,
            }
            let v = Tokens::decode(data).ok()?;
            (
                CONTROL_FLOW_CONTROL_TOKEN,
                FlowControlToken {
                    tokens: v.tokens? as u16,
                }
                .encode()
                .to_vec(),
            )
        }
        107 => {
            let v = wire::RadioToRouterSelfMetric::decode(data).ok()?;
            (
                CONTROL_R2RI_SELF_METRIC,
                R2riSelfMetric {
                    broadcast_data_rate_bps: v.broadcast_data_ratebps,
                    max_data_rate_bps: v.max_data_ratebps,
                    report_interval_microseconds: micros(v.report_interval)?,
                }
                .encode()
                .to_vec(),
            )
        }
        106 => {
            let v = wire::RadioToRouterQueueMetrics::decode(data).ok()?;
            (
                CONTROL_R2RI_QUEUE_METRIC,
                R2riQueueMetrics {
                    metrics: v
                        .metrics
                        .into_iter()
                        .map(|m| {
                            Some(R2riQueueMetric {
                                queue_id: m.queue_id.try_into().ok()?,
                                max_size: m.max_size,
                                current_depth_high_water: m.current_depth,
                                num_discards_high_water: m.num_discards,
                                average_delay_microseconds: micros(m.avg_delay)?,
                            })
                        })
                        .collect::<Option<Vec<_>>>()?,
                }
                .encode()?,
            )
        }
        105 => {
            let v = wire::RadioToRouterNeighborMetrics::decode(data).ok()?;
            (
                CONTROL_R2RI_NEIGHBOR_METRIC,
                R2riNeighborMetrics {
                    metrics: v
                        .metrics
                        .into_iter()
                        .map(|m| {
                            Some(R2riNeighborMetric {
                                nem_id: m.neighbor_id.try_into().ok()?,
                                num_rx_frames: m.num_rx_frames,
                                num_tx_frames: m.num_tx_frames,
                                num_missed_frames: m.num_missed_frames,
                                bandwidth_consumption_microseconds: micros(
                                    m.bandwidth_consumption,
                                )?,
                                sinr_average_db: m.sinr_average,
                                sinr_stddev: m.sinr_stddev,
                                noise_floor_average_dbm: m.noise_floor_avg,
                                noise_floor_stddev: m.noise_floor_stddev,
                                rx_average_data_rate_bps: m.rx_avg_data_ratebps,
                                tx_average_data_rate_bps: m.tx_avg_data_ratebps,
                            })
                        })
                        .collect::<Option<Vec<_>>>()?,
                }
                .encode()?,
            )
        }
        _ => (u32::from(id), data.to_vec()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn flow_control_uses_cpp_identifier_and_protobuf() {
        let native = FlowControlToken { tokens: 10 }.encode();
        assert_eq!(
            encode(CONTROL_FLOW_CONTROL_TOKEN, &native).unwrap(),
            Some((104, vec![8, 10]))
        );
        assert_eq!(
            decode(104, &[8, 10]),
            Some((CONTROL_FLOW_CONTROL_TOKEN, native.to_vec()))
        );
        assert_eq!(
            decode(104, &[8, 0xff, 0xff, 0xff, 0x7f]),
            Some((
                CONTROL_FLOW_CONTROL_TOKEN,
                FlowControlToken { tokens: u16::MAX }.encode().to_vec()
            ))
        );
        assert!(decode(104, &[]).is_none());
        assert!(decode(104, &[16, 2]).is_none());
        assert!(decode(104, &[8, 128]).is_none());
        assert_eq!(
            decode(104, &[8, 0]),
            Some((
                CONTROL_FLOW_CONTROL_TOKEN,
                FlowControlToken { tokens: 0 }.encode().to_vec()
            ))
        );
        assert!(encode(CONTROL_MODEL_HEADER, &[]).unwrap().is_none());
    }
    #[test]
    fn r2ri_uses_seconds_on_the_wire() {
        let self_metric = R2riSelfMetric {
            broadcast_data_rate_bps: 1_000_000,
            max_data_rate_bps: 2_000_000,
            report_interval_microseconds: 500_000,
        }
        .encode();
        let (id, bytes) = encode(CONTROL_R2RI_SELF_METRIC, &self_metric)
            .unwrap()
            .unwrap();
        assert_eq!(id, 107);
        assert_eq!(
            wire::RadioToRouterSelfMetric::decode(bytes.as_slice())
                .unwrap()
                .report_interval,
            0.5
        );
        assert_eq!(decode(id, &bytes).unwrap().1, self_metric);
        let native = R2riQueueMetrics {
            metrics: vec![R2riQueueMetric {
                queue_id: 2,
                max_size: 256,
                current_depth_high_water: 17,
                num_discards_high_water: 3,
                average_delay_microseconds: 125_000,
            }],
        }
        .encode()
        .unwrap();
        let (id, bytes) = encode(CONTROL_R2RI_QUEUE_METRIC, &native).unwrap().unwrap();
        assert_eq!(
            wire::RadioToRouterQueueMetrics::decode(bytes.as_slice())
                .unwrap()
                .metrics[0]
                .avg_delay,
            0.125
        );
        assert_eq!(decode(id, &bytes).unwrap().1, native);
    }
}
