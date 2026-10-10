pub mod numeric;
pub mod random;
pub mod spectrum;
pub use spectrum::*;
use std::collections::HashMap;
use std::ffi::CString;
use std::os::raw::{c_char, c_void};
use std::sync::{Mutex, OnceLock};

/// Native control-message identifiers used at the Rust MAC/PHY boundary.
/// Values live outside the legacy framework range and the payloads use an
/// explicitly versioned, big-endian wire format so they are also safe to
/// carry over OTA multicast.
pub const CONTROL_BYPASS_PHY: u32 = 0x454D_0014;
pub const CONTROL_TX_PROPERTIES: u32 = 0x454D_0001;
pub const CONTROL_RX_PROPERTIES: u32 = 0x454D_0002;
pub const CONTROL_MODEL_HEADER: u32 = 0x454D_0003;
pub const CONTROL_FREQUENCY_INTEREST: u32 = 0x454D_0004;
pub const CONTROL_COMM_EFFECT_HEADER: u32 = 0x454D_0005;
pub const CONTROL_TIMING_ANALYSIS_HEADER: u32 = 0x454D_0006;
pub const CONTROL_TX_FREQUENCY_SEGMENTS: u32 = 0x454D_0007;
pub const CONTROL_TX_TRANSMITTERS: u32 = 0x454D_0008;
pub const CONTROL_TX_ANTENNA_PROFILE: u32 = 0x454D_0009;
pub const CONTROL_RX_FREQUENCY_SEGMENTS: u32 = 0x454D_000A;
pub const CONTROL_FLOW_CONTROL_TOKEN: u32 = 0x454D_000B;
pub const CONTROL_MIMO_TX_PROPERTIES: u32 = 0x454D_000C;
pub const CONTROL_MIMO_RX_PROPERTIES: u32 = 0x454D_000D;
pub const CONTROL_R2RI_SELF_METRIC: u32 = 0x454D_000E;
pub const CONTROL_R2RI_QUEUE_METRIC: u32 = 0x454D_000F;
pub const CONTROL_R2RI_NEIGHBOR_METRIC: u32 = 0x454D_0010;
pub const CONTROL_RX_ANTENNA_ADD: u32 = 0x454D_0011;
pub const CONTROL_RX_ANTENNA_UPDATE: u32 = 0x454D_0012;
pub const CONTROL_RX_ANTENNA_REMOVE: u32 = 0x454D_0013;

pub const MAC_REGISTRATION_IEEE80211ABG: u16 = 0x0003;
pub const MAC_REGISTRATION_BYPASS: u16 = 0x0001;
pub const MAC_REGISTRATION_RFPIPE: u16 = 0x0004;
pub const MAC_REGISTRATION_TDMA: u16 = 0x0005;
pub const MAC_REGISTRATION_BENTPIPE: u16 = 0x0006;

pub const CONTROL_SPECTRUM_FILTER_ADD: u32 = 0x454D_0015;
pub const CONTROL_SPECTRUM_FILTER_REMOVE: u32 = 0x454D_0016;
pub const CONTROL_SPECTRUM_FILTER_DATA: u32 = 0x454D_0017;
pub const CONTROL_SELF_INTERFERENCE: u32 = 0x454D_0018;

const PROPERTIES_VERSION: u8 = 1;
const MIMO_TX_PROPERTIES_VERSION: u8 = 3;
const MIMO_RX_PROPERTIES_VERSION: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowControlToken {
    pub tokens: u16,
}

impl FlowControlToken {
    pub const ENCODED_LEN: usize = 3;

    pub fn encode(self) -> [u8; Self::ENCODED_LEN] {
        let mut data = [0u8; Self::ENCODED_LEN];
        data[0] = PROPERTIES_VERSION;
        put_u16(&mut data, 1, self.tokens);
        data
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        (data.len() == Self::ENCODED_LEN && data[0] == PROPERTIES_VERSION).then(|| Self {
            tokens: get_u16(data, 1),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct R2riSelfMetric {
    pub broadcast_data_rate_bps: u64,
    pub max_data_rate_bps: u64,
    pub report_interval_microseconds: u64,
}

impl R2riSelfMetric {
    pub const ENCODED_LEN: usize = 25;

    pub fn encode(self) -> [u8; Self::ENCODED_LEN] {
        let mut data = [0u8; Self::ENCODED_LEN];
        data[0] = PROPERTIES_VERSION;
        put_u64(&mut data, 1, self.broadcast_data_rate_bps);
        put_u64(&mut data, 9, self.max_data_rate_bps);
        put_u64(&mut data, 17, self.report_interval_microseconds);
        data
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        (data.len() == Self::ENCODED_LEN && data[0] == PROPERTIES_VERSION).then(|| Self {
            broadcast_data_rate_bps: get_u64(data, 1),
            max_data_rate_bps: get_u64(data, 9),
            report_interval_microseconds: get_u64(data, 17),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct R2riQueueMetric {
    pub queue_id: u16,
    pub max_size: u32,
    pub current_depth_high_water: u32,
    pub num_discards_high_water: u32,
    pub average_delay_microseconds: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R2riQueueMetrics {
    pub metrics: Vec<R2riQueueMetric>,
}

impl R2riQueueMetrics {
    const ENTRY_LEN: usize = 22;

    pub fn encode(&self) -> Option<Vec<u8>> {
        let count = u16::try_from(self.metrics.len()).ok()?;
        let mut data = Vec::with_capacity(3 + self.metrics.len() * Self::ENTRY_LEN);
        data.push(PROPERTIES_VERSION);
        data.extend_from_slice(&count.to_be_bytes());
        for metric in &self.metrics {
            data.extend_from_slice(&metric.queue_id.to_be_bytes());
            data.extend_from_slice(&metric.max_size.to_be_bytes());
            data.extend_from_slice(&metric.current_depth_high_water.to_be_bytes());
            data.extend_from_slice(&metric.num_discards_high_water.to_be_bytes());
            data.extend_from_slice(&metric.average_delay_microseconds.to_be_bytes());
        }
        Some(data)
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 3 || data[0] != PROPERTIES_VERSION {
            return None;
        }
        let count = usize::from(get_u16(data, 1));
        if data.len() != 3usize.checked_add(count.checked_mul(Self::ENTRY_LEN)?)? {
            return None;
        }
        let metrics = (0..count)
            .map(|index| {
                let offset = 3 + index * Self::ENTRY_LEN;
                R2riQueueMetric {
                    queue_id: get_u16(data, offset),
                    max_size: get_u32(data, offset + 2),
                    current_depth_high_water: get_u32(data, offset + 6),
                    num_discards_high_water: get_u32(data, offset + 10),
                    average_delay_microseconds: get_u64(data, offset + 14),
                }
            })
            .collect();
        Some(Self { metrics })
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct R2riNeighborMetric {
    pub nem_id: u16,
    pub num_rx_frames: u64,
    pub num_tx_frames: u64,
    pub num_missed_frames: u64,
    pub bandwidth_consumption_microseconds: u64,
    pub sinr_average_db: f32,
    pub sinr_stddev: f32,
    pub noise_floor_average_dbm: f32,
    pub noise_floor_stddev: f32,
    pub rx_average_data_rate_bps: u64,
    pub tx_average_data_rate_bps: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct R2riNeighborMetrics {
    pub metrics: Vec<R2riNeighborMetric>,
}

impl R2riNeighborMetrics {
    const ENTRY_LEN: usize = 66;

    pub fn encode(&self) -> Option<Vec<u8>> {
        let count = u16::try_from(self.metrics.len()).ok()?;
        if self.metrics.iter().any(|metric| {
            !metric.sinr_average_db.is_finite()
                || !metric.sinr_stddev.is_finite()
                || !metric.noise_floor_average_dbm.is_finite()
                || !metric.noise_floor_stddev.is_finite()
        }) {
            return None;
        }
        let mut data = Vec::with_capacity(3 + self.metrics.len() * Self::ENTRY_LEN);
        data.push(PROPERTIES_VERSION);
        data.extend_from_slice(&count.to_be_bytes());
        for metric in &self.metrics {
            data.extend_from_slice(&metric.nem_id.to_be_bytes());
            data.extend_from_slice(&metric.num_rx_frames.to_be_bytes());
            data.extend_from_slice(&metric.num_tx_frames.to_be_bytes());
            data.extend_from_slice(&metric.num_missed_frames.to_be_bytes());
            data.extend_from_slice(&metric.bandwidth_consumption_microseconds.to_be_bytes());
            data.extend_from_slice(&metric.sinr_average_db.to_bits().to_be_bytes());
            data.extend_from_slice(&metric.sinr_stddev.to_bits().to_be_bytes());
            data.extend_from_slice(&metric.noise_floor_average_dbm.to_bits().to_be_bytes());
            data.extend_from_slice(&metric.noise_floor_stddev.to_bits().to_be_bytes());
            data.extend_from_slice(&metric.rx_average_data_rate_bps.to_be_bytes());
            data.extend_from_slice(&metric.tx_average_data_rate_bps.to_be_bytes());
        }
        Some(data)
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 3 || data[0] != PROPERTIES_VERSION {
            return None;
        }
        let count = usize::from(get_u16(data, 1));
        if data.len() != 3usize.checked_add(count.checked_mul(Self::ENTRY_LEN)?)? {
            return None;
        }
        let metrics = (0..count)
            .map(|index| {
                let offset = 3 + index * Self::ENTRY_LEN;
                R2riNeighborMetric {
                    nem_id: get_u16(data, offset),
                    num_rx_frames: get_u64(data, offset + 2),
                    num_tx_frames: get_u64(data, offset + 10),
                    num_missed_frames: get_u64(data, offset + 18),
                    bandwidth_consumption_microseconds: get_u64(data, offset + 26),
                    sinr_average_db: f32::from_bits(get_u32(data, offset + 34)),
                    sinr_stddev: f32::from_bits(get_u32(data, offset + 38)),
                    noise_floor_average_dbm: f32::from_bits(get_u32(data, offset + 42)),
                    noise_floor_stddev: f32::from_bits(get_u32(data, offset + 46)),
                    rx_average_data_rate_bps: get_u64(data, offset + 50),
                    tx_average_data_rate_bps: get_u64(data, offset + 58),
                }
            })
            .collect::<Vec<_>>();
        (!metrics.iter().any(|metric| {
            !metric.sinr_average_db.is_finite()
                || !metric.sinr_stddev.is_finite()
                || !metric.noise_floor_average_dbm.is_finite()
                || !metric.noise_floor_stddev.is_finite()
        }))
        .then_some(Self { metrics })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommEffectHeader {
    pub group_id: u32,
    pub sequence: u32,
    pub tx_time_microseconds: i64,
}

impl CommEffectHeader {
    pub const ENCODED_LEN: usize = 17;

    pub fn encode(self) -> [u8; Self::ENCODED_LEN] {
        let mut data = [0u8; Self::ENCODED_LEN];
        data[0] = PROPERTIES_VERSION;
        data[1..5].copy_from_slice(&self.group_id.to_be_bytes());
        data[5..9].copy_from_slice(&self.sequence.to_be_bytes());
        data[9..17].copy_from_slice(&(self.tx_time_microseconds as u64).to_be_bytes());
        data
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        (data.len() == Self::ENCODED_LEN && data[0] == PROPERTIES_VERSION).then(|| Self {
            group_id: u32::from_be_bytes(data[1..5].try_into().unwrap()),
            sequence: u32::from_be_bytes(data[5..9].try_into().unwrap()),
            tx_time_microseconds: u64::from_be_bytes(data[9..17].try_into().unwrap()) as i64,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimingAnalysisHeader {
    pub tx_time_microseconds: u64,
    pub source: u16,
    pub packet_id: u16,
}

impl TimingAnalysisHeader {
    pub const ENCODED_LEN: usize = 13;

    pub fn encode(self) -> [u8; Self::ENCODED_LEN] {
        let mut data = [0u8; Self::ENCODED_LEN];
        data[0] = PROPERTIES_VERSION;
        data[1..9].copy_from_slice(&self.tx_time_microseconds.to_be_bytes());
        data[9..11].copy_from_slice(&self.source.to_be_bytes());
        data[11..13].copy_from_slice(&self.packet_id.to_be_bytes());
        data
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        (data.len() == Self::ENCODED_LEN && data[0] == PROPERTIES_VERSION).then(|| Self {
            tx_time_microseconds: u64::from_be_bytes(data[1..9].try_into().unwrap()),
            source: u16::from_be_bytes(data[9..11].try_into().unwrap()),
            packet_id: u16::from_be_bytes(data[11..13].try_into().unwrap()),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrequencyOfInterest {
    pub bandwidth_hz: u64,
    pub frequencies_hz: Vec<u64>,
}

impl FrequencyOfInterest {
    pub fn encode(&self) -> Option<Vec<u8>> {
        let count = u16::try_from(self.frequencies_hz.len()).ok()?;
        if self.bandwidth_hz == 0 || count == 0 || self.frequencies_hz.contains(&0) {
            return None;
        }
        let mut data = Vec::with_capacity(11 + self.frequencies_hz.len() * 8);
        data.push(PROPERTIES_VERSION);
        data.extend_from_slice(&count.to_be_bytes());
        data.extend_from_slice(&self.bandwidth_hz.to_be_bytes());
        for frequency in &self.frequencies_hz {
            data.extend_from_slice(&frequency.to_be_bytes());
        }
        Some(data)
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 19 || data[0] != PROPERTIES_VERSION {
            return None;
        }
        let count = get_u16(data, 1) as usize;
        if count == 0 || data.len() != 11usize.checked_add(count.checked_mul(8)?)? {
            return None;
        }
        let bandwidth_hz = get_u64(data, 3);
        let frequencies_hz: Vec<_> = (0..count)
            .map(|index| get_u64(data, 11 + index * 8))
            .collect();
        (!frequencies_hz.contains(&0)).then_some(Self {
            bandwidth_hz,
            frequencies_hz,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxFrequencySegment {
    pub frequency_hz: u64,
    pub duration_microseconds: u64,
    pub offset_microseconds: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxFrequencySegments {
    pub segments: Vec<TxFrequencySegment>,
}

impl TxFrequencySegments {
    const ENTRY_LEN: usize = 24;

    pub fn encode(&self) -> Option<Vec<u8>> {
        let count = u16::try_from(self.segments.len()).ok()?;
        if count == 0 {
            return None;
        }
        let mut data = Vec::with_capacity(3 + self.segments.len() * Self::ENTRY_LEN);
        data.push(PROPERTIES_VERSION);
        data.extend_from_slice(&count.to_be_bytes());
        for segment in &self.segments {
            data.extend_from_slice(&segment.frequency_hz.to_be_bytes());
            data.extend_from_slice(&segment.duration_microseconds.to_be_bytes());
            data.extend_from_slice(&segment.offset_microseconds.to_be_bytes());
        }
        Some(data)
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 3 || data[0] != PROPERTIES_VERSION {
            return None;
        }
        let count = get_u16(data, 1) as usize;
        if count == 0 || data.len() != 3usize.checked_add(count.checked_mul(Self::ENTRY_LEN)?)? {
            return None;
        }
        let segments = (0..count)
            .map(|index| {
                let offset = 3 + index * Self::ENTRY_LEN;
                TxFrequencySegment {
                    frequency_hz: get_u64(data, offset),
                    duration_microseconds: get_u64(data, offset + 8),
                    offset_microseconds: get_u64(data, offset + 16),
                }
            })
            .collect::<Vec<_>>();
        Some(Self { segments })
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RxFrequencySegment {
    pub frequency_hz: u64,
    pub rx_power_dbm: f64,
    pub duration_microseconds: u64,
    pub offset_microseconds: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RxFrequencySegments {
    pub segments: Vec<RxFrequencySegment>,
}

impl RxFrequencySegments {
    const ENTRY_LEN: usize = 32;

    pub fn encode(&self) -> Option<Vec<u8>> {
        let count = u16::try_from(self.segments.len()).ok()?;
        if count == 0
            || self
                .segments
                .iter()
                .any(|segment| !segment.rx_power_dbm.is_finite())
        {
            return None;
        }
        let mut data = Vec::with_capacity(3 + self.segments.len() * Self::ENTRY_LEN);
        data.push(PROPERTIES_VERSION);
        data.extend_from_slice(&count.to_be_bytes());
        for segment in &self.segments {
            data.extend_from_slice(&segment.frequency_hz.to_be_bytes());
            data.extend_from_slice(&segment.rx_power_dbm.to_bits().to_be_bytes());
            data.extend_from_slice(&segment.duration_microseconds.to_be_bytes());
            data.extend_from_slice(&segment.offset_microseconds.to_be_bytes());
        }
        Some(data)
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 3 || data[0] != PROPERTIES_VERSION {
            return None;
        }
        let count = get_u16(data, 1) as usize;
        if count == 0 || data.len() != 3usize.checked_add(count.checked_mul(Self::ENTRY_LEN)?)? {
            return None;
        }
        let segments = (0..count)
            .map(|index| {
                let offset = 3 + index * Self::ENTRY_LEN;
                RxFrequencySegment {
                    frequency_hz: get_u64(data, offset),
                    rx_power_dbm: f64::from_bits(get_u64(data, offset + 8)),
                    duration_microseconds: get_u64(data, offset + 16),
                    offset_microseconds: get_u64(data, offset + 24),
                }
            })
            .collect::<Vec<_>>();
        (!segments
            .iter()
            .any(|segment| !segment.rx_power_dbm.is_finite()))
        .then_some(Self { segments })
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TxTransmitter {
    pub nem_id: u16,
    pub tx_power_dbm: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct TxTransmitters {
    pub transmitters: Vec<TxTransmitter>,
}

impl TxTransmitters {
    const ENTRY_LEN: usize = 10;

    pub fn encode(&self) -> Option<Vec<u8>> {
        let count = u16::try_from(self.transmitters.len()).ok()?;
        if count == 0
            || self
                .transmitters
                .iter()
                .any(|transmitter| transmitter.nem_id == 0 || !transmitter.tx_power_dbm.is_finite())
        {
            return None;
        }
        let mut data = Vec::with_capacity(3 + self.transmitters.len() * Self::ENTRY_LEN);
        data.push(PROPERTIES_VERSION);
        data.extend_from_slice(&count.to_be_bytes());
        for transmitter in &self.transmitters {
            data.extend_from_slice(&transmitter.nem_id.to_be_bytes());
            data.extend_from_slice(&transmitter.tx_power_dbm.to_bits().to_be_bytes());
        }
        Some(data)
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 3 || data[0] != PROPERTIES_VERSION {
            return None;
        }
        let count = get_u16(data, 1) as usize;
        if count == 0 || data.len() != 3usize.checked_add(count.checked_mul(Self::ENTRY_LEN)?)? {
            return None;
        }
        let transmitters = (0..count)
            .map(|index| {
                let offset = 3 + index * Self::ENTRY_LEN;
                TxTransmitter {
                    nem_id: get_u16(data, offset),
                    tx_power_dbm: f64::from_bits(get_u64(data, offset + 2)),
                }
            })
            .collect::<Vec<_>>();
        (!transmitters
            .iter()
            .any(|transmitter| transmitter.nem_id == 0 || !transmitter.tx_power_dbm.is_finite()))
        .then_some(Self { transmitters })
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TxAntennaProfile {
    pub profile_id: u16,
    pub azimuth_degrees: f64,
    pub elevation_degrees: f64,
}

impl TxAntennaProfile {
    pub const ENCODED_LEN: usize = 19;

    pub fn encode(self) -> Option<[u8; Self::ENCODED_LEN]> {
        if self.profile_id == 0
            || !self.azimuth_degrees.is_finite()
            || !(0.0..=360.0).contains(&self.azimuth_degrees)
            || !self.elevation_degrees.is_finite()
            || !(-90.0..=90.0).contains(&self.elevation_degrees)
        {
            return None;
        }
        let mut data = [0u8; Self::ENCODED_LEN];
        data[0] = PROPERTIES_VERSION;
        put_u16(&mut data, 1, self.profile_id);
        put_u64(&mut data, 3, self.azimuth_degrees.to_bits());
        put_u64(&mut data, 11, self.elevation_degrees.to_bits());
        Some(data)
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() != Self::ENCODED_LEN || data[0] != PROPERTIES_VERSION {
            return None;
        }
        let result = Self {
            profile_id: get_u16(data, 1),
            azimuth_degrees: f64::from_bits(get_u64(data, 3)),
            elevation_degrees: f64::from_bits(get_u64(data, 11)),
        };
        (result.profile_id != 0
            && result.azimuth_degrees.is_finite()
            && (0.0..=360.0).contains(&result.azimuth_degrees)
            && result.elevation_degrees.is_finite()
            && (-90.0..=90.0).contains(&result.elevation_degrees))
        .then_some(result)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MimoTxFrequencySegment {
    pub frequency_hz: u64,
    /// None uses each collaborating transmitter's own power.
    pub tx_power_dbm: Option<f64>,
    pub duration_microseconds: u64,
    pub offset_microseconds: u64,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MimoTxAntenna {
    pub frequency_group_index: u16,
    pub antenna_index: u16,
    pub bandwidth_hz: u64,
    pub spectral_mask_index: u16,
    pub pattern: AntennaPattern,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AntennaPattern {
    Default,
    IdealOmni { gain_db: f64 },
    Profile(TxAntennaProfile),
}

impl AntennaPattern {
    const ENCODED_LEN: usize = 27;

    fn encode(self, data: &mut Vec<u8>) -> Option<()> {
        let (kind, gain, profile_id, azimuth, elevation) = match self {
            Self::Default => (0, 0.0, 0, 0.0, 0.0),
            Self::IdealOmni { gain_db } if gain_db.is_finite() => (1, gain_db, 0, 0.0, 0.0),
            Self::Profile(profile) if profile.encode().is_some() => (
                2,
                0.0,
                profile.profile_id,
                profile.azimuth_degrees,
                profile.elevation_degrees,
            ),
            _ => return None,
        };
        data.push(kind);
        data.extend_from_slice(&gain.to_bits().to_be_bytes());
        data.extend_from_slice(&profile_id.to_be_bytes());
        data.extend_from_slice(&azimuth.to_bits().to_be_bytes());
        data.extend_from_slice(&elevation.to_bits().to_be_bytes());
        Some(())
    }

    fn decode(data: &[u8], offset: &mut usize) -> Option<Self> {
        let kind = *data.get(*offset)?;
        *offset += 1;
        let gain_db = f64::from_bits(read_u64(data, offset)?);
        let profile_id = read_u16(data, offset)?;
        let azimuth_degrees = f64::from_bits(read_u64(data, offset)?);
        let elevation_degrees = f64::from_bits(read_u64(data, offset)?);
        match kind {
            0 => Some(Self::Default),
            1 if gain_db.is_finite() => Some(Self::IdealOmni { gain_db }),
            2 => {
                let profile = TxAntennaProfile {
                    profile_id,
                    azimuth_degrees,
                    elevation_degrees,
                };
                profile.encode().map(|_| Self::Profile(profile))
            }
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct MimoTxProperties {
    pub frequency_groups: Vec<Vec<MimoTxFrequencySegment>>,
    pub transmit_antennas: Vec<MimoTxAntenna>,
}

impl MimoTxProperties {
    const SEGMENT_LEN: usize = 33;
    const ANTENNA_LEN: usize = 14 + AntennaPattern::ENCODED_LEN;

    pub fn encode(&self) -> Option<Vec<u8>> {
        let group_count = u16::try_from(self.frequency_groups.len()).ok()?;
        let antenna_count = u16::try_from(self.transmit_antennas.len()).ok()?;
        if group_count == 0
            || antenna_count == 0
            || self.frequency_groups.iter().any(|group| {
                group.is_empty()
                    || group.len() > usize::from(u16::MAX)
                    || group
                        .iter()
                        .any(|segment| segment.tx_power_dbm.is_some_and(|power| !power.is_finite()))
            })
        {
            return None;
        }
        let segment_count = self.frequency_groups.iter().map(Vec::len).sum::<usize>();
        let capacity = 5usize
            .checked_add(self.frequency_groups.len().checked_mul(2)?)?
            .checked_add(segment_count.checked_mul(Self::SEGMENT_LEN)?)?
            .checked_add(
                self.transmit_antennas
                    .len()
                    .checked_mul(Self::ANTENNA_LEN)?,
            )?;
        let mut data = Vec::with_capacity(capacity);
        data.push(MIMO_TX_PROPERTIES_VERSION);
        data.extend_from_slice(&group_count.to_be_bytes());
        for group in &self.frequency_groups {
            data.extend_from_slice(&u16::try_from(group.len()).ok()?.to_be_bytes());
            for segment in group {
                data.extend_from_slice(&segment.frequency_hz.to_be_bytes());
                data.push(u8::from(segment.tx_power_dbm.is_some()));
                data.extend_from_slice(
                    &segment.tx_power_dbm.unwrap_or(0.0).to_bits().to_be_bytes(),
                );
                data.extend_from_slice(&segment.duration_microseconds.to_be_bytes());
                data.extend_from_slice(&segment.offset_microseconds.to_be_bytes());
            }
        }
        data.extend_from_slice(&antenna_count.to_be_bytes());
        for antenna in &self.transmit_antennas {
            data.extend_from_slice(&antenna.frequency_group_index.to_be_bytes());
            data.extend_from_slice(&antenna.antenna_index.to_be_bytes());
            data.extend_from_slice(&antenna.bandwidth_hz.to_be_bytes());
            data.extend_from_slice(&antenna.spectral_mask_index.to_be_bytes());
            antenna.pattern.encode(&mut data)?;
        }
        Some(data)
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 5 || data[0] != MIMO_TX_PROPERTIES_VERSION {
            return None;
        }
        let group_count = usize::from(get_u16(data, 1));
        if group_count == 0 {
            return None;
        }
        let mut offset = 3usize;
        let mut frequency_groups = Vec::with_capacity(group_count);
        for _ in 0..group_count {
            let count = usize::from(read_u16(data, &mut offset)?);
            if count == 0 {
                return None;
            }
            let end = offset.checked_add(count.checked_mul(Self::SEGMENT_LEN)?)?;
            if end > data.len() {
                return None;
            }
            let mut group = Vec::with_capacity(count);
            for _ in 0..count {
                group.push(MimoTxFrequencySegment {
                    frequency_hz: read_u64(data, &mut offset)?,
                    tx_power_dbm: {
                        let present = *data.get(offset)?;
                        offset += 1;
                        let power = f64::from_bits(read_u64(data, &mut offset)?);
                        match present {
                            0 => None,
                            1 => Some(power),
                            _ => return None,
                        }
                    },
                    duration_microseconds: read_u64(data, &mut offset)?,
                    offset_microseconds: read_u64(data, &mut offset)?,
                });
            }
            frequency_groups.push(group);
        }
        let antenna_count = usize::from(read_u16(data, &mut offset)?);
        if antenna_count == 0
            || data.len() != offset.checked_add(antenna_count.checked_mul(Self::ANTENNA_LEN)?)?
        {
            return None;
        }
        let mut transmit_antennas = Vec::with_capacity(antenna_count);
        for _ in 0..antenna_count {
            transmit_antennas.push(MimoTxAntenna {
                frequency_group_index: read_u16(data, &mut offset)?,
                antenna_index: read_u16(data, &mut offset)?,
                bandwidth_hz: read_u64(data, &mut offset)?,
                spectral_mask_index: read_u16(data, &mut offset)?,
                pattern: AntennaPattern::decode(data, &mut offset)?,
            });
        }
        let result = Self {
            frequency_groups,
            transmit_antennas,
        };
        // A frequency-group index is a semantic property of the PHY message,
        // not a wire-format constraint.  Keep an invalid index available to
        // the receive path so it can account for the legacy "Antenna Freq"
        // drop instead of treating the MIMO control as if it were absent.
        result
            .frequency_groups
            .iter()
            .flatten()
            .all(|segment| segment.tx_power_dbm.is_none_or(f64::is_finite))
            .then_some(result)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct RxAntennaAdd {
    pub antenna: MimoTxAntenna,
    pub frequencies_hz: Vec<u64>,
}

impl RxAntennaAdd {
    pub fn encode(&self) -> Option<Vec<u8>> {
        let count = u16::try_from(self.frequencies_hz.len()).ok()?;
        if self.frequencies_hz.contains(&0) {
            return None;
        }
        let mut data =
            Vec::with_capacity(17 + AntennaPattern::ENCODED_LEN + 8 * usize::from(count));
        data.push(PROPERTIES_VERSION);
        data.extend_from_slice(&self.antenna.antenna_index.to_be_bytes());
        data.extend_from_slice(&self.antenna.bandwidth_hz.to_be_bytes());
        data.extend_from_slice(&self.antenna.spectral_mask_index.to_be_bytes());
        self.antenna.pattern.encode(&mut data)?;
        data.extend_from_slice(&count.to_be_bytes());
        for frequency in &self.frequencies_hz {
            data.extend_from_slice(&frequency.to_be_bytes());
        }
        Some(data)
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.first().copied() != Some(PROPERTIES_VERSION) {
            return None;
        }
        let mut offset = 1;
        let antenna_index = read_u16(data, &mut offset)?;
        let bandwidth_hz = read_u64(data, &mut offset)?;
        let spectral_mask_index = read_u16(data, &mut offset)?;
        let pattern = AntennaPattern::decode(data, &mut offset)?;
        let count = usize::from(read_u16(data, &mut offset)?);
        if data.len() != offset.checked_add(count.checked_mul(8)?)? {
            return None;
        }
        let frequencies_hz = (0..count)
            .map(|_| read_u64(data, &mut offset))
            .collect::<Option<Vec<_>>>()?;
        (!frequencies_hz.contains(&0)).then_some(Self {
            antenna: MimoTxAntenna {
                frequency_group_index: 0,
                antenna_index,
                bandwidth_hz,
                spectral_mask_index,
                pattern,
            },
            frequencies_hz,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RxAntennaRemove {
    pub antenna_index: u16,
}

impl RxAntennaRemove {
    pub fn encode(self) -> [u8; 3] {
        [
            PROPERTIES_VERSION,
            (self.antenna_index >> 8) as u8,
            self.antenna_index as u8,
        ]
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        (data.len() == 3 && data[0] == PROPERTIES_VERSION).then(|| Self {
            antenna_index: get_u16(data, 1),
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct MimoRxAntennaInfo {
    pub receive_antenna_index: u16,
    pub transmit_antenna_index: u16,
    pub span_microseconds: u64,
    pub receiver_sensitivity_dbm: f64,
    pub noise_floor_dbm: f64,
    pub segments: Vec<RxFrequencySegment>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct MimoRxProperties {
    pub tx_time_microseconds: i64,
    pub propagation_microseconds: u64,
    pub antenna_infos: Vec<MimoRxAntennaInfo>,
    pub doppler_shifts_hz: Vec<(u64, i64)>,
}

impl MimoRxProperties {
    const INFO_LEN: usize = 30;
    const SEGMENT_LEN: usize = 32;
    const DOPPLER_LEN: usize = 16;

    pub fn encode(&self) -> Option<Vec<u8>> {
        let info_count = u16::try_from(self.antenna_infos.len()).ok()?;
        let doppler_count = u16::try_from(self.doppler_shifts_hz.len()).ok()?;
        if info_count == 0
            || self.antenna_infos.iter().any(|info| {
                info.segments.is_empty()
                    || info.segments.len() > usize::from(u16::MAX)
                    || !info.receiver_sensitivity_dbm.is_finite()
                    || !info.noise_floor_dbm.is_finite()
                    || info
                        .segments
                        .iter()
                        .any(|segment| !segment.rx_power_dbm.is_finite())
            })
        {
            return None;
        }
        let segment_count = self
            .antenna_infos
            .iter()
            .map(|info| info.segments.len())
            .sum::<usize>();
        let capacity = 21usize
            .checked_add(self.antenna_infos.len().checked_mul(Self::INFO_LEN)?)?
            .checked_add(segment_count.checked_mul(Self::SEGMENT_LEN)?)?
            .checked_add(
                self.doppler_shifts_hz
                    .len()
                    .checked_mul(Self::DOPPLER_LEN)?,
            )?;
        let mut data = Vec::with_capacity(capacity);
        data.push(MIMO_RX_PROPERTIES_VERSION);
        data.extend_from_slice(&(self.tx_time_microseconds as u64).to_be_bytes());
        data.extend_from_slice(&self.propagation_microseconds.to_be_bytes());
        data.extend_from_slice(&info_count.to_be_bytes());
        for info in &self.antenna_infos {
            data.extend_from_slice(&info.receive_antenna_index.to_be_bytes());
            data.extend_from_slice(&info.transmit_antenna_index.to_be_bytes());
            data.extend_from_slice(&info.span_microseconds.to_be_bytes());
            data.extend_from_slice(&info.receiver_sensitivity_dbm.to_bits().to_be_bytes());
            data.extend_from_slice(&info.noise_floor_dbm.to_bits().to_be_bytes());
            data.extend_from_slice(&u16::try_from(info.segments.len()).ok()?.to_be_bytes());
            for segment in &info.segments {
                data.extend_from_slice(&segment.frequency_hz.to_be_bytes());
                data.extend_from_slice(&segment.rx_power_dbm.to_bits().to_be_bytes());
                data.extend_from_slice(&segment.duration_microseconds.to_be_bytes());
                data.extend_from_slice(&segment.offset_microseconds.to_be_bytes());
            }
        }
        data.extend_from_slice(&doppler_count.to_be_bytes());
        for (frequency_hz, shift_hz) in &self.doppler_shifts_hz {
            data.extend_from_slice(&frequency_hz.to_be_bytes());
            data.extend_from_slice(&(*shift_hz as u64).to_be_bytes());
        }
        Some(data)
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 21 || data[0] != MIMO_RX_PROPERTIES_VERSION {
            return None;
        }
        let mut offset = 1usize;
        let tx_time_microseconds = read_u64(data, &mut offset)? as i64;
        let propagation_microseconds = read_u64(data, &mut offset)?;
        let info_count = usize::from(read_u16(data, &mut offset)?);
        if info_count == 0 {
            return None;
        }
        let mut antenna_infos = Vec::with_capacity(info_count);
        for _ in 0..info_count {
            let receive_antenna_index = read_u16(data, &mut offset)?;
            let transmit_antenna_index = read_u16(data, &mut offset)?;
            let span_microseconds = read_u64(data, &mut offset)?;
            let receiver_sensitivity_dbm = f64::from_bits(read_u64(data, &mut offset)?);
            let noise_floor_dbm = f64::from_bits(read_u64(data, &mut offset)?);
            let count = usize::from(read_u16(data, &mut offset)?);
            if count == 0 {
                return None;
            }
            let mut segments = Vec::with_capacity(count);
            for _ in 0..count {
                segments.push(RxFrequencySegment {
                    frequency_hz: read_u64(data, &mut offset)?,
                    rx_power_dbm: f64::from_bits(read_u64(data, &mut offset)?),
                    duration_microseconds: read_u64(data, &mut offset)?,
                    offset_microseconds: read_u64(data, &mut offset)?,
                });
            }
            antenna_infos.push(MimoRxAntennaInfo {
                receive_antenna_index,
                transmit_antenna_index,
                span_microseconds,
                receiver_sensitivity_dbm,
                noise_floor_dbm,
                segments,
            });
        }
        let doppler_count = usize::from(read_u16(data, &mut offset)?);
        if data.len() != offset.checked_add(doppler_count.checked_mul(Self::DOPPLER_LEN)?)? {
            return None;
        }
        let mut doppler_shifts_hz = Vec::with_capacity(doppler_count);
        for _ in 0..doppler_count {
            doppler_shifts_hz.push((
                read_u64(data, &mut offset)?,
                read_u64(data, &mut offset)? as i64,
            ));
        }
        let result = Self {
            tx_time_microseconds,
            propagation_microseconds,
            antenna_infos,
            doppler_shifts_hz,
        };
        result.encode().map(|_| result)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModelHeader {
    pub registration_id: u16,
    pub sequence: u64,
    pub data_rate_bps: u64,
    pub category: u8,
    pub message_type: u8,
    pub flags: u16,
}

impl ModelHeader {
    pub const ENCODED_LEN: usize = 24;

    pub fn encode(self) -> [u8; Self::ENCODED_LEN] {
        let mut data = [0u8; Self::ENCODED_LEN];
        data[0] = PROPERTIES_VERSION;
        put_u16(&mut data, 1, self.registration_id);
        put_u64(&mut data, 3, self.sequence);
        put_u64(&mut data, 11, self.data_rate_bps);
        data[19] = self.category;
        data[20] = self.message_type;
        put_u16(&mut data, 21, self.flags);
        data
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        (data.len() >= Self::ENCODED_LEN && data[0] == PROPERTIES_VERSION).then(|| Self {
            registration_id: get_u16(data, 1),
            sequence: get_u64(data, 3),
            data_rate_bps: get_u64(data, 11),
            category: data[19],
            message_type: data[20],
            flags: get_u16(data, 21),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TxProperties {
    pub frequency_hz: u64,
    pub bandwidth_hz: u64,
    pub tx_power_dbm: f64,
    pub duration_microseconds: u64,
    pub offset_microseconds: u64,
    pub tx_time_microseconds: i64,
    pub antenna_index: u16,
    pub spectral_mask_index: u16,
    pub sub_id: u16,
}

impl TxProperties {
    pub const ENCODED_LEN: usize = 55;

    pub fn encode(self) -> [u8; Self::ENCODED_LEN] {
        let mut data = [0u8; Self::ENCODED_LEN];
        data[0] = PROPERTIES_VERSION;
        put_u64(&mut data, 1, self.frequency_hz);
        put_u64(&mut data, 9, self.bandwidth_hz);
        put_u64(&mut data, 17, self.tx_power_dbm.to_bits());
        put_u64(&mut data, 25, self.duration_microseconds);
        put_u64(&mut data, 33, self.offset_microseconds);
        put_u64(&mut data, 41, self.tx_time_microseconds as u64);
        put_u16(&mut data, 49, self.antenna_index);
        put_u16(&mut data, 51, self.spectral_mask_index);
        put_u16(&mut data, 53, self.sub_id);
        data
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        (data.len() == Self::ENCODED_LEN && data[0] == PROPERTIES_VERSION).then(|| Self {
            frequency_hz: get_u64(data, 1),
            bandwidth_hz: get_u64(data, 9),
            tx_power_dbm: f64::from_bits(get_u64(data, 17)),
            duration_microseconds: get_u64(data, 25),
            offset_microseconds: get_u64(data, 33),
            tx_time_microseconds: get_u64(data, 41) as i64,
            antenna_index: get_u16(data, 49),
            spectral_mask_index: get_u16(data, 51),
            sub_id: get_u16(data, 53),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RxProperties {
    pub frequency_hz: u64,
    pub bandwidth_hz: u64,
    pub rx_power_dbm: f64,
    pub noise_floor_dbm: f64,
    pub tx_time_microseconds: i64,
    pub propagation_microseconds: u64,
    pub duration_microseconds: u64,
    pub antenna_index: u16,
    pub sub_id: u16,
    pub signal_in_noise: bool,
}

impl RxProperties {
    pub const ENCODED_LEN: usize = 63;

    pub fn encode(self) -> [u8; Self::ENCODED_LEN] {
        let mut data = [0u8; Self::ENCODED_LEN];
        data[0] = PROPERTIES_VERSION;
        put_u64(&mut data, 1, self.frequency_hz);
        put_u64(&mut data, 9, self.bandwidth_hz);
        put_u64(&mut data, 17, self.rx_power_dbm.to_bits());
        put_u64(&mut data, 25, self.noise_floor_dbm.to_bits());
        put_u64(&mut data, 33, self.tx_time_microseconds as u64);
        put_u64(&mut data, 41, self.propagation_microseconds);
        put_u64(&mut data, 49, self.duration_microseconds);
        put_u16(&mut data, 57, self.antenna_index);
        put_u16(&mut data, 59, self.sub_id);
        data[61] = u8::from(self.signal_in_noise);
        // Byte 62 is reserved for compatible extension.
        data
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        (data.len() == Self::ENCODED_LEN && data[0] == PROPERTIES_VERSION && data[61] <= 1).then(
            || Self {
                frequency_hz: get_u64(data, 1),
                bandwidth_hz: get_u64(data, 9),
                rx_power_dbm: f64::from_bits(get_u64(data, 17)),
                noise_floor_dbm: f64::from_bits(get_u64(data, 25)),
                tx_time_microseconds: get_u64(data, 33) as i64,
                propagation_microseconds: get_u64(data, 41),
                duration_microseconds: get_u64(data, 49),
                antenna_index: get_u16(data, 57),
                sub_id: get_u16(data, 59),
                signal_in_noise: data[61] != 0,
            },
        )
    }
}

fn put_u16(data: &mut [u8], offset: usize, value: u16) {
    data[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

fn put_u64(data: &mut [u8], offset: usize, value: u64) {
    data[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}

fn get_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(data[offset..offset + 2].try_into().unwrap())
}

fn get_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap())
}

fn get_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(data[offset..offset + 8].try_into().unwrap())
}

fn read_u16(data: &[u8], offset: &mut usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let value = u16::from_be_bytes(data.get(*offset..end)?.try_into().ok()?);
    *offset = end;
    Some(value)
}

fn read_u64(data: &[u8], offset: &mut usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    let value = u64::from_be_bytes(data.get(*offset..end)?.try_into().ok()?);
    *offset = end;
    Some(value)
}

// Version 2 made configuration and start failures explicit. Version 3 adds
// framework event delivery. Version 4 adds native statistics, version 5 adds
// R2RI metrics, version 6 adds native RF tables and event publication, and
// version 7 adds the framework file-descriptor service. Version 8 adds native
// floating-point statistics. Version 10 adds typed native statistic tables;
// version 11 lets their owners clear rows when model state is replaced;
// version 12 adds removal of individual table rows.
// Version 15 preserves packet UUIDs through reception and neighbor metrics.
// Version 16 exposes spectrum filter windows.
// Version 17 preserves optional MIMO segment powers. Rebuild core and plugins together.
pub const PLUGIN_ABI_VERSION: u32 = 17;

pub const STATISTIC_VALUE_U64: u32 = 1;
pub const STATISTIC_VALUE_F64: u32 = 2;
pub const STATISTIC_VALUE_STRING: u32 = 3;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FfiStatisticValue {
    pub value_type: u32,
    pub u64_value: u64,
    pub f64_value: f64,
    pub string_value: *const c_char,
}

pub type FfiFileDescriptorCallback = extern "C" fn(context: *mut c_void, fd: i32, events: u32);

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FfiSlice {
    pub data: *const u8,
    pub len: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FfiPacketInfo {
    pub uuid: [u8; 16],
    pub source: u16,
    pub destination: u16,
    pub priority: u8,
    pub creation_time_sec: u64,
    pub creation_time_usec: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FfiControlMessage {
    pub msg_type: u32,
    pub payload: FfiSlice,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FfiPacket {
    pub info: FfiPacketInfo,
    pub payload: FfiSlice,
}

/// A local spectrum query, made after the requested reception interval has ended.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FfiSpectrumQuery {
    pub frequency_hz: u64,
    pub start_time_microseconds: i64,
    pub duration_microseconds: u64,
    pub rx_power_dbm: f64,
    /// Receive antenna index; zero selects the default SISO monitor.
    pub antenna_index: u16,
}

impl FfiSpectrumQuery {
    pub fn from_rx(rx: RxProperties, segment: Option<&RxFrequencySegment>) -> Self {
        Self {
            frequency_hz: segment.map_or(rx.frequency_hz, |segment| segment.frequency_hz),
            start_time_microseconds: rx
                .tx_time_microseconds
                .saturating_add(i64::try_from(rx.propagation_microseconds).unwrap_or(i64::MAX))
                .saturating_add(segment.map_or(0, |segment| {
                    i64::try_from(segment.offset_microseconds).unwrap_or(i64::MAX)
                })),
            duration_microseconds: rx.duration_microseconds.max(1),
            rx_power_dbm: segment.map_or(rx.rx_power_dbm, |segment| segment.rx_power_dbm),
            antenna_index: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FfiSpectrumResult {
    pub receiver_sensitivity_dbm: f64,
    pub noise_floor_dbm: f64,
    pub signal_in_noise: bool,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FfiFrameworkService {
    pub framework_ctx: *mut c_void,
    pub send_downstream_packet: extern "C" fn(
        ctx: *mut c_void,
        nem_id: u16,
        packet: *const FfiPacket,
        messages: *const FfiControlMessage,
        message_count: usize,
    ),
    pub send_upstream_packet: extern "C" fn(
        ctx: *mut c_void,
        nem_id: u16,
        packet: *const FfiPacket,
        messages: *const FfiControlMessage,
        message_count: usize,
    ),
    pub send_downstream_control: extern "C" fn(
        ctx: *mut c_void,
        nem_id: u16,
        messages: *const FfiControlMessage,
        message_count: usize,
    ),
    pub send_upstream_control: extern "C" fn(
        ctx: *mut c_void,
        nem_id: u16,
        messages: *const FfiControlMessage,
        message_count: usize,
    ),
    pub schedule_timed_event: extern "C" fn(
        ctx: *mut c_void,
        nem_id: u16,
        time_sec: u64,
        time_usec: u32,
        event_id: u32,
        data: *const u8,
        data_len: usize,
    ) -> u64,
    pub cancel_timed_event: extern "C" fn(ctx: *mut c_void, nem_id: u16, timer_id: u64),
    pub log: extern "C" fn(ctx: *mut c_void, level: u32, message: *const c_char),
    pub register_counter: extern "C" fn(
        ctx: *mut c_void,
        name: *const c_char,
        description: *const c_char,
        clearable: bool,
    ) -> u64,
    pub register_counter32: extern "C" fn(
        ctx: *mut c_void,
        name: *const c_char,
        description: *const c_char,
        clearable: bool,
    ) -> u64,
    pub increment_counter: extern "C" fn(ctx: *mut c_void, handle: u64, amount: u64) -> bool,
    pub maximize_counter: extern "C" fn(ctx: *mut c_void, handle: u64, value: u64) -> bool,
    pub register_double: extern "C" fn(
        ctx: *mut c_void,
        name: *const c_char,
        description: *const c_char,
        clearable: bool,
    ) -> u64,
    pub set_double: extern "C" fn(ctx: *mut c_void, handle: u64, value: f64) -> bool,
    pub register_average: extern "C" fn(
        ctx: *mut c_void,
        name: *const c_char,
        description: *const c_char,
        clearable: bool,
    ) -> u64,
    pub sample_average: extern "C" fn(ctx: *mut c_void, handle: u64, sample: f64) -> bool,
    pub register_table: extern "C" fn(
        ctx: *mut c_void,
        name: *const c_char,
        labels: *const *const c_char,
        label_count: usize,
        description: *const c_char,
        clearable: bool,
    ) -> u64,
    pub set_table_row: extern "C" fn(
        ctx: *mut c_void,
        handle: u64,
        key: *const u64,
        key_count: usize,
        values: *const FfiStatisticValue,
        value_count: usize,
    ) -> bool,
    pub clear_table: extern "C" fn(ctx: *mut c_void, handle: u64) -> bool,
    pub remove_table_row:
        extern "C" fn(ctx: *mut c_void, handle: u64, key: *const u64, key_count: usize) -> bool,
    pub table_generation: extern "C" fn(ctx: *mut c_void, handle: u64) -> u64,
    pub update_neighbor_tx: extern "C" fn(
        ctx: *mut c_void,
        destination: u16,
        data_rate_bps: u64,
        tx_time_microseconds: u64,
    ),
    pub update_neighbor_rx: extern "C" fn(
        ctx: *mut c_void,
        source: u16,
        sequence: u64,
        uuid: *const u8,
        sinr_db: f64,
        noise_floor_dbm: f64,
        rx_time_microseconds: u64,
        duration_microseconds: u64,
        data_rate_bps: u64,
    ),
    pub update_neighbor_status: extern "C" fn(ctx: *mut c_void),
    pub update_queue_metric: extern "C" fn(
        ctx: *mut c_void,
        queue_id: u16,
        max_size: u32,
        current_depth: u32,
        num_discards: u32,
        delay_microseconds: u64,
    ),
    pub publish_r2ri: extern "C" fn(
        ctx: *mut c_void,
        broadcast_data_rate_bps: u64,
        max_data_rate_bps: u64,
        report_interval_microseconds: u64,
        neighbor_delete_microseconds: u64,
    ),
    pub register_rf_signal_table: extern "C" fn(ctx: *mut c_void, nem_id: u16) -> u64,
    pub configure_rf_signal_table: extern "C" fn(
        ctx: *mut c_void,
        handle: u64,
        average_all_antennas: bool,
        average_all_frequencies: bool,
    ) -> bool,
    pub update_rf_signal_table: extern "C" fn(
        ctx: *mut c_void,
        handle: u64,
        source: u16,
        antenna: u16,
        frequency_hz: u64,
        rx_power_dbm: f64,
        sinr_db: f64,
        noise_floor_dbm: f64,
        receiver_sensitivity_dbm: f64,
    ) -> bool,
    pub publish_event:
        extern "C" fn(ctx: *mut c_void, event_id: u16, data: *const u8, data_len: usize) -> bool,
    pub register_file_descriptor: extern "C" fn(
        ctx: *mut c_void,
        fd: i32,
        interests: u32,
        callback_context: *mut c_void,
        callback: FfiFileDescriptorCallback,
    ) -> u64,
    pub unregister_file_descriptor: extern "C" fn(ctx: *mut c_void, handle: u64) -> bool,
    pub query_spectrum_filter: extern "C" fn(
        ctx: *mut c_void,
        query: *const FfiFilterQuery,
        result: *mut FfiFilterResult,
    ) -> bool,
    /// Returns false for unavailable, expired or incomplete spectrum windows.
    pub query_spectrum: extern "C" fn(
        ctx: *mut c_void,
        query: *const FfiSpectrumQuery,
        result: *mut FfiSpectrumResult,
    ) -> bool,
}

impl FfiFrameworkService {
    pub fn reception_noise(self, query: &FfiSpectrumQuery) -> Option<FfiSpectrumResult> {
        let mut result = FfiSpectrumResult::default();
        (self.query_spectrum)(self.framework_ctx, query, &mut result).then_some(result)
    }
}

unsafe impl Send for FfiFrameworkService {}
unsafe impl Sync for FfiFrameworkService {}

#[derive(Clone, Copy, Default)]
struct TrafficCounters {
    average_processing_delay: u64,
    packets_unicast_tx: u64,
    bytes_unicast_tx: u64,
    packets_broadcast_tx: u64,
    bytes_broadcast_tx: u64,
    packets_unicast_rx: u64,
    bytes_unicast_rx: u64,
    packets_unicast_drop: u64,
    packets_broadcast_rx: u64,
    bytes_broadcast_rx: u64,
    packets_broadcast_drop: u64,
    packets_unicast_generated: u64,
    bytes_unicast_generated: u64,
    packets_broadcast_generated: u64,
    bytes_broadcast_generated: u64,
}

#[derive(Clone, Copy, Default)]
pub struct CommonLayerCounters {
    upstream: TrafficCounters,
    downstream: TrafficCounters,
    unicast_drop_table: u64,
    broadcast_drop_table: u64,
    unicast_accept_table: u64,
    broadcast_accept_table: u64,
    unicast_drop_columns: usize,
    broadcast_drop_columns: usize,
}

#[derive(Clone, Default)]
struct CommonAcceptCounts {
    tx_packets: u64,
    tx_bytes: u64,
    rx_packets: u64,
    rx_bytes: u64,
}

#[derive(Default)]
struct CommonTableState {
    generation: u64,
    accepts: HashMap<u16, CommonAcceptCounts>,
    drops: HashMap<u16, Vec<u64>>,
}

fn common_table_states() -> &'static Mutex<HashMap<u64, CommonTableState>> {
    static STATES: OnceLock<Mutex<HashMap<u64, CommonTableState>>> = OnceLock::new();
    STATES.get_or_init(|| Mutex::new(HashMap::new()))
}

impl CommonLayerCounters {
    pub fn register(framework: FfiFrameworkService) -> Self {
        Self::register_with_drop_labels(framework, "", &[], &[])
    }

    pub fn register_with_drop_labels(
        framework: FfiFrameworkService,
        instance: &str,
        unicast_drop_labels: &[&str],
        broadcast_drop_labels: &[&str],
    ) -> Self {
        let register_counter = |base: &str, description: &str| {
            let Ok(name) = CString::new(format!("{base}{instance}")) else {
                return 0;
            };
            let Ok(description) = CString::new(description) else {
                return 0;
            };
            (framework.register_counter)(
                framework.framework_ctx,
                name.as_ptr(),
                description.as_ptr(),
                true,
            )
        };
        let register_average = |base: &str, description: &str| {
            let Ok(name) = CString::new(format!("{base}{instance}")) else {
                return 0;
            };
            let Ok(description) = CString::new(description) else {
                return 0;
            };
            (framework.register_average)(
                framework.framework_ctx,
                name.as_ptr(),
                description.as_ptr(),
                true,
            )
        };
        let register_table = |base: &str, labels: &[&str], description: &str| {
            let Ok(name) = CString::new(format!("{base}{instance}")) else {
                return 0;
            };
            let Ok(labels) = labels
                .iter()
                .map(|label| CString::new(*label))
                .collect::<Result<Vec<_>, _>>()
            else {
                return 0;
            };
            let pointers = labels
                .iter()
                .map(|label| label.as_ptr())
                .collect::<Vec<_>>();
            let Ok(description) = CString::new(description) else {
                return 0;
            };
            (framework.register_table)(
                framework.framework_ctx,
                name.as_ptr(),
                pointers.as_ptr(),
                pointers.len(),
                description.as_ptr(),
                true,
            )
        };
        let accept_labels = [
            "NEM",
            "Num Pkts Tx",
            "Num Bytes Tx",
            "Num Pkts Rx",
            "Num Bytes Rx",
        ];
        let mut unicast_drop_table = 0;
        let mut broadcast_drop_table = 0;
        let mut unicast_drop_columns = 0;
        let mut broadcast_drop_columns = 0;
        if !unicast_drop_labels.is_empty() {
            let mut labels = Vec::with_capacity(unicast_drop_labels.len() + 1);
            labels.push("NEM");
            labels.extend_from_slice(unicast_drop_labels);
            unicast_drop_table = register_table(
                "UnicastPacketDropTable",
                &labels,
                "Unicast packets dropped by reason code",
            );
            unicast_drop_columns = unicast_drop_labels.len();

            let effective_broadcast_labels = if broadcast_drop_labels.is_empty() {
                unicast_drop_labels
            } else {
                broadcast_drop_labels
            };
            let mut labels = Vec::with_capacity(effective_broadcast_labels.len() + 1);
            labels.push("NEM");
            labels.extend_from_slice(effective_broadcast_labels);
            broadcast_drop_table = register_table(
                "BroadcastPacketDropTable",
                &labels,
                "Broadcast packets dropped by reason code",
            );
            broadcast_drop_columns = effective_broadcast_labels.len();
        }
        Self {
            upstream: TrafficCounters {
                average_processing_delay: register_average(
                    "avgUpstreamProcessingDelay",
                    "Average upstream processing delay",
                ),
                packets_unicast_tx: register_counter(
                    "numUpstreamPacketsUnicastTx",
                    "Number of upstream unicast packets transmitted",
                ),
                bytes_unicast_tx: register_counter(
                    "numUpstreamBytesUnicastTx",
                    "Number of upstream unicast bytes transmitted",
                ),
                packets_broadcast_tx: register_counter(
                    "numUpstreamPacketsBroadcastTx",
                    "Number of upstream broadcast packets transmitted",
                ),
                bytes_broadcast_tx: register_counter(
                    "numUpstreamBytesBroadcastTx",
                    "Number of upstream broadcast bytes transmitted",
                ),
                packets_unicast_rx: register_counter(
                    "numUpstreamPacketsUnicastRx",
                    "Number of upstream unicast packets received",
                ),
                bytes_unicast_rx: register_counter(
                    "numUpstreamBytesUnicastRx",
                    "Number of upstream unicast bytes received",
                ),
                packets_unicast_drop: register_counter(
                    "numUpstreamPacketsUnicastDrop",
                    "Number of upstream unicast packets dropped",
                ),
                packets_broadcast_rx: register_counter(
                    "numUpstreamPacketsBroadcastRx",
                    "Number of upstream broadcast packets received",
                ),
                bytes_broadcast_rx: register_counter(
                    "numUpstreamBytesBroadcastRx",
                    "Number of upstream broadcast bytes received",
                ),
                packets_broadcast_drop: register_counter(
                    "numUpstreamPacketsBroadcastDrop",
                    "Number of upstream broadcast packets dropped",
                ),
                ..TrafficCounters::default()
            },
            downstream: TrafficCounters {
                average_processing_delay: register_average(
                    "avgDownstreamProcessingDelay",
                    "Average downstream processing delay",
                ),
                packets_unicast_tx: register_counter(
                    "numDownstreamPacketsUnicastTx",
                    "Number of downstream unicast packets transmitted",
                ),
                bytes_unicast_tx: register_counter(
                    "numDownstreamBytesUnicastTx",
                    "Number of downstream unicast bytes transmitted",
                ),
                packets_broadcast_tx: register_counter(
                    "numDownstreamPacketsBroadcastTx",
                    "Number of downstream broadcast packets transmitted",
                ),
                bytes_broadcast_tx: register_counter(
                    "numDownstreamBytesBroadcastTx",
                    "Number of downstream broadcast bytes transmitted",
                ),
                packets_unicast_rx: register_counter(
                    "numDownstreamPacketsUnicastRx",
                    "Number of downstream unicast packets received",
                ),
                bytes_unicast_rx: register_counter(
                    "numDownstreamBytesUnicastRx",
                    "Number of downstream unicast bytes received",
                ),
                packets_unicast_drop: register_counter(
                    "numDownstreamPacketsUnicastDrop",
                    "Number of downstream unicast packets dropped",
                ),
                packets_broadcast_rx: register_counter(
                    "numDownstreamPacketsBroadcastRx",
                    "Number of downstream broadcast packets received",
                ),
                bytes_broadcast_rx: register_counter(
                    "numDownstreamBytesBroadcastRx",
                    "Number of downstream broadcast bytes received",
                ),
                packets_broadcast_drop: register_counter(
                    "numDownstreamPacketsBroadcastDrop",
                    "Number of downstream broadcast packets dropped",
                ),
                packets_unicast_generated: register_counter(
                    "numDownstreamPacketsUnicastGenerated",
                    "Number of layer generated downstream unicast packets",
                ),
                bytes_unicast_generated: register_counter(
                    "numDownstreamBytesUnicastGenerated",
                    "Number of layer generated downstream unicast bytes",
                ),
                packets_broadcast_generated: register_counter(
                    "numDownstreamPacketsBroadcastGenerated",
                    "Number of layer generated downstream broadcast packets",
                ),
                bytes_broadcast_generated: register_counter(
                    "numDownstreamBytesBroadcastGenerated",
                    "Number of layer generated downstream broadcast bytes",
                ),
            },
            unicast_drop_table,
            broadcast_drop_table,
            unicast_accept_table: register_table(
                "UnicastPacketAcceptTable",
                &accept_labels,
                "Unicast packets accepted",
            ),
            broadcast_accept_table: register_table(
                "BroadcastPacketAcceptTable",
                &accept_labels,
                "Broadcast packets accepted",
            ),
            unicast_drop_columns,
            broadcast_drop_columns,
        }
    }

    fn increment(framework: FfiFrameworkService, handle: u64, amount: u64) {
        if handle != 0 {
            (framework.increment_counter)(framework.framework_ctx, handle, amount);
        }
    }

    fn inbound(
        counters: TrafficCounters,
        framework: FfiFrameworkService,
        destination: u16,
        bytes: usize,
    ) {
        let (packets, byte_counter) = if destination == u16::MAX {
            (counters.packets_broadcast_rx, counters.bytes_broadcast_rx)
        } else {
            (counters.packets_unicast_rx, counters.bytes_unicast_rx)
        };
        Self::increment(framework, packets, 1);
        Self::increment(
            framework,
            byte_counter,
            u64::try_from(bytes).unwrap_or(u64::MAX),
        );
    }

    fn outbound(
        counters: TrafficCounters,
        framework: FfiFrameworkService,
        destination: u16,
        bytes: usize,
        processing_delay_microseconds: u64,
        self_generated: bool,
    ) {
        let (packets, byte_counter) = if self_generated {
            if destination == u16::MAX {
                (
                    counters.packets_broadcast_generated,
                    counters.bytes_broadcast_generated,
                )
            } else {
                (
                    counters.packets_unicast_generated,
                    counters.bytes_unicast_generated,
                )
            }
        } else if destination == u16::MAX {
            (counters.packets_broadcast_tx, counters.bytes_broadcast_tx)
        } else {
            (counters.packets_unicast_tx, counters.bytes_unicast_tx)
        };
        Self::increment(framework, packets, 1);
        Self::increment(
            framework,
            byte_counter,
            u64::try_from(bytes).unwrap_or(u64::MAX),
        );
        if counters.average_processing_delay != 0 {
            (framework.sample_average)(
                framework.framework_ctx,
                counters.average_processing_delay,
                processing_delay_microseconds as f64,
            );
        }
    }

    fn drop(counters: TrafficCounters, framework: FfiFrameworkService, destination: u16) {
        let handle = if destination == u16::MAX {
            counters.packets_broadcast_drop
        } else {
            counters.packets_unicast_drop
        };
        Self::increment(framework, handle, 1);
    }

    fn set_accept_row(
        self,
        framework: FfiFrameworkService,
        source: u16,
        destination: u16,
        bytes: usize,
        upstream: bool,
    ) {
        let table = if destination == u16::MAX {
            self.broadcast_accept_table
        } else {
            self.unicast_accept_table
        };
        if table == 0 {
            return;
        }
        let generation = (framework.table_generation)(framework.framework_ctx, table);
        let mut states = common_table_states().lock().unwrap();
        let state = states.entry(table).or_default();
        if state.generation != generation {
            state.generation = generation;
            state.accepts.clear();
            state.drops.clear();
        }
        let counts = state.accepts.entry(source).or_default();
        if upstream {
            counts.rx_packets = counts.rx_packets.saturating_add(1);
            counts.rx_bytes = counts
                .rx_bytes
                .saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX));
        } else {
            counts.tx_packets = counts.tx_packets.saturating_add(1);
            counts.tx_bytes = counts
                .tx_bytes
                .saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX));
        }
        let key = [u64::from(source)];
        let values = [
            statistic_u64(u64::from(source)),
            statistic_u64(counts.tx_packets),
            statistic_u64(counts.tx_bytes),
            statistic_u64(counts.rx_packets),
            statistic_u64(counts.rx_bytes),
        ];
        (framework.set_table_row)(
            framework.framework_ctx,
            table,
            key.as_ptr(),
            key.len(),
            values.as_ptr(),
            values.len(),
        );
    }

    fn set_drop_row(
        self,
        framework: FfiFrameworkService,
        source: u16,
        destination: u16,
        drop_code: usize,
        upstream: bool,
    ) {
        let broadcast = destination == u16::MAX;
        let (table, columns) = if broadcast {
            (self.broadcast_drop_table, self.broadcast_drop_columns)
        } else {
            (self.unicast_drop_table, self.unicast_drop_columns)
        };
        if table == 0 || drop_code == 0 || drop_code > columns {
            return;
        }
        let peer = if upstream { source } else { destination };
        let generation = (framework.table_generation)(framework.framework_ctx, table);
        let mut states = common_table_states().lock().unwrap();
        let state = states.entry(table).or_default();
        if state.generation != generation {
            state.generation = generation;
            state.accepts.clear();
            state.drops.clear();
        }
        let counts = state.drops.entry(peer).or_insert_with(|| vec![0; columns]);
        counts[drop_code - 1] = counts[drop_code - 1].saturating_add(1);
        let key = [u64::from(peer)];
        let mut values = Vec::with_capacity(columns + 1);
        values.push(statistic_u64(u64::from(peer)));
        values.extend(counts.iter().copied().map(statistic_u64));
        (framework.set_table_row)(
            framework.framework_ctx,
            table,
            key.as_ptr(),
            key.len(),
            values.as_ptr(),
            values.len(),
        );
    }

    pub fn downstream_rx_packet(
        self,
        framework: FfiFrameworkService,
        _source: u16,
        destination: u16,
        bytes: usize,
    ) {
        Self::inbound(self.downstream, framework, destination, bytes);
    }

    pub fn downstream_tx_packet(
        self,
        framework: FfiFrameworkService,
        source: u16,
        destination: u16,
        bytes: usize,
        processing_delay_microseconds: u64,
        self_generated: bool,
    ) {
        Self::outbound(
            self.downstream,
            framework,
            destination,
            bytes,
            processing_delay_microseconds,
            self_generated,
        );
        self.set_accept_row(framework, source, destination, bytes, false);
    }

    pub fn downstream_drop_packet(
        self,
        framework: FfiFrameworkService,
        source: u16,
        destination: u16,
        drop_code: usize,
    ) {
        Self::drop(self.downstream, framework, destination);
        self.set_drop_row(framework, source, destination, drop_code, false);
    }

    pub fn upstream_rx_packet(
        self,
        framework: FfiFrameworkService,
        _source: u16,
        destination: u16,
        bytes: usize,
    ) {
        Self::inbound(self.upstream, framework, destination, bytes);
    }

    pub fn upstream_tx_packet(
        self,
        framework: FfiFrameworkService,
        source: u16,
        destination: u16,
        bytes: usize,
        processing_delay_microseconds: u64,
    ) {
        Self::outbound(
            self.upstream,
            framework,
            destination,
            bytes,
            processing_delay_microseconds,
            false,
        );
        self.set_accept_row(framework, source, destination, bytes, true);
    }

    pub fn upstream_drop_packet(
        self,
        framework: FfiFrameworkService,
        source: u16,
        destination: u16,
        drop_code: usize,
    ) {
        Self::drop(self.upstream, framework, destination);
        self.set_drop_row(framework, source, destination, drop_code, true);
    }
}

fn statistic_u64(value: u64) -> FfiStatisticValue {
    FfiStatisticValue {
        value_type: STATISTIC_VALUE_U64,
        u64_value: value,
        f64_value: 0.0,
        string_value: std::ptr::null(),
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FfiConfigStringArray {
    pub data: *const *const c_char,
    pub len: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FfiConfigItem {
    pub name: *const c_char,
    pub values: FfiConfigStringArray,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FfiConfigRequest {
    pub data: *const FfiConfigItem,
    pub len: usize,
}

#[repr(C)]
pub struct PluginApi {
    pub abi_version: u32,
    pub struct_size: usize,
    pub name: *const c_char,
    pub plugin_type: u32,
    pub init: extern "C" fn(id: u16, framework: *const FfiFrameworkService) -> *mut c_void,
    pub configure: extern "C" fn(plugin: *mut c_void, request: *const c_void) -> bool,
    pub start: extern "C" fn(plugin: *mut c_void) -> bool,
    pub post_start: extern "C" fn(plugin: *mut c_void),
    pub stop: extern "C" fn(plugin: *mut c_void),
    pub destroy: extern "C" fn(plugin: *mut c_void),
    pub process_upstream: extern "C" fn(
        plugin: *mut c_void,
        packet: *const FfiPacket,
        messages: *const FfiControlMessage,
        message_count: usize,
    ),
    pub process_downstream: extern "C" fn(
        plugin: *mut c_void,
        packet: *const FfiPacket,
        messages: *const FfiControlMessage,
        message_count: usize,
    ),
    pub process_timed_event: extern "C" fn(
        plugin: *mut c_void,
        timer_id: u64,
        event_id: u32,
        data: *const u8,
        data_len: usize,
    ),
    pub process_event:
        extern "C" fn(plugin: *mut c_void, event_id: u16, data: *const u8, data_len: usize),
}

unsafe impl Send for PluginApi {}
unsafe impl Sync for PluginApi {}

pub type PluginEntryFunc = extern "C" fn() -> *const PluginApi;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn properties_wire_formats_round_trip() {
        let flow = FlowControlToken { tokens: 10 };
        assert_eq!(FlowControlToken::decode(&flow.encode()), Some(flow));

        let self_metric = R2riSelfMetric {
            broadcast_data_rate_bps: 1_000_000,
            max_data_rate_bps: 54_000_000,
            report_interval_microseconds: 500_000,
        };
        assert_eq!(
            R2riSelfMetric::decode(&self_metric.encode()),
            Some(self_metric)
        );
        let queue_metrics = R2riQueueMetrics {
            metrics: vec![R2riQueueMetric {
                queue_id: 2,
                max_size: 255,
                current_depth_high_water: 10,
                num_discards_high_water: 3,
                average_delay_microseconds: 42,
            }],
        };
        assert_eq!(
            R2riQueueMetrics::decode(&queue_metrics.encode().unwrap()),
            Some(queue_metrics)
        );
        let neighbor_metrics = R2riNeighborMetrics {
            metrics: vec![R2riNeighborMetric {
                nem_id: 9,
                num_rx_frames: 4,
                num_tx_frames: 3,
                num_missed_frames: 1,
                bandwidth_consumption_microseconds: 200,
                sinr_average_db: 12.5,
                sinr_stddev: 0.5,
                noise_floor_average_dbm: -101.0,
                noise_floor_stddev: 1.25,
                rx_average_data_rate_bps: 1_000_000,
                tx_average_data_rate_bps: 2_000_000,
            }],
        };
        assert_eq!(
            R2riNeighborMetrics::decode(&neighbor_metrics.encode().unwrap()),
            Some(neighbor_metrics)
        );

        let tx = TxProperties {
            frequency_hz: 2_347_000_000,
            bandwidth_hz: 1_000_000,
            tx_power_dbm: -3.25,
            duration_microseconds: 42,
            offset_microseconds: 7,
            tx_time_microseconds: -8,
            antenna_index: 2,
            spectral_mask_index: 4,
            sub_id: 9,
        };
        assert_eq!(TxProperties::decode(&tx.encode()), Some(tx));

        let rx = RxProperties {
            frequency_hz: tx.frequency_hz,
            bandwidth_hz: tx.bandwidth_hz,
            rx_power_dbm: -44.0,
            noise_floor_dbm: -101.5,
            tx_time_microseconds: 88,
            propagation_microseconds: 2,
            duration_microseconds: 42,
            antenna_index: 3,
            sub_id: 9,
            signal_in_noise: true,
        };
        assert_eq!(RxProperties::decode(&rx.encode()), Some(rx));

        let header = ModelHeader {
            registration_id: MAC_REGISTRATION_RFPIPE,
            sequence: 44,
            data_rate_bps: 1_000_000,
            category: 3,
            message_type: 2,
            flags: 9,
        };
        assert_eq!(ModelHeader::decode(&header.encode()), Some(header));

        let foi = FrequencyOfInterest {
            bandwidth_hz: 2_000_000,
            frequencies_hz: vec![100, 200],
        };
        assert_eq!(
            FrequencyOfInterest::decode(&foi.encode().unwrap()),
            Some(foi)
        );

        let segments = TxFrequencySegments {
            segments: vec![
                TxFrequencySegment {
                    frequency_hz: 2_400_000_000,
                    duration_microseconds: 100,
                    offset_microseconds: 0,
                },
                TxFrequencySegment {
                    frequency_hz: 2_410_000_000,
                    duration_microseconds: 50,
                    offset_microseconds: 100,
                },
            ],
        };
        assert_eq!(
            TxFrequencySegments::decode(&segments.encode().unwrap()),
            Some(segments)
        );

        let received_segments = RxFrequencySegments {
            segments: vec![RxFrequencySegment {
                frequency_hz: 2_400_000_000,
                rx_power_dbm: -72.5,
                duration_microseconds: 100,
                offset_microseconds: 5,
            }],
        };
        assert_eq!(
            RxFrequencySegments::decode(&received_segments.encode().unwrap()),
            Some(received_segments.clone())
        );

        let transmitters = TxTransmitters {
            transmitters: vec![
                TxTransmitter {
                    nem_id: 1,
                    tx_power_dbm: 10.0,
                },
                TxTransmitter {
                    nem_id: 2,
                    tx_power_dbm: -3.5,
                },
            ],
        };
        assert_eq!(
            TxTransmitters::decode(&transmitters.encode().unwrap()),
            Some(transmitters)
        );

        let antenna = TxAntennaProfile {
            profile_id: 4,
            azimuth_degrees: 45.0,
            elevation_degrees: -5.0,
        };
        assert_eq!(
            TxAntennaProfile::decode(&antenna.encode().unwrap()),
            Some(antenna)
        );

        let mimo_tx = MimoTxProperties {
            frequency_groups: vec![
                vec![MimoTxFrequencySegment {
                    frequency_hz: 2_400_000_000,
                    tx_power_dbm: Some(3.0),
                    duration_microseconds: 100,
                    offset_microseconds: 0,
                }],
                vec![MimoTxFrequencySegment {
                    frequency_hz: 2_410_000_000,
                    tx_power_dbm: Some(-2.0),
                    duration_microseconds: 50,
                    offset_microseconds: 100,
                }],
            ],
            transmit_antennas: vec![
                MimoTxAntenna {
                    frequency_group_index: 0,
                    antenna_index: 1,
                    bandwidth_hz: 1_000_000,
                    spectral_mask_index: 0,
                    pattern: AntennaPattern::IdealOmni { gain_db: 2.5 },
                },
                MimoTxAntenna {
                    frequency_group_index: 1,
                    antenna_index: 2,
                    bandwidth_hz: 2_000_000,
                    spectral_mask_index: 3,
                    pattern: AntennaPattern::Profile(TxAntennaProfile {
                        profile_id: 9,
                        azimuth_degrees: 20.0,
                        elevation_degrees: -5.0,
                    }),
                },
            ],
        };
        assert_eq!(
            MimoTxProperties::decode(&mimo_tx.encode().unwrap()),
            Some(mimo_tx.clone())
        );
        let mut fallback = mimo_tx.clone();
        for segment in fallback.frequency_groups.iter_mut().flatten() {
            segment.tx_power_dbm = None;
        }
        assert_eq!(
            MimoTxProperties::decode(&fallback.encode().unwrap()),
            Some(fallback)
        );
        let mut invalid_group = mimo_tx.encode().unwrap();
        let antenna_offset = invalid_group.len() - 2 * MimoTxProperties::ANTENNA_LEN;
        invalid_group[antenna_offset..antenna_offset + 2].copy_from_slice(&9u16.to_be_bytes());
        assert_eq!(
            MimoTxProperties::decode(&invalid_group)
                .unwrap()
                .transmit_antennas[0]
                .frequency_group_index,
            9
        );
        let rx_antenna = RxAntennaAdd {
            antenna: MimoTxAntenna {
                frequency_group_index: 0,
                antenna_index: 7,
                bandwidth_hz: 2_000_000,
                spectral_mask_index: 4,
                pattern: AntennaPattern::Profile(antenna),
            },
            frequencies_hz: vec![2_400_000_000, 2_410_000_000],
        };
        assert_eq!(
            RxAntennaAdd::decode(&rx_antenna.encode().unwrap()),
            Some(rx_antenna.clone())
        );
        let mut defaults = rx_antenna;
        defaults.antenna.bandwidth_hz = 0;
        defaults.frequencies_hz.clear();
        assert_eq!(
            RxAntennaAdd::decode(&defaults.encode().unwrap()),
            Some(defaults)
        );

        let mimo_rx = MimoRxProperties {
            tx_time_microseconds: -20,
            propagation_microseconds: 4,
            antenna_infos: vec![MimoRxAntennaInfo {
                receive_antenna_index: 0,
                transmit_antenna_index: 2,
                span_microseconds: 150,
                receiver_sensitivity_dbm: -101.0,
                noise_floor_dbm: -95.0,
                segments: received_segments.segments.clone(),
            }],
            doppler_shifts_hz: vec![(2_400_000_000, -12)],
        };
        assert_eq!(
            MimoRxProperties::decode(&mimo_rx.encode().unwrap()),
            Some(mimo_rx)
        );
    }
}

pub mod pcr_validation;

pub mod xml_document;

pub mod xml_schema;
