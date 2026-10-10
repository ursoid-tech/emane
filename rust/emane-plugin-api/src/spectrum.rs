//! Owned model/PHY controls. Filter predicates are copied with the message;
//! no plugin-owned callback or borrowed pointer outlives control delivery.
use super::*;
#[derive(Clone, Debug, PartialEq)]
pub enum FilterCriterion {
    Any,
    Numeric {
        field: u8,
        comparison: u8,
        value: u64,
    }, // frequency, bandwidth, subid
    Data {
        comparison: u8,
        value: Vec<u8>,
    },
    And(Vec<Self>),
    Or(Vec<Self>),
    Not(Box<Self>),
}
fn compare(order: std::cmp::Ordering, op: u8) -> bool {
    use std::cmp::Ordering::*;
    match op {
        0 => order == Equal,
        1 => order != Equal,
        2 => order == Less,
        3 => order != Greater,
        4 => order == Greater,
        5 => order != Less,
        _ => false,
    }
}
impl FilterCriterion {
    pub fn matches(&self, frequency: u64, bandwidth: u64, subid: u16, data: &[u8]) -> bool {
        match self {
            Self::Any => true,
            Self::Numeric {
                field,
                comparison,
                value,
            } => compare(
                match field {
                    0 => frequency,
                    1 => bandwidth,
                    2 => u64::from(subid),
                    _ => return false,
                }
                .cmp(value),
                *comparison,
            ),
            Self::Data { comparison, value } => compare(data.cmp(value), *comparison),
            Self::And(items) => items
                .iter()
                .all(|c| c.matches(frequency, bandwidth, subid, data)),
            Self::Or(items) => items
                .iter()
                .any(|c| c.matches(frequency, bandwidth, subid, data)),
            Self::Not(c) => !c.matches(frequency, bandwidth, subid, data),
        }
    }
    fn write(&self, out: &mut Vec<u8>, depth: usize) -> Option<()> {
        if depth > 32 {
            return None;
        }
        match self {
            Self::Any => out.push(0),
            Self::Numeric {
                field,
                comparison,
                value,
            } => {
                if *field > 2 || *comparison > 5 {
                    return None;
                }
                out.extend([1, *field, *comparison]);
                out.extend(value.to_be_bytes());
            }
            Self::Data { comparison, value } => {
                if *comparison > 5 {
                    return None;
                }
                out.extend([2, *comparison]);
                out.extend(u16::try_from(value.len()).ok()?.to_be_bytes());
                out.extend(value);
            }
            Self::And(items) | Self::Or(items) => {
                out.push(if matches!(self, Self::And(_)) { 3 } else { 4 });
                out.extend(u16::try_from(items.len()).ok()?.to_be_bytes());
                for item in items {
                    item.write(out, depth + 1)?;
                }
            }
            Self::Not(item) => {
                out.push(5);
                item.write(out, depth + 1)?;
            }
        }
        Some(())
    }
    fn read(data: &[u8], pos: &mut usize, depth: usize) -> Option<Self> {
        if depth > 32 {
            return None;
        }
        let tag = *data.get(*pos)?;
        *pos += 1;
        Some(match tag {
            0 => Self::Any,
            1 => {
                let field = *data.get(*pos)?;
                let comparison = *data.get(*pos + 1)?;
                *pos += 2;
                if field > 2 || comparison > 5 {
                    return None;
                }
                Self::Numeric {
                    field,
                    comparison,
                    value: read_u64(data, pos)?,
                }
            }
            2 => {
                let comparison = *data.get(*pos)?;
                *pos += 1;
                if comparison > 5 {
                    return None;
                }
                let len = usize::from(read_u16(data, pos)?);
                let value = data.get(*pos..pos.checked_add(len)?)?.to_vec();
                *pos += len;
                Self::Data { comparison, value }
            }
            3 | 4 => {
                let count = read_u16(data, pos)?;
                let mut v = Vec::new();
                for _ in 0..count {
                    v.push(Self::read(data, pos, depth + 1)?);
                }
                if tag == 3 {
                    Self::And(v)
                } else {
                    Self::Or(v)
                }
            }
            5 => Self::Not(Box::new(Self::read(data, pos, depth + 1)?)),
            _ => return None,
        })
    }
}
#[derive(Clone, Debug, PartialEq)]
pub struct SpectrumFilterAdd {
    pub antenna_index: u16,
    pub filter_index: u16,
    pub frequency_hz: u64,
    pub bandwidth_hz: u64,
    pub sub_band_hz: u64,
    pub criterion: FilterCriterion,
}
impl SpectrumFilterAdd {
    pub fn encode(&self) -> Option<Vec<u8>> {
        if self.bandwidth_hz == 0 {
            return None;
        }
        let mut b = vec![1];
        b.extend(self.antenna_index.to_be_bytes());
        b.extend(self.filter_index.to_be_bytes());
        for v in [self.frequency_hz, self.bandwidth_hz, self.sub_band_hz] {
            b.extend(v.to_be_bytes());
        }
        self.criterion.write(&mut b, 0)?;
        Some(b)
    }
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.first() != Some(&1) {
            return None;
        }
        let mut p = 1;
        let v = Self {
            antenna_index: read_u16(b, &mut p)?,
            filter_index: read_u16(b, &mut p)?,
            frequency_hz: read_u64(b, &mut p)?,
            bandwidth_hz: read_u64(b, &mut p)?,
            sub_band_hz: read_u64(b, &mut p)?,
            criterion: FilterCriterion::read(b, &mut p, 0)?,
        };
        (p == b.len() && v.bandwidth_hz > 0).then_some(v)
    }
}
/// Removes an antenna's filter. Removal of an unknown filter is harmless.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpectrumFilterRemove {
    pub antenna_index: u16,
    pub filter_index: u16,
}
impl SpectrumFilterRemove {
    pub fn encode(self) -> [u8; 4] {
        let [a, b] = self.antenna_index.to_be_bytes();
        let [c, d] = self.filter_index.to_be_bytes();
        [a, b, c, d]
    }
    pub fn decode(b: &[u8]) -> Option<Self> {
        let [a, b, c, d] = <[u8; 4]>::try_from(b).ok()?;
        Some(Self {
            antenna_index: u16::from_be_bytes([a, b]),
            filter_index: u16::from_be_bytes([c, d]),
        })
    }
}
#[derive(Clone, Debug, PartialEq)]
pub struct SelfInterference {
    pub antennas: Vec<AntennaInterference>,
}
#[derive(Clone, Debug, PartialEq)]
pub struct AntennaInterference {
    pub antenna_index: u16,
    pub groups: Vec<(u16, Vec<f64>)>,
}
impl SelfInterference {
    pub fn encode(&self) -> Option<Vec<u8>> {
        let mut b = vec![1];
        b.extend(u16::try_from(self.antennas.len()).ok()?.to_be_bytes());
        let mut seen = std::collections::HashSet::new();
        for a in &self.antennas {
            if !seen.insert(a.antenna_index) {
                return None;
            }
            b.extend(a.antenna_index.to_be_bytes());
            b.extend(u16::try_from(a.groups.len()).ok()?.to_be_bytes());
            for (g, powers) in &a.groups {
                b.extend(g.to_be_bytes());
                b.extend(u16::try_from(powers.len()).ok()?.to_be_bytes());
                for p in powers {
                    if !p.is_finite() || *p < 0.0 {
                        return None;
                    }
                    b.extend(p.to_bits().to_be_bytes());
                }
            }
        }
        Some(b)
    }
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.first() != Some(&1) {
            return None;
        }
        let mut p = 1;
        let mut antennas = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..read_u16(b, &mut p)? {
            let antenna_index = read_u16(b, &mut p)?;
            if !seen.insert(antenna_index) {
                return None;
            }
            let mut groups = Vec::new();
            for _ in 0..read_u16(b, &mut p)? {
                let index = read_u16(b, &mut p)?;
                let mut powers = Vec::new();
                for _ in 0..read_u16(b, &mut p)? {
                    let value = f64::from_bits(read_u64(b, &mut p)?);
                    if !value.is_finite() || value < 0.0 {
                        return None;
                    }
                    powers.push(value);
                }
                groups.push((index, powers));
            }
            antennas.push(AntennaInterference {
                antenna_index,
                groups,
            });
        }
        (p == b.len()).then_some(Self { antennas })
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FfiFilterQuery {
    pub antenna_index: u16,
    pub filter_index: u16,
    pub start_time_microseconds: i64,
    pub duration_microseconds: u64,
}
#[repr(C)]
pub struct FfiFilterResult {
    pub data: *mut f64,
    pub capacity: usize,
    pub length: usize,
    pub start_time_microseconds: i64,
    pub bin_size_microseconds: i64,
    pub sensitivity_mw: f64,
    pub sub_band_count: usize,
}
pub extern "C" fn unavailable_filter(
    _: *mut c_void,
    _: *const FfiFilterQuery,
    _: *mut FfiFilterResult,
) -> bool {
    false
}
