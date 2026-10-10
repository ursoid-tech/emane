use roxmltree::Document;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::PathBuf;
use std::sync::OnceLock;

fn file_uri_path(uri: &str) -> Result<PathBuf, String> {
    if let Some(path) = uri.strip_prefix("file://") {
        if path.starts_with('/') {
            Ok(PathBuf::from(path))
        } else if let Some(path) = path.strip_prefix("localhost/") {
            Ok(PathBuf::from(format!("/{path}")))
        } else {
            Err(format!("unsupported non-local file URI: {uri}"))
        }
    } else {
        Ok(PathBuf::from(uri))
    }
}

pub fn frequency_overlap_ratio(freq1: u64, bw1: u64, freq2: u64, bw2: u64) -> (f64, u64, u64) {
    if bw1 == 0 || bw2 == 0 {
        return (0.0, 0, 0);
    }
    let upper1 = freq1.saturating_add(bw1 / 2);
    let lower1 = freq1.saturating_sub(bw1 / 2);

    let upper2 = freq2.saturating_add(bw2 / 2);
    let lower2 = freq2.saturating_sub(bw2 / 2);

    let mut lower_overlap = 0;
    let mut upper_overlap = 0;
    let mut ratio = 0.0;

    if lower2 < upper1 && upper2 > lower1 {
        if lower2 >= lower1 {
            lower_overlap = lower2;
            if upper2 <= upper1 {
                upper_overlap = upper2;
                ratio = 1.0;
            } else {
                upper_overlap = upper1;
                ratio = (upper1 - lower2) as f64 / bw2 as f64;
            }
        } else {
            lower_overlap = lower1;
            if upper2 <= upper1 {
                upper_overlap = upper2;
                ratio = (upper2 - lower1) as f64 / bw2 as f64;
            } else {
                upper_overlap = upper1;
                ratio = (upper1 - lower1) as f64 / bw2 as f64;
            }
        }
    }

    (ratio, lower_overlap, upper_overlap)
}

#[repr(C)]
pub struct FfiSpectralSegment {
    overlap_ratio: f64,
    modifier_mw: f64,
    lower_hz: u64,
    upper_hz: u64,
}

#[repr(C)]
pub struct FfiSpectralOverlap {
    segments: *mut FfiSpectralSegment,
    segments_len: usize,
    lower_hz: u64,
    upper_hz: u64,
}

#[repr(C)]
pub struct FfiMaskOverlap {
    overlaps: *mut FfiSpectralOverlap,
    overlaps_len: usize,
    lower_hz: u64,
    upper_hz: u64,
    total: u64,
}

#[derive(Default)]
pub struct SpectralMaskManager {
    // mask_id -> Vec<(offset, bandwidth, Vec<(width, dBr)>)>
    masks: HashMap<u16, Vec<(i64, u64, Vec<(u64, f64)>)>>,
}

impl SpectralMaskManager {
    pub fn new() -> Self {
        Self {
            masks: HashMap::new(),
        }
    }

    pub fn load(&mut self, uri: &str) -> Result<(), String> {
        let path = file_uri_path(uri)?;
        let content = emane_plugin_api::xml_document::read(&path)
            .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
        let doc = Document::parse_with_options(
            &content,
            roxmltree::ParsingOptions {
                allow_dtd: true,
                ..Default::default()
            },
        )
        .map_err(|e| format!("Failed to parse XML: {}", e))?;

        let root = doc.root_element();
        emane_plugin_api::xml_schema::validate(root, emane_plugin_api::xml_schema::SPECTRAL_MASK)?;
        if root.tag_name().name() != "spectral-mask-manifest" {
            return Err("Invalid document root".to_string());
        }

        for node in root
            .children()
            .filter(|n| n.is_element() && n.tag_name().name() == "mask")
        {
            let id_str = node.attribute("id").ok_or("mask missing id attribute")?;
            let id: u16 = id_str.parse().map_err(|_| "invalid mask id")?;
            if id == 0 || self.masks.contains_key(&id) {
                return Err(format!("invalid or duplicate mask id {id}"));
            }

            let mut mask_entries = Vec::new();
            let mut primary_count = 0usize;

            for child in node.children().filter(|n| n.is_element()) {
                if child.tag_name().name() == "primary" {
                    primary_count += 1;
                    if primary_count != 1 || !mask_entries.is_empty() {
                        return Err(format!("mask {id} has an invalid primary section"));
                    }
                    let mut shape = Vec::new();
                    let mut bandwidth = 0u64;
                    for width_node in child
                        .children()
                        .filter(|n| n.is_element() && n.tag_name().name() == "width")
                    {
                        let hz_str = width_node
                            .attribute("hz")
                            .ok_or("primary width missing hz")?;
                        let hz = parse_frequency(hz_str)?;

                        let dbr = if let Some(dbr_str) = width_node.attribute("dBr") {
                            parse_finite(dbr_str, "invalid primary dBr")?
                        } else {
                            0.0
                        };

                        shape.push((hz, db_to_milliwatt(dbr)));
                        bandwidth = bandwidth
                            .checked_add(hz)
                            .ok_or("primary bandwidth overflow")?;
                    }
                    if shape.is_empty() {
                        return Err(format!("mask {id} primary has no widths"));
                    }
                    mask_entries.push((0, bandwidth, shape));
                } else if child.tag_name().name() == "spurs" {
                    for spur_node in child
                        .children()
                        .filter(|n| n.is_element() && n.tag_name().name() == "spur")
                    {
                        let offset_str = spur_node
                            .attribute("offset_from_center_hz")
                            .ok_or("spur missing offset")?;
                        let offset = parse_frequency_i64(offset_str)?;

                        let mut shape = Vec::new();
                        let mut bandwidth = 0u64;
                        for width_node in spur_node
                            .children()
                            .filter(|n| n.is_element() && n.tag_name().name() == "width")
                        {
                            let hz_str =
                                width_node.attribute("hz").ok_or("spur width missing hz")?;
                            let hz = parse_frequency(hz_str)?;

                            let dbr = parse_finite(
                                width_node
                                    .attribute("dBr")
                                    .ok_or("spur width missing dBr")?,
                                "invalid spur dBr",
                            )?;

                            shape.push((hz, db_to_milliwatt(dbr)));
                            bandwidth =
                                bandwidth.checked_add(hz).ok_or("spur bandwidth overflow")?;
                        }
                        if shape.is_empty() {
                            return Err(format!("mask {id} spur has no widths"));
                        }
                        mask_entries.push((offset, bandwidth, shape));
                    }
                }
            }
            if primary_count != 1 {
                return Err(format!("mask {id} must contain exactly one primary"));
            }
            self.masks.insert(id, mask_entries);
        }

        Ok(())
    }

    pub fn get_primary_signal_bandwidth(&self, mask_id: u16) -> u64 {
        if mask_id != 0 {
            if let Some(mask) = self.masks.get(&mask_id) {
                if !mask.is_empty() {
                    return mask[0].1;
                }
            }
        }
        0
    }

    pub fn get_spectral_overlap(
        &self,
        tx_freq: u64,
        rx_freq: u64,
        mut rx_bw: u64,
        tx_bw: u64,
        mask_id: u16,
    ) -> Option<(Vec<(Vec<(f64, f64, u64, u64)>, u64, u64)>, u64, u64, u64)> {
        if mask_id != 0 {
            if let Some(mask_entries) = self.masks.get(&mask_id) {
                let mut lower_mask_overlap = u64::MAX;
                let mut upper_mask_overlap = 0;
                let mut total = 0;
                let mut overlaps = Vec::new();

                for (offset, mask_bw, shape) in mask_entries {
                    if rx_bw == 0 {
                        rx_bw = *mask_bw;
                    }

                    let mut lower_spur_overlap = u64::MAX;
                    let mut upper_spur_overlap = 0;
                    let mut segments = Vec::new();

                    let tx_lower =
                        i128::from(tx_freq) + i128::from(*offset) - i128::from(*mask_bw / 2);
                    if !(0..=i128::from(u64::MAX)).contains(&tx_lower) {
                        continue;
                    }
                    let mut tx_lower = tx_lower as u64;

                    for (seg_width, seg_mw) in shape {
                        let seg_width = *seg_width;
                        let Some(tx_upper) = tx_lower.checked_add(seg_width) else {
                            break;
                        };

                        let tx_center = tx_lower.saturating_add(seg_width / 2);

                        let (ratio, lower_seg, upper_seg) =
                            frequency_overlap_ratio(rx_freq, rx_bw, tx_center, seg_width);

                        if ratio > 0.0 {
                            segments.push((ratio, *seg_mw, tx_lower, tx_upper));
                            if lower_spur_overlap > lower_seg {
                                lower_spur_overlap = lower_seg;
                            }
                            if upper_spur_overlap < upper_seg {
                                upper_spur_overlap = upper_seg;
                            }
                            total += 1;
                        }

                        tx_lower = tx_upper;
                    }

                    if !segments.is_empty() {
                        if lower_mask_overlap > lower_spur_overlap {
                            lower_mask_overlap = lower_spur_overlap;
                        }
                        if upper_mask_overlap < upper_spur_overlap {
                            upper_mask_overlap = upper_spur_overlap;
                        }
                        overlaps.push((segments, lower_spur_overlap, upper_spur_overlap));
                    }
                }

                if !overlaps.is_empty() {
                    return Some((overlaps, lower_mask_overlap, upper_mask_overlap, total));
                }
            }
        } else {
            let (ratio, lower, upper) = frequency_overlap_ratio(rx_freq, rx_bw, tx_freq, tx_bw);
            if ratio > 0.0 {
                let segments = vec![(ratio, 1.0, lower, upper)];
                let overlaps = vec![(segments, lower, upper)];
                return Some((overlaps, lower, upper, 1));
            }
        }
        None
    }
}

fn parse_finite(val: &str, error: &str) -> Result<f64, String> {
    let value: f64 = val.parse().map_err(|_| error.to_string())?;
    value
        .is_finite()
        .then_some(value)
        .ok_or_else(|| error.to_string())
}

fn parse_frequency(val: &str) -> Result<u64, String> {
    let (num_str, multiplier) = if let Some(value) = val.strip_suffix('G') {
        (value, 1_000_000_000.0)
    } else if let Some(value) = val.strip_suffix('M') {
        (value, 1_000_000.0)
    } else if let Some(value) = val.strip_suffix('K') {
        (value, 1_000.0)
    } else {
        (val, 1.0)
    };

    let num = parse_finite(num_str, "invalid frequency")?;
    let scaled = num * multiplier;
    if num < 0.0 || !scaled.is_finite() || scaled > u64::MAX as f64 {
        return Err("invalid frequency".to_string());
    }
    Ok(scaled as u64)
}

fn parse_frequency_i64(val: &str) -> Result<i64, String> {
    let mut multiplier = 1.0;
    let mut num_str = val;
    let mut sign = 1.0;

    if num_str.starts_with('-') {
        sign = -1.0;
        num_str = &num_str[1..];
    } else if num_str.starts_with('+') {
        num_str = &num_str[1..];
    }

    if num_str.ends_with('G') {
        multiplier = 1_000_000_000.0;
        num_str = &num_str[..num_str.len() - 1];
    } else if num_str.ends_with('M') {
        multiplier = 1_000_000.0;
        num_str = &num_str[..num_str.len() - 1];
    } else if num_str.ends_with('K') {
        multiplier = 1_000.0;
        num_str = &num_str[..num_str.len() - 1];
    }

    let num = parse_finite(num_str, "invalid signed frequency")?;
    let scaled = sign * num * multiplier;
    if num < 0.0 || !scaled.is_finite() || scaled < i64::MIN as f64 || scaled > i64::MAX as f64 {
        return Err("invalid signed frequency".to_string());
    }
    Ok(scaled as i64)
}

fn db_to_milliwatt(db: f64) -> f64 {
    10.0f64.powf(db / 10.0)
}

static MANAGER: OnceLock<SpectralMaskManager> = OnceLock::new();
static EMPTY_MANAGER: OnceLock<SpectralMaskManager> = OnceLock::new();

pub fn get_manager() -> &'static SpectralMaskManager {
    MANAGER
        .get()
        .unwrap_or_else(|| EMPTY_MANAGER.get_or_init(SpectralMaskManager::new))
}

pub fn load_global(uri: &str) -> Result<(), String> {
    let mut manager = SpectralMaskManager::new();
    manager.load(uri)?;
    MANAGER
        .set(manager)
        .map_err(|_| "spectral masks already loaded".to_string())
}

#[no_mangle]
pub extern "C" fn emane_rs_spectral_mask_load(
    uri: *const c_char,
    error_buf: *mut c_char,
    error_buf_len: usize,
) {
    if uri.is_null() {
        write_error(error_buf, error_buf_len, "null spectral mask URI");
        return;
    }
    let uri_str = unsafe { CStr::from_ptr(uri).to_string_lossy() };
    let result = load_global(&uri_str);
    match result {
        Ok(_) => {
            if !error_buf.is_null() && error_buf_len > 0 {
                unsafe {
                    *error_buf = 0;
                }
            }
        }
        Err(e) => {
            if !error_buf.is_null() && error_buf_len > 0 {
                write_error(error_buf, error_buf_len, &e);
            }
        }
    }
}

fn write_error(error_buf: *mut c_char, error_buf_len: usize, message: &str) {
    if error_buf.is_null() || error_buf_len == 0 {
        return;
    }
    let message = CString::new(message).unwrap_or_else(|_| CString::new("invalid error").unwrap());
    let bytes = message.as_bytes();
    let copy_len = bytes.len().min(error_buf_len - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), error_buf.cast::<u8>(), copy_len);
        *error_buf.add(copy_len) = 0;
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_spectral_mask_get_primary_bandwidth(mask_id: u16) -> u64 {
    get_manager().get_primary_signal_bandwidth(mask_id)
}

#[no_mangle]
pub extern "C" fn emane_rs_spectral_mask_get_overlap(
    tx_freq: u64,
    rx_freq: u64,
    rx_bw: u64,
    tx_bw: u64,
    mask_id: u16,
    out: *mut FfiMaskOverlap,
) -> bool {
    if out.is_null() {
        return false;
    }
    if let Some((overlaps, lower, upper, total)) =
        get_manager().get_spectral_overlap(tx_freq, rx_freq, rx_bw, tx_bw, mask_id)
    {
        let mut ffi_overlaps = Vec::with_capacity(overlaps.len());
        for (segments, spur_lower, spur_upper) in overlaps {
            let mut ffi_segments = Vec::with_capacity(segments.len());
            for (ratio, mw, seg_lower, seg_upper) in segments {
                ffi_segments.push(FfiSpectralSegment {
                    overlap_ratio: ratio,
                    modifier_mw: mw,
                    lower_hz: seg_lower,
                    upper_hz: seg_upper,
                });
            }

            let segments_len = ffi_segments.len();
            let segments_ptr = ffi_segments.leak().as_mut_ptr();

            ffi_overlaps.push(FfiSpectralOverlap {
                segments: segments_ptr,
                segments_len,
                lower_hz: spur_lower,
                upper_hz: spur_upper,
            });
        }

        let overlaps_len = ffi_overlaps.len();
        let overlaps_ptr = ffi_overlaps.leak().as_mut_ptr();

        unsafe {
            *out = FfiMaskOverlap {
                overlaps: overlaps_ptr,
                overlaps_len,
                lower_hz: lower,
                upper_hz: upper,
                total,
            };
        }
        true
    } else {
        false
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_spectral_mask_free_overlap(overlap: *mut FfiMaskOverlap) {
    unsafe {
        if overlap.is_null() {
            return;
        }

        if (*overlap).overlaps_len == 0 {
            (*overlap).overlaps = std::ptr::null_mut();
            return;
        }
        if (*overlap).overlaps.is_null() {
            return;
        }

        let overlaps = Vec::from_raw_parts(
            (*overlap).overlaps,
            (*overlap).overlaps_len,
            (*overlap).overlaps_len,
        );
        for ov in overlaps {
            if !ov.segments.is_null() {
                Vec::from_raw_parts(ov.segments, ov.segments_len, ov.segments_len);
            }
        }
        (*overlap).overlaps = std::ptr::null_mut();
        (*overlap).overlaps_len = 0;
        (*overlap).total = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_finite_and_out_of_range_frequencies() {
        assert!(parse_frequency("NaN").is_err());
        assert!(parse_frequency("-1").is_err());
        assert!(parse_frequency_i64("+inf").is_err());
    }

    #[test]
    fn negative_spur_does_not_wrap_below_zero() {
        let mut manager = SpectralMaskManager::new();
        manager.masks.insert(1, vec![(-200, 100, vec![(100, 1.0)])]);
        assert!(manager
            .get_spectral_overlap(100, 100, 100, 100, 1)
            .is_none());
    }
}
