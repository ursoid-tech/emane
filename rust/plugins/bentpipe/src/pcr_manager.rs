use emane_plugin_api::numeric::LegacyParse;
use std::collections::{BTreeMap, HashMap};
use std::ffi::CStr;
use std::os::raw::{c_char, c_void};

pub struct PCRManager {
    modifier_length_bytes: usize,
    curve_table: HashMap<u16, CurveEntry>,
}

pub struct CurveEntry {
    min_scaled_sinr: i32,
    max_scaled_sinr: i32,
    curve: BTreeMap<i32, f32>,
}

impl PCRManager {
    pub fn new() -> Self {
        Self {
            modifier_length_bytes: 0,
            curve_table: HashMap::new(),
        }
    }

    pub fn load(&mut self, file_name: &str) -> Result<(), String> {
        let file_name = file_name.strip_prefix("file://").unwrap_or(file_name);
        let content = emane_plugin_api::xml_document::read(file_name)
            .map_err(|e| format!("Failed to read file: {}", e))?;
        let doc = roxmltree::Document::parse_with_options(
            &content,
            roxmltree::ParsingOptions {
                allow_dtd: true,
                ..Default::default()
            },
        )
        .map_err(|e| format!("Failed to parse XML: {}", e))?;

        let root = doc.root_element();
        if root.tag_name().name() != "bentpipe-model-pcr" {
            return Err("Invalid root element, expected bentpipe-model-pcr".to_string());
        }

        emane_plugin_api::pcr_validation::validate(root, "curve", "index")?;

        if let Some(packet_size) = root.attribute("packetsize") {
            self.modifier_length_bytes = packet_size
                .parse_legacy::<u16>()
                .map_err(|_| "Invalid packetsize")?
                as usize;
        } else {
            return Err("Missing packetsize attribute".to_string());
        }

        self.curve_table.clear();

        for curve_node in root.children().filter(|n| n.has_tag_name("curve")) {
            let index_str = curve_node.attribute("index").ok_or("Missing curve index")?;
            let index: u16 = index_str
                .parse_legacy()
                .map_err(|_| "Invalid curve index")?;

            let mut curve = BTreeMap::new();
            let mut min_scaled_sinr = i32::MAX;
            let mut max_scaled_sinr = i32::MIN;

            for entry_node in curve_node.children().filter(|n| n.has_tag_name("entry")) {
                let sinr_str = entry_node
                    .attribute("sinr")
                    .ok_or("Missing sinr attribute")?;
                let por_str = entry_node.attribute("por").ok_or("Missing por attribute")?;

                let scaled_sinr = scale_float_to_integer(sinr_str)?;
                let por: f32 = por_str
                    .parse_legacy::<f32>()
                    .map_err(|_| "Invalid por attribute")?;
                if !por.is_finite() || por < 0.0 {
                    return Err("POR must be finite and nonnegative".to_string());
                }
                let por = por / 100.0;

                if curve.insert(scaled_sinr, por).is_some() {
                    return Err(format!(
                        "duplicate PCR SINR value for index: {} sinr: {} in {}",
                        index, sinr_str, file_name
                    ));
                }

                min_scaled_sinr = min_scaled_sinr.min(scaled_sinr);
                max_scaled_sinr = max_scaled_sinr.max(scaled_sinr);
            }

            if curve.is_empty() {
                return Err(format!("PCR curve {index} has no entries"));
            }

            let mut interpolation = BTreeMap::new();
            let mut iter = curve.iter().peekable();

            while let Some((&x0, &y0)) = iter.next() {
                if let Some(&(&x1, &y1)) = iter.peek() {
                    let slope = (y1 - y0) / (x1 - x0) as f32;
                    for i in x0..x1 {
                        interpolation.insert(i, y1 - (x1 - i) as f32 * slope);
                    }
                }
            }

            for (k, v) in interpolation {
                curve.entry(k).or_insert(v);
            }

            if self
                .curve_table
                .insert(
                    index,
                    CurveEntry {
                        min_scaled_sinr,
                        max_scaled_sinr,
                        curve,
                    },
                )
                .is_some()
            {
                return Err(format!("duplicate PCR curve: {} in {}", index, file_name));
            }
        }

        if self.curve_table.is_empty() {
            return Err("PCR document has no curves".to_string());
        }

        Ok(())
    }

    pub fn contains_curve(&self, index: u16) -> bool {
        self.curve_table.contains_key(&index)
    }

    pub fn get_por(&self, index: u16, sinr: f32, packet_length_bytes: usize) -> Option<f32> {
        let entry = self.curve_table.get(&index)?;

        let scaled_sinr = (sinr * 100.0) as i32;

        if scaled_sinr < entry.min_scaled_sinr {
            return Some(0.0);
        }

        if scaled_sinr > entry.max_scaled_sinr {
            return Some(1.0);
        }

        if let Some(&por) = entry.curve.get(&scaled_sinr) {
            let mut result_por = por;
            if self.modifier_length_bytes > 0 {
                result_por =
                    result_por.powf(packet_length_bytes as f32 / self.modifier_length_bytes as f32);
            }
            return Some(result_por);
        }

        Some(0.0)
    }
}

fn scale_float_to_integer(value: &str) -> Result<i32, String> {
    emane_plugin_api::pcr_validation::scaled_sinr(value)
}

#[no_mangle]
pub extern "C" fn rust_bentpipe_pcr_manager_new() -> *mut c_void {
    let manager = Box::new(PCRManager::new());
    Box::into_raw(manager) as *mut c_void
}

#[no_mangle]
pub extern "C" fn rust_bentpipe_pcr_manager_free(ptr: *mut c_void) {
    if !ptr.is_null() {
        unsafe {
            let _ = Box::from_raw(ptr as *mut PCRManager);
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_bentpipe_pcr_manager_load(
    ptr: *mut c_void,
    filename: *const c_char,
) -> bool {
    if ptr.is_null() || filename.is_null() {
        return false;
    }

    let manager = unsafe { &mut *(ptr as *mut PCRManager) };
    let filename_str = unsafe { CStr::from_ptr(filename).to_string_lossy() };

    match manager.load(&filename_str) {
        Ok(_) => true,
        Err(e) => {
            eprintln!("PCRManager load error: {}", e);
            false
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_bentpipe_pcr_manager_get_por(
    ptr: *mut c_void,
    index: u16,
    sinr: f32,
    packet_length_bytes: usize,
    out_por: *mut f32,
) -> bool {
    if ptr.is_null() || out_por.is_null() {
        return false;
    }

    let manager = unsafe { &*(ptr as *mut PCRManager) };
    if let Some(por) = manager.get_por(index, sinr, packet_length_bytes) {
        unsafe { *out_por = por };
        true
    } else {
        false
    }
}

#[no_mangle]
pub extern "C" fn rust_bentpipe_pcr_manager_get_indices(
    ptr: *mut c_void,
    out_indices: *mut u16,
    max_indices: usize,
) -> usize {
    if ptr.is_null() || out_indices.is_null() {
        return 0;
    }

    let manager = unsafe { &*(ptr as *mut PCRManager) };
    let mut count = 0;

    for &index in manager.curve_table.keys() {
        if count >= max_indices {
            break;
        }
        unsafe {
            *out_indices.add(count) = index;
        }
        count += 1;
    }

    count
}
