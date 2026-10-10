use std::collections::HashMap;
use std::ffi::{c_char, c_void, CStr};

pub struct PCREntry {
    pub sinr: f32,
    pub por: f32,
}

pub struct PcrPor {
    pub pcr: Vec<PCREntry>,
    pub por: Vec<f32>,
}

pub struct PCRManager {
    pcr_por_map: HashMap<u16, PcrPor>,
    table_packet_size: u32,
    precision_factor: i32,
}

impl PCRManager {
    pub fn new() -> Self {
        Self {
            pcr_por_map: HashMap::new(),
            table_packet_size: 0,
            precision_factor: 100,
        }
    }

    pub fn load(&mut self, uri: &str) -> Result<(), String> {
        let uri = uri.strip_prefix("file://").unwrap_or(uri);
        let content = emane_plugin_api::xml_document::read(uri)
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
        if !root.has_tag_name("pcr") {
            return Err("Invalid PCR document root".to_string());
        }
        let mut tables = root.children().filter(|node| node.has_tag_name("table"));
        let table = tables
            .next()
            .ok_or_else(|| "PCR document has no table".to_string())?;
        if tables.next().is_some() {
            return Err("PCR document has multiple tables".to_string());
        }
        let table_packet_size = table
            .attribute("pktsize")
            .ok_or_else(|| "PCR table is missing pktsize".to_string())?
            .parse::<u32>()
            .map_err(|_| "PCR table has invalid pktsize".to_string())?;
        let mut curves = HashMap::new();
        for datarate in table
            .children()
            .filter(|node| node.has_tag_name("datarate"))
        {
            let index = datarate
                .attribute("index")
                .ok_or_else(|| "PCR datarate is missing index".to_string())?
                .parse::<u16>()
                .map_err(|_| "PCR datarate has invalid index".to_string())?;
            if index == 0 {
                return Err("PCR datarate index must be nonzero".to_string());
            }
            let mut points = Vec::new();
            for row in datarate.children().filter(|node| node.has_tag_name("row")) {
                let sinr = row
                    .attribute("sinr")
                    .ok_or_else(|| "PCR row is missing sinr".to_string())?
                    .parse::<f32>()
                    .map_err(|_| "PCR row has invalid sinr".to_string())?;
                let percent = row
                    .attribute("por")
                    .ok_or_else(|| "PCR row is missing por".to_string())?
                    .parse::<f32>()
                    .map_err(|_| "PCR row has invalid por".to_string())?;
                if !sinr.is_finite()
                    || !percent.is_finite()
                    || !(0.0..=100.0).contains(&percent)
                    || points
                        .last()
                        .is_some_and(|last: &PCREntry| sinr <= last.sinr)
                {
                    return Err(format!("invalid PCR row for datarate index {index}"));
                }
                points.push(PCREntry {
                    sinr,
                    por: percent / 100.0,
                });
            }
            if points.is_empty()
                || curves
                    .insert(
                        index,
                        PcrPor {
                            pcr: points,
                            por: Vec::new(),
                        },
                    )
                    .is_some()
            {
                return Err(format!("empty or duplicate PCR datarate index {index}"));
            }
        }
        if curves.is_empty() {
            return Err("PCR document has no datarates".to_string());
        }
        self.table_packet_size = table_packet_size;
        self.pcr_por_map = curves;

        self.interpolate();
        Ok(())
    }

    pub fn contains_rate(&self, index: u16) -> bool {
        self.pcr_por_map.contains_key(&index)
    }

    fn interpolate(&mut self) {
        for pcr_por in self.pcr_por_map.values_mut() {
            for i in 0..pcr_por.pcr.len().saturating_sub(1) {
                let x1 = (pcr_por.pcr[i].sinr * self.precision_factor as f32) as i32;
                let y1 = pcr_por.pcr[i].por;
                let x2 = (pcr_por.pcr[i + 1].sinr * self.precision_factor as f32) as i32;
                let y2 = pcr_por.pcr[i + 1].por;

                let slope = (y2 - y1) / (x2 - x1) as f32;

                for dx in x1..x2 {
                    pcr_por.por.push(((dx - x1) as f32) * slope + y1);
                }
            }

            pcr_por.por.push(pcr_por.pcr.last().unwrap().por);
        }
    }

    pub fn get_pcr(&self, sinr: f32, packet_len: usize, data_rate_index: u16) -> f32 {
        if let Some(pcr_por) = self.pcr_por_map.get(&data_rate_index) {
            if pcr_por.pcr.is_empty() {
                return 0.0;
            }

            let first = pcr_por.pcr.first().unwrap();
            let last = pcr_por.pcr.last().unwrap();

            if sinr < first.sinr {
                return 0.0;
            } else if sinr > last.sinr {
                return 1.0;
            }

            let mut por = if first.sinr == last.sinr {
                first.por
            } else {
                let sinr_scaled = (sinr * self.precision_factor as f32) as i32;
                let sinr_offset = (first.sinr * self.precision_factor as f32) as i32;

                let mut idx = (sinr_scaled - sinr_offset) as usize;
                if idx >= pcr_por.por.len() {
                    idx = pcr_por.por.len() - 1;
                }

                pcr_por.por[idx]
            };

            if self.table_packet_size > 0 {
                por = por.powf(packet_len as f32 / self.table_packet_size as f32);
            }

            por
        } else {
            0.0
        }
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_ieee80211abg_pcrmanager_new() -> *mut c_void {
    Box::into_raw(Box::new(PCRManager::new())) as *mut c_void
}

#[no_mangle]
pub extern "C" fn emane_rs_ieee80211abg_pcrmanager_drop(mgr: *mut c_void) {
    if !mgr.is_null() {
        unsafe {
            let _ = Box::from_raw(mgr as *mut PCRManager);
        }
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_ieee80211abg_pcrmanager_load(
    mgr: *mut c_void,
    uri: *const c_char,
) -> bool {
    let mgr = unsafe { &mut *(mgr as *mut PCRManager) };
    if uri.is_null() {
        return false;
    }
    let uri_str = unsafe { CStr::from_ptr(uri).to_string_lossy().into_owned() };
    mgr.load(&uri_str).is_ok()
}

#[no_mangle]
pub extern "C" fn emane_rs_ieee80211abg_pcrmanager_get_pcr(
    mgr: *mut c_void,
    sinr: f32,
    packet_len: usize,
    data_rate_index: u16,
) -> f32 {
    let mgr = unsafe { &*(mgr as *mut PCRManager) };
    mgr.get_pcr(sinr, packet_len, data_rate_index)
}

#[cfg(test)]
mod tests {
    use super::PCRManager;

    #[test]
    fn loads_all_rates_from_the_legacy_fixture() {
        let uri = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/ieee80211abg-pcr.xml");
        let mut manager = PCRManager::new();
        manager.load(uri.to_str().unwrap()).unwrap();
        for rate in 1..=12 {
            assert!(manager.contains_rate(rate));
        }
    }
}
