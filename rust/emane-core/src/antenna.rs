use roxmltree::{Document, ParsingOptions};
use std::collections::{BTreeMap, HashMap};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::{Path, PathBuf};
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

fn resolve_uri(uri: &str, manifest_path: &Path) -> Result<PathBuf, String> {
    let path = file_uri_path(uri)?;
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(manifest_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(path))
    }
}

pub struct AntennaPattern {
    elevation_bearing_gain: BTreeMap<i16, Option<BTreeMap<i16, f64>>>,
    missing_value: f64,
}

impl AntennaPattern {
    pub fn new(uri: &str, sub_root_name: &str, missing_value: f64) -> Result<Self, String> {
        let path = file_uri_path(uri)?;
        let content = emane_plugin_api::xml_document::read(&path)
            .map_err(|e| format!("Unable to read {}: {}", path.display(), e))?;
        let doc = Document::parse_with_options(
            &content,
            ParsingOptions {
                allow_dtd: true,
                ..ParsingOptions::default()
            },
        )
        .map_err(|e| format!("Validation failure {}: {}", uri, e))?;

        let root = doc.root_element();
        if root.tag_name().name() != "antennaprofile" {
            return Err(format!("Invalid antenna pattern root {}", uri));
        }

        let mut pattern = AntennaPattern {
            elevation_bearing_gain: BTreeMap::new(),
            missing_value,
        };

        for node in root
            .children()
            .filter(|n| n.is_element() && n.tag_name().name() == sub_root_name)
        {
            let mut elevation_range_max: i16 = 0;
            let mut first_elevation = true;

            for elevation_node in node
                .children()
                .filter(|n| n.is_element() && n.tag_name().name() == "elevation")
            {
                let min_str = elevation_node
                    .attribute("min")
                    .ok_or_else(|| format!("Bad entry {}: elevation missing min", uri))?;
                let elevation_min: i16 = min_str
                    .parse()
                    .map_err(|_| format!("Bad entry {}: elevation min parse", uri))?;

                let max_str = elevation_node
                    .attribute("max")
                    .ok_or_else(|| format!("Bad entry {}: elevation missing max", uri))?;
                let elevation_max: i16 = max_str
                    .parse()
                    .map_err(|_| format!("Bad entry {}: elevation max parse", uri))?;

                if elevation_min > elevation_max {
                    return Err(format!(
                        "Bad entry {}: elevation [{},{}] min > max",
                        uri, elevation_min, elevation_max
                    ));
                }

                if !first_elevation
                    && elevation_range_max >= elevation_min
                    && !pattern.elevation_bearing_gain.is_empty()
                {
                    return Err(format!("Bad entry {}: elevation [{},{}] may be out of order or overlap with a previous elevation", uri, elevation_min, elevation_max));
                } else {
                    elevation_range_max = elevation_max;
                    first_elevation = false;
                }

                let mut bearing_gain_map = BTreeMap::new();
                let mut bearing_range_max: i16 = 0;
                let mut first_bearing = true;

                for bearing_node in elevation_node
                    .children()
                    .filter(|n| n.is_element() && n.tag_name().name() == "bearing")
                {
                    let b_min_str = bearing_node
                        .attribute("min")
                        .ok_or_else(|| format!("Bad entry {}: bearing missing min", uri))?;
                    let bearing_min: i16 = b_min_str
                        .parse()
                        .map_err(|_| format!("Bad entry {}: bearing min parse", uri))?;

                    let b_max_str = bearing_node
                        .attribute("max")
                        .ok_or_else(|| format!("Bad entry {}: bearing missing max", uri))?;
                    let bearing_max: i16 = b_max_str
                        .parse()
                        .map_err(|_| format!("Bad entry {}: bearing max parse", uri))?;

                    if bearing_min > bearing_max {
                        return Err(format!(
                            "Bad entry {}: elevation [{},{}] bearing [{},{}] min > max",
                            uri, elevation_min, elevation_max, bearing_min, bearing_max
                        ));
                    }

                    if !first_bearing
                        && bearing_range_max >= bearing_min
                        && !bearing_gain_map.is_empty()
                    {
                        return Err(format!("Bad entry {}: elevation [{},{}] bearing [{},{}] may be out of order or overlap", uri, elevation_min, elevation_max, bearing_min, bearing_max));
                    } else {
                        bearing_range_max = bearing_max;
                        first_bearing = false;
                    }

                    for gain_node in bearing_node
                        .children()
                        .filter(|n| n.is_element() && n.tag_name().name() == "gain")
                    {
                        let gain_str = gain_node
                            .attribute("value")
                            .ok_or_else(|| format!("Bad entry {}: gain missing value", uri))?;
                        let gain: f64 = gain_str
                            .parse()
                            .map_err(|_| format!("Bad entry {}: gain value parse", uri))?;
                        if !gain.is_finite() {
                            return Err(format!("Bad entry {}: gain must be finite", uri));
                        }

                        let Some(preceding_bearing) = bearing_min.checked_sub(1) else {
                            return Err(format!(
                                "Bad entry {}: bearing minimum is out of range",
                                uri
                            ));
                        };
                        bearing_gain_map
                            .entry(preceding_bearing)
                            .or_insert(missing_value);
                        bearing_gain_map.insert(bearing_max, gain);
                    }
                }

                let Some(preceding_elevation) = elevation_min.checked_sub(1) else {
                    return Err(format!(
                        "Bad entry {}: elevation minimum is out of range",
                        uri
                    ));
                };
                pattern
                    .elevation_bearing_gain
                    .entry(preceding_elevation)
                    .or_insert(None);
                pattern
                    .elevation_bearing_gain
                    .insert(elevation_max, Some(bearing_gain_map));
            }
        }

        if pattern.elevation_bearing_gain.is_empty() {
            return Err(format!("Bad entry {}: missing {}", uri, sub_root_name));
        }

        Ok(pattern)
    }

    pub fn get_gain(&self, mut bearing: i16, elevation: i16) -> f64 {
        let mut gain = self.missing_value;

        if bearing == 360 {
            bearing = 0;
        }

        if let Some((_, Some(bearing_map))) = self.elevation_bearing_gain.range(elevation..).next()
        {
            if let Some((_, val)) = bearing_map.range(bearing..).next() {
                gain = *val;
            }
        }

        gain
    }
}

pub struct AntennaProfileManifest {
    profiles: HashMap<u16, (usize, usize, f64, f64, f64)>, // (antenna_idx, blockage_idx, north, east, up)
    patterns: Vec<AntennaPattern>,
    pattern_uri_to_idx: HashMap<String, usize>,
}

impl Default for AntennaProfileManifest {
    fn default() -> Self {
        Self::new()
    }
}

impl AntennaProfileManifest {
    pub fn new() -> Self {
        Self {
            profiles: HashMap::new(),
            patterns: Vec::new(),
            pattern_uri_to_idx: HashMap::new(),
        }
    }

    fn get_or_load_pattern(
        &mut self,
        uri: &str,
        sub_root: &str,
        missing: f64,
    ) -> Result<usize, String> {
        if let Some(&idx) = self.pattern_uri_to_idx.get(uri) {
            return Ok(idx);
        }
        let p = AntennaPattern::new(uri, sub_root, missing)?;
        let idx = self.patterns.len();
        self.patterns.push(p);
        self.pattern_uri_to_idx.insert(uri.to_string(), idx);
        Ok(idx)
    }

    pub fn load(&mut self, uri: &str) -> Result<(), String> {
        let manifest_path = file_uri_path(uri)?;
        let content = emane_plugin_api::xml_document::read(&manifest_path)
            .map_err(|e| format!("Unable to read {}: {}", manifest_path.display(), e))?;
        let doc = Document::parse_with_options(
            &content,
            ParsingOptions {
                allow_dtd: true,
                ..ParsingOptions::default()
            },
        )
        .map_err(|e| format!("Validation failure {}: {}", uri, e))?;

        let root = doc.root_element();
        if root.tag_name().name() != "profiles" {
            return Err(format!(
                "Invalid antenna profile manifest root {}",
                manifest_path.display()
            ));
        }

        for node in root
            .children()
            .filter(|n| n.is_element() && n.tag_name().name() == "profile")
        {
            let id_str = node
                .attribute("id")
                .ok_or_else(|| "profile missing id".to_string())?;
            let id: u16 = id_str.parse().map_err(|_| "profile id parse".to_string())?;

            let antenna_uri = node
                .attribute("antennapatternuri")
                .ok_or_else(|| "profile missing antennapatternuri".to_string())?;
            let blockage_uri = node.attribute("blockagepatternuri");

            let mut north: f64 = 0.0;
            let mut east: f64 = 0.0;
            let mut up: f64 = 0.0;

            let mut placements = 0usize;
            for child in node
                .children()
                .filter(|n| n.is_element() && n.tag_name().name() == "placement")
            {
                placements += 1;
                if placements > 1 {
                    return Err(format!("profile {id} has multiple placements"));
                }
                north = child
                    .attribute("north")
                    .ok_or_else(|| format!("profile {id} placement missing north"))?
                    .parse()
                    .map_err(|_| format!("profile {id} placement north parse"))?;
                east = child
                    .attribute("east")
                    .ok_or_else(|| format!("profile {id} placement missing east"))?
                    .parse()
                    .map_err(|_| format!("profile {id} placement east parse"))?;
                up = child
                    .attribute("up")
                    .ok_or_else(|| format!("profile {id} placement missing up"))?
                    .parse()
                    .map_err(|_| format!("profile {id} placement up parse"))?;
                if !north.is_finite() || !east.is_finite() || !up.is_finite() {
                    return Err(format!("profile {id} placement must be finite"));
                }
            }

            let antenna_path = resolve_uri(antenna_uri, &manifest_path)?;
            let antenna_path = antenna_path.to_str().ok_or_else(|| {
                format!("non-UTF-8 antenna pattern path: {}", antenna_path.display())
            })?;
            let ant_idx = self.get_or_load_pattern(
                antenna_path,
                "antennapattern",
                -327.0, /* legacy EMANE::DBM_MIN */
            )?;

            let mut blk_idx = usize::MAX;
            if let Some(uri) = blockage_uri {
                if !uri.is_empty() {
                    let blockage_path = resolve_uri(uri, &manifest_path)?;
                    let blockage_path = blockage_path.to_str().ok_or_else(|| {
                        format!(
                            "non-UTF-8 blockage pattern path: {}",
                            blockage_path.display()
                        )
                    })?;
                    blk_idx = self.get_or_load_pattern(blockage_path, "blockagepattern", 0.0)?;
                }
            }

            if self.profiles.contains_key(&id) {
                return Err(format!("Duplicate antenna profile id {}", id));
            }
            self.profiles
                .insert(id, (ant_idx, blk_idx, north, east, up));
        }

        Ok(())
    }

    pub fn get_profile_info(
        &self,
        id: u16,
    ) -> Option<(*const AntennaPattern, *const AntennaPattern, f64, f64, f64)> {
        if let Some(&(ant_idx, blk_idx, north, east, up)) = self.profiles.get(&id) {
            let ant_ptr = &self.patterns[ant_idx] as *const AntennaPattern;
            let blk_ptr = if blk_idx == usize::MAX {
                std::ptr::null()
            } else {
                &self.patterns[blk_idx] as *const AntennaPattern
            };
            Some((ant_ptr, blk_ptr, north, east, up))
        } else {
            None
        }
    }

    pub fn get_profile_gain(
        &self,
        id: u16,
        bearing_degrees: f64,
        elevation_degrees: f64,
        blockage_bearing_degrees: f64,
        blockage_elevation_degrees: f64,
    ) -> Option<f64> {
        let &(antenna_index, blockage_index, _, _, _) = self.profiles.get(&id)?;
        let bearing = bearing_degrees.round().clamp(0.0, 360.0) as i16;
        let elevation = elevation_degrees.round().clamp(-90.0, 90.0) as i16;
        let mut gain = self.patterns[antenna_index].get_gain(bearing, elevation);
        if blockage_index != usize::MAX {
            let blockage_bearing = blockage_bearing_degrees.round().clamp(0.0, 360.0) as i16;
            let blockage_elevation = blockage_elevation_degrees.round().clamp(-90.0, 90.0) as i16;
            gain += self.patterns[blockage_index].get_gain(blockage_bearing, blockage_elevation);
        }
        Some(gain)
    }
}

static MANAGER: OnceLock<AntennaProfileManifest> = OnceLock::new();
static EMPTY_MANAGER: OnceLock<AntennaProfileManifest> = OnceLock::new();

pub fn get_manager() -> &'static AntennaProfileManifest {
    MANAGER
        .get()
        .unwrap_or_else(|| EMPTY_MANAGER.get_or_init(AntennaProfileManifest::new))
}

pub fn load_global(uri: &str) -> Result<(), String> {
    let mut manager = AntennaProfileManifest::new();
    manager.load(uri)?;
    MANAGER
        .set(manager)
        .map_err(|_| "antenna profiles already loaded".to_string())
}

#[no_mangle]
pub extern "C" fn emane_rs_antenna_profile_load(
    uri: *const c_char,
    error_buf: *mut c_char,
    error_buf_len: usize,
) {
    if uri.is_null() {
        write_error(error_buf, error_buf_len, "null antenna profile URI");
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
pub extern "C" fn emane_rs_antenna_profile_get_info(
    id: u16,
    ant_ptr_out: *mut *const AntennaPattern,
    blk_ptr_out: *mut *const AntennaPattern,
    north_out: *mut f64,
    east_out: *mut f64,
    up_out: *mut f64,
) -> bool {
    if ant_ptr_out.is_null()
        || blk_ptr_out.is_null()
        || north_out.is_null()
        || east_out.is_null()
        || up_out.is_null()
    {
        return false;
    }
    if let Some((a, b, n, e, u)) = get_manager().get_profile_info(id) {
        unsafe {
            *ant_ptr_out = a;
            *blk_ptr_out = b;
            *north_out = n;
            *east_out = e;
            *up_out = u;
        }
        true
    } else {
        false
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_antenna_pattern_get_gain(
    pattern: *const AntennaPattern,
    bearing: i16,
    elevation: i16,
) -> f64 {
    if pattern.is_null() {
        return -300.0; // Fallback
    }
    unsafe { (*pattern).get_gain(bearing, elevation) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn loads_file_uri_and_resolves_patterns_relative_to_manifest() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("emane-antenna-{unique}"));
        std::fs::create_dir(&directory).unwrap();
        let pattern = directory.join("pattern.xml");
        let manifest = directory.join("manifest.xml");
        std::fs::write(
            &pattern,
            r#"<!DOCTYPE antennaprofile SYSTEM "file:///usr/share/emane/dtd/antennaprofile.dtd"><antennaprofile><antennapattern><elevation min="-90" max="90"><bearing min="0" max="5"><gain value="7.5"/></bearing></elevation></antennapattern></antennaprofile>"#,
        )
        .unwrap();
        std::fs::write(
            &manifest,
            r#"<!DOCTYPE profiles SYSTEM "file:///usr/share/emane/dtd/antennaprofile.dtd"><profiles><profile id="3" antennapatternuri="pattern.xml"><placement north="1" east="2" up="3"/></profile></profiles>"#,
        )
        .unwrap();

        let mut profiles = AntennaProfileManifest::new();
        profiles
            .load(&format!("file://{}", manifest.display()))
            .unwrap();
        assert_eq!(profiles.get_profile_gain(3, 3.0, 0.0, 3.0, 0.0), Some(7.5));
        assert_eq!(
            profiles.get_profile_gain(3, 180.0, 0.0, 180.0, 0.0),
            Some(-327.0)
        );
        assert!(profiles.get_profile_info(3).is_some());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn rejects_invalid_manifest_root_and_non_finite_placement() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("emane-antenna-invalid-{unique}"));
        std::fs::create_dir(&directory).unwrap();
        let manifest = directory.join("manifest.xml");
        std::fs::write(&manifest, "<antennaprofilemanifest/>").unwrap();
        assert!(AntennaProfileManifest::new()
            .load(manifest.to_str().unwrap())
            .is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
