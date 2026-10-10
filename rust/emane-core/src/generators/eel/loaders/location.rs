use emane_plugin_api::numeric::LegacyParse;
use prost::Message;
use std::collections::HashMap;
use std::ffi::CStr;
use std::os::raw::{c_char, c_void};

use crate::protobufs::emane_message;

#[derive(Clone, Default)]
struct LocationEntry {
    has_position: bool,
    lat: f64,
    lon: f64,
    alt: f64,
    has_orientation: bool,
    roll: f64,
    pitch: f64,
    yaw: f64,
    has_velocity: bool,
    azimuth: f64,
    elevation: f64,
    magnitude: f64,
}

pub struct LocationLoader {
    cache: HashMap<u16, LocationEntry>,
    delta_cache: HashMap<u16, LocationEntry>,
}

impl Default for LocationLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl LocationLoader {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
            delta_cache: HashMap::new(),
        }
    }

    pub fn load(
        &mut self,
        module_type: &str,
        module_id: u16,
        event_type: &str,
        args: &[String],
    ) -> Result<(), String> {
        if module_type != "nem" {
            return Ok(());
        }

        if event_type == "location" {
            if args.is_empty() || args[0] != "gps" {
                return Err("EELLoaderLocation only support 'gps' location type".to_string());
            }
            if args.len() < 2 {
                return Err("LoaderLocation missing arguments".to_string());
            }
            let params: Vec<&str> = args[1].split(',').collect();
            if params.len() != 4 {
                return Err("LoaderLocation gps expected 4 params".to_string());
            }
            let lat: f64 = params[0]
                .parse_legacy()
                .map_err(|e| format!("EELEventGenerator: Parameter conversion error. {}", e))?;
            let lon: f64 = params[1]
                .parse_legacy()
                .map_err(|e| format!("EELEventGenerator: Parameter conversion error. {}", e))?;
            let alt: f64 = params[2]
                .parse_legacy()
                .map_err(|e| format!("EELEventGenerator: Parameter conversion error. {}", e))?;
            let alt_type = params[3];
            if alt_type != "msl" && alt_type != "agl" {
                return Err("LoaderLocation gps unkown altitude type".to_string());
            }

            let snapshot = {
                let entry = self.cache.entry(module_id).or_default();
                entry.has_position = true;
                entry.lat = lat;
                entry.lon = lon;
                entry.alt = alt;
                entry.clone()
            };
            self.delta_cache.insert(module_id, snapshot);
        } else if event_type == "orientation" {
            if args.is_empty() {
                return Err("EELLoaderLocation orientation missing arguments".to_string());
            }
            let params: Vec<&str> = args[0].split(',').collect();
            if params.len() != 4 {
                return Err("EELLoaderLocation orientation expects 4 params".to_string());
            }
            let pitch: f64 = params[0]
                .parse_legacy()
                .map_err(|e| format!("EELEventGenerator: Parameter conversion error. {}", e))?;
            let roll: f64 = params[1]
                .parse_legacy()
                .map_err(|e| format!("EELEventGenerator: Parameter conversion error. {}", e))?;
            let yaw: f64 = params[2]
                .parse_legacy()
                .map_err(|e| format!("EELEventGenerator: Parameter conversion error. {}", e))?;
            let type_str = params[3];
            if type_str != "degrees" && type_str != "relative" {
                return Err("EELLoaderLocation orientation unkown or unsupported keyword. Only degrees and relative keywords supported.".to_string());
            }

            let snapshot = {
                let entry = self.cache.entry(module_id).or_default();
                entry.has_orientation = true;
                entry.roll = roll;
                entry.pitch = pitch;
                entry.yaw = yaw;
                entry.clone()
            };
            self.delta_cache.insert(module_id, snapshot);
        } else if event_type == "velocity" {
            if args.is_empty() {
                return Err("EELLoaderLocation velocity missing arguments".to_string());
            }
            let params: Vec<&str> = args[0].split(',').collect();
            if params.len() != 4 {
                return Err("EELLoaderLocation velocity expects 4 params".to_string());
            }
            let azimuth: f64 = params[0]
                .parse_legacy()
                .map_err(|e| format!("EELEventGenerator: Parameter conversion error. {}", e))?;
            let elevation: f64 = params[1]
                .parse_legacy()
                .map_err(|e| format!("EELEventGenerator: Parameter conversion error. {}", e))?;
            let magnitude: f64 = params[2]
                .parse_legacy()
                .map_err(|e| format!("EELEventGenerator: Parameter conversion error. {}", e))?;
            let type_str = params[3];
            if type_str != "degrees"
                && type_str != "mps"
                && type_str != "azimuth"
                && type_str != "relative"
            {
                return Err("EELLoaderLocation velocity unkown or unsupported keyword. Only degrees, relative, mps and azimuth keywords supported.".to_string());
            }

            let snapshot = {
                let entry = self.cache.entry(module_id).or_default();
                entry.has_velocity = true;
                entry.azimuth = azimuth;
                entry.elevation = elevation;
                entry.magnitude = magnitude;
                entry.clone()
            };
            self.delta_cache.insert(module_id, snapshot);
        }

        Ok(())
    }

    pub fn get_events(
        &mut self,
        mode: i32,
        callback_data: *mut c_void,
        cb: extern "C" fn(*mut c_void, u16, u16, *const u8, usize),
    ) {
        if self.delta_cache.is_empty() {
            return;
        }

        let cache = if mode == 0 {
            // DELTA
            &self.delta_cache
        } else {
            // FULL
            &self.cache
        };

        let mut sorted_keys: Vec<&u16> = cache.keys().collect();
        sorted_keys.sort();

        let mut msg = emane_message::LocationEvent::default();
        for &k in sorted_keys {
            let v = cache.get(&k).unwrap();
            let mut loc = emane_message::location_event::Location {
                nem_id: k as u32,
                position: emane_message::location_event::location::Position {
                    latitude_degrees: v.lat,
                    longitude_degrees: v.lon,
                    altitude_meters: v.alt,
                },
                velocity: None,
                orientation: None,
            };

            if v.has_velocity {
                loc.velocity = Some(emane_message::location_event::location::Velocity {
                    azimuth_degrees: v.azimuth,
                    elevation_degrees: v.elevation,
                    magnitude_meters_per_second: v.magnitude,
                });
            }
            if v.has_orientation {
                loc.orientation = Some(emane_message::location_event::location::Orientation {
                    roll_degrees: v.roll,
                    pitch_degrees: v.pitch,
                    yaw_degrees: v.yaw,
                });
            }

            msg.locations.push(loc);
        }

        if !msg.locations.is_empty() {
            let mut buf = Vec::with_capacity(msg.encoded_len());
            if msg.encode(&mut buf).is_ok() {
                cb(callback_data, 0, 100, buf.as_ptr(), buf.len()); // EMANE_EVENT_LOCATION = 100, target NEM = 0
            }
        }

        self.delta_cache.clear();
    }
}

#[no_mangle]
pub extern "C" fn emane_location_loader_create() -> *mut LocationLoader {
    Box::into_raw(Box::new(LocationLoader::new()))
}

#[no_mangle]
pub extern "C" fn emane_location_loader_destroy(ptr: *mut LocationLoader) {
    if !ptr.is_null() {
        unsafe {
            drop(Box::from_raw(ptr));
        }
    }
}

#[no_mangle]
pub extern "C" fn emane_location_loader_load(
    ptr: *mut LocationLoader,
    module_type: *const c_char,
    module_id: u16,
    event_type: *const c_char,
    args: *const *const c_char,
    argc: usize,
) -> bool {
    let loader = unsafe { &mut *ptr };
    let m_type = unsafe { CStr::from_ptr(module_type).to_string_lossy().into_owned() };
    let e_type = unsafe { CStr::from_ptr(event_type).to_string_lossy().into_owned() };

    let mut args_vec = Vec::with_capacity(argc);
    let args_slice = unsafe { std::slice::from_raw_parts(args, argc) };
    for &arg_ptr in args_slice {
        args_vec.push(unsafe { CStr::from_ptr(arg_ptr).to_string_lossy().into_owned() });
    }

    match loader.load(&m_type, module_id, &e_type, &args_vec) {
        Ok(_) => true,
        Err(e) => {
            eprintln!("{}", e);
            false
        }
    }
}

#[no_mangle]
pub extern "C" fn emane_location_loader_get_events(
    ptr: *mut LocationLoader,
    mode: i32,
    callback_data: *mut c_void,
    cb: extern "C" fn(*mut c_void, u16, u16, *const u8, usize),
) {
    let loader = unsafe { &mut *ptr };
    loader.get_events(mode, callback_data, cb);
}

#[cfg(test)]
mod tests {
    use super::*;

    extern "C" fn collect(context: *mut c_void, _: u16, _: u16, data: *const u8, len: usize) {
        let output = unsafe { &mut *(context as *mut Vec<Vec<u8>>) };
        output.push(unsafe { std::slice::from_raw_parts(data, len) }.to_vec());
    }

    #[test]
    fn delta_orientation_preserves_current_position() {
        let mut loader = LocationLoader::new();
        loader
            .load(
                "nem",
                7,
                "location",
                &["gps".to_string(), "10,20,30,msl".to_string()],
            )
            .unwrap();
        let mut output: Vec<Vec<u8>> = Vec::new();
        loader.get_events(0, (&mut output as *mut Vec<Vec<u8>>).cast(), collect);
        output.clear();

        loader
            .load("nem", 7, "orientation", &["1,2,3,degrees".to_string()])
            .unwrap();
        loader.get_events(0, (&mut output as *mut Vec<Vec<u8>>).cast(), collect);
        let event = emane_message::LocationEvent::decode(output[0].as_slice()).unwrap();
        let location = &event.locations[0];
        assert_eq!(location.nem_id, 7);
        assert_eq!(location.position.latitude_degrees, 10.0);
        assert_eq!(location.position.longitude_degrees, 20.0);
        assert_eq!(location.position.altitude_meters, 30.0);
        assert_eq!(location.orientation.as_ref().unwrap().roll_degrees, 2.0);
    }
}
