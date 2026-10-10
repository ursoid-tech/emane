use emane_plugin_api::numeric::LegacyParse;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::slice;

use crate::events::{
    emane_rs_antennaprofile_event_free_serialize, emane_rs_antennaprofile_event_serialize,
    EmaneRsAntennaProfile,
};

pub struct AntennaProfileLoader {
    full_cache: HashMap<u16, EmaneRsAntennaProfile>,
    delta_cache: HashMap<u16, EmaneRsAntennaProfile>,
}

impl Default for AntennaProfileLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl AntennaProfileLoader {
    pub fn new() -> Self {
        Self {
            full_cache: HashMap::new(),
            delta_cache: HashMap::new(),
        }
    }

    pub fn load(&mut self, module_type: &str, module_id: u16, args: &[&str]) -> Result<(), String> {
        if module_type == "nem" {
            if args.len() != 1 {
                return Err("LoaderAntennaProfile loader expects 1 argument".to_string());
            }

            let params: Vec<&str> = args[0].split(',').collect();
            if params.len() != 3 {
                return Err("LoaderAntennaProfile too many arguments".to_string());
            }

            let profile_id = params[0]
                .parse_legacy::<u16>()
                .map_err(|e| format!("EELEventGenerator: Parameter conversion error. {}", e))?;
            let azimuth = params[1]
                .parse_legacy::<f64>()
                .map_err(|e| format!("EELEventGenerator: Parameter conversion error. {}", e))?;
            let elevation = params[2]
                .parse_legacy::<f64>()
                .map_err(|e| format!("EELEventGenerator: Parameter conversion error. {}", e))?;

            let profile = EmaneRsAntennaProfile {
                nem_id: module_id as u32,
                profile_id: u32::from(profile_id),
                antenna_azimuth_degrees: azimuth,
                antenna_elevation_degrees: elevation,
            };

            self.full_cache.insert(
                module_id,
                EmaneRsAntennaProfile {
                    nem_id: profile.nem_id,
                    profile_id: profile.profile_id,
                    antenna_azimuth_degrees: profile.antenna_azimuth_degrees,
                    antenna_elevation_degrees: profile.antenna_elevation_degrees,
                },
            );
            self.delta_cache.insert(module_id, profile);
        }
        Ok(())
    }

    pub fn get_events<F>(&mut self, mode: u8, mut cb: F)
    where
        F: FnMut(u16, &[u8]),
    {
        let cache = if mode == 0 {
            // DELTA
            &self.delta_cache
        } else {
            &self.full_cache
        };

        if !cache.is_empty() {
            let mut keys: Vec<_> = cache.keys().copied().collect();
            keys.sort_unstable();
            let profiles: Vec<EmaneRsAntennaProfile> = keys
                .into_iter()
                .map(|key| &cache[&key])
                .map(|p| EmaneRsAntennaProfile {
                    nem_id: p.nem_id,
                    profile_id: p.profile_id,
                    antenna_azimuth_degrees: p.antenna_azimuth_degrees,
                    antenna_elevation_degrees: p.antenna_elevation_degrees,
                })
                .collect();

            let mut out_len = 0;
            let serialized = emane_rs_antennaprofile_event_serialize(
                profiles.as_ptr(),
                profiles.len(),
                &mut out_len,
            );

            if !serialized.is_null() && out_len > 0 {
                let slice = unsafe { slice::from_raw_parts(serialized, out_len) };
                cb(0, slice);
                emane_rs_antennaprofile_event_free_serialize(serialized, out_len);
            }
        }

        self.delta_cache.clear();
    }
}

#[no_mangle]
pub extern "C" fn emane_antennaprofile_loader_new() -> *mut AntennaProfileLoader {
    Box::into_raw(Box::new(AntennaProfileLoader::new()))
}

#[no_mangle]
pub unsafe extern "C" fn emane_antennaprofile_loader_drop(ptr: *mut AntennaProfileLoader) {
    if !ptr.is_null() {
        drop(Box::from_raw(ptr));
    }
}

#[no_mangle]
pub unsafe extern "C" fn emane_antennaprofile_loader_load(
    ptr: *mut AntennaProfileLoader,
    module_type: *const c_char,
    module_id: u16,
    args: *const *const c_char,
    num_args: usize,
    error_out: *mut *mut c_char,
) -> bool {
    let loader = &mut *ptr;
    let module_type_str = CStr::from_ptr(module_type).to_string_lossy();

    let mut args_vec = Vec::with_capacity(num_args);
    for i in 0..num_args {
        args_vec.push(CStr::from_ptr(*args.add(i)).to_string_lossy());
    }
    let args_str: Vec<&str> = args_vec.iter().map(|s| s.as_ref()).collect();

    match loader.load(&module_type_str, module_id, &args_str) {
        Ok(_) => true,
        Err(e) => {
            if !error_out.is_null() {
                *error_out = CString::new(e).unwrap().into_raw();
            }
            false
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn emane_antennaprofile_loader_free_error(err: *mut c_char) {
    if !err.is_null() {
        drop(CString::from_raw(err));
    }
}

pub type EventCallback =
    unsafe extern "C" fn(nem_id: u16, payload: *const u8, payload_len: usize, ctx: *mut c_void);

#[no_mangle]
pub unsafe extern "C" fn emane_antennaprofile_loader_get_events(
    ptr: *mut AntennaProfileLoader,
    mode: u8,
    cb: EventCallback,
    ctx: *mut c_void,
) {
    let loader = &mut *ptr;
    loader.get_events(mode, |nem_id, payload| {
        cb(nem_id, payload.as_ptr(), payload.len(), ctx);
    });
}
