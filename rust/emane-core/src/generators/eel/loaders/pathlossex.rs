use crate::protobufs::emane_message;
use emane_plugin_api::numeric::LegacyParse;
use prost::Message;
use std::collections::HashMap;
use std::ffi::CStr;
use std::os::raw::{c_char, c_void};

pub struct PathlossExLoader {
    cache: HashMap<u16, HashMap<u16, HashMap<u64, f32>>>,
    delta_cache: HashMap<u16, HashMap<u16, HashMap<u64, f32>>>,
}

impl Default for PathlossExLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl PathlossExLoader {
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
        _event_type: &str,
        args: &[String],
    ) -> Result<(), String> {
        if module_type != "nem" {
            return Ok(());
        }
        if args.is_empty() {
            return Err("LoaderPathlossEx expects at least 1 argument".to_string());
        }

        for arg in args {
            let params: Vec<&str> = arg.split(',').collect();
            if params.is_empty() {
                return Err("LoaderPathlossEx expects at least 1 parameter".to_string());
            }

            let dest_str = params[0];
            let colon_pos = dest_str.find(':');
            if colon_pos.is_none() || &dest_str[..colon_pos.unwrap()] != "nem" {
                return Err("LoaderPathlossEx only supports 'nem' module type".to_string());
            }
            let dst_nem: u16 = dest_str[colon_pos.unwrap() + 1..]
                .parse_legacy()
                .map_err(|e| {
                    format!("LoaderPathlossEx loader: Parameter conversion error. {}", e)
                })?;

            let src_nem = module_id;

            for parameter in params.iter().skip(1) {
                let pathloss_params: Vec<&str> = parameter.split(':').collect();
                if pathloss_params.len() == 2 || pathloss_params.len() == 3 {
                    let freq_hz: u64 = pathloss_params[0].parse_legacy().map_err(|e| {
                        format!("LoaderPathlossEx loader: Parameter conversion error. {}", e)
                    })?;
                    let fwd_db: f32 = pathloss_params[1].parse_legacy().map_err(|e| {
                        format!("LoaderPathlossEx loader: Parameter conversion error. {}", e)
                    })?;

                    let rev_db: f32 = if pathloss_params.len() == 3 {
                        pathloss_params[2].parse_legacy().map_err(|e| {
                            format!("LoaderPathlossEx loader: Parameter conversion error. {}", e)
                        })?
                    } else {
                        fwd_db
                    };

                    Self::update_cache(&mut self.cache, dst_nem, src_nem, freq_hz, fwd_db, rev_db);
                    Self::update_cache(
                        &mut self.delta_cache,
                        dst_nem,
                        src_nem,
                        freq_hz,
                        fwd_db,
                        rev_db,
                    );
                } else {
                    return Err("LoaderPathlossEx loader malformed parameters".to_string());
                }
            }
        }
        Ok(())
    }

    fn update_cache(
        cache: &mut HashMap<u16, HashMap<u16, HashMap<u64, f32>>>,
        dst_nem: u16,
        src_nem: u16,
        freq_hz: u64,
        fwd: f32,
        rev: f32,
    ) {
        cache
            .entry(dst_nem)
            .or_default()
            .entry(src_nem)
            .or_default()
            .insert(freq_hz, fwd);
        cache
            .entry(src_nem)
            .or_default()
            .entry(dst_nem)
            .or_default()
            .insert(freq_hz, rev);
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
            &self.cache
        };

        let mut sorted_dests: Vec<&u16> = cache.keys().collect();
        sorted_dests.sort();

        for &dst in sorted_dests {
            let src_map = cache.get(&dst).unwrap();
            let mut sorted_srcs: Vec<&u16> = src_map.keys().collect();
            sorted_srcs.sort();

            let mut msg = emane_message::PathlossExEvent::default();
            for &src in sorted_srcs {
                let freq_map = src_map.get(&src).unwrap();
                let mut sorted_freqs: Vec<&u64> = freq_map.keys().collect();
                sorted_freqs.sort();

                let mut pathloss = emane_message::pathloss_ex_event::Pathloss {
                    nem_id: src as u32,
                    entries: Vec::new(),
                };

                for &freq in sorted_freqs {
                    let db = freq_map.get(&freq).unwrap();
                    pathloss
                        .entries
                        .push(emane_message::pathloss_ex_event::pathloss::Entry {
                            frequency_hz: freq,
                            pathlossd_b: *db,
                        });
                }
                msg.pathlosses.push(pathloss);
            }

            if !msg.pathlosses.is_empty() {
                let mut buf = Vec::with_capacity(msg.encoded_len());
                if msg.encode(&mut buf).is_ok() {
                    cb(callback_data, dst, 107, buf.as_ptr(), buf.len()); // EMANE_EVENT_PATHLOSS_EX = 107
                }
            }
        }

        self.delta_cache.clear();
    }
}

#[no_mangle]
pub extern "C" fn emane_pathlossex_loader_create() -> *mut PathlossExLoader {
    Box::into_raw(Box::new(PathlossExLoader::new()))
}

#[no_mangle]
pub extern "C" fn emane_pathlossex_loader_destroy(ptr: *mut PathlossExLoader) {
    if !ptr.is_null() {
        unsafe {
            drop(Box::from_raw(ptr));
        }
    }
}

#[no_mangle]
pub extern "C" fn emane_pathlossex_loader_load(
    ptr: *mut PathlossExLoader,
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
pub extern "C" fn emane_pathlossex_loader_get_events(
    ptr: *mut PathlossExLoader,
    mode: i32,
    callback_data: *mut c_void,
    cb: extern "C" fn(*mut c_void, u16, u16, *const u8, usize),
) {
    let loader = unsafe { &mut *ptr };
    loader.get_events(mode, callback_data, cb);
}
