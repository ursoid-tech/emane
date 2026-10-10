use crate::protobufs::emane_message;
use emane_plugin_api::numeric::LegacyParse;
use prost::Message;
use std::collections::HashMap;
use std::ffi::CStr;
use std::os::raw::{c_char, c_void};

#[derive(Clone, Default)]
struct PathlossEntry {
    forward: f32,
    reverse: f32,
}

pub struct PathlossLoader {
    cache: HashMap<u16, HashMap<u16, PathlossEntry>>,
    delta_cache: HashMap<u16, HashMap<u16, PathlossEntry>>,
}

impl Default for PathlossLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl PathlossLoader {
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
            return Err("LoaderPathloss expects at least 1 argument".to_string());
        }

        for arg in args {
            let params: Vec<&str> = arg.split(',').collect();
            if params.len() < 2 {
                return Err("LoaderPathloss expects at least 1 parameter".to_string());
            }

            let dest_str = params[0];
            let colon_pos = dest_str.find(':');
            if colon_pos.is_none() || &dest_str[..colon_pos.unwrap()] != "nem" {
                return Err("LoaderPathloss only supports 'nem' module type".to_string());
            }
            let dst_nem: u16 = dest_str[colon_pos.unwrap() + 1..]
                .parse_legacy()
                .map_err(|e| format!("LoaderPathloss loader: Parameter conversion error. {}", e))?;

            let fwd_db: f32 = params[1]
                .parse_legacy()
                .map_err(|e| format!("LoaderPathloss loader: Parameter conversion error. {}", e))?;

            let rev_db: f32 = if params.len() >= 3 {
                params[2].parse_legacy().map_err(|e| {
                    format!("LoaderPathloss loader: Parameter conversion error. {}", e)
                })?
            } else {
                fwd_db
            };

            if params.len() > 3 {
                return Err("LoaderPathloss loader too many parameters".to_string());
            }

            let src_nem = module_id;

            Self::update_cache(&mut self.cache, dst_nem, src_nem, fwd_db, rev_db);
            Self::update_cache(&mut self.delta_cache, dst_nem, src_nem, fwd_db, rev_db);
        }
        Ok(())
    }

    fn update_cache(
        cache: &mut HashMap<u16, HashMap<u16, PathlossEntry>>,
        dst_nem: u16,
        src_nem: u16,
        fwd: f32,
        rev: f32,
    ) {
        let entry = cache
            .entry(dst_nem)
            .or_default()
            .entry(src_nem)
            .or_default();
        entry.forward = fwd;
        entry.reverse = rev;

        let reverse_entry = cache
            .entry(src_nem)
            .or_default()
            .entry(dst_nem)
            .or_default();
        reverse_entry.forward = rev;
        reverse_entry.reverse = fwd;
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

            let mut msg = emane_message::PathlossEvent::default();
            for &src in sorted_srcs {
                let entry = src_map.get(&src).unwrap();
                msg.pathlosses
                    .push(emane_message::pathloss_event::Pathloss {
                        nem_id: src as u32,
                        forward_pathlossd_b: entry.forward,
                        reverse_pathlossd_b: entry.reverse,
                    });
            }

            if !msg.pathlosses.is_empty() {
                let mut buf = Vec::with_capacity(msg.encoded_len());
                if msg.encode(&mut buf).is_ok() {
                    cb(callback_data, dst, 101, buf.as_ptr(), buf.len()); // EMANE_EVENT_PATHLOSS = 101
                }
            }
        }

        self.delta_cache.clear();
    }
}

#[no_mangle]
pub extern "C" fn emane_pathloss_loader_create() -> *mut PathlossLoader {
    Box::into_raw(Box::new(PathlossLoader::new()))
}

#[no_mangle]
pub extern "C" fn emane_pathloss_loader_destroy(ptr: *mut PathlossLoader) {
    if !ptr.is_null() {
        unsafe {
            drop(Box::from_raw(ptr));
        }
    }
}

#[no_mangle]
pub extern "C" fn emane_pathloss_loader_load(
    ptr: *mut PathlossLoader,
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
pub extern "C" fn emane_pathloss_loader_get_events(
    ptr: *mut PathlossLoader,
    mode: i32,
    callback_data: *mut c_void,
    cb: extern "C" fn(*mut c_void, u16, u16, *const u8, usize),
) {
    let loader = unsafe { &mut *ptr };
    loader.get_events(mode, callback_data, cb);
}
