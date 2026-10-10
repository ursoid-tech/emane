use emane_plugin_api::numeric::LegacyParse;
use prost::Message;
use std::collections::HashMap;
use std::ffi::CStr;
use std::os::raw::{c_char, c_void};

use crate::protobufs::emane_message;

pub struct FadingSelectionLoader {
    cache: HashMap<u16, HashMap<u16, i32>>,
    delta_cache: HashMap<u16, HashMap<u16, i32>>,
}

impl Default for FadingSelectionLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl FadingSelectionLoader {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
            delta_cache: HashMap::new(),
        }
    }

    pub fn load(
        &mut self,
        module_type: &str,
        target_nem: u16,
        _event_type: &str,
        args: &[String],
    ) -> Result<(), String> {
        if module_type != "nem" {
            return Ok(());
        }
        if args.is_empty() {
            return Err("LoaderFadingSelection expects at least 1 argument".to_string());
        }

        for arg in args {
            let params: Vec<&str> = arg.split(',').collect();
            if params.len() != 2 {
                return Err("LoaderFadingSelection expects 2 parameters".to_string());
            }

            let tx_nem_str = params[0];
            let tx_nem = if let Some(stripped) = tx_nem_str.strip_prefix("nem:") {
                stripped.parse_legacy::<u16>().map_err(|e| {
                    format!(
                        "LoaderFadingSelection loader: Parameter conversion error. {}",
                        e
                    )
                })?
            } else {
                return Err("LoaderFadingSelection only supports 'nem' module type".to_string());
            };

            let s_model = params[1];
            let model = match s_model {
                "none" => 1,
                "nakagami" => 2,
                "lognormal" => 3,
                _ => {
                    return Err(format!(
                        "LoaderFadingSelection loader unknown fading model: {}",
                        s_model
                    ))
                }
            };

            self.cache
                .entry(target_nem)
                .or_default()
                .insert(tx_nem, model);
            self.delta_cache
                .entry(target_nem)
                .or_default()
                .insert(tx_nem, model);
        }

        Ok(())
    }

    pub fn get_events(
        &mut self,
        mode: i32,
        callback_data: *mut c_void,
        cb: extern "C" fn(*mut c_void, u16, u16, *const u8, usize),
    ) {
        let cache = if mode == 0 {
            // DELTA
            &self.delta_cache
        } else {
            // FULL
            &self.cache
        };

        // Sort by NEM ID to be deterministic if needed, though C++ used std::map which is sorted
        let mut sorted_targets: Vec<&u16> = cache.keys().collect();
        sorted_targets.sort();

        for &target_nem in sorted_targets {
            let entries = cache.get(&target_nem).unwrap();
            let mut sorted_tx_nems: Vec<&u16> = entries.keys().collect();
            sorted_tx_nems.sort();

            let mut msg = emane_message::FadingSelectionEvent::default();
            for &tx_nem in sorted_tx_nems {
                msg.entries
                    .push(emane_message::fading_selection_event::Entry {
                        nem_id: tx_nem as u32,
                        model: *entries.get(&tx_nem).unwrap(),
                    });
            }

            let mut buf = Vec::with_capacity(msg.encoded_len());
            if msg.encode(&mut buf).is_ok() {
                cb(callback_data, target_nem, 106, buf.as_ptr(), buf.len()); // EMANE_EVENT_FADING_SELECTION = 106
            }
        }

        self.delta_cache.clear();
    }
}

#[no_mangle]
pub extern "C" fn emane_fadingselection_loader_create() -> *mut FadingSelectionLoader {
    Box::into_raw(Box::new(FadingSelectionLoader::new()))
}

#[no_mangle]
pub extern "C" fn emane_fadingselection_loader_destroy(ptr: *mut FadingSelectionLoader) {
    if !ptr.is_null() {
        unsafe {
            drop(Box::from_raw(ptr));
        }
    }
}

#[no_mangle]
pub extern "C" fn emane_fadingselection_loader_load(
    ptr: *mut FadingSelectionLoader,
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
            eprintln!("{}", e); // Optionally we could pass error back, but returning false allows C++ to throw FormatException
            false
        }
    }
}

#[no_mangle]
pub extern "C" fn emane_fadingselection_loader_get_events(
    ptr: *mut FadingSelectionLoader,
    mode: i32,
    callback_data: *mut c_void,
    cb: extern "C" fn(*mut c_void, u16, u16, *const u8, usize),
) {
    let loader = unsafe { &mut *ptr };
    loader.get_events(mode, callback_data, cb);
}
