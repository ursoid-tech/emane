use emane_plugin_api::numeric::LegacyParse;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::slice;

use crate::events::{
    emane_rs_commeffect_event_free_serialize, emane_rs_commeffect_event_serialize,
    EmaneRsCommEffect,
};

pub struct CommEffectLoader {
    full_cache: HashMap<u16, HashMap<u16, EmaneRsCommEffect>>,
    delta_cache: HashMap<u16, HashMap<u16, EmaneRsCommEffect>>,
}

impl Default for CommEffectLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl CommEffectLoader {
    pub fn new() -> Self {
        Self {
            full_cache: HashMap::new(),
            delta_cache: HashMap::new(),
        }
    }

    pub fn load(&mut self, module_type: &str, module_id: u16, args: &[&str]) -> Result<(), String> {
        if module_type == "nem" {
            if args.is_empty() {
                return Err("LoaderCommEffect expects at least 1 argument".to_string());
            }

            for arg in args {
                let params: Vec<&str> = arg.split(',').collect();
                if params.len() != 7 {
                    return Err("LoaderCommEffect expects 7 parameters <dstModuleID>,<latency seconds>,<jitter seconds>, <loss>,<duplicates>,<unicast bps>,<broadcast bps>".to_string());
                }

                let dst_nem_str = params[0];
                let dst_nem: u16;
                if let Some(idx) = dst_nem_str.find(':') {
                    if &dst_nem_str[..idx] == "nem" {
                        dst_nem = dst_nem_str[idx + 1..].parse_legacy::<u16>().map_err(|e| {
                            format!("LoaderCommEffect loader: Parameter conversion error. {}", e)
                        })?;
                    } else {
                        return Err("LoaderCommEffect only supports 'nem' module type".to_string());
                    }
                } else {
                    return Err(
                        "LoaderCommEffect loader: Parameter conversion error. Invalid format"
                            .to_string(),
                    );
                }

                let latency = params[1].parse_legacy::<f32>().map_err(|e| {
                    format!("LoaderCommEffect loader: Parameter conversion error. {}", e)
                })?;
                let jitter = params[2].parse_legacy::<f32>().map_err(|e| {
                    format!("LoaderCommEffect loader: Parameter conversion error. {}", e)
                })?;
                let loss = params[3].parse_legacy::<f32>().map_err(|e| {
                    format!("LoaderCommEffect loader: Parameter conversion error. {}", e)
                })?;
                let duplicates = params[4].parse_legacy::<f32>().map_err(|e| {
                    format!("LoaderCommEffect loader: Parameter conversion error. {}", e)
                })?;
                let unicast = params[5].parse_legacy::<u64>().map_err(|e| {
                    format!("LoaderCommEffect loader: Parameter conversion error. {}", e)
                })?;
                let broadcast = params[6].parse_legacy::<u64>().map_err(|e| {
                    format!("LoaderCommEffect loader: Parameter conversion error. {}", e)
                })?;

                let effect = EmaneRsCommEffect {
                    nem_id: module_id as u32,
                    latency_seconds: latency,
                    jitter_seconds: jitter,
                    probability_loss: loss,
                    probability_duplicate: duplicates,
                    unicast_bit_rate_bps: unicast,
                    broadcast_bit_rate_bps: broadcast,
                };

                self.full_cache.entry(dst_nem).or_default().insert(
                    module_id,
                    EmaneRsCommEffect {
                        nem_id: effect.nem_id,
                        latency_seconds: effect.latency_seconds,
                        jitter_seconds: effect.jitter_seconds,
                        probability_loss: effect.probability_loss,
                        probability_duplicate: effect.probability_duplicate,
                        unicast_bit_rate_bps: effect.unicast_bit_rate_bps,
                        broadcast_bit_rate_bps: effect.broadcast_bit_rate_bps,
                    },
                );
                self.delta_cache
                    .entry(dst_nem)
                    .or_default()
                    .insert(module_id, effect);
            }
        }
        Ok(())
    }

    pub fn get_events<F>(&mut self, mode: u8, mut cb: F)
    where
        F: FnMut(u16, &[u8]),
    {
        let cache = if mode == 0 {
            &self.delta_cache
        } else {
            &self.full_cache
        };

        let mut destinations: Vec<_> = cache.keys().copied().collect();
        destinations.sort_unstable();
        for dst_nem in destinations {
            let entries = &cache[&dst_nem];
            let mut sources: Vec<_> = entries.keys().copied().collect();
            sources.sort_unstable();
            let effects: Vec<EmaneRsCommEffect> = sources
                .into_iter()
                .map(|source| &entries[&source])
                .map(|e| EmaneRsCommEffect {
                    nem_id: e.nem_id,
                    latency_seconds: e.latency_seconds,
                    jitter_seconds: e.jitter_seconds,
                    probability_loss: e.probability_loss,
                    probability_duplicate: e.probability_duplicate,
                    unicast_bit_rate_bps: e.unicast_bit_rate_bps,
                    broadcast_bit_rate_bps: e.broadcast_bit_rate_bps,
                })
                .collect();
            if !effects.is_empty() {
                let mut out_len = 0;
                let serialized = emane_rs_commeffect_event_serialize(
                    effects.as_ptr(),
                    effects.len(),
                    &mut out_len,
                );

                if !serialized.is_null() && out_len > 0 {
                    let slice = unsafe { slice::from_raw_parts(serialized, out_len) };
                    cb(dst_nem, slice);
                    emane_rs_commeffect_event_free_serialize(serialized, out_len);
                }
            }
        }

        self.delta_cache.clear();
    }
}

#[no_mangle]
pub extern "C" fn emane_commeffect_loader_new() -> *mut CommEffectLoader {
    Box::into_raw(Box::new(CommEffectLoader::new()))
}

#[no_mangle]
pub unsafe extern "C" fn emane_commeffect_loader_drop(ptr: *mut CommEffectLoader) {
    if !ptr.is_null() {
        drop(Box::from_raw(ptr));
    }
}

#[no_mangle]
pub unsafe extern "C" fn emane_commeffect_loader_load(
    ptr: *mut CommEffectLoader,
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
pub unsafe extern "C" fn emane_commeffect_loader_free_error(err: *mut c_char) {
    if !err.is_null() {
        drop(CString::from_raw(err));
    }
}

pub type CommEffectEventCallback =
    unsafe extern "C" fn(nem_id: u16, payload: *const u8, payload_len: usize, ctx: *mut c_void);

#[no_mangle]
pub unsafe extern "C" fn emane_commeffect_loader_get_events(
    ptr: *mut CommEffectLoader,
    mode: u8,
    cb: CommEffectEventCallback,
    ctx: *mut c_void,
) {
    let loader = &mut *ptr;
    loader.get_events(mode, |nem_id, payload| {
        cb(nem_id, payload.as_ptr(), payload.len(), ctx);
    });
}
