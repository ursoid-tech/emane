pub use emane_plugin_api::flow_control::FlowControlManager;

#[no_mangle]
pub extern "C" fn emane_rs_flow_control_manager_create() -> *mut FlowControlManager {
    Box::into_raw(Box::new(FlowControlManager::new()))
}

#[no_mangle]
pub extern "C" fn emane_rs_flow_control_manager_destroy(ptr: *mut FlowControlManager) {
    if !ptr.is_null() {
        unsafe {
            let _ = Box::from_raw(ptr);
        }
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_flow_control_manager_start(
    ptr: *mut FlowControlManager,
    total_tokens: u16,
) -> u16 {
    if let Some(m) = unsafe { ptr.as_mut() } {
        m.start(total_tokens)
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_flow_control_manager_stop(ptr: *mut FlowControlManager) {
    if let Some(m) = unsafe { ptr.as_mut() } {
        m.stop();
    }
}

#[repr(C)]
pub struct FfiAddTokenResult {
    pub tokens_available: u16,
    pub status: bool,
    pub has_send_update: bool,
    pub send_update: u16,
}

#[no_mangle]
pub extern "C" fn emane_rs_flow_control_manager_add_token(
    ptr: *mut FlowControlManager,
    tokens: u16,
) -> FfiAddTokenResult {
    if let Some(m) = unsafe { ptr.as_mut() } {
        let (tokens_available, status, send_update) = m.add_token(tokens);
        FfiAddTokenResult {
            tokens_available,
            status,
            has_send_update: send_update.is_some(),
            send_update: send_update.unwrap_or(0),
        }
    } else {
        FfiAddTokenResult {
            tokens_available: 0,
            status: false,
            has_send_update: false,
            send_update: 0,
        }
    }
}

#[repr(C)]
pub struct FfiRemoveTokenResult {
    pub tokens_available: u16,
    pub status: bool,
}

#[no_mangle]
pub extern "C" fn emane_rs_flow_control_manager_remove_token(
    ptr: *mut FlowControlManager,
) -> FfiRemoveTokenResult {
    if let Some(m) = unsafe { ptr.as_mut() } {
        let (tokens_available, status) = m.remove_token();
        FfiRemoveTokenResult {
            tokens_available,
            status,
        }
    } else {
        FfiRemoveTokenResult {
            tokens_available: 0,
            status: false,
        }
    }
}

#[repr(C)]
pub struct FfiProcessMessageResult {
    pub has_send_update: bool,
    pub send_update: u16,
}

#[no_mangle]
pub extern "C" fn emane_rs_flow_control_manager_process_message(
    ptr: *mut FlowControlManager,
    tokens: u16,
) -> FfiProcessMessageResult {
    if let Some(m) = unsafe { ptr.as_mut() } {
        let res = m.process_flow_control_message(tokens);
        FfiProcessMessageResult {
            has_send_update: res.is_some(),
            send_update: res.unwrap_or(0),
        }
    } else {
        FfiProcessMessageResult {
            has_send_update: false,
            send_update: 0,
        }
    }
}
