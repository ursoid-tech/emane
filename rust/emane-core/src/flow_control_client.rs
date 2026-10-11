use std::sync::{Arc, Condvar, Mutex};

type SendControlCallback = extern "C" fn(*mut std::ffi::c_void, u16);

struct FlowControlState {
    tokens_available: u16,
    cancel: bool,
}

pub struct FlowControlClient {
    state: Arc<(Mutex<FlowControlState>, Condvar)>,
    transport_ptr: *mut std::ffi::c_void,
    send_cb: SendControlCallback,
}

impl FlowControlClient {
    pub fn new(transport_ptr: *mut std::ffi::c_void, send_cb: SendControlCallback) -> Self {
        Self {
            state: Arc::new((
                Mutex::new(FlowControlState {
                    tokens_available: 0,
                    cancel: false,
                }),
                Condvar::new(),
            )),
            transport_ptr,
            send_cb,
        }
    }

    pub fn start(&self) {
        let (lock, _) = &*self.state;
        let state = lock.lock().unwrap();
        (self.send_cb)(self.transport_ptr, state.tokens_available);
    }

    pub fn stop(&self) {
        let (lock, cvar) = &*self.state;
        let mut state = lock.lock().unwrap();
        state.cancel = true;
        cvar.notify_all();
    }

    pub fn remove_token(&self) -> (u16, bool) {
        let (lock, cvar) = &*self.state;
        let mut state = lock.lock().unwrap();

        while state.tokens_available == 0 && !state.cancel {
            state = cvar.wait(state).unwrap();
        }

        if state.cancel {
            (state.tokens_available, false)
        } else {
            state.tokens_available -= 1;
            (state.tokens_available, true)
        }
    }

    pub fn process_flow_control_message(&self, tokens: u16) {
        let (lock, cvar) = &*self.state;
        let mut state = lock.lock().unwrap();

        state.tokens_available = tokens;
        (self.send_cb)(self.transport_ptr, state.tokens_available);

        cvar.notify_all();
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_flow_control_client_new(
    transport_ptr: *mut std::ffi::c_void,
    send_cb: SendControlCallback,
) -> *mut FlowControlClient {
    Box::into_raw(Box::new(FlowControlClient::new(transport_ptr, send_cb)))
}

#[no_mangle]
pub extern "C" fn emane_rs_flow_control_client_free(ptr: *mut FlowControlClient) {
    if !ptr.is_null() {
        unsafe {
            let _ = Box::from_raw(ptr);
        }
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_flow_control_client_start(ptr: *mut FlowControlClient) {
    if let Some(client) = unsafe { ptr.as_ref() } {
        client.start();
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_flow_control_client_stop(ptr: *mut FlowControlClient) {
    if let Some(client) = unsafe { ptr.as_ref() } {
        client.stop();
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_flow_control_client_remove_token(
    ptr: *mut FlowControlClient,
    status: *mut bool,
) -> u16 {
    if let Some(client) = unsafe { ptr.as_ref() } {
        let (tokens, ok) = client.remove_token();
        if !status.is_null() {
            unsafe {
                *status = ok;
            }
        }
        tokens
    } else {
        if !status.is_null() {
            unsafe {
                *status = false;
            }
        }
        0
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_flow_control_client_process_message(
    ptr: *mut FlowControlClient,
    tokens: u16,
) {
    if let Some(client) = unsafe { ptr.as_ref() } {
        client.process_flow_control_message(tokens);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern "C" fn ignore(_: *mut std::ffi::c_void, _: u16) {}
    #[test]
    fn cancellation_preserves_available_count_across_restart() {
        let client = FlowControlClient::new(std::ptr::null_mut(), ignore);
        client.process_flow_control_message(3);
        assert_eq!(client.remove_token(), (2, true));
        client.stop();
        assert_eq!(client.remove_token(), (2, false));
        client.start();
        client.process_flow_control_message(5);
        assert_eq!(client.remove_token(), (5, false));
    }
}
