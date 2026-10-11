use super::*;
#[derive(Default)]
struct Record {
    calls: [usize; 7],
    entered: bool,
    released: bool,
}
struct State {
    record: Mutex<Record>,
    wake: Condvar,
}
impl State {
    fn hold(&self) {
        let mut r = self.record.lock().unwrap();
        r.entered = true;
        self.wake.notify_all();
        while !r.released {
            r = self.wake.wait(r).unwrap();
        }
        r.entered = false;
        r.released = false;
    }
    fn wait(&self) {
        let r = self.record.lock().unwrap();
        let (_record, timeout) = self
            .wake
            .wait_timeout_while(r, Duration::from_secs(2), |r| !r.entered)
            .unwrap();
        assert!(!timeout.timed_out());
    }
    fn release(&self) {
        self.record.lock().unwrap().released = true;
        self.wake.notify_all();
    }
    fn line(&self, phase: &str) -> String {
        format!(
            "{}:{}",
            phase,
            self.record
                .lock()
                .unwrap()
                .calls
                .iter()
                .map(|n| format!("{n},"))
                .collect::<String>()
        )
    }
}
fn state<'a>(ctx: *mut c_void) -> &'a State {
    unsafe { &*ctx.cast::<State>() }
}
extern "C" fn init(_: u16, _: *const FfiFrameworkService) -> *mut c_void {
    std::ptr::null_mut()
}
extern "C" fn configure(ctx: *mut c_void, _: *const c_void) -> bool {
    state(ctx).record.lock().unwrap().calls[6] += 1;
    true
}
extern "C" fn start(ctx: *mut c_void) -> bool {
    state(ctx).hold();
    true
}
extern "C" fn stop(ctx: *mut c_void) {
    state(ctx).hold();
}
extern "C" fn post(_: *mut c_void) {}
extern "C" fn destroy(ctx: *mut c_void) {
    unsafe {
        drop(Box::from_raw(ctx.cast::<State>()));
    }
}
extern "C" fn up(ctx: *mut c_void, p: *const FfiPacket, _: *const FfiControlMessage, _: usize) {
    state(ctx).record.lock().unwrap().calls[if p.is_null() { 0 } else { 2 }] += 1;
}
extern "C" fn down(ctx: *mut c_void, p: *const FfiPacket, _: *const FfiControlMessage, _: usize) {
    state(ctx).record.lock().unwrap().calls[if p.is_null() { 1 } else { 3 }] += 1;
}
extern "C" fn event(ctx: *mut c_void, _: u16, _: *const u8, _: usize) {
    state(ctx).record.lock().unwrap().calls[4] += 1;
}
extern "C" fn timed(ctx: *mut c_void, _: u64, _: u32, _: *const u8, _: usize) {
    state(ctx).record.lock().unwrap().calls[5] += 1;
}
fn api() -> &'static PluginApi {
    static API: OnceLock<PluginApi> = OnceLock::new();
    API.get_or_init(|| PluginApi {
        abi_version: PLUGIN_ABI_VERSION,
        struct_size: std::mem::size_of::<PluginApi>(),
        name: c"dispatch-recorder".as_ptr(),
        plugin_type: 1,
        init,
        configure,
        start,
        post_start: post,
        stop,
        destroy,
        process_upstream: up,
        process_downstream: down,
        process_event: event,
        process_timed_event: timed,
    })
}
fn run_dispatch_probe() {
    let mut manager = NemManager::new([56; 16]);
    manager.add_layer_configured(602, "", 1, &[]).unwrap();
    let ctx = Box::into_raw(Box::new(State {
        record: Mutex::new(Record::default()),
        wake: Condvar::new(),
    }));
    let layer = &mut manager.layers.get_mut(&602).unwrap()[0];
    layer.invocation.call(|api, ctx| (api.destroy)(ctx));
    layer.invocation.api = api() as *const PluginApi as usize;
    layer.invocation.plugin_ctx = ctx as usize;
    let invocation = layer.invocation;
    manager
        .runtime
        .invocations
        .write()
        .unwrap()
        .get_mut(&602)
        .unwrap()[0] = invocation;
    let send = || {
        let info = FfiPacketInfo {
            uuid: [0; 16],
            source: 1,
            destination: 2,
            priority: 0,
            creation_time_sec: 0,
            creation_time_usec: 0,
        };
        let bytes = [0u8];
        let packet = FfiPacket {
            info,
            payload: FfiSlice {
                data: bytes.as_ptr(),
                len: 1,
            },
        };
        invocation.process(false, std::ptr::null(), std::ptr::null(), 0);
        invocation.process(true, std::ptr::null(), std::ptr::null(), 0);
        invocation.process(false, &packet, std::ptr::null(), 0);
        invocation.process(true, &packet, std::ptr::null(), 0);
        let _ = invocation.configure_running(Vec::new());
        invocation.process_event(123, b"x".as_ptr(), 1);
        invocation.process_timed_event(1, 0, &[], 0, 0, 0);
    };
    let flush = || {
        let (tx, rx) = std::sync::mpsc::channel();
        assert!(invocation
            .queue()
            .unwrap()
            .enqueue(
                QueueTaskKind::FileDescriptor,
                Box::new(move || {
                    tx.send(()).unwrap();
                })
            )
            .is_ok());
        rx.recv_timeout(Duration::from_secs(2)).unwrap();
    };
    let mut rows = Vec::new();
    send();
    rows.push(state(ctx.cast()).line("before-start"));
    std::thread::scope(|scope| {
        let start = scope.spawn(|| manager.start().unwrap());
        state(ctx.cast()).wait();
        flush();
        rows.push(state(ctx.cast()).line("starting-backlog"));
        send();
        flush();
        rows.push(state(ctx.cast()).line("during-start"));
        state(ctx.cast()).release();
        start.join().unwrap();
    });
    send();
    flush();
    rows.push(state(ctx.cast()).line("running"));
    std::thread::scope(|scope| {
        let stop = scope.spawn(|| manager.stop());
        state(ctx.cast()).wait();
        send();
        flush();
        rows.push(state(ctx.cast()).line("during-stop"));
        state(ctx.cast()).release();
        stop.join().unwrap();
    });
    send();
    rows.push(state(ctx.cast()).line("after-stop"));
    if std::env::var_os("EMANE_PARITY_DISPATCH_PROBE").is_some() {
        for row in rows {
            println!("DISPATCH|{row}");
        }
    } else {
        assert_eq!(
            rows,
            vec![
                "before-start:0,0,0,0,0,0,0,",
                "starting-backlog:0,0,0,0,0,0,0,",
                "during-start:0,0,0,0,0,0,0,",
                "running:1,1,1,1,1,1,1,",
                "during-stop:2,2,2,2,2,2,2,",
                "after-stop:2,2,2,2,2,2,2,"
            ]
        );
    }
}

#[test]
fn parity_dispatch_probe() {
    let repetitions = std::env::var("EMANE_PARITY_DISPATCH_REPETITIONS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(1);
    for _ in 0..repetitions {
        run_dispatch_probe();
    }
}
