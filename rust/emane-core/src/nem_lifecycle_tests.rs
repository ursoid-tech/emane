use super::*;
use std::sync::Mutex;

#[derive(Default)]
struct Record {
    starts: usize,
    posts: usize,
    stops: usize,
    fail: bool,
}
extern "C" fn init(_: u16, _: *const FfiFrameworkService) -> *mut c_void {
    std::ptr::null_mut()
}
extern "C" fn configure(_: *mut c_void, _: *const c_void) -> bool {
    true
}
extern "C" fn start(ctx: *mut c_void) -> bool {
    let mut r = unsafe { &*ctx.cast::<Mutex<Record>>() }.lock().unwrap();
    r.starts += 1;
    !r.fail
}
extern "C" fn post(ctx: *mut c_void) {
    unsafe { &*ctx.cast::<Mutex<Record>>() }
        .lock()
        .unwrap()
        .posts += 1;
}
extern "C" fn stop(ctx: *mut c_void) {
    unsafe { &*ctx.cast::<Mutex<Record>>() }
        .lock()
        .unwrap()
        .stops += 1;
}
extern "C" fn destroy(ctx: *mut c_void) {
    unsafe { drop(Box::from_raw(ctx.cast::<Mutex<Record>>())) };
}
extern "C" fn packet(_: *mut c_void, _: *const FfiPacket, _: *const FfiControlMessage, _: usize) {}
extern "C" fn timed(_: *mut c_void, _: u64, _: u32, _: *const u8, _: usize) {}
extern "C" fn event(_: *mut c_void, _: u16, _: *const u8, _: usize) {}
fn api() -> &'static PluginApi {
    static API: OnceLock<PluginApi> = OnceLock::new();
    API.get_or_init(|| PluginApi {
        abi_version: PLUGIN_ABI_VERSION,
        struct_size: std::mem::size_of::<PluginApi>(),
        name: c"lifecycle-recorder".as_ptr(),
        plugin_type: 1,
        init,
        configure,
        start,
        post_start: post,
        stop,
        destroy,
        process_upstream: packet,
        process_downstream: packet,
        process_timed_event: timed,
        process_event: event,
    })
}
fn run(trace: &str) -> String {
    let mut manager = NemManager::new([55; 16]);
    manager.add_layer_configured(601, "", 1, &[]).unwrap();
    let record = Box::into_raw(Box::new(Mutex::new(Record::default())));
    let layer = &mut manager.layers.get_mut(&601).unwrap()[0];
    layer.invocation.call(|api, ctx| (api.destroy)(ctx));
    layer.invocation.api = api() as *const PluginApi as usize;
    layer.invocation.plugin_ctx = record as usize;
    manager
        .runtime
        .invocations
        .write()
        .unwrap()
        .get_mut(&601)
        .unwrap()[0] = layer.invocation;
    let mut output = String::new();
    for op in trace.chars() {
        match op {
            'S' => {
                let _ = manager.start();
            }
            'P' => manager.post_start(),
            'X' => manager.stop(),
            'F' => unsafe { &*record }.lock().unwrap().fail = true,
            'R' => unsafe { &*record }.lock().unwrap().fail = false,
            _ => panic!("unknown operation"),
        }
        let r = unsafe { &*record }.lock().unwrap();
        output.push_str(&format!("{},{},{};", r.starts, r.posts, r.stops));
    }
    output
}
#[test]
fn parity_lifecycle_probe() {
    if let Ok(path) = std::env::var("EMANE_PARITY_LIFECYCLE_INPUT") {
        for line in std::fs::read_to_string(path).unwrap().lines() {
            println!("LIFECYCLE|{}", run(line));
        }
    } else {
        // Expected callback counts come from the original NEMStatefulLayer.
        assert_eq!(
            run("PSPPXSPSX"),
            "0,0,0;1,0,0;1,1,0;1,2,0;1,2,1;1,2,1;1,2,1;1,2,1;1,2,1;"
        );
        assert_eq!(
            run("XFSPRSXP"),
            "0,0,0;0,0,0;1,0,0;1,0,0;1,0,0;2,0,0;2,0,1;2,0,1;"
        );
    }
}
