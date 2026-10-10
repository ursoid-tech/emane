use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashSet};
use std::os::raw::c_void;
use std::sync::{Arc, Condvar, Mutex, Once};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub type TimerCallback = extern "C" fn(
    event_id: usize,
    expire_time_micros: u64,
    schedule_time_micros: u64,
    fire_time_micros: u64,
    arg: *const c_void,
    p_timer_service_user: *mut c_void,
);

pub type TimerFreeCallback = extern "C" fn(p_user: *mut c_void);

#[derive(Clone)]
struct TimerEntry {
    event_id: usize,
    expire_time_micros: u64,
    schedule_time_micros: u64,
    interval_micros: u64,
    arg: *const c_void,
    p_user: *mut c_void,
    callback: TimerCallback,
    free_callback: Option<TimerFreeCallback>,
}

unsafe impl Send for TimerEntry {}
unsafe impl Sync for TimerEntry {}

impl PartialEq for TimerEntry {
    fn eq(&self, other: &Self) -> bool {
        self.expire_time_micros == other.expire_time_micros && self.event_id == other.event_id
    }
}
impl Eq for TimerEntry {}

impl PartialOrd for TimerEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TimerEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse order for min-heap (earliest expiration time first)
        other
            .expire_time_micros
            .cmp(&self.expire_time_micros)
            .then_with(|| other.event_id.cmp(&self.event_id))
    }
}

struct TimerState {
    timers: BinaryHeap<TimerEntry>,
    cancelled: HashSet<usize>,
    repeating_in_flight: HashSet<usize>,
    next_event_id: usize,
    shutdown: bool,
}

static TIMER_STATE: std::sync::OnceLock<Arc<(Mutex<TimerState>, Condvar)>> =
    std::sync::OnceLock::new();

fn get_timer_state() -> Arc<(Mutex<TimerState>, Condvar)> {
    TIMER_STATE
        .get_or_init(|| {
            Arc::new((
                Mutex::new(TimerState {
                    timers: BinaryHeap::new(),
                    cancelled: HashSet::new(),
                    repeating_in_flight: HashSet::new(),
                    next_event_id: 1,
                    shutdown: false,
                }),
                Condvar::new(),
            ))
        })
        .clone()
}

static INIT_THREAD: Once = Once::new();

fn timer_thread() {
    let pair = get_timer_state();
    let mut state = pair.0.lock().unwrap();
    loop {
        if state.shutdown {
            break;
        }
        let now = || {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_micros() as u64
        };
        let Some(top) = state.timers.peek() else {
            state = pair.1.wait(state).unwrap();
            continue;
        };
        let collected_at = now();
        if top.expire_time_micros > collected_at {
            let wait = Duration::from_micros(top.expire_time_micros - collected_at);
            state = pair.1.wait_timeout(state, wait).unwrap().0;
            continue;
        }
        // Snapshot all expired timers before rearming any periodic timer. The
        // original scheduler runs this entire batch before collecting another.
        let mut expired = Vec::new();
        while state
            .timers
            .peek()
            .is_some_and(|t| t.expire_time_micros <= collected_at)
        {
            expired.push(state.timers.pop().unwrap());
        }
        for timer in &expired {
            if timer.interval_micros != 0 {
                state.repeating_in_flight.insert(timer.event_id);
                let mut next = timer.clone();
                next.expire_time_micros =
                    next.expire_time_micros.saturating_add(next.interval_micros);
                next.schedule_time_micros = collected_at;
                state.timers.push(next);
            }
        }
        drop(state);
        for timer in expired {
            (timer.callback)(
                timer.event_id,
                timer.expire_time_micros,
                timer.schedule_time_micros,
                now(),
                timer.arg,
                timer.p_user,
            );
            state = pair.0.lock().unwrap();
            state.repeating_in_flight.remove(&timer.event_id);
            let release = timer.interval_micros == 0 || state.cancelled.remove(&timer.event_id);
            drop(state);
            if release {
                if let Some(free) = timer.free_callback {
                    free(timer.p_user);
                }
            }
        }
        state = pair.0.lock().unwrap();
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_timer_schedule(
    expire_micros: u64,
    interval_micros: u64,
    arg: *const c_void,
    p_user: *mut c_void,
    callback: TimerCallback,
    free_callback: Option<TimerFreeCallback>,
) -> usize {
    INIT_THREAD.call_once(|| {
        thread::spawn(timer_thread);
    });

    let pair = get_timer_state();
    let mut state = pair.0.lock().unwrap();

    let event_id = state.next_event_id;
    state.next_event_id += 1;

    let now_micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64;

    let entry = TimerEntry {
        event_id,
        expire_time_micros: expire_micros,
        schedule_time_micros: now_micros,
        interval_micros,
        arg,
        p_user,
        callback,
        free_callback,
    };

    // Check if we need to wake up thread immediately (if this timer is earlier than existing ones)
    let wake_thread = if let Some(top) = state.timers.peek() {
        expire_micros < top.expire_time_micros
    } else {
        true
    };

    state.timers.push(entry);

    if wake_thread {
        pair.1.notify_one();
    }

    event_id
}

#[no_mangle]
pub extern "C" fn emane_rs_timer_cancel(event_id: usize) -> bool {
    let pair = get_timer_state();
    let mut state = pair.0.lock().unwrap();

    // Cancelled far-future timers must release their owned callback data now,
    // even when an earlier periodic timer remains at the head of the queue.
    let mut removed = None;
    state.timers.retain(|entry| {
        if entry.event_id == event_id {
            removed = Some(entry.clone());
            false
        } else {
            true
        }
    });
    if let Some(entry) = removed {
        pair.1.notify_one();
        // An expired callback still runs even if its next interval is cancelled.
        // Keep its owned data alive until that callback has returned.
        if state.repeating_in_flight.contains(&event_id) {
            state.cancelled.insert(event_id);
        } else {
            drop(state);
            if let Some(free) = entry.free_callback {
                free(entry.p_user);
            }
        }
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    extern "C" fn test_callback(
        event_id: usize,
        _expire_time_micros: u64,
        _schedule_time_micros: u64,
        _fire_time_micros: u64,
        arg: *const c_void,
        _p_timer_service_user: *mut c_void,
    ) {
        let sender: &mpsc::Sender<usize> = unsafe { &*(arg as *const mpsc::Sender<usize>) };
        let _ = sender.send(event_id);
    }

    extern "C" fn test_free_callback(p_user: *mut c_void) {
        if !p_user.is_null() {
            unsafe {
                let boxed_arc = Box::from_raw(p_user as *mut Arc<AtomicBool>);
                boxed_arc.store(true, Ordering::SeqCst);
            }
        }
    }

    fn now_micros() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64
    }

    fn wait_for_bool(flag: &Arc<AtomicBool>, timeout_ms: u64) -> bool {
        let mut elapsed = 0;
        while !flag.load(Ordering::SeqCst) && elapsed < timeout_ms {
            std::thread::sleep(Duration::from_millis(10));
            elapsed += 10;
        }
        flag.load(Ordering::SeqCst)
    }

    #[test]
    fn test_timer_schedule() {
        let (tx, rx) = mpsc::channel::<usize>();
        let tx_box = Box::new(tx);
        let arg = Box::into_raw(tx_box) as *const c_void;

        let expire = now_micros() + 10_000; // 10ms

        let id = emane_rs_timer_schedule(expire, 0, arg, std::ptr::null_mut(), test_callback, None);

        let received_id = rx
            .recv_timeout(Duration::from_millis(1000))
            .expect("Timer did not fire");
        assert_eq!(id, received_id);

        unsafe {
            let _ = Box::from_raw(arg as *mut mpsc::Sender<usize>);
        }
    }

    #[test]
    fn cancellation_releases_later_timers_and_rejects_unknown_ids() {
        let early = emane_rs_timer_schedule(
            now_micros() + 60_000_000,
            1_000_000,
            std::ptr::null(),
            std::ptr::null_mut(),
            test_callback,
            None,
        );
        for _ in 0..1000 {
            let flag = Arc::new(AtomicBool::new(false));
            let user = Box::into_raw(Box::new(flag.clone()));
            let later = emane_rs_timer_schedule(
                now_micros() + 3_600_000_000,
                0,
                std::ptr::null(),
                user.cast(),
                test_callback,
                Some(test_free_callback),
            );
            assert!(emane_rs_timer_cancel(later));
            assert!(flag.load(Ordering::SeqCst));
            assert!(!emane_rs_timer_cancel(later));
        }
        assert!(emane_rs_timer_cancel(early));
        assert!(!emane_rs_timer_cancel(usize::MAX));
    }

    #[test]
    fn test_timer_cancel() {
        let (tx, rx) = mpsc::channel::<()>();
        let tx_box = Box::new(tx);
        let arg = Box::into_raw(tx_box) as *const c_void;

        let expire = now_micros() + 100_000; // 100ms

        let id = emane_rs_timer_schedule(expire, 0, arg, std::ptr::null_mut(), test_callback, None);

        let cancelled = emane_rs_timer_cancel(id);
        assert!(cancelled);

        let result = rx.recv_timeout(Duration::from_millis(200));
        assert!(result.is_err(), "Timer should have been cancelled");

        unsafe {
            let _ = Box::from_raw(arg as *mut mpsc::Sender<usize>);
        }
    }

    #[test]
    fn test_timer_interval() {
        let (tx, rx) = mpsc::channel::<usize>();
        let tx_box = Box::new(tx);
        let arg = Box::into_raw(tx_box) as *const c_void;

        let expire = now_micros() + 20_000; // 20ms
        let interval = 20_000; // 20ms

        let id = emane_rs_timer_schedule(
            expire,
            interval,
            arg,
            std::ptr::null_mut(),
            test_callback,
            None,
        );

        let mut count = 0;
        for _ in 0..3 {
            let received_id = rx
                .recv_timeout(Duration::from_millis(1000))
                .expect("Interval timer did not fire");
            assert_eq!(id, received_id);
            count += 1;
        }
        assert_eq!(count, 3);

        emane_rs_timer_cancel(id);

        let result = rx.recv_timeout(Duration::from_millis(100));
        assert!(result.is_err(), "Interval timer should have been cancelled");

        unsafe {
            let _ = Box::from_raw(arg as *mut mpsc::Sender<usize>);
        }
    }

    #[test]
    fn test_timer_free_callback_on_fire() {
        let (tx, rx) = mpsc::channel::<usize>();
        let tx_box = Box::new(tx);
        let arg = Box::into_raw(tx_box) as *const c_void;

        let freed_flag = Arc::new(AtomicBool::new(false));
        let p_user = Box::into_raw(Box::new(freed_flag.clone())) as *mut c_void;

        let expire = now_micros() + 10_000; // 10ms

        let id = emane_rs_timer_schedule(
            expire,
            0,
            arg,
            p_user,
            test_callback,
            Some(test_free_callback),
        );

        let received_id = rx
            .recv_timeout(Duration::from_millis(1000))
            .expect("Timer did not fire");
        assert_eq!(id, received_id);

        assert!(
            wait_for_bool(&freed_flag, 1000),
            "Free callback was not called after timer fired"
        );

        unsafe {
            let _ = Box::from_raw(arg as *mut mpsc::Sender<usize>);
        }
    }

    #[test]
    fn test_timer_free_callback_on_cancel() {
        let (tx, _rx) = mpsc::channel::<usize>();
        let tx_box = Box::new(tx);
        let arg = Box::into_raw(tx_box) as *const c_void;

        let freed_flag = Arc::new(AtomicBool::new(false));
        let p_user = Box::into_raw(Box::new(freed_flag.clone())) as *mut c_void;

        let expire = now_micros() + 500_000; // 500ms

        let id = emane_rs_timer_schedule(
            expire,
            0,
            arg,
            p_user,
            test_callback,
            Some(test_free_callback),
        );

        emane_rs_timer_cancel(id);

        assert!(
            wait_for_bool(&freed_flag, 1500),
            "Free callback was not called after cancel"
        );

        unsafe {
            let _ = Box::from_raw(arg as *mut mpsc::Sender<usize>);
        }
    }
}

#[cfg(test)]
mod schedule_regressions {
    use super::*;
    use std::sync::mpsc;
    struct Probe {
        sender: mpsc::Sender<u64>,
        count: usize,
    }
    extern "C" fn callback(
        id: usize,
        expire: u64,
        _: u64,
        _: u64,
        _: *const c_void,
        user: *mut c_void,
    ) {
        let probe = unsafe { &mut *(user as *mut Probe) };
        probe.count += 1;
        if probe.count == 1 {
            std::thread::sleep(Duration::from_millis(25));
        }
        if probe.count == 3 {
            emane_rs_timer_cancel(id);
        }
        let _ = probe.sender.send(expire);
    }
    extern "C" fn free(user: *mut c_void) {
        unsafe {
            drop(Box::from_raw(user as *mut Probe));
        }
    }
    #[test]
    fn late_callbacks_preserve_the_original_expiration_sequence() {
        let (sender, receiver) = mpsc::channel();
        let user = Box::into_raw(Box::new(Probe { sender, count: 0 }));
        let start = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64
            + 5_000;
        emane_rs_timer_schedule(
            start,
            5_000,
            std::ptr::null(),
            user.cast(),
            callback,
            Some(free),
        );
        for n in 0..3 {
            assert_eq!(
                receiver.recv_timeout(Duration::from_secs(1)).unwrap(),
                start + n * 5_000
            );
        }
    }
}

#[cfg(test)]
mod batch_regressions {
    use super as timer;
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
    use std::sync::Mutex;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    static ENTERED: AtomicBool = AtomicBool::new(false);
    static RELEASE: AtomicBool = AtomicBool::new(false);
    static REPEATS: AtomicUsize = AtomicUsize::new(0);
    static TRACE: Mutex<String> = Mutex::new(String::new());

    extern "C" fn blocker(_: usize, _: u64, _: u64, _: u64, _: *const c_void, _: *mut c_void) {
        ENTERED.store(true, SeqCst);
        while !RELEASE.load(SeqCst) {
            std::thread::yield_now();
        }
    }

    extern "C" fn a(id: usize, _: u64, _: u64, _: u64, _: *const c_void, _: *mut c_void) {
        TRACE.lock().unwrap().push('A');
        if REPEATS.fetch_add(1, SeqCst) == 2 {
            timer::emane_rs_timer_cancel(id);
        }
    }

    extern "C" fn b(_: usize, _: u64, _: u64, _: u64, _: *const c_void, _: *mut c_void) {
        TRACE.lock().unwrap().push('B');
    }

    #[test]
    fn overdue_callbacks_run_in_original_batch_order() {
        let now = || {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_micros() as u64
        };
        let schedule = |time, interval, callback| {
            timer::emane_rs_timer_schedule(
                time,
                interval,
                std::ptr::null(),
                std::ptr::null_mut(),
                callback,
                None,
            )
        };
        schedule(now(), 0, blocker);
        while !ENTERED.load(SeqCst) {
            std::thread::yield_now();
        }
        let start = now();
        schedule(start - 100_000, 10_000, a);
        schedule(start - 50_000, 0, b);
        RELEASE.store(true, SeqCst);
        for _ in 0..1000 {
            let trace = TRACE.lock().unwrap().clone();
            if trace.len() == 4 {
                assert_eq!(trace, "ABAA");
                return;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        panic!("timer probe timed out");
    }
}

#[cfg(test)]
mod batch_ownership_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
    use std::sync::mpsc;

    struct Context {
        release: (Mutex<bool>, Condvar),
        entered: mpsc::Sender<()>,
        target: AtomicUsize,
        cancelled: AtomicBool,
        fired: AtomicBool,
        freed: AtomicBool,
    }
    extern "C" fn block(_: usize, _: u64, _: u64, _: u64, arg: *const c_void, _: *mut c_void) {
        let ctx = unsafe { &*(arg as *const Context) };
        ctx.entered.send(()).unwrap();
        let mut release = ctx.release.0.lock().unwrap();
        while !*release {
            release = ctx.release.1.wait(release).unwrap();
        }
    }
    extern "C" fn cancel_next(
        _: usize,
        _: u64,
        _: u64,
        _: u64,
        arg: *const c_void,
        _: *mut c_void,
    ) {
        let ctx = unsafe { &*(arg as *const Context) };
        ctx.cancelled
            .store(emane_rs_timer_cancel(ctx.target.load(SeqCst)), SeqCst);
    }
    extern "C" fn target(_: usize, _: u64, _: u64, _: u64, _: *const c_void, user: *mut c_void) {
        let ctx = unsafe { &*(user as *const Arc<Context>) };
        assert!(
            !ctx.freed.load(SeqCst),
            "cancel must not free a callback already in the expired batch"
        );
        ctx.fired.store(true, SeqCst);
    }
    extern "C" fn free(user: *mut c_void) {
        let ctx = unsafe { Box::from_raw(user as *mut Arc<Context>) };
        assert!(ctx.fired.load(SeqCst));
        ctx.freed.store(true, SeqCst);
    }
    #[test]
    fn cancellation_keeps_expired_periodic_callback_data_alive() {
        let (send, receive) = mpsc::channel();
        let ctx = Arc::new(Context {
            release: (Mutex::new(false), Condvar::new()),
            entered: send,
            target: AtomicUsize::new(0),
            cancelled: AtomicBool::new(false),
            fired: AtomicBool::new(false),
            freed: AtomicBool::new(false),
        });
        let ptr = Arc::as_ptr(&ctx).cast();
        let now = || {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_micros() as u64
        };
        emane_rs_timer_schedule(now(), 0, ptr, std::ptr::null_mut(), block, None);
        receive.recv_timeout(Duration::from_secs(2)).unwrap();
        let start = now();
        emane_rs_timer_schedule(
            start - 100_000,
            0,
            ptr,
            std::ptr::null_mut(),
            cancel_next,
            None,
        );
        let owned = Box::into_raw(Box::new(ctx.clone())).cast();
        let id = emane_rs_timer_schedule(
            start - 50_000,
            1_000_000,
            std::ptr::null(),
            owned,
            target,
            Some(free),
        );
        ctx.target.store(id, SeqCst);
        *ctx.release.0.lock().unwrap() = true;
        ctx.release.1.notify_one();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !ctx.freed.load(SeqCst) && std::time::Instant::now() < deadline {
            thread::yield_now();
        }
        assert!(ctx.freed.load(SeqCst));
        assert!(ctx.cancelled.load(SeqCst));
        assert!(!emane_rs_timer_cancel(id));
    }
}
