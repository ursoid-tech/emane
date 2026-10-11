use crate::statistics::{
    increment_native_counter, native_table_generation, register_native_average,
    register_native_counter, register_native_table, sample_native_average, set_native_table_row,
    NativeTableValue,
};
use libc::{
    epoll_create1, epoll_ctl, epoll_event, epoll_wait, eventfd, EPOLLIN, EPOLLOUT, EPOLL_CTL_ADD,
    EPOLL_CTL_DEL, EPOLL_CTL_MOD,
};
use std::collections::{HashMap, VecDeque};
use std::os::raw::c_void;
use std::os::unix::io::RawFd;
use std::sync::{
    atomic::{AtomicBool, AtomicU8, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy)]
pub enum QueueTaskKind {
    DownstreamPacket,
    UpstreamPacket,
    DownstreamControl,
    UpstreamControl,
    Configuration,
    FileDescriptor,
    Event(u16),
    TimedEvent {
        expire_microseconds: u64,
        schedule_microseconds: u64,
        fire_microseconds: u64,
    },
}

struct QueuedTask {
    operation: Box<dyn FnOnce() + Send>,
    enqueued: Instant,
    kind: QueueTaskKind,
}

#[derive(Clone, Copy, Default)]
struct QueueStatistics {
    queued: u64,
    processed_downstream_packet: u64,
    processed_upstream_packet: u64,
    processed_downstream_control: u64,
    processed_upstream_control: u64,
    processed_event: u64,
    processed_configuration: u64,
    processed_timed_event: u64,
    average_wait: u64,
    average_depth: u64,
    average_timer_latency: u64,
    average_timer_latency_ratio: u64,
    event_table: u64,
}

impl QueueStatistics {
    fn register(build_id: u16) -> Self {
        let counter = |name, description| {
            register_native_counter(build_id, name, description, true).unwrap_or(0)
        };
        let average = |name, description| {
            register_native_average(build_id, name, description, true).unwrap_or(0)
        };
        Self {
            queued: counter("numAPIQueued", "The number of queued API events."),
            processed_downstream_packet: counter(
                "processedDownstreamPackets",
                "The number of processed downstream packets.",
            ),
            processed_upstream_packet: counter(
                "processedUpstreamPackets",
                "The number of processed upstream packets.",
            ),
            processed_downstream_control: counter(
                "processedDownstreamControl",
                "The number of processed downstream control.",
            ),
            processed_upstream_control: counter(
                "processedUpstreamControl",
                "The number of processed upstream control.",
            ),
            processed_event: counter("processedEvents", "The number of processed events."),
            processed_configuration: counter(
                "processedConfiguration",
                "The number of processed configuration.",
            ),
            processed_timed_event: counter(
                "processedTimedEvents",
                "The number of processed timed events.",
            ),
            average_wait: average(
                "avgProcessAPIQueueWait",
                "Average API queue wait in microseconds.",
            ),
            average_depth: average("avgProcessAPIQueueDepth", "Average API queue depth."),
            average_timer_latency: average(
                "avgTimedEventLatency",
                "Average timed-event latency in microseconds.",
            ),
            average_timer_latency_ratio: average(
                "avgTimedEventLatencyRatio",
                "Average timer latency to requested-duration ratio.",
            ),
            event_table: register_native_table(
                build_id,
                "EventReceptionTable",
                &["Event", "Total Rx"],
                "Received event counts",
                true,
            )
            .unwrap_or(0),
        }
    }
}

#[derive(Default)]
struct EventCounts {
    generation: u64,
    counts: HashMap<u16, u64>,
}

pub struct NemQueuedLayer {
    queue: Arc<Mutex<VecDeque<QueuedTask>>>,
    cancel: Arc<Mutex<bool>>,
    lifecycle: AtomicU8,
    model_running: AtomicBool,
    event_fd: RawFd,
    epoll_fd: RawFd,
    thread: Mutex<Option<thread::JoinHandle<()>>>,
    callbacks: Arc<Mutex<HashMap<RawFd, (u32, Arc<dyn Fn(RawFd) + Send + Sync>)>>>,
    statistics: QueueStatistics,
    event_counts: Arc<Mutex<EventCounts>>,
}

const LIFECYCLE_CREATED: u8 = 0;
const LIFECYCLE_RUNNING: u8 = 1;
const LIFECYCLE_STOPPED: u8 = 2;

impl NemQueuedLayer {
    pub fn new(_id: u16) -> Self {
        Self::new_inner(QueueStatistics::default())
    }

    pub fn new_with_build_id(_id: u16, build_id: u16) -> Self {
        Self::new_inner(QueueStatistics::register(build_id))
    }

    fn new_inner(statistics: QueueStatistics) -> Self {
        unsafe {
            let event_fd = eventfd(0, 0);
            let epoll_fd = epoll_create1(0);

            let mut ev = epoll_event {
                events: EPOLLIN as u32,
                u64: event_fd as u64,
            };
            epoll_ctl(epoll_fd, EPOLL_CTL_ADD, event_fd, &mut ev);

            Self {
                queue: Arc::new(Mutex::new(VecDeque::new())),
                cancel: Arc::new(Mutex::new(false)),
                lifecycle: AtomicU8::new(LIFECYCLE_CREATED),
                model_running: AtomicBool::new(false),
                event_fd,
                epoll_fd,
                thread: Mutex::new(None),
                callbacks: Arc::new(Mutex::new(HashMap::new())),
                statistics,
                event_counts: Arc::new(Mutex::new(EventCounts::default())),
            }
        }
    }

    pub fn is_running(&self) -> bool {
        self.lifecycle.load(Ordering::Acquire) == LIFECYCLE_RUNNING
    }

    pub fn is_model_running(&self) -> bool {
        self.model_running.load(Ordering::Acquire)
    }

    pub fn set_model_running(&self, running: bool) {
        self.model_running.store(running, Ordering::Release);
    }

    pub fn accepts_direct_calls(&self) -> bool {
        self.lifecycle.load(Ordering::Acquire) == LIFECYCLE_CREATED
    }

    pub fn start(&self) {
        let mut worker = self.thread.lock().unwrap();
        if worker.is_some() {
            return;
        }
        {
            let _queue = self.queue.lock().unwrap();
            *self.cancel.lock().unwrap() = false;
            self.lifecycle.store(LIFECYCLE_RUNNING, Ordering::Release);
        }
        let queue = self.queue.clone();
        let cancel = self.cancel.clone();
        let event_fd = self.event_fd;
        let epoll_fd = self.epoll_fd;
        let callbacks = self.callbacks.clone();
        let statistics = self.statistics;
        let event_counts = Arc::clone(&self.event_counts);

        *worker = Some(thread::spawn(move || unsafe {
            let mut events: [epoll_event; 32] = std::mem::zeroed();
            loop {
                let nfds = epoll_wait(epoll_fd, events.as_mut_ptr(), 32, -1);
                if nfds == -1 {
                    if *libc::__errno_location() == libc::EINTR {
                        continue;
                    }
                    break;
                }

                for i in 0..nfds {
                    let ev = &events[i as usize];
                    let fd = ev.u64 as RawFd;

                    if fd == event_fd {
                        let mut val: u64 = 0;
                        libc::read(event_fd, &mut val as *mut u64 as *mut c_void, 8);

                        let mut current_queue = VecDeque::new();
                        {
                            let mut q = queue.lock().unwrap();
                            std::mem::swap(&mut current_queue, &mut q);
                        }

                        if *cancel.lock().unwrap() {
                            return;
                        }

                        for task in current_queue {
                            let wait = task.enqueued.elapsed().as_micros() as f64;
                            if !matches!(task.kind, QueueTaskKind::FileDescriptor) {
                                let _ = sample_native_average(statistics.average_wait, wait);
                            }
                            match task.kind {
                                QueueTaskKind::DownstreamPacket => {
                                    let _ = increment_native_counter(
                                        statistics.processed_downstream_packet,
                                        1,
                                    );
                                }
                                QueueTaskKind::UpstreamPacket => {
                                    let _ = increment_native_counter(
                                        statistics.processed_upstream_packet,
                                        1,
                                    );
                                }
                                QueueTaskKind::DownstreamControl => {
                                    let _ = increment_native_counter(
                                        statistics.processed_downstream_control,
                                        1,
                                    );
                                }
                                QueueTaskKind::UpstreamControl => {
                                    let _ = increment_native_counter(
                                        statistics.processed_upstream_control,
                                        1,
                                    );
                                }
                                QueueTaskKind::Configuration => {
                                    let _ = increment_native_counter(
                                        statistics.processed_configuration,
                                        1,
                                    );
                                }
                                QueueTaskKind::FileDescriptor => {}
                                QueueTaskKind::Event(event_id) => {
                                    let _ = increment_native_counter(statistics.processed_event, 1);
                                    if statistics.event_table != 0 {
                                        let generation =
                                            native_table_generation(statistics.event_table)
                                                .unwrap_or(0);
                                        let mut events = event_counts.lock().unwrap();
                                        if events.generation != generation {
                                            events.generation = generation;
                                            events.counts.clear();
                                        }
                                        let count = events.counts.entry(event_id).or_default();
                                        *count = count.saturating_add(1);
                                        let _ = set_native_table_row(
                                            statistics.event_table,
                                            vec![u64::from(event_id)],
                                            vec![
                                                NativeTableValue::UInt16(event_id),
                                                NativeTableValue::UInt64(*count),
                                            ],
                                        );
                                    }
                                }
                                QueueTaskKind::TimedEvent {
                                    expire_microseconds,
                                    schedule_microseconds,
                                    fire_microseconds,
                                } => {
                                    let _ = increment_native_counter(
                                        statistics.processed_timed_event,
                                        1,
                                    );
                                    let now = SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_micros()
                                        .min(u128::from(u64::MAX))
                                        as u64;
                                    let latency = now.saturating_sub(expire_microseconds) as f64;
                                    let _ = sample_native_average(
                                        statistics.average_timer_latency,
                                        latency,
                                    );
                                    let requested =
                                        expire_microseconds.saturating_sub(schedule_microseconds);
                                    let ratio = if requested == 0 {
                                        1.0
                                    } else {
                                        fire_microseconds.saturating_sub(expire_microseconds) as f64
                                            / requested as f64
                                    };
                                    let _ = sample_native_average(
                                        statistics.average_timer_latency_ratio,
                                        ratio,
                                    );
                                }
                            }
                            (task.operation)();
                        }
                    } else {
                        let cb = {
                            let cbs = callbacks.lock().unwrap();
                            cbs.get(&fd).map(|(_, f)| f.clone())
                        };
                        if let Some(f) = cb {
                            f(fd);
                        }
                    }
                }
            }
        }));
    }

    pub fn stop(&self) {
        let mut worker = self.thread.lock().unwrap();
        {
            let _queue = self.queue.lock().unwrap();
            *self.cancel.lock().unwrap() = true;
            self.lifecycle.store(LIFECYCLE_STOPPED, Ordering::Release);
        }
        unsafe {
            let val: u64 = 1;
            libc::write(self.event_fd, &val as *const u64 as *const c_void, 8);
        }
        if let Some(t) = worker.take() {
            let _ = t.join();
        }
        *self.cancel.lock().unwrap() = false;
    }

    pub fn enqueue(
        &self,
        kind: QueueTaskKind,
        operation: Box<dyn FnOnce() + Send>,
    ) -> Result<(), Box<dyn FnOnce() + Send>> {
        let depth = {
            let mut queue = self.queue.lock().unwrap();
            // The original queue accepts work before start and after stop.
            // The model's lifecycle gate is checked when that work executes.
            queue.push_back(QueuedTask {
                operation,
                enqueued: Instant::now(),
                kind,
            });
            queue.len()
        };
        if !matches!(kind, QueueTaskKind::FileDescriptor) {
            let _ = increment_native_counter(self.statistics.queued, 1);
            let _ = sample_native_average(self.statistics.average_depth, depth as f64);
        }
        unsafe {
            let val: u64 = 1;
            libc::write(self.event_fd, &val as *const u64 as *const c_void, 8);
        }
        Ok(())
    }

    pub fn add_fd(&self, fd: RawFd, is_read: bool, cb: Arc<dyn Fn(RawFd) + Send + Sync>) {
        let events = if is_read {
            EPOLLIN as u32
        } else {
            EPOLLOUT as u32
        };
        let mut callbacks = self.callbacks.lock().unwrap();

        unsafe {
            let mut ev = epoll_event {
                events,
                u64: fd as u64,
            };

            if callbacks.contains_key(&fd) {
                epoll_ctl(self.epoll_fd, EPOLL_CTL_MOD, fd, &mut ev);
            } else {
                epoll_ctl(self.epoll_fd, EPOLL_CTL_ADD, fd, &mut ev);
            }
        }
        callbacks.insert(fd, (events, cb));
    }

    pub fn remove_fd(&self, fd: RawFd) {
        let mut callbacks = self.callbacks.lock().unwrap();
        if callbacks.remove(&fd).is_some() {
            unsafe {
                epoll_ctl(self.epoll_fd, EPOLL_CTL_DEL, fd, std::ptr::null_mut());
            }
        }
    }
}

impl Drop for NemQueuedLayer {
    fn drop(&mut self) {
        self.stop();
        unsafe {
            libc::close(self.event_fd);
            libc::close(self.epoll_fd);
        }
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_nem_queued_layer_new(id: u16) -> *mut NemQueuedLayer {
    Box::into_raw(Box::new(NemQueuedLayer::new(id)))
}

#[no_mangle]
pub extern "C" fn emane_rs_nem_queued_layer_free(ptr: *mut NemQueuedLayer) {
    if !ptr.is_null() {
        unsafe {
            drop(Box::from_raw(ptr));
        }
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_nem_queued_layer_start(ptr: *mut NemQueuedLayer) {
    let layer = unsafe { &*ptr };
    layer.start();
}

#[no_mangle]
pub extern "C" fn emane_rs_nem_queued_layer_stop(ptr: *mut NemQueuedLayer) {
    let layer = unsafe { &*ptr };
    layer.stop();
}

#[no_mangle]
pub extern "C" fn emane_rs_nem_queued_layer_enqueue(
    ptr: *mut NemQueuedLayer,
    execute: extern "C" fn(*mut c_void),
    context: *mut c_void,
    destroy: extern "C" fn(*mut c_void),
) {
    let layer = unsafe { &*ptr };
    struct CTask {
        execute: extern "C" fn(*mut c_void),
        context: *mut c_void,
        destroy: extern "C" fn(*mut c_void),
    }
    unsafe impl Send for CTask {}
    impl Drop for CTask {
        fn drop(&mut self) {
            (self.destroy)(self.context);
        }
    }
    impl CTask {
        fn call(&self) {
            (self.execute)(self.context);
        }
    }
    let task = CTask {
        execute,
        context,
        destroy,
    };
    let _ = layer.enqueue(
        QueueTaskKind::FileDescriptor,
        Box::new(move || {
            task.call();
        }),
    );
}

#[no_mangle]
pub extern "C" fn emane_rs_nem_queued_layer_add_fd(
    ptr: *mut NemQueuedLayer,
    fd: i32,
    is_read: bool,
    execute: extern "C" fn(i32, *mut c_void),
    context: *mut c_void,
    destroy: extern "C" fn(*mut c_void),
) {
    let layer = unsafe { &*ptr };
    struct CFdTask {
        execute: extern "C" fn(i32, *mut c_void),
        context: *mut c_void,
        destroy: extern "C" fn(*mut c_void),
    }
    unsafe impl Send for CFdTask {}
    unsafe impl Sync for CFdTask {}
    impl Drop for CFdTask {
        fn drop(&mut self) {
            (self.destroy)(self.context);
        }
    }
    impl CFdTask {
        fn call(&self, f: i32) {
            (self.execute)(f, self.context);
        }
    }
    let task = CFdTask {
        execute,
        context,
        destroy,
    };
    layer.add_fd(
        fd,
        is_read,
        Arc::new(move |f| {
            task.call(f);
        }),
    );
}

#[no_mangle]
pub extern "C" fn emane_rs_nem_queued_layer_remove_fd(ptr: *mut NemQueuedLayer, fd: i32) {
    let layer = unsafe { &*ptr };
    layer.remove_fd(fd);
}
