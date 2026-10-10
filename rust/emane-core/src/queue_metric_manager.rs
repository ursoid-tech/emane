use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct R2RIQueueMetric {
    pub queue_id: u16,
    pub queue_max_size: u32,
    pub queue_current_depth_high_water: u32,
    pub num_discards_high_water: u32,
    pub avg_delay_microseconds: u64,
}

#[derive(Default)]
struct QueueData {
    max_queue_size: u32,
    queue_high_water_mark: u32,
    num_samples: u32,
    num_discards_high_water_mark: u32,
    sum_delay_microseconds: u64,
}

impl QueueData {
    fn new(max_size: u32) -> Self {
        Self {
            max_queue_size: max_size,
            ..Default::default()
        }
    }

    fn reset(&mut self) {
        self.num_discards_high_water_mark = 0;
        self.sum_delay_microseconds = 0;
        self.num_samples = 0;
        self.queue_high_water_mark = 0;
    }
}

pub struct QueueMetricManager {
    _nem_id: u16,
    queue_data_map: HashMap<u16, QueueData>,
}

impl QueueMetricManager {
    pub fn new(nem_id: u16) -> Self {
        Self {
            _nem_id: nem_id,
            queue_data_map: HashMap::new(),
        }
    }

    pub fn update_queue_metric(
        &mut self,
        queue_id: u16,
        max_queue_size: u32,
        current_queue_depth: u32,
        num_discards: u32,
        delay_microseconds: u64,
    ) {
        let data = self.queue_data_map.entry(queue_id).or_default();

        data.num_samples += 1;
        data.sum_delay_microseconds += delay_microseconds;

        if data.max_queue_size != max_queue_size {
            data.max_queue_size = max_queue_size;
            data.queue_high_water_mark = 0;
        }

        if data.queue_high_water_mark < current_queue_depth {
            data.queue_high_water_mark = current_queue_depth;
        }

        if data.num_discards_high_water_mark < num_discards {
            data.num_discards_high_water_mark = num_discards;
        }
    }

    pub fn get_queue_metrics(&mut self) -> Vec<R2RIQueueMetric> {
        let mut metrics = Vec::with_capacity(self.queue_data_map.len());

        for (&queue_id, data) in self.queue_data_map.iter_mut() {
            let avg_delay_microseconds = if data.num_samples > 1 {
                // C++ uses USEC_PER_SEC_F (float), then converts DoubleSeconds
                // back to integral microseconds. Preserve both rounding stages.
                let seconds =
                    data.sum_delay_microseconds as f32 / (1_000_000.0f32 * data.num_samples as f32);
                (f64::from(seconds) * 1_000_000.0) as u64
            } else if data.num_samples == 1 {
                data.sum_delay_microseconds
            } else {
                0
            };

            metrics.push(R2RIQueueMetric {
                queue_id,
                queue_max_size: data.max_queue_size,
                queue_current_depth_high_water: data.queue_high_water_mark,
                num_discards_high_water: data.num_discards_high_water_mark,
                avg_delay_microseconds,
            });

            data.reset();
        }

        metrics
    }

    pub fn add_queue_metric(&mut self, queue_id: u16, max_queue_size: u32) -> bool {
        if let std::collections::hash_map::Entry::Vacant(e) = self.queue_data_map.entry(queue_id) {
            e.insert(QueueData::new(max_queue_size));
            true
        } else {
            false
        }
    }

    pub fn remove_queue_metric(&mut self, queue_id: u16) -> bool {
        self.queue_data_map.remove(&queue_id).is_some()
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_queue_metric_manager_create(nem_id: u16) -> *mut QueueMetricManager {
    Box::into_raw(Box::new(QueueMetricManager::new(nem_id)))
}

#[no_mangle]
pub extern "C" fn emane_rs_queue_metric_manager_destroy(ptr: *mut QueueMetricManager) {
    if !ptr.is_null() {
        unsafe {
            drop(Box::from_raw(ptr));
        }
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_queue_metric_manager_update(
    ptr: *mut QueueMetricManager,
    queue_id: u16,
    max_queue_size: u32,
    current_queue_depth: u32,
    num_discards: u32,
    delay_microseconds: u64,
) {
    if let Some(m) = unsafe { ptr.as_mut() } {
        m.update_queue_metric(
            queue_id,
            max_queue_size,
            current_queue_depth,
            num_discards,
            delay_microseconds,
        );
    }
}

#[repr(C)]
pub struct FfiR2RIQueueMetric {
    pub queue_id: u16,
    pub queue_max_size: u32,
    pub queue_current_depth_high_water: u32,
    pub num_discards_high_water: u32,
    pub avg_delay_microseconds: u64,
}

#[no_mangle]
pub extern "C" fn emane_rs_queue_metric_manager_get(
    ptr: *mut QueueMetricManager,
    out_len: *mut usize,
) -> *mut FfiR2RIQueueMetric {
    if let Some(m) = unsafe { ptr.as_mut() } {
        let metrics = m.get_queue_metrics();
        let mut ffi_metrics = Vec::with_capacity(metrics.len());
        for metric in metrics {
            ffi_metrics.push(FfiR2RIQueueMetric {
                queue_id: metric.queue_id,
                queue_max_size: metric.queue_max_size,
                queue_current_depth_high_water: metric.queue_current_depth_high_water,
                num_discards_high_water: metric.num_discards_high_water,
                avg_delay_microseconds: metric.avg_delay_microseconds,
            });
        }

        ffi_metrics.shrink_to_fit();
        unsafe {
            *out_len = ffi_metrics.len();
        }
        let ptr = ffi_metrics.as_mut_ptr();
        std::mem::forget(ffi_metrics);
        ptr
    } else {
        unsafe {
            *out_len = 0;
        }
        std::ptr::null_mut()
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_queue_metric_manager_free(ptr: *mut FfiR2RIQueueMetric, len: usize) {
    if !ptr.is_null() && len > 0 {
        unsafe {
            Vec::from_raw_parts(ptr, len, len);
        }
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_queue_metric_manager_add(
    ptr: *mut QueueMetricManager,
    queue_id: u16,
    max_queue_size: u32,
) -> bool {
    if let Some(m) = unsafe { ptr.as_mut() } {
        m.add_queue_metric(queue_id, max_queue_size)
    } else {
        false
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_queue_metric_manager_remove(
    ptr: *mut QueueMetricManager,
    queue_id: u16,
) -> bool {
    if let Some(m) = unsafe { ptr.as_mut() } {
        m.remove_queue_metric(queue_id)
    } else {
        false
    }
}

#[cfg(test)]
mod parity_tests {
    use super::*;
    #[test]
    fn legacy_report_rounding_and_interval_reset() {
        let mut queue = QueueMetricManager::new(1);
        for delay in [545, 1308, 2071] {
            queue.update_queue_metric(5, 100, 19, 12, delay);
        }
        let report = queue.get_queue_metrics();
        assert_eq!(report[0].avg_delay_microseconds, 1307);
        assert_eq!(report[0].queue_current_depth_high_water, 19);
        assert_eq!(queue.get_queue_metrics()[0].avg_delay_microseconds, 0);
        queue.update_queue_metric(5, 100, 1, 0, 2001);
        assert_eq!(queue.get_queue_metrics()[0].avg_delay_microseconds, 2001);
    }
}
