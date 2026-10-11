use std::collections::BTreeMap;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct R2RINeighborMetric {
    pub neighbor_id: u16,
    pub num_rx_frames: u64,
    pub num_tx_frames: u64,
    pub num_rx_missed_frames: u64,
    pub rx_utilization_microseconds: u64,
    pub sinr_avg: f32,
    pub sinr_std: f32,
    pub noise_floor_avg: f32,
    pub noise_floor_stdv: f32,
    pub rx_data_rate_avg: u64,
    pub tx_data_rate_avg: u64,
}

#[derive(Clone, Debug)]
pub struct NeighborMetricStatus {
    pub neighbor_id: u16,
    pub num_rx_frames: u64,
    pub num_tx_frames: u64,
    pub num_rx_missed_frames: u64,
    pub rx_utilization_microseconds: u64,
    pub last_rx_time_seconds: f64,
    pub last_tx_time_seconds: f64,
    pub sinr_avg: f64,
    pub sinr_std: f64,
    pub noise_floor_avg: f64,
    pub noise_floor_stdv: f64,
    pub rx_data_rate_avg: u64,
    pub tx_data_rate_avg: u64,
}

#[derive(Clone, Debug)]
pub struct NeighborStatusSnapshot {
    pub neighbor_id: u16,
    pub num_rx_frames: u64,
    pub num_tx_frames: u64,
    pub num_rx_missed_frames: u64,
    pub bandwidth_utilization_ratio: f64,
    pub sinr_avg: f64,
    pub noise_floor_avg: f64,
    pub rx_age_seconds: f64,
}

#[derive(Clone, Default)]
struct NeighborData {
    _nem_id: u16,
    last_rx_seq_num: u64,
    have_ever_had_rx_activity: bool,
    last_rx_time: Duration,
    last_tx_time: Duration,
    num_rx_frames: u64,
    num_rx_missed_frames: u64,
    num_tx_frames: u64,
    rx_utilization_microseconds: u64,
    sinr_sum: f64,
    sinr_sum2: f64,
    noise_floor_sum: f64,
    noise_floor_sum2: f64,
    rx_data_rate_min: u64,
    rx_data_rate_max: u64,
    rx_data_rate_avg: u64,
    tx_data_rate_min: u64,
    tx_data_rate_max: u64,
    tx_data_rate_avg: u64,
    uuid: [u8; 16],
}

impl NeighborData {
    fn new(nem_id: u16) -> Self {
        Self {
            _nem_id: nem_id,
            uuid: [0; 16],
            ..Default::default()
        }
    }

    fn clear_data(&mut self) {
        self.num_rx_missed_frames = 0;
        self.num_rx_frames = 0;
        self.num_tx_frames = 0;
        self.rx_utilization_microseconds = 0;
        self.sinr_sum = 0.0;
        self.sinr_sum2 = 0.0;
        self.noise_floor_sum = 0.0;
        self.noise_floor_sum2 = 0.0;
        self.rx_data_rate_min = 0;
        self.rx_data_rate_max = 0;
        self.rx_data_rate_avg = 0;
        self.tx_data_rate_min = 0;
        self.tx_data_rate_max = 0;
        self.tx_data_rate_avg = 0;
    }
}

pub struct NeighborMetricManager {
    _nem_id: u16,
    r2ri_metric_table: BTreeMap<u16, Box<NeighborData>>,
    neighbor_data_table: BTreeMap<u16, (Box<NeighborData>, Box<NeighborData>)>,
    neighbor_delete_age_microseconds: Duration,
    last_neighbor_status_update_time: Duration,
}

impl NeighborMetricManager {
    pub fn new(nem_id: u16) -> Self {
        Self {
            _nem_id: nem_id,
            r2ri_metric_table: BTreeMap::new(),
            neighbor_data_table: BTreeMap::new(),
            neighbor_delete_age_microseconds: Duration::from_secs(60),
            last_neighbor_status_update_time: Duration::default(),
        }
    }

    pub fn set_neighbor_delete_time_microseconds(&mut self, age: Duration) {
        self.neighbor_delete_age_microseconds = age;
    }

    pub fn handle_tx_activity(&mut self, dst: u16, data_rate_bps: u64, tx_time: Duration) {
        if dst != 0xFFFF {
            // EMANE::NEM_BROADCAST_MAC_ADDRESS
            self.handle_r2ri_tx_activity(dst, data_rate_bps, tx_time);
        }
        self.handle_neighbor_tx_activity(dst, data_rate_bps, tx_time);
    }

    pub fn handle_rx_activity(
        &mut self,
        src: u16,
        seq_num: u64,
        uuid: &[u8; 16],
        sinr: f64,
        noise_floor: f64,
        rx_time: Duration,
        duration: Duration,
        data_rate_bps: u64,
    ) {
        self.handle_r2ri_rx_activity(
            src,
            seq_num,
            uuid,
            sinr,
            noise_floor,
            rx_time,
            duration,
            data_rate_bps,
        );

        self.update_neighbor_rx_activity(
            src,
            seq_num,
            uuid,
            sinr,
            noise_floor,
            rx_time,
            duration,
            data_rate_bps,
        );
    }

    pub fn get_neighbor_metrics(&mut self, current_time: Duration) -> Vec<R2RINeighborMetric> {
        let mut metrics = Vec::new();
        let mut to_remove = Vec::new();

        for (&nem_id, data) in &mut self.r2ri_metric_table {
            let age = current_time.saturating_sub(data.last_rx_time);

            if age > self.neighbor_delete_age_microseconds {
                to_remove.push(nem_id);
            } else {
                let (sinr_avg, _) =
                    get_avg_and_std(data.sinr_sum, data.sinr_sum2, data.num_rx_frames);
                let (nf_avg, nf_std) = get_avg_and_std(
                    data.noise_floor_sum,
                    data.noise_floor_sum2,
                    data.num_rx_frames,
                );

                metrics.push(R2RINeighborMetric {
                    neighbor_id: nem_id,
                    num_rx_frames: data.num_rx_frames,
                    num_tx_frames: data.num_tx_frames,
                    num_rx_missed_frames: data.num_rx_missed_frames,
                    rx_utilization_microseconds: data.rx_utilization_microseconds,
                    sinr_avg: sinr_avg as f32,
                    // The original R2RINeighborMetric::getSINRStddev accessor
                    // returns the noise-floor deviation, including on the wire.
                    sinr_std: nf_std as f32,
                    noise_floor_avg: nf_avg as f32,
                    noise_floor_stdv: nf_std as f32,
                    rx_data_rate_avg: data.rx_data_rate_avg,
                    tx_data_rate_avg: data.tx_data_rate_avg,
                });

                data.clear_data();
            }
        }

        for nem_id in to_remove {
            self.r2ri_metric_table.remove(&nem_id);
        }

        metrics
    }

    pub fn get_neighbor_metric_status(&self, nem_id: u16) -> Option<NeighborMetricStatus> {
        let data = &self.neighbor_data_table.get(&nem_id)?.1;
        let (sinr_avg, sinr_std) =
            get_avg_and_std(data.sinr_sum, data.sinr_sum2, data.num_rx_frames);
        let (noise_floor_avg, noise_floor_stdv) = get_avg_and_std(
            data.noise_floor_sum,
            data.noise_floor_sum2,
            data.num_rx_frames,
        );
        Some(NeighborMetricStatus {
            neighbor_id: nem_id,
            num_rx_frames: data.num_rx_frames,
            num_tx_frames: data.num_tx_frames,
            num_rx_missed_frames: data.num_rx_missed_frames,
            rx_utilization_microseconds: data.rx_utilization_microseconds,
            last_rx_time_seconds: data.last_rx_time.as_secs_f64(),
            last_tx_time_seconds: data.last_tx_time.as_secs_f64(),
            sinr_avg,
            sinr_std,
            noise_floor_avg,
            noise_floor_stdv,
            rx_data_rate_avg: data.rx_data_rate_avg,
            tx_data_rate_avg: data.tx_data_rate_avg,
        })
    }

    pub fn get_neighbor_statuses(&mut self, current_time: Duration) -> Vec<NeighborStatusSnapshot> {
        let elapsed = current_time.saturating_sub(self.last_neighbor_status_update_time);
        let first_update = self.last_neighbor_status_update_time.is_zero();
        let elapsed_seconds = elapsed.as_secs_f64();
        let mut statuses = Vec::with_capacity(self.neighbor_data_table.len());
        for (&neighbor_id, (interval, _)) in &mut self.neighbor_data_table {
            let sinr_avg = if interval.num_rx_frames == 0 {
                0.0
            } else {
                interval.sinr_sum / interval.num_rx_frames as f64
            };
            let noise_floor_avg = if interval.num_rx_frames == 0 {
                0.0
            } else {
                interval.noise_floor_sum / interval.num_rx_frames as f64
            };
            statuses.push(NeighborStatusSnapshot {
                neighbor_id,
                num_rx_frames: interval.num_rx_frames,
                num_tx_frames: interval.num_tx_frames,
                num_rx_missed_frames: interval.num_rx_missed_frames,
                bandwidth_utilization_ratio: if first_update || elapsed_seconds == 0.0 {
                    0.0
                } else {
                    interval.rx_utilization_microseconds as f64 / 1_000_000.0 / elapsed_seconds
                },
                sinr_avg,
                noise_floor_avg,
                rx_age_seconds: if interval.have_ever_had_rx_activity {
                    current_time
                        .saturating_sub(interval.last_rx_time)
                        .as_secs_f64()
                } else {
                    0.0
                },
            });
            interval.clear_data();
        }
        self.last_neighbor_status_update_time = current_time;
        statuses
    }

    fn lookup_r2ri_metric(&mut self, nem_id: u16) -> &mut NeighborData {
        self.r2ri_metric_table
            .entry(nem_id)
            .or_insert_with(|| Box::new(NeighborData::new(nem_id)))
    }

    fn lookup_neighbor_data(&mut self, nem_id: u16) -> &mut (Box<NeighborData>, Box<NeighborData>) {
        self.neighbor_data_table.entry(nem_id).or_insert_with(|| {
            (
                Box::new(NeighborData::new(nem_id)),
                Box::new(NeighborData::new(nem_id)),
            )
        })
    }

    fn handle_r2ri_tx_activity(&mut self, dst: u16, data_rate_bps: u64, tx_time: Duration) {
        let data = self.lookup_r2ri_metric(dst);
        update_tx_activity_data(data, data_rate_bps, tx_time);
    }

    fn handle_neighbor_tx_activity(&mut self, dst: u16, data_rate_bps: u64, tx_time: Duration) {
        let pair = self.lookup_neighbor_data(dst);
        update_tx_activity_data(&mut pair.0, data_rate_bps, tx_time);
        update_tx_activity_data(&mut pair.1, data_rate_bps, tx_time);
    }

    fn handle_r2ri_rx_activity(
        &mut self,
        src: u16,
        seq_num: u64,
        uuid: &[u8; 16],
        sinr: f64,
        noise_floor: f64,
        rx_time: Duration,
        duration: Duration,
        data_rate_bps: u64,
    ) {
        let data = self.lookup_r2ri_metric(src);
        update_rx_activity_data(data, seq_num, uuid, rx_time);
        update_rx_activity_channel_data(
            data,
            sinr,
            noise_floor,
            duration.as_micros() as u64,
            data_rate_bps,
        );
    }

    fn update_neighbor_rx_activity(
        &mut self,
        src: u16,
        seq_num: u64,
        uuid: &[u8; 16],
        sinr: f64,
        noise_floor: f64,
        rx_time: Duration,
        duration: Duration,
        data_rate_bps: u64,
    ) {
        let pair = self.lookup_neighbor_data(src);
        let duration_us = duration.as_micros() as u64;

        update_rx_activity_data(&mut pair.0, seq_num, uuid, rx_time);
        update_rx_activity_data(&mut pair.1, seq_num, uuid, rx_time);

        update_rx_activity_channel_data(&mut pair.0, sinr, noise_floor, duration_us, data_rate_bps);
        update_rx_activity_channel_data(&mut pair.1, sinr, noise_floor, duration_us, data_rate_bps);
    }
}

fn update_tx_activity_data(data: &mut NeighborData, data_rate_bps: u64, tx_time: Duration) {
    data.num_tx_frames += 1;
    data.last_tx_time = tx_time;
    update_running_average(
        &mut data.tx_data_rate_avg,
        data.num_tx_frames,
        data_rate_bps,
    );
    update_min_max(
        &mut data.tx_data_rate_min,
        &mut data.tx_data_rate_max,
        data_rate_bps,
    );
}

fn update_rx_activity_data(
    data: &mut NeighborData,
    seq_num: u64,
    uuid: &[u8; 16],
    rx_time: Duration,
) {
    if uuid == &data.uuid {
        if seq_num > data.last_rx_seq_num {
            data.num_rx_missed_frames += seq_num - data.last_rx_seq_num - 1;
            data.last_rx_seq_num = seq_num;
        } else if data.num_rx_missed_frames > 0 {
            data.num_rx_missed_frames -= 1;
        }
    } else {
        data.uuid.copy_from_slice(uuid);
        data.last_rx_seq_num = seq_num;
    }

    data.num_rx_frames += 1;
    data.last_rx_time = rx_time;
    data.have_ever_had_rx_activity = true;
}

fn update_rx_activity_channel_data(
    data: &mut NeighborData,
    sinr: f64,
    noise_floor: f64,
    duration_us: u64,
    data_rate_bps: u64,
) {
    data.rx_utilization_microseconds += duration_us;
    data.sinr_sum += sinr;
    data.sinr_sum2 += sinr * sinr;
    data.noise_floor_sum += noise_floor;
    data.noise_floor_sum2 += noise_floor * noise_floor;

    update_min_max(
        &mut data.rx_data_rate_min,
        &mut data.rx_data_rate_max,
        data_rate_bps,
    );
    update_running_average(
        &mut data.rx_data_rate_avg,
        data.num_rx_frames,
        data_rate_bps,
    );
}

fn update_running_average(avg: &mut u64, count: u64, val: u64) {
    if count == 1 {
        *avg = val;
    } else {
        // Preserve the original manager's count weighting (count has already
        // been incremented), including unsigned arithmetic semantics.
        *avg = avg.wrapping_mul(count).wrapping_add(val) / count.wrapping_add(1);
    }
}

fn update_min_max(min: &mut u64, max: &mut u64, val: u64) {
    if *min > val || *min == 0 {
        *min = val;
    }
    if *max < val || *max == 0 {
        *max = val;
    }
}

fn get_avg_and_std(sum: f64, sum2: f64, count: u64) -> (f64, f64) {
    if count == 0 {
        return (0.0, 0.0);
    }
    let avg = sum / (count as f64);
    let mut std = 0.0;
    if count > 1 {
        // This intentionally matches the legacy statistic, rather than the
        // conventional sample standard deviation.
        let delta = sum2 - (sum * sum);
        if delta > 0.0 {
            std = (delta / count as f64).sqrt() / (count as f64 - 1.0);
        }
    }
    (avg, std)
}

#[no_mangle]
pub extern "C" fn emane_rs_neighbor_metric_manager_create(
    nem_id: u16,
) -> *mut NeighborMetricManager {
    Box::into_raw(Box::new(NeighborMetricManager::new(nem_id)))
}

#[no_mangle]
pub extern "C" fn emane_rs_neighbor_metric_manager_destroy(ptr: *mut NeighborMetricManager) {
    if !ptr.is_null() {
        unsafe {
            drop(Box::from_raw(ptr));
        }
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_neighbor_metric_manager_set_delete_time(
    ptr: *mut NeighborMetricManager,
    age_usec: u64,
) {
    if let Some(m) = unsafe { ptr.as_mut() } {
        m.set_neighbor_delete_time_microseconds(Duration::from_micros(age_usec));
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_neighbor_metric_manager_update_tx(
    ptr: *mut NeighborMetricManager,
    dst: u16,
    data_rate_bps: u64,
    tx_time_sec: f64,
) {
    if let Some(m) = unsafe { ptr.as_mut() } {
        m.handle_tx_activity(dst, data_rate_bps, Duration::from_secs_f64(tx_time_sec));
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_neighbor_metric_manager_update_rx_short(
    ptr: *mut NeighborMetricManager,
    src: u16,
    seq_num: u64,
    uuid: *const u8,
    rx_time_sec: f64,
) {
    if let Some(m) = unsafe { ptr.as_mut() } {
        let mut uuid_arr = [0u8; 16];
        unsafe {
            std::ptr::copy_nonoverlapping(uuid, uuid_arr.as_mut_ptr(), 16);
        }
        // For short rx activity, we just pass 0s for channel data
        m.handle_rx_activity(
            src,
            seq_num,
            &uuid_arr,
            0.0,
            0.0,
            Duration::from_secs_f64(rx_time_sec),
            Duration::from_micros(0),
            0,
        );
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_neighbor_metric_manager_update_rx_long(
    ptr: *mut NeighborMetricManager,
    src: u16,
    seq_num: u64,
    uuid: *const u8,
    sinr: f64,
    noise_floor: f64,
    rx_time_sec: f64,
    duration_usec: u64,
    data_rate_bps: u64,
) {
    if let Some(m) = unsafe { ptr.as_mut() } {
        let mut uuid_arr = [0u8; 16];
        unsafe {
            std::ptr::copy_nonoverlapping(uuid, uuid_arr.as_mut_ptr(), 16);
        }
        m.handle_rx_activity(
            src,
            seq_num,
            &uuid_arr,
            sinr,
            noise_floor,
            Duration::from_secs_f64(rx_time_sec),
            Duration::from_micros(duration_usec),
            data_rate_bps,
        );
    }
}

#[repr(C)]
pub struct FfiR2RINeighborMetric {
    pub neighbor_id: u16,
    pub num_rx_frames: u64,
    pub num_tx_frames: u64,
    pub num_rx_missed_frames: u64,
    pub rx_utilization_microseconds: u64,
    pub sinr_avg: f32,
    pub sinr_std: f32,
    pub noise_floor_avg: f32,
    pub noise_floor_stdv: f32,
    pub rx_data_rate_avg: u64,
    pub tx_data_rate_avg: u64,
}

#[repr(C)]
pub struct FfiNeighborData {
    pub nem_id: u16,
    pub num_rx_frames: u64,
    pub num_tx_frames: u64,
    pub num_rx_missed_frames: u64,
    pub rx_utilization_microseconds: u64,
    pub sinr_avg: f64,
    pub sinr_std: f64,
    pub noise_floor_avg: f64,
    pub noise_floor_stdv: f64,
    pub rx_data_rate_avg: u64,
    pub tx_data_rate_avg: u64,
    pub last_rx_time_sec: f64,
    pub have_ever_had_rx_activity: bool,
}

#[no_mangle]
pub extern "C" fn emane_rs_neighbor_metric_manager_get_metrics(
    ptr: *mut NeighborMetricManager,
    current_time_sec: f64,
    out_len: *mut usize,
) -> *mut FfiR2RINeighborMetric {
    if let Some(m) = unsafe { ptr.as_mut() } {
        let metrics = m.get_neighbor_metrics(Duration::from_secs_f64(current_time_sec));
        let mut ffi_metrics = Vec::with_capacity(metrics.len());
        for metric in metrics {
            ffi_metrics.push(FfiR2RINeighborMetric {
                neighbor_id: metric.neighbor_id,
                num_rx_frames: metric.num_rx_frames,
                num_tx_frames: metric.num_tx_frames,
                num_rx_missed_frames: metric.num_rx_missed_frames,
                rx_utilization_microseconds: metric.rx_utilization_microseconds,
                sinr_avg: metric.sinr_avg,
                sinr_std: metric.sinr_std,
                noise_floor_avg: metric.noise_floor_avg,
                noise_floor_stdv: metric.noise_floor_stdv,
                rx_data_rate_avg: metric.rx_data_rate_avg,
                tx_data_rate_avg: metric.tx_data_rate_avg,
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
pub extern "C" fn emane_rs_neighbor_metric_manager_free_metrics(
    ptr: *mut FfiR2RINeighborMetric,
    len: usize,
) {
    if !ptr.is_null() && len > 0 {
        unsafe {
            Vec::from_raw_parts(ptr, len, len);
        }
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_neighbor_metric_manager_get_status(
    ptr: *mut NeighborMetricManager,
    current_time_sec: f64,
    out_len: *mut usize,
) -> *mut FfiNeighborData {
    if let Some(m) = unsafe { ptr.as_mut() } {
        let current_time = Duration::from_secs_f64(current_time_sec);

        let mut to_remove = Vec::new();
        let mut results = Vec::new();

        for (&nem_id, pair) in &mut m.neighbor_data_table {
            let data = &mut pair.0;
            let age = current_time.saturating_sub(data.last_rx_time);

            if age > m.neighbor_delete_age_microseconds {
                to_remove.push(nem_id);
            } else {
                let (sinr_avg, sinr_std) =
                    get_avg_and_std(data.sinr_sum, data.sinr_sum2, data.num_rx_frames);
                let (nf_avg, nf_std) = get_avg_and_std(
                    data.noise_floor_sum,
                    data.noise_floor_sum2,
                    data.num_rx_frames,
                );

                results.push(FfiNeighborData {
                    nem_id,
                    num_rx_frames: data.num_rx_frames,
                    num_tx_frames: data.num_tx_frames,
                    num_rx_missed_frames: data.num_rx_missed_frames,
                    rx_utilization_microseconds: data.rx_utilization_microseconds,
                    sinr_avg,
                    sinr_std,
                    noise_floor_avg: nf_avg,
                    noise_floor_stdv: nf_std,
                    rx_data_rate_avg: data.rx_data_rate_avg,
                    tx_data_rate_avg: data.tx_data_rate_avg,
                    last_rx_time_sec: data.last_rx_time.as_secs_f64(),
                    have_ever_had_rx_activity: data.have_ever_had_rx_activity,
                });

                data.clear_data();
            }
        }

        for nem_id in to_remove {
            m.neighbor_data_table.remove(&nem_id);
        }

        results.shrink_to_fit();
        unsafe {
            *out_len = results.len();
        }
        let out_ptr = results.as_mut_ptr();
        std::mem::forget(results);
        out_ptr
    } else {
        unsafe {
            *out_len = 0;
        }
        std::ptr::null_mut()
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_neighbor_metric_manager_free_status(
    ptr: *mut FfiNeighborData,
    len: usize,
) {
    if !ptr.is_null() && len > 0 {
        unsafe {
            Vec::from_raw_parts(ptr, len, len);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r2ri_sinr_deviation_matches_original_accessor_without_changing_statistics() {
        let mut manager = NeighborMetricManager::new(1);
        for (sequence, sinr, noise) in [(1, -10.0, -4.0), (2, 10.0, 4.0)] {
            manager.handle_rx_activity(
                2,
                sequence,
                &[1; 16],
                sinr,
                noise,
                Duration::from_secs(sequence),
                Duration::from_micros(100),
                1_000_000,
            );
        }
        let status = manager.get_neighbor_metric_status(2).unwrap();
        assert_eq!(status.sinr_std, 10.0);
        assert_eq!(status.noise_floor_stdv, 4.0);
        let metrics = manager.get_neighbor_metrics(Duration::from_secs(3));
        assert_eq!(metrics[0].sinr_std, 4.0);
        assert_eq!(metrics[0].noise_floor_stdv, 4.0);
    }

    #[test]
    fn neighbor_reports_preserve_original_id_order_across_intervals() {
        let mut manager = NeighborMetricManager::new(1);
        for id in [65535, 3, 19, 2] {
            manager.handle_rx_activity(
                id,
                1,
                &[1; 16],
                40.0,
                -110.0,
                Duration::from_secs(1),
                Duration::from_micros(100),
                1_000_000,
            );
        }
        for now in [2, 3] {
            let ids: Vec<_> = manager
                .get_neighbor_metrics(Duration::from_secs(now))
                .iter()
                .map(|v| v.neighbor_id)
                .collect();
            assert_eq!(ids, [2, 3, 19, 65535]);
            let ids: Vec<_> = manager
                .get_neighbor_statuses(Duration::from_secs(now))
                .iter()
                .map(|v| v.neighbor_id)
                .collect();
            assert_eq!(ids, [2, 3, 19, 65535]);
        }
    }

    #[test]
    fn varying_rates_and_sinr_preserve_original_neighbor_statistics() {
        let mut manager = NeighborMetricManager::new(1);
        for (sequence, rate, sinr) in [(0, 1_000_000, 40.0), (1, 2_000_000, 53.0)] {
            manager.handle_rx_activity(
                2,
                sequence,
                &[1; 16],
                sinr,
                -110.0,
                Duration::from_secs(sequence + 1),
                Duration::from_micros(100),
                rate,
            );
            manager.handle_tx_activity(2, rate, Duration::from_secs(sequence + 1));
        }
        let status = manager.get_neighbor_metric_status(2).unwrap();
        assert_eq!(status.rx_data_rate_avg, 1_333_333);
        assert_eq!(status.tx_data_rate_avg, 1_333_333);
        assert_eq!(status.sinr_avg, 46.5);
        assert_eq!(status.sinr_std, 0.0);
        let metrics = manager.get_neighbor_metrics(Duration::from_secs(3));
        assert_eq!(metrics[0].rx_data_rate_avg, 1_333_333);
        assert_eq!(metrics[0].sinr_std, 0.0);
        // C++'s unusual deviation expression also has a nonzero branch.
        assert_eq!(get_avg_and_std(0.0, 200.0, 2), (0.0, 10.0));
    }

    #[test]
    fn neighbor_status_uses_interval_data_without_clearing_long_term_metrics() {
        let mut manager = NeighborMetricManager::new(1);
        manager.handle_rx_activity(
            2,
            1,
            &[0; 16],
            10.0,
            -90.0,
            Duration::from_secs_f64(1.0),
            Duration::from_millis(200),
            1_000_000,
        );
        let first = manager.get_neighbor_statuses(Duration::from_secs(2));
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].num_rx_frames, 1);
        assert_eq!(first[0].bandwidth_utilization_ratio, 0.0);

        manager.handle_rx_activity(
            2,
            2,
            &[0; 16],
            20.0,
            -80.0,
            Duration::from_secs_f64(2.5),
            Duration::from_millis(100),
            2_000_000,
        );
        let second = manager.get_neighbor_statuses(Duration::from_secs(3));
        assert_eq!(second[0].num_rx_frames, 1);
        assert!((second[0].bandwidth_utilization_ratio - 0.1).abs() < 1.0e-12);
        assert!((second[0].rx_age_seconds - 0.5).abs() < 1.0e-12);
        assert_eq!(second[0].sinr_avg, 20.0);

        let long_term = manager.get_neighbor_metric_status(2).unwrap();
        assert_eq!(long_term.num_rx_frames, 2);
        assert_eq!(long_term.sinr_avg, 15.0);
    }
}
