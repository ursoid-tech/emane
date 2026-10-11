use std::cmp;
use std::collections::{BTreeMap, HashMap};

pub struct Wheel {
    slots: usize,
    bins: usize,
    store: Vec<f64>,
}

impl Wheel {
    pub fn new(slots: usize, bins: usize) -> Self {
        Self {
            slots,
            bins,
            store: vec![0.0; slots * bins],
        }
    }

    pub fn slots(&self) -> usize {
        self.slots
    }

    pub fn bins(&self) -> usize {
        self.bins
    }

    pub fn dump(&self) -> Vec<f64> {
        self.store.clone()
    }

    pub fn add(&mut self, begin: usize, slots: usize, value: f64, bin_begin: usize, bins: usize) {
        if slots > self.slots || begin >= self.slots {
            panic!("IndexError: wheel total slots available: {} attempting to set slots: {} starting at: {}", self.slots, slots, begin);
        }
        if slots == 0 {
            return;
        }
        if bins > self.bins || bin_begin >= self.bins {
            panic!("IndexError: wheel total bins available: {} attempting to set bins: {} starting at: {}", self.bins, bins, bin_begin);
        }
        if bins == 0 {
            return;
        }

        let mut remainder = 0;
        if begin + slots > self.slots {
            remainder = (begin + slots) % self.slots;
        }

        let limit = begin + slots - remainder;
        for i in begin..limit {
            for j in bin_begin..(bin_begin + bins) {
                self.store[i * self.bins + j] += value;
            }
        }

        if remainder > 0 {
            for i in 0..remainder {
                for j in bin_begin..(bin_begin + bins) {
                    self.store[i * self.bins + j] += value;
                }
            }
        }
    }

    pub fn set(&mut self, begin: usize, slots: usize, value: f64, bin_begin: usize, bins: usize) {
        if slots > self.slots || begin >= self.slots {
            panic!("IndexError: wheel total slots available: {} attempting to set slots: {} starting at: {}", self.slots, slots, begin);
        }
        if slots == 0 {
            return;
        }
        if bins > self.bins || bin_begin >= self.bins {
            panic!("IndexError: wheel total bins available: {} attempting to set bins: {} starting at: {}", self.bins, bins, bin_begin);
        }
        if bins == 0 {
            return;
        }

        let mut remainder = 0;
        if begin + slots > self.slots {
            remainder = (begin + slots) % self.slots;
        }

        let limit = begin + slots - remainder;
        for i in begin..limit {
            for j in bin_begin..(bin_begin + bins) {
                self.store[i * self.bins + j] = value;
            }
        }

        if remainder > 0 {
            for i in 0..remainder {
                for j in bin_begin..(bin_begin + bins) {
                    self.store[i * self.bins + j] = value;
                }
            }
        }
    }

    pub fn get(&self, begin: usize, slots: usize) -> Vec<f64> {
        if slots > self.slots || begin >= self.slots {
            panic!("IndexError: wheel total slots available: {} attempting to set slots: {} starting at: {}", self.slots, slots, begin);
        }

        let mut values = vec![0.0; slots * self.bins];

        if begin >= slots - 1 {
            let src_start = (begin + 1 - slots) * self.bins;
            let src_end = src_start + slots * self.bins;
            values.copy_from_slice(&self.store[src_start..src_end]);
        } else {
            let remainder = slots - begin - 1;
            let src_start1 = (self.slots - remainder) * self.bins;
            let len1 = remainder * self.bins;
            values[..len1].copy_from_slice(&self.store[src_start1..(src_start1 + len1)]);

            let len2 = (begin + 1) * self.bins;
            values[len1..(len1 + len2)].copy_from_slice(&self.store[..len2]);
        }
        values
    }
}

pub struct NoiseRecorder {
    total_window_bins: i64,
    total_wheel_bins: i64,
    bin_size_microseconds: i64,
    u64_bandwidth_bin_size_hz: u64,
    u64_band_start_frequency_hz: u64,
    total_sub_band_bins: usize,
    u64_band_end_frequency_hz: u64,

    wheel: Wheel,
    _d_rx_sensitivity_milli_watt: f64,
    max_end_of_reception_bin: i64,
    min_start_of_reception_bin: i64,

    // Map from NEMId -> (AntennaIndex -> EOR bin)
    nem_antenna_index_eor_bin_map: HashMap<u16, HashMap<u16, i64>>,

    // Map from (start_freq, end_freq) -> Vec<(start_bin, end_bin, multiplier)>
    bin_power_apply_map: BTreeMap<(u64, u64), Vec<(usize, usize, f64)>>,
}

fn frequency_overlap_ratio(
    u64_frequency_hz1: u64,
    u64_bandwidth_hz1: u64,
    u64_frequency_hz2: u64,
    u64_bandwidth_hz2: u64,
) -> (f64, u64, u64) {
    let u64_upper_frequency_hz1 = u64_frequency_hz1 + u64_bandwidth_hz1 / 2;
    let u64_lower_frequency_hz1 = u64_frequency_hz1 - u64_bandwidth_hz1 / 2;

    let u64_upper_frequency_hz2 = u64_frequency_hz2 + u64_bandwidth_hz2 / 2;
    let u64_lower_frequency_hz2 = u64_frequency_hz2 - u64_bandwidth_hz2 / 2;

    let mut u64_lower_overlap_frequency_hz = 0;
    let mut u64_upper_overlap_frequency_hz = 0;
    let mut d_ratio = 0.0;

    if u64_lower_frequency_hz2 < u64_upper_frequency_hz1
        && u64_upper_frequency_hz2 > u64_lower_frequency_hz1
    {
        if u64_lower_frequency_hz2 >= u64_lower_frequency_hz1 {
            u64_lower_overlap_frequency_hz = u64_lower_frequency_hz2;
            if u64_upper_frequency_hz2 <= u64_upper_frequency_hz1 {
                u64_upper_overlap_frequency_hz = u64_upper_frequency_hz2;
                d_ratio = 1.0;
            } else {
                u64_upper_overlap_frequency_hz = u64_upper_frequency_hz1;
                d_ratio = (u64_upper_frequency_hz1 - u64_lower_frequency_hz2) as f64
                    / u64_bandwidth_hz2 as f64;
            }
        } else {
            u64_lower_overlap_frequency_hz = u64_lower_frequency_hz1;
            if u64_upper_frequency_hz2 <= u64_upper_frequency_hz1 {
                u64_upper_overlap_frequency_hz = u64_upper_frequency_hz2;
                d_ratio = (u64_upper_frequency_hz2 - u64_lower_frequency_hz1) as f64
                    / u64_bandwidth_hz2 as f64;
            } else {
                u64_upper_overlap_frequency_hz = u64_upper_frequency_hz1;
                d_ratio = (u64_upper_frequency_hz1 - u64_lower_frequency_hz1) as f64
                    / u64_bandwidth_hz2 as f64;
            }
        }
    }

    (
        d_ratio,
        u64_lower_overlap_frequency_hz,
        u64_upper_overlap_frequency_hz,
    )
}

impl NoiseRecorder {
    pub fn new(
        bin: i64,
        max_offset: i64,
        max_propagation: i64,
        max_duration: i64,
        d_rx_sensitivity_milli_watt: f64,
        u64_frequency_hz: u64,
        u64_bandwidth_hz: u64,
        u64_bandwidth_bin_size_hz: u64,
    ) -> Self {
        // Framework configuration normally guarantees positive, aligned time
        // values. Keep the native API sound for malformed FFI callers too:
        // the old expression divided by zero and could construct a zero-slot
        // wheel, which later panicked on every update.
        let bin = bin.max(1);
        let max_offset = max_offset.max(0);
        let max_propagation = max_propagation.max(0);
        let max_duration = max_duration.max(bin);
        let total_window_bins = (max_duration / bin).max(1);
        let total_wheel_bins = max_offset
            .saturating_add(max_propagation)
            .saturating_add(max_duration.saturating_mul(2))
            .checked_div(bin)
            .unwrap_or(1)
            .max(1);
        let u64_band_start_frequency_hz = u64_frequency_hz.saturating_sub(u64_bandwidth_hz / 2);

        let total_sub_band_bins = if u64_bandwidth_bin_size_hz > 0 {
            ((u64_bandwidth_hz as f64 / u64_bandwidth_bin_size_hz as f64).ceil() as usize) + 1
        } else {
            1
        };

        let u64_band_end_frequency_hz = if u64_bandwidth_bin_size_hz == 0 {
            u64_band_start_frequency_hz
                .saturating_add(u64_bandwidth_hz)
                .saturating_sub(1)
        } else {
            u64_band_start_frequency_hz
                .saturating_add(
                    (total_sub_band_bins as u64).saturating_mul(u64_bandwidth_bin_size_hz),
                )
                .saturating_sub(1)
        };

        Self {
            total_window_bins,
            total_wheel_bins,
            bin_size_microseconds: bin,
            u64_bandwidth_bin_size_hz,
            u64_band_start_frequency_hz,
            total_sub_band_bins,
            u64_band_end_frequency_hz,
            wheel: Wheel::new(total_wheel_bins as usize, total_sub_band_bins),
            _d_rx_sensitivity_milli_watt: d_rx_sensitivity_milli_watt,
            max_end_of_reception_bin: 0,
            min_start_of_reception_bin: 0,
            nem_antenna_index_eor_bin_map: HashMap::new(),
            bin_power_apply_map: BTreeMap::new(),
        }
    }

    fn timepoint_to_bin(&self, tp_micros: i64, adjust: bool) -> i64 {
        if tp_micros == 0 {
            0
        } else {
            tp_micros / self.bin_size_microseconds
                - if adjust && (tp_micros % self.bin_size_microseconds == 0) {
                    1
                } else {
                    0
                }
        }
    }

    pub fn update(
        &mut self,
        _now: i64,
        tx_time: i64,
        offset: i64,
        propagation: i64,
        duration: i64,
        d_rx_power: f64,
        transmitters: &[u16],
        u64_start_frequency_hz: u64,
        u64_end_frequency_hz: u64,
        tx_antenna_index: u16,
        b_is_more: bool,
    ) -> (i64, i64) {
        let start_of_reception = tx_time + offset + propagation;
        let end_of_reception = start_of_reception + duration;

        let reported_start_of_reception_bin = self.timepoint_to_bin(start_of_reception, false);
        let end_of_reception_bin = self.timepoint_to_bin(end_of_reception, true);

        let mut start_of_reception_bin = reported_start_of_reception_bin;
        let mut stored_max_eor_bin = 0;

        let mut sub_band_bin_start = 0;
        let mut sub_band_bin_end = self.total_sub_band_bins - 1;
        let mut sub_band_bins = 1;

        if self.u64_bandwidth_bin_size_hz > 0 {
            if u64_start_frequency_hz > self.u64_band_start_frequency_hz {
                sub_band_bin_start = (u64_start_frequency_hz - self.u64_band_start_frequency_hz)
                    .checked_div(self.u64_bandwidth_bin_size_hz)
                    .unwrap_or(0) as usize;
            }
            if u64_end_frequency_hz < self.u64_band_end_frequency_hz {
                sub_band_bin_end = self.total_sub_band_bins
                    - 1
                    - (self.u64_band_end_frequency_hz - u64_end_frequency_hz)
                        .checked_div(self.u64_bandwidth_bin_size_hz)
                        .unwrap_or(0) as usize;
            }

            sub_band_bins = sub_band_bin_end - sub_band_bin_start + 1;

            let key = (u64_start_frequency_hz, u64_end_frequency_hz);
            if !self.bin_power_apply_map.contains_key(&key) {
                let mut bin_power_applies = Vec::new();
                let mut pending_start = 0;
                let mut pending_multi = 0.0;
                let mut is_pending = false;

                for bin in sub_band_bin_start..=sub_band_bin_end {
                    let u64_bin_start_frequency_hz = (bin as u64) * self.u64_bandwidth_bin_size_hz
                        + self.u64_band_start_frequency_hz;

                    let (d_overlap_ratio, _, _) = frequency_overlap_ratio(
                        u64_bin_start_frequency_hz + self.u64_bandwidth_bin_size_hz / 2,
                        self.u64_bandwidth_bin_size_hz,
                        u64_start_frequency_hz
                            + (u64_end_frequency_hz - u64_start_frequency_hz) / 2,
                        u64_end_frequency_hz - u64_start_frequency_hz,
                    );

                    if d_overlap_ratio > 0.0 && d_overlap_ratio < 1.0 {
                        if is_pending {
                            bin_power_applies.push((pending_start, bin - 1, pending_multi));
                            is_pending = false;
                        }
                        bin_power_applies.push((bin, bin, d_overlap_ratio));
                    } else if d_overlap_ratio == 1.0 {
                        if !is_pending {
                            pending_start = bin;
                            pending_multi = d_overlap_ratio;
                            is_pending = true;
                        }
                    } else {
                        if is_pending {
                            bin_power_applies.push((pending_start, bin - 1, pending_multi));
                            is_pending = false;
                        }
                    }
                }
                if is_pending {
                    bin_power_applies.push((pending_start, sub_band_bin_end, pending_multi));
                }

                self.bin_power_apply_map.insert(key, bin_power_applies);
            }
        }

        for transmitter in transmitters {
            if let Some(amap) = self.nem_antenna_index_eor_bin_map.get(transmitter) {
                if let Some(&eor_bin) = amap.get(&tx_antenna_index) {
                    if stored_max_eor_bin < eor_bin {
                        stored_max_eor_bin = eor_bin;
                    }
                }
            }
        }

        if start_of_reception_bin <= stored_max_eor_bin {
            start_of_reception_bin = stored_max_eor_bin + 1;
        }

        if end_of_reception_bin >= start_of_reception_bin {
            let duration_bin_count = end_of_reception_bin - start_of_reception_bin + 1;

            // Once a reception starts at least one full wheel beyond the
            // newest stored reception, every value currently on the wheel is
            // stale. Reset the valid range before computing gaps; otherwise a
            // long idle period is mistaken for a gap that must be cleared and
            // Wheel::set is asked to clear more slots than the wheel contains.
            // This mirrors the legacy NoiseRecorder implementation.
            if self
                .max_end_of_reception_bin
                .saturating_add(self.total_wheel_bins)
                <= start_of_reception_bin
            {
                self.max_end_of_reception_bin = 0;
                self.min_start_of_reception_bin = 0;
            }

            let start_index = start_of_reception_bin as usize % self.total_wheel_bins as usize;
            let bin_power_applies = self
                .bin_power_apply_map
                .get(&(u64_start_frequency_hz, u64_end_frequency_hz))
                .cloned()
                .unwrap_or_default();

            if self.max_end_of_reception_bin == 0 && self.min_start_of_reception_bin == 0 {
                if self.total_sub_band_bins > 1 {
                    for &(start, end, multiplier) in &bin_power_applies {
                        self.wheel.set(
                            start_index,
                            duration_bin_count as usize,
                            d_rx_power * multiplier,
                            start,
                            end - start + 1,
                        );
                    }
                } else {
                    self.wheel.set(
                        start_index,
                        duration_bin_count as usize,
                        d_rx_power,
                        sub_band_bin_start,
                        sub_band_bins,
                    );
                }

                self.min_start_of_reception_bin = start_of_reception_bin;
                self.max_end_of_reception_bin = end_of_reception_bin;
            } else {
                let mut before_min_sor_bin_duration_count = 0;
                let mut after_max_eor_bin_duration_count = 0;

                if start_of_reception_bin < self.min_start_of_reception_bin {
                    before_min_sor_bin_duration_count =
                        if end_of_reception_bin < self.min_start_of_reception_bin {
                            duration_bin_count
                        } else {
                            self.min_start_of_reception_bin - start_of_reception_bin
                        };

                    if self.total_sub_band_bins > 1 {
                        self.wheel.set(
                            start_index,
                            before_min_sor_bin_duration_count as usize,
                            0.0,
                            0,
                            self.total_sub_band_bins,
                        );
                        for &(start, end, multiplier) in &bin_power_applies {
                            self.wheel.set(
                                start_index,
                                duration_bin_count as usize,
                                d_rx_power * multiplier,
                                start,
                                end - start + 1,
                            );
                        }
                    } else {
                        self.wheel.set(
                            start_index,
                            before_min_sor_bin_duration_count as usize,
                            d_rx_power,
                            sub_band_bin_start,
                            sub_band_bins,
                        );
                    }
                }

                if end_of_reception_bin > self.max_end_of_reception_bin {
                    after_max_eor_bin_duration_count =
                        if start_of_reception_bin > self.max_end_of_reception_bin {
                            duration_bin_count
                        } else {
                            end_of_reception_bin - self.max_end_of_reception_bin
                        };
                    let after_start_index = (start_index + duration_bin_count as usize
                        - after_max_eor_bin_duration_count as usize)
                        % self.total_wheel_bins as usize;

                    if self.total_sub_band_bins > 1 {
                        self.wheel.set(
                            after_start_index,
                            after_max_eor_bin_duration_count as usize,
                            0.0,
                            0,
                            self.total_sub_band_bins,
                        );
                        for &(start, end, multiplier) in &bin_power_applies {
                            self.wheel.set(
                                start_index,
                                duration_bin_count as usize,
                                d_rx_power * multiplier,
                                start,
                                end - start + 1,
                            );
                        }
                    } else {
                        self.wheel.set(
                            after_start_index,
                            after_max_eor_bin_duration_count as usize,
                            d_rx_power,
                            sub_band_bin_start,
                            sub_band_bins,
                        );
                    }
                }

                let within_min_sor_max_eor_bin_count = duration_bin_count
                    - before_min_sor_bin_duration_count
                    - after_max_eor_bin_duration_count;

                if within_min_sor_max_eor_bin_count > 0 {
                    let within_start_index = (start_index
                        + before_min_sor_bin_duration_count as usize)
                        % self.total_wheel_bins as usize;
                    if self.total_sub_band_bins > 1 {
                        for &(start, end, multiplier) in &bin_power_applies {
                            self.wheel.add(
                                within_start_index,
                                within_min_sor_max_eor_bin_count as usize,
                                d_rx_power * multiplier,
                                start,
                                end - start + 1,
                            );
                        }
                    } else {
                        self.wheel.add(
                            within_start_index,
                            within_min_sor_max_eor_bin_count as usize,
                            d_rx_power,
                            sub_band_bin_start,
                            sub_band_bins,
                        );
                    }
                } else {
                    if before_min_sor_bin_duration_count > 0 {
                        self.wheel.set(
                            (start_index + before_min_sor_bin_duration_count as usize)
                                % self.total_wheel_bins as usize,
                            (self.min_start_of_reception_bin
                                - (start_of_reception_bin + before_min_sor_bin_duration_count))
                                as usize,
                            0.0,
                            0,
                            self.total_sub_band_bins,
                        );
                    }
                    if after_max_eor_bin_duration_count > 0 {
                        self.wheel.set(
                            (self.max_end_of_reception_bin + 1) as usize
                                % self.total_wheel_bins as usize,
                            (start_of_reception_bin - self.max_end_of_reception_bin - 1) as usize,
                            0.0,
                            0,
                            self.total_sub_band_bins,
                        );
                    }
                }

                if before_min_sor_bin_duration_count > 0 {
                    self.min_start_of_reception_bin = start_of_reception_bin;
                }
                if after_max_eor_bin_duration_count > 0 {
                    self.max_end_of_reception_bin = end_of_reception_bin;
                }
            }
            // A fully overlapping segment is skipped. It must not move the
            // transmitter's end marker backward and admit later duplicate bins.
            if !b_is_more {
                for &transmitter in transmitters {
                    let map = self
                        .nem_antenna_index_eor_bin_map
                        .entry(transmitter)
                        .or_default();
                    map.insert(tx_antenna_index, end_of_reception_bin);
                }
            }
        }

        (start_of_reception, end_of_reception)
    }

    pub fn get(&self, now: i64, duration: i64, start_time: i64) -> (Vec<f64>, i64) {
        self.try_get(now, duration, start_time)
            .expect("invalid spectrum window")
    }

    pub fn try_get(&self, now: i64, duration: i64, start_time: i64) -> Option<(Vec<f64>, i64)> {
        if duration < 0 || now < 0 {
            return None;
        }
        let now_bin = self.timepoint_to_bin(now, true);
        let min_start_of_window_time =
            (now_bin - self.total_window_bins + 1) * self.bin_size_microseconds;

        let mut valid_start_time = start_time;
        let valid_duration = duration;

        if valid_start_time == -9223372036854775808 {
            // TIMEPOINT_MIN conceptually
            valid_start_time = min_start_of_window_time;
        } else if valid_start_time < min_start_of_window_time || valid_start_time > now {
            return None;
        }

        let start_time_bin = self.timepoint_to_bin(valid_start_time, false);

        let mut end_time = now;
        if valid_duration != 0 {
            end_time = valid_start_time.checked_add(valid_duration)?;
            if end_time > now {
                return None;
            }
        }

        let end_time_bin = self.timepoint_to_bin(end_time, true);
        let duration_bin_count = end_time_bin - start_time_bin + 1;

        let mut window = Vec::new();

        let start_of_window_time = start_time_bin * self.bin_size_microseconds;

        if start_of_window_time >= min_start_of_window_time {
            if self.max_end_of_reception_bin != 0 && self.min_start_of_reception_bin != 0 {
                let mut before_duration_count = 0;
                let mut after_duration_count = 0;

                if end_time_bin > self.max_end_of_reception_bin {
                    after_duration_count = cmp::min(
                        end_time_bin - self.max_end_of_reception_bin,
                        duration_bin_count,
                    );
                }

                if start_time_bin < self.min_start_of_reception_bin {
                    before_duration_count = cmp::min(
                        self.min_start_of_reception_bin - start_time_bin,
                        duration_bin_count,
                    );
                }

                let remainder_bin_count =
                    duration_bin_count - (before_duration_count + after_duration_count);

                let mut mid_window = Vec::new();
                if remainder_bin_count > 0 {
                    mid_window = self.wheel.get(
                        ((end_time_bin - after_duration_count) % self.total_wheel_bins) as usize,
                        remainder_bin_count as usize,
                    );
                }

                window.reserve((duration_bin_count as usize) * self.total_sub_band_bins);
                window.extend(vec![
                    0.0;
                    (before_duration_count as usize)
                        * self.total_sub_band_bins
                ]);
                window.extend(mid_window);
                window.extend(vec![
                    0.0;
                    (after_duration_count as usize)
                        * self.total_sub_band_bins
                ]);
            } else {
                window.extend(vec![
                    0.0;
                    (duration_bin_count as usize) * self.total_sub_band_bins
                ]);
            }
        } else {
            return None;
        }

        Some((window, start_of_window_time))
    }

    pub fn dump(&self) -> Vec<f64> {
        self.wheel.dump()
    }

    pub fn get_sub_band_bin_count(&self) -> usize {
        self.total_sub_band_bins
    }
}

// FFI
#[no_mangle]
pub extern "C" fn emane_rs_noise_recorder_new(
    bin: i64,
    max_offset: i64,
    max_propagation: i64,
    max_duration: i64,
    d_rx_sensitivity_milli_watt: f64,
    u64_frequency_hz: u64,
    u64_bandwidth_hz: u64,
    u64_bandwidth_bin_size_hz: u64,
) -> *mut NoiseRecorder {
    Box::into_raw(Box::new(NoiseRecorder::new(
        bin,
        max_offset,
        max_propagation,
        max_duration,
        d_rx_sensitivity_milli_watt,
        u64_frequency_hz,
        u64_bandwidth_hz,
        u64_bandwidth_bin_size_hz,
    )))
}

#[no_mangle]
pub extern "C" fn emane_rs_noise_recorder_free(ptr: *mut NoiseRecorder) {
    if !ptr.is_null() {
        unsafe {
            let _ = Box::from_raw(ptr);
        }
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_noise_recorder_update(
    ptr: *mut NoiseRecorder,
    now: i64,
    tx_time: i64,
    offset: i64,
    propagation: i64,
    duration: i64,
    d_rx_power: f64,
    transmitters_ptr: *const u16,
    transmitters_len: usize,
    u64_start_frequency_hz: u64,
    u64_end_frequency_hz: u64,
    tx_antenna_index: u16,
    b_is_more: bool,
    out_sor: *mut i64,
    out_eor: *mut i64,
) {
    if ptr.is_null() || (transmitters_len != 0 && transmitters_ptr.is_null()) {
        return;
    }
    let recorder = unsafe { &mut *ptr };
    let transmitters = if transmitters_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(transmitters_ptr, transmitters_len) }
    };

    let (sor, eor) = recorder.update(
        now,
        tx_time,
        offset,
        propagation,
        duration,
        d_rx_power,
        transmitters,
        u64_start_frequency_hz,
        u64_end_frequency_hz,
        tx_antenna_index,
        b_is_more,
    );
    if !out_sor.is_null() {
        unsafe {
            *out_sor = sor;
        }
    }
    if !out_eor.is_null() {
        unsafe {
            *out_eor = eor;
        }
    }
}

#[repr(C)]
pub struct EmaneRsNoiseWindowResult {
    pub data: *mut f64,
    pub length: usize,
    pub start_of_window_time: i64,
}

#[no_mangle]
pub extern "C" fn emane_rs_noise_recorder_get(
    ptr: *const NoiseRecorder,
    now: i64,
    duration: i64,
    start_time: i64,
) -> EmaneRsNoiseWindowResult {
    if ptr.is_null() {
        return EmaneRsNoiseWindowResult {
            data: std::ptr::null_mut(),
            length: 0,
            start_of_window_time: 0,
        };
    }
    let recorder = unsafe { &*ptr };
    let (mut vec, time) = recorder.get(now, duration, start_time);
    vec.shrink_to_fit();
    let length = vec.len();
    let data = vec.as_mut_ptr();
    std::mem::forget(vec);
    EmaneRsNoiseWindowResult {
        data,
        length,
        start_of_window_time: time,
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_noise_recorder_free_window(ptr: *mut f64, len: usize) {
    if !ptr.is_null() {
        unsafe {
            let _ = Vec::from_raw_parts(ptr, len, len);
        }
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_noise_recorder_get_sub_band_bin_count(
    ptr: *const NoiseRecorder,
) -> usize {
    if ptr.is_null() {
        return 0;
    }
    let recorder = unsafe { &*ptr };
    recorder.get_sub_band_bin_count()
}

#[no_mangle]
pub extern "C" fn emane_rs_noise_recorder_dump(
    ptr: *const NoiseRecorder,
    out_len: *mut usize,
) -> *mut f64 {
    if ptr.is_null() {
        if !out_len.is_null() {
            unsafe {
                *out_len = 0;
            }
        }
        return std::ptr::null_mut();
    }
    let recorder = unsafe { &*ptr };
    let mut vec = recorder.dump();
    vec.shrink_to_fit();
    let length = vec.len();
    if !out_len.is_null() {
        unsafe {
            *out_len = length;
        }
    }
    let data = vec.as_mut_ptr();
    std::mem::forget(vec);
    data
}

#[cfg(test)]
mod tests {
    use super::NoiseRecorder;

    #[test]
    fn skipped_overlap_does_not_rewind_transmitter_end() {
        let mut recorder = NoiseRecorder::new(
            1000,
            10000,
            10000,
            1000000,
            0.0,
            2_400_000_000,
            1_000_000,
            0,
        );
        recorder.update(0, 100000, 500, 0, 3500, 1.0, &[2, 3], 0, 0, 0, false);
        recorder.update(0, 100000, 500, 0, 1000, 2.0, &[2, 3], 0, 0, 0, false);
        recorder.update(0, 100000, 2000, 0, 1000, 3.0, &[2, 3], 0, 0, 0, false);
        assert_eq!(
            recorder.get(110000, 5000, 100000).0,
            vec![1.0, 1.0, 1.0, 1.0, 0.0]
        );
        // A different transmit antenna has independent overlap suppression.
        recorder.update(0, 100000, 2000, 0, 1000, 3.0, &[2, 3], 0, 0, 1, false);
        assert_eq!(
            recorder.get(110000, 5000, 100000).0,
            vec![1.0, 1.0, 4.0, 1.0, 0.0]
        );
    }

    #[test]
    fn update_resets_stale_wheel_after_long_idle_period() {
        let mut recorder = NoiseRecorder::new(10, 10, 10, 100, 0.0, 2_400_000_000, 1_000_000, 0);

        recorder.update(0, 1_000, 0, 0, 20, 1.0, &[1], 0, 0, 0, false);

        // This starts more than one complete wheel after the previous EoR.
        // The old Rust port tried to clear the entire intervening gap and
        // panicked because that gap was larger than the wheel.
        recorder.update(0, 2_000, 0, 0, 20, 2.0, &[2], 0, 0, 0, false);

        assert_eq!(recorder.min_start_of_reception_bin, 200);
        assert_eq!(recorder.max_end_of_reception_bin, 201);

        let wheel = recorder.dump();
        assert_eq!(wheel[200 % recorder.total_wheel_bins as usize], 2.0);
        assert_eq!(wheel[201 % recorder.total_wheel_bins as usize], 2.0);
    }
}
