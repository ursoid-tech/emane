use emane_plugin_api::random::{LegacyNormal, LegacyRandom};

pub struct NakagamiFadingAlgorithm {
    rng: LegacyRandom,
    distribution: LegacyNormal,
}

impl Default for NakagamiFadingAlgorithm {
    fn default() -> Self {
        Self::new()
    }
}

impl NakagamiFadingAlgorithm {
    pub fn new() -> Self {
        Self {
            rng: LegacyRandom::seeded(5489),
            distribution: LegacyNormal::default(),
        }
    }

    pub fn compute(
        &mut self,
        power_dbm: f64,
        distance_meters: f64,
        d0: f64,
        d1: f64,
        m0: f64,
        m1: f64,
        m2: f64,
    ) -> f64 {
        let m = if distance_meters < d0 {
            m0
        } else if distance_meters < d1 {
            m1
        } else {
            m2
        };

        // db_to_milliwatt equivalent in Rust
        let mw = 10_f64.powf(power_dbm / 10.0);
        let scale = mw / m;

        self.distribution.gamma(&mut self.rng, m, scale)
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_nakagami_fading_new() -> *mut NakagamiFadingAlgorithm {
    Box::into_raw(Box::new(NakagamiFadingAlgorithm::new()))
}

#[no_mangle]
pub extern "C" fn emane_rs_nakagami_fading_free(ptr: *mut NakagamiFadingAlgorithm) {
    if !ptr.is_null() {
        unsafe {
            let _ = Box::from_raw(ptr);
        }
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_nakagami_fading_compute(
    ptr: *mut NakagamiFadingAlgorithm,
    power_dbm: f64,
    distance_meters: f64,
    d0: f64,
    d1: f64,
    m0: f64,
    m1: f64,
    m2: f64,
) -> f64 {
    if let Some(algo) = unsafe { ptr.as_mut() } {
        algo.compute(power_dbm, distance_meters, d0, d1, m0, m1, m2)
    } else {
        0.0
    }
}
