//! std::mt19937 and the libstdc++ uniform_real_distribution<float> mapping
//! used by the original MACs. Explicit seeds support differential tests.
#[derive(Clone)]
pub struct LegacyRandom {
    state: [u32; 624],
    index: usize,
}
impl LegacyRandom {
    pub fn seeded(seed: u32) -> Self {
        let mut state = [0; 624];
        state[0] = seed;
        for i in 1..624 {
            state[i] = 1812433253u32
                .wrapping_mul(state[i - 1] ^ (state[i - 1] >> 30))
                .wrapping_add(i as u32);
        }
        Self { state, index: 624 }
    }
    pub fn from_clock() -> Self {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u32;
        Self::seeded(seed)
    }
    pub fn next_u32(&mut self) -> u32 {
        if self.index == 624 {
            for i in 0..624 {
                let x = (self.state[i] & 0x80000000) | (self.state[(i + 1) % 624] & 0x7fffffff);
                self.state[i] = self.state[(i + 397) % 624]
                    ^ (x >> 1)
                    ^ if x & 1 != 0 { 0x9908b0df } else { 0 };
            }
            self.index = 0;
        }
        let mut y = self.state[self.index];
        self.index += 1;
        y ^= y >> 11;
        y ^= (y << 7) & 0x9d2c5680;
        y ^= (y << 15) & 0xefc60000;
        y ^= y >> 18;
        y
    }
    pub fn unit(&mut self) -> f32 {
        (self.next_u32() as f32 / 4_294_967_296.0).min(f32::from_bits(1.0f32.to_bits() - 1))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mt19937_reference_sequence() {
        let mut rng = LegacyRandom::seeded(5489);
        assert_eq!(
            (0..5).map(|_| rng.next_u32()).collect::<Vec<_>>(),
            vec![3499211612, 581869302, 3890346734, 3586334585, 545404204]
        );
    }
}

#[cfg(test)]
mod cpp_regressions {
    use super::*;
    #[test]
    fn twist_boundaries_and_float_mapping_match_libstdcxx() {
        let mut rng = LegacyRandom::seeded(5489);
        for i in 0..10_000 {
            let value = rng.next_u32();
            match i {
                623 => assert_eq!(value, 4020325887),
                624 => assert_eq!(value, 4178893912),
                9999 => assert_eq!(value, 4123659995),
                _ => {}
            }
        }
        let mut rng = LegacyRandom::seeded(11);
        assert_eq!(
            (0..4).map(|_| rng.unit().to_bits()).collect::<Vec<_>>(),
            vec![1043896478, 1032578166, 1017088650, 1059728156]
        );
    }
}

impl LegacyRandom {
    /// C++17 generate_canonical<double, 53> with a 32-bit engine.
    pub fn unit_double(&mut self) -> f64 {
        let low = f64::from(self.next_u32());
        let high = f64::from(self.next_u32());
        ((low + high * 4_294_967_296.0) / 18_446_744_073_709_551_616.0)
            .min(f64::from_bits(1.0f64.to_bits() - 1))
    }
}

/// Polar normal sampler. Keep one instance per distribution: the original
/// normal, lognormal, and gamma distributions each retain their own spare.
#[derive(Default)]
pub struct LegacyNormal {
    spare: Option<f64>,
}
impl LegacyNormal {
    pub fn sample(&mut self, rng: &mut LegacyRandom, mean: f64, sigma: f64) -> f64 {
        let z = if let Some(spare) = self.spare.take() {
            spare
        } else {
            loop {
                let x = 2.0 * rng.unit_double() - 1.0;
                let y = 2.0 * rng.unit_double() - 1.0;
                let radius = x * x + y * y;
                if radius > 0.0 && radius <= 1.0 {
                    let factor = (-2.0 * radius.ln() / radius).sqrt();
                    self.spare = Some(x * factor);
                    break y * factor;
                }
            }
        };
        z * sigma + mean
    }

    /// Marsaglia–Tsang gamma sampling, including the shape < 1 transform.
    pub fn gamma(&mut self, rng: &mut LegacyRandom, shape: f64, scale: f64) -> f64 {
        let d = if shape < 1.0 { shape + 1.0 } else { shape } - 1.0 / 3.0;
        let c = 1.0 / (9.0 * d).sqrt();
        loop {
            let z = self.sample(rng, 0.0, 1.0);
            let v = 1.0 + c * z;
            if v <= 0.0 {
                continue;
            }
            let v = v * v * v;
            let u = rng.unit_double();
            if u > 1.0 - 0.0331 * z * z * z * z && u.ln() > 0.5 * z * z + d * (1.0 - v + v.ln()) {
                continue;
            }
            return if shape < 1.0 {
                let u = loop {
                    let u = rng.unit_double();
                    if u != 0.0 {
                        break u;
                    }
                };
                u.powf(1.0 / shape) * d * v * scale
            } else {
                d * v * scale
            };
        }
    }
}
