use emane_plugin_api::numeric::LegacyParse;
use roxmltree::Document;
use std::collections::BTreeMap;

#[derive(Default)]
pub struct PcrManager {
    curves: BTreeMap<u64, Vec<(f64, f64)>>,
    packet_size: usize,
    default_rate: u64,
}

impl PcrManager {
    pub fn load(uri: &str) -> Result<Self, String> {
        let path = uri.strip_prefix("file://").unwrap_or(uri);
        let content = emane_plugin_api::xml_document::read(path)
            .map_err(|error| format!("failed to read PCR curve {path}: {error}"))?;
        let document = Document::parse_with_options(
            &content,
            roxmltree::ParsingOptions {
                allow_dtd: true,
                ..Default::default()
            },
        )
        .map_err(|error| format!("failed to parse PCR curve {path}: {error}"))?;
        let root = document.root_element();
        if !root.has_tag_name("tdmabasemodel-pcr") {
            return Err("PCR curve has an invalid document root".to_string());
        }
        emane_plugin_api::pcr_validation::validate(root, "datarate", "bps")?;
        let packet_size = root
            .attribute("packetsize")
            .unwrap()
            .parse_legacy::<u16>()
            .map_err(|_| "PCR curve has an invalid packetsize".to_string())?;
        let mut curves = BTreeMap::new();
        let mut default_rate = 0;
        for table in root.children().filter(|node| node.has_tag_name("datarate")) {
            let rate = parse_rate(
                table
                    .attribute("bps")
                    .ok_or_else(|| "PCR datarate is missing bps".to_string())?,
            )
            .ok_or_else(|| "PCR datarate has an invalid bps".to_string())?;
            if curves.is_empty() {
                default_rate = rate;
            }
            let mut points = Vec::new();
            for entry in table.children().filter(|node| node.has_tag_name("entry")) {
                let sinr = f64::from(emane_plugin_api::pcr_validation::scaled_sinr(
                    entry.attribute("sinr").unwrap(),
                )?) / 100.0;
                let por = entry.attribute("por").unwrap().parse_legacy::<f32>()?;
                if !sinr.is_finite() || !por.is_finite() || por < 0.0 {
                    return Err("PCR entry is outside its valid range".to_string());
                }
                points.push((sinr, f64::from(por / 100.0)));
            }
            points.sort_by(|a, b| a.0.total_cmp(&b.0));
            if points.windows(2).any(|p| p[0].0 == p[1].0) {
                return Err("duplicate PCR SINR value".into());
            }
            if points.is_empty() || curves.insert(rate, points).is_some() {
                return Err("PCR curve has an empty or duplicate datarate".to_string());
            }
        }
        if curves.is_empty() {
            return Err("PCR curve has no datarates".to_string());
        }
        Ok(Self {
            curves,
            packet_size: usize::from(packet_size),
            default_rate,
        })
    }

    pub fn probability(&self, rate: u64, sinr: f64, packet_length: usize) -> f64 {
        let Some(points) = self
            .curves
            .get(&rate)
            .or_else(|| self.curves.get(&self.default_rate))
        else {
            return 0.0;
        };
        let x = ((sinr as f32) * 100.0) as i32;
        let scaled = |point: &(f64, f64)| (point.0 * 100.0).round() as i32;
        let probability = match points.binary_search_by_key(&x, scaled) {
            Ok(i) => points[i].1 as f32,
            Err(0) => return 0.0,
            Err(i) if i == points.len() => return 1.0,
            Err(i) => {
                let (x0, x1) = (scaled(&points[i - 1]), scaled(&points[i]));
                let (y0, y1) = (points[i - 1].1 as f32, points[i].1 as f32);
                let slope = (y1 - y0) / (x1 - x0) as f32;
                y1 - (x1 - x) as f32 * slope
            }
        };
        f64::from(if self.packet_size == 0 {
            probability
        } else {
            probability.powf(packet_length as f32 / self.packet_size as f32)
        })
    }
}

pub fn parse_rate(value: &str) -> Option<u64> {
    value.parse_legacy::<u64>().ok()
}

#[cfg(test)]
mod legacy_regressions {
    use super::*;
    #[test]
    fn unlisted_rate_uses_first_curve_in_file() {
        let path = std::env::temp_dir().join(format!("tdma-default-{}.xml", std::process::id()));
        std::fs::write(&path,r#"<tdmabasemodel-pcr packetsize="0"><datarate bps="2000000"><entry sinr="0" por="100"/><entry sinr="20" por="100"/></datarate><datarate bps="1000000"><entry sinr="0" por="0"/><entry sinr="20" por="0"/></datarate></tdmabasemodel-pcr>"#).unwrap();
        let curve = PcrManager::load(path.to_str().unwrap()).unwrap();
        std::fs::remove_file(path).unwrap();
        assert_eq!(curve.probability(3_000_000, 10.0, 100), 1.0);
        assert_eq!(curve.probability(1_000_000, 10.0, 100), 0.0);
    }
}
