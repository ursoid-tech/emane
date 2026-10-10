use roxmltree::Document;

#[derive(Default)]
pub struct PcrCurve {
    points: Vec<(f32, f32)>,
    packet_size: usize,
    table: Vec<f32>,
}

impl PcrCurve {
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
        if !root.has_tag_name("pcr") {
            return Err("PCR curve has an invalid document root".to_string());
        }
        let mut tables = root.children().filter(|node| node.has_tag_name("table"));
        let table = tables
            .next()
            .ok_or_else(|| "PCR curve has no table".to_string())?;
        if tables.next().is_some() {
            return Err("PCR curve has multiple tables".to_string());
        }
        let packet_size = table
            .attribute("pktsize")
            .unwrap_or("0")
            .parse::<usize>()
            .map_err(|_| "PCR table has an invalid pktsize".to_string())?;
        let mut points = Vec::new();
        for row in table.children().filter(|node| node.has_tag_name("row")) {
            let sinr = row
                .attribute("sinr")
                .ok_or_else(|| "PCR row is missing sinr".to_string())?
                .parse::<f32>()
                .map_err(|_| "PCR row has an invalid sinr".to_string())?;
            let percent = row
                .attribute("por")
                .ok_or_else(|| "PCR row is missing por".to_string())?
                .parse::<f32>()
                .map_err(|_| "PCR row has an invalid por".to_string())?;
            if !(-255.0..=255.0).contains(&sinr)
                || !percent.is_finite()
                || !(0.0..=100.0).contains(&percent)
            {
                return Err("PCR row is outside its valid range".to_string());
            }
            if points.last().is_some_and(|(previous, _)| sinr <= *previous) {
                return Err("PCR SINR values must be strictly increasing".to_string());
            }
            points.push((sinr, percent / 100.0));
        }
        if points.is_empty() {
            return Err("PCR curve has no rows".to_string());
        }
        let mut lookup = Vec::new();
        for rows in points.windows(2) {
            let (x0, y0) = rows[0];
            let (x1, y1) = rows[1];
            let (x0, x1) = ((x0 * 100.0) as i32, (x1 * 100.0) as i32);
            let slope = (y1 - y0) / (x1 - x0) as f32;
            for x in x0..x1 {
                lookup.push((x - x0) as f32 * slope + y0);
            }
        }
        lookup.push(points.last().unwrap().1);
        Ok(Self {
            points,
            packet_size,
            table: lookup,
        })
    }

    pub fn probability(&self, sinr: f64, packet_length: usize) -> f64 {
        let sinr = sinr as f32;
        if !sinr.is_finite() || self.points.is_empty() {
            return 0.0;
        }
        if sinr < self.points[0].0 {
            return 0.0;
        }
        if sinr > self.points.last().unwrap().0 {
            return 1.0;
        }
        let index = ((sinr * 100.0) as i32 - (self.points[0].0 * 100.0) as i32).max(0) as usize;
        let probability = self.table[index.min(self.table.len() - 1)];
        f64::from(if self.packet_size == 0 {
            probability
        } else {
            f64::from(probability).powf(f64::from(packet_length as f32 / self.packet_size as f32))
                as f32
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_curve_fails_without_panicking() {
        assert!(PcrCurve::load("/path/that/does/not/exist").is_err());
    }
}

#[cfg(test)]
mod legacy_regressions {
    use super::*;
    #[test]
    fn stock_doctype_and_hundredth_db_lookup() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rfpipe-pcr.xml");
        assert!(PcrCurve::load(path.to_str().unwrap()).is_ok());
        let curve = PcrCurve {
            points: vec![(0.0, 0.0), (1.0, 1.0)],
            packet_size: 0,
            table: (0..=100).map(|i| i as f32 / 100.0).collect(),
        };
        assert_eq!(curve.probability(0.009, 100), 0.0);
        assert_eq!(curve.probability(0.01, 100), f64::from(0.01f32));
    }
}
