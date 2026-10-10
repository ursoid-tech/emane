pub struct PCREntry {
    pub sinr: f32,
    pub por: f32,
}

pub struct PCRManager {
    pcr_entry_vector: Vec<PCREntry>,
    por_vector: Vec<f32>,
    table_packet_size: u32,
    precision_factor: i32,
}

impl Default for PCRManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PCRManager {
    pub fn new() -> Self {
        Self {
            pcr_entry_vector: Vec::new(),
            por_vector: Vec::new(),
            table_packet_size: 0,
            precision_factor: 100,
        }
    }

    pub fn load(&mut self, uri: &str) -> Result<(), String> {
        let content = emane_plugin_api::xml_document::read(uri)
            .map_err(|e| format!("Failed to read file: {}", e))?;
        let doc = roxmltree::Document::parse_with_options(
            &content,
            roxmltree::ParsingOptions {
                allow_dtd: true,
                ..Default::default()
            },
        )
        .map_err(|e| format!("Failed to parse XML: {}", e))?;

        self.pcr_entry_vector.clear();
        self.por_vector.clear();

        for node in doc.descendants() {
            if node.has_tag_name("pcr") {
                for child in node.children() {
                    if child.has_tag_name("table") {
                        if let Some(pkt_size) = child.attribute("pktsize") {
                            self.table_packet_size = pkt_size.parse().unwrap_or(0);
                        }

                        for row in child.children() {
                            if row.has_tag_name("row") {
                                let sinr: f32 =
                                    row.attribute("sinr").unwrap_or("0").parse().unwrap_or(0.0);
                                let por_percent: f32 =
                                    row.attribute("por").unwrap_or("0").parse().unwrap_or(0.0);
                                let por = por_percent / 100.0;

                                if let Some(last) = self.pcr_entry_vector.last() {
                                    if sinr == last.sinr {
                                        return Err(format!("Duplicate sinr value {}", sinr));
                                    } else if sinr < last.sinr {
                                        return Err(format!("Out of order sinr value {}", sinr));
                                    }
                                }

                                self.pcr_entry_vector.push(PCREntry { sinr, por });
                            }
                        }
                    }
                }
            }
        }

        if self.pcr_entry_vector.is_empty() {
            return Err("Need at least 1 point to define a pcr curve".to_string());
        }

        self.interpolate();
        Ok(())
    }

    fn interpolate(&mut self) {
        for i in 0..self.pcr_entry_vector.len() - 1 {
            let x1 = (self.pcr_entry_vector[i].sinr * self.precision_factor as f32) as i32;
            let y1 = self.pcr_entry_vector[i].por;
            let x2 = (self.pcr_entry_vector[i + 1].sinr * self.precision_factor as f32) as i32;
            let y2 = self.pcr_entry_vector[i + 1].por;

            let slope = (y2 - y1) / (x2 - x1) as f32;

            for dx in x1..x2 {
                self.por_vector.push(((dx - x1) as f32) * slope + y1);
            }
        }

        self.por_vector
            .push(self.pcr_entry_vector.last().unwrap().por);
    }

    pub fn get_pcr(&self, sinr: f32, packet_len: usize) -> f32 {
        if self.pcr_entry_vector.is_empty() {
            return 0.0;
        }

        let first = self.pcr_entry_vector.first().unwrap();
        let last = self.pcr_entry_vector.last().unwrap();

        if sinr < first.sinr {
            return 0.0;
        } else if sinr > last.sinr {
            return 1.0;
        }

        let mut por = if first.sinr == last.sinr {
            first.por
        } else {
            let sinr_scaled = (sinr * self.precision_factor as f32) as i32;
            let sinr_offset = (first.sinr * self.precision_factor as f32) as i32;

            let mut idx = (sinr_scaled - sinr_offset) as usize;
            if idx >= self.por_vector.len() {
                idx = self.por_vector.len() - 1;
            }

            self.por_vector[idx]
        };

        if self.table_packet_size > 0 {
            por = por.powf(packet_len as f32 / self.table_packet_size as f32);
        }

        por
    }
}
