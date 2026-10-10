//! Constraints shared by the original TDMA and Bent Pipe PCR XML schemas.
use roxmltree::Node;

fn element(node: Node<'_, '_>, attributes: &[&str], child: Option<&str>) -> Result<(), String> {
    if node.tag_name().namespace().is_some()
        || node
            .attributes()
            .any(|a| a.namespace().is_some() || !attributes.contains(&a.name()))
        || attributes
            .iter()
            .any(|name| node.attribute(*name).is_none())
        || node.children().any(|n| {
            (n.is_element() && Some(n.tag_name().name()) != child)
                || (n.is_text() && !n.text().unwrap_or("").trim().is_empty())
        })
    {
        return Err(format!("invalid PCR element {}", node.tag_name().name()));
    }
    Ok(())
}

pub fn scaled_sinr(value: &str) -> Result<i32, String> {
    use crate::numeric::LegacyParse;
    let mut scaled = value.to_string();
    if let Some(dot) = scaled.find('.') {
        let fraction = scaled.len() - dot - 1;
        if fraction > 2 {
            scaled.insert(scaled.len() - (fraction - 2), '.');
        } else {
            scaled.push_str(&"0".repeat(2 - fraction));
        }
        scaled.remove(dot);
    } else {
        scaled.push_str("00");
    }
    scaled.parse_legacy()
}

pub fn validate(root: Node<'_, '_>, table: &str, key: &str) -> Result<(), String> {
    use crate::numeric::LegacyParse;
    crate::xml_schema::validate(
        root,
        if table == "datarate" {
            crate::xml_schema::TDMA_PCR
        } else {
            crate::xml_schema::BENTPIPE_PCR
        },
    )?;
    element(root, &["packetsize"], Some(table))?;
    root.attribute("packetsize")
        .unwrap()
        .parse_legacy::<u16>()
        .map_err(|_| "invalid PCR packetsize")?;
    for curve in root.children().filter(|n| n.is_element()) {
        element(curve, &[key], Some("entry"))?;
        for entry in curve.children().filter(|n| n.is_element()) {
            element(entry, &["sinr", "por"], None)?;
            scaled_sinr(entry.attribute("sinr").unwrap())?;
            entry.attribute("por").unwrap().parse_legacy::<f32>()?;
        }
    }
    Ok(())
}
