//! Native evaluator for the XSD constructs in the three original EMANE data
//! schemas. The checked-in schemas are authoritative. Unsupported constructs
//! are errors, not silently ignored extensions.
use roxmltree::Node;
fn children<'a, 'b>(node: Node<'a, 'b>, tag: &str) -> Vec<Node<'a, 'b>> {
    node.children()
        .filter(|n| n.is_element() && n.tag_name().name() == tag)
        .collect()
}
fn simple(schema: Node<'_, '_>, kind: &str, value: &str) -> Result<(), String> {
    let normalized = value.split_whitespace().collect::<Vec<_>>().join(" ");
    let v = normalized.as_str();
    let valid = match kind {
        "xs:string" | "xs:token" => true,
        "xs:unsignedShort" => {
            !v.starts_with(['+', '-']) && v.parse::<i64>().is_ok_and(|v| (0..=65535).contains(&v))
        }
        "xs:decimal" => regex::Regex::new(r"^[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)$")
            .unwrap()
            .is_match(v),
        name if name.starts_with("xs:") => return Err(format!("unsupported schema type {name}")),
        name => {
            let def = children(schema, "simpleType")
                .into_iter()
                .find(|n| n.attribute("name") == Some(name))
                .ok_or_else(|| format!("unknown schema type {name}"))?;
            let r = children(def, "restriction")
                .first()
                .copied()
                .ok_or("missing type restriction")?;
            simple(schema, r.attribute("base").ok_or("missing base")?, v)?;
            for facet in r.children().filter(|n| n.is_element()) {
                let value = facet.attribute("value").ok_or("missing facet value")?;
                let valid = match facet.tag_name().name() {
                    "pattern" => regex::Regex::new(&format!("^(?:{value})$"))
                        .map_err(|e| e.to_string())?
                        .is_match(v),
                    "minInclusive" => v
                        .parse::<f64>()
                        .ok()
                        .zip(value.parse::<f64>().ok())
                        .is_some_and(|(a, b)| a >= b),
                    "maxInclusive" => v
                        .parse::<f64>()
                        .ok()
                        .zip(value.parse::<f64>().ok())
                        .is_some_and(|(a, b)| a <= b),
                    _ => return Err("unsupported schema facet".into()),
                };
                if !valid {
                    return Err(format!("value {v} violates {name}"));
                }
            }
            true
        }
    };
    if valid {
        Ok(())
    } else {
        Err(format!("invalid {kind}: {v}"))
    }
}
fn element(
    schema: Node<'_, '_>,
    definition: Node<'_, '_>,
    node: Node<'_, '_>,
) -> Result<(), String> {
    if definition.attribute("name") != Some(node.tag_name().name())
        || node.tag_name().namespace().is_some()
    {
        return Err("schema element mismatch".into());
    }
    let complex = children(definition, "complexType")
        .first()
        .copied()
        .ok_or("unsupported schema element type")?;
    if node
        .children()
        .any(|n| n.is_text() && !n.text().unwrap_or("").trim().is_empty())
    {
        return Err("unexpected XML text".into());
    }
    let attributes = children(complex, "attribute");
    for a in node.attributes() {
        if a.namespace().is_some() {
            return Err("unexpected namespaced attribute".into());
        }
        let spec = attributes
            .iter()
            .find(|n| n.attribute("name") == Some(a.name()))
            .ok_or_else(|| format!("unknown attribute {}", a.name()))?;
        simple(
            schema,
            spec.attribute("type").ok_or("missing attribute type")?,
            a.value(),
        )?;
    }
    for a in &attributes {
        if a.attribute("use") == Some("required")
            && node.attribute(a.attribute("name").unwrap()).is_none()
        {
            return Err("missing required XML attribute".into());
        }
    }
    let input: Vec<_> = node.children().filter(|n| n.is_element()).collect();
    let mut index = 0;
    for sequence in children(complex, "sequence") {
        for def in sequence.children().filter(|n| n.is_element()) {
            if !def.has_tag_name(("http://www.w3.org/2001/XMLSchema", "element")) {
                return Err("unsupported schema compositor".into());
            }
            let min = def
                .attribute("minOccurs")
                .unwrap_or("1")
                .parse::<usize>()
                .map_err(|e| e.to_string())?;
            let max = match def.attribute("maxOccurs").unwrap_or("1") {
                "unbounded" => usize::MAX,
                s => s.parse::<usize>().map_err(|e| e.to_string())?,
            };
            let mut count = 0;
            while count < max
                && input
                    .get(index)
                    .is_some_and(|n| Some(n.tag_name().name()) == def.attribute("name"))
            {
                element(schema, def, input[index])?;
                index += 1;
                count += 1;
            }
            if count < min {
                return Err("missing required XML child".into());
            }
        }
    }
    if index != input.len() {
        return Err("unexpected XML child or order".into());
    }
    for constraint in children(definition, "unique") {
        let selector = children(constraint, "selector")[0]
            .attribute("xpath")
            .ok_or("missing selector")?;
        let field = children(constraint, "field")[0]
            .attribute("xpath")
            .and_then(|s| s.strip_prefix('@'))
            .ok_or("unsupported unique field")?;
        let mut seen = std::collections::HashSet::new();
        for n in node.children().filter(|n| n.has_tag_name(selector)) {
            if let Some(value) = n.attribute(field) {
                let key = value
                    .trim()
                    .parse::<u64>()
                    .map(|v| v.to_string())
                    .unwrap_or_else(|_| value.to_string());
                if !seen.insert(key) {
                    return Err("duplicate schema key".into());
                }
            }
        }
    }
    Ok(())
}
pub fn validate(root: Node<'_, '_>, schema: &str) -> Result<(), String> {
    let document = roxmltree::Document::parse(schema).map_err(|e| e.to_string())?;
    let schema = document.root_element();
    let def = children(schema, "element")
        .into_iter()
        .find(|n| n.attribute("name") == Some(root.tag_name().name()))
        .ok_or("unknown schema root")?;
    element(schema, def, root)
}
pub const TDMA_PCR: &str = include_str!("../schema/tdma-pcr.xsd");
pub const BENTPIPE_PCR: &str = include_str!("../schema/bentpipe-pcr.xsd");
pub const SPECTRAL_MASK: &str = include_str!("../schema/spectral-mask.xsd");
