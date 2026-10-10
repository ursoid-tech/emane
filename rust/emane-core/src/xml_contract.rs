//! Validate the standard EMANE configuration vocabulary before interpreting it.
//! DTD declarations select the strict legacy grammar. Documents without a DTD
//! retain the port's inline plugin/definition extensions.
use roxmltree::Node;

pub fn validate(root: Node<'_, '_>, strict: bool) -> Result<(), String> {
    fn check(node: Node<'_, '_>, strict: bool, root: bool) -> Result<(), String> {
        let tag = node.tag_name().name();
        let (allowed, required, children): (&[&str], &[&str], &[&str]) = match tag {
            "platform" => (&["name"], &[], &["param", "paramlist", "nem"]),
            "nem" if root => (
                &["name", "type"],
                &[],
                &["param", "shim", "transport", "mac", "phy"],
            ),
            "nem" => (
                &["name", "id", "definition", "transport"],
                &["id", "definition"],
                &["param", "shim", "transport", "mac", "phy"],
            ),
            "mac" | "shim" | "transport" | "phy" if root => (
                &["name", "library"],
                if tag == "phy" { &[] } else { &["library"] },
                &["param", "paramlist"],
            ),
            "mac" | "shim" | "transport" | "phy" => (
                &["definition", "group"],
                if tag == "phy" { &[] } else { &["definition"] },
                &["param", "paramlist"],
            ),
            "param" => (&["name", "value"], &["name", "value"], &[]),
            "paramlist" => (&["name"], &["name"], &["item"]),
            "item" => (&["value"], &["value"], &[]),
            "eventservice" => (&["name"], &[], &["param", "paramlist", "generator"]),
            "eventdaemon" => (
                &["name", "nemid"],
                &["nemid"],
                &["param", "paramlist", "agent"],
            ),
            "generator" => (&["name", "definition"], &["definition"], &[]),
            "agent" => (&["definition"], &["definition"], &[]),
            "eventagent" | "eventgenerator" => {
                (&["name", "library"], &["library"], &["param", "paramlist"])
            }
            "transportdaemon" => (&[], &[], &["param", "paramlist", "instance"]),
            "instance" => (&["nemid"], &["nemid"], &["param", "paramlist", "transport"]),
            _ => return Err(format!("unknown configuration element {tag}")),
        };
        if node.attribute("group").is_some()
            && !(tag == "transport" && node.document().root_element().has_tag_name("platform"))
        {
            return Err(format!("unexpected group attribute on {tag}"));
        }
        for attr in node.attributes() {
            let extension = !strict
                && match tag {
                    "nem" => matches!(attr.name(), "id" | "type" | "transport" | "definition"),
                    "mac" | "phy" | "transport" | "shim" => {
                        matches!(attr.name(), "plugin" | "library" | "definition")
                    }
                    _ => false,
                };
            if attr.namespace().is_some() || (!allowed.contains(&attr.name()) && !extension) {
                return Err(format!("unknown attribute {} on {tag}", attr.name()));
            }
        }
        if node.tag_name().namespace().is_some() {
            return Err(format!("unexpected namespace on {tag}"));
        }
        for &name in required {
            if node.attribute(name).is_none()
                && (strict || !matches!(name, "definition" | "library"))
            {
                return Err(format!("missing {name} on {tag}"));
            }
        }
        if tag == "nem"
            && (node
                .attribute("type")
                .is_some_and(|v| !matches!(v, "structured" | "unstructured"))
                || node
                    .attribute("transport")
                    .is_some_and(|v| !matches!(v, "internal" | "external")))
        {
            return Err("invalid NEM type or transport".into());
        }
        let mut non_parameters = false;
        let mut layer_position = 0;
        let mut elements = Vec::new();
        for child in node.children() {
            if child.is_text() && !child.text().unwrap_or("").trim().is_empty() {
                return Err(format!("unexpected text in {tag}"));
            }
            if !child.is_element() {
                continue;
            }
            let name = child.tag_name().name();
            if !children.contains(&name) {
                return Err(format!("unexpected {name} in {tag}"));
            }
            if strict {
                if matches!(name, "param" | "paramlist") {
                    if non_parameters {
                        return Err(format!("parameters must precede components in {tag}"));
                    }
                } else {
                    non_parameters = true;
                }
                if tag == "nem" {
                    let position = match name {
                        "transport" => 1,
                        "mac" => 2,
                        "phy" => 3,
                        _ => 0,
                    };
                    if position != 0 {
                        if position <= layer_position {
                            return Err("invalid NEM layer order".into());
                        }
                        layer_position = position;
                    }
                }
            }
            elements.push(name);
            check(child, strict, false)?;
        }
        if (tag == "paramlist" && elements.is_empty())
            || (strict && tag == "platform" && !elements.contains(&"nem"))
            || (strict && tag == "transportdaemon" && !elements.contains(&"instance"))
            || (tag == "instance" && elements.iter().filter(|&&n| n == "transport").count() != 1)
        {
            return Err(format!("missing required child of {tag}"));
        }
        Ok(())
    }
    check(root, strict, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unknown_attributes_children_missing_values_and_bad_order() {
        for xml in [
            "<nem unsupported='yes'/>",
            "<platform><ignored/></platform>",
            "<phy><param name='subid'/></phy>",
            "<phy><paramlist name='frequencyofinterest'/></phy>",
            "<nem><phy/><mac definition='mac.xml'/></nem>",
            "<nem type='other'/>",
            "<platform><nem id='1'/></platform>",
        ] {
            let doc = roxmltree::Document::parse(xml).unwrap();
            assert!(validate(doc.root_element(), true).is_err(), "{xml}");
        }
        for xml in [
            "<nem><transport definition='transport.xml'/><shim definition='shim.xml'/><mac definition='mac.xml'/><phy/></nem>",
            "<phy><paramlist name='frequencyofinterest'><item value='0'/><item value='1G'/></paramlist></phy>",
            "<platform><nem id='1' definition='nem.xml' transport='external'/></platform>",
        ] {
            let doc = roxmltree::Document::parse(xml).unwrap();
            validate(doc.root_element(), true).unwrap();
        }
    }
}
