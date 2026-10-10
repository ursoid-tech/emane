//! Shared runtime and manifest parameter contracts, captured from the original
//! C++ registrations. The XML records the reference revision for maintenance.
use crate::native_configuration::{ConfigurationSchema, ConfigurationValue as V, ParameterSchema};
use std::collections::BTreeMap;
use std::sync::OnceLock;

pub fn get(plugin: &str) -> ConfigurationSchema {
    static SCHEMAS: OnceLock<BTreeMap<String, ConfigurationSchema>> = OnceLock::new();
    SCHEMAS
        .get_or_init(|| {
            let doc = roxmltree::Document::parse(include_str!("configuration_schema.xml"))
                .expect("checked-in configuration schema");
            doc.root_element()
                .children()
                .filter(|n| n.is_element())
                .map(|component| {
                    let schema = component
                        .children()
                        .filter(|n| n.is_element())
                        .map(|param| {
                            let data = param.children().find(|n| n.is_element()).unwrap();
                            let prototype = match data.attribute("type").unwrap() {
                                "int8" => V::Int8(0),
                                "uint8" => V::UInt8(0),
                                "int16" => V::Int16(0),
                                "uint16" => V::UInt16(0),
                                "int32" => V::Int32(0),
                                "uint32" => V::UInt32(0),
                                "int64" => V::Int64(0),
                                "uint64" => V::UInt64(0),
                                "float" => V::Float(0.0),
                                "double" => V::Double(0.0),
                                "bool" => V::Boolean(false),
                                "inetaddr" => V::InetAddr(String::new()),
                                "string" => V::String(String::new()),
                                other => panic!("unknown type {other}"),
                            };
                            let parse = |s: &str| {
                                V::parse_as(&prototype, s).expect("schema value matches type")
                            };
                            let values =
                                data.children().find(|n| n.has_tag_name("values")).unwrap();
                            let defaults = values
                                .children()
                                .filter(|n| n.has_tag_name("value"))
                                .map(|n| parse(n.text().unwrap_or("")))
                                .collect();
                            let minimum = data.attribute("minValue").map(parse);
                            let maximum = data.attribute("maxValue").map(parse);
                            let regex = data
                                .children()
                                .find(|n| n.has_tag_name("regex"))
                                .and_then(|n| n.text())
                                .map(|s| regex::Regex::new(s).expect("schema regex"));
                            (
                                param.attribute("name").unwrap().to_string(),
                                ParameterSchema {
                                    prototype,
                                    defaults,
                                    minimum,
                                    maximum,
                                    regex,
                                    min_occurs: values
                                        .attribute("minOccurs")
                                        .unwrap()
                                        .parse()
                                        .unwrap(),
                                    max_occurs: values
                                        .attribute("maxOccurs")
                                        .unwrap()
                                        .parse()
                                        .unwrap(),
                                    required: param.attribute("required") == Some("yes"),
                                    has_default: param.attribute("default") == Some("yes"),
                                    modifiable: param.attribute("modifiable") == Some("yes"),
                                },
                            )
                        })
                        .collect();
                    (component.attribute("name").unwrap().to_string(), schema)
                })
                .collect()
        })
        .get(plugin)
        .cloned()
        .unwrap_or_default()
}
