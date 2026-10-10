use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};

pub const TYPE_INT64: i32 = 7;
pub const TYPE_UINT64: i32 = 8;
pub const TYPE_DOUBLE: i32 = 10;
pub const TYPE_STRING: i32 = 11;
pub const TYPE_BOOLEAN: i32 = 12;
pub const TYPE_INETADDR: i32 = 13;

#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub enum ConfigurationValue {
    Int8(i8),
    UInt8(u8),
    Int16(i16),
    UInt16(u16),
    Int32(i32),
    UInt32(u32),
    Int64(i64),
    UInt64(u64),
    Float(f32),
    Double(f64),
    String(String),
    Boolean(bool),
    InetAddr(String),
}

impl ConfigurationValue {
    pub fn any_type(&self) -> i32 {
        match self {
            Self::Int8(_) => 1,
            Self::UInt8(_) => 2,
            Self::Int16(_) => 3,
            Self::UInt16(_) => 4,
            Self::Int32(_) => 5,
            Self::UInt32(_) => 6,
            Self::Int64(_) => TYPE_INT64,
            Self::UInt64(_) => TYPE_UINT64,
            Self::Float(_) => 9,
            Self::Double(_) => TYPE_DOUBLE,
            Self::String(_) => TYPE_STRING,
            Self::Boolean(_) => TYPE_BOOLEAN,
            Self::InetAddr(_) => TYPE_INETADDR,
        }
    }

    pub fn text(&self) -> String {
        match self {
            Self::Int8(value) => value.to_string(),
            Self::UInt8(value) => value.to_string(),
            Self::Int16(value) => value.to_string(),
            Self::UInt16(value) => value.to_string(),
            Self::Int32(value) => value.to_string(),
            Self::UInt32(value) => value.to_string(),
            Self::Int64(value) => value.to_string(),
            Self::UInt64(value) => value.to_string(),
            Self::Float(value) => value.to_string(),
            Self::Double(value) => value.to_string(),
            Self::String(value) | Self::InetAddr(value) => value.clone(),
            Self::Boolean(value) => value.to_string(),
        }
    }

    pub fn parse_as(prototype: &Self, value: &str) -> Option<Self> {
        use emane_plugin_api::numeric::LegacyParse;
        match prototype {
            Self::Int8(_) => value.parse_legacy::<i8>().ok().map(Self::Int8),
            Self::UInt8(_) => value.parse_legacy::<u8>().ok().map(Self::UInt8),
            Self::Int16(_) => value.parse_legacy::<i16>().ok().map(Self::Int16),
            Self::UInt16(_) => value.parse_legacy::<u16>().ok().map(Self::UInt16),
            Self::Int32(_) => value.parse_legacy::<i32>().ok().map(Self::Int32),
            Self::UInt32(_) => value.parse_legacy::<u32>().ok().map(Self::UInt32),
            Self::Int64(_) => value.parse_legacy::<i64>().ok().map(Self::Int64),
            Self::UInt64(_) => value.parse_legacy::<u64>().ok().map(Self::UInt64),
            Self::Float(_) => value
                .parse_legacy::<f32>()
                .ok()
                .filter(|v| v.is_finite())
                .map(Self::Float),
            Self::Double(_) => value
                .parse_legacy::<f64>()
                .ok()
                .filter(|v| v.is_finite())
                .map(Self::Double),
            Self::String(_) => Some(Self::String(value.to_string())),
            Self::Boolean(_) => match value.to_ascii_lowercase().as_str() {
                "true" | "on" | "yes" | "1" => Some(Self::Boolean(true)),
                "false" | "off" | "no" | "0" => Some(Self::Boolean(false)),
                _ => None,
            },
            Self::InetAddr(_) => Some(Self::InetAddr(value.to_string())),
        }
    }

    pub fn infer(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "true" | "on" | "yes" => return Self::Boolean(true),
            "false" | "off" | "no" => return Self::Boolean(false),
            _ => {}
        }
        if value.parse::<IpAddr>().is_ok()
            || value
                .rsplit_once(':')
                .is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok())
        {
            return Self::InetAddr(value.to_string());
        }
        if let Ok(value) = value.parse::<u64>() {
            return Self::UInt64(value);
        }
        if let Ok(value) = value.parse::<i64>() {
            return Self::Int64(value);
        }
        if let Ok(value) = value.parse::<f64>() {
            if value.is_finite() {
                return Self::Double(value);
            }
        }
        Self::String(value.to_string())
    }
}

pub type ConfigurationUpdate = Vec<(String, Vec<ConfigurationValue>)>;
type UpdateHandler = Arc<dyn Fn(&ConfigurationUpdate) -> Result<(), String> + Send + Sync>;

#[derive(Clone)]
pub struct ParameterSchema {
    pub prototype: ConfigurationValue,
    pub min_occurs: usize,
    pub max_occurs: usize,
    pub required: bool,
    pub has_default: bool,
    pub modifiable: bool,
    pub defaults: Vec<ConfigurationValue>,
    pub minimum: Option<ConfigurationValue>,
    pub maximum: Option<ConfigurationValue>,
    pub regex: Option<regex::Regex>,
}
impl ParameterSchema {
    pub fn scalar(prototype: ConfigurationValue) -> Self {
        Self {
            prototype,
            min_occurs: 1,
            max_occurs: 1,
            required: false,
            has_default: false,
            modifiable: false,
            defaults: Vec::new(),
            minimum: None,
            maximum: None,
            regex: None,
        }
    }
    pub fn validate(&self, values: &[ConfigurationValue]) -> bool {
        (self.min_occurs..=self.max_occurs).contains(&values.len())
            && values.iter().all(|value| {
                value.any_type() == self.prototype.any_type()
                    && !matches!(value, ConfigurationValue::Float(v) if !v.is_finite())
                    && !matches!(value, ConfigurationValue::Double(v) if !v.is_finite())
                    && self.minimum.as_ref().is_none_or(|min| value >= min)
                    && self.maximum.as_ref().is_none_or(|max| value <= max)
                    && self
                        .regex
                        .as_ref()
                        .is_none_or(|regex| regex.is_match(&value.text()))
            })
    }
}
pub type ConfigurationSchema = BTreeMap<String, ParameterSchema>;

pub fn parse_initial(
    schema: &ConfigurationSchema,
    initial: &[(String, Vec<String>)],
) -> Result<ConfigurationUpdate, String> {
    for (name, spec) in schema {
        if spec.required && !initial.iter().any(|(key, _)| key == name) {
            return Err(format!(
                "required configuration parameter {name} is missing"
            ));
        }
    }
    let mut seen = HashSet::new();
    initial
        .iter()
        .map(|(name, values)| {
            if !seen.insert(name) {
                return Err(format!("duplicate configuration parameter {name}"));
            }
            let Some(spec) = schema.get(name) else {
                if schema.is_empty() {
                    return Ok((
                        name.clone(),
                        values
                            .iter()
                            .map(|s| ConfigurationValue::infer(s))
                            .collect(),
                    ));
                }
                return Err(format!("unknown configuration parameter {name}"));
            };
            if !(spec.min_occurs..=spec.max_occurs).contains(&values.len()) {
                return Err(format!("invalid value count for parameter {name}"));
            }
            let values = values
                .iter()
                .map(|value| {
                    ConfigurationValue::parse_as(&spec.prototype, value)
                        .ok_or_else(|| format!("invalid value for parameter {name}: {value}"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            if !spec.validate(&values) {
                return Err(format!("value outside constraints for parameter {name}"));
            }
            Ok((name.clone(), values))
        })
        .collect()
}

struct ComponentConfiguration {
    schema: ConfigurationSchema,
    values: BTreeMap<String, Vec<ConfigurationValue>>,
    modifiable: HashSet<String>,
    update: UpdateHandler,
    update_lock: Arc<Mutex<()>>,
}

fn registry() -> &'static Mutex<HashMap<u16, ComponentConfiguration>> {
    static REGISTRY: OnceLock<Mutex<HashMap<u16, ComponentConfiguration>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn register<F>(
    build_id: u16,
    initial: &[(String, Vec<String>)],
    update: F,
) -> Result<(), String>
where
    F: Fn(&ConfigurationUpdate) -> Result<(), String> + Send + Sync + 'static,
{
    let values = initial
        .iter()
        .map(|(name, values)| {
            (
                name.clone(),
                values
                    .iter()
                    .map(|value| ConfigurationValue::infer(value))
                    .collect(),
            )
        })
        .collect();
    let modifiable = initial.iter().map(|(name, _)| name.clone()).collect();
    let mut registry = registry()
        .lock()
        .map_err(|_| "configuration registry lock poisoned".to_string())?;
    if registry
        .insert(
            build_id,
            ComponentConfiguration {
                schema: ConfigurationSchema::new(),
                values,
                modifiable,
                update: Arc::new(update),
                update_lock: Arc::new(Mutex::new(())),
            },
        )
        .is_some()
    {
        return Err(format!(
            "configuration build id {build_id} is already registered"
        ));
    }
    Ok(())
}

pub fn register_with_defaults<F>(
    build_id: u16,
    defaults: ConfigurationUpdate,
    initial: &[(String, Vec<String>)],
    modifiable: &[String],
    update: F,
) -> Result<(), String>
where
    F: Fn(&ConfigurationUpdate) -> Result<(), String> + Send + Sync + 'static,
{
    let schema = defaults
        .iter()
        .map(|(name, values)| {
            (
                name.clone(),
                ParameterSchema::scalar(
                    values
                        .first()
                        .cloned()
                        .unwrap_or_else(|| ConfigurationValue::String(String::new())),
                ),
            )
        })
        .collect();
    register_with_schema(build_id, defaults, schema, initial, modifiable, update)
}

pub fn register_with_schema<F>(
    build_id: u16,
    defaults: ConfigurationUpdate,
    schema: ConfigurationSchema,
    initial: &[(String, Vec<String>)],
    modifiable: &[String],
    update: F,
) -> Result<(), String>
where
    F: Fn(&ConfigurationUpdate) -> Result<(), String> + Send + Sync + 'static,
{
    let mut values = defaults.into_iter().collect::<BTreeMap<_, _>>();
    values.extend(parse_initial(&schema, initial)?);
    let mut registry = registry()
        .lock()
        .map_err(|_| "configuration registry lock poisoned".to_string())?;
    if registry
        .insert(
            build_id,
            ComponentConfiguration {
                schema,
                values,
                modifiable: modifiable.iter().cloned().collect(),
                update: Arc::new(update),
                update_lock: Arc::new(Mutex::new(())),
            },
        )
        .is_some()
    {
        return Err(format!(
            "configuration build id {build_id} is already registered"
        ));
    }
    Ok(())
}

pub fn unregister(build_id: u16) {
    if let Ok(mut registry) = registry().lock() {
        registry.remove(&build_id);
    }
}

pub fn query(
    build_id: u16,
    names: &[String],
) -> Result<Vec<(String, Vec<ConfigurationValue>)>, String> {
    let registry = registry()
        .lock()
        .map_err(|_| "configuration registry lock poisoned".to_string())?;
    let component = registry
        .get(&build_id)
        .ok_or_else(|| format!("unknown configuration build id {build_id}"))?;
    if names.is_empty() {
        return Ok(component
            .values
            .iter()
            .map(|(name, values)| (name.clone(), values.clone()))
            .collect());
    }
    names
        .iter()
        .map(|name| {
            component
                .values
                .get(name)
                .cloned()
                .map(|values| (name.clone(), values))
                .ok_or_else(|| format!("unknown configuration parameter {name}"))
        })
        .collect()
}

pub fn update(build_id: u16, updates: ConfigurationUpdate) -> Result<(), String> {
    let update_lock = {
        let registry = registry()
            .lock()
            .map_err(|_| "configuration registry lock poisoned".to_string())?;
        Arc::clone(
            &registry
                .get(&build_id)
                .ok_or_else(|| format!("unknown configuration build id {build_id}"))?
                .update_lock,
        )
    };
    let _update_guard = update_lock
        .lock()
        .map_err(|_| "configuration update lock poisoned".to_string())?;
    let (handler, rollback) = {
        let registry = registry()
            .lock()
            .map_err(|_| "configuration registry lock poisoned".to_string())?;
        let component = registry
            .get(&build_id)
            .ok_or_else(|| format!("unknown configuration build id {build_id}"))?;
        let mut seen = HashSet::new();
        let mut rollback = Vec::with_capacity(updates.len());
        for (name, values) in &updates {
            if !seen.insert(name) {
                return Err(format!("duplicate configuration parameter {name}"));
            }
            if !component.modifiable.contains(name) {
                return Err(format!("configuration parameter {name} is not modifiable"));
            }
            let current = component
                .values
                .get(name)
                .ok_or_else(|| format!("unknown configuration parameter {name}"))?;
            if let Some(spec) = component.schema.get(name) {
                if !spec.validate(values) {
                    return Err(format!("invalid value type or count for parameter {name}"));
                }
            }
            let expected_type = current
                .first()
                .map(ConfigurationValue::any_type)
                .or_else(|| values.first().map(ConfigurationValue::any_type));
            if (values.is_empty() && !component.schema.contains_key(name))
                || expected_type
                    .is_some_and(|expected| values.iter().any(|value| value.any_type() != expected))
            {
                return Err(format!("invalid value type or count for parameter {name}"));
            }
            rollback.push((name.clone(), current.clone()));
        }
        (Arc::clone(&component.update), rollback)
    };
    if let Err(error) = handler(&updates) {
        return match handler(&rollback) {
            Ok(()) => Err(error),
            Err(rollback_error) => Err(format!(
                "{error}; failed to restore the previous configuration: {rollback_error}"
            )),
        };
    }
    let mut registry = registry()
        .lock()
        .map_err(|_| "configuration registry lock poisoned".to_string())?;
    let component = registry
        .get_mut(&build_id)
        .ok_or_else(|| format!("configuration build id {build_id} was removed during update"))?;
    for (name, values) in updates {
        component.values.insert(name, values);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_id_service::emane_rs_buildid_assign;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn native_configuration_queries_and_applies_updates() {
        static CALLS: AtomicUsize = AtomicUsize::new(0);
        let build_id = emane_rs_buildid_assign();
        register(
            build_id,
            &[("enabled".to_string(), vec!["true".to_string()])],
            |_| {
                CALLS.fetch_add(1, Ordering::Relaxed);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            query(build_id, &[]).unwrap()[0].1,
            vec![ConfigurationValue::Boolean(true)]
        );
        update(
            build_id,
            vec![(
                "enabled".to_string(),
                vec![ConfigurationValue::Boolean(false)],
            )],
        )
        .unwrap();
        assert_eq!(CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(
            query(build_id, &[]).unwrap()[0].1,
            vec![ConfigurationValue::Boolean(false)]
        );
        unregister(build_id);
    }

    #[test]
    fn rejected_multi_parameter_update_restores_component_state() {
        let build_id = emane_rs_buildid_assign();
        let component_state = Arc::new(Mutex::new((true, true)));
        let callback_state = Arc::clone(&component_state);
        register(
            build_id,
            &[
                ("first".to_string(), vec!["true".to_string()]),
                ("second".to_string(), vec!["true".to_string()]),
            ],
            move |updates| {
                let mut state = callback_state.lock().unwrap();
                for (name, values) in updates {
                    let ConfigurationValue::Boolean(value) = values[0] else {
                        return Err("wrong type".to_string());
                    };
                    match name.as_str() {
                        "first" => state.0 = value,
                        "second" if value => state.1 = value,
                        "second" => return Err("second cannot be false".to_string()),
                        _ => return Err("unknown parameter".to_string()),
                    }
                }
                Ok(())
            },
        )
        .unwrap();

        let result = update(
            build_id,
            vec![
                (
                    "first".to_string(),
                    vec![ConfigurationValue::Boolean(false)],
                ),
                (
                    "second".to_string(),
                    vec![ConfigurationValue::Boolean(false)],
                ),
            ],
        );
        assert!(result.is_err());
        assert_eq!(*component_state.lock().unwrap(), (true, true));
        assert_eq!(
            query(build_id, &[]).unwrap(),
            vec![
                ("first".to_string(), vec![ConfigurationValue::Boolean(true)]),
                (
                    "second".to_string(),
                    vec![ConfigurationValue::Boolean(true)]
                ),
            ]
        );
        unregister(build_id);
    }
}
