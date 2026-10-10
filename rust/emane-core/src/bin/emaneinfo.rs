use emane_core::native_configuration::ConfigurationValue;
use emane_core::nem_manager::{
    canonical_plugin_name, component_configuration_schema, resolve_plugin_path, NemManager,
};
use emane_core::plugin_interface::{PluginApi, PluginEntryFunc, PLUGIN_ABI_VERSION};
use emane_core::statistics::{
    emane_rs_statistic_free_manifest, emane_rs_statistic_free_table_manifest,
    emane_rs_statistic_get_manifest, emane_rs_statistic_get_table_manifest,
};
use libloading::{Library, Symbol};
use roxmltree::{Document, Node};
use std::env;
use std::ffi::CStr;
use std::process::{self, ExitCode};

fn usage() {
    println!("usage: emaneinfo [OPTIONS]... <plugin>|'nemmanager'|'transportmanager'|");
    println!("                              'eventagentmanager'|'eventgeneratormanager'");
    println!();
    println!(" CONFIG_URI                    URI of XML configuration file.");
    println!();
    println!("options:");
    println!("  -h, --help                     Print this message and exit.");
    println!("  -m, --manifest                 Print manifest.");
    println!("  -v, --version                  Print version and exit.");
    println!("  -c, --configuration            Parse configuration.");
}

fn plugin_type_name(plugin_type: u32) -> &'static str {
    match plugin_type {
        1 => "mac",
        2 => "phy",
        3 => "shim",
        4 => "transport",
        _ => "unknown",
    }
}

fn load_api(plugin: &str) -> Result<(Library, *const PluginApi), String> {
    let path = resolve_plugin_path(plugin)?;
    let library = unsafe { Library::new(&path) }
        .map_err(|error| format!("failed to load {}: {error}", path.display()))?;
    let entry: Symbol<PluginEntryFunc> = unsafe { library.get(b"emane_plugin_create") }
        .map_err(|error| format!("{} has no emane_plugin_create: {error}", path.display()))?;
    let api = entry();
    if api.is_null() {
        return Err(format!("{} returned a null plugin API", path.display()));
    }
    Ok((library, api))
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn configuration_from_xml(root: Node<'_, '_>) -> Result<Vec<(String, Vec<String>)>, String> {
    emane_core::xml_parser::parse_params(root)
        .map(|params| {
            params
                .into_iter()
                .map(|(name, values)| (name, values.values))
                .collect()
        })
        .map_err(|error| error.to_string())
}

fn inspection_required_values(plugin: &str) -> Vec<(String, Vec<String>)> {
    let value = |name: &str, value: &str| (name.to_string(), vec![value.to_string()]);
    match canonical_plugin_name(plugin) {
        "emanephy" => vec![value("subid", "1")],
        "rfpipe" | "ieee80211abg" | "tdma" => {
            vec![value("pcrcurveuri", "file:///dev/null")]
        }
        "phyapitestshim" => vec![value("bandwidth", "1")],
        "bentpipe" => vec![
            value("pcrcurveuri", "file:///dev/null"),
            value("antenna.defines", "1:omni;0;0"),
            value("transponder.receive.frequency", "1:1"),
            value("transponder.receive.bandwidth", "1:1"),
            value("transponder.receive.antenna", "1:1"),
            value("transponder.receive.action", "1:process"),
            value("transponder.receive.enable", "1:off"),
            value("transponder.transmit.pcrcurveindex", "1:0"),
            value("transponder.transmit.frequency", "1:1"),
            value("transponder.transmit.bandwidth", "1:1"),
            value("transponder.transmit.antenna", "1:1"),
            value("transponder.transmit.ubend.delay", "1:na"),
            value("transponder.transmit.datarate", "1:1"),
            value("transponder.transmit.power", "1:0"),
            value("transponder.transmit.tosmap", "1:na"),
            value("transponder.transmit.slotperframe", "1:na"),
            value("transponder.transmit.slotsize", "1:na"),
            value("transponder.transmit.txslots", "1:na"),
            value("transponder.transmit.mtu", "1:1"),
            value("transponder.transmit.enable", "1:off"),
        ],
        _ => Vec::new(),
    }
}

fn type_name(value: &ConfigurationValue) -> &'static str {
    match value {
        ConfigurationValue::Int8(_) => "int8",
        ConfigurationValue::UInt8(_) => "uint8",
        ConfigurationValue::Int16(_) => "int16",
        ConfigurationValue::UInt16(_) => "uint16",
        ConfigurationValue::Int32(_) => "int32",
        ConfigurationValue::UInt32(_) => "uint32",
        ConfigurationValue::Int64(_) => "int64",
        ConfigurationValue::UInt64(_) => "uint64",
        ConfigurationValue::Float(_) => "float",
        ConfigurationValue::Double(_) => "double",
        ConfigurationValue::String(_) => "string",
        ConfigurationValue::Boolean(_) => "bool",
        ConfigurationValue::InetAddr(_) => "inetaddr",
    }
}

fn print_parameter(name: &str, spec: &emane_core::native_configuration::ParameterSchema) {
    println!(
        "      <parameter name=\"{}\" default=\"{}\" required=\"{}\" modifiable=\"{}\">",
        xml_escape(name),
        if spec.has_default { "yes" } else { "no" },
        if spec.required { "yes" } else { "no" },
        if spec.modifiable { "yes" } else { "no" }
    );
    let tag = if spec.minimum.is_some() {
        "numeric"
    } else {
        "nonnumeric"
    };
    print!("        <{tag} type=\"{}\"", type_name(&spec.prototype));
    if let (Some(min), Some(max)) = (&spec.minimum, &spec.maximum) {
        print!(" minValue=\"{}\" maxValue=\"{}\"", min.text(), max.text());
    }
    println!(">");
    println!(
        "          <values minOccurs=\"{}\" maxOccurs=\"{}\">",
        spec.min_occurs, spec.max_occurs
    );
    for value in &spec.defaults {
        println!("            <value>{}</value>", xml_escape(&value.text()));
    }
    println!("          </values>");
    if let Some(regex) = &spec.regex {
        println!("          <regex>{}</regex>", xml_escape(regex.as_str()));
    }
    println!("        </{tag}>\n      </parameter>");
}

fn statistic_type_name(value: i32) -> &'static str {
    match value {
        1 => "int8",
        2 => "uint8",
        3 => "int16",
        4 => "uint16",
        5 => "int32",
        6 => "uint32",
        7 => "int64",
        8 => "uint64",
        9 => "float",
        10 => "double",
        11 => "string",
        12 => "bool",
        13 => "inetaddr",
        _ => "unknown",
    }
}

fn print_manifest(plugin: &str, build_id: Option<u16>) {
    println!("<?xml version=\"1.0\"?>\n<manifest>");
    println!(
        "  <plugin name=\"{}\">\n    <configuration>",
        xml_escape(plugin)
    );
    for (name, spec) in component_configuration_schema(plugin) {
        print_parameter(&name, &spec);
    }
    println!("    </configuration>");
    println!("    <statistics>");
    if let Some(build_id) = build_id {
        let manifest = emane_rs_statistic_get_manifest(build_id);
        let entries = if manifest.len == 0 || manifest.data.is_null() {
            &[][..]
        } else {
            unsafe { std::slice::from_raw_parts(manifest.data, manifest.len) }
        };
        for entry in entries {
            let name = unsafe { CStr::from_ptr(entry.name) }.to_string_lossy();
            let description = unsafe { CStr::from_ptr(entry.description) }.to_string_lossy();
            println!(
                "      <element name=\"{}\" type=\"{}\" clearable=\"{}\">",
                xml_escape(&name),
                statistic_type_name(entry.any_type),
                if entry.is_clearable { "yes" } else { "no" }
            );
            if !description.is_empty() {
                println!(
                    "        <description>{}</description>",
                    xml_escape(&description)
                );
            }
            println!("      </element>");
        }
        emane_rs_statistic_free_manifest(manifest);
    }
    println!("    </statistics>");
    println!("    <statistictables>");
    if let Some(build_id) = build_id {
        let manifest = emane_rs_statistic_get_table_manifest(build_id);
        let entries = if manifest.len == 0 || manifest.data.is_null() {
            &[][..]
        } else {
            unsafe { std::slice::from_raw_parts(manifest.data, manifest.len) }
        };
        for entry in entries {
            let name = unsafe { CStr::from_ptr(entry.name) }.to_string_lossy();
            let description = unsafe { CStr::from_ptr(entry.description) }.to_string_lossy();
            println!(
                "      <table name=\"{}\" clearable=\"{}\">",
                xml_escape(&name),
                if entry.is_clearable { "yes" } else { "no" }
            );
            if !description.is_empty() {
                println!(
                    "        <description>{}</description>",
                    xml_escape(&description)
                );
            }
            println!("      </table>");
        }
        emane_rs_statistic_free_table_manifest(manifest);
    }
    println!("    </statistictables>");
    println!("  </plugin>");
    println!("</manifest>");
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    let mut configuration = false;
    let mut manifest = false;
    let mut target = None;
    for argument in &args[1..] {
        match argument.as_str() {
            "-h" | "--help" => {
                usage();
                return Ok(());
            }
            "-v" | "--version" => {
                println!("EMANE 1.2.5 (Rust Port)");
                return Ok(());
            }
            "-c" | "--configuration" => configuration = true,
            "-m" | "--manifest" => manifest = true,
            option if option.starts_with('-') => return Err(format!("unknown option: {option}")),
            value => {
                if target.replace(value.to_string()).is_some() {
                    return Err("only one plugin may be inspected".to_string());
                }
            }
        }
    }
    let target = target.ok_or_else(|| "missing plugin".to_string())?;
    let manager_names = [
        "nemmanager",
        "transportmanager",
        "eventgeneratormanager",
        "eventagentmanager",
    ];
    if !configuration && manager_names.contains(&target.as_str()) {
        if manifest {
            emane_core::event_service::configure_statistics(0);
            if target == "nemmanager" {
                emane_core::ota_manager::configure_statistics(0, 0);
            }
            print_manifest(&target, Some(0));
        }
        return Ok(());
    }

    let (plugin, declared_type, config) = if configuration {
        let content = emane_plugin_api::xml_document::read(&target)
            .map_err(|error| format!("failed to read {target}: {error}"))?;
        let document = Document::parse_with_options(
            &content,
            roxmltree::ParsingOptions {
                allow_dtd: true,
                ..Default::default()
            },
        )
        .map_err(|error| format!("failed to parse {target}: {error}"))?;
        let root = document.root_element();
        if !emane_plugin_api::xml_document::has_doctype(&content) {
            emane_core::xml_contract::validate(root, false)?;
        }
        let layer_type = root.tag_name().name().to_string();
        if !matches!(layer_type.as_str(), "mac" | "phy" | "shim" | "transport") {
            return Err(format!(
                "configuration root must be a layer, got {layer_type}"
            ));
        }
        let plugin = root
            .attribute("library")
            .or_else(|| root.attribute("plugin"))
            .unwrap_or(if layer_type == "phy" { "emanephy" } else { "" });
        if plugin.is_empty() {
            return Err(format!("{layer_type} configuration has no plugin"));
        }
        (
            plugin.to_string(),
            Some(layer_type),
            configuration_from_xml(root)?,
        )
    } else {
        (target.clone(), None, Vec::new())
    };

    let (kind, reported_name, _library) = if matches!(
        plugin.as_str(),
        "emanephy" | "virtualtransport" | "rawtransport" | "transvirtual" | "transraw"
    ) {
        let kind = if plugin == "emanephy" {
            "phy"
        } else {
            "transport"
        };
        (kind.to_string(), plugin.clone(), None)
    } else {
        let (library, api_ptr) = load_api(&plugin)?;
        let api = unsafe { &*api_ptr };
        if api.abi_version != PLUGIN_ABI_VERSION
            || api.struct_size != std::mem::size_of::<PluginApi>()
        {
            return Err(format!(
                "plugin ABI mismatch: version {}, size {}",
                api.abi_version, api.struct_size
            ));
        }
        let name = if api.name.is_null() {
            return Err(format!("plugin {plugin} returned a null name"));
        } else {
            unsafe { CStr::from_ptr(api.name) }
                .to_string_lossy()
                .into_owned()
        };
        (
            plugin_type_name(api.plugin_type).to_string(),
            name,
            Some(library),
        )
    };
    if let Some(declared_type) = declared_type {
        if declared_type != kind {
            return Err(format!(
                "configuration declares {declared_type}, but plugin reports {kind}"
            ));
        }
    }

    let mut inspection_config = config;
    if !configuration {
        for required in inspection_required_values(&reported_name) {
            if !inspection_config
                .iter()
                .any(|(name, _)| name == &required.0)
            {
                inspection_config.push(required);
            }
        }
    }
    let expected_type = match kind.as_str() {
        "mac" => 1,
        "phy" => 2,
        "shim" => 3,
        "transport" => 4,
        _ => return Err(format!("unsupported plugin type {kind}")),
    };
    let mut manager = NemManager::new([0; 16]);
    manager.add_layer_configured(1, &plugin, expected_type, &inspection_config)?;
    let build_id = manager
        .layer_build_ids(1)
        .into_iter()
        .next()
        .ok_or_else(|| "plugin did not receive a build id".to_string())?;
    if manifest {
        print_manifest(&reported_name, Some(build_id));
    }
    Ok(())
}

fn main() -> ExitCode {
    #[cfg(unix)]
    unsafe {
        // Match normal Unix command-line behavior when manifest output is
        // consumed by tools such as head(1), instead of panicking on EPIPE.
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("emaneinfo: {error}");
            process::ExitCode::FAILURE
        }
    }
}
