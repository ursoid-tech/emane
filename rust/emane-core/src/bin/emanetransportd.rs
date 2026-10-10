use emane_core::application_runtime::{consume_option, prepare, RuntimeOptions};
use emane_core::boundary_message_manager::BoundaryProtocol;
use emane_core::nem_manager::NemManager;
use emane_core::xml_parser::{parse_layer, parse_params, ParamMap};
use roxmltree::Document;
use std::collections::HashSet;
use std::env;
use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_shutdown(_: libc::c_int) {
    SHUTDOWN.store(true, Ordering::Relaxed);
}

fn install_signal_handlers() {
    unsafe {
        let handler = handle_shutdown as *const () as libc::sighandler_t;
        libc::signal(libc::SIGINT, handler);
        libc::signal(libc::SIGTERM, handler);
    }
}

fn parameter<'a>(params: &'a ParamMap, name: &str) -> Option<&'a str> {
    params.get(name)?.values.first().map(String::as_str)
}

fn run() -> Result<(), String> {
    let mut config = None;
    let args: Vec<_> = env::args().collect();
    let mut runtime_options = RuntimeOptions::default();
    let mut index = 1;
    while index < args.len() {
        if consume_option(&args, &mut index, &mut runtime_options)? {
            index += 1;
            continue;
        }
        match args[index].as_str() {
            "-h" | "--help" => {
                println!("usage: emanetransportd [OPTIONS] CONFIG_URL");
                return Ok(());
            }
            "-v" | "--version" => {
                println!("EMANE 1.2.5 (Rust Port)");
                return Ok(());
            }
            option if option.starts_with('-') => return Err(format!("unknown option {option}")),
            value => {
                if config.replace(value.to_string()).is_some() {
                    return Err("only one configuration may be supplied".to_string());
                }
            }
        }
        index += 1;
    }
    let config = config.ok_or_else(|| "missing CONFIG_URL".to_string())?;
    let config_path = Path::new(&config);
    let content = emane_plugin_api::xml_document::read(config_path)
        .map_err(|error| format!("failed to read {config}: {error}"))?;
    let document = Document::parse_with_options(
        &content,
        roxmltree::ParsingOptions {
            allow_dtd: true,
            ..Default::default()
        },
    )
    .map_err(|error| format!("failed to parse {config}: {error}"))?;
    let root = document.root_element();
    if !emane_plugin_api::xml_document::has_doctype(&content) {
        emane_core::xml_contract::validate(root, false)?;
    }
    if !root.has_tag_name("transportdaemon") {
        return Err("configuration root must be transportdaemon".to_string());
    }

    let uuid = rand::random();
    let mut manager = NemManager::new(uuid);
    let mut count = 0usize;
    let mut ids = HashSet::new();
    for instance in root
        .children()
        .filter(|node| node.is_element() && node.has_tag_name("instance"))
    {
        let id: u16 = instance
            .attribute("nemid")
            .ok_or_else(|| "transport instance missing nemid".to_string())?
            .parse()
            .map_err(|_| "transport instance has invalid nemid".to_string())?;
        if !ids.insert(id) {
            return Err(format!("duplicate transport instance nemid {id}"));
        }
        let instance_parameters = parse_params(instance).map_err(|error| error.to_string())?;
        let platform_endpoint = parameter(&instance_parameters, "platformendpoint")
            .ok_or_else(|| format!("transport instance {id} requires platformendpoint"))?;
        let transport_endpoint = parameter(&instance_parameters, "transportendpoint")
            .ok_or_else(|| format!("transport instance {id} requires transportendpoint"))?;
        let protocol = BoundaryProtocol::transport(
            parameter(&instance_parameters, "protocol").unwrap_or("udp"),
        )?;
        let transport = instance
            .children()
            .find(|node| node.is_element() && node.has_tag_name("transport"))
            .ok_or_else(|| format!("transport instance {id} has no transport layer"))?;
        let layer =
            parse_layer(config_path, transport, "transport").map_err(|error| error.to_string())?;
        let plugin = layer.plugin.as_deref().unwrap_or("virtualtransport");
        let parameters: Vec<_> = layer
            .params
            .into_iter()
            .map(|(name, values)| (name, values.values))
            .collect();
        manager
            .add_layer_configured(id, plugin, 4, &parameters)
            .map_err(|error| format!("failed to construct transport {id}: {error}"))?;
        manager.add_transport_boundary(
            id,
            transport_endpoint.to_string(),
            platform_endpoint.to_string(),
            protocol,
        )?;
        count += 1;
    }
    if count == 0 {
        return Err("configuration contains no transport instances".to_string());
    }

    prepare("emanetransportd", &runtime_options, uuid)?;
    install_signal_handlers();
    manager.start()?;
    manager.post_start();
    println!("emanetransportd started with {count} transport instance(s)");
    while !SHUTDOWN.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(100));
    }
    manager.stop();
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("emanetransportd: {error}");
            ExitCode::FAILURE
        }
    }
}
