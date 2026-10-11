use emane_core::agents::gpsdlocation::GpsdLocationAgent;
use emane_core::application_runtime::{consume_option, prepare, RuntimeOptions};
use emane_core::event_service::{
    emane_rs_event_service_mcast_close, emane_rs_event_service_mcast_open,
    emane_rs_event_service_process_loop, emane_rs_event_service_register_event,
    register_native_user, unregister_user,
};
use emane_core::generators::eel::native::NativeEelGenerator;
use emane_core::protobufs::emane_message::LocationEvent;
use prost::Message;
use roxmltree::Document;
use std::collections::HashMap;
use std::env;
use std::ffi::{c_void, CString};
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_shutdown(_: libc::c_int) {
    SHUTDOWN.store(true, Ordering::Relaxed);
}

// Original Application::Main handles INT and QUIT; TERM retains its default action.
fn install_signal_handlers() {
    unsafe {
        let handler = handle_shutdown as *const () as libc::sighandler_t;
        libc::signal(libc::SIGINT, handler);
        libc::signal(libc::SIGQUIT, handler);
    }
}

fn parameters(node: roxmltree::Node<'_, '_>) -> HashMap<String, Vec<String>> {
    let mut result = HashMap::new();
    for parameter in node.children().filter(|child| child.is_element()) {
        match parameter.tag_name().name() {
            "param" => {
                if let (Some(name), Some(value)) =
                    (parameter.attribute("name"), parameter.attribute("value"))
                {
                    result
                        .entry(name.to_string())
                        .or_insert_with(Vec::new)
                        .push(value.to_string());
                }
            }
            "paramlist" => {
                if let Some(name) = parameter.attribute("name") {
                    let values = result.entry(name.to_string()).or_insert_with(Vec::new);
                    for item in parameter.children().filter(|child| child.is_element()) {
                        if let Some(value) = item.attribute("value") {
                            values.push(value.to_string());
                        }
                    }
                }
            }
            _ => {}
        }
    }
    result
}

fn single<'a>(params: &'a HashMap<String, Vec<String>>, name: &str) -> Option<&'a str> {
    params.get(name)?.first().map(String::as_str)
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "on" | "true" | "yes" => Some(true),
        "0" | "off" | "false" | "no" => Some(false),
        _ => None,
    }
}

fn instance_uuid() -> [u8; 16] {
    let mut uuid = [0u8; 16];
    if let Ok(value) = fs::read_to_string("/proc/sys/kernel/random/uuid") {
        let bytes: Vec<_> = value.trim().bytes().filter(|byte| *byte != b'-').collect();
        if bytes.len() == 32 {
            for (index, pair) in bytes.chunks_exact(2).enumerate() {
                if let Ok(text) = std::str::from_utf8(pair) {
                    if let Ok(value) = u8::from_str_radix(text, 16) {
                        uuid[index] = value;
                    }
                }
            }
            if uuid != [0; 16] {
                return uuid;
            }
        }
    }
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .to_be_bytes();
    uuid.copy_from_slice(&time);
    uuid[0..4]
        .iter_mut()
        .zip(std::process::id().to_be_bytes())
        .for_each(|(target, value)| *target ^= value);
    uuid
}

fn open_event_network(
    params: &HashMap<String, Vec<String>>,
    uuid: &[u8; 16],
) -> Result<(), String> {
    let group = single(params, "eventservicegroup")
        .ok_or_else(|| "eventservicegroup is required".to_string())?;
    let device = single(params, "eventservicedevice").unwrap_or("");
    let ttl = single(params, "eventservicettl")
        .unwrap_or("1")
        .parse::<i32>()
        .map_err(|_| "invalid eventservicettl".to_string())?;
    let loopback = match single(params, "eventserviceloopback") {
        Some(value) => {
            parse_bool(value).ok_or_else(|| "invalid eventserviceloopback".to_string())?
        }
        None => true,
    };
    let group = CString::new(group).map_err(|_| "eventservicegroup contains NUL".to_string())?;
    let device = CString::new(device).map_err(|_| "eventservicedevice contains NUL".to_string())?;
    if !emane_rs_event_service_mcast_open(
        group.as_ptr(),
        device.as_ptr(),
        ttl,
        loopback,
        uuid.as_ptr(),
    ) {
        return Err("failed to open event service multicast socket".to_string());
    }
    Ok(())
}

struct EventNetworkGuard;

impl Drop for EventNetworkGuard {
    fn drop(&mut self) {
        emane_rs_event_service_mcast_close();
    }
}

struct AgentRuntime {
    agents: Vec<Arc<Mutex<GpsdLocationAgent>>>,
    build_ids: Vec<u16>,
}

impl Drop for AgentRuntime {
    fn drop(&mut self) {
        for build_id in self.build_ids.drain(..) {
            unregister_user(build_id);
        }
        for agent in &self.agents {
            if let Ok(mut agent) = agent.lock() {
                agent.stop();
            }
        }
    }
}

fn load_definition(
    path: &Path,
    expected_root: &str,
) -> Result<(String, HashMap<String, Vec<String>>), String> {
    let content = emane_plugin_api::xml_document::read(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let document = Document::parse_with_options(
        &content,
        roxmltree::ParsingOptions {
            allow_dtd: true,
            ..Default::default()
        },
    )
    .map_err(|error| format!("failed to parse {}: {error}", path.display()))?;
    let root = document.root_element();
    if !emane_plugin_api::xml_document::has_doctype(&content) {
        emane_core::xml_contract::validate(root, false)?;
    }
    if root.tag_name().name() != expected_root {
        return Err(format!("{} root must be {expected_root}", path.display()));
    }
    let library = root
        .attribute("library")
        .ok_or_else(|| format!("{} is missing library", path.display()))?
        .to_string();
    Ok((library, parameters(root)))
}

fn run_generators(
    root: roxmltree::Node<'_, '_>,
    config_path: &Path,
    uuid: [u8; 16],
) -> Result<(), String> {
    open_event_network(&parameters(root), &uuid)?;
    let _network = EventNetworkGuard;
    let stop = Arc::new(AtomicBool::new(false));
    let mut generators = Vec::new();
    for component in root
        .children()
        .filter(|node| node.is_element() && node.has_tag_name("generator"))
    {
        let definition = component
            .attribute("definition")
            .ok_or_else(|| "generator is missing definition".to_string())?;
        let definition_path = config_path
            .parent()
            .unwrap_or(Path::new(""))
            .join(definition);
        let (library, params) = load_definition(&definition_path, "eventgenerator")?;
        if library != "eelgenerator" && library != "emanegeneel" {
            return Err(format!("unsupported event generator {library}"));
        }
        if let Some(name) = params
            .keys()
            .find(|name| !matches!(name.as_str(), "inputfile" | "loader"))
        {
            return Err(format!("EEL generator has unknown parameter {name}"));
        }
        for required in ["inputfile", "loader"] {
            let count = params.get(required).map_or(0, Vec::len);
            if !(1..=1024).contains(&count) {
                return Err(format!(
                    "EEL generator parameter {required} requires 1 through 1024 values"
                ));
            }
        }
        let base = definition_path.parent().unwrap_or(Path::new(""));
        let inputs = params
            .get("inputfile")
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|input| {
                let input_path = Path::new(&input);
                if input_path.is_absolute() {
                    input
                } else {
                    base.join(input_path).to_string_lossy().into_owned()
                }
            })
            .collect();
        let loaders = params.get("loader").cloned().unwrap_or_default();
        generators.push(NativeEelGenerator::new(inputs, loaders)?);
    }
    let (sender, receiver) = mpsc::channel();
    let mut handles = Vec::with_capacity(generators.len());
    for generator in generators {
        let generator_stop = Arc::clone(&stop);
        let result_sender = sender.clone();
        handles.push(thread::spawn(move || {
            let _ = result_sender.send(generator.run(generator_stop));
        }));
    }
    drop(sender);
    while !SHUTDOWN.load(Ordering::Relaxed) {
        match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(Err(error)) => {
                stop.store(true, Ordering::Relaxed);
                for handle in handles {
                    let _ = handle.join();
                }
                return Err(error);
            }
            Ok(Ok(())) | Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
    stop.store(true, Ordering::Relaxed);
    for handle in handles {
        let _ = handle.join();
    }
    Ok(())
}

extern "C" fn gps_location_event(context: *mut c_void, event_id: u16, data: *const u8, len: usize) {
    if context.is_null() || event_id != 100 || (len != 0 && data.is_null()) {
        return;
    }
    let bytes = if len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(data, len) }
    };
    let Ok(event) = LocationEvent::decode(bytes) else {
        return;
    };
    let agent = unsafe { &*(context as *const Mutex<GpsdLocationAgent>) };
    let Ok(mut agent) = agent.lock() else { return };
    if let Some(location) = event
        .locations
        .into_iter()
        .find(|location| location.nem_id == u32::from(agent.nem_id()))
    {
        let position = location.position;
        let velocity = location.velocity.map(|velocity| {
            (
                velocity.azimuth_degrees,
                velocity.magnitude_meters_per_second,
            )
        });
        agent.update_location(
            position.latitude_degrees,
            position.longitude_degrees,
            position.altitude_meters,
            velocity,
        );
    }
}

fn run_agents(
    root: roxmltree::Node<'_, '_>,
    config_path: &Path,
    uuid: [u8; 16],
) -> Result<(), String> {
    let nem_id = root
        .attribute("nemid")
        .ok_or_else(|| "eventdaemon is missing nemid".to_string())?
        .parse::<u16>()
        .map_err(|_| "invalid eventdaemon nemid".to_string())?;
    open_event_network(&parameters(root), &uuid)?;
    let _network = EventNetworkGuard;
    let mut runtime = AgentRuntime {
        agents: Vec::new(),
        build_ids: Vec::new(),
    };
    for (index, component) in root
        .children()
        .filter(|node| node.is_element() && node.has_tag_name("agent"))
        .enumerate()
    {
        let definition = component
            .attribute("definition")
            .ok_or_else(|| "agent is missing definition".to_string())?;
        let definition_path = config_path
            .parent()
            .unwrap_or(Path::new(""))
            .join(definition);
        let (library, params) = load_definition(&definition_path, "eventagent")?;
        if library != "gpsdlocationagent" {
            return Err(format!("unsupported event agent {library}"));
        }
        let pseudo_terminal = single(&params, "pseudoterminalfile").unwrap_or("/tmp/gps.pty");
        let agent = Arc::new(Mutex::new(GpsdLocationAgent::new(nem_id)));
        agent.lock().unwrap().start(pseudo_terminal)?;
        let build_id = 50_000u16
            .checked_add(u16::try_from(index).map_err(|_| "too many agents".to_string())?)
            .ok_or_else(|| "too many agents".to_string())?;
        register_native_user(
            build_id,
            nem_id,
            Arc::as_ptr(&agent) as *mut Mutex<GpsdLocationAgent> as *mut c_void,
            gps_location_event,
        );
        runtime.build_ids.push(build_id);
        if !emane_rs_event_service_register_event(build_id, 100) {
            return Err("failed to register GPSD agent for Location events".to_string());
        }
        runtime.agents.push(agent);
    }
    let receive_uuid = uuid;
    let receiver =
        thread::spawn(move || emane_rs_event_service_process_loop(receive_uuid.as_ptr()));
    while !SHUTDOWN.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_secs(1));
        if SHUTDOWN.load(Ordering::Relaxed) {
            break;
        }
        for agent in &runtime.agents {
            agent.lock().unwrap().process_timed_event();
        }
    }
    emane_rs_event_service_mcast_close();
    let _ = receiver.join();
    Ok(())
}

fn parse_start_time(value: &str) -> Result<u64, String> {
    let fields: Vec<_> = value.split(':').collect();
    if fields.len() != 3 {
        return Err("--starttime must use HH:MM:SS".to_string());
    }
    let hour: u64 = fields[0]
        .parse()
        .map_err(|_| "invalid start hour".to_string())?;
    let minute: u64 = fields[1]
        .parse()
        .map_err(|_| "invalid start minute".to_string())?;
    let second: u64 = fields[2]
        .parse()
        .map_err(|_| "invalid start second".to_string())?;
    if hour > 23 || minute > 59 || second > 59 {
        return Err("--starttime is outside 00:00:00..23:59:59".to_string());
    }
    Ok(hour * 3600 + minute * 60 + second)
}

pub fn run_event_application(expected_root: &str, component_tag: &str) -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    let mut config = None;
    let mut start_time = None;
    let mut next_day = false;
    let mut runtime_options = RuntimeOptions::default();
    let mut index = 1;
    while index < args.len() {
        if consume_option(&args, &mut index, &mut runtime_options)? {
            index += 1;
            continue;
        }
        match args[index].as_str() {
            "-h" | "--help" => {
                println!("usage: {} [OPTIONS] CONFIG_URL", args[0]);
                return Ok(());
            }
            "-v" | "--version" => {
                println!("EMANE 1.2.5 (Rust Port)");
                return Ok(());
            }
            "-s" | "--starttime" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--starttime requires a value".to_string())?;
                start_time = Some(parse_start_time(value)?);
            }
            "-n" | "--nextday" => next_day = true,
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
    let path = Path::new(&config);
    let content = emane_plugin_api::xml_document::read(path)
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
    if root.tag_name().name() != expected_root {
        return Err(format!("configuration root must be {expected_root}"));
    }
    let mut component_count = 0;
    for component in root
        .children()
        .filter(|node| node.is_element() && node.tag_name().name() == component_tag)
    {
        if let Some(definition) = component.attribute("definition") {
            let definition_path = path.parent().unwrap_or(Path::new("")).join(definition);
            let definition_content = emane_plugin_api::xml_document::read(&definition_path)
                .map_err(|error| {
                    format!("failed to read {}: {error}", definition_path.display())
                })?;
            Document::parse_with_options(
                &definition_content,
                roxmltree::ParsingOptions {
                    allow_dtd: true,
                    ..Default::default()
                },
            )
            .map_err(|error| format!("failed to parse {}: {error}", definition_path.display()))?;
        }
        component_count += 1;
    }
    if component_count == 0 {
        return Err(format!(
            "configuration contains no {component_tag} components"
        ));
    }

    let uuid = instance_uuid();
    let application = Path::new(&args[0])
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(expected_root);
    prepare(application, &runtime_options, uuid)?;

    if let Some(target) = start_time {
        let now = unsafe { libc::time(std::ptr::null_mut()) };
        let mut local: libc::tm = unsafe { std::mem::zeroed() };
        if unsafe { libc::localtime_r(&now, &mut local) }.is_null() {
            return Err("unable to determine local time".to_string());
        }
        let current = (local.tm_hour * 3600 + local.tm_min * 60 + local.tm_sec) as u64;
        let delay = if next_day {
            24 * 3600 - current + target
        } else if target >= current {
            target - current
        } else {
            return Err("start time is in the past (use --nextday)".to_string());
        };
        std::thread::sleep(Duration::from_secs(delay));
    }

    SHUTDOWN.store(false, Ordering::Relaxed);
    install_signal_handlers();
    println!(
        "{} started with {} {} component(s)",
        expected_root, component_count, component_tag
    );
    match expected_root {
        "eventservice" => run_generators(root, path, uuid),
        "eventdaemon" => run_agents(root, path, uuid),
        _ => Err(format!("unsupported event application {expected_root}")),
    }
}
