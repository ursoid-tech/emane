use emane_core::application_runtime::{consume_option, prepare, RuntimeOptions};
use emane_core::boundary_message_manager::BoundaryProtocol;
use emane_core::control_port::ControlPort;
use emane_core::nem_manager::NemManager;
use emane_core::xml_parser::{parse_platform, ParamMap};
use emane_core::{antenna, event_service, ota_manager, spectral_mask};
use std::collections::HashSet;
use std::env;
use std::ffi::CString;
use std::net::SocketAddr;
use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_shutdown(_: libc::c_int) {
    SHUTDOWN.store(true, Ordering::Relaxed);
}

// Original Application::Main handles INT and QUIT; TERM retains its default action.
fn install_signal_handlers() {
    unsafe {
        libc::signal(
            libc::SIGINT,
            handle_shutdown as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGQUIT,
            handle_shutdown as *const () as libc::sighandler_t,
        );
    }
}

fn usage() {
    println!("Usage: emane [OPTIONS] platform.xml");
}

struct NetworkServices {
    ota: bool,
    event: bool,
    control: Option<ControlPort>,
    workers: Vec<std::thread::JoinHandle<()>>,
}

impl NetworkServices {
    fn start(params: &ParamMap, uuid: [u8; 16]) -> Result<Self, String> {
        if let Some(uri) = parameter(params, "antennaprofilemanifesturi") {
            antenna::load_global(uri)
                .map_err(|error| format!("failed to load antenna profile manifest: {error}"))?;
        }
        if let Some(uri) = parameter(params, "spectralmaskmanifesturi") {
            spectral_mask::load_global(uri)
                .map_err(|error| format!("failed to load spectral mask manifest: {error}"))?;
        }

        let mut services = Self {
            ota: false,
            event: false,
            control: None,
            workers: Vec::new(),
        };
        ota_manager::configure_statistics(
            parse_parameter::<u32>(params, "stats.ota.maxpacketcountrows", 0)?,
            parse_parameter::<u32>(params, "stats.ota.maxeventcountrows", 0)?,
        );
        event_service::configure_statistics(parse_parameter::<u32>(
            params,
            "stats.event.maxeventcountrows",
            0,
        )?);
        let control_endpoint = parameter(params, "controlportendpoint").unwrap_or("0.0.0.0:47000");
        services.control = Some(ControlPort::open(control_endpoint)?);
        if let Some(group) = parameter(params, "eventservicegroup") {
            let group = c_string(group, "eventservicegroup")?;
            let device = c_string(
                parameter(params, "eventservicedevice").unwrap_or(""),
                "eventservicedevice",
            )?;
            let ttl = parse_parameter::<i32>(params, "eventservicettl", 1)?;
            let loopback = parse_bool_parameter(params, "eventserviceloopback", false)?;
            if !event_service::emane_rs_event_service_mcast_open(
                group.as_ptr(),
                device.as_ptr(),
                ttl,
                loopback,
                uuid.as_ptr(),
            ) {
                return Err("failed to open Event Service channel".to_string());
            }
            services.event = true;
            services.workers.push(
                std::thread::Builder::new()
                    .name("emane-event-service".to_string())
                    .spawn(move || {
                        event_service::emane_rs_event_service_process_loop(uuid.as_ptr())
                    })
                    .map_err(|error| format!("failed to start Event Service worker: {error}"))?,
            );
        }

        let ota_enabled = parse_bool_parameter(params, "otamanagerchannelenable", true)?;
        if ota_enabled {
            if let Some(group) = parameter(params, "otamanagergroup") {
                let group = c_string(group, "otamanagergroup")?;
                let device = c_string(
                    parameter(params, "otamanagerdevice").unwrap_or(""),
                    "otamanagerdevice",
                )?;
                let ttl = parse_parameter::<u8>(params, "otamanagerttl", 1)?;
                let mtu = parse_parameter::<usize>(params, "otamanagermtu", 0)?;
                let check = parse_parameter::<u16>(params, "otamanagerpartcheckthreshold", 2)?;
                let timeout = parse_parameter::<u16>(params, "otamanagerparttimeoutthreshold", 5)?;
                let loopback = parse_bool_parameter(params, "otamanagerloopback", false)?;
                if !ota_manager::emane_rs_ota_manager_open(
                    group.as_ptr(),
                    device.as_ptr(),
                    ttl,
                    loopback,
                    uuid.as_ptr(),
                    mtu,
                    check,
                    timeout,
                ) {
                    return Err("failed to open OTA channel".to_string());
                }
                services.ota = true;
                services.workers.push(
                    std::thread::Builder::new()
                        .name("emane-ota-manager".to_string())
                        .spawn(|| ota_manager::emane_rs_ota_manager_process_loop())
                        .map_err(|error| format!("failed to start OTA worker: {error}"))?,
                );
            }
        }
        Ok(services)
    }
}

impl Drop for NetworkServices {
    fn drop(&mut self) {
        if self.ota {
            ota_manager::emane_rs_ota_manager_close();
        }
        if self.event {
            event_service::emane_rs_event_service_mcast_close();
        }
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

fn parameter<'a>(params: &'a ParamMap, name: &str) -> Option<&'a str> {
    params.get(name)?.values.first().map(String::as_str)
}

fn parse_parameter<T>(params: &ParamMap, name: &str, default: T) -> Result<T, String>
where
    T: std::str::FromStr,
{
    parameter(params, name).map_or(Ok(default), |value| {
        value
            .parse()
            .map_err(|_| format!("invalid platform parameter {name}: {value}"))
    })
}

fn parse_bool_parameter(params: &ParamMap, name: &str, default: bool) -> Result<bool, String> {
    parameter(params, name).map_or(Ok(default), |value| {
        match value.to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => Ok(true),
            "false" | "0" | "no" | "off" => Ok(false),
            _ => Err(format!("invalid platform parameter {name}: {value}")),
        }
    })
}

fn c_string(value: &str, name: &str) -> Result<CString, String> {
    CString::new(value).map_err(|_| format!("platform parameter {name} contains a NUL byte"))
}

fn validate_platform_parameters(params: &ParamMap) -> Result<(), String> {
    const ALLOWED: &[&str] = &[
        "eventservicegroup",
        "eventservicedevice",
        "eventservicettl",
        "eventserviceloopback",
        "otamanagergroup",
        "otamanagerdevice",
        "otamanagermtu",
        "otamanagerpartcheckthreshold",
        "otamanagerparttimeoutthreshold",
        "otamanagerttl",
        "otamanagerloopback",
        "otamanagerchannelenable",
        "controlportendpoint",
        "antennaprofilemanifesturi",
        "stats.ota.maxpacketcountrows",
        "stats.ota.maxeventcountrows",
        "stats.event.maxeventcountrows",
        "spectralmaskmanifesturi",
    ];
    for (name, values) in params {
        if !ALLOWED.contains(&name.as_str()) {
            return Err(format!("unknown platform parameter {name}"));
        }
        if values.values.len() != 1 {
            return Err(format!(
                "platform parameter {name} requires exactly one value"
            ));
        }
    }
    parameter(params, "eventservicegroup")
        .ok_or_else(|| "required platform parameter eventservicegroup is missing".to_string())?
        .parse::<SocketAddr>()
        .map_err(|_| "invalid platform parameter eventservicegroup".to_string())?;
    for name in ["otamanagergroup", "controlportendpoint"] {
        if let Some(value) = parameter(params, name) {
            value
                .parse::<SocketAddr>()
                .map_err(|_| format!("invalid platform parameter {name}: {value}"))?;
        }
    }
    for name in ["eventservicettl", "otamanagerttl"] {
        let _ = parse_parameter::<u8>(params, name, 1)?;
    }
    for name in [
        "otamanagerpartcheckthreshold",
        "otamanagerparttimeoutthreshold",
    ] {
        let _ = parse_parameter::<u16>(params, name, 0)?;
    }
    for name in [
        "otamanagermtu",
        "stats.ota.maxpacketcountrows",
        "stats.ota.maxeventcountrows",
        "stats.event.maxeventcountrows",
    ] {
        let _ = parse_parameter::<u32>(params, name, 0)?;
    }
    for name in [
        "eventserviceloopback",
        "otamanagerloopback",
        "otamanagerchannelenable",
    ] {
        let _ = parse_bool_parameter(params, name, false)?;
    }
    Ok(())
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    let mut config_url = None;
    let mut runtime_options = RuntimeOptions::default();
    let mut index = 1;
    while index < args.len() {
        if consume_option(&args, &mut index, &mut runtime_options)? {
            index += 1;
            continue;
        }
        match args[index].as_str() {
            "-v" | "--version" => {
                println!("EMANE 1.2.5 (Rust Port)");
                return Ok(());
            }
            "-h" | "--help" => {
                usage();
                return Ok(());
            }
            option if option.starts_with('-') => return Err(format!("unknown option: {option}")),
            value => {
                if config_url.replace(value.to_string()).is_some() {
                    return Err("only one platform configuration may be supplied".to_string());
                }
            }
        }
        index += 1;
    }

    let config_url = config_url.ok_or_else(|| "missing platform configuration".to_string())?;
    let platform = parse_platform(Path::new(&config_url)).map_err(|error| error.to_string())?;
    if platform.nems.is_empty() {
        return Err("platform contains no NEMs".to_string());
    }
    validate_platform_parameters(&platform.params)?;

    let uuid = rand::random();
    let mut manager = NemManager::new(uuid);
    let mut nem_ids = HashSet::new();
    for nem in platform.nems {
        if !nem_ids.insert(nem.id) {
            return Err(format!("duplicate NEM id {}", nem.id));
        }
        if nem.external_transport {
            if let Some(name) = nem.params.keys().find(|name| {
                !matches!(
                    name.as_str(),
                    "platformendpoint" | "transportendpoint" | "protocol"
                )
            }) {
                return Err(format!(
                    "external NEM {} has unknown parameter {name}",
                    nem.id
                ));
            }
            let platform_endpoint = parameter(&nem.params, "platformendpoint")
                .ok_or_else(|| format!("external NEM {} requires platformendpoint", nem.id))?;
            let transport_endpoint = parameter(&nem.params, "transportendpoint")
                .ok_or_else(|| format!("external NEM {} requires transportendpoint", nem.id))?;
            let protocol =
                BoundaryProtocol::platform(parameter(&nem.params, "protocol").unwrap_or("udp"))?;
            manager.add_platform_boundary(
                nem.id,
                platform_endpoint.to_string(),
                transport_endpoint.to_string(),
                protocol,
            )?;
        } else if let Some(name) = nem.params.keys().next() {
            return Err(format!("NEM {} has unexpected parameter {name}", nem.id));
        }
        for layer in nem.layers {
            if nem.external_transport && layer.layer_type == "transport" {
                continue;
            }
            let expected_type = match layer.layer_type.as_str() {
                "mac" => 1,
                "phy" => 2,
                "shim" => 3,
                "transport" => 4,
                other => return Err(format!("NEM {} has unknown layer type {other}", nem.id)),
            };
            let default_plugin = match expected_type {
                2 => "emanephy",
                4 => "virtualtransport",
                _ => "",
            };
            let plugin = layer.plugin.as_deref().unwrap_or(default_plugin);
            if plugin.is_empty() {
                return Err(format!(
                    "NEM {} {} layer has no plugin",
                    nem.id, layer.layer_type
                ));
            }
            let config: Vec<_> = layer
                .params
                .into_iter()
                .map(|(name, values)| (name, values.values))
                .collect();
            manager
                .add_layer_configured(nem.id, plugin, expected_type, &config)
                .map_err(|error| {
                    format!(
                        "failed to construct NEM {} {} layer ({plugin}): {error}",
                        nem.id, layer.layer_type
                    )
                })?;
        }
    }

    prepare("emane", &runtime_options, uuid)?;
    let _network_services = NetworkServices::start(&platform.params, uuid)?;

    install_signal_handlers();
    manager.start()?;
    manager.post_start();
    println!(
        "EMANE started with {} NEM(s); press Ctrl-C to stop",
        nem_ids.len()
    );
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
            eprintln!("emane: {error}");
            ExitCode::FAILURE
        }
    }
}
