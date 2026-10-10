use super::loaders::{
    antennaprofile::AntennaProfileLoader, commeffect::CommEffectLoader,
    fadingselection::FadingSelectionLoader, location::LocationLoader, pathloss::PathlossLoader,
    pathlossex::PathlossExLoader,
};
use super::parser::EelInputParser;
use crate::event_service::emane_rs_event_service_send_event;
use emane_plugin_api::numeric::LegacyParse;
use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

struct Publication {
    nem_id: u16,
    event_id: u16,
    data: Vec<u8>,
}

extern "C" fn collect_publication(
    context: *mut c_void,
    nem_id: u16,
    event_id: u16,
    data: *const u8,
    len: usize,
) {
    if context.is_null() || (len != 0 && data.is_null()) {
        return;
    }
    let publications = unsafe { &mut *(context as *mut Vec<Publication>) };
    let data = if len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(data, len) }.to_vec()
    };
    publications.push(Publication {
        nem_id,
        event_id,
        data,
    });
}

enum NativeLoader {
    Antenna(AntennaProfileLoader),
    CommEffect(CommEffectLoader),
    Fading(FadingSelectionLoader),
    Location(LocationLoader),
    Pathloss(PathlossLoader),
    PathlossEx(PathlossExLoader),
}

impl NativeLoader {
    fn from_library(library: &str) -> Result<Self, String> {
        let name = library
            .strip_prefix("lib")
            .unwrap_or(library)
            .strip_suffix(".so")
            .unwrap_or(library.strip_prefix("lib").unwrap_or(library));
        match name {
            "eelloaderantennaprofile" | "antennaprofile" => {
                Ok(Self::Antenna(AntennaProfileLoader::new()))
            }
            "eelloadercommeffect" | "commeffect" => Ok(Self::CommEffect(CommEffectLoader::new())),
            "eelloaderfadingselection" | "fadingselection" => {
                Ok(Self::Fading(FadingSelectionLoader::new()))
            }
            "eelloaderlocation" | "location" => Ok(Self::Location(LocationLoader::new())),
            "eelloaderpathloss" | "pathloss" => Ok(Self::Pathloss(PathlossLoader::new())),
            "eelloaderpathlossex" | "pathlossex" => Ok(Self::PathlossEx(PathlossExLoader::new())),
            _ => Err(format!("unsupported EEL loader library {library}")),
        }
    }

    fn load(
        &mut self,
        module_type: &str,
        module_id: u16,
        event_type: &str,
        arguments: &[String],
    ) -> Result<(), String> {
        let borrowed: Vec<_> = arguments.iter().map(String::as_str).collect();
        match self {
            Self::Antenna(loader) => loader.load(module_type, module_id, &borrowed),
            Self::CommEffect(loader) => loader.load(module_type, module_id, &borrowed),
            Self::Fading(loader) => loader.load(module_type, module_id, event_type, arguments),
            Self::Location(loader) => loader.load(module_type, module_id, event_type, arguments),
            Self::Pathloss(loader) => loader.load(module_type, module_id, event_type, arguments),
            Self::PathlossEx(loader) => loader.load(module_type, module_id, event_type, arguments),
        }
    }

    fn publications(&mut self, mode: u8) -> Vec<Publication> {
        let mut publications = Vec::new();
        match self {
            Self::Antenna(loader) => loader.get_events(mode, |nem_id, data| {
                publications.push(Publication {
                    nem_id,
                    event_id: 102,
                    data: data.to_vec(),
                });
            }),
            Self::CommEffect(loader) => loader.get_events(mode, |nem_id, data| {
                publications.push(Publication {
                    nem_id,
                    event_id: 103,
                    data: data.to_vec(),
                });
            }),
            Self::Fading(loader) => loader.get_events(
                i32::from(mode),
                (&mut publications as *mut Vec<Publication>).cast(),
                collect_publication,
            ),
            Self::Location(loader) => loader.get_events(
                i32::from(mode),
                (&mut publications as *mut Vec<Publication>).cast(),
                collect_publication,
            ),
            Self::Pathloss(loader) => loader.get_events(
                i32::from(mode),
                (&mut publications as *mut Vec<Publication>).cast(),
                collect_publication,
            ),
            Self::PathlossEx(loader) => loader.get_events(
                i32::from(mode),
                (&mut publications as *mut Vec<Publication>).cast(),
                collect_publication,
            ),
        }
        publications
    }
}

struct LoaderEntry {
    loader: NativeLoader,
    mode: u8,
}

pub struct NativeEelGenerator {
    input_files: Vec<String>,
    loaders: Vec<LoaderEntry>,
    event_loaders: HashMap<String, usize>,
    start: Instant,
}

impl NativeEelGenerator {
    pub fn new(input_files: Vec<String>, loader_specs: Vec<String>) -> Result<Self, String> {
        if input_files.is_empty() {
            return Err("EEL generator requires at least one inputfile".to_string());
        }
        let mut loaders = Vec::new();
        let mut event_loaders = HashMap::new();
        for spec in loader_specs {
            let mut fields = spec.split(':');
            let event_types = fields.next().unwrap_or_default();
            let library = fields.next().ok_or_else(|| {
                format!("bad EEL loader specification {spec}; expected events:library[:mode]")
            })?;
            let mode = match fields.next().unwrap_or("delta") {
                "delta" => 0,
                "full" => 1,
                value => return Err(format!("unknown EEL publish mode {value}")),
            };
            if fields.next().is_some() || event_types.is_empty() {
                return Err(format!("bad EEL loader specification {spec}"));
            }
            let index = loaders.len();
            loaders.push(LoaderEntry {
                loader: NativeLoader::from_library(library)?,
                mode,
            });
            for event_type in event_types.split(',') {
                if event_type.is_empty()
                    || event_loaders
                        .insert(event_type.to_string(), index)
                        .is_some()
                {
                    return Err(format!("duplicate or empty EEL event type {event_type}"));
                }
            }
        }
        if loaders.is_empty() {
            return Err("EEL generator requires at least one loader".to_string());
        }
        Ok(Self {
            input_files,
            loaders,
            event_loaders,
            start: Instant::now(),
        })
    }

    fn publish(&mut self, elapsed: Duration, stop: &AtomicBool) -> bool {
        while !stop.load(Ordering::Relaxed) {
            let now = Instant::now();
            if now.saturating_duration_since(self.start) >= elapsed {
                break;
            }
            let remaining = elapsed.saturating_sub(now.saturating_duration_since(self.start));
            std::thread::sleep(remaining.min(Duration::from_millis(50)));
        }
        if stop.load(Ordering::Relaxed) {
            return false;
        }
        let mut published = HashSet::new();
        for index in self.event_loaders.values().copied() {
            if published.insert(index) {
                let mode = self.loaders[index].mode;
                for publication in self.loaders[index].loader.publications(mode) {
                    emane_rs_event_service_send_event(
                        0,
                        publication.nem_id,
                        publication.event_id,
                        publication.data.as_ptr().cast(),
                        publication.data.len(),
                    );
                }
            }
        }
        true
    }

    pub fn run(mut self, stop: Arc<AtomicBool>) -> Result<(), String> {
        self.start = Instant::now();
        let mut current_time = None;
        for filename in self.input_files.clone() {
            let file = File::open(&filename)
                .map_err(|error| format!("failed to open EEL input {filename}: {error}"))?;
            for (line_number, line) in BufReader::new(file).lines().enumerate() {
                if stop.load(Ordering::Relaxed) {
                    return Ok(());
                }
                let line = line.map_err(|error| {
                    format!("failed to read {filename}:{}: {error}", line_number + 1)
                })?;
                let Some((event_time, module, event_type, arguments)) =
                    EelInputParser::parse(&line)
                        .map_err(|error| format!("{filename}:{}: {error}", line_number + 1))?
                else {
                    continue;
                };
                if !event_time.is_finite()
                    || event_time < 0.0
                    || module.is_empty()
                    || event_type.is_empty()
                {
                    return Err(format!(
                        "{filename}:{}: malformed EEL record",
                        line_number + 1
                    ));
                }
                if current_time.is_some_and(|previous| event_time < previous) {
                    return Err(format!(
                        "{filename}:{}: event times are not monotonic",
                        line_number + 1
                    ));
                }
                if current_time.is_some_and(|previous| event_time != previous)
                    && !self.publish(Duration::from_secs_f32(current_time.unwrap()), &stop)
                {
                    return Ok(());
                }
                current_time = Some(event_time);
                let (module_type, module_id) = module.split_once(':').ok_or_else(|| {
                    format!("{filename}:{}: invalid module {module}", line_number + 1)
                })?;
                let module_id = module_id.parse_legacy::<u16>().map_err(|_| {
                    format!(
                        "{filename}:{}: invalid module id in {module}",
                        line_number + 1
                    )
                })?;
                let index = *self.event_loaders.get(&event_type).ok_or_else(|| {
                    format!("{filename}:{}: no loader for {event_type}", line_number + 1)
                })?;
                self.loaders[index]
                    .loader
                    .load(module_type, module_id, &event_type, &arguments)
                    .map_err(|error| format!("{filename}:{}: {error}", line_number + 1))?;
            }
        }
        if let Some(time) = current_time {
            self.publish(Duration::from_secs_f32(time), &stop);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    static DELIVERIES: AtomicUsize = AtomicUsize::new(0);

    extern "C" fn delivered(_: *mut c_void, event_id: u16, _: *const u8, len: usize) {
        if event_id == 100 && len != 0 {
            DELIVERIES.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn runs_native_location_loader_and_publishes() {
        DELIVERIES.store(0, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "emane-native-eel-{}-{}.eel",
            std::process::id(),
            Instant::now().elapsed().as_nanos()
        ));
        std::fs::write(&path, "0.0 nem:1 location gps 40.0,-74.0,10.0,msl\n").unwrap();
        crate::event_service::register_native_user(49_000, 1, std::ptr::null_mut(), delivered);
        assert!(crate::event_service::emane_rs_event_service_register_event(
            49_000, 100
        ));
        let generator = NativeEelGenerator::new(
            vec![path.to_string_lossy().into_owned()],
            vec!["location:eelloaderlocation:delta".to_string()],
        )
        .unwrap();
        generator.run(Arc::new(AtomicBool::new(false))).unwrap();
        crate::event_service::unregister_user(49_000);
        let _ = std::fs::remove_file(path);
        assert_eq!(DELIVERIES.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn rejects_unknown_or_duplicate_loader_types() {
        assert!(NativeEelGenerator::new(
            vec!["input.eel".to_string()],
            vec!["location:missing".to_string()]
        )
        .is_err());
        assert!(NativeEelGenerator::new(
            vec!["input.eel".to_string()],
            vec![
                "location:eelloaderlocation".to_string(),
                "location:eelloaderlocation".to_string()
            ]
        )
        .is_err());
    }
}
