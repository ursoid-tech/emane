use crate::boundary_message_manager::{
    with_ffi_messages, BoundaryMessage, BoundaryMessageManager, BoundaryProtocol,
};
use crate::build_id_service::{
    emane_rs_buildid_assign, emane_rs_buildid_register_layer, unregister_native_layer,
};
use crate::event_service::{
    emane_rs_event_service_register_event, emane_rs_event_service_send_event,
    register_native_user as register_event_user, unregister_user as unregister_event_user,
};
use crate::file_descriptor_service;
use crate::native_configuration::{
    register_with_schema as register_native_configuration,
    unregister as unregister_native_configuration, ConfigurationValue,
};
use crate::neighbor_metric_manager::NeighborMetricManager;
use crate::nem_queued_layer::{NemQueuedLayer, QueueTaskKind};
use crate::ota_manager::{
    emane_rs_ota_manager_send_ota_packet, register_native_user, unregister_native_user,
};
use crate::plugin_interface::{
    AntennaPattern, CommEffectHeader, CommonLayerCounters, FfiConfigItem, FfiConfigRequest,
    FfiConfigStringArray, FfiControlMessage, FfiFrameworkService, FfiPacket, FfiPacketInfo,
    FfiSlice, FfiStatisticValue, FlowControlToken, FrequencyOfInterest, MimoRxAntennaInfo,
    MimoRxProperties, MimoTxAntenna, MimoTxFrequencySegment, MimoTxProperties, ModelHeader,
    PluginApi, PluginEntryFunc, R2riNeighborMetric, R2riNeighborMetrics, R2riQueueMetric,
    R2riQueueMetrics, R2riSelfMetric, RxAntennaAdd, RxAntennaRemove, RxFrequencySegment,
    RxFrequencySegments, RxProperties, TxAntennaProfile, TxFrequencySegment, TxFrequencySegments,
    TxProperties, TxTransmitter, TxTransmitters, CONTROL_COMM_EFFECT_HEADER,
    CONTROL_FLOW_CONTROL_TOKEN, CONTROL_FREQUENCY_INTEREST, CONTROL_MIMO_RX_PROPERTIES,
    CONTROL_MIMO_TX_PROPERTIES, CONTROL_MODEL_HEADER, CONTROL_R2RI_NEIGHBOR_METRIC,
    CONTROL_R2RI_QUEUE_METRIC, CONTROL_R2RI_SELF_METRIC, CONTROL_RX_ANTENNA_ADD,
    CONTROL_RX_ANTENNA_REMOVE, CONTROL_RX_ANTENNA_UPDATE, CONTROL_RX_FREQUENCY_SEGMENTS,
    CONTROL_RX_PROPERTIES, CONTROL_TX_ANTENNA_PROFILE, CONTROL_TX_FREQUENCY_SEGMENTS,
    CONTROL_TX_PROPERTIES, CONTROL_TX_TRANSMITTERS, MAC_REGISTRATION_BENTPIPE, PLUGIN_ABI_VERSION,
    STATISTIC_VALUE_F64, STATISTIC_VALUE_I64, STATISTIC_VALUE_STRING, STATISTIC_VALUE_U16,
    STATISTIC_VALUE_U32, STATISTIC_VALUE_U64, STATISTIC_VALUE_U8,
};
use crate::protobufs::emane_message::{
    common_phy_header, CommEffectShimHeader, CommonMacHeader, CommonPhyHeader,
};
use crate::queue_metric_manager::QueueMetricManager;
use crate::spectrum_monitor::{FfiFrequencySegment, NoiseMode, SpectrumMonitor};
use crate::statistics::{
    clear_native_table, configure_native_rf_signal_table, increment_native_counter,
    maximize_native_counter, native_table_generation, register_native_counter,
    register_native_double, register_native_float_average, register_native_rf_signal_table,
    register_native_table, remove_native_table_row, sample_native_average, set_native_double,
    set_native_table_row, unregister_native_statistics, update_native_rf_signal_table,
    NativeTableValue,
};
use crate::timer_service::{emane_rs_timer_cancel, emane_rs_timer_schedule};
use crate::{
    common::ethernet_transport::{
        emane_rs_ethernet_transport_parse_frame, emane_rs_ethernet_transport_update_arp_cache,
        emane_rs_ethernet_transport_verify_frame, EthernetTransportState,
    },
    r#virtual::virtual_transport::{
        emane_rs_virtual_transport_free, emane_rs_virtual_transport_new,
        emane_rs_virtual_transport_process_upstream_packet, emane_rs_virtual_transport_start,
        emane_rs_virtual_transport_stop, VirtualTransport,
    },
    raw_transport::{
        emane_rs_raw_transport_free, emane_rs_raw_transport_new,
        emane_rs_raw_transport_process_upstream_packet, emane_rs_raw_transport_start,
        emane_rs_raw_transport_stop, RawTransport,
    },
};
use crate::{LognormalFadingParameters, LognormalFadingState};
use libloading::{Library, Symbol};
use prost::Message;
use std::cell::Cell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::{c_void, CStr, CString};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, OnceLock, RwLock, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use emane_plugin_api::{
    FfiFilterQuery, FfiFilterResult, FfiSpectrumQuery, FfiSpectrumResult, SelfInterference,
    SpectrumFilterAdd, CONTROL_SELF_INTERFERENCE, CONTROL_SPECTRUM_FILTER_ADD,
    CONTROL_SPECTRUM_FILTER_DATA, CONTROL_SPECTRUM_FILTER_REMOVE,
};

const BROADCAST_NEM: u16 = u16::MAX;

#[derive(Clone, Copy)]
struct Invocation {
    api: usize,
    plugin_ctx: usize,
    queue: usize,
}

struct QueuedControl {
    message_type: u32,
    payload: Vec<u8>,
}

struct QueuedCall {
    packet: Option<(FfiPacketInfo, Vec<u8>)>,
    controls: Vec<QueuedControl>,
}

impl QueuedCall {
    fn capture(
        packet: *const FfiPacket,
        messages: *const FfiControlMessage,
        message_count: usize,
    ) -> Option<Self> {
        let packet = if let Some(packet) = unsafe { packet.as_ref() } {
            if packet.payload.len > 64 << 20
                || (packet.payload.len != 0 && packet.payload.data.is_null())
            {
                return None;
            }
            let payload = if packet.payload.len == 0 {
                Vec::new()
            } else {
                unsafe {
                    std::slice::from_raw_parts(packet.payload.data, packet.payload.len).to_vec()
                }
            };
            Some((packet.info, payload))
        } else {
            None
        };
        let messages = ffi_control_messages(messages, message_count)?;
        let controls = messages
            .iter()
            .map(|message| {
                if message.payload.len > 16 << 20
                    || (message.payload.len != 0 && message.payload.data.is_null())
                {
                    return None;
                }
                Some(QueuedControl {
                    message_type: message.msg_type,
                    payload: if message.payload.len == 0 {
                        Vec::new()
                    } else {
                        unsafe {
                            std::slice::from_raw_parts(message.payload.data, message.payload.len)
                                .to_vec()
                        }
                    },
                })
            })
            .collect::<Option<Vec<_>>>()?;
        Some(Self { packet, controls })
    }

    fn run(self, invocation: Invocation, downstream: bool) {
        if !invocation.model_running() {
            return;
        }
        let messages = self
            .controls
            .iter()
            .map(|control| FfiControlMessage {
                msg_type: control.message_type,
                payload: FfiSlice {
                    data: control.payload.as_ptr(),
                    len: control.payload.len(),
                },
            })
            .collect::<Vec<_>>();
        let packet = self.packet.as_ref().map(|(info, payload)| FfiPacket {
            info: *info,
            payload: FfiSlice {
                data: payload.as_ptr(),
                len: payload.len(),
            },
        });
        invocation.call(|api, context| {
            let process = if downstream {
                api.process_downstream
            } else {
                api.process_upstream
            };
            process(
                context,
                packet
                    .as_ref()
                    .map_or(std::ptr::null(), |packet| packet as *const FfiPacket),
                messages.as_ptr(),
                messages.len(),
            );
        });
    }
}

impl Invocation {
    fn api(self) -> &'static PluginApi {
        unsafe { &*(self.api as *const PluginApi) }
    }

    fn context(self) -> *mut c_void {
        self.plugin_ctx as *mut c_void
    }

    fn call<T>(self, operation: impl FnOnce(&PluginApi, *mut c_void) -> T) -> T {
        with_component_execution(|| operation(self.api(), self.context()))
    }

    fn queue(self) -> Option<&'static NemQueuedLayer> {
        (self.queue != 0).then(|| unsafe { &*(self.queue as *const NemQueuedLayer) })
    }

    fn configure_running(self, values: Vec<(String, Vec<String>)>) -> Result<(), String> {
        let configure = move || {
            if !self.model_running() {
                return true;
            }
            let guard = ConfigGuard::new(&values);
            self.call(|api, context| {
                (api.configure)(
                    context,
                    &guard.request as *const FfiConfigRequest as *const c_void,
                )
            })
        };
        let configured = if let Some(queue) = self.queue() {
            let wait = queue.is_running();
            let (sender, receiver) = std::sync::mpsc::sync_channel(1);
            queue
                .enqueue(
                    QueueTaskKind::Configuration,
                    Box::new(move || {
                        let _ = sender.send(configure());
                    }),
                )
                .map_err(|_| "layer configuration queue unavailable".to_string())?;
            // Before startup or after shutdown, the original accepts and
            // queues the update without executing a model callback.
            if !wait {
                return Ok(());
            }
            receiver
                .recv_timeout(Duration::from_secs(5))
                .map_err(|_| "layer configuration queue stopped or timed out".to_string())?
        } else {
            configure()
        };
        configured
            .then_some(())
            .ok_or_else(|| "plugin rejected runtime configuration update".to_string())
    }

    fn model_running(self) -> bool {
        self.queue().is_none_or(NemQueuedLayer::is_model_running)
    }

    fn process(
        self,
        downstream: bool,
        packet: *const FfiPacket,
        messages: *const FfiControlMessage,
        message_count: usize,
    ) {
        let Some(call) = QueuedCall::capture(packet, messages, message_count) else {
            return;
        };
        let kind = match (downstream, call.packet.is_some()) {
            (true, true) => QueueTaskKind::DownstreamPacket,
            (false, true) => QueueTaskKind::UpstreamPacket,
            (true, false) => QueueTaskKind::DownstreamControl,
            (false, false) => QueueTaskKind::UpstreamControl,
        };
        if let Some(queue) = self.queue() {
            if let Err(operation) =
                queue.enqueue(kind, Box::new(move || call.run(self, downstream)))
            {
                if queue.accepts_direct_calls() {
                    operation();
                }
            }
        } else {
            call.run(self, downstream);
        }
    }

    fn process_event(self, event_id: u16, data: *const u8, data_len: usize) {
        if data_len > 16 << 20 || (data_len != 0 && data.is_null()) {
            return;
        }
        let data = if data_len == 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(data, data_len).to_vec() }
        };
        let operation = move || {
            if !self.model_running() {
                return;
            }
            self.call(|api, context| {
                (api.process_event)(context, event_id, data.as_ptr(), data.len())
            });
        };
        if let Some(queue) = self.queue() {
            if let Err(operation) =
                queue.enqueue(QueueTaskKind::Event(event_id), Box::new(operation))
            {
                if queue.accepts_direct_calls() {
                    operation();
                }
            }
        } else {
            operation();
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn process_timed_event(
        self,
        timer_id: u64,
        event_id: u32,
        data: &[u8],
        expire_microseconds: u64,
        schedule_microseconds: u64,
        fire_microseconds: u64,
    ) {
        let data = data.to_vec();
        let operation = move || {
            if !self.model_running() {
                return;
            }
            self.call(|api, context| {
                (api.process_timed_event)(context, timer_id, event_id, data.as_ptr(), data.len())
            });
        };
        if let Some(queue) = self.queue() {
            if let Err(operation) = queue.enqueue(
                QueueTaskKind::TimedEvent {
                    expire_microseconds,
                    schedule_microseconds,
                    fire_microseconds,
                },
                Box::new(operation),
            ) {
                if queue.accepts_direct_calls() {
                    operation();
                }
            }
        } else {
            operation();
        }
    }
}

thread_local! {
    static COMPONENT_EXECUTION_DEPTH: Cell<u32> = const { Cell::new(0) };
}

pub(crate) fn with_component_execution<T>(operation: impl FnOnce() -> T) -> T {
    COMPONENT_EXECUTION_DEPTH.with(|depth| {
        struct RestoreDepth<'a> {
            depth: &'a Cell<u32>,
            previous: u32,
        }
        impl Drop for RestoreDepth<'_> {
            fn drop(&mut self) {
                self.depth.set(self.previous);
            }
        }

        let previous = depth.get();
        depth.set(previous.saturating_add(1));
        let _restore = RestoreDepth { depth, previous };
        operation()
    })
}

pub(crate) fn component_execution_active() -> bool {
    COMPONENT_EXECUTION_DEPTH.with(|depth| depth.get() != 0)
}

struct FrameworkContext {
    runtime: Weak<Runtime>,
    nem_id: u16,
    layer_index: usize,
    build_id: u16,
    neighbor_metrics: Mutex<NeighborMetricManager>,
    queue_metrics: Mutex<QueueMetricManager>,
    compatibility_tables: Mutex<HashMap<String, u64>>,
    descriptor_handles: Mutex<Vec<u64>>,
}

struct NemLayer {
    // The library must outlive every function pointer and plugin instance.
    _library: Option<Library>,
    invocation: Invocation,
    queue: Box<NemQueuedLayer>,
    _framework_context: Box<FrameworkContext>,
    event_build_id: u16,
    started: bool,
    destroyed: bool,
}

fn next_event_build_id() -> u16 {
    emane_rs_buildid_assign()
}

struct Runtime {
    uuid: [u8; 16],
    invocations: RwLock<HashMap<u16, Vec<Invocation>>>,
    boundaries: RwLock<HashMap<u16, BoundaryRoute>>,
    phy_tx_sequences: Mutex<HashMap<u16, u16>>,
    spectrum_monitors: RwLock<HashMap<(u16, u16), Weak<Mutex<SpectrumMonitor>>>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BoundaryRole {
    Platform,
    Transport,
}

#[derive(Clone)]
struct BoundaryRoute {
    role: BoundaryRole,
    endpoint: Arc<Mutex<BoundaryMessageManager>>,
}

impl Runtime {
    fn next_phy_tx_sequence(&self, nem_id: u16) -> u16 {
        let Ok(mut sequences) = self.phy_tx_sequences.lock() else {
            return 0;
        };
        let sequence = sequences.entry(nem_id).or_default();
        let current = *sequence;
        *sequence = sequence.wrapping_add(1);
        current
    }

    fn invocation(&self, nem_id: u16, index: usize) -> Option<Invocation> {
        self.invocations
            .read()
            .ok()?
            .get(&nem_id)
            .and_then(|layers| layers.get(index))
            .copied()
    }

    fn last_invocation(&self, nem_id: u16) -> Option<Invocation> {
        self.invocations
            .read()
            .ok()?
            .get(&nem_id)
            .and_then(|layers| layers.last())
            .copied()
    }

    fn route_downstream(
        &self,
        nem_id: u16,
        current_index: usize,
        packet: *const FfiPacket,
        messages: *const FfiControlMessage,
        message_count: usize,
    ) {
        if let Some(next) = self.invocation(nem_id, current_index + 1) {
            next.process(true, packet, messages, message_count);
            return;
        }

        if packet.is_null() {
            return;
        }

        let mut local_packet = unsafe { *packet };
        if local_packet.info.uuid == [0; 16] {
            local_packet.info.uuid = self.uuid;
        }
        let packet = &local_packet as *const FfiPacket;
        if let Some(route) = self.boundary(nem_id, BoundaryRole::Transport) {
            let messages = match ffi_control_messages(messages, message_count) {
                Some(messages) => messages,
                None => return,
            };
            if let Ok(endpoint) = route.endpoint.lock() {
                if let Err(error) = endpoint.send_packet(unsafe { &*packet }, messages) {
                    eprintln!("NEM {nem_id}: boundary send failed: {error}");
                }
            }
            return;
        }

        let packet_ref = unsafe { &*packet };
        let incoming = ffi_control_messages(messages, message_count);
        let phy_sequence = incoming
            .and_then(|messages| {
                control_payload(messages, CONTROL_MODEL_HEADER)
                    .zip(control_payload(messages, CONTROL_TX_PROPERTIES))
            })
            .map(|_| self.next_phy_tx_sequence(nem_id))
            .unwrap_or_default();
        let legacy_payload =
            encode_legacy_ota_payload(packet_ref, messages, message_count, phy_sequence);
        let serialized_controls = if legacy_payload.is_some() {
            incoming.and_then(encode_legacy_ota_controls)
        } else {
            encode_controls(messages, message_count)
        };
        let private_payload = if packet_ref.payload.len == 0 {
            Some(&[][..])
        } else if packet_ref.payload.data.is_null() {
            None
        } else {
            Some(unsafe {
                std::slice::from_raw_parts(packet_ref.payload.data, packet_ref.payload.len)
            })
        };
        if let (Some(payload), Some(controls)) = (
            legacy_payload.as_deref().or(private_payload),
            serialized_controls.as_deref(),
        ) {
            let _ = emane_rs_ota_manager_send_ota_packet(
                packet_ref.info.source,
                packet_ref.info.destination,
                payload.as_ptr(),
                payload.len(),
                controls.as_ptr(),
                controls.len(),
                std::ptr::null(),
                0,
            );
        }

        // OTA is a shared medium: every other local PHY must observe the
        // transmission. Packet destination filtering happens in the MAC, not
        // here, so that promiscuous reception and interference remain correct.
        let ota_transmitters = if legacy_payload.is_some() {
            incoming
                .and_then(|messages| control_payload(messages, CONTROL_OTA_TRANSMITTERS))
                .and_then(|bytes| LegacyOtaTransmitterSet::decode(bytes).ok())
                .map(|set| set.nem_ids.into_iter().map(|id| id as u16).collect())
                .unwrap_or_default()
        } else {
            incoming
                .and_then(find_tx_transmitters)
                .map(|transmitters| {
                    transmitters
                        .transmitters
                        .into_iter()
                        .map(|transmitter| transmitter.nem_id)
                        .collect::<HashSet<_>>()
                })
                .unwrap_or_default()
        };
        let targets: Vec<Invocation> = {
            let Ok(layers) = self.invocations.read() else {
                return;
            };
            layers
                .iter()
                .filter(|(id, _)| **id != nem_id)
                .filter(|(id, _)| !ota_transmitters.contains(id))
                .filter_map(|(_, stack)| stack.last().copied())
                .collect()
        };
        for target in targets {
            target.process(false, packet, messages, message_count);
        }
    }

    fn route_upstream(
        &self,
        nem_id: u16,
        current_index: usize,
        packet: *const FfiPacket,
        messages: *const FfiControlMessage,
        message_count: usize,
    ) {
        if current_index > 0 {
            if let Some(previous) = self.invocation(nem_id, current_index - 1) {
                previous.process(false, packet, messages, message_count);
            }
        } else if let Some(route) = self.boundary(nem_id, BoundaryRole::Platform) {
            let messages = match ffi_control_messages(messages, message_count) {
                Some(messages) => messages,
                None => return,
            };
            if let Some(packet) = unsafe { packet.as_ref() } {
                if let Ok(endpoint) = route.endpoint.lock() {
                    if let Err(error) = endpoint.send_packet(packet, messages) {
                        eprintln!("NEM {nem_id}: boundary send failed: {error}");
                    }
                }
            }
        }
    }

    fn route_control(
        &self,
        nem_id: u16,
        current_index: usize,
        downstream: bool,
        messages: *const FfiControlMessage,
        message_count: usize,
    ) {
        let target = if downstream {
            self.invocation(nem_id, current_index + 1)
        } else if current_index > 0 {
            self.invocation(nem_id, current_index - 1)
        } else {
            None
        };
        if let Some(target) = target {
            target.process(downstream, std::ptr::null(), messages, message_count);
        } else {
            let role = if downstream {
                BoundaryRole::Transport
            } else {
                BoundaryRole::Platform
            };
            if let Some(route) = self.boundary(nem_id, role) {
                let Some(messages) = ffi_control_messages(messages, message_count) else {
                    return;
                };
                if let Ok(endpoint) = route.endpoint.lock() {
                    if let Err(error) = endpoint.send_control(messages) {
                        eprintln!("NEM {nem_id}: boundary control send failed: {error}");
                    }
                }
            }
        }
    }

    fn boundary(&self, nem_id: u16, role: BoundaryRole) -> Option<BoundaryRoute> {
        self.boundaries
            .read()
            .ok()?
            .get(&nem_id)
            .filter(|route| route.role == role)
            .cloned()
    }

    fn process_boundary_message(&self, nem_id: u16, role: BoundaryRole, message: BoundaryMessage) {
        let target = match role {
            BoundaryRole::Platform => self.invocation(nem_id, 0),
            BoundaryRole::Transport => self.last_invocation(nem_id),
        };
        let Some(target) = target else {
            return;
        };
        match message {
            BoundaryMessage::Packet(packet) => {
                with_ffi_messages(&packet.controls, |messages| {
                    let ffi_packet = FfiPacket {
                        info: packet.info,
                        payload: FfiSlice {
                            data: packet.payload.as_ptr(),
                            len: packet.payload.len(),
                        },
                    };
                    target.process(
                        role == BoundaryRole::Platform,
                        &ffi_packet,
                        messages.as_ptr(),
                        messages.len(),
                    );
                });
            }
            BoundaryMessage::Control(controls) => {
                with_ffi_messages(&controls, |messages| {
                    target.process(
                        role == BoundaryRole::Platform,
                        std::ptr::null(),
                        messages.as_ptr(),
                        messages.len(),
                    );
                });
            }
        }
    }
}

extern "C" fn ota_packet(
    context_ptr: *mut c_void,
    source: u16,
    destination: u16,
    priority: u8,
    uuid: *const u8,
    data: *const u8,
    data_len: usize,
    controls: *const u8,
    controls_len: usize,
) {
    let Some(context) = context(context_ptr) else {
        return;
    };
    if (data_len != 0 && data.is_null()) || (controls_len != 0 && controls.is_null()) {
        return;
    }
    let control_bytes = if controls_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(controls, controls_len) }
    };
    let decoded_controls = decode_controls(control_bytes);
    let decoded_legacy = decode_legacy_ota_payload(
        if data_len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(data, data_len) }
        },
        source,
    );
    let (payload_data, decoded) = if let Some(legacy) = decoded_legacy.as_ref() {
        (legacy.payload.as_slice(), legacy.controls())
    } else {
        let Some(decoded) = decoded_controls.as_ref() else {
            return;
        };
        (
            if data_len == 0 {
                &[][..]
            } else {
                unsafe { std::slice::from_raw_parts(data, data_len) }
            },
            decoded.messages.as_slice(),
        )
    };
    let excluded = if decoded_legacy.is_some() {
        let Some(transmitters) = decode_legacy_ota_transmitters(control_bytes) else {
            return;
        };
        transmitters.contains(&context.nem_id)
    } else {
        find_tx_transmitters(decoded).is_some_and(|transmitters| {
            transmitters
                .transmitters
                .iter()
                .any(|transmitter| transmitter.nem_id == context.nem_id)
        })
    };
    if excluded {
        return;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    if uuid.is_null() {
        return;
    }
    let sender_uuid: [u8; 16] = unsafe { std::slice::from_raw_parts(uuid, 16) }
        .try_into()
        .unwrap();
    let packet = FfiPacket {
        info: FfiPacketInfo {
            uuid: sender_uuid,
            source,
            destination,
            priority,
            creation_time_sec: now.as_secs(),
            creation_time_usec: now.subsec_micros(),
        },
        payload: FfiSlice {
            data: payload_data.as_ptr(),
            len: payload_data.len(),
        },
    };
    if let Some(runtime) = context.runtime.upgrade() {
        if let Some(phy) = runtime.last_invocation(context.nem_id) {
            phy.process(false, &packet, decoded.as_ptr(), decoded.len());
        }
    }
}

extern "C" fn framework_event(
    context_ptr: *mut c_void,
    event_id: u16,
    data: *const u8,
    data_len: usize,
) {
    let Some(context) = context(context_ptr) else {
        return;
    };
    if data_len != 0 && data.is_null() {
        return;
    }
    if let Some(runtime) = context.runtime.upgrade() {
        if let Some(layer) = runtime.invocation(context.nem_id, context.layer_index) {
            layer.process_event(event_id, data, data_len);
        }
    }
}

extern "C" fn register_file_descriptor(
    context_ptr: *mut c_void,
    fd: i32,
    interests: u32,
    callback_context: *mut c_void,
    callback: crate::plugin_interface::FfiFileDescriptorCallback,
) -> u64 {
    let Some(context) = context(context_ptr) else {
        return 0;
    };
    let queue = context
        .runtime
        .upgrade()
        .and_then(|runtime| runtime.invocation(context.nem_id, context.layer_index))
        .map_or(0, |invocation| invocation.queue);
    let Some(handle) =
        file_descriptor_service::register(fd, interests, callback_context, callback, queue)
    else {
        return 0;
    };
    let Ok(mut handles) = context.descriptor_handles.lock() else {
        let _ = file_descriptor_service::unregister(handle);
        return 0;
    };
    handles.push(handle);
    handle
}

extern "C" fn unregister_file_descriptor(context_ptr: *mut c_void, handle: u64) -> bool {
    let Some(context) = context(context_ptr) else {
        return false;
    };
    let Ok(mut handles) = context.descriptor_handles.lock() else {
        return false;
    };
    let Some(index) = handles.iter().position(|candidate| *candidate == handle) else {
        return false;
    };
    if file_descriptor_service::unregister(handle) {
        handles.swap_remove(index);
        true
    } else {
        false
    }
}

const MAX_CONTROL_WIRE_SIZE: usize = 16 * 1024 * 1024;

// Serialized OTATransmitterControlMessage, kept separate from the PHY's full
// transmitter list: only explicitly supplied collaborators belong in this set.
const CONTROL_OTA_TRANSMITTERS: u32 = 108;

#[derive(Clone, PartialEq, Message)]
struct LegacyOtaTransmitterSet {
    #[prost(uint32, repeated, tag = "1")]
    nem_ids: Vec<u32>,
}

fn explicit_ota_transmitters(messages: &[FfiControlMessage]) -> LegacyOtaTransmitterSet {
    let mut nem_ids: Vec<_> = messages
        .iter()
        .filter_map(|message| {
            control_payload(std::slice::from_ref(message), CONTROL_TX_TRANSMITTERS)
                .and_then(TxTransmitters::decode)
        })
        .flat_map(|transmitters| transmitters.transmitters)
        .map(|transmitter| u32::from(transmitter.nem_id))
        .collect();
    // Original FrameworkPHY accumulates a set across every Transmitter control,
    // while the last such control supplies the PHY header's transmitter vector.
    nem_ids.sort_unstable();
    nem_ids.dedup();
    LegacyOtaTransmitterSet { nem_ids }
}

fn encode_legacy_ota_controls(messages: &[FfiControlMessage]) -> Option<Vec<u8>> {
    let Some(payload) = control_payload(messages, CONTROL_OTA_TRANSMITTERS) else {
        return Some(vec![0, 0]);
    };
    let mut result = vec![0, 1];
    result.extend_from_slice(&(CONTROL_OTA_TRANSMITTERS as u16).to_be_bytes());
    result.extend_from_slice(&u16::try_from(payload.len()).ok()?.to_be_bytes());
    result.extend_from_slice(payload);
    Some(result)
}

fn decode_legacy_ota_transmitters(data: &[u8]) -> Option<HashSet<u16>> {
    if data.is_empty() {
        return Some(HashSet::new());
    }
    if data.len() > MAX_CONTROL_WIRE_SIZE {
        return None;
    }
    let count = u16::from_be_bytes(data.get(..2)?.try_into().ok()?);
    let mut remaining = &data[2..];
    let mut transmitters = HashSet::new();
    for _ in 0..count {
        let header = remaining.get(..4)?;
        let kind = u16::from_be_bytes(header[..2].try_into().ok()?);
        let length = usize::from(u16::from_be_bytes(header[2..].try_into().ok()?));
        let payload = remaining.get(4..4 + length)?;
        if u32::from(kind) == CONTROL_OTA_TRANSMITTERS {
            // The receiving OTAManager replaces the set for each control.
            // Protobuf accepts packed and unpacked repeated uint32 values.
            transmitters = LegacyOtaTransmitterSet::decode(payload)
                .ok()?
                .nem_ids
                .into_iter()
                .map(|id| id as u16)
                .collect();
        }
        remaining = &remaining[4 + length..];
    }
    Some(transmitters)
}
const PHY_BYPASS_REGISTRATION: u32 = 1;
const PHY_FRAMEWORK_REGISTRATION: u32 = 0x0007;
const PHY_COMM_EFFECT_REGISTRATION: u32 = 0x0005;

// Native MAC headers travel as controls until OTA serialization, whereas C++
// prepends its CommonMACHeader before entering FrameworkPHY. Include that wire
// framing in PHY accounting without exposing it as application payload.
fn phy_accounted_packet_len(packet: &FfiPacket, messages: &[FfiControlMessage]) -> usize {
    let header_len = control_payload(messages, CONTROL_MODEL_HEADER)
        .and_then(ModelHeader::decode)
        .map(|model| {
            2 + CommonMacHeader {
                registration_id: u32::from(model.registration_id),
                sequence_number: model.sequence,
            }
            .encoded_len()
        })
        .unwrap_or(0);
    packet.payload.len.saturating_add(header_len)
}

fn encode_legacy_ota_payload(
    packet: &FfiPacket,
    messages: *const FfiControlMessage,
    count: usize,
    phy_sequence: u16,
) -> Option<Vec<u8>> {
    let messages = ffi_control_messages(messages, count)?;
    let model = control_payload(messages, CONTROL_MODEL_HEADER).and_then(ModelHeader::decode);
    if messages
        .iter()
        .any(|m| m.msg_type == emane_plugin_api::CONTROL_BYPASS_PHY)
    {
        let phy = CommonPhyHeader {
            registration_id: PHY_BYPASS_REGISTRATION,
            sub_id: 0,
            sequence_number: u32::from(phy_sequence),
            tx_time_microseconds: unix_time_microseconds().max(0) as u64,
            transmitters: vec![common_phy_header::Transmitter {
                nem_id: u32::from(packet.info.source),
                powerd_bm: 0.0,
            }],
            frequency_groups: vec![common_phy_header::FrequencyGroup {
                frequency_segments: vec![common_phy_header::frequency_group::FrequencySegment {
                    frequency_hz: 0,
                    offset_microseconds: 0,
                    duration_microseconds: 0,
                    powerd_bm: None,
                }],
            }],
            transmit_antennas: vec![],
            filter_data: filter_data(messages),
        }
        .encode_to_vec();
        let mut wire = Vec::new();
        wire.extend_from_slice(&(phy.len() as u16).to_be_bytes());
        wire.extend_from_slice(&phy);
        if let Some(model) = model {
            let mac = CommonMacHeader {
                registration_id: u32::from(model.registration_id),
                sequence_number: model.sequence,
            }
            .encode_to_vec();
            wire.extend_from_slice(&(mac.len() as u16).to_be_bytes());
            wire.extend_from_slice(&mac);
        }
        if packet.payload.len != 0 {
            if packet.payload.data.is_null() {
                return None;
            }
            wire.extend_from_slice(unsafe {
                std::slice::from_raw_parts(packet.payload.data, packet.payload.len)
            });
        }
        return Some(wire);
    }
    if model.is_none() {
        return encode_legacy_commeffect_payload(packet, messages);
    }
    let model = model?;
    let tx = find_tx_properties(messages)?;
    let transmitters = find_tx_transmitters(messages).unwrap_or(TxTransmitters {
        transmitters: vec![TxTransmitter {
            nem_id: packet.info.source,
            tx_power_dbm: tx.tx_power_dbm,
        }],
    });
    let mimo = find_mimo_tx_properties(messages).unwrap_or_else(|| {
        let segments = find_tx_frequency_segments(messages).map_or_else(
            || {
                vec![MimoTxFrequencySegment {
                    frequency_hz: tx.frequency_hz,
                    tx_power_dbm: None,
                    duration_microseconds: tx.duration_microseconds,
                    offset_microseconds: tx.offset_microseconds,
                }]
            },
            |segments| {
                segments
                    .segments
                    .into_iter()
                    .map(|segment| MimoTxFrequencySegment {
                        frequency_hz: segment.frequency_hz,
                        tx_power_dbm: None,
                        duration_microseconds: segment.duration_microseconds,
                        offset_microseconds: segment.offset_microseconds,
                    })
                    .collect()
            },
        );
        MimoTxProperties {
            frequency_groups: vec![segments],
            transmit_antennas: vec![MimoTxAntenna {
                frequency_group_index: 0,
                antenna_index: tx.antenna_index,
                bandwidth_hz: tx.bandwidth_hz,
                spectral_mask_index: tx.spectral_mask_index,
                pattern: AntennaPattern::Default,
            }],
        }
    });
    let frequency_groups = mimo
        .frequency_groups
        .iter()
        .map(|group| common_phy_header::FrequencyGroup {
            frequency_segments: group
                .iter()
                .map(
                    |segment| common_phy_header::frequency_group::FrequencySegment {
                        frequency_hz: segment.frequency_hz,
                        offset_microseconds: segment.offset_microseconds,
                        duration_microseconds: segment.duration_microseconds,
                        powerd_bm: segment.tx_power_dbm,
                    },
                )
                .collect(),
        })
        .collect();
    let transmit_antennas = mimo
        .transmit_antennas
        .iter()
        .map(|antenna| {
            let (fixed_gaind_bi, pointing) = match antenna.pattern {
                AntennaPattern::Default => (None, None),
                AntennaPattern::IdealOmni { gain_db } => (Some(gain_db), None),
                AntennaPattern::Profile(profile) => (
                    None,
                    Some(common_phy_header::transmit_antenna::Pointing {
                        profile_id: u32::from(profile.profile_id),
                        azimuth_degrees: profile.azimuth_degrees,
                        elevation_degrees: profile.elevation_degrees,
                    }),
                ),
            };
            common_phy_header::TransmitAntenna {
                antenna_index: u32::from(antenna.antenna_index),
                frequency_group_index: u32::from(antenna.frequency_group_index),
                bandwidth_hz: if antenna.spectral_mask_index == 0 {
                    antenna.bandwidth_hz
                } else {
                    0
                },
                fixed_gaind_bi,
                pointing,
                spectral_mask_index: (antenna.spectral_mask_index != 0)
                    .then_some(u32::from(antenna.spectral_mask_index)),
            }
        })
        .collect();
    let phy = CommonPhyHeader {
        registration_id: PHY_FRAMEWORK_REGISTRATION,
        sub_id: u32::from(tx.sub_id),
        sequence_number: u32::from(phy_sequence),
        tx_time_microseconds: tx.tx_time_microseconds.max(0) as u64,
        transmitters: transmitters
            .transmitters
            .into_iter()
            .map(|transmitter| common_phy_header::Transmitter {
                nem_id: u32::from(transmitter.nem_id),
                powerd_bm: transmitter.tx_power_dbm,
            })
            .collect(),
        frequency_groups,
        transmit_antennas,
        filter_data: filter_data(messages),
    }
    .encode_to_vec();
    let mac = CommonMacHeader {
        registration_id: u32::from(model.registration_id),
        sequence_number: model.sequence,
    }
    .encode_to_vec();
    let payload = if packet.payload.len == 0 {
        &[][..]
    } else if packet.payload.data.is_null() {
        return None;
    } else {
        unsafe { std::slice::from_raw_parts(packet.payload.data, packet.payload.len) }
    };
    let mut result = Vec::with_capacity(4 + phy.len() + mac.len() + payload.len());
    result.extend_from_slice(&u16::try_from(phy.len()).ok()?.to_be_bytes());
    result.extend_from_slice(&phy);
    result.extend_from_slice(&u16::try_from(mac.len()).ok()?.to_be_bytes());
    result.extend_from_slice(&mac);
    result.extend_from_slice(payload);
    Some(result)
}

fn encode_controls(messages: *const FfiControlMessage, count: usize) -> Option<Vec<u8>> {
    let messages = ffi_control_messages(messages, count)?;
    let count = u16::try_from(messages.len()).ok()?;
    let mut data = Vec::new();
    data.extend_from_slice(&count.to_be_bytes());
    for message in messages {
        if message.payload.len > u32::MAX as usize
            || (message.payload.len != 0 && message.payload.data.is_null())
        {
            return None;
        }
        let required = 8usize.checked_add(message.payload.len)?;
        if data.len().checked_add(required)? > MAX_CONTROL_WIRE_SIZE {
            return None;
        }
        data.extend_from_slice(&message.msg_type.to_be_bytes());
        data.extend_from_slice(&(message.payload.len as u32).to_be_bytes());
        if message.payload.len != 0 {
            data.extend_from_slice(unsafe {
                std::slice::from_raw_parts(message.payload.data, message.payload.len)
            });
        }
    }
    Some(data)
}

fn encode_legacy_commeffect_payload(
    packet: &FfiPacket,
    messages: &[FfiControlMessage],
) -> Option<Vec<u8>> {
    let header =
        control_payload(messages, CONTROL_COMM_EFFECT_HEADER).and_then(CommEffectHeader::decode)?;
    let phy = CommonPhyHeader {
        registration_id: PHY_COMM_EFFECT_REGISTRATION,
        sub_id: header.sequence,
        sequence_number: 0,
        tx_time_microseconds: header.tx_time_microseconds.max(0) as u64,
        transmitters: vec![common_phy_header::Transmitter {
            nem_id: u32::from(packet.info.source),
            powerd_bm: 0.0,
        }],
        frequency_groups: vec![common_phy_header::FrequencyGroup {
            frequency_segments: vec![common_phy_header::frequency_group::FrequencySegment {
                frequency_hz: 0,
                offset_microseconds: 0,
                duration_microseconds: 0,
                powerd_bm: None,
            }],
        }],
        transmit_antennas: Vec::new(),
        filter_data: filter_data(messages),
    }
    .encode_to_vec();
    let shim = CommEffectShimHeader {
        group_id: header.group_id,
        sequence_number: header.sequence,
        tx_time_microseconds: header.tx_time_microseconds.max(0) as u64,
    }
    .encode_to_vec();
    let payload = if packet.payload.len == 0 {
        &[][..]
    } else if packet.payload.data.is_null() {
        return None;
    } else {
        unsafe { std::slice::from_raw_parts(packet.payload.data, packet.payload.len) }
    };
    let mut result = Vec::with_capacity(4 + phy.len() + shim.len() + payload.len());
    result.extend_from_slice(&u16::try_from(phy.len()).ok()?.to_be_bytes());
    result.extend_from_slice(&phy);
    result.extend_from_slice(&u16::try_from(shim.len()).ok()?.to_be_bytes());
    result.extend_from_slice(&shim);
    result.extend_from_slice(payload);
    Some(result)
}

struct DecodedLegacyOta {
    payload: Vec<u8>,
    _control_payloads: Vec<Vec<u8>>,
    messages: Vec<FfiControlMessage>,
}

impl DecodedLegacyOta {
    fn controls(&self) -> &[FfiControlMessage] {
        &self.messages
    }
}

fn decode_legacy_ota_payload(data: &[u8], source: u16) -> Option<DecodedLegacyOta> {
    let phy_length = usize::from(u16::from_be_bytes(data.get(..2)?.try_into().ok()?));
    let phy_end = 2usize.checked_add(phy_length)?;
    let phy = CommonPhyHeader::decode(data.get(2..phy_end)?).ok()?;
    if phy.registration_id == PHY_COMM_EFFECT_REGISTRATION {
        let shim_length_end = phy_end.checked_add(2)?;
        let shim_length = usize::from(u16::from_be_bytes(
            data.get(phy_end..shim_length_end)?.try_into().ok()?,
        ));
        let shim_end = shim_length_end.checked_add(shim_length)?;
        let shim = CommEffectShimHeader::decode(data.get(shim_length_end..shim_end)?).ok()?;
        let header = CommEffectHeader {
            group_id: shim.group_id,
            sequence: shim.sequence_number,
            tx_time_microseconds: i64::try_from(shim.tx_time_microseconds).unwrap_or(i64::MAX),
        }
        .encode()
        .to_vec();
        let messages = vec![FfiControlMessage {
            msg_type: CONTROL_COMM_EFFECT_HEADER,
            payload: FfiSlice {
                data: header.as_ptr(),
                len: header.len(),
            },
        }];
        return Some(DecodedLegacyOta {
            payload: data.get(shim_end..)?.to_vec(),
            _control_payloads: vec![header],
            messages,
        });
    }
    if phy.registration_id != PHY_FRAMEWORK_REGISTRATION
        && phy.registration_id != PHY_BYPASS_REGISTRATION
    {
        return None;
    }
    let (mac, mac_end) = if let Some(length_bytes) = data.get(phy_end..phy_end.checked_add(2)?) {
        let mac_length = usize::from(u16::from_be_bytes(length_bytes.try_into().ok()?));
        let mac_start = phy_end + 2;
        let mac_end = mac_start.checked_add(mac_length)?;
        match CommonMacHeader::decode(data.get(mac_start..mac_end)?).ok() {
            Some(mac) => (Some(mac), mac_end),
            None => (None, phy_end),
        }
    } else {
        (None, phy_end)
    };
    if phy.registration_id == PHY_BYPASS_REGISTRATION {
        let mut payloads = Vec::new();
        let mut messages = Vec::new();
        if let Some(mac) = mac {
            let header = ModelHeader {
                registration_id: mac.registration_id.try_into().ok()?,
                sequence: mac.sequence_number,
                data_rate_bps: 0,
                category: 0,
                message_type: 0,
                flags: 0,
            }
            .encode()
            .to_vec();
            messages.push(FfiControlMessage {
                msg_type: CONTROL_MODEL_HEADER,
                payload: FfiSlice {
                    data: header.as_ptr(),
                    len: header.len(),
                },
            });
            payloads.push(header);
        }
        return Some(DecodedLegacyOta {
            payload: data.get(mac_end..)?.to_vec(),
            _control_payloads: payloads,
            messages,
        });
    }
    let tx_power_dbm = phy
        .transmitters
        .iter()
        .find(|transmitter| transmitter.nem_id == u32::from(source))
        .or_else(|| phy.transmitters.first())
        .map(|transmitter| transmitter.powerd_bm)?;
    let first_antenna = phy.transmit_antennas.first()?;
    let first_group = phy
        .frequency_groups
        .get(usize::try_from(first_antenna.frequency_group_index).ok()?)?;
    let first_segment = first_group.frequency_segments.first()?;
    let start = first_group
        .frequency_segments
        .iter()
        .map(|segment| segment.offset_microseconds)
        .min()?;
    let duration = first_group
        .frequency_segments
        .iter()
        .map(|segment| {
            segment
                .offset_microseconds
                .saturating_add(segment.duration_microseconds)
        })
        .max()?
        .saturating_sub(start)
        .max(1);
    let tx = TxProperties {
        frequency_hz: first_segment.frequency_hz,
        bandwidth_hz: first_antenna.bandwidth_hz,
        tx_power_dbm: first_segment.powerd_bm.unwrap_or(tx_power_dbm),
        duration_microseconds: duration,
        offset_microseconds: start,
        tx_time_microseconds: i64::try_from(phy.tx_time_microseconds).unwrap_or(i64::MAX),
        antenna_index: u16::try_from(first_antenna.antenna_index).ok()?,
        spectral_mask_index: u16::try_from(first_antenna.spectral_mask_index.unwrap_or(0)).ok()?,
        sub_id: u16::try_from(phy.sub_id).ok()?,
    }
    .encode()
    .to_vec();
    let segments = TxFrequencySegments {
        segments: first_group
            .frequency_segments
            .iter()
            .map(|segment| TxFrequencySegment {
                frequency_hz: segment.frequency_hz,
                duration_microseconds: segment.duration_microseconds,
                offset_microseconds: segment.offset_microseconds,
            })
            .collect(),
    }
    .encode()?;
    let transmitters = TxTransmitters {
        transmitters: phy
            .transmitters
            .iter()
            .filter_map(|transmitter| {
                Some(TxTransmitter {
                    nem_id: u16::try_from(transmitter.nem_id).ok()?,
                    tx_power_dbm: transmitter.powerd_bm,
                })
            })
            .collect(),
    }
    .encode()?;
    let mimo = MimoTxProperties {
        frequency_groups: phy
            .frequency_groups
            .iter()
            .map(|group| {
                group
                    .frequency_segments
                    .iter()
                    .map(|segment| MimoTxFrequencySegment {
                        frequency_hz: segment.frequency_hz,
                        tx_power_dbm: segment.powerd_bm,
                        duration_microseconds: segment.duration_microseconds,
                        offset_microseconds: segment.offset_microseconds,
                    })
                    .collect()
            })
            .collect(),
        transmit_antennas: phy
            .transmit_antennas
            .iter()
            .filter_map(|antenna| {
                let pattern = if let Some(gain_db) = antenna.fixed_gaind_bi {
                    AntennaPattern::IdealOmni { gain_db }
                } else if let Some(pointing) = &antenna.pointing {
                    AntennaPattern::Profile(TxAntennaProfile {
                        profile_id: u16::try_from(pointing.profile_id).ok()?,
                        azimuth_degrees: pointing.azimuth_degrees,
                        elevation_degrees: pointing.elevation_degrees,
                    })
                } else {
                    AntennaPattern::Default
                };
                Some(MimoTxAntenna {
                    frequency_group_index: u16::try_from(antenna.frequency_group_index).ok()?,
                    antenna_index: u16::try_from(antenna.antenna_index).ok()?,
                    bandwidth_hz: antenna.bandwidth_hz,
                    spectral_mask_index: u16::try_from(antenna.spectral_mask_index.unwrap_or(0))
                        .ok()?,
                    pattern,
                })
            })
            .collect(),
    }
    .encode()?;
    let mut control_payloads = Vec::new();
    let mut kinds = Vec::new();
    if let Some(data) = phy.filter_data {
        control_payloads.push(data);
        kinds.push(CONTROL_SPECTRUM_FILTER_DATA);
    }
    if let Some(mac) = mac {
        control_payloads.push(
            ModelHeader {
                registration_id: u16::try_from(mac.registration_id).ok()?,
                sequence: mac.sequence_number,
                data_rate_bps: 0,
                category: 0,
                message_type: u8::from(mac.registration_id == u32::from(MAC_REGISTRATION_BENTPIPE)),
                flags: 0,
            }
            .encode()
            .to_vec(),
        );
        kinds.push(CONTROL_MODEL_HEADER);
    }
    control_payloads.extend([tx, segments, transmitters, mimo.to_vec()]);
    kinds.extend([
        CONTROL_TX_PROPERTIES,
        CONTROL_TX_FREQUENCY_SEGMENTS,
        CONTROL_TX_TRANSMITTERS,
        CONTROL_MIMO_TX_PROPERTIES,
    ]);
    let messages = kinds
        .into_iter()
        .zip(control_payloads.iter())
        .map(|(msg_type, payload)| FfiControlMessage {
            msg_type,
            payload: FfiSlice {
                data: payload.as_ptr(),
                len: payload.len(),
            },
        })
        .collect();
    Some(DecodedLegacyOta {
        payload: data.get(mac_end..)?.to_vec(),
        _control_payloads: control_payloads,
        messages,
    })
}

struct DecodedControls {
    _payloads: Vec<Vec<u8>>,
    messages: Vec<FfiControlMessage>,
}

fn decode_controls(data: &[u8]) -> Option<DecodedControls> {
    if data.len() < 2 || data.len() > MAX_CONTROL_WIRE_SIZE {
        return None;
    }
    let count = u16::from_be_bytes(data[..2].try_into().ok()?) as usize;
    let mut offset = 2usize;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let header_end = offset.checked_add(8)?;
        if header_end > data.len() {
            return None;
        }
        let msg_type = u32::from_be_bytes(data[offset..offset + 4].try_into().ok()?);
        let len = u32::from_be_bytes(data[offset + 4..header_end].try_into().ok()?) as usize;
        offset = header_end;
        let end = offset.checked_add(len)?;
        if end > data.len() {
            return None;
        }
        entries.push((msg_type, data[offset..end].to_vec()));
        offset = end;
    }
    if offset != data.len() {
        return None;
    }
    let payloads: Vec<Vec<u8>> = entries.iter().map(|(_, payload)| payload.clone()).collect();
    let messages = entries
        .iter()
        .zip(payloads.iter())
        .map(|((msg_type, _), payload)| FfiControlMessage {
            msg_type: *msg_type,
            payload: FfiSlice {
                data: payload.as_ptr(),
                len: payload.len(),
            },
        })
        .collect();
    Some(DecodedControls {
        _payloads: payloads,
        messages,
    })
}

struct TimerDispatch {
    runtime: Weak<Runtime>,
    nem_id: u16,
    layer_index: usize,
    plugin_event_id: u32,
    data: Vec<u8>,
}

extern "C" fn timer_dispatch(
    timer_id: usize,
    expire: u64,
    schedule: u64,
    fire: u64,
    _arg: *const c_void,
    user: *mut c_void,
) {
    let Some(dispatch) = (unsafe { (user as *const TimerDispatch).as_ref() }) else {
        return;
    };
    if let Some(runtime) = dispatch.runtime.upgrade() {
        if let Some(layer) = runtime.invocation(dispatch.nem_id, dispatch.layer_index) {
            layer.process_timed_event(
                timer_id as u64,
                dispatch.plugin_event_id,
                &dispatch.data,
                expire,
                schedule,
                fire,
            );
        }
    }
}

extern "C" fn timer_dispatch_free(user: *mut c_void) {
    if !user.is_null() {
        unsafe { drop(Box::from_raw(user as *mut TimerDispatch)) };
    }
}

fn context(ctx: *mut c_void) -> Option<&'static FrameworkContext> {
    unsafe { (ctx as *const FrameworkContext).as_ref() }
}

extern "C" fn send_downstream_packet(
    ctx: *mut c_void,
    _nem_id: u16,
    packet: *const FfiPacket,
    messages: *const FfiControlMessage,
    count: usize,
) {
    if let Some(ctx) = context(ctx) {
        if let Some(runtime) = ctx.runtime.upgrade() {
            runtime.route_downstream(ctx.nem_id, ctx.layer_index, packet, messages, count);
        }
    }
}

extern "C" fn send_upstream_packet(
    ctx: *mut c_void,
    _nem_id: u16,
    packet: *const FfiPacket,
    messages: *const FfiControlMessage,
    count: usize,
) {
    if let Some(ctx) = context(ctx) {
        if let Some(runtime) = ctx.runtime.upgrade() {
            runtime.route_upstream(ctx.nem_id, ctx.layer_index, packet, messages, count);
        }
    }
}

extern "C" fn send_downstream_control(
    ctx: *mut c_void,
    _nem_id: u16,
    messages: *const FfiControlMessage,
    count: usize,
) {
    if let Some(ctx) = context(ctx) {
        if let Some(runtime) = ctx.runtime.upgrade() {
            runtime.route_control(ctx.nem_id, ctx.layer_index, true, messages, count);
        }
    }
}

extern "C" fn send_upstream_control(
    ctx: *mut c_void,
    _nem_id: u16,
    messages: *const FfiControlMessage,
    count: usize,
) {
    if let Some(ctx) = context(ctx) {
        if let Some(runtime) = ctx.runtime.upgrade() {
            runtime.route_control(ctx.nem_id, ctx.layer_index, false, messages, count);
        }
    }
}

fn timed_event_expiration(requested: u64, now: u64) -> u64 {
    if requested >= now {
        requested
    } else if requested < now / 2 {
        // The plugin API historically accepts small relative intervals as
        // well as absolute epoch timestamps.
        now.saturating_add(requested)
    } else {
        // An absolute deadline can become slightly stale while a packet moves
        // through the model stack. Fire it immediately instead of treating an
        // epoch timestamp as a relative interval measured in millennia.
        now
    }
}

extern "C" fn schedule_timed_event(
    ctx: *mut c_void,
    _nem_id: u16,
    time_sec: u64,
    time_usec: u32,
    event_id: u32,
    data: *const u8,
    data_len: usize,
) -> u64 {
    let Some(ctx) = context(ctx) else { return 0 };
    let Some(runtime) = ctx.runtime.upgrade() else {
        return 0;
    };
    let payload = if data.is_null() || data_len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(data, data_len) }.to_vec()
    };
    let dispatch = Box::new(TimerDispatch {
        runtime: Arc::downgrade(&runtime),
        nem_id: ctx.nem_id,
        layer_index: ctx.layer_index,
        plugin_event_id: event_id,
        data: payload,
    });
    let requested = time_sec
        .saturating_mul(1_000_000)
        .saturating_add(time_usec as u64);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64;
    let expiration = timed_event_expiration(requested, now);
    emane_rs_timer_schedule(
        expiration,
        0,
        std::ptr::null(),
        Box::into_raw(dispatch) as *mut c_void,
        timer_dispatch,
        Some(timer_dispatch_free),
    ) as u64
}

extern "C" fn cancel_timed_event(_ctx: *mut c_void, _nem_id: u16, timer_id: u64) {
    emane_rs_timer_cancel(timer_id as usize);
}

extern "C" fn log(_ctx: *mut c_void, level: u32, message: *const std::os::raw::c_char) {
    if !message.is_null() {
        let message = unsafe { CStr::from_ptr(message) }.to_string_lossy();
        eprintln!("[EMANE:{level}] {message}");
    }
}

extern "C" fn register_counter(
    ctx: *mut c_void,
    name: *const std::os::raw::c_char,
    description: *const std::os::raw::c_char,
    clearable: bool,
) -> u64 {
    let (Some(ctx), Some(name), Some(description)) = (
        context(ctx),
        (!name.is_null()).then(|| unsafe { CStr::from_ptr(name) }),
        (!description.is_null()).then(|| unsafe { CStr::from_ptr(description) }),
    ) else {
        return 0;
    };
    let (Ok(name), Ok(description)) = (name.to_str(), description.to_str()) else {
        return 0;
    };
    register_native_counter(ctx.build_id, name, description, clearable).unwrap_or(0)
}
extern "C" fn register_counter32(
    ctx: *mut c_void,
    name: *const std::os::raw::c_char,
    description: *const std::os::raw::c_char,
    clearable: bool,
) -> u64 {
    let (Some(ctx), Some(name), Some(description)) = (
        context(ctx),
        (!name.is_null()).then(|| unsafe { CStr::from_ptr(name) }),
        (!description.is_null()).then(|| unsafe { CStr::from_ptr(description) }),
    ) else {
        return 0;
    };
    let (Ok(name), Ok(description)) = (name.to_str(), description.to_str()) else {
        return 0;
    };
    crate::statistics::register_native_counter32(ctx.build_id, name, description, clearable)
        .unwrap_or(0)
}

extern "C" fn increment_counter(ctx: *mut c_void, handle: u64, amount: u64) -> bool {
    context(ctx).is_some() && handle != 0 && increment_native_counter(handle, amount)
}

extern "C" fn maximize_counter(ctx: *mut c_void, handle: u64, value: u64) -> bool {
    context(ctx).is_some() && handle != 0 && maximize_native_counter(handle, value)
}

extern "C" fn register_double(
    ctx: *mut c_void,
    name: *const std::os::raw::c_char,
    description: *const std::os::raw::c_char,
    clearable: bool,
) -> u64 {
    let (Some(ctx), Some(name), Some(description)) = (
        context(ctx),
        (!name.is_null()).then(|| unsafe { CStr::from_ptr(name) }),
        (!description.is_null()).then(|| unsafe { CStr::from_ptr(description) }),
    ) else {
        return 0;
    };
    let (Ok(name), Ok(description)) = (name.to_str(), description.to_str()) else {
        return 0;
    };
    register_native_double(ctx.build_id, name, description, clearable).unwrap_or(0)
}

extern "C" fn set_double(ctx: *mut c_void, handle: u64, value: f64) -> bool {
    context(ctx).is_some() && handle != 0 && set_native_double(handle, value)
}

extern "C" fn register_average(
    ctx: *mut c_void,
    name: *const std::os::raw::c_char,
    description: *const std::os::raw::c_char,
    clearable: bool,
) -> u64 {
    let (Some(ctx), Some(name), Some(description)) = (
        context(ctx),
        (!name.is_null()).then(|| unsafe { CStr::from_ptr(name) }),
        (!description.is_null()).then(|| unsafe { CStr::from_ptr(description) }),
    ) else {
        return 0;
    };
    let (Ok(name), Ok(description)) = (name.to_str(), description.to_str()) else {
        return 0;
    };
    register_native_float_average(ctx.build_id, name, description, clearable).unwrap_or(0)
}

extern "C" fn sample_average(ctx: *mut c_void, handle: u64, sample: f64) -> bool {
    context(ctx).is_some() && handle != 0 && sample_native_average(handle, sample)
}

extern "C" fn register_table(
    ctx: *mut c_void,
    name: *const std::os::raw::c_char,
    labels: *const *const std::os::raw::c_char,
    label_count: usize,
    description: *const std::os::raw::c_char,
    clearable: bool,
) -> u64 {
    let Some(ctx) = context(ctx) else { return 0 };
    if name.is_null()
        || description.is_null()
        || label_count == 0
        || label_count > 256
        || labels.is_null()
    {
        return 0;
    }
    let (Ok(name), Ok(description)) = (
        unsafe { CStr::from_ptr(name) }.to_str(),
        unsafe { CStr::from_ptr(description) }.to_str(),
    ) else {
        return 0;
    };
    let labels = unsafe { std::slice::from_raw_parts(labels, label_count) };
    let Some(labels) = labels
        .iter()
        .map(|label| {
            (!label.is_null())
                .then(|| unsafe { CStr::from_ptr(*label) }.to_str().ok())
                .flatten()
        })
        .collect::<Option<Vec<_>>>()
    else {
        return 0;
    };
    register_native_table(ctx.build_id, name, &labels, description, clearable).unwrap_or(0)
}

extern "C" fn set_table_row(
    ctx: *mut c_void,
    handle: u64,
    key: *const u64,
    key_count: usize,
    values: *const FfiStatisticValue,
    value_count: usize,
) -> bool {
    if context(ctx).is_none()
        || handle == 0
        || key_count == 0
        || key_count > 16
        || key.is_null()
        || value_count == 0
        || value_count > 256
        || values.is_null()
    {
        return false;
    }
    let key = unsafe { std::slice::from_raw_parts(key, key_count) }.to_vec();
    let values = unsafe { std::slice::from_raw_parts(values, value_count) };
    let Some(values) = values
        .iter()
        .map(|value| match value.value_type {
            STATISTIC_VALUE_U16 => u16::try_from(value.u64_value)
                .ok()
                .map(NativeTableValue::UInt16),
            STATISTIC_VALUE_U64 => Some(NativeTableValue::UInt64(value.u64_value)),
            STATISTIC_VALUE_U8 => u8::try_from(value.u64_value)
                .ok()
                .map(NativeTableValue::UInt8),
            STATISTIC_VALUE_U32 => u32::try_from(value.u64_value)
                .ok()
                .map(NativeTableValue::UInt32),
            STATISTIC_VALUE_I64 => Some(NativeTableValue::Int64(value.u64_value as i64)),
            STATISTIC_VALUE_F64 if value.f64_value.is_finite() => {
                Some(NativeTableValue::Double(value.f64_value))
            }
            STATISTIC_VALUE_STRING if !value.string_value.is_null() => unsafe {
                CStr::from_ptr(value.string_value)
                    .to_str()
                    .ok()
                    .map(|value| NativeTableValue::String(value.to_string()))
            },
            _ => None,
        })
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    set_native_table_row(handle, key, values)
}

extern "C" fn clear_table(ctx: *mut c_void, handle: u64) -> bool {
    context(ctx).is_some() && handle != 0 && clear_native_table(handle)
}

extern "C" fn remove_table_row(
    ctx: *mut c_void,
    handle: u64,
    key: *const u64,
    key_count: usize,
) -> bool {
    if context(ctx).is_none() || handle == 0 || key_count == 0 || key_count > 16 || key.is_null() {
        return false;
    }
    remove_native_table_row(handle, unsafe {
        std::slice::from_raw_parts(key, key_count)
    })
}

extern "C" fn table_generation(ctx: *mut c_void, handle: u64) -> u64 {
    if context(ctx).is_some() && handle != 0 {
        native_table_generation(handle).unwrap_or(0)
    } else {
        0
    }
}

extern "C" fn register_rf_signal_table(ctx: *mut c_void, nem_id: u16) -> u64 {
    let Some(ctx) = context(ctx) else { return 0 };
    register_native_rf_signal_table(ctx.build_id, nem_id).unwrap_or(0)
}

extern "C" fn configure_rf_signal_table(
    ctx: *mut c_void,
    handle: u64,
    average_all_antennas: bool,
    average_all_frequencies: bool,
) -> bool {
    context(ctx).is_some()
        && handle != 0
        && configure_native_rf_signal_table(handle, average_all_antennas, average_all_frequencies)
}

#[allow(clippy::too_many_arguments)]
extern "C" fn update_rf_signal_table(
    ctx: *mut c_void,
    handle: u64,
    source: u16,
    antenna: u16,
    frequency_hz: u64,
    rx_power_dbm: f64,
    sinr_db: f64,
    noise_floor_dbm: f64,
    receiver_sensitivity_dbm: f64,
) -> bool {
    context(ctx).is_some()
        && handle != 0
        && update_native_rf_signal_table(
            handle,
            source,
            antenna,
            frequency_hz,
            rx_power_dbm,
            sinr_db,
            noise_floor_dbm,
            receiver_sensitivity_dbm,
        )
}

extern "C" fn publish_event(
    ctx: *mut c_void,
    event_id: u16,
    data: *const u8,
    data_len: usize,
) -> bool {
    let Some(ctx) = context(ctx) else {
        return false;
    };
    if data_len > 16 * 1024 * 1024 || (data_len != 0 && data.is_null()) {
        return false;
    }
    // Native publication is a broadcast. The event payload identifies its
    // source; the routing NEM id is the destination selector, not the source.
    emane_rs_event_service_send_event(ctx.build_id, 0, event_id, data.cast(), data_len);
    true
}

extern "C" fn update_neighbor_tx(
    ctx: *mut c_void,
    destination: u16,
    data_rate_bps: u64,
    tx_time_microseconds: u64,
) {
    let Some(context) = context(ctx) else {
        return;
    };
    if let Ok(mut metrics) = context.neighbor_metrics.lock() {
        if metrics.get_neighbor_metric_status(destination).is_none() {
            initialize_neighbor_status_row(context, destination);
        }
        metrics.handle_tx_activity(
            destination,
            data_rate_bps,
            Duration::from_micros(tx_time_microseconds),
        );
        if let Some(status) = metrics.get_neighbor_metric_status(destination) {
            update_neighbor_metric_table(context, status);
        }
    }
}

extern "C" fn update_neighbor_rx(
    ctx: *mut c_void,
    source: u16,
    sequence: u64,
    uuid: *const u8,
    sinr_db: f64,
    noise_floor_dbm: f64,
    rx_time_microseconds: u64,
    duration_microseconds: u64,
    data_rate_bps: u64,
) {
    let Some(context) = context(ctx) else {
        return;
    };
    if uuid.is_null() {
        return;
    }
    let uuid: &[u8; 16] = unsafe { &*(uuid.cast()) };
    if let Ok(mut metrics) = context.neighbor_metrics.lock() {
        if metrics.get_neighbor_metric_status(source).is_none() {
            initialize_neighbor_status_row(context, source);
        }
        metrics.handle_rx_activity(
            source,
            sequence,
            uuid,
            sinr_db,
            noise_floor_dbm,
            Duration::from_micros(rx_time_microseconds),
            Duration::from_micros(duration_microseconds),
            data_rate_bps,
        );
        if let Some(status) = metrics.get_neighbor_metric_status(source) {
            update_neighbor_metric_table(context, status);
        }
    }
}

fn initialize_neighbor_status_row(context: &FrameworkContext, neighbor: u16) {
    let handle = context
        .compatibility_tables
        .lock()
        .ok()
        .and_then(|tables| tables.get("NeighborStatusTable").copied());
    if let Some(handle) = handle {
        // C++ lookupNeighborData creates both public rows immediately; interval
        // status remains zero until the first explicit status update.
        let _ = set_native_table_row(
            handle,
            vec![u64::from(neighbor)],
            vec![
                NativeTableValue::UInt16(neighbor),
                NativeTableValue::UInt64(0),
                NativeTableValue::UInt64(0),
                NativeTableValue::UInt64(0),
                NativeTableValue::Double(0.0),
                NativeTableValue::Double(0.0),
                NativeTableValue::Double(0.0),
                NativeTableValue::Double(0.0),
            ],
        );
    }
}

extern "C" fn update_neighbor_status(ctx: *mut c_void) {
    let Some(context) = context(ctx) else {
        return;
    };
    let handle = context
        .compatibility_tables
        .lock()
        .ok()
        .and_then(|tables| tables.get("NeighborStatusTable").copied());
    let Some(handle) = handle else { return };
    let statuses = context
        .neighbor_metrics
        .lock()
        .map(|mut manager| {
            manager.get_neighbor_statuses(Duration::from_micros(
                unix_time_microseconds().max(0) as u64
            ))
        })
        .unwrap_or_default();
    for status in statuses {
        let _ = set_native_table_row(
            handle,
            vec![u64::from(status.neighbor_id)],
            vec![
                NativeTableValue::UInt16(status.neighbor_id),
                NativeTableValue::UInt64(status.num_rx_frames),
                NativeTableValue::UInt64(status.num_tx_frames),
                NativeTableValue::UInt64(status.num_rx_missed_frames),
                NativeTableValue::Double(status.bandwidth_utilization_ratio),
                NativeTableValue::Double(status.sinr_avg),
                NativeTableValue::Double(status.noise_floor_avg),
                NativeTableValue::Double(status.rx_age_seconds),
            ],
        );
    }
}

fn update_neighbor_metric_table(
    context: &FrameworkContext,
    status: crate::neighbor_metric_manager::NeighborMetricStatus,
) {
    let handle = context
        .compatibility_tables
        .lock()
        .ok()
        .and_then(|tables| tables.get("NeighborMetricTable").copied());
    let Some(handle) = handle else { return };
    let _ = set_native_table_row(
        handle,
        vec![u64::from(status.neighbor_id)],
        vec![
            NativeTableValue::UInt16(status.neighbor_id),
            NativeTableValue::UInt64(status.num_rx_frames),
            NativeTableValue::UInt64(status.num_tx_frames),
            NativeTableValue::UInt64(status.num_rx_missed_frames),
            if status.num_rx_frames == 0 {
                NativeTableValue::UInt64(0)
            } else {
                NativeTableValue::Int64(status.rx_utilization_microseconds as i64)
            },
            NativeTableValue::Double(status.last_rx_time_seconds),
            NativeTableValue::Double(status.last_tx_time_seconds),
            NativeTableValue::Double(status.sinr_avg),
            NativeTableValue::Double(status.sinr_std),
            NativeTableValue::Double(status.noise_floor_avg),
            NativeTableValue::Double(status.noise_floor_stdv),
            if status.num_rx_frames == 0 {
                NativeTableValue::Double(0.0)
            } else {
                NativeTableValue::UInt64(status.rx_data_rate_avg)
            },
            if status.num_tx_frames == 0 {
                NativeTableValue::Double(0.0)
            } else {
                NativeTableValue::UInt64(status.tx_data_rate_avg)
            },
        ],
    );
}

// Share only the monitor, never the mutable PHY state, with other layer queues.
fn register_spectrum_monitors(state: &BuiltinState) {
    let Some(runtime) =
        context(state.framework.framework_ctx).and_then(|ctx| ctx.runtime.upgrade())
    else {
        return;
    };
    let Ok(mut monitors) = runtime.spectrum_monitors.write() else {
        return;
    };
    monitors.retain(|(nem, _), _| *nem != state.id);
    if state.phy.compatibility_mode == 1 {
        monitors.insert((state.id, 0), Arc::downgrade(&state.phy.monitor));
    }
    for (index, antenna) in &state.phy.receive_antennas {
        monitors.insert((state.id, *index), Arc::downgrade(&antenna.monitor));
    }
}

extern "C" fn query_spectrum(
    ctx: *mut c_void,
    query: *const FfiSpectrumQuery,
    result: *mut FfiSpectrumResult,
) -> bool {
    let (Some(ctx), Some(query), Some(result)) =
        (context(ctx), unsafe { query.as_ref() }, unsafe {
            result.as_mut()
        })
    else {
        return false;
    };
    let Some(runtime) = ctx.runtime.upgrade() else {
        return false;
    };
    let monitor = runtime.spectrum_monitors.read().ok().and_then(|monitors| {
        monitors
            .get(&(ctx.nem_id, query.antenna_index))
            .and_then(Weak::upgrade)
    });
    let Some(monitor) = monitor else { return false };
    let Some(value) = monitor
        .lock()
        .ok()
        .and_then(|monitor| monitor.reception_noise(unix_time_microseconds(), query))
    else {
        return false;
    };
    *result = value;
    true
}

extern "C" fn query_spectrum_filter(
    ctx: *mut c_void,
    query: *const FfiFilterQuery,
    result: *mut FfiFilterResult,
) -> bool {
    let (Some(ctx), Some(query), Some(result)) =
        (context(ctx), unsafe { query.as_ref() }, unsafe {
            result.as_mut()
        })
    else {
        return false;
    };
    let Some(runtime) = ctx.runtime.upgrade() else {
        return false;
    };
    let monitor = runtime.spectrum_monitors.read().ok().and_then(|m| {
        m.get(&(ctx.nem_id, query.antenna_index))
            .and_then(Weak::upgrade)
    });
    let Some(monitor) = monitor else {
        return false;
    };
    let Some((data, start, bin, sensitivity, subbands)) = monitor.lock().ok().and_then(|m| {
        m.try_filter_window(
            unix_time_microseconds(),
            query.filter_index,
            i64::try_from(query.duration_microseconds).ok()?,
            query.start_time_microseconds,
        )
    }) else {
        return false;
    };
    result.length = data.len();
    result.start_time_microseconds = start;
    result.bin_size_microseconds = bin;
    result.sensitivity_mw = sensitivity;
    result.sub_band_count = subbands;
    if result.capacity == 0 {
        return true;
    }
    if result.capacity < data.len() || result.data.is_null() {
        return false;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(data.as_ptr(), result.data, data.len());
    }
    true
}

fn filter_data(messages: &[FfiControlMessage]) -> Option<Vec<u8>> {
    messages
        .iter()
        .find(|m| m.msg_type == CONTROL_SPECTRUM_FILTER_DATA)
        .and_then(|m| {
            if m.payload.len == 0 {
                Some(Vec::new())
            } else if m.payload.data.is_null() {
                None
            } else {
                Some(unsafe { std::slice::from_raw_parts(m.payload.data, m.payload.len) }.to_vec())
            }
        })
}

extern "C" fn register_queue_metric(ctx: *mut c_void, queue_id: u16, max_size: u32) -> bool {
    let Some(context) = (unsafe { (ctx as *const FrameworkContext).as_ref() }) else {
        return false;
    };
    context
        .queue_metrics
        .lock()
        .map(|mut metrics| metrics.add_queue_metric(queue_id, max_size))
        .unwrap_or(false)
}

extern "C" fn update_queue_metric(
    ctx: *mut c_void,
    queue_id: u16,
    max_size: u32,
    current_depth: u32,
    num_discards: u32,
    delay_microseconds: u64,
) {
    let Some(context) = context(ctx) else {
        return;
    };
    if let Ok(mut metrics) = context.queue_metrics.lock() {
        metrics.update_queue_metric(
            queue_id,
            max_size,
            current_depth,
            num_discards,
            delay_microseconds,
        );
    }
}

extern "C" fn publish_r2ri(
    ctx: *mut c_void,
    broadcast_data_rate_bps: u64,
    max_data_rate_bps: u64,
    report_interval_microseconds: u64,
    neighbor_delete_microseconds: u64,
) {
    let Some(context) = context(ctx) else {
        return;
    };
    let queue_metrics = context
        .queue_metrics
        .lock()
        .map(|mut manager| manager.get_queue_metrics())
        .unwrap_or_default();
    update_neighbor_status(ctx);
    let neighbor_metrics = context
        .neighbor_metrics
        .lock()
        .map(|mut manager| {
            manager.set_neighbor_delete_time_microseconds(Duration::from_micros(
                neighbor_delete_microseconds,
            ));
            manager
                .get_neighbor_metrics(Duration::from_micros(unix_time_microseconds().max(0) as u64))
        })
        .unwrap_or_default();
    let self_bytes = R2riSelfMetric {
        broadcast_data_rate_bps,
        max_data_rate_bps,
        report_interval_microseconds,
    }
    .encode();
    let queue_bytes = R2riQueueMetrics {
        metrics: queue_metrics
            .into_iter()
            .map(|metric| R2riQueueMetric {
                queue_id: metric.queue_id,
                max_size: metric.queue_max_size,
                current_depth_high_water: metric.queue_current_depth_high_water,
                num_discards_high_water: metric.num_discards_high_water,
                average_delay_microseconds: metric.avg_delay_microseconds,
            })
            .collect(),
    }
    .encode()
    .unwrap_or_default();
    let neighbor_bytes = R2riNeighborMetrics {
        metrics: neighbor_metrics
            .into_iter()
            .map(|metric| R2riNeighborMetric {
                nem_id: metric.neighbor_id,
                num_rx_frames: metric.num_rx_frames,
                num_tx_frames: metric.num_tx_frames,
                num_missed_frames: metric.num_rx_missed_frames,
                bandwidth_consumption_microseconds: metric.rx_utilization_microseconds,
                sinr_average_db: metric.sinr_avg,
                sinr_stddev: metric.sinr_std,
                noise_floor_average_dbm: metric.noise_floor_avg,
                noise_floor_stddev: metric.noise_floor_stdv,
                rx_average_data_rate_bps: metric.rx_data_rate_avg,
                tx_average_data_rate_bps: metric.tx_data_rate_avg,
            })
            .collect(),
    }
    .encode()
    .unwrap_or_default();
    let messages = [
        FfiControlMessage {
            msg_type: CONTROL_R2RI_SELF_METRIC,
            payload: FfiSlice {
                data: self_bytes.as_ptr(),
                len: self_bytes.len(),
            },
        },
        FfiControlMessage {
            msg_type: CONTROL_R2RI_QUEUE_METRIC,
            payload: FfiSlice {
                data: queue_bytes.as_ptr(),
                len: queue_bytes.len(),
            },
        },
        FfiControlMessage {
            msg_type: CONTROL_R2RI_NEIGHBOR_METRIC,
            payload: FfiSlice {
                data: neighbor_bytes.as_ptr(),
                len: neighbor_bytes.len(),
            },
        },
    ];
    send_upstream_control(ctx, context.nem_id, messages.as_ptr(), messages.len());
}

pub fn canonical_plugin_name(name: &str) -> &str {
    match name {
        "ieee80211abgmaclayer" | "emane-model-ieee80211abg" => "ieee80211abg",
        "bentpipemaclayer" | "emane-model-bentpipe" => "bentpipe",
        "rfpipemaclayer" | "emane-model-rfpipe" => "rfpipe",
        "tdmaeventschedulerradiomodel" | "tdmamaclayer" => "tdma",
        "transvirtual" => "virtualtransport",
        "transraw" => "rawtransport",
        "bypassmaclayer" => "bypass_mac",
        "bypassphylayer" => "bypass_phy",
        "dummy-mac" | "dummy_mac" => "dummy_mac",
        other => other,
    }
}

pub fn component_configuration_defaults(plugin: &str) -> Vec<(String, Vec<ConfigurationValue>)> {
    component_configuration_schema(plugin)
        .into_iter()
        .map(|(name, spec)| (name, spec.defaults))
        .collect()
}
pub fn component_configuration_schema(
    plugin: &str,
) -> crate::native_configuration::ConfigurationSchema {
    crate::configuration_schema::get(canonical_plugin_name(plugin))
}
pub fn component_modifiable_parameters(plugin: &str) -> Vec<String> {
    component_configuration_schema(plugin)
        .into_iter()
        .filter_map(|(name, spec)| spec.modifiable.then_some(name))
        .collect()
}

fn component_event_ids(plugin: &str) -> &'static [u16] {
    match canonical_plugin_name(plugin) {
        "emanephy" => &[100, 101, 102, 106, 107],
        "commeffectshim" => &[103],
        "ieee80211abg" => &[104],
        "tdma" => &[105],
        _ => &[],
    }
}

fn register_model_compatibility_statistics(build_id: u16, plugin: &str) -> HashMap<String, u64> {
    let mut handles = HashMap::new();
    let counter = |name: &str| {
        if canonical_plugin_name(plugin) == "ieee80211abg" {
            let _ = crate::statistics::register_native_counter32(build_id, name, "", true);
        } else {
            let _ = register_native_counter(
                build_id,
                name,
                "",
                !name.starts_with("numTxSlot") && !name.starts_with("numRxSlot"),
            );
        }
    };
    let mut table = |name: &str, labels: &[&str], description: &str, clearable: bool| {
        if let Some(handle) = register_native_table(build_id, name, labels, description, clearable)
        {
            handles.insert(name.to_string(), handle);
        }
    };
    match canonical_plugin_name(plugin) {
        "rfpipe" => {
            table(
                "NeighborMetricTable",
                &[
                    "NEM",
                    "Rx Pkts",
                    "Tx Pkts",
                    "Missed Pkts",
                    "BW Util",
                    "Last Rx",
                    "Last Tx",
                    "SINR Avg",
                    "SINR Stdv",
                    "NF Avg",
                    "NF Stdv",
                    "Rx Rate Avg",
                    "Tx Rate Avg",
                ],
                "Neighbor metric table.",
                false,
            );
        }
        "ieee80211abg" => {
            for name in [
                "numUnicastPacketsUnsupported",
                "numUnicastBytesUnsupported",
                "numBroadcastPacketsUnsupported",
                "numBroadcastBytesUnsupported",
                "numDownstreamUnicastDataDiscardDueToRetries",
                "numDownstreamUnicastRtsCtsDataDiscardDueToRetries",
                "numUpstreamUnicastDataDiscardDueToSinr",
                "numUpstreamBroadcastDataDiscardDueToSinr",
                "numUpstreamUnicastDataDiscardDueToClobberRxDuringTx",
                "numUpstreamBroadcastDataDiscardDueToClobberRxDuringTx",
                "numUpstreamUnicastDataDiscardDueToClobberRxHiddenBusy",
                "numUpstreamBroadcastDataDiscardDueToClobberRxHiddenBusy",
                "numDownstreamUnicastDataDiscardDueToTxop",
                "numDownstreamBroadcastDataDiscardDueToTxop",
                "numUpstreamUnicastDataNoiseHiddenRx",
                "numUpstreamBroadcastDataNoiseHiddenRx",
                "numUpstreamUnicastDataNoiseRxCommon",
                "numUpstreamBroadcastDataNoiseRxCommon",
                "numUpstreamUnicastRtsCtsDataRxFromPhy",
                "numUpstreamUnicastRtsCtsRxFromPhy",
                "numOneHopNbrHighWaterMark",
                "numTwoHopNbrHighWaterMark",
                "numRxOneHopNbrListEvents",
                "numRxOneHopNbrListInvalidEvents",
                "numTxOneHopNbrListEvents",
            ] {
                counter(name);
            }
            for category in 0..4 {
                for prefix in [
                    "numUnicastPacketsTooLarge",
                    "numUnicastBytesTooLarge",
                    "numBroadcastPacketsTooLarge",
                    "numBroadcastBytesTooLarge",
                    "numHighWaterMark",
                    "numHighWaterMax",
                ] {
                    counter(&format!("{prefix}{category}"));
                }
            }
            table(
                "NeighborMetricTable",
                &[
                    "NEM",
                    "Rx Pkts",
                    "Tx Pkts",
                    "Missed Pkts",
                    "BW Util",
                    "Last Rx",
                    "Last Tx",
                    "SINR Avg",
                    "SINR Stdv",
                    "NF Avg",
                    "NF Stdv",
                    "Rx Rate Avg",
                    "Tx Rate Avg",
                ],
                "Neighbor metric table.",
                false,
            );
        }
        "tdma" => {
            for name in [
                "scheduler.scheduleRejectSlotIndexRange",
                "scheduler.scheduleRejectFrameIndexRange",
                "scheduler.scheduleRejectUpdateBeforeFull",
                "scheduler.scheduleRejectOther",
                "scheduler.scheduleAcceptFull",
                "scheduler.scheduleAcceptUpdate",
                "numTxSlotValid",
                "numTxSlotErrorMissed",
                "numTxSlotErrorTooBig",
                "numRxSlotValid",
                "numRxSlotErrorMissed",
                "numRxSlotErrorRxDuringIdle",
                "numRxSlotErrorRxDuringTx",
                "numRxSlotErrorRxTooLong",
                "numRxSlotErrorRxWrongFrequency",
                "numRxSlotErrorRxLock",
                "highWaterMarkQueue0",
                "highWaterMarkQueue1",
                "highWaterMarkQueue2",
                "highWaterMarkQueue3",
                "highWaterMarkQueue4",
            ] {
                counter(name);
            }
            table(
                "PacketComponentAggregationHistogram",
                &["Components", "Count"],
                "Shows a histogram of the number of components contained in transmitted messages.",
                false,
            );
            table(
                "scheduler.ScheduleInfoTable",
                &[
                    "Index",
                    "Frame",
                    "Slot",
                    "Type",
                    "Frequency",
                    "Data Rate",
                    "Power",
                    "Class",
                    "Destination",
                ],
                "Shows the current TDMA schedule.",
                false,
            );
            table(
                "scheduler.StructureInfoTable",
                &["Name", "Value"],
                "Shows the current TDMA structure.",
                false,
            );
            table(
                "QueueStatusTable",
                &[
                    "Queue", "Enqueued", "Dequeued", "Overflow", "Too Big", "0", "1", "2", "3", "4",
                ],
                "TDMA queue status.",
                false,
            );
            table(
                "QueueFragmentHistogram",
                &["Queue", "1", "2", "3", "4", "5", "6", "7", "8", "9", ">9"],
                "TDMA queue fragment histogram.",
                false,
            );
            table(
                "TxSlotStatusTable",
                &[
                    "Index", "Frame", "Slot", "Valid", "Missed", "Big", ".25", ".50", ".75", "1.0",
                    "1.25", "1.50", "1.75", ">1.75",
                ],
                "TDMA transmit slot status.",
                false,
            );
            table(
                "RxSlotStatusTable",
                &[
                    "Index", "Frame", "Slot", "Valid", "Missed", "Idle", "Tx", "Long", "Freq",
                    "Lock", ".25", ".50", ".75", "1.0", "1.25", "1.50", "1.75", ">1.75",
                ],
                "TDMA receive slot status.",
                false,
            );
            for queue in 0..5 {
                for prefix in [
                    "BroadcastByteAcceptTable",
                    "UnicastByteAcceptTable",
                    "BroadcastByteDropTable",
                    "UnicastByteDropTable",
                ] {
                    let accept = prefix.contains("Accept");
                    table(
                        &format!("{prefix}{queue}"),
                        if accept {
                            &["NEM", "Num Bytes Tx", "Num Bytes Rx"]
                        } else {
                            &[
                                "NEM",
                                "SINR",
                                "Reg Id",
                                "Dst MAC",
                                "Queue Overflow",
                                "Bad Control",
                                "Bad Spectrum Query",
                                "Flow Control",
                                "Big",
                                "Long",
                                "Freq",
                                "Slot Error",
                                "Miss Fragment",
                            ]
                        },
                        "TDMA packet status.",
                        true,
                    );
                }
            }
            table(
                "NeighborMetricTable",
                &[
                    "NEM",
                    "Rx Pkts",
                    "Tx Pkts",
                    "Missed Pkts",
                    "BW Util",
                    "Last Rx",
                    "Last Tx",
                    "SINR Avg",
                    "SINR Stdv",
                    "NF Avg",
                    "NF Stdv",
                    "Rx Rate Avg",
                    "Tx Rate Avg",
                ],
                "Neighbor metric table.",
                false,
            );
        }
        "bentpipe" => {
            for (name, labels) in [
                (
                    "AntennaStatusTable",
                    &[
                        "Index",
                        "Profile",
                        "Bandwidth",
                        "Rx Frequency",
                        "Fixed Gain",
                        "Azimuth",
                        "Elevation",
                        "Mask",
                    ][..],
                ),
                (
                    "NeighborStatusTable",
                    &[
                        "NEM",
                        "Transponder",
                        "SINR_wma",
                        "NF_wma",
                        "Samples",
                        "SINR_avg",
                        "NF_avg",
                        "Timestamp",
                    ],
                ),
                (
                    "QueueStatusTable",
                    &[
                        "Transponder",
                        "Enqueued",
                        "Dequeued",
                        "Overflow",
                        "Too Big",
                        "Depth",
                        "High Water",
                    ],
                ),
                (
                    "QueueFragmentHistogram",
                    &[
                        "Transponder",
                        "1",
                        "2",
                        "3",
                        "4",
                        "5",
                        "6",
                        "7",
                        "8",
                        "9",
                        ">9",
                    ],
                ),
                (
                    "QueueAggregateHistogram",
                    &[
                        "Transponder",
                        "1",
                        "2",
                        "3",
                        "4",
                        "5",
                        "6",
                        "7",
                        "8",
                        "9",
                        ">9",
                    ],
                ),
                (
                    "TxSlotStatusTable",
                    &[
                        "Transponder",
                        "Valid",
                        "Missed",
                        ".25",
                        ".50",
                        ".75",
                        "1.0",
                        "1.25",
                        "1.50",
                        "1.75",
                        ">1.75",
                    ],
                ),
                (
                    "TransponderStatusTable",
                    &[
                        "Idx",
                        "Rx Hz",
                        "Rx Bw",
                        "Rx Ant",
                        "Rx Enable",
                        "Action",
                        "Tx Hz",
                        "Tx Bw",
                        "Tx Bps",
                        "Tx Ant",
                        "Tx dBm",
                        "Tx Enable",
                    ],
                ),
                (
                    "TransponderStatusExTable",
                    &["Idx", "Tx U_Delay", "Tx Slots/Frame", "Tx Slot Size", "MTU"],
                ),
            ] {
                table(name, labels, "BentPipe model status.", false);
            }
        }
        _ => {}
    }
    if matches!(
        canonical_plugin_name(plugin),
        "rfpipe" | "ieee80211abg" | "tdma"
    ) {
        table(
            "NeighborStatusTable",
            &[
                "NEM",
                "Rx Pkts",
                "Tx Pkts",
                "Missed Pkts",
                "BW Util Ratio",
                "SINR Avg",
                "NF Avg",
                "Rx Age",
            ],
            "Neighbor Status Table",
            false,
        );
    }
    handles
}

pub fn resolve_plugin_path(name: &str) -> Result<PathBuf, String> {
    let supplied = Path::new(name);
    if supplied.exists() {
        return Ok(supplied.to_path_buf());
    }
    if supplied.components().count() > 1 || name.ends_with(".so") {
        return Err(format!(
            "plugin path does not exist: {}",
            supplied.display()
        ));
    }
    let canonical = canonical_plugin_name(name);
    let library_basename = match canonical {
        "bypass_mac" => "bypassmaclayer",
        "bypass_phy" => "bypassphylayer",
        other => other,
    };
    let filename = if library_basename.starts_with("lib") && library_basename.ends_with(".so") {
        library_basename.to_string()
    } else {
        format!("lib{library_basename}.so")
    };
    let mut directories = Vec::new();
    if let Some(paths) = std::env::var_os("EMANE_PLUGIN_PATH") {
        directories.extend(std::env::split_paths(&paths));
    }
    if let Ok(executable) = std::env::current_exe() {
        if let Some(parent) = executable.parent() {
            // Unit-test executables live in target/{profile}/deps. Loading a
            // bare cdylib from there can select a stale, pre-ABI-change copy;
            // Cargo's deployable cdylibs are emitted one directory above it.
            if parent.file_name().is_some_and(|name| name == "deps") {
                if let Some(profile) = parent.parent() {
                    directories.push(profile.to_path_buf());
                }
            } else {
                directories.push(parent.to_path_buf());
                // A Make installation places executables in PREFIX/bin and
                // EMANE plugins in PREFIX/lib/emane. Search relative to the
                // executable so non-system prefixes work without setting
                // EMANE_PLUGIN_PATH or modifying the dynamic loader config.
                if let Some(prefix) = parent.parent() {
                    directories.push(prefix.join("lib/emane"));
                    directories.push(prefix.join("lib64/emane"));
                }
            }
        }
    }
    directories.extend([
        PathBuf::from("rust/target/debug"),
        PathBuf::from("rust/target/release"),
        PathBuf::from("target/debug"),
        PathBuf::from("target/release"),
    ]);
    for directory in directories {
        let candidate = directory.join(&filename);
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    // A bare filename lets the platform dynamic loader search its configured
    // system paths (LD_LIBRARY_PATH, ld.so cache, and the platform defaults).
    Ok(PathBuf::from(filename))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BuiltinKind {
    Phy,
    VirtualTransport,
    RawTransport,
}

struct BuiltinState {
    id: u16,
    framework: FfiFrameworkService,
    kind: BuiltinKind,
    virtual_transport: *mut VirtualTransport,
    raw_transport: *mut RawTransport,
    ethernet: Box<EthernetTransportState>,
    device_path: String,
    device_name: String,
    address: IpAddr,
    mask: IpAddr,
    arp_mode: bool,
    broadcast_mode: bool,
    arp_cache_mode: bool,
    arp_priority: u8,
    unknown_priorities: HashMap<u16, u8>,
    flow_control_enabled: bool,
    transport_flow: Mutex<TransportFlow>,
    transport_flow_changed: Condvar,
    bitrate_bps: u64,
    bit_pool: crate::bit_pool::BitPool,
    counters: CommonLayerCounters,
    phy: PhyState,
}

#[derive(Default)]
struct TransportFlow {
    tokens: u16,
    stopped: bool,
}

struct PendingTransportFrame {
    payload: Vec<u8>,
    destination: u16,
    priority: u8,
    creation_time_sec: u64,
    creation_time_usec: u32,
    received_at: Instant,
}

#[path = "mimo_receive.rs"]
mod mimo_receive;

struct PhyState {
    compatibility_mode: u8,
    processing_pool_size: u16,
    processing_pool: Option<crate::processing_pool::ProcessingPool>,
    receive_power_table_enabled: bool,
    observed_power_table_enabled: bool,
    rx_sensitivity_promiscuous_mode_enabled: bool,
    receive_power_table: Option<u64>,
    observed_power_table: Option<u64>,
    location_event_table: Option<u64>,
    pathloss_event_table: Option<u64>,
    pathloss_ex_event_table: Option<u64>,
    antenna_profile_event_table: Option<u64>,
    fading_selection_event_table: Option<u64>,
    radio_silence_drop_counter: u64,
    time_sync_rewrite_counter: u64,
    gain_cache_hit_counter: u64,
    gain_cache_miss_counter: u64,
    gain_cache: HashMap<Vec<u64>, (f64, f64)>,
    gain_antennas: HashMap<(u16, u16), MimoTxAntenna>,
    frequency_hz: u64,
    frequencies_of_interest: Vec<u64>,
    bandwidth_hz: u64,
    tx_power_dbm: f64,
    fixed_antenna_gain_db: f64,
    fixed_antenna_gain_enabled: bool,
    propagation_model: PropagationModel,
    locations: HashMap<u16, Location>,
    pathloss: HashMap<u16, HashMap<u64, f64>>,
    antenna_profiles: HashMap<u16, AntennaProfileSelection>,
    fading_selections: HashMap<u16, FadingMode>,
    fading_mode: FadingMode,
    nakagami: HashMap<u16, crate::nakagami_fading_algorithm::NakagamiFadingAlgorithm>,
    nakagami_parameters: NakagamiParameters,
    lognormal_states: HashMap<u16, LognormalFadingState>,
    lognormal_parameters: LognormalFadingParameters,
    lognormal_configured: bool,
    doppler_shift_enabled: bool,
    spectral_mask_index: u16,
    radio_silence_enabled: bool,
    exclude_same_sub_id_from_filter: bool,
    sub_id: u16,
    noise_mode: NoiseMode,
    noise_bin_size: i64,
    max_segment_offset: i64,
    max_message_propagation: i64,
    max_segment_duration: i64,
    time_sync_threshold: i64,
    noise_max_clamp: bool,
    system_noise_figure_db: f64,
    monitor: Arc<Mutex<SpectrumMonitor>>,
    receive_antennas: HashMap<u16, ReceiveAntennaState>,
}

struct ReceiveAntennaState {
    antenna: MimoTxAntenna,
    monitor: Arc<Mutex<SpectrumMonitor>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PropagationModel {
    Precomputed,
    FreeSpace,
    TwoRay,
}

#[derive(Clone, Copy)]
struct Location {
    latitude_degrees: f64,
    longitude_degrees: f64,
    altitude_meters: f64,
    velocity: Option<Velocity>,
    orientation: Orientation,
}

#[derive(Clone, Copy, Default, PartialEq)]
struct Velocity {
    azimuth_degrees: f64,
    elevation_degrees: f64,
    magnitude_meters_per_second: f64,
}

#[derive(Clone, Copy, Default, PartialEq)]
struct Orientation {
    roll_degrees: f64,
    pitch_degrees: f64,
    yaw_degrees: f64,
}

#[derive(Clone, Copy)]
struct AntennaProfileSelection {
    profile_id: u16,
    azimuth_degrees: f64,
    elevation_degrees: f64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FadingMode {
    None,
    Event,
    Nakagami,
    Lognormal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PhyPathError {
    Propagation,
    GainLocation,
    GainHorizon,
    GainProfile,
    FadeLocation,
    FadeAlgorithm,
    FadeSelection,
}

impl PhyPathError {
    const fn drop_code(self) -> usize {
        match self {
            Self::Propagation => 3,
            Self::GainLocation => 4,
            Self::GainHorizon => 5,
            Self::GainProfile => 6,
            Self::FadeLocation => 9,
            Self::FadeAlgorithm => 10,
            Self::FadeSelection => 11,
        }
    }
}

struct NakagamiParameters {
    distance0_meters: f64,
    distance1_meters: f64,
    m0: f64,
    m1: f64,
    m2: f64,
}

impl PhyState {
    fn new() -> Self {
        Self {
            compatibility_mode: 1,
            processing_pool_size: 0,
            processing_pool: None,
            receive_power_table_enabled: true,
            observed_power_table_enabled: true,
            rx_sensitivity_promiscuous_mode_enabled: false,
            receive_power_table: None,
            observed_power_table: None,
            location_event_table: None,
            pathloss_event_table: None,
            pathloss_ex_event_table: None,
            antenna_profile_event_table: None,
            fading_selection_event_table: None,
            radio_silence_drop_counter: 0,
            time_sync_rewrite_counter: 0,
            gain_cache_hit_counter: 0,
            gain_cache_miss_counter: 0,
            gain_cache: HashMap::new(),
            gain_antennas: HashMap::new(),
            frequency_hz: 2_347_000_000,
            frequencies_of_interest: vec![2_347_000_000],
            bandwidth_hz: 1_000_000,
            tx_power_dbm: 0.0,
            fixed_antenna_gain_db: 0.0,
            fixed_antenna_gain_enabled: true,
            propagation_model: PropagationModel::Precomputed,
            locations: HashMap::new(),
            pathloss: HashMap::new(),
            antenna_profiles: HashMap::new(),
            fading_selections: HashMap::new(),
            fading_mode: FadingMode::None,
            nakagami: HashMap::new(),
            nakagami_parameters: NakagamiParameters {
                distance0_meters: 100.0,
                distance1_meters: 250.0,
                m0: 0.75,
                m1: 1.0,
                m2: 200.0,
            },
            lognormal_states: HashMap::new(),
            lognormal_parameters: LognormalFadingParameters {
                dmu: 5.0,
                dsigma: 1.0,
                dlthresh: 0.25,
                maxpathloss: 100.0,
                duthresh: 0.75,
                minpathloss: 0.0,
                lmean: 0.005,
                lstddev: 0.001,
                counter: 1,
            },
            lognormal_configured: false,
            doppler_shift_enabled: true,
            spectral_mask_index: 0,
            radio_silence_enabled: false,
            exclude_same_sub_id_from_filter: true,
            sub_id: 1,
            noise_mode: NoiseMode::All,
            noise_bin_size: 20,
            max_segment_offset: 300_000,
            max_message_propagation: 200_000,
            max_segment_duration: 1_000_000,
            time_sync_threshold: 10_000,
            noise_max_clamp: false,
            system_noise_figure_db: 4.0,
            monitor: Arc::new(Mutex::new(SpectrumMonitor::new())),
            receive_antennas: HashMap::new(),
        }
    }

    fn update_location(
        &mut self,
        nem_id: u16,
        latitude_degrees: f64,
        longitude_degrees: f64,
        altitude_meters: f64,
        orientation: Option<Orientation>,
        velocity: Option<Velocity>,
    ) {
        let previous = self.locations.get(&nem_id).copied();
        if previous.is_some_and(|old| {
            old.latitude_degrees == latitude_degrees
                && old.longitude_degrees == longitude_degrees
                && old.altitude_meters == altitude_meters
                && orientation.is_none_or(|value| value == old.orientation)
                && velocity.is_none_or(|value| value == old.velocity.unwrap_or_default())
        }) {
            return;
        }
        self.locations.insert(
            nem_id,
            Location {
                latitude_degrees,
                longitude_degrees,
                altitude_meters,
                orientation: orientation
                    .or_else(|| previous.map(|location| location.orientation))
                    .unwrap_or_default(),
                velocity: velocity.or_else(|| previous.and_then(|location| location.velocity)),
            },
        );
        // Preserve every change, including A -> B -> A before the next packet.
        // Incomplete location pairs still share the original invalid sequence.
        self.gain_cache.retain(|key, _| {
            !((key[0] == u64::from(nem_id) || key[1] == u64::from(nem_id))
                && self.locations.contains_key(&(key[0] as u16))
                && self.locations.contains_key(&(key[1] as u16)))
        });
    }

    fn receiver_sensitivity_dbm(&self) -> f64 {
        -174.0 + 10.0 * (self.bandwidth_hz.max(1) as f64).log10() + self.system_noise_figure_db
    }

    #[allow(clippy::too_many_arguments)]
    fn publish_receive_power(
        &self,
        source: u16,
        receive_antenna: u16,
        transmit_antenna: u16,
        frequency_hz: u64,
        receive_power_dbm: f64,
        transmit_gain_db: f64,
        receive_gain_db: f64,
        transmit_power_dbm: f64,
        pathloss_db: f64,
        doppler_shift_hz: f64,
        packet_time_seconds: f64,
    ) {
        if !self.receive_power_table_enabled {
            return;
        }
        if let Some(handle) = self.receive_power_table {
            let _ = set_native_table_row(
                handle,
                vec![
                    u64::from(source),
                    u64::from(receive_antenna),
                    u64::from(transmit_antenna),
                    frequency_hz,
                ],
                vec![
                    NativeTableValue::UInt16(source),
                    NativeTableValue::UInt16(receive_antenna),
                    NativeTableValue::UInt16(transmit_antenna),
                    NativeTableValue::UInt64(frequency_hz),
                    NativeTableValue::Double(receive_power_dbm),
                    NativeTableValue::Double(transmit_gain_db),
                    NativeTableValue::Double(receive_gain_db),
                    NativeTableValue::Double(transmit_power_dbm),
                    NativeTableValue::Double(pathloss_db),
                    NativeTableValue::Double(doppler_shift_hz),
                    NativeTableValue::Double(packet_time_seconds),
                ],
            );
        }
    }

    fn publish_observed_power(
        &self,
        source: u16,
        receive_antenna: u16,
        transmit_antenna: u16,
        frequency_hz: u64,
        spectral_mask_index: u16,
        receive_power_dbm: f64,
        packet_time_seconds: f64,
    ) {
        if !self.observed_power_table_enabled {
            return;
        }
        if let Some(handle) = self.observed_power_table {
            let _ = set_native_table_row(
                handle,
                vec![
                    u64::from(source),
                    u64::from(receive_antenna),
                    u64::from(transmit_antenna),
                    frequency_hz,
                ],
                vec![
                    NativeTableValue::UInt16(source),
                    NativeTableValue::UInt16(receive_antenna),
                    NativeTableValue::UInt16(transmit_antenna),
                    NativeTableValue::UInt64(frequency_hz),
                    NativeTableValue::UInt16(spectral_mask_index),
                    NativeTableValue::Double(receive_power_dbm),
                    NativeTableValue::Double(packet_time_seconds),
                ],
            );
        }
    }

    fn initialize_monitor(&mut self) {
        let sensitivity_mw = 10.0f64.powf(self.receiver_sensitivity_dbm() / 10.0);
        self.monitor.lock().unwrap().initialize(
            self.sub_id,
            &self.frequencies_of_interest,
            self.bandwidth_hz,
            sensitivity_mw,
            self.noise_mode,
            self.noise_bin_size,
            self.max_segment_offset,
            self.max_message_propagation,
            self.max_segment_duration,
            self.time_sync_threshold,
            self.noise_max_clamp,
            self.exclude_same_sub_id_from_filter,
        );
    }

    fn receiver_sensitivity_for_bandwidth_dbm(&self, bandwidth_hz: u64) -> f64 {
        -174.0 + 10.0 * (bandwidth_hz.max(1) as f64).log10() + self.system_noise_figure_db
    }

    fn make_monitor(&self, frequencies_hz: &[u64], bandwidth_hz: u64) -> SpectrumMonitor {
        let sensitivity_mw =
            10.0f64.powf(self.receiver_sensitivity_for_bandwidth_dbm(bandwidth_hz) / 10.0);
        let mut monitor = SpectrumMonitor::new();
        monitor.initialize(
            self.sub_id,
            frequencies_hz,
            bandwidth_hz,
            sensitivity_mw,
            self.noise_mode,
            self.noise_bin_size,
            self.max_segment_offset,
            self.max_message_propagation,
            self.max_segment_duration,
            self.time_sync_threshold,
            self.noise_max_clamp,
            self.exclude_same_sub_id_from_filter,
        );
        monitor
    }

    fn default_antenna_pattern(&self, nem_id: u16) -> Option<AntennaPattern> {
        if self.fixed_antenna_gain_enabled {
            Some(AntennaPattern::IdealOmni {
                gain_db: self.fixed_antenna_gain_db,
            })
        } else {
            self.antenna_profiles.get(&nem_id).map(|profile| {
                AntennaPattern::Profile(TxAntennaProfile {
                    profile_id: profile.profile_id,
                    azimuth_degrees: profile.azimuth_degrees,
                    elevation_degrees: profile.elevation_degrees,
                })
            })
        }
    }

    #[cfg(test)]
    fn antenna_pair_gain(
        &mut self,
        local_id: u16,
        source: u16,
        local_pattern: AntennaPattern,
        remote_pattern: AntennaPattern,
    ) -> Option<f64> {
        self.antenna_pair_gains(local_id, source, local_pattern, remote_pattern)
            .map(|(receive_gain, transmit_gain, _)| receive_gain + transmit_gain)
    }

    #[cfg(test)]
    fn antenna_pair_gains(
        &mut self,
        local_id: u16,
        source: u16,
        local_pattern: AntennaPattern,
        remote_pattern: AntennaPattern,
    ) -> Option<(f64, f64, bool)> {
        self.antenna_pair_gains_detailed(local_id, source, local_pattern, remote_pattern)
            .ok()
    }

    #[cfg(test)]
    fn antenna_pair_gains_detailed(
        &mut self,
        local_id: u16,
        source: u16,
        local_pattern: AntennaPattern,
        remote_pattern: AntennaPattern,
    ) -> Result<(f64, f64, bool), PhyPathError> {
        self.antenna_pair_gains_for(local_id, source, 0, 0, local_pattern, remote_pattern)
    }

    fn update_gain_antenna(&mut self, nem_id: u16, mut antenna: MimoTxAntenna) {
        if antenna.pattern == AntennaPattern::Default && antenna.antenna_index == 0 {
            if let Some(profile) = self.antenna_profiles.get(&nem_id) {
                antenna.pattern = AntennaPattern::Profile(TxAntennaProfile {
                    profile_id: profile.profile_id,
                    azimuth_degrees: profile.azimuth_degrees,
                    elevation_degrees: profile.elevation_degrees,
                });
            }
        }
        let key = (nem_id, antenna.antenna_index);
        if self.gain_antennas.get(&key).is_some_and(|previous| {
            let same_pattern = match (previous.pattern, antenna.pattern) {
                (AntennaPattern::Default, AntennaPattern::Default) => true,
                (
                    AntennaPattern::IdealOmni { gain_db: a },
                    AntennaPattern::IdealOmni { gain_db: b },
                ) => (a - b).abs() < 0.00001,
                (AntennaPattern::Profile(a), AntennaPattern::Profile(b)) => {
                    a.profile_id == b.profile_id
                        && (a.azimuth_degrees - b.azimuth_degrees).abs() < 0.00001
                        && (a.elevation_degrees - b.elevation_degrees).abs() < 0.00001
                }
                _ => false,
            };
            previous.bandwidth_hz == antenna.bandwidth_hz && same_pattern
        }) {
            return;
        }
        // AntennaManager changes its sequence on bandwidth or pattern changes,
        // even if no gain calculation occurs between updates. Group and mask
        // indices are not part of the original Antenna equality comparison.
        self.gain_antennas.insert(key, antenna);
        self.gain_cache.retain(|pair, _| {
            !(pair[0] == u64::from(nem_id) && pair[2] == u64::from(antenna.antenna_index)
                || pair[1] == u64::from(nem_id) && pair[3] == u64::from(antenna.antenna_index))
        });
    }

    fn antenna_pair_gains_for(
        &mut self,
        local_id: u16,
        source: u16,
        receive_index: u16,
        transmit_index: u16,
        local_pattern: AntennaPattern,
        remote_pattern: AntennaPattern,
    ) -> Result<(f64, f64, bool), PhyPathError> {
        let local_pattern = self
            .gain_antennas
            .get(&(local_id, receive_index))
            .map_or(local_pattern, |a| a.pattern);
        let remote_pattern = self
            .gain_antennas
            .get(&(source, transmit_index))
            .map_or(remote_pattern, |a| a.pattern);
        let local_pattern = match local_pattern {
            AntennaPattern::Default => self
                .default_antenna_pattern(local_id)
                .ok_or(PhyPathError::GainProfile)?,
            pattern => pattern,
        };
        let remote_pattern = match remote_pattern {
            AntennaPattern::Default => self
                .antenna_profiles
                .get(&source)
                .map(|profile| {
                    AntennaPattern::Profile(TxAntennaProfile {
                        profile_id: profile.profile_id,
                        azimuth_degrees: profile.azimuth_degrees,
                        elevation_degrees: profile.elevation_degrees,
                    })
                })
                .or_else(|| self.default_antenna_pattern(source))
                .ok_or(PhyPathError::GainProfile)?,
            pattern => pattern,
        };
        if (matches!(local_pattern, AntennaPattern::Profile(_))
            || matches!(remote_pattern, AntennaPattern::Profile(_)))
            && self.distance(local_id, source).is_none()
        {
            return Err(PhyPathError::GainLocation);
        }
        let profile_placement = |pattern: AntennaPattern| match pattern {
            AntennaPattern::Profile(profile) => crate::antenna::get_manager()
                .get_profile_info(profile.profile_id)
                .map(|(_, _, north, east, up)| (north, east, up)),
            _ => Some((0.0, 0.0, 0.0)),
        };
        let local_placement = profile_placement(local_pattern).ok_or(PhyPathError::GainProfile)?;
        let remote_placement =
            profile_placement(remote_pattern).ok_or(PhyPathError::GainProfile)?;
        let mut key = vec![
            u64::from(local_id),
            u64::from(source),
            u64::from(receive_index),
            u64::from(transmit_index),
        ];
        let mut append_pattern = |pattern: AntennaPattern| match pattern {
            AntennaPattern::Default => key.extend([0, 0, 0, 0]),
            AntennaPattern::IdealOmni { gain_db } => key.extend([1, gain_db.to_bits(), 0, 0]),
            AntennaPattern::Profile(profile) => key.extend([
                2,
                u64::from(profile.profile_id),
                profile.azimuth_degrees.to_bits(),
                profile.elevation_degrees.to_bits(),
            ]),
        };
        append_pattern(local_pattern);
        append_pattern(remote_pattern);
        for placement in [local_placement, remote_placement] {
            key.extend([
                placement.0.to_bits(),
                placement.1.to_bits(),
                placement.2.to_bits(),
            ]);
        }
        let valid_pair =
            self.locations.contains_key(&local_id) && self.locations.contains_key(&source);
        key.push(u64::from(valid_pair));
        for location in [self.locations.get(&local_id), self.locations.get(&source)] {
            let location = location.filter(|_| valid_pair);
            if let Some(location) = location {
                key.extend([
                    location.latitude_degrees.to_bits(),
                    location.longitude_degrees.to_bits(),
                    location.altitude_meters.to_bits(),
                    location.orientation.roll_degrees.to_bits(),
                    location.orientation.pitch_degrees.to_bits(),
                    location.orientation.yaw_degrees.to_bits(),
                ]);
                // LocationManager invalidates pair information on velocity changes too.
                let velocity = location.velocity.unwrap_or_default();
                key.extend([
                    velocity.azimuth_degrees.to_bits(),
                    velocity.elevation_degrees.to_bits(),
                    velocity.magnitude_meters_per_second.to_bits(),
                ]);
            } else {
                key.extend([0; 9]);
            }
        }
        if let Some((receive_gain, transmit_gain)) = self.gain_cache.get(&key).copied() {
            return Ok((receive_gain, transmit_gain, true));
        }
        let locations = self
            .locations
            .get(&local_id)
            .copied()
            .zip(self.locations.get(&source).copied());
        let needs_location = matches!(local_pattern, AntennaPattern::Profile(_))
            || matches!(remote_pattern, AntennaPattern::Profile(_));
        if needs_location && locations.is_none() {
            return Err(PhyPathError::GainLocation);
        }
        if let Some((local, remote)) = locations {
            let distance = distance_meters(local, remote);
            if distance > 10.0
                && !above_horizon(
                    local.altitude_meters + local_placement.2,
                    remote.altitude_meters + remote_placement.2,
                    distance,
                )
            {
                return Err(PhyPathError::GainHorizon);
            }
        }
        let (receive_gain, transmit_gain) = self
            .antenna_pair_gains_with_placements(
                local_id,
                source,
                local_pattern,
                remote_pattern,
                local_placement,
                remote_placement,
                |profile, bearing, elevation, reference_bearing, reference_elevation| {
                    crate::antenna::get_manager().get_profile_gain(
                        profile.profile_id,
                        bearing,
                        elevation,
                        reference_bearing,
                        reference_elevation,
                    )
                },
            )
            .ok_or(PhyPathError::GainProfile)?;
        // GainManager retains only the latest result for each antenna pair.
        // Keeping historical configurations incorrectly turns A -> B -> A
        // updates into cache hits and grows the cache without a bound.
        self.gain_cache
            .retain(|previous, _| previous[..4] != key[..4]);
        self.gain_cache.insert(key, (receive_gain, transmit_gain));
        Ok((receive_gain, transmit_gain, false))
    }

    #[cfg(test)]
    fn antenna_pair_gain_with<F>(
        &self,
        local_id: u16,
        source: u16,
        local_pattern: AntennaPattern,
        remote_pattern: AntennaPattern,
        profile_gain: F,
    ) -> Option<f64>
    where
        F: FnMut(TxAntennaProfile, f64, f64, f64, f64) -> Option<f64>,
    {
        self.antenna_pair_gains_with(
            local_id,
            source,
            local_pattern,
            remote_pattern,
            profile_gain,
        )
        .map(|(receive_gain, transmit_gain)| receive_gain + transmit_gain)
    }

    #[cfg(test)]
    fn antenna_pair_gains_with<F>(
        &self,
        local_id: u16,
        source: u16,
        local_pattern: AntennaPattern,
        remote_pattern: AntennaPattern,
        profile_gain: F,
    ) -> Option<(f64, f64)>
    where
        F: FnMut(TxAntennaProfile, f64, f64, f64, f64) -> Option<f64>,
    {
        self.antenna_pair_gains_with_placements(
            local_id,
            source,
            local_pattern,
            remote_pattern,
            (0.0, 0.0, 0.0),
            (0.0, 0.0, 0.0),
            profile_gain,
        )
    }

    fn antenna_pair_gains_with_placements<F>(
        &self,
        local_id: u16,
        source: u16,
        local_pattern: AntennaPattern,
        remote_pattern: AntennaPattern,
        local_placement: (f64, f64, f64),
        remote_placement: (f64, f64, f64),
        mut profile_gain: F,
    ) -> Option<(f64, f64)>
    where
        F: FnMut(TxAntennaProfile, f64, f64, f64, f64) -> Option<f64>,
    {
        let local_pattern = match local_pattern {
            AntennaPattern::Default => self.default_antenna_pattern(local_id)?,
            pattern => pattern,
        };
        let remote_pattern = match remote_pattern {
            AntennaPattern::Default => self
                .antenna_profiles
                .get(&source)
                .map(|profile| {
                    AntennaPattern::Profile(TxAntennaProfile {
                        profile_id: profile.profile_id,
                        azimuth_degrees: profile.azimuth_degrees,
                        elevation_degrees: profile.elevation_degrees,
                    })
                })
                .or_else(|| self.default_antenna_pattern(source))?,
            pattern => pattern,
        };
        let fixed = |pattern| match pattern {
            AntennaPattern::IdealOmni { gain_db } => Some(gain_db),
            _ => None,
        };
        let locations = self
            .locations
            .get(&local_id)
            .copied()
            .zip(self.locations.get(&source).copied());
        if let Some((local, remote)) = locations {
            let distance = distance_meters(local, remote);
            if distance > 10.0
                && !above_horizon(
                    local.altitude_meters + local_placement.2,
                    remote.altitude_meters + remote_placement.2,
                    distance,
                )
            {
                return None;
            }
        }
        if let (Some(local_gain), Some(remote_gain)) = (fixed(local_pattern), fixed(remote_pattern))
        {
            return Some((local_gain, remote_gain));
        }
        let (local, remote) = locations?;
        let mut side_gain =
            |pattern: AntennaPattern,
             from: Location,
             from_placement: (f64, f64, f64),
             to: Location,
             to_placement: (f64, f64, f64)| match pattern {
                AntennaPattern::IdealOmni { gain_db } => Some(gain_db),
                AntennaPattern::Profile(profile) => {
                    let (reference_azimuth, reference_elevation, _) =
                        antenna_direction(from, from_placement, to, to_placement)?;
                    profile_gain(
                        profile,
                        normalize_azimuth(reference_azimuth - profile.azimuth_degrees),
                        normalize_elevation(reference_elevation - profile.elevation_degrees),
                        reference_azimuth,
                        reference_elevation,
                    )
                }
                AntennaPattern::Default => None,
            };
        Some((
            side_gain(
                local_pattern,
                local,
                local_placement,
                remote,
                remote_placement,
            )?,
            side_gain(
                remote_pattern,
                remote,
                remote_placement,
                local,
                local_placement,
            )?,
        ))
    }

    #[cfg(test)]
    fn propagation(&self, local_id: u16, source: u16, frequency_hz: u64) -> Option<(f64, i64)> {
        self.propagation_detailed(local_id, source, frequency_hz)
            .ok()
    }

    fn propagation_detailed(
        &self,
        local_id: u16,
        source: u16,
        frequency_hz: u64,
    ) -> Result<(f64, i64), PhyPathError> {
        match self.propagation_model {
            PropagationModel::Precomputed => {
                let values = self
                    .pathloss
                    .get(&source)
                    .ok_or(PhyPathError::Propagation)?;
                let pathloss = values
                    .get(&frequency_hz)
                    .or_else(|| values.get(&0))
                    .copied()
                    .ok_or(PhyPathError::Propagation)?;
                let delay = self
                    .distance(local_id, source)
                    .map_or(0, |d| (d / 299_792_458.0 * 1_000_000.0).round() as i64);
                Ok((pathloss, delay))
            }
            PropagationModel::FreeSpace | PropagationModel::TwoRay => {
                let local = self
                    .locations
                    .get(&local_id)
                    .ok_or(PhyPathError::Propagation)?;
                let remote = self
                    .locations
                    .get(&source)
                    .ok_or(PhyPathError::Propagation)?;
                let distance = distance_meters(*local, *remote);
                let pathloss = match self.propagation_model {
                    PropagationModel::FreeSpace => {
                        crate::emane_rs_freespace_pathloss_single(distance, frequency_hz as f64)
                    }
                    PropagationModel::TwoRay => crate::emane_rs_tworay_pathloss(
                        distance,
                        local.altitude_meters,
                        remote.altitude_meters,
                    ),
                    PropagationModel::Precomputed => unreachable!(),
                };
                let delay = (distance / 299_792_458.0 * 1_000_000.0).round();
                Ok((pathloss, delay.clamp(0.0, i64::MAX as f64) as i64))
            }
        }
    }

    fn distance(&self, local_id: u16, source: u16) -> Option<f64> {
        Some(distance_meters(
            *self.locations.get(&local_id)?,
            *self.locations.get(&source)?,
        ))
    }

    fn doppler_fraction(&self, local_id: u16, source: u16) -> f64 {
        if !self.doppler_shift_enabled {
            return 0.0;
        }
        let Some(local) = self.locations.get(&local_id).copied() else {
            return 0.0;
        };
        let Some(remote) = self.locations.get(&source).copied() else {
            return 0.0;
        };
        let (Some(local_velocity), Some(remote_velocity)) = (local.velocity, remote.velocity)
        else {
            return 0.0;
        };
        let local_position = position_ecef(local);
        let remote_position = position_ecef(remote);
        let position_delta = (
            remote_position.0 - local_position.0,
            remote_position.1 - local_position.1,
            remote_position.2 - local_position.2,
        );
        let distance = (position_delta.0 * position_delta.0
            + position_delta.1 * position_delta.1
            + position_delta.2 * position_delta.2)
            .sqrt();
        if distance <= f64::EPSILON || !distance.is_finite() {
            return 0.0;
        }
        let local_velocity = velocity_ecef(local_velocity, local);
        let remote_velocity = velocity_ecef(remote_velocity, remote);
        let velocity_delta = (
            local_velocity.0 - remote_velocity.0,
            local_velocity.1 - remote_velocity.1,
            local_velocity.2 - remote_velocity.2,
        );
        let dot_product = position_delta.0 * velocity_delta.0
            + position_delta.1 * velocity_delta.1
            + position_delta.2 * velocity_delta.2;
        let magnitude = (velocity_delta.0 * velocity_delta.0
            + velocity_delta.1 * velocity_delta.1
            + velocity_delta.2 * velocity_delta.2)
            .sqrt();
        if magnitude == 0.0 {
            return 0.0;
        }
        // Preserve the original operation order: simplifying this projection
        // changes the last bit of the published double-precision Doppler shift.
        let cos_theta = dot_product / (distance * magnitude);
        let radial_velocity = magnitude * cos_theta;
        const SPEED_OF_LIGHT: f64 = 299_792_458.0;
        let denominator = SPEED_OF_LIGHT - radial_velocity;
        if denominator <= 0.0 || !denominator.is_finite() {
            0.0
        } else {
            SPEED_OF_LIGHT / denominator - 1.0
        }
    }

    #[cfg(test)]
    fn apply_fading(
        &mut self,
        local_id: u16,
        source: u16,
        power_dbm: f64,
        now_microseconds: u64,
    ) -> Option<f64> {
        self.apply_fading_detailed(local_id, source, power_dbm, now_microseconds)
            .ok()
    }

    #[cfg(test)]
    fn apply_fading_detailed(
        &mut self,
        local_id: u16,
        source: u16,
        power_dbm: f64,
        now_microseconds: u64,
    ) -> Result<f64, PhyPathError> {
        self.apply_fading_on_antenna(0, local_id, source, power_dbm, now_microseconds)
    }

    fn apply_fading_on_antenna(
        &mut self,
        antenna: u16,
        local_id: u16,
        source: u16,
        power_dbm: f64,
        now_microseconds: u64,
    ) -> Result<f64, PhyPathError> {
        let mode = match self.fading_mode {
            FadingMode::Event => *self
                .fading_selections
                .get(&source)
                .ok_or(PhyPathError::FadeSelection)?,
            mode => mode,
        };
        let power_mw = match mode {
            FadingMode::None => return Ok(power_dbm),
            FadingMode::Event => return Err(PhyPathError::FadeAlgorithm),
            FadingMode::Nakagami => {
                let distance = self
                    .distance(local_id, source)
                    .ok_or(PhyPathError::FadeLocation)?;
                self.nakagami.entry(antenna).or_default().compute(
                    power_dbm,
                    distance,
                    self.nakagami_parameters.distance0_meters,
                    self.nakagami_parameters.distance1_meters,
                    self.nakagami_parameters.m0,
                    self.nakagami_parameters.m1,
                    self.nakagami_parameters.m2,
                )
            }
            FadingMode::Lognormal => {
                self.distance(local_id, source)
                    .ok_or(PhyPathError::FadeLocation)?;
                self.lognormal_states
                    .entry(antenna)
                    .or_default()
                    .process(power_dbm, &self.lognormal_parameters, now_microseconds)
                    .ok_or(PhyPathError::FadeAlgorithm)?
            }
        };
        (power_mw.is_finite() && power_mw > 0.0)
            .then_some(10.0 * power_mw.log10())
            .ok_or(PhyPathError::FadeAlgorithm)
    }
}

fn distance_meters(a: Location, b: Location) -> f64 {
    let a = position_ecef(a);
    let b = position_ecef(b);
    let (x, y, z) = (b.0 - a.0, b.1 - a.1, b.2 - a.2);
    (x * x + y * y + z * z).sqrt()
}

#[cfg(test)]
fn oriented_direction_angles(local: Location, remote: Location) -> Option<(f64, f64)> {
    antenna_direction(local, (0.0, 0.0, 0.0), remote, (0.0, 0.0, 0.0))
        .map(|(azimuth, elevation, _)| (azimuth, elevation))
}

fn antenna_direction(
    local: Location,
    local_placement: (f64, f64, f64),
    remote: Location,
    remote_placement: (f64, f64, f64),
) -> Option<(f64, f64, f64)> {
    let mut direction = rotate_neu(relative_neu(local, remote), adjusted_orientation(local));
    let local_orientation = adjusted_orientation(local);
    let remote_orientation = adjusted_orientation(remote);
    let remote_placement = rotate_neu(
        remote_placement,
        Orientation {
            yaw_degrees: local_orientation.yaw_degrees - remote_orientation.yaw_degrees,
            pitch_degrees: local_orientation.pitch_degrees - remote_orientation.pitch_degrees,
            roll_degrees: local_orientation.roll_degrees - remote_orientation.roll_degrees,
        },
    );
    direction.0 += -local_placement.0 + remote_placement.0;
    direction.1 += -local_placement.1 + remote_placement.1;
    direction.2 += -local_placement.2 + remote_placement.2;
    let (north, east, up) = direction;
    let magnitude = north.hypot(east).hypot(up);
    if !magnitude.is_finite() {
        return None;
    }
    let elevation = if magnitude == 0.0 {
        0.0
    } else {
        normalize_elevation((up / magnitude).clamp(-1.0, 1.0).asin().to_degrees())
    };
    let azimuth = if north == 0.0 {
        if east > 0.0 {
            90.0
        } else {
            270.0
        }
    } else {
        let mut azimuth = if east == 0.0 {
            if north > 0.0 {
                0.0
            } else {
                180.0
            }
        } else {
            (east / north).atan().to_degrees()
        };
        if north < 0.0 {
            azimuth += 180.0;
        }
        if north > 0.0 && east < 0.0 {
            azimuth += 360.0;
        }
        normalize_azimuth(azimuth)
    };
    Some((azimuth, elevation, magnitude))
}

fn adjusted_orientation(location: Location) -> Orientation {
    let mut orientation = location.orientation;
    if let Some(velocity) = location.velocity {
        orientation.yaw_degrees =
            normalize_azimuth(orientation.yaw_degrees + velocity.azimuth_degrees);
        orientation.pitch_degrees =
            normalize_elevation(orientation.pitch_degrees + velocity.elevation_degrees);
    }
    orientation
}

fn rotate_neu(vector: (f64, f64, f64), orientation: Orientation) -> (f64, f64, f64) {
    let (north, east, up) = vector;
    let yaw = degrees_to_radians(orientation.yaw_degrees);
    let pitch = degrees_to_radians(orientation.pitch_degrees);
    let roll = degrees_to_radians(orientation.roll_degrees);
    (
        north * yaw.cos() * pitch.cos() + east * yaw.sin() * pitch.cos() + up * pitch.sin(),
        north * (yaw.cos() * pitch.sin() * roll.sin() - yaw.sin() * roll.cos())
            + east * (yaw.cos() * roll.cos() + yaw.sin() * pitch.sin() * roll.sin())
            - up * pitch.cos() * roll.sin(),
        -north * (yaw.cos() * pitch.sin() * roll.cos() + yaw.sin() * roll.sin())
            - east * (yaw.sin() * pitch.sin() * roll.cos() - yaw.cos() * roll.sin())
            + up * pitch.cos() * roll.cos(),
    )
}

fn above_horizon(local_height_meters: f64, remote_height_meters: f64, distance: f64) -> bool {
    const MEAN_EARTH_RADIUS_METERS: f64 = (2.0 * 6_378_137.0 + 6_356_752.314_2) / 3.0;
    let horizon_distance = |height: f64| {
        let height = height.max(0.0);
        (height * (2.0 * MEAN_EARTH_RADIUS_METERS + height)).sqrt()
    };
    horizon_distance(local_height_meters) + horizon_distance(remote_height_meters) > distance
}

fn relative_neu(local: Location, remote: Location) -> (f64, f64, f64) {
    let local_ecef = position_ecef(local);
    let remote_ecef = position_ecef(remote);
    let x = remote_ecef.0 - local_ecef.0;
    let y = remote_ecef.1 - local_ecef.1;
    let z = remote_ecef.2 - local_ecef.2;
    let latitude = degrees_to_radians(local.latitude_degrees);
    let longitude = degrees_to_radians(local.longitude_degrees);
    let north = -x * latitude.sin() * longitude.cos() - y * latitude.sin() * longitude.sin()
        + z * latitude.cos();
    let east = -x * longitude.sin() + y * longitude.cos();
    let up = x * latitude.cos() * longitude.cos()
        + y * latitude.cos() * longitude.sin()
        + z * latitude.sin();
    (north, east, up)
}

fn position_ecef(location: Location) -> (f64, f64, f64) {
    const SEMI_MAJOR: f64 = 6_378_137.0;
    const SEMI_MINOR: f64 = 6_356_752.314_2;
    const ECCENTRICITY_SQUARED: f64 =
        (SEMI_MAJOR * SEMI_MAJOR - SEMI_MINOR * SEMI_MINOR) / (SEMI_MAJOR * SEMI_MAJOR);
    let latitude = degrees_to_radians(location.latitude_degrees);
    let longitude = degrees_to_radians(location.longitude_degrees);
    let radius = SEMI_MAJOR / (1.0 - ECCENTRICITY_SQUARED * latitude.sin().powi(2)).sqrt();
    (
        (radius + location.altitude_meters) * latitude.cos() * longitude.cos(),
        (radius + location.altitude_meters) * latitude.cos() * longitude.sin(),
        ((1.0 - ECCENTRICITY_SQUARED) * radius + location.altitude_meters) * latitude.sin(),
    )
}

fn velocity_neu(velocity: Velocity) -> (f64, f64, f64) {
    let azimuth = degrees_to_radians(velocity.azimuth_degrees);
    let elevation = degrees_to_radians(velocity.elevation_degrees);
    let horizontal = velocity.magnitude_meters_per_second * elevation.cos();
    (
        horizontal * azimuth.cos(),
        horizontal * azimuth.sin(),
        velocity.magnitude_meters_per_second * elevation.sin(),
    )
}

fn velocity_ecef(velocity: Velocity, location: Location) -> (f64, f64, f64) {
    let velocity = velocity_neu(velocity);
    let latitude = degrees_to_radians(location.latitude_degrees);
    let longitude = degrees_to_radians(location.longitude_degrees);
    // Preserve the legacy EMANE transform exactly, including its historical
    // longitude terms, because these values are part of the published Doppler
    // and receive-power contracts.
    (
        -velocity.1 * longitude.sin() - velocity.0 * latitude.sin() * longitude.cos()
            + velocity.2 * longitude.cos() * longitude.cos(),
        velocity.1 * longitude.cos() - velocity.0 * latitude.sin() * longitude.sin()
            + velocity.2 * latitude.cos() * longitude.sin(),
        velocity.0 * latitude.cos() + velocity.2 * longitude.sin(),
    )
}

// The original conversion multiplies in extended precision before returning a
// double. A compensated product retains that precision without a C++ runtime.
fn degrees_to_radians(degrees: f64) -> f64 {
    const HIGH: f64 = std::f64::consts::PI / 180.0;
    const LOW: f64 = 2.947_674_656_444_965e-19;
    degrees.mul_add(HIGH, degrees * LOW)
}

fn normalize_azimuth(value: f64) -> f64 {
    value.rem_euclid(360.0)
}

fn normalize_elevation(value: f64) -> f64 {
    let value = value.rem_euclid(360.0);
    match value {
        value if value >= 270.0 => value - 360.0,
        value if value > 90.0 => value - 180.0,
        value => value,
    }
}

fn builtin_init(id: u16, framework: *const FfiFrameworkService, kind: BuiltinKind) -> *mut c_void {
    if framework.is_null() {
        return std::ptr::null_mut();
    }
    let framework = unsafe { *framework };
    let mut state = Box::new(BuiltinState {
        id,
        framework,
        kind,
        virtual_transport: std::ptr::null_mut(),
        raw_transport: std::ptr::null_mut(),
        ethernet: Box::new(EthernetTransportState::new()),
        device_path: "/dev/net/tun".to_string(),
        device_name: "emane0".to_string(),
        address: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        mask: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        arp_mode: true,
        broadcast_mode: false,
        arp_cache_mode: true,
        arp_priority: 0,
        unknown_priorities: HashMap::new(),
        flow_control_enabled: false,
        transport_flow: Mutex::new(TransportFlow::default()),
        transport_flow_changed: Condvar::new(),
        bitrate_bps: 0,
        bit_pool: crate::bit_pool::BitPool::default(),
        counters: match kind {
            BuiltinKind::Phy => CommonLayerCounters::register_with_drop_labels(
                framework,
                "0",
                &[
                    "Out-of-Band",
                    "Rx Sensitivity",
                    "Propagation Model",
                    "Gain Location",
                    "Gain Horizon",
                    "Gain Profile",
                    "Not FOI",
                    "Spectrum Clamp",
                    "Fade Location",
                    "Fade Algorithm",
                    "Fade Select",
                    "Antenna Freq",
                    "Gain Antenna",
                    "Missing Control",
                ],
                &[],
            ),
            BuiltinKind::VirtualTransport => CommonLayerCounters::register_with_drop_labels(
                framework,
                "",
                &["Write Error", "Frame Error"],
                &[],
            ),
            // The legacy raw transport does not publish common-layer packet
            // statistics.
            BuiltinKind::RawTransport => CommonLayerCounters::default(),
        },
        phy: PhyState::new(),
    });
    let state_ptr = state.as_mut() as *mut BuiltinState;
    match kind {
        BuiltinKind::VirtualTransport => {
            state.virtual_transport =
                emane_rs_virtual_transport_new(id, state_ptr.cast(), builtin_ethernet_downstream);
            if state.virtual_transport.is_null() {
                return std::ptr::null_mut();
            }
        }
        BuiltinKind::RawTransport => {
            state.raw_transport =
                emane_rs_raw_transport_new(id, state_ptr.cast(), builtin_ethernet_downstream);
            if state.raw_transport.is_null() {
                return std::ptr::null_mut();
            }
        }
        BuiltinKind::Phy => {
            state.phy.radio_silence_drop_counter = (framework.register_counter)(
                framework.framework_ctx,
                c"numDownstreamPacketsRadioSilenceEnabledDrop".as_ptr(),
                c"Packets dropped while radio silence is enabled".as_ptr(),
                true,
            );
            state.phy.time_sync_rewrite_counter = (framework.register_counter)(
                framework.framework_ctx,
                c"numTimeSyncThresholdRewrite".as_ptr(),
                c"Receive timestamps rewritten by the time-sync threshold".as_ptr(),
                true,
            );
            state.phy.gain_cache_hit_counter = (framework.register_counter)(
                framework.framework_ctx,
                c"numGainCacheHit".as_ptr(),
                c"Antenna gain cache hits".as_ptr(),
                true,
            );
            state.phy.gain_cache_miss_counter = (framework.register_counter)(
                framework.framework_ctx,
                c"numGainCacheMiss".as_ptr(),
                c"Antenna gain cache misses".as_ptr(),
                true,
            );
            if let Some(context) = context(framework.framework_ctx) {
                state.phy.location_event_table = register_native_table(
                    context.build_id,
                    "LocationEventInfoTable",
                    &[
                        "NEM",
                        "Latitude",
                        "Longitude",
                        "Altitude",
                        "Pitch",
                        "Roll",
                        "Yaw",
                        "Azimuth",
                        "Elevation",
                        "Magnitude",
                    ],
                    "Shows the location event information received",
                    false,
                );
                state.phy.pathloss_event_table = register_native_table(
                    context.build_id,
                    "PathlossEventInfoTable",
                    &["NEM", "Forward Pathloss", "Reverse Pathloss"],
                    "Shows the precomputed pathloss information received",
                    false,
                );
                state.phy.pathloss_ex_event_table = register_native_table(
                    context.build_id,
                    "PathlossExEventInfoTable",
                    &["NEM", "Frequency", "Pathloss"],
                    "Shows the per frequency precomputed pathloss information received",
                    false,
                );
                state.phy.antenna_profile_event_table = register_native_table(
                    context.build_id,
                    "AntennaProfileEventInfoTable",
                    &[
                        "NEM",
                        "Antenna Profile",
                        "Antenna Azimuth",
                        "Antenna Elevation",
                    ],
                    "Shows the antenna profile information received",
                    false,
                );
                state.phy.fading_selection_event_table = register_native_table(
                    context.build_id,
                    "FadingSelectionInfoTable",
                    &["NEM", "Model"],
                    "Shows the selected fading model information received",
                    false,
                );
                state.phy.receive_power_table = register_native_table(
                    context.build_id,
                    "ReceivePowerTable",
                    &[
                        "NEM",
                        "Rx Antenna",
                        "Tx Antenna",
                        "Frequency",
                        "Rx Power",
                        "Tx Gain",
                        "Rx Gain",
                        "Tx Power",
                        "Pathloss",
                        "Doppler",
                        "Last Packet Time",
                    ],
                    "Shows the calculated receive power for the last received segment.",
                    false,
                );
                state.phy.observed_power_table = register_native_table(
                    context.build_id,
                    "ObservedPowerTable",
                    &[
                        "NEM",
                        "Rx Antenna",
                        "Tx Antenna",
                        "Frequency",
                        "Spectral Mask",
                        "Rx Power",
                        "Last Packet Time",
                    ],
                    "Shows the calculated observed power for the last received segment.",
                    false,
                );
                if state.phy.location_event_table.is_none()
                    || state.phy.pathloss_event_table.is_none()
                    || state.phy.pathloss_ex_event_table.is_none()
                    || state.phy.antenna_profile_event_table.is_none()
                    || state.phy.fading_selection_event_table.is_none()
                    || state.phy.receive_power_table.is_none()
                    || state.phy.observed_power_table.is_none()
                {
                    return std::ptr::null_mut();
                }
            }
        }
    }
    Box::into_raw(state).cast()
}

extern "C" fn builtin_phy_init(id: u16, framework: *const FfiFrameworkService) -> *mut c_void {
    builtin_init(id, framework, BuiltinKind::Phy)
}

extern "C" fn builtin_virtual_init(id: u16, framework: *const FfiFrameworkService) -> *mut c_void {
    builtin_init(id, framework, BuiltinKind::VirtualTransport)
}

extern "C" fn builtin_raw_init(id: u16, framework: *const FfiFrameworkService) -> *mut c_void {
    builtin_init(id, framework, BuiltinKind::RawTransport)
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn parse_scaled_u64(value: &str) -> Option<u64> {
    let value = value.trim();
    let (number, multiplier) = match value.as_bytes().last().copied() {
        Some(b'K' | b'k') => (&value[..value.len() - 1], 1_000.0),
        Some(b'M' | b'm') => (&value[..value.len() - 1], 1_000_000.0),
        Some(b'G' | b'g') => (&value[..value.len() - 1], 1_000_000_000.0),
        _ => (value, 1.0),
    };
    let number = number.parse::<f64>().ok()?;
    let scaled = number * multiplier;
    (number >= 0.0 && scaled.is_finite() && scaled <= u64::MAX as f64)
        .then_some(scaled.round() as u64)
}

fn parse_u16(value: &str) -> Option<u16> {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or_else(
            || value.parse().ok(),
            |value| u16::from_str_radix(value, 16).ok(),
        )
}

fn parse_i64_config(value: &str) -> Option<i64> {
    value
        .parse::<u64>()
        .ok()
        .and_then(|value| i64::try_from(value).ok())
}

unsafe fn config_items(request: *const c_void) -> Option<Vec<(String, Vec<String>)>> {
    let request = (request as *const FfiConfigRequest).as_ref()?;
    if request.len > 4096 || (request.len != 0 && request.data.is_null()) {
        return None;
    }
    let mut result = Vec::with_capacity(request.len);
    let items = if request.len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(request.data, request.len)
    };
    for item in items {
        if item.name.is_null()
            || item.values.len > 4096
            || (item.values.len != 0 && item.values.data.is_null())
        {
            return None;
        }
        let name = CStr::from_ptr(item.name).to_str().ok()?.to_string();
        let mut values = Vec::with_capacity(item.values.len);
        let item_values = if item.values.len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(item.values.data, item.values.len)
        };
        for value in item_values {
            if value.is_null() {
                return None;
            }
            values.push(CStr::from_ptr(*value).to_str().ok()?.to_string());
        }
        result.push((name, values));
    }
    Some(result)
}

extern "C" fn builtin_configure(state: *mut c_void, request: *const c_void) -> bool {
    let Some(state) = (unsafe { (state as *mut BuiltinState).as_mut() }) else {
        return false;
    };
    let Some(mut items) = (unsafe { config_items(request) }) else {
        return false;
    };
    if matches!(state.kind, BuiltinKind::Phy) && !state.phy.lognormal_configured {
        // C++ starts the manager at zero, applies explicit values first, then
        // missing defaults in name order. Applying preloaded defaults instead
        // changes the result of the interdependent threshold/loss setters.
        state.phy.lognormal_parameters = LognormalFadingParameters {
            dmu: 0.0,
            dsigma: 0.0,
            dlthresh: 0.0,
            maxpathloss: 0.0,
            duthresh: 0.0,
            minpathloss: 0.0,
            lmean: 0.0,
            lstddev: 0.0,
            counter: 0,
        };
        for (name, values) in component_configuration_defaults("emanephy") {
            if name.starts_with("fading.lognormal.") && !items.iter().any(|(key, _)| *key == name) {
                items.push((name, values.iter().map(ConfigurationValue::text).collect()));
            }
        }
        state.phy.lognormal_configured = true;
    }
    // Runtime power/gain/fading changes must not destroy pending noise windows.
    let reset_monitor = items.iter().any(|(name, _)| {
        matches!(
            name.as_str(),
            "subid"
                | "frequencyofinterest"
                | "bandwidth"
                | "noisemode"
                | "noisebinsize"
                | "noisemaxclampenable"
                | "noisemaxsegmentoffset"
                | "noisemaxmessagepropagation"
                | "noisemaxsegmentduration"
                | "timesyncthreshold"
                | "systemnoisefigure"
                | "excludesamesubidfromfilterenable"
        )
    });
    let mut fixed_antenna_gain_updated = false;
    for (name, values) in items {
        let Some(value) = values.first() else {
            return false;
        };
        let valid_for_kind = match state.kind {
            BuiltinKind::Phy => matches!(
                name.as_str(),
                "frequency"
                    | "frequencyofinterest"
                    | "bandwidth"
                    | "txpower"
                    | "fixedantennagain"
                    | "fixedantennagainenable"
                    | "subid"
                    | "noisemode"
                    | "noisebinsize"
                    | "noisemaxsegmentoffset"
                    | "noisemaxmessagepropagation"
                    | "noisemaxsegmentduration"
                    | "timesyncthreshold"
                    | "noisemaxclampenable"
                    | "systemnoisefigure"
                    | "propagationmodel"
                    | "excludesamesubidfromfilterenable"
                    | "compatibilitymode"
                    | "processingpoolsize"
                    | "stats.receivepowertableenable"
                    | "stats.observedpowertableenable"
                    | "rxsensitivitypromiscuousmodeenable"
                    | "dopplershiftenable"
                    | "spectralmaskindex"
                    | "radiosilenceenable"
                    | "fading.model"
                    | "fading.nakagami.m0"
                    | "fading.nakagami.m1"
                    | "fading.nakagami.m2"
                    | "fading.nakagami.distance0"
                    | "fading.nakagami.distance1"
                    | "fading.lognormal.dmu"
                    | "fading.lognormal.dsigma"
                    | "fading.lognormal.dlthresh"
                    | "fading.lognormal.duthresh"
                    | "fading.lognormal.maxpathloss"
                    | "fading.lognormal.minpathloss"
                    | "fading.lognormal.lmean"
                    | "fading.lognormal.lstddev"
            ),
            BuiltinKind::VirtualTransport => matches!(
                name.as_str(),
                "devicepath"
                    | "device"
                    | "arpmodeenable"
                    | "broadcastmodeenable"
                    | "arpcacheenable"
                    | "ethernet.type.arp.priority"
                    | "ethernet.type.unknown.priority"
                    | "bitrate"
                    | "flowcontrolenable"
                    | "address"
                    | "mask"
            ),
            BuiltinKind::RawTransport => matches!(
                name.as_str(),
                "device"
                    | "broadcastmodeenable"
                    | "arpcacheenable"
                    | "ethernet.type.arp.priority"
                    | "ethernet.type.unknown.priority"
                    | "bitrate"
            ),
        };
        if !valid_for_kind {
            return false;
        }
        match name.as_str() {
            "devicepath" => state.device_path.clone_from(value),
            "device" => state.device_name.clone_from(value),
            "arpmodeenable" => {
                let Some(value) = parse_bool(value) else {
                    return false;
                };
                state.arp_mode = value;
            }
            "broadcastmodeenable" => {
                let Some(value) = parse_bool(value) else {
                    return false;
                };
                state.broadcast_mode = value;
            }
            "arpcacheenable" => {
                let Some(value) = parse_bool(value) else {
                    return false;
                };
                state.arp_cache_mode = value;
            }
            "ethernet.type.arp.priority" => {
                let Ok(value) = value.parse() else {
                    return false;
                };
                state.arp_priority = value;
            }
            "ethernet.type.unknown.priority" => {
                for value in values {
                    let Some((ether_type, priority)) = value.split_once(':') else {
                        return false;
                    };
                    let (Some(ether_type), Ok(priority)) =
                        (parse_u16(ether_type), priority.parse::<u8>())
                    else {
                        return false;
                    };
                    state.unknown_priorities.insert(ether_type, priority);
                }
            }
            "frequency" => {
                let Some(value) = parse_scaled_u64(value) else {
                    return false;
                };
                if value == 0 {
                    return false;
                }
                state.phy.frequency_hz = value;
            }
            "frequencyofinterest" => {
                let mut frequencies = Vec::with_capacity(values.len());
                for value in values {
                    let Some(value) = parse_scaled_u64(&value) else {
                        return false;
                    };
                    frequencies.push(value);
                }
                if frequencies.is_empty() {
                    return false;
                }
                state.phy.frequencies_of_interest = frequencies;
            }
            "bandwidth" => {
                let Some(value) = parse_scaled_u64(value) else {
                    return false;
                };
                if value == 0 {
                    return false;
                }
                state.phy.bandwidth_hz = value;
            }
            "txpower" => {
                let Ok(value) = value.parse::<f64>() else {
                    return false;
                };
                if !value.is_finite() {
                    return false;
                }
                state.phy.tx_power_dbm = value;
            }
            "fixedantennagain" => {
                let Ok(value) = value.parse::<f64>() else {
                    return false;
                };
                if !value.is_finite() {
                    return false;
                }
                state.phy.fixed_antenna_gain_db = value;
                fixed_antenna_gain_updated = true;
            }
            "subid" => {
                let Ok(value) = value.parse::<u16>() else {
                    return false;
                };
                if value == 0 {
                    return false;
                }
                state.phy.sub_id = value;
            }
            "noisemode" => {
                state.phy.noise_mode = match value.as_str() {
                    "none" => NoiseMode::None,
                    "all" => NoiseMode::All,
                    "outofband" => NoiseMode::OutOfBand,
                    "passthrough" => NoiseMode::PassThrough,
                    _ => return false,
                };
            }
            "noisebinsize" => {
                let Some(value) = parse_i64_config(value) else {
                    return false;
                };
                if value == 0 {
                    return false;
                }
                state.phy.noise_bin_size = value;
            }
            "noisemaxsegmentoffset" => {
                let Some(value) = parse_i64_config(value) else {
                    return false;
                };
                state.phy.max_segment_offset = value;
            }
            "noisemaxmessagepropagation" => {
                let Some(value) = parse_i64_config(value) else {
                    return false;
                };
                state.phy.max_message_propagation = value;
            }
            "noisemaxsegmentduration" => {
                let Some(value) = parse_i64_config(value) else {
                    return false;
                };
                state.phy.max_segment_duration = value;
            }
            "timesyncthreshold" => {
                let Some(value) = parse_i64_config(value) else {
                    return false;
                };
                state.phy.time_sync_threshold = value;
            }
            "noisemaxclampenable" => {
                let Some(value) = parse_bool(value) else {
                    return false;
                };
                state.phy.noise_max_clamp = value;
            }
            "systemnoisefigure" => {
                let Ok(value) = value.parse::<f64>() else {
                    return false;
                };
                if !value.is_finite() {
                    return false;
                }
                state.phy.system_noise_figure_db = value;
            }
            "fixedantennagainenable" => {
                let Some(value) = parse_bool(value) else {
                    return false;
                };
                state.phy.fixed_antenna_gain_enabled = value;
            }
            "propagationmodel" => {
                state.phy.propagation_model = match value.as_str() {
                    "precomputed" => PropagationModel::Precomputed,
                    "freespace" => PropagationModel::FreeSpace,
                    "2ray" => PropagationModel::TwoRay,
                    _ => return false,
                };
            }
            "excludesamesubidfromfilterenable" => {
                let Some(value) = parse_bool(value) else {
                    return false;
                };
                state.phy.exclude_same_sub_id_from_filter = value;
            }
            "compatibilitymode" => {
                state.phy.compatibility_mode = match value.parse::<u8>() {
                    Ok(value @ 1..=2) => value,
                    _ => return false,
                };
            }
            "processingpoolsize" => {
                state.phy.processing_pool_size = match value.parse::<u16>() {
                    Ok(0) => 0,
                    Ok(value) if value >= 2 => value,
                    _ => return false,
                };
            }
            "stats.receivepowertableenable" => {
                state.phy.receive_power_table_enabled = match parse_bool(value) {
                    Some(value) => value,
                    None => return false,
                };
            }
            "stats.observedpowertableenable" => {
                state.phy.observed_power_table_enabled = match parse_bool(value) {
                    Some(value) => value,
                    None => return false,
                };
            }
            "rxsensitivitypromiscuousmodeenable" => {
                state.phy.rx_sensitivity_promiscuous_mode_enabled = match parse_bool(value) {
                    Some(value) => value,
                    None => return false,
                };
            }
            "dopplershiftenable" => {
                let Some(value) = parse_bool(value) else {
                    return false;
                };
                state.phy.doppler_shift_enabled = value;
            }
            "spectralmaskindex" => {
                let Ok(value) = value.parse::<u16>() else {
                    return false;
                };
                state.phy.spectral_mask_index = value;
            }
            "radiosilenceenable" => {
                let Some(value) = parse_bool(value) else {
                    return false;
                };
                state.phy.radio_silence_enabled = value;
            }
            "fading.model" => {
                state.phy.fading_mode = match value.as_str() {
                    "none" => FadingMode::None,
                    "event" => FadingMode::Event,
                    "nakagami" => FadingMode::Nakagami,
                    "lognormal" => FadingMode::Lognormal,
                    _ => return false,
                };
            }
            "fading.nakagami.m0" | "fading.nakagami.m1" | "fading.nakagami.m2" => {
                let Ok(parsed) = value.parse::<f64>() else {
                    return false;
                };
                if !parsed.is_finite() || parsed < 0.5 {
                    return false;
                }
                match name.as_str() {
                    "fading.nakagami.m0" => state.phy.nakagami_parameters.m0 = parsed,
                    "fading.nakagami.m1" => state.phy.nakagami_parameters.m1 = parsed,
                    _ => state.phy.nakagami_parameters.m2 = parsed,
                }
            }
            "fading.nakagami.distance0" | "fading.nakagami.distance1" => {
                let Ok(parsed) = value.parse::<f64>() else {
                    return false;
                };
                if !parsed.is_finite() || parsed < 0.0 {
                    return false;
                }
                if name == "fading.nakagami.distance0" {
                    state.phy.nakagami_parameters.distance0_meters = parsed;
                } else {
                    state.phy.nakagami_parameters.distance1_meters = parsed;
                }
            }
            "fading.lognormal.dmu"
            | "fading.lognormal.dsigma"
            | "fading.lognormal.dlthresh"
            | "fading.lognormal.duthresh"
            | "fading.lognormal.maxpathloss"
            | "fading.lognormal.minpathloss"
            | "fading.lognormal.lmean"
            | "fading.lognormal.lstddev" => {
                let Ok(parsed) = value.parse::<f64>() else {
                    return false;
                };
                if !parsed.is_finite()
                    || (matches!(
                        name.as_str(),
                        "fading.lognormal.lmean" | "fading.lognormal.lstddev"
                    ) && parsed < 0.0)
                {
                    return false;
                }
                match name.as_str() {
                    "fading.lognormal.dmu" => state.phy.lognormal_parameters.dmu = parsed,
                    "fading.lognormal.dsigma" => state.phy.lognormal_parameters.dsigma = parsed,
                    "fading.lognormal.dlthresh" => {
                        state.phy.lognormal_parameters.dlthresh = parsed;
                        if parsed > state.phy.lognormal_parameters.duthresh {
                            state.phy.lognormal_parameters.duthresh = parsed;
                        }
                    }
                    "fading.lognormal.duthresh" => {
                        state.phy.lognormal_parameters.duthresh = parsed;
                        if parsed < state.phy.lognormal_parameters.dlthresh {
                            state.phy.lognormal_parameters.dlthresh = parsed;
                        }
                    }
                    "fading.lognormal.maxpathloss" => {
                        state.phy.lognormal_parameters.maxpathloss = parsed;
                        if parsed <= state.phy.lognormal_parameters.minpathloss {
                            state.phy.lognormal_parameters.minpathloss = parsed - 0.001;
                        }
                    }
                    "fading.lognormal.minpathloss" => {
                        state.phy.lognormal_parameters.minpathloss = parsed;
                        if parsed >= state.phy.lognormal_parameters.maxpathloss {
                            state.phy.lognormal_parameters.maxpathloss = parsed + 0.001;
                        }
                    }
                    "fading.lognormal.lmean" => state.phy.lognormal_parameters.lmean = parsed,
                    _ => state.phy.lognormal_parameters.lstddev = parsed,
                }
                state.phy.lognormal_parameters.counter =
                    state.phy.lognormal_parameters.counter.wrapping_add(1);
            }
            "bitrate" => {
                state.bitrate_bps = match parse_scaled_u64(value) {
                    Some(value) => value,
                    None => return false,
                };
                state.bit_pool.start(state.bitrate_bps);
            }
            "flowcontrolenable" => {
                state.flow_control_enabled = match parse_bool(value) {
                    Some(value) => value,
                    None => return false,
                };
            }
            "address" | "mask" => {
                let Ok(address) = value.parse::<IpAddr>() else {
                    return false;
                };
                if name == "address" {
                    state.address = address;
                } else {
                    state.mask = address;
                }
            }
            _ => return false,
        }
    }
    if state.kind == BuiltinKind::Phy {
        if state.phy.max_segment_duration < state.phy.noise_bin_size
            || state
                .phy
                .max_segment_offset
                .saturating_add(state.phy.max_message_propagation)
                .saturating_add(state.phy.max_segment_duration.saturating_mul(2))
                % state.phy.noise_bin_size
                != 0
            || state.phy.nakagami_parameters.distance0_meters
                >= state.phy.nakagami_parameters.distance1_meters
        {
            return false;
        }
        // Apply after all configuration values so initial enable/gain ordering
        // cannot install an omni antenna when fixed gain is disabled.
        if fixed_antenna_gain_updated && state.phy.fixed_antenna_gain_enabled {
            let pattern = AntennaPattern::IdealOmni {
                gain_db: state.phy.fixed_antenna_gain_db,
            };
            state.phy.update_gain_antenna(
                state.id,
                MimoTxAntenna {
                    antenna_index: 0,
                    frequency_group_index: 0,
                    bandwidth_hz: 0,
                    spectral_mask_index: 0,
                    pattern,
                },
            );
            if let Some(entry) = state.phy.receive_antennas.get_mut(&0) {
                entry.antenna.pattern = pattern;
            }
        }
        if reset_monitor {
            state.phy.initialize_monitor();
            register_spectrum_monitors(state);
        }
    }
    true
}

extern "C" fn builtin_start(state: *mut c_void) -> bool {
    let Some(state) = (unsafe { (state as *mut BuiltinState).as_mut() }) else {
        return false;
    };
    let Ok(name) = CString::new(state.device_name.as_str()) else {
        return false;
    };
    match state.kind {
        BuiltinKind::Phy => {
            if state.phy.processing_pool_size > 0 {
                match crate::processing_pool::ProcessingPool::new(state.phy.processing_pool_size) {
                    Ok(pool) => state.phy.processing_pool = Some(pool),
                    Err(_) => return false,
                }
            }
            true
        }
        BuiltinKind::VirtualTransport => {
            let Ok(path) = CString::new(state.device_path.as_str()) else {
                return false;
            };
            let Some(transport) = (unsafe { state.virtual_transport.as_mut() }) else {
                return false;
            };
            transport.set_address(state.address, state.mask);
            state.bit_pool.start(state.bitrate_bps);
            emane_rs_virtual_transport_start(
                state.virtual_transport,
                path.as_ptr(),
                name.as_ptr(),
                state.arp_mode,
            ) == 0
        }
        BuiltinKind::RawTransport => {
            state.bit_pool.start(state.bitrate_bps);
            emane_rs_raw_transport_start(state.raw_transport, name.as_ptr()) == 0
        }
    }
}

fn transport_flow_ack(state: &BuiltinState, token: FlowControlToken) {
    let bytes = token.encode();
    let message = FfiControlMessage {
        msg_type: CONTROL_FLOW_CONTROL_TOKEN,
        payload: FfiSlice {
            data: bytes.as_ptr(),
            len: bytes.len(),
        },
    };
    (state.framework.send_downstream_control)(state.framework.framework_ctx, state.id, &message, 1);
}

extern "C" fn builtin_post_start(state: *mut c_void) {
    let Some(state) = (unsafe { (state as *mut BuiltinState).as_ref() }) else {
        return;
    };
    if state.flow_control_enabled
        && matches!(
            state.kind,
            BuiltinKind::VirtualTransport | BuiltinKind::RawTransport
        )
    {
        transport_flow_ack(
            state,
            FlowControlToken {
                tokens: state.transport_flow.lock().unwrap().tokens,
            },
        );
    }
}

extern "C" fn builtin_stop(context: *mut c_void) {
    if let Some(state) = unsafe { (context as *const BuiltinState).as_ref() } {
        state.bit_pool.cancel();
        // Wake a reader waiting for credit before joining its device thread.
        state.transport_flow.lock().unwrap().stopped = true;
        state.transport_flow_changed.notify_all();
        match state.kind {
            BuiltinKind::VirtualTransport => {
                emane_rs_virtual_transport_stop(state.virtual_transport)
            }
            BuiltinKind::RawTransport => emane_rs_raw_transport_stop(state.raw_transport),
            BuiltinKind::Phy => {
                // PHY has no device reader borrowing this state.
                unsafe { &mut *(context as *mut BuiltinState) }
                    .phy
                    .processing_pool
                    .take();
                return;
            }
        }
        // Join the device reader before clearing its pending frame.
        *state.transport_flow.lock().unwrap() = TransportFlow::default();
    }
}

extern "C" fn builtin_destroy(state: *mut c_void) {
    if !state.is_null() {
        if unsafe { (*(state as *const BuiltinState)).kind } != BuiltinKind::Phy {
            builtin_stop(state);
        }
        let state = unsafe { Box::from_raw(state as *mut BuiltinState) };
        match state.kind {
            BuiltinKind::VirtualTransport => {
                emane_rs_virtual_transport_free(state.virtual_transport)
            }
            BuiltinKind::RawTransport => emane_rs_raw_transport_free(state.raw_transport),
            BuiltinKind::Phy => {}
        }
    }
}

extern "C" fn builtin_query_unknown(
    state: *const c_void,
    ether_type: u16,
    priority: *mut u8,
) -> bool {
    let (Some(state), Some(priority)) =
        (unsafe { (state as *const BuiltinState).as_ref() }, unsafe {
            priority.as_mut()
        })
    else {
        return false;
    };
    if let Some(value) = state.unknown_priorities.get(&ether_type) {
        *priority = *value;
        true
    } else {
        false
    }
}

fn send_transport_frame(
    framework: FfiFrameworkService,
    id: u16,
    bit_pool: &crate::bit_pool::BitPool,
    counters: CommonLayerCounters,
    frame: &PendingTransportFrame,
) {
    let packet = FfiPacket {
        info: FfiPacketInfo {
            uuid: [0; 16],
            source: id,
            destination: frame.destination,
            priority: frame.priority,
            creation_time_sec: frame.creation_time_sec,
            creation_time_usec: frame.creation_time_usec,
        },
        payload: FfiSlice {
            data: frame.payload.as_ptr(),
            len: frame.payload.len(),
        },
    };
    counters.downstream_tx_packet(
        framework,
        id,
        frame.destination,
        frame.payload.len(),
        frame
            .received_at
            .elapsed()
            .as_micros()
            .min(u128::from(u64::MAX)) as u64,
        false,
    );
    (framework.send_downstream_packet)(framework.framework_ctx, id, &packet, std::ptr::null(), 0);
    bit_pool.get((frame.payload.len() as u64).saturating_mul(8));
}

extern "C" fn builtin_ethernet_downstream(context: *mut c_void, data: *const u8, len: usize) {
    let Some(state) = (unsafe { (context as *const BuiltinState).as_ref() }) else {
        return;
    };
    if (len != 0 && data.is_null())
        || emane_rs_ethernet_transport_verify_frame(data.cast(), len) < 0
    {
        return;
    }
    let mut destination = BROADCAST_NEM;
    let mut priority = 0;
    let status = emane_rs_ethernet_transport_parse_frame(
        state.ethernet.as_ref(),
        data.cast(),
        len,
        state.broadcast_mode,
        state.arp_cache_mode,
        state.arp_priority,
        state as *const BuiltinState as *const c_void,
        builtin_query_unknown,
        &mut destination,
        &mut priority,
    );
    if status < 0 {
        return;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let frame = PendingTransportFrame {
        payload: if len == 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(data, len) }.to_vec()
        },
        destination,
        priority,
        creation_time_sec: now.as_secs(),
        creation_time_usec: now.subsec_micros(),
        received_at: Instant::now(),
    };
    state.counters.downstream_rx_packet(
        state.framework,
        state.id,
        destination,
        frame.payload.len(),
    );
    if state.flow_control_enabled {
        let mut flow = state.transport_flow.lock().unwrap();
        // Match FlowControlClient::removeToken: retain one parsed frame on
        // the device thread, leaving further traffic in the kernel TAP queue.
        // Releasing this lock while waiting lets grants and stop wake us.
        while flow.tokens == 0 && !flow.stopped {
            flow = state.transport_flow_changed.wait(flow).unwrap();
        }
        if flow.stopped {
            return;
        }
        flow.tokens -= 1;
    }
    let framework = state.framework;
    let id = state.id;
    send_transport_frame(framework, id, &state.bit_pool, state.counters, &frame);
}

extern "C" fn builtin_upstream(
    context: *mut c_void,
    packet: *const FfiPacket,
    messages: *const FfiControlMessage,
    count: usize,
) {
    let Some(state) = (unsafe { (context as *const BuiltinState).as_ref() }) else {
        return;
    };
    if packet.is_null()
        && matches!(
            state.kind,
            BuiltinKind::VirtualTransport | BuiltinKind::RawTransport
        )
    {
        let Some(incoming) = ffi_control_messages(messages, count) else {
            return;
        };
        if !state.flow_control_enabled {
            return;
        }
        for message in incoming {
            if message.msg_type != CONTROL_FLOW_CONTROL_TOKEN {
                continue;
            }
            let Some(token) =
                control_payload(std::slice::from_ref(message), CONTROL_FLOW_CONTROL_TOKEN)
                    .and_then(FlowControlToken::decode)
            else {
                continue;
            };
            let mut flow = state.transport_flow.lock().unwrap();
            // Publish the ACK before the device reader can consume the grant.
            transport_flow_ack(state, token);
            flow.tokens = token.tokens;
            state.transport_flow_changed.notify_all();
        }
        return;
    }
    let received_at = unix_time_microseconds();
    match state.kind {
        BuiltinKind::Phy => {
            let state = unsafe { &mut *(context as *mut BuiltinState) };
            let Some(packet) = (unsafe { packet.as_ref() }) else {
                (state.framework.send_upstream_control)(
                    state.framework.framework_ctx,
                    state.id,
                    messages,
                    count,
                );
                return;
            };
            let accounted_len = phy_accounted_packet_len(
                packet,
                ffi_control_messages(messages, count).unwrap_or_default(),
            );
            state.counters.upstream_rx_packet(
                state.framework,
                packet.info.source,
                packet.info.destination,
                accounted_len,
            );
            let Some(incoming) = ffi_control_messages(messages, count) else {
                state.counters.upstream_drop_packet(
                    state.framework,
                    packet.info.source,
                    packet.info.destination,
                    14,
                );
                return;
            };
            let Some(tx) = find_tx_properties(incoming) else {
                // Keep bypass and third-party MAC plugins interoperable.
                (state.framework.send_upstream_packet)(
                    state.framework.framework_ctx,
                    state.id,
                    packet,
                    messages,
                    count,
                );
                state.counters.upstream_tx_packet(
                    state.framework,
                    packet.info.source,
                    packet.info.destination,
                    accounted_len,
                    unix_time_microseconds().saturating_sub(received_at).max(0) as u64,
                );
                return;
            };

            let now = unix_time_microseconds();
            if state.phy.compatibility_mode == 2 && state.phy.receive_antennas.is_empty() {
                state.counters.upstream_drop_packet(
                    state.framework,
                    packet.info.source,
                    packet.info.destination,
                    14,
                );
                return;
            }
            let mimo = find_mimo_tx_properties(incoming).unwrap_or_else(|| {
                let segments =
                    find_tx_frequency_segments(incoming).unwrap_or(TxFrequencySegments {
                        segments: vec![TxFrequencySegment {
                            frequency_hz: tx.frequency_hz,
                            duration_microseconds: tx.duration_microseconds,
                            offset_microseconds: tx.offset_microseconds,
                        }],
                    });
                MimoTxProperties {
                    frequency_groups: vec![segments
                        .segments
                        .iter()
                        .map(|s| MimoTxFrequencySegment {
                            frequency_hz: s.frequency_hz,
                            tx_power_dbm: None,
                            duration_microseconds: s.duration_microseconds,
                            offset_microseconds: s.offset_microseconds,
                        })
                        .collect()],
                    transmit_antennas: vec![MimoTxAntenna {
                        antenna_index: tx.antenna_index,
                        frequency_group_index: 0,
                        bandwidth_hz: tx.bandwidth_hz,
                        spectral_mask_index: tx.spectral_mask_index,
                        pattern: if state.phy.fixed_antenna_gain_enabled {
                            AntennaPattern::IdealOmni { gain_db: 0.0 }
                        } else {
                            find_tx_antenna_profile(incoming)
                                .map_or(AntennaPattern::Default, AntennaPattern::Profile)
                        },
                    }],
                }
            });
            let properties = match mimo_receive::receive(state, packet, tx, &mimo, incoming, now) {
                Ok(value) => value,
                Err(code) => {
                    if code == 2
                        && state.phy.compatibility_mode == 2
                        && state.phy.rx_sensitivity_promiscuous_mode_enabled
                    {
                        (state.framework.send_upstream_packet)(
                            state.framework.framework_ctx,
                            state.id,
                            packet,
                            std::ptr::null(),
                            0,
                        );
                    }
                    state.counters.upstream_drop_packet(
                        state.framework,
                        packet.info.source,
                        packet.info.destination,
                        code,
                    );
                    return;
                }
            };
            let mut controls = Vec::new();
            if state.phy.compatibility_mode == 2 {
                let Some(bytes) = properties.encode() else {
                    return;
                };
                controls.push((CONTROL_MIMO_RX_PROPERTIES, bytes));
            } else {
                let info = &properties.antenna_infos[0];
                let first = info.segments[0];
                let bandwidth_hz = mimo
                    .transmit_antennas
                    .iter()
                    .find(|a| a.antenna_index == info.transmit_antenna_index)
                    .map_or(tx.bandwidth_hz, |a| a.bandwidth_hz);
                let rx = RxProperties {
                    frequency_hz: first.frequency_hz,
                    bandwidth_hz,
                    rx_power_dbm: first.rx_power_dbm,
                    noise_floor_dbm: info.noise_floor_dbm,
                    tx_time_microseconds: properties.tx_time_microseconds,
                    propagation_microseconds: properties.propagation_microseconds,
                    duration_microseconds: info.span_microseconds,
                    antenna_index: info.receive_antenna_index,
                    sub_id: tx.sub_id,
                    signal_in_noise: state.phy.noise_mode == NoiseMode::All,
                };
                controls.push((CONTROL_RX_PROPERTIES, rx.encode().to_vec()));
                let Some(bytes) = (RxFrequencySegments {
                    segments: info.segments.clone(),
                })
                .encode() else {
                    return;
                };
                controls.push((CONTROL_RX_FREQUENCY_SEGMENTS, bytes));
            }
            let mut outgoing = incoming
                .iter()
                .copied()
                .filter(|m| {
                    !matches!(
                        m.msg_type,
                        CONTROL_RX_PROPERTIES
                            | CONTROL_RX_FREQUENCY_SEGMENTS
                            | CONTROL_MIMO_RX_PROPERTIES
                    )
                })
                .collect::<Vec<_>>();
            outgoing.extend(controls.iter().map(|(msg_type, bytes)| FfiControlMessage {
                msg_type: *msg_type,
                payload: FfiSlice {
                    data: bytes.as_ptr(),
                    len: bytes.len(),
                },
            }));
            if properties.tx_time_microseconds != tx.tx_time_microseconds {
                (state.framework.increment_counter)(
                    state.framework.framework_ctx,
                    state.phy.time_sync_rewrite_counter,
                    1,
                );
            }
            state.counters.upstream_tx_packet(
                state.framework,
                packet.info.source,
                packet.info.destination,
                accounted_len,
                unix_time_microseconds().saturating_sub(received_at).max(0) as u64,
            );
            (state.framework.send_upstream_packet)(
                state.framework.framework_ctx,
                state.id,
                packet,
                outgoing.as_ptr(),
                outgoing.len(),
            );
        }
        BuiltinKind::VirtualTransport | BuiltinKind::RawTransport if !packet.is_null() => {
            let packet = unsafe { &*packet };
            state.counters.upstream_rx_packet(
                state.framework,
                packet.info.source,
                packet.info.destination,
                packet.payload.len,
            );
            if packet.payload.len != 0 && packet.payload.data.is_null() {
                state.counters.upstream_drop_packet(
                    state.framework,
                    packet.info.source,
                    packet.info.destination,
                    0,
                );
                return;
            }
            emane_rs_ethernet_transport_update_arp_cache(
                state.ethernet.as_ref(),
                packet.payload.data.cast(),
                packet.payload.len,
                packet.info.source,
                state.broadcast_mode,
                state.arp_cache_mode,
            );
            let status = match state.kind {
                BuiltinKind::VirtualTransport => {
                    emane_rs_virtual_transport_process_upstream_packet(
                        state.virtual_transport,
                        packet.payload.data,
                        packet.payload.len,
                    )
                }
                BuiltinKind::RawTransport => emane_rs_raw_transport_process_upstream_packet(
                    state.raw_transport,
                    packet.payload.data,
                    packet.payload.len,
                ),
                BuiltinKind::Phy => unreachable!(),
            };
            if status < 0 {
                state.counters.upstream_drop_packet(
                    state.framework,
                    packet.info.source,
                    packet.info.destination,
                    1,
                );
                return;
            }
            state.counters.upstream_tx_packet(
                state.framework,
                packet.info.source,
                packet.info.destination,
                packet.payload.len,
                unix_time_microseconds().saturating_sub(received_at).max(0) as u64,
            );
            state
                .bit_pool
                .get((packet.payload.len as u64).saturating_mul(8));
        }
        _ => {}
    }
}

extern "C" fn builtin_downstream(
    state: *mut c_void,
    packet: *const FfiPacket,
    messages: *const FfiControlMessage,
    count: usize,
) {
    let Some(state) = (unsafe { (state as *mut BuiltinState).as_mut() }) else {
        return;
    };
    let began_at = unix_time_microseconds();
    if state.kind == BuiltinKind::Phy {
        let Some(incoming) = ffi_control_messages(messages, count) else {
            return;
        };
        if let Some(foi) = incoming.iter().find_map(|message| {
            if message.msg_type != CONTROL_FREQUENCY_INTEREST || message.payload.data.is_null() {
                return None;
            }
            FrequencyOfInterest::decode(unsafe {
                std::slice::from_raw_parts(message.payload.data, message.payload.len)
            })
        }) {
            if state.phy.compatibility_mode == 1 {
                // A zero bandwidth preserves the current bandwidth; an empty
                // frequency set clears reception (for example a TDMA flush).
                if foi.bandwidth_hz != 0 {
                    state.phy.bandwidth_hz = foi.bandwidth_hz;
                }
                state.phy.frequencies_of_interest = foi.frequencies_hz;
                state.phy.initialize_monitor();
            }
        }
        for message in incoming {
            let payload = if message.payload.len == 0 || message.payload.data.is_null() {
                &[][..]
            } else {
                unsafe { std::slice::from_raw_parts(message.payload.data, message.payload.len) }
            };
            match message.msg_type {
                CONTROL_SPECTRUM_FILTER_ADD => {
                    if let Some(spec) = SpectrumFilterAdd::decode(payload) {
                        let monitor =
                            if state.phy.compatibility_mode == 1 && spec.antenna_index == 0 {
                                Some(state.phy.monitor.clone())
                            } else {
                                state
                                    .phy
                                    .receive_antennas
                                    .get(&spec.antenna_index)
                                    .map(|a| a.monitor.clone())
                            };
                        if let Some(m) = monitor {
                            m.lock().unwrap().add_owned_filter(spec);
                        }
                    }
                }
                CONTROL_SPECTRUM_FILTER_REMOVE if payload.len() == 4 => {
                    let antenna = u16::from_be_bytes([payload[0], payload[1]]);
                    let filter = u16::from_be_bytes([payload[2], payload[3]]);
                    let monitor = if state.phy.compatibility_mode == 1 && antenna == 0 {
                        Some(state.phy.monitor.clone())
                    } else {
                        state
                            .phy
                            .receive_antennas
                            .get(&antenna)
                            .map(|a| a.monitor.clone())
                    };
                    if let Some(m) = monitor {
                        m.lock().unwrap().remove_filter(filter);
                    }
                }
                CONTROL_RX_ANTENNA_ADD | CONTROL_RX_ANTENNA_UPDATE => {
                    if state.phy.compatibility_mode != 2 {
                        continue;
                    }
                    let Some(mut add) = RxAntennaAdd::decode(payload) else {
                        continue;
                    };
                    if add.antenna.pattern == AntennaPattern::Default {
                        add.antenna.pattern = state
                            .phy
                            .default_antenna_pattern(state.id)
                            .unwrap_or(AntennaPattern::Default);
                    }
                    state.phy.update_gain_antenna(state.id, add.antenna);
                    if message.msg_type == CONTROL_RX_ANTENNA_UPDATE {
                        // Pointing/gain changes leave the antenna's spectrum history,
                        // filters, configured bandwidth and FOI intact.
                        if let Some(entry) = state
                            .phy
                            .receive_antennas
                            .get_mut(&add.antenna.antenna_index)
                        {
                            entry.antenna = add.antenna;
                        }
                        continue;
                    }
                    if state
                        .phy
                        .receive_antennas
                        .contains_key(&add.antenna.antenna_index)
                    {
                        continue;
                    }
                    if add.antenna.bandwidth_hz == 0 {
                        add.antenna.bandwidth_hz = state.phy.bandwidth_hz;
                    }
                    if add.frequencies_hz.is_empty() {
                        add.frequencies_hz = state.phy.frequencies_of_interest.clone();
                    } else {
                        // Original ADD updates the fallback FOI for subsequent adds.
                        state.phy.frequencies_of_interest = add.frequencies_hz.clone();
                    }
                    let monitor = state
                        .phy
                        .make_monitor(&add.frequencies_hz, add.antenna.bandwidth_hz);
                    state.phy.receive_antennas.insert(
                        add.antenna.antenna_index,
                        ReceiveAntennaState {
                            antenna: add.antenna,
                            monitor: Arc::new(Mutex::new(monitor)),
                        },
                    );
                }
                CONTROL_RX_ANTENNA_REMOVE => {
                    if let Some(remove) = RxAntennaRemove::decode(payload) {
                        state.phy.receive_antennas.remove(&remove.antenna_index);
                        state
                            .phy
                            .gain_antennas
                            .remove(&(state.id, remove.antenna_index));
                        state
                            .phy
                            .gain_cache
                            .retain(|key, _| key[2] != u64::from(remove.antenna_index));
                        state.phy.nakagami.remove(&remove.antenna_index);
                        state.phy.lognormal_states.remove(&remove.antenna_index);
                    }
                }
                _ => {}
            }
        }
        register_spectrum_monitors(state);
        if packet.is_null() {
            return;
        }
        let packet = unsafe { &*packet };
        if state.phy.radio_silence_enabled {
            (state.framework.increment_counter)(
                state.framework.framework_ctx,
                state.phy.radio_silence_drop_counter,
                1,
            );
            return;
        }
        let accounted_len = phy_accounted_packet_len(packet, incoming);
        state.counters.downstream_rx_packet(
            state.framework,
            packet.info.source,
            packet.info.destination,
            accounted_len,
        );
        let now = unix_time_microseconds();
        let mut tx = find_tx_properties(incoming).unwrap_or(TxProperties {
            frequency_hz: state.phy.frequency_hz,
            bandwidth_hz: state.phy.bandwidth_hz,
            tx_power_dbm: state.phy.tx_power_dbm,
            duration_microseconds: 1,
            offset_microseconds: 0,
            tx_time_microseconds: now,
            antenna_index: 0,
            spectral_mask_index: 0,
            sub_id: state.phy.sub_id,
        });
        if tx.frequency_hz == 0 {
            tx.frequency_hz = state.phy.frequency_hz;
        }
        if tx.bandwidth_hz == 0 {
            tx.bandwidth_hz = state.phy.bandwidth_hz;
        }
        if !tx.tx_power_dbm.is_finite() {
            tx.tx_power_dbm = state.phy.tx_power_dbm;
        }
        if tx.tx_time_microseconds == 0 {
            tx.tx_time_microseconds = now;
        }
        if tx.sub_id == 0 {
            tx.sub_id = state.phy.sub_id;
        }
        tx.spectral_mask_index = state.phy.spectral_mask_index;

        let normalized_segments =
            find_tx_frequency_segments(incoming).map(|segments| TxFrequencySegments {
                segments: segments
                    .segments
                    .into_iter()
                    .map(|segment| TxFrequencySegment {
                        frequency_hz: if segment.frequency_hz == 0 {
                            tx.frequency_hz
                        } else {
                            segment.frequency_hz
                        },
                        duration_microseconds: segment.duration_microseconds,
                        offset_microseconds: segment.offset_microseconds,
                    })
                    .collect(),
            });
        if let Some(segments) = &normalized_segments {
            let first = segments.segments[0];
            tx.frequency_hz = first.frequency_hz;
            tx.offset_microseconds = segments
                .segments
                .iter()
                .map(|segment| segment.offset_microseconds)
                .min()
                .unwrap_or(0);
            tx.duration_microseconds = segments
                .segments
                .iter()
                .map(|segment| {
                    segment
                        .offset_microseconds
                        .saturating_add(segment.duration_microseconds)
                })
                .max()
                .unwrap_or(1)
                .saturating_sub(tx.offset_microseconds);
        }

        let default_mimo = || {
            let group = normalized_segments.as_ref().map_or_else(
                || {
                    vec![MimoTxFrequencySegment {
                        frequency_hz: tx.frequency_hz,
                        tx_power_dbm: None,
                        duration_microseconds: tx.duration_microseconds,
                        offset_microseconds: tx.offset_microseconds,
                    }]
                },
                |segments| {
                    segments
                        .segments
                        .iter()
                        .map(|segment| MimoTxFrequencySegment {
                            frequency_hz: segment.frequency_hz,
                            tx_power_dbm: None,
                            duration_microseconds: segment.duration_microseconds,
                            offset_microseconds: segment.offset_microseconds,
                        })
                        .collect()
                },
            );
            MimoTxProperties {
                frequency_groups: vec![group],
                transmit_antennas: vec![MimoTxAntenna {
                    frequency_group_index: 0,
                    antenna_index: tx.antenna_index,
                    bandwidth_hz: tx.bandwidth_hz,
                    spectral_mask_index: tx.spectral_mask_index,
                    pattern: state
                        .phy
                        .default_antenna_pattern(state.id)
                        .unwrap_or(AntennaPattern::Default),
                }],
            }
        };
        let normalized_mimo = Some(if state.phy.compatibility_mode == 2 {
            find_mimo_tx_properties(incoming)
                .map(|mut mimo| {
                    for group in &mut mimo.frequency_groups {
                        for segment in group {
                            if segment.frequency_hz == 0 {
                                segment.frequency_hz = tx.frequency_hz;
                            }
                        }
                    }
                    for antenna in &mut mimo.transmit_antennas {
                        if antenna.bandwidth_hz == 0 {
                            antenna.bandwidth_hz = tx.bandwidth_hz;
                        }
                        if antenna.spectral_mask_index == 0 {
                            antenna.spectral_mask_index = state.phy.spectral_mask_index;
                        }
                        if antenna.pattern == AntennaPattern::Default {
                            if let Some(pattern) = state.phy.default_antenna_pattern(state.id) {
                                antenna.pattern = pattern;
                            }
                        }
                    }
                    mimo
                })
                .unwrap_or_else(default_mimo)
        } else {
            default_mimo()
        });
        if let Some(mimo) = &normalized_mimo {
            let antenna = mimo.transmit_antennas[0];
            if let Some(group) = mimo
                .frequency_groups
                .get(usize::from(antenna.frequency_group_index))
            {
                let first = group[0];
                tx.frequency_hz = first.frequency_hz;
                tx.tx_power_dbm = first.tx_power_dbm.unwrap_or(tx.tx_power_dbm);
                tx.antenna_index = antenna.antenna_index;
                tx.bandwidth_hz = antenna.bandwidth_hz;
                tx.spectral_mask_index = antenna.spectral_mask_index;
                tx.offset_microseconds = group
                    .iter()
                    .map(|segment| segment.offset_microseconds)
                    .min()
                    .unwrap_or(0);
                tx.duration_microseconds = group
                    .iter()
                    .map(|segment| {
                        segment
                            .offset_microseconds
                            .saturating_add(segment.duration_microseconds)
                    })
                    .max()
                    .unwrap_or(1)
                    .saturating_sub(tx.offset_microseconds)
                    .max(1);
            }
        }

        let ota_transmitters = explicit_ota_transmitters(incoming);
        let ota_transmitter_bytes =
            (!ota_transmitters.nem_ids.is_empty()).then(|| ota_transmitters.encode_to_vec());
        let normalized_transmitters = {
            let mut transmitters = find_tx_transmitters(incoming)
                .map(|transmitters| transmitters.transmitters)
                .unwrap_or_default();
            if !transmitters
                .iter()
                .any(|transmitter| transmitter.nem_id == state.id)
            {
                transmitters.push(TxTransmitter {
                    nem_id: state.id,
                    tx_power_dbm: tx.tx_power_dbm,
                });
            }
            TxTransmitters { transmitters }
        };

        let tx_bytes = tx.encode();
        let segment_bytes = normalized_segments
            .as_ref()
            .and_then(TxFrequencySegments::encode);
        let transmitter_bytes = normalized_transmitters.encode();
        let mimo_bytes = normalized_mimo.as_ref().and_then(MimoTxProperties::encode);
        let mut outgoing: Vec<_> = incoming
            .iter()
            .copied()
            .filter(|message| {
                message.msg_type != CONTROL_TX_PROPERTIES
                    && message.msg_type != CONTROL_TX_FREQUENCY_SEGMENTS
                    && message.msg_type != CONTROL_TX_TRANSMITTERS
                    && message.msg_type != CONTROL_OTA_TRANSMITTERS
                    && message.msg_type != CONTROL_MIMO_TX_PROPERTIES
            })
            .collect();
        outgoing.push(FfiControlMessage {
            msg_type: CONTROL_TX_PROPERTIES,
            payload: FfiSlice {
                data: tx_bytes.as_ptr(),
                len: tx_bytes.len(),
            },
        });
        if let Some(bytes) = &segment_bytes {
            outgoing.push(FfiControlMessage {
                msg_type: CONTROL_TX_FREQUENCY_SEGMENTS,
                payload: FfiSlice {
                    data: bytes.as_ptr(),
                    len: bytes.len(),
                },
            });
        }
        if let Some(bytes) = &transmitter_bytes {
            outgoing.push(FfiControlMessage {
                msg_type: CONTROL_TX_TRANSMITTERS,
                payload: FfiSlice {
                    data: bytes.as_ptr(),
                    len: bytes.len(),
                },
            });
        }
        if let Some(bytes) = &ota_transmitter_bytes {
            outgoing.push(FfiControlMessage {
                msg_type: CONTROL_OTA_TRANSMITTERS,
                payload: FfiSlice {
                    data: bytes.as_ptr(),
                    len: bytes.len(),
                },
            });
        }
        if let Some(bytes) = &mimo_bytes {
            outgoing.push(FfiControlMessage {
                msg_type: CONTROL_MIMO_TX_PROPERTIES,
                payload: FfiSlice {
                    data: bytes.as_ptr(),
                    len: bytes.len(),
                },
            });
        }
        state.counters.downstream_tx_packet(
            state.framework,
            packet.info.source,
            packet.info.destination,
            accounted_len,
            unix_time_microseconds().saturating_sub(began_at).max(0) as u64,
            false,
        );
        (state.framework.send_downstream_packet)(
            state.framework.framework_ctx,
            state.id,
            packet,
            outgoing.as_ptr(),
            outgoing.len(),
        );
        if let Some(interference) = incoming
            .iter()
            .find(|m| m.msg_type == CONTROL_SELF_INTERFERENCE)
            .and_then(|m| {
                if m.payload.data.is_null() {
                    None
                } else {
                    SelfInterference::decode(unsafe {
                        std::slice::from_raw_parts(m.payload.data, m.payload.len)
                    })
                }
            })
        {
            if let Some(mimo) = &normalized_mimo {
                let mut jobs: Vec<Box<dyn FnOnce() + Send>> = Vec::new();
                for antenna in interference.antennas {
                    let monitor = if state.phy.compatibility_mode == 1 && antenna.antenna_index == 0
                    {
                        Some(state.phy.monitor.clone())
                    } else {
                        state
                            .phy
                            .receive_antennas
                            .get(&antenna.antenna_index)
                            .map(|a| a.monitor.clone())
                    };
                    let Some(monitor) = monitor else {
                        continue;
                    };
                    let groups = mimo.frequency_groups.clone();
                    let filter = filter_data(incoming).unwrap_or_default();
                    let id = state.id;
                    jobs.push(Box::new(move || {
                        let mut monitor = monitor.lock().unwrap();
                        for (index, (group, powers)) in antenna.groups.into_iter().enumerate() {
                            let Some(group) = groups.get(usize::from(group)) else {
                                return;
                            };
                            let powers = if powers.len() == 1 {
                                vec![powers[0]; group.len()]
                            } else if powers.len() == group.len() {
                                powers
                            } else {
                                return;
                            };
                            let segments = group
                                .iter()
                                .zip(&powers)
                                .map(|(s, p)| FfiFrequencySegment {
                                    frequency_hz: s.frequency_hz,
                                    rx_power_dbm: 10.0 * p.log10(),
                                    duration_microsec: s.duration_microseconds.min(i64::MAX as u64)
                                        as i64,
                                    offset_microsec: s.offset_microseconds.min(i64::MAX as u64)
                                        as i64,
                                })
                                .collect::<Vec<_>>();
                            monitor.update(
                                now,
                                tx.tx_time_microseconds,
                                0,
                                0.0,
                                &segments,
                                tx.bandwidth_hz,
                                &powers,
                                false,
                                &[id],
                                tx.sub_id,
                                index as u16,
                                0,
                                filter.as_ptr(),
                                filter.len(),
                            );
                        }
                    }));
                }
                if let Some(pool) = &state.phy.processing_pool {
                    let _ = pool.run(jobs);
                } else {
                    for job in jobs {
                        job();
                    }
                }
            }
        }
        return;
    }
    if let Some(packet) = unsafe { packet.as_ref() } {
        state.counters.downstream_rx_packet(
            state.framework,
            packet.info.source,
            packet.info.destination,
            packet.payload.len,
        );
    }
    (state.framework.send_downstream_packet)(
        state.framework.framework_ctx,
        state.id,
        packet,
        messages,
        count,
    );
    if let Some(packet) = unsafe { packet.as_ref() } {
        state.counters.downstream_tx_packet(
            state.framework,
            packet.info.source,
            packet.info.destination,
            packet.payload.len,
            unix_time_microseconds().saturating_sub(began_at).max(0) as u64,
            false,
        );
    }
}

fn ffi_control_messages<'a>(
    messages: *const FfiControlMessage,
    count: usize,
) -> Option<&'a [FfiControlMessage]> {
    if count > 4096 || (count != 0 && messages.is_null()) {
        None
    } else if count == 0 {
        Some(&[])
    } else {
        Some(unsafe { std::slice::from_raw_parts(messages, count) })
    }
}

fn find_tx_properties(messages: &[FfiControlMessage]) -> Option<TxProperties> {
    messages.iter().find_map(|message| {
        if message.msg_type != CONTROL_TX_PROPERTIES
            || message.payload.len != TxProperties::ENCODED_LEN
            || message.payload.data.is_null()
        {
            return None;
        }
        TxProperties::decode(unsafe {
            std::slice::from_raw_parts(message.payload.data, message.payload.len)
        })
    })
}

fn control_payload(messages: &[FfiControlMessage], kind: u32) -> Option<&[u8]> {
    messages.iter().find_map(|message| {
        if message.msg_type != kind
            || message.payload.len > MAX_CONTROL_WIRE_SIZE
            || (message.payload.len != 0 && message.payload.data.is_null())
        {
            None
        } else if message.payload.len == 0 {
            Some(&[] as &[u8])
        } else {
            Some(unsafe { std::slice::from_raw_parts(message.payload.data, message.payload.len) })
        }
    })
}

fn find_tx_frequency_segments(messages: &[FfiControlMessage]) -> Option<TxFrequencySegments> {
    control_payload(messages, CONTROL_TX_FREQUENCY_SEGMENTS).and_then(TxFrequencySegments::decode)
}

fn find_tx_transmitters(messages: &[FfiControlMessage]) -> Option<TxTransmitters> {
    messages
        .iter()
        .rev()
        .find(|message| message.msg_type == CONTROL_TX_TRANSMITTERS)
        .and_then(|message| control_payload(std::slice::from_ref(message), CONTROL_TX_TRANSMITTERS))
        .and_then(TxTransmitters::decode)
}

fn find_tx_antenna_profile(messages: &[FfiControlMessage]) -> Option<TxAntennaProfile> {
    control_payload(messages, CONTROL_TX_ANTENNA_PROFILE).and_then(TxAntennaProfile::decode)
}

fn find_mimo_tx_properties(messages: &[FfiControlMessage]) -> Option<MimoTxProperties> {
    control_payload(messages, CONTROL_MIMO_TX_PROPERTIES).and_then(MimoTxProperties::decode)
}

fn unix_time_microseconds() -> i64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    i64::try_from(now.as_micros()).unwrap_or(i64::MAX)
}

fn reception_noise_floor_dbm(
    monitor: &SpectrumMonitor,
    now: i64,
    tx_time: i64,
    propagation: i64,
    span: i64,
    segment: &FfiFrequencySegment,
) -> f64 {
    let start = tx_time
        .saturating_add(propagation)
        .saturating_add(segment.offset_microsec);
    let duration = span.max(segment.duration_microsec).max(1);
    let query_time = now.max(start.saturating_add(duration));
    let (bins, _, _, sensitivity_mw, signal_in_noise) =
        monitor.request_i(query_time, segment.frequency_hz, duration, start);
    let max_mw = bins.into_iter().fold(sensitivity_mw, f64::max);
    let signal_mw = 10.0f64.powf(segment.rx_power_dbm / 10.0);
    let noise_mw = if signal_in_noise {
        (max_mw - signal_mw).max(sensitivity_mw)
    } else {
        max_mw.max(sensitivity_mw)
    };
    10.0 * noise_mw.log10()
}

extern "C" fn builtin_timed(_: *mut c_void, _: u64, _: u32, _: *const u8, _: usize) {}
extern "C" fn builtin_event(state: *mut c_void, event_id: u16, data: *const u8, len: usize) {
    let Some(state) = (unsafe { (state as *mut BuiltinState).as_mut() }) else {
        return;
    };
    if state.kind != BuiltinKind::Phy || len > 16 * 1024 * 1024 || (len != 0 && data.is_null()) {
        return;
    }
    let bytes = if len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(data, len) }
    };
    use crate::protobufs::emane_message::{
        fading_selection_event, AntennaProfileEvent, FadingSelectionEvent, LocationEvent,
        PathlossEvent, PathlossExEvent,
    };
    match event_id {
        100 => {
            let Ok(event) = LocationEvent::decode(bytes) else {
                return;
            };
            for location in event.locations {
                let Ok(nem_id) = u16::try_from(location.nem_id) else {
                    continue;
                };
                let position = location.position;
                if position.latitude_degrees.is_finite()
                    && position.longitude_degrees.is_finite()
                    && position.altitude_meters.is_finite()
                    && (-90.0..=90.0).contains(&position.latitude_degrees)
                    && (-180.0..=180.0).contains(&position.longitude_degrees)
                {
                    let velocity = location.velocity.and_then(|velocity| {
                        (velocity.azimuth_degrees.is_finite()
                            && velocity.elevation_degrees.is_finite()
                            && velocity.magnitude_meters_per_second.is_finite()
                            && velocity.magnitude_meters_per_second >= 0.0)
                            .then_some(Velocity {
                                azimuth_degrees: velocity.azimuth_degrees,
                                elevation_degrees: velocity.elevation_degrees,
                                magnitude_meters_per_second: velocity.magnitude_meters_per_second,
                            })
                    });
                    let orientation = location.orientation.and_then(|orientation| {
                        (orientation.roll_degrees.is_finite()
                            && orientation.pitch_degrees.is_finite()
                            && orientation.yaw_degrees.is_finite())
                        .then_some(Orientation {
                            roll_degrees: orientation.roll_degrees,
                            pitch_degrees: orientation.pitch_degrees,
                            yaw_degrees: orientation.yaw_degrees,
                        })
                    });
                    state.phy.update_location(
                        nem_id,
                        position.latitude_degrees,
                        position.longitude_degrees,
                        position.altitude_meters,
                        orientation,
                        velocity,
                    );
                    if let (Some(handle), Some(location)) = (
                        state.phy.location_event_table,
                        state.phy.locations.get(&nem_id).copied(),
                    ) {
                        let velocity = location.velocity.unwrap_or(Velocity {
                            azimuth_degrees: 0.0,
                            elevation_degrees: 0.0,
                            magnitude_meters_per_second: 0.0,
                        });
                        let _ = set_native_table_row(
                            handle,
                            vec![u64::from(nem_id)],
                            vec![
                                NativeTableValue::UInt16(nem_id),
                                NativeTableValue::Double(location.latitude_degrees),
                                NativeTableValue::Double(location.longitude_degrees),
                                NativeTableValue::Double(location.altitude_meters),
                                NativeTableValue::Double(location.orientation.pitch_degrees),
                                NativeTableValue::Double(location.orientation.roll_degrees),
                                NativeTableValue::Double(location.orientation.yaw_degrees),
                                NativeTableValue::Double(velocity.azimuth_degrees),
                                NativeTableValue::Double(velocity.elevation_degrees),
                                NativeTableValue::Double(velocity.magnitude_meters_per_second),
                            ],
                        );
                    }
                }
            }
        }
        101 => {
            let Ok(event) = PathlossEvent::decode(bytes) else {
                return;
            };
            for pathloss in event.pathlosses {
                let Ok(nem_id) = u16::try_from(pathloss.nem_id) else {
                    continue;
                };
                let value = f64::from(pathloss.forward_pathlossd_b);
                if value.is_finite() {
                    state
                        .phy
                        .pathloss
                        .entry(nem_id)
                        .or_default()
                        .insert(0, value);
                    if let Some(handle) = state.phy.pathloss_event_table {
                        let _ = set_native_table_row(
                            handle,
                            vec![u64::from(nem_id)],
                            vec![
                                NativeTableValue::UInt16(nem_id),
                                NativeTableValue::Float(pathloss.forward_pathlossd_b),
                                NativeTableValue::Float(pathloss.reverse_pathlossd_b),
                            ],
                        );
                    }
                }
            }
        }
        107 => {
            let Ok(event) = PathlossExEvent::decode(bytes) else {
                return;
            };
            for pathloss in event.pathlosses {
                let Ok(nem_id) = u16::try_from(pathloss.nem_id) else {
                    continue;
                };
                let values = state.phy.pathloss.entry(nem_id).or_default();
                for entry in pathloss.entries {
                    let value = f64::from(entry.pathlossd_b);
                    if value.is_finite() {
                        values.insert(entry.frequency_hz, value);
                        if let Some(handle) = state.phy.pathloss_ex_event_table {
                            let _ = set_native_table_row(
                                handle,
                                vec![u64::from(nem_id), entry.frequency_hz],
                                vec![
                                    NativeTableValue::UInt16(nem_id),
                                    NativeTableValue::UInt64(entry.frequency_hz),
                                    NativeTableValue::Float(entry.pathlossd_b),
                                ],
                            );
                        }
                    }
                }
            }
        }
        102 => {
            let Ok(event) = AntennaProfileEvent::decode(bytes) else {
                return;
            };
            for profile in event.profiles {
                let (Ok(nem_id), Ok(profile_id)) = (
                    u16::try_from(profile.nem_id),
                    u16::try_from(profile.profile_id),
                ) else {
                    continue;
                };
                if profile.antenna_azimuth_degrees.is_finite()
                    && profile.antenna_elevation_degrees.is_finite()
                {
                    state.phy.antenna_profiles.insert(
                        nem_id,
                        AntennaProfileSelection {
                            profile_id,
                            azimuth_degrees: profile.antenna_azimuth_degrees,
                            elevation_degrees: profile.antenna_elevation_degrees,
                        },
                    );
                    let pattern = AntennaPattern::Profile(TxAntennaProfile {
                        profile_id,
                        azimuth_degrees: profile.antenna_azimuth_degrees,
                        elevation_degrees: profile.antenna_elevation_degrees,
                    });
                    let existing = state.phy.gain_antennas.get(&(nem_id, 0)).copied();
                    state.phy.update_gain_antenna(
                        nem_id,
                        MimoTxAntenna {
                            antenna_index: 0,
                            frequency_group_index: existing
                                .map_or(0, |antenna| antenna.frequency_group_index),
                            bandwidth_hz: existing.map_or(0, |antenna| antenna.bandwidth_hz),
                            spectral_mask_index: existing
                                .map_or(0, |antenna| antenna.spectral_mask_index),
                            pattern,
                        },
                    );
                    if nem_id == state.id {
                        if let Some(entry) = state.phy.receive_antennas.get_mut(&0) {
                            entry.antenna.pattern = pattern;
                        }
                    }
                    if let Some(handle) = state.phy.antenna_profile_event_table {
                        let _ = set_native_table_row(
                            handle,
                            vec![u64::from(nem_id)],
                            vec![
                                NativeTableValue::UInt16(nem_id),
                                NativeTableValue::UInt16(profile_id),
                                NativeTableValue::Double(profile.antenna_azimuth_degrees),
                                NativeTableValue::Double(profile.antenna_elevation_degrees),
                            ],
                        );
                    }
                }
            }
        }
        106 => {
            let Ok(event) = FadingSelectionEvent::decode(bytes) else {
                return;
            };
            for entry in event.entries {
                let Ok(nem_id) = u16::try_from(entry.nem_id) else {
                    continue;
                };
                let (mode, name) = match fading_selection_event::Model::try_from(entry.model) {
                    Ok(fading_selection_event::Model::TypeNone) => (FadingMode::None, "none"),
                    Ok(fading_selection_event::Model::TypeNakagami) => {
                        (FadingMode::Nakagami, "nakagami")
                    }
                    Ok(fading_selection_event::Model::TypeLognormal) => {
                        (FadingMode::Lognormal, "lognormal")
                    }
                    Err(_) => continue,
                };
                state.phy.fading_selections.insert(nem_id, mode);

                if let Some(handle) = state.phy.fading_selection_event_table {
                    let _ = set_native_table_row(
                        handle,
                        vec![u64::from(nem_id)],
                        vec![
                            NativeTableValue::UInt16(nem_id),
                            NativeTableValue::String(name.to_string()),
                        ],
                    );
                }
            }
        }
        _ => {}
    }
}

fn builtin_api(plugin: &str, plugin_type: u32) -> &'static PluginApi {
    static PHY: OnceLock<PluginApi> = OnceLock::new();
    static VIRTUAL: OnceLock<PluginApi> = OnceLock::new();
    static RAW: OnceLock<PluginApi> = OnceLock::new();
    let virtual_transport = matches!(plugin, "virtualtransport" | "transvirtual");
    let (slot, name, init): (
        &OnceLock<PluginApi>,
        &'static [u8],
        extern "C" fn(u16, *const FfiFrameworkService) -> *mut c_void,
    ) = if plugin_type == 2 {
        (&PHY, b"emanephy\0", builtin_phy_init)
    } else if virtual_transport {
        (&VIRTUAL, b"virtualtransport\0", builtin_virtual_init)
    } else {
        (&RAW, b"rawtransport\0", builtin_raw_init)
    };
    slot.get_or_init(|| PluginApi {
        abi_version: PLUGIN_ABI_VERSION,
        struct_size: std::mem::size_of::<PluginApi>(),
        name: name.as_ptr().cast(),
        plugin_type,
        init,
        configure: builtin_configure,
        start: builtin_start,
        post_start: builtin_post_start,
        stop: builtin_stop,
        destroy: builtin_destroy,
        process_upstream: builtin_upstream,
        process_downstream: builtin_downstream,
        process_timed_event: builtin_timed,
        process_event: builtin_event,
    })
}

struct ConfigGuard {
    request: FfiConfigRequest,
    _names: Vec<CString>,
    _values: Vec<Vec<CString>>,
    _value_pointers: Vec<Vec<*const std::os::raw::c_char>>,
    _items: Vec<FfiConfigItem>,
}

impl ConfigGuard {
    fn new(config: &[(String, Vec<String>)]) -> Self {
        let names: Vec<_> = config
            .iter()
            .map(|(name, _)| CString::new(name.as_str()).unwrap())
            .collect();
        let values: Vec<Vec<_>> = config
            .iter()
            .map(|(_, values)| {
                values
                    .iter()
                    .map(|value| CString::new(value.as_str()).unwrap())
                    .collect()
            })
            .collect();
        let value_pointers: Vec<Vec<_>> = values
            .iter()
            .map(|values| values.iter().map(|value| value.as_ptr()).collect())
            .collect();
        let items: Vec<_> = names
            .iter()
            .zip(value_pointers.iter())
            .map(|(name, values)| FfiConfigItem {
                name: name.as_ptr(),
                values: FfiConfigStringArray {
                    data: values.as_ptr(),
                    len: values.len(),
                },
            })
            .collect();
        let request = FfiConfigRequest {
            data: items.as_ptr(),
            len: items.len(),
        };
        Self {
            request,
            _names: names,
            _values: values,
            _value_pointers: value_pointers,
            _items: items,
        }
    }
}

pub struct NemManager {
    uuid: [u8; 16],
    runtime: Arc<Runtime>,
    layers: BTreeMap<u16, Vec<NemLayer>>,
    boundary_definitions: BTreeMap<u16, BoundaryDefinition>,
    boundary_endpoints: BTreeMap<u16, Arc<Mutex<BoundaryMessageManager>>>,
    stopped: bool,
    stopped_after_start: bool,
}

#[derive(Clone)]
struct BoundaryDefinition {
    local: String,
    remote: String,
    protocol: BoundaryProtocol,
    role: BoundaryRole,
}

impl NemManager {
    pub fn new(uuid: [u8; 16]) -> Self {
        Self {
            uuid,
            runtime: Arc::new(Runtime {
                uuid,
                invocations: RwLock::new(HashMap::new()),
                boundaries: RwLock::new(HashMap::new()),
                phy_tx_sequences: Mutex::new(HashMap::new()),
                spectrum_monitors: RwLock::new(HashMap::new()),
            }),
            layers: BTreeMap::new(),
            boundary_definitions: BTreeMap::new(),
            boundary_endpoints: BTreeMap::new(),
            stopped: true,
            stopped_after_start: false,
        }
    }

    pub fn uuid(&self) -> [u8; 16] {
        self.uuid
    }

    pub fn layer_build_ids(&self, nem_id: u16) -> Vec<u16> {
        self.layers
            .get(&nem_id)
            .map(|layers| layers.iter().map(|layer| layer.event_build_id).collect())
            .unwrap_or_default()
    }

    pub fn add_layer(&mut self, nem_id: u16, plugin: &str) -> Result<(), String> {
        self.add_layer_configured(nem_id, plugin, 1, &[])
    }

    pub fn add_platform_boundary(
        &mut self,
        nem_id: u16,
        platform_endpoint: String,
        transport_endpoint: String,
        protocol: BoundaryProtocol,
    ) -> Result<(), String> {
        self.add_boundary(
            nem_id,
            platform_endpoint,
            transport_endpoint,
            protocol,
            BoundaryRole::Platform,
        )
    }

    pub fn add_transport_boundary(
        &mut self,
        nem_id: u16,
        transport_endpoint: String,
        platform_endpoint: String,
        protocol: BoundaryProtocol,
    ) -> Result<(), String> {
        self.add_boundary(
            nem_id,
            transport_endpoint,
            platform_endpoint,
            protocol,
            BoundaryRole::Transport,
        )
    }

    fn add_boundary(
        &mut self,
        nem_id: u16,
        local: String,
        remote: String,
        protocol: BoundaryProtocol,
        role: BoundaryRole,
    ) -> Result<(), String> {
        if !self.stopped {
            return Err("cannot add a boundary endpoint after manager start".to_string());
        }
        if local.is_empty() || remote.is_empty() {
            return Err(format!("NEM {nem_id} boundary endpoints must not be empty"));
        }
        if self
            .boundary_definitions
            .insert(
                nem_id,
                BoundaryDefinition {
                    local,
                    remote,
                    protocol,
                    role,
                },
            )
            .is_some()
        {
            return Err(format!("NEM {nem_id} has more than one boundary endpoint"));
        }
        Ok(())
    }

    pub fn add_layer_configured(
        &mut self,
        nem_id: u16,
        plugin: &str,
        expected_type: u32,
        config: &[(String, Vec<String>)],
    ) -> Result<(), String> {
        let layer_index = self.layers.get(&nem_id).map_or(0, Vec::len);
        let (library, api): (Option<Library>, *const PluginApi) = if plugin.is_empty()
            || plugin == "emanephy"
            || plugin == "virtualtransport"
            || plugin == "rawtransport"
            || plugin == "transvirtual"
            || plugin == "transraw"
        {
            (None, builtin_api(plugin, expected_type) as *const PluginApi)
        } else {
            let path = resolve_plugin_path(plugin)?;
            let library = unsafe { Library::new(&path) }
                .map_err(|error| format!("failed to load {}: {error}", path.display()))?;
            let entry: Symbol<PluginEntryFunc> = unsafe { library.get(b"emane_plugin_create") }
                .map_err(|error| {
                    format!("{} has no emane_plugin_create: {error}", path.display())
                })?;
            let api = entry();
            if api.is_null() {
                return Err(format!("{} returned a null plugin API", path.display()));
            }
            (Some(library), api)
        };

        let abi_version = unsafe { (*api).abi_version };
        let struct_size = unsafe { (*api).struct_size };
        if abi_version != PLUGIN_ABI_VERSION || struct_size != std::mem::size_of::<PluginApi>() {
            return Err(format!(
                "plugin ABI mismatch for {plugin}: version {abi_version}, size {struct_size}"
            ));
        }
        let actual_type = unsafe { (*api).plugin_type };
        if actual_type != expected_type {
            return Err(format!(
                "plugin type mismatch for {plugin}: expected {expected_type}, got {actual_type}"
            ));
        }
        let api_name = unsafe { (*api).name };
        if api_name.is_null() {
            return Err(format!("plugin {plugin} returned a null name"));
        }
        let registered_plugin_name = unsafe { CStr::from_ptr(api_name) }
            .to_string_lossy()
            .into_owned();
        let configuration_schema = component_configuration_schema(&registered_plugin_name);
        let normalized = crate::native_configuration::parse_initial(&configuration_schema, config)?
            .into_iter()
            .map(|(name, values)| {
                (
                    name,
                    values.into_iter().map(|v| v.text()).collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>();
        let config = &normalized;
        let event_build_id = next_event_build_id();
        if event_build_id == 0 {
            return Err("component build-id space is exhausted".to_string());
        }
        let queue = Box::new(NemQueuedLayer::new_with_build_id(nem_id, event_build_id));
        let queue_ptr = queue.as_ref() as *const NemQueuedLayer as usize;
        let mut framework_context = Box::new(FrameworkContext {
            runtime: Arc::downgrade(&self.runtime),
            nem_id,
            layer_index,
            build_id: event_build_id,
            neighbor_metrics: Mutex::new(NeighborMetricManager::new(nem_id)),
            queue_metrics: Mutex::new(QueueMetricManager::new(nem_id)),
            compatibility_tables: Mutex::new(HashMap::new()),
            descriptor_handles: Mutex::new(Vec::new()),
        });
        let framework = FfiFrameworkService {
            framework_ctx: framework_context.as_mut() as *mut FrameworkContext as *mut c_void,
            send_downstream_packet,
            send_upstream_packet,
            send_downstream_control,
            send_upstream_control,
            schedule_timed_event,
            cancel_timed_event,
            log,
            register_counter,
            register_counter32,
            increment_counter,
            maximize_counter,
            register_double,
            set_double,
            register_average,
            sample_average,
            register_table,
            set_table_row,
            clear_table,
            remove_table_row,
            table_generation,
            update_neighbor_tx,
            update_neighbor_rx,
            update_neighbor_status,
            register_queue_metric,
            update_queue_metric,
            publish_r2ri,
            register_rf_signal_table,
            configure_rf_signal_table,
            update_rf_signal_table,
            publish_event,
            register_file_descriptor,
            unregister_file_descriptor,
            query_spectrum_filter,
            query_spectrum,
        };
        let plugin_context =
            with_component_execution(|| unsafe { ((*api).init)(nem_id, &framework) });
        if plugin_context.is_null() {
            unregister_native_statistics(event_build_id);
            return Err(format!("plugin {plugin} failed to initialize"));
        }
        let config_guard = ConfigGuard::new(config);
        let configured = with_component_execution(|| unsafe {
            ((*api).configure)(
                plugin_context,
                &config_guard.request as *const FfiConfigRequest as *const c_void,
            )
        });
        if !configured {
            with_component_execution(|| unsafe { ((*api).destroy)(plugin_context) });
            unregister_native_statistics(event_build_id);
            return Err(format!("plugin {plugin} rejected its configuration"));
        }
        if let Ok(mut tables) = framework_context.compatibility_tables.lock() {
            *tables =
                register_model_compatibility_statistics(event_build_id, &registered_plugin_name);
        }
        let invocation = Invocation {
            api: api as usize,
            plugin_ctx: plugin_context as usize,
            queue: queue_ptr,
        };
        let update_invocation = invocation;
        if let Err(error) = register_native_configuration(
            event_build_id,
            component_configuration_defaults(&registered_plugin_name),
            configuration_schema,
            config,
            &component_modifiable_parameters(&registered_plugin_name),
            move |updates| {
                let values = updates
                    .iter()
                    .map(|(name, values)| {
                        (
                            name.clone(),
                            values.iter().map(|value| value.text()).collect::<Vec<_>>(),
                        )
                    })
                    .collect::<Vec<_>>();
                update_invocation.configure_running(values)
            },
        ) {
            with_component_execution(|| unsafe { ((*api).destroy)(plugin_context) });
            unregister_native_statistics(event_build_id);
            return Err(error);
        }
        let framework_context_ptr =
            framework_context.as_mut() as *mut FrameworkContext as *mut c_void;
        register_event_user(
            event_build_id,
            nem_id,
            framework_context_ptr,
            framework_event,
        );
        for event_id in component_event_ids(&registered_plugin_name) {
            if !emane_rs_event_service_register_event(event_build_id, *event_id) {
                unregister_event_user(event_build_id);
                unregister_native_configuration(event_build_id);
                unregister_native_statistics(event_build_id);
                with_component_execution(|| unsafe { ((*api).destroy)(plugin_context) });
                return Err(format!(
                    "failed to register plugin {plugin} for event {event_id}"
                ));
            }
        }
        if expected_type == 2 {
            register_native_user(nem_id, framework_context_ptr, ota_packet);
        }
        let runtime_result = self.runtime.invocations.write();
        let Ok(mut runtime_layers) = runtime_result else {
            if expected_type == 2 {
                unregister_native_user(nem_id, framework_context_ptr);
            }
            unregister_event_user(event_build_id);
            unregister_native_configuration(event_build_id);
            unregister_native_statistics(event_build_id);
            with_component_execution(|| unsafe { ((*api).destroy)(plugin_context) });
            return Err("NEM runtime lock poisoned".to_string());
        };
        runtime_layers.entry(nem_id).or_default().push(invocation);
        drop(runtime_layers);
        self.layers.entry(nem_id).or_default().push(NemLayer {
            _library: library,
            invocation,
            queue,
            _framework_context: framework_context,
            event_build_id,
            started: false,
            destroyed: false,
        });
        emane_rs_buildid_register_layer(
            nem_id,
            event_build_id,
            i32::try_from(actual_type).unwrap_or(i32::MAX),
            unsafe { (*api).name },
        );
        Ok(())
    }

    pub fn start(&mut self) -> Result<(), String> {
        // Original NEMLayerStateStopped is terminal: only destroy is valid.
        // A failed first start stays configurable and may still be retried.
        if self.stopped_after_start {
            return Err("NEM layers cannot restart after stop".to_string());
        }
        if !self.stopped {
            return Err("NEM manager is already started".to_string());
        }
        self.stopped = false;
        let definitions = self
            .boundary_definitions
            .iter()
            .map(|(nem_id, definition)| (*nem_id, definition.clone()))
            .collect::<Vec<_>>();
        for (nem_id, definition) in definitions {
            if !self.layers.contains_key(&nem_id) {
                self.stop();
                return Err(format!("boundary endpoint references unknown NEM {nem_id}"));
            }
            let weak_runtime = Arc::downgrade(&self.runtime);
            let id = nem_id;
            let role = definition.role;
            let endpoint = match BoundaryMessageManager::open(
                &definition.local,
                &definition.remote,
                definition.protocol,
                move |message| {
                    if let Some(runtime) = weak_runtime.upgrade() {
                        runtime.process_boundary_message(id, role, message);
                    }
                },
            ) {
                Ok(endpoint) => Arc::new(Mutex::new(endpoint)),
                Err(error) => {
                    self.stop();
                    return Err(format!("failed to open NEM {nem_id} boundary: {error}"));
                }
            };
            self.boundary_endpoints
                .insert(nem_id, Arc::clone(&endpoint));
            let Ok(mut routes) = self.runtime.boundaries.write() else {
                self.stop();
                return Err("NEM boundary runtime lock poisoned".to_string());
            };
            routes.insert(nem_id, BoundaryRoute { role, endpoint });
        }
        let mut failure = None;
        for layers in self.layers.values_mut() {
            for layer in layers {
                layer.queue.start();
                if !layer.invocation.call(|api, context| (api.start)(context)) {
                    layer.queue.stop();
                    failure = Some(format!(
                        "plugin type {} failed to start",
                        layer.invocation.api().plugin_type
                    ));
                    break;
                }
                layer.queue.set_model_running(true);
                layer.started = true;
            }
            if failure.is_some() {
                break;
            }
        }
        if let Some(error) = failure {
            self.stop();
            return Err(error);
        }
        Ok(())
    }

    pub fn post_start(&self) {
        for layers in self.layers.values() {
            for layer in layers.iter().filter(|layer| layer.started) {
                layer
                    .invocation
                    .call(|api, context| (api.post_start)(context));
            }
        }
    }

    pub fn stop(&mut self) {
        if self.stopped {
            return;
        }
        if let Ok(mut routes) = self.runtime.boundaries.write() {
            routes.clear();
        }
        for endpoint in self.boundary_endpoints.values() {
            if let Ok(mut endpoint) = endpoint.lock() {
                endpoint.close();
            }
        }
        self.boundary_endpoints.clear();
        for layers in self.layers.values_mut() {
            for layer in layers {
                if layer.started {
                    self.stopped_after_start = true;
                    layer.invocation.call(|api, context| (api.stop)(context));
                    layer.queue.set_model_running(false);
                    if let Ok(mut handles) = layer._framework_context.descriptor_handles.lock() {
                        for handle in handles.drain(..) {
                            let _ = file_descriptor_service::unregister(handle);
                        }
                    }
                    layer.queue.stop();
                    layer.started = false;
                } else if layer.queue.is_running() {
                    layer.queue.stop();
                }
            }
        }
        self.stopped = true;
    }

    pub fn process_downstream(
        &self,
        nem_id: u16,
        packet: &FfiPacket,
        messages: &[FfiControlMessage],
    ) -> Result<(), String> {
        let first = self
            .runtime
            .invocation(nem_id, 0)
            .ok_or_else(|| format!("unknown or empty NEM {nem_id}"))?;
        first.process(true, packet, messages.as_ptr(), messages.len());
        Ok(())
    }

    pub fn process_upstream(
        &self,
        nem_id: u16,
        packet: &FfiPacket,
        messages: &[FfiControlMessage],
    ) -> Result<(), String> {
        let last = self
            .runtime
            .last_invocation(nem_id)
            .ok_or_else(|| format!("unknown or empty NEM {nem_id}"))?;
        last.process(false, packet, messages.as_ptr(), messages.len());
        Ok(())
    }
}

impl Drop for NemManager {
    fn drop(&mut self) {
        self.stop();
        if let Ok(mut invocations) = self.runtime.invocations.write() {
            invocations.clear();
        }
        for (nem_id, layers) in &self.layers {
            for layer in layers
                .iter()
                .filter(|layer| layer.invocation.api().plugin_type == 2)
            {
                unregister_native_user(
                    *nem_id,
                    layer._framework_context.as_ref() as *const FrameworkContext as *mut c_void,
                );
            }
        }
        for layer in self.layers.values().flatten() {
            if let Ok(mut handles) = layer._framework_context.descriptor_handles.lock() {
                for handle in handles.drain(..) {
                    let _ = file_descriptor_service::unregister(handle);
                }
            }
            unregister_event_user(layer.event_build_id);
            unregister_native_statistics(layer.event_build_id);
            unregister_native_configuration(layer.event_build_id);
        }
        for (nem_id, layer) in self
            .layers
            .iter()
            .flat_map(|(nem_id, layers)| layers.iter().map(move |layer| (nem_id, layer)))
        {
            unregister_native_layer(*nem_id, layer.event_build_id);
        }
        if let Ok(mut runtime_layers) = self.runtime.invocations.write() {
            runtime_layers.clear();
        }
        for layers in self.layers.values_mut() {
            for layer in layers {
                if !layer.destroyed {
                    layer.invocation.call(|api, context| (api.destroy)(context));
                    layer.destroyed = true;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin_interface::{FfiPacketInfo, FfiSlice};
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::Mutex as StdMutex;

    static LOCAL_OTA_HITS: AtomicUsize = AtomicUsize::new(0);
    static BYPASS_STACK_HITS: AtomicUsize = AtomicUsize::new(0);
    static BYPASS_STACK_BYTES: AtomicUsize = AtomicUsize::new(0);
    static PHY_CAPTURE_SEGMENTS: AtomicUsize = AtomicUsize::new(0);
    static PHY_CAPTURE_POWER_BITS: AtomicU64 = AtomicU64::new(0);
    static PHY_CAPTURE_MIMO_INFOS: AtomicUsize = AtomicUsize::new(0);
    static PHY_CAPTURE_RX_ANTENNA: AtomicUsize = AtomicUsize::new(0);
    static PHY_CAPTURE_TX_POWER_BITS: AtomicU64 = AtomicU64::new(0);
    static PHY_CAPTURE_TX_GAIN_BITS: AtomicU64 = AtomicU64::new(0);
    static R2RI_CAPTURE_COUNT: AtomicUsize = AtomicUsize::new(0);
    // Dynamically loaded model libraries contain process-global state. Keep
    // tests that load them from racing each other inside one test process.
    static DYNAMIC_PLUGIN_TEST_LOCK: StdMutex<()> = StdMutex::new(());

    #[test]
    fn timed_event_expiration_distinguishes_relative_and_stale_absolute_time() {
        let now = 1_800_000_000_000_000u64;
        assert_eq!(timed_event_expiration(250_000, now), now + 250_000);
        assert_eq!(timed_event_expiration(now - 1, now), now);
        assert_eq!(timed_event_expiration(now + 1, now), now + 1);
    }

    #[test]
    fn configuration_surfaces_include_legacy_parameters_without_defaults() {
        for plugin in [
            "emanephy",
            "rfpipe",
            "ieee80211abg",
            "tdma",
            "bentpipe",
            "phyapitestshim",
        ] {
            let defaults = component_configuration_defaults(plugin)
                .into_iter()
                .collect::<HashMap<_, _>>();
            for (required, _) in component_configuration_schema(plugin)
                .iter()
                .filter(|(_, spec)| spec.required)
            {
                assert_eq!(
                    defaults.get(required),
                    Some(&Vec::new()),
                    "{plugin} must manifest required parameter {required} without inventing a default"
                );
            }
        }

        let names = |plugin: &str| {
            component_configuration_defaults(plugin)
                .into_iter()
                .map(|(name, _)| name)
                .collect::<std::collections::BTreeSet<_>>()
        };

        let virtual_transport = names("virtualtransport");
        for expected in ["address", "mask", "ethernet.type.unknown.priority"] {
            assert!(virtual_transport.contains(expected));
        }

        let raw_transport = names("rawtransport");
        for expected in ["device", "ethernet.type.unknown.priority"] {
            assert!(raw_transport.contains(expected));
        }

        assert!(names("commeffectshim").contains("filterfile"));
        let phy_api_test = names("phyapitestshim");
        for expected in [
            "bandwidth",
            "antennaprofileid",
            "antennaazimuth",
            "antennaelevation",
            "frequency",
            "transmitter",
        ] {
            assert!(phy_api_test.contains(expected));
        }

        let rfpipe = names("rfpipe");
        assert!(rfpipe.contains("rfsignaltable.averageallantennas"));
        assert!(!rfpipe.contains("rfsignaltable.averageallantenna"));
    }

    struct CaptureTransport {
        id: u16,
        framework: FfiFrameworkService,
    }

    extern "C" fn test_init(_: u16, _: *const FfiFrameworkService) -> *mut c_void {
        std::ptr::dangling_mut::<u8>().cast()
    }
    extern "C" fn test_configure(_: *mut c_void, _: *const c_void) -> bool {
        true
    }
    extern "C" fn test_start(_: *mut c_void) -> bool {
        true
    }
    extern "C" fn test_lifecycle(_: *mut c_void) {}
    extern "C" fn test_packet(
        _: *mut c_void,
        _: *const FfiPacket,
        _: *const FfiControlMessage,
        _: usize,
    ) {
    }
    extern "C" fn test_upstream(
        _: *mut c_void,
        _: *const FfiPacket,
        _: *const FfiControlMessage,
        _: usize,
    ) {
        LOCAL_OTA_HITS.fetch_add(1, Ordering::Relaxed);
    }
    extern "C" fn test_timed(_: *mut c_void, _: u64, _: u32, _: *const u8, _: usize) {}
    extern "C" fn test_event(_: *mut c_void, _: u16, _: *const u8, _: usize) {}

    extern "C" fn phy_capture_packet(
        _: *mut c_void,
        _: u16,
        _: *const FfiPacket,
        messages: *const FfiControlMessage,
        count: usize,
    ) {
        let Some(messages) = ffi_control_messages(messages, count) else {
            return;
        };
        if let Some(tx) = find_tx_properties(messages) {
            PHY_CAPTURE_TX_POWER_BITS.store(tx.tx_power_dbm.to_bits(), Ordering::Relaxed);
        }
        if let Some(mimo) = find_mimo_tx_properties(messages) {
            if let Some(antenna) = mimo.transmit_antennas.first() {
                if let AntennaPattern::IdealOmni { gain_db } = antenna.pattern {
                    PHY_CAPTURE_TX_GAIN_BITS.store(gain_db.to_bits(), Ordering::Relaxed);
                }
            }
        }
        if let Some(properties) =
            control_payload(messages, CONTROL_MIMO_RX_PROPERTIES).and_then(MimoRxProperties::decode)
        {
            PHY_CAPTURE_MIMO_INFOS.store(properties.antenna_infos.len(), Ordering::Relaxed);
            PHY_CAPTURE_SEGMENTS.store(
                properties
                    .antenna_infos
                    .iter()
                    .map(|info| info.segments.len())
                    .sum(),
                Ordering::Relaxed,
            );
            if let Some(info) = properties.antenna_infos.first() {
                PHY_CAPTURE_RX_ANTENNA
                    .store(usize::from(info.receive_antenna_index), Ordering::Relaxed);
                if let Some(segment) = info.segments.first() {
                    PHY_CAPTURE_POWER_BITS.store(segment.rx_power_dbm.to_bits(), Ordering::Relaxed);
                }
            }
        }
        let Some(segments) = control_payload(messages, CONTROL_RX_FREQUENCY_SEGMENTS)
            .and_then(RxFrequencySegments::decode)
        else {
            return;
        };
        PHY_CAPTURE_SEGMENTS.store(segments.segments.len(), Ordering::Relaxed);
        if let Some(segment) = segments.segments.first() {
            PHY_CAPTURE_POWER_BITS.store(segment.rx_power_dbm.to_bits(), Ordering::Relaxed);
        }
    }

    extern "C" fn phy_capture_control(
        _: *mut c_void,
        _: u16,
        _: *const FfiControlMessage,
        _: usize,
    ) {
    }

    extern "C" fn phy_capture_schedule(
        _: *mut c_void,
        _: u16,
        _: u64,
        _: u32,
        _: u32,
        _: *const u8,
        _: usize,
    ) -> u64 {
        0
    }

    extern "C" fn phy_capture_cancel(_: *mut c_void, _: u16, _: u64) {}

    extern "C" fn phy_capture_log(_: *mut c_void, _: u32, _: *const std::os::raw::c_char) {}

    extern "C" fn phy_capture_register(
        _: *mut c_void,
        _: *const std::os::raw::c_char,
        _: *const std::os::raw::c_char,
        _: bool,
    ) -> u64 {
        0
    }

    extern "C" fn phy_capture_increment(_: *mut c_void, _: u64, _: u64) -> bool {
        false
    }

    extern "C" fn phy_capture_register_double(
        _: *mut c_void,
        _: *const std::os::raw::c_char,
        _: *const std::os::raw::c_char,
        _: bool,
    ) -> u64 {
        0
    }

    extern "C" fn phy_capture_set_double(_: *mut c_void, _: u64, _: f64) -> bool {
        false
    }

    extern "C" fn capture_init(id: u16, framework: *const FfiFrameworkService) -> *mut c_void {
        let Some(framework) = (unsafe { framework.as_ref() }) else {
            return std::ptr::null_mut();
        };
        Box::into_raw(Box::new(CaptureTransport {
            id,
            framework: *framework,
        }))
        .cast()
    }

    extern "C" fn capture_destroy(plugin: *mut c_void) {
        if !plugin.is_null() {
            unsafe { drop(Box::from_raw(plugin as *mut CaptureTransport)) };
        }
    }

    extern "C" fn capture_upstream(
        plugin: *mut c_void,
        packet: *const FfiPacket,
        messages: *const FfiControlMessage,
        count: usize,
    ) {
        if plugin.is_null() {
            return;
        }
        if packet.is_null() {
            let Some(messages) = ffi_control_messages(messages, count) else {
                return;
            };
            let valid = messages
                .iter()
                .filter(|message| {
                    let Some(payload) = control_payload(messages, message.msg_type) else {
                        return false;
                    };
                    match message.msg_type {
                        CONTROL_R2RI_SELF_METRIC => R2riSelfMetric::decode(payload).is_some(),
                        CONTROL_R2RI_QUEUE_METRIC => R2riQueueMetrics::decode(payload).is_some(),
                        CONTROL_R2RI_NEIGHBOR_METRIC => {
                            R2riNeighborMetrics::decode(payload).is_some()
                        }
                        _ => false,
                    }
                })
                .count();
            R2RI_CAPTURE_COUNT.store(valid, Ordering::Relaxed);
            return;
        }
        let packet = unsafe { &*packet };
        if packet.payload.len != 0 && !packet.payload.data.is_null() {
            let payload =
                unsafe { std::slice::from_raw_parts(packet.payload.data, packet.payload.len) };
            BYPASS_STACK_BYTES.store(
                payload.iter().map(|value| *value as usize).sum(),
                Ordering::Relaxed,
            );
            BYPASS_STACK_HITS.fetch_add(1, Ordering::Relaxed);
        }
    }

    extern "C" fn capture_downstream(
        plugin: *mut c_void,
        packet: *const FfiPacket,
        messages: *const FfiControlMessage,
        count: usize,
    ) {
        let Some(state) = (unsafe { (plugin as *const CaptureTransport).as_ref() }) else {
            return;
        };
        (state.framework.send_downstream_packet)(
            state.framework.framework_ctx,
            state.id,
            packet,
            messages,
            count,
        );
    }

    fn capture_api() -> &'static PluginApi {
        static API: OnceLock<PluginApi> = OnceLock::new();
        API.get_or_init(|| PluginApi {
            abi_version: PLUGIN_ABI_VERSION,
            struct_size: std::mem::size_of::<PluginApi>(),
            name: c"capture-transport".as_ptr(),
            plugin_type: 4,
            init: capture_init,
            configure: test_configure,
            start: test_start,
            post_start: test_lifecycle,
            stop: test_lifecycle,
            destroy: capture_destroy,
            process_upstream: capture_upstream,
            process_downstream: capture_downstream,
            process_timed_event: test_timed,
            process_event: test_event,
        })
    }

    fn flush_test_layer(manager: &NemManager, id: u16, index: usize) {
        let (tx, rx) = std::sync::mpsc::channel();
        assert!(manager.layers[&id][index]
            .queue
            .enqueue(
                QueueTaskKind::FileDescriptor,
                Box::new(move || {
                    tx.send(()).unwrap();
                })
            )
            .is_ok());
        rx.recv_timeout(Duration::from_secs(2)).unwrap();
    }

    fn add_capture_transport(manager: &mut NemManager, nem_id: u16) {
        let mut framework_context = Box::new(FrameworkContext {
            runtime: Arc::downgrade(&manager.runtime),
            nem_id,
            layer_index: 0,
            build_id: next_event_build_id(),
            neighbor_metrics: Mutex::new(NeighborMetricManager::new(nem_id)),
            queue_metrics: Mutex::new(QueueMetricManager::new(nem_id)),
            compatibility_tables: Mutex::new(HashMap::new()),
            descriptor_handles: Mutex::new(Vec::new()),
        });
        let framework = FfiFrameworkService {
            framework_ctx: framework_context.as_mut() as *mut FrameworkContext as *mut c_void,
            send_downstream_packet,
            send_upstream_packet,
            send_downstream_control,
            send_upstream_control,
            schedule_timed_event,
            cancel_timed_event,
            log,
            register_counter,
            register_counter32,
            increment_counter,
            maximize_counter,
            register_double,
            set_double,
            register_average,
            sample_average,
            register_table,
            set_table_row,
            clear_table,
            remove_table_row,
            table_generation,
            update_neighbor_tx,
            update_neighbor_rx,
            update_neighbor_status,
            register_queue_metric,
            update_queue_metric,
            publish_r2ri,
            register_rf_signal_table,
            configure_rf_signal_table,
            update_rf_signal_table,
            publish_event,
            register_file_descriptor,
            unregister_file_descriptor,
            query_spectrum_filter,
            query_spectrum,
        };
        let context = (capture_api().init)(nem_id, &framework);
        let queue = Box::new(NemQueuedLayer::new(nem_id));
        let invocation = Invocation {
            api: capture_api() as *const PluginApi as usize,
            plugin_ctx: context as usize,
            queue: queue.as_ref() as *const NemQueuedLayer as usize,
        };
        manager.layers.entry(nem_id).or_default().push(NemLayer {
            _library: None,
            invocation,
            queue,
            _framework_context: framework_context,
            event_build_id: next_event_build_id(),
            started: false,
            destroyed: false,
        });
        manager
            .runtime
            .invocations
            .write()
            .unwrap()
            .entry(nem_id)
            .or_default()
            .push(invocation);
    }

    fn test_api() -> &'static PluginApi {
        static API: OnceLock<PluginApi> = OnceLock::new();
        API.get_or_init(|| PluginApi {
            abi_version: PLUGIN_ABI_VERSION,
            struct_size: std::mem::size_of::<PluginApi>(),
            name: c"test".as_ptr(),
            plugin_type: 2,
            init: test_init,
            configure: test_configure,
            start: test_start,
            post_start: test_lifecycle,
            stop: test_lifecycle,
            destroy: test_lifecycle,
            process_upstream: test_upstream,
            process_downstream: test_packet,
            process_timed_event: test_timed,
            process_event: test_event,
        })
    }

    #[test]
    fn scaled_frequency_values_match_emane_configuration_syntax() {
        assert_eq!(parse_scaled_u64("1M"), Some(1_000_000));
        assert_eq!(parse_scaled_u64("2.347G"), Some(2_347_000_000));
        assert_eq!(parse_scaled_u64("500k"), Some(500_000));
        assert_eq!(parse_scaled_u64("-1M"), None);
        assert_eq!(parse_scaled_u64("garbage"), None);
    }

    #[test]
    fn builtin_transport_acknowledges_before_waking_blocked_reader() {
        struct Events {
            values: Mutex<Vec<(char, u16)>>,
            packets: std::sync::mpsc::Sender<u16>,
        }
        extern "C" fn control(
            ctx: *mut c_void,
            _: u16,
            messages: *const FfiControlMessage,
            count: usize,
        ) {
            let events = unsafe { &*(ctx as *const Events) };
            let incoming = ffi_control_messages(messages, count).unwrap();
            let token = control_payload(incoming, CONTROL_FLOW_CONTROL_TOKEN)
                .and_then(FlowControlToken::decode)
                .unwrap();
            events.values.lock().unwrap().push(('C', token.tokens));
        }
        extern "C" fn packet(
            ctx: *mut c_void,
            _: u16,
            packet: *const FfiPacket,
            _: *const FfiControlMessage,
            _: usize,
        ) {
            let events = unsafe { &*(ctx as *const Events) };
            let destination = unsafe { (*packet).info.destination };
            events.values.lock().unwrap().push(('P', destination));
            events.packets.send(destination).unwrap();
        }
        let mut manager = NemManager::new([21; 16]);
        manager
            .add_layer_configured(
                601,
                "virtualtransport",
                4,
                &[
                    ("flowcontrolenable".into(), vec!["true".into()]),
                    ("arpcacheenable".into(), vec!["false".into()]),
                ],
            )
            .unwrap();
        let context = manager.layers[&601][0].invocation.context();
        let (tx, rx) = std::sync::mpsc::channel();
        let mut events = Events {
            values: Mutex::new(Vec::new()),
            packets: tx,
        };
        let framework = unsafe { (*(context as *const BuiltinState)).framework };
        {
            let state = unsafe { &mut *(context as *mut BuiltinState) };
            state.framework.framework_ctx = (&mut events as *mut Events).cast();
            state.framework.send_downstream_control = control;
            state.framework.send_downstream_packet = packet;
            state.counters = CommonLayerCounters::default();
        }
        builtin_post_start(context);
        let reader_context = context as usize;
        let reader = std::thread::spawn(move || {
            for destination in [2, 3] {
                let mut frame = [0; 96];
                frame[..6].copy_from_slice(&[2, 2, 0, 0, 0, destination]);
                frame[12..14].copy_from_slice(&[0x88, 0xb5]);
                builtin_ethernet_downstream(
                    reader_context as *mut c_void,
                    frame.as_ptr(),
                    frame.len(),
                );
            }
        });
        let grant = |tokens| {
            let payload = FlowControlToken { tokens }.encode();
            let message = FfiControlMessage {
                msg_type: CONTROL_FLOW_CONTROL_TOKEN,
                payload: FfiSlice {
                    data: payload.as_ptr(),
                    len: payload.len(),
                },
            };
            builtin_upstream(context, std::ptr::null(), &message, 1);
        };
        assert!(rx.recv_timeout(Duration::from_millis(20)).is_err());
        grant(1);
        assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), 2);
        grant(0);
        assert!(rx.recv_timeout(Duration::from_millis(20)).is_err());
        grant(1);
        assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), 3);
        reader.join().unwrap();
        assert_eq!(
            *events.values.lock().unwrap(),
            vec![('C', 0), ('C', 1), ('P', 2), ('C', 0), ('C', 1), ('P', 3)]
        );
        unsafe {
            (*(context as *mut BuiltinState)).framework = framework;
        }
    }

    #[test]
    fn builtin_configuration_rejects_cross_layer_values_and_accepts_transport_pacing() {
        let mut manager = NemManager::new([11; 16]);
        assert!(manager
            .add_layer_configured(
                1,
                "emanephy",
                2,
                &[("frequncy".to_string(), vec!["2.4G".to_string()])],
            )
            .is_err());
        assert!(manager
            .add_layer_configured(
                2,
                "virtualtransport",
                4,
                &[("frequency".to_string(), vec!["2.4G".to_string()])],
            )
            .is_err());
        assert!(manager
            .add_layer_configured(
                3,
                "virtualtransport",
                4,
                &[
                    ("bitrate".to_string(), vec!["1M".to_string()]),
                    ("flowcontrolenable".to_string(), vec!["true".to_string()]),
                ],
            )
            .is_ok());
        manager
            .add_layer_configured(
                4,
                "virtualtransport",
                4,
                &[
                    ("bitrate".to_string(), vec!["0".to_string()]),
                    ("address".to_string(), vec!["172.30.1.1".to_string()]),
                    ("mask".to_string(), vec!["255.255.0.0".to_string()]),
                ],
            )
            .unwrap();
    }

    #[test]
    fn precomputed_propagation_prefers_frequency_specific_pathloss() {
        let mut phy = PhyState::new();
        phy.pathloss
            .insert(2, HashMap::from([(0, 50.0), (2_347_000_000, 72.5)]));
        assert_eq!(phy.propagation(1, 2, 2_347_000_000), Some((72.5, 0)));
        assert_eq!(phy.propagation(1, 2, 915_000_000), Some((50.0, 0)));
        assert_eq!(phy.propagation(1, 3, 915_000_000), None);
    }

    #[test]
    fn matches_legacy_propagation_scenario_001_two_ray_value() {
        let mut phy = PhyState::new();
        phy.propagation_model = PropagationModel::TwoRay;
        phy.update_location(1, 40.025495, -74.315441, 3.0, None, None);
        phy.update_location(2, 40.025495, -74.312888, 3.0, None, None);
        for frequency in [3_000_000_000, 3_001_000_000] {
            let (pathloss, _) = phy.propagation(1, 2, frequency).unwrap();
            assert!(
                (pathloss - 74.447_792_17).abs() < 1.0e-8,
                "legacy pathloss mismatch at {frequency}: {pathloss}"
            );
        }
    }

    #[test]
    fn partial_location_updates_preserve_legacy_orientation_and_velocity_state() {
        let mut phy = PhyState::new();
        phy.update_location(
            1,
            40.0,
            -74.0,
            3.0,
            Some(Orientation {
                yaw_degrees: 30.0,
                ..Orientation::default()
            }),
            Some(Velocity {
                azimuth_degrees: 60.0,
                elevation_degrees: -20.0,
                magnitude_meters_per_second: 10.0,
            }),
        );
        phy.update_location(
            1,
            40.1,
            -74.1,
            4.0,
            Some(Orientation {
                yaw_degrees: 240.0,
                ..Orientation::default()
            }),
            None,
        );
        let location = phy.locations[&1];
        assert_eq!(location.latitude_degrees, 40.1);
        assert_eq!(location.orientation.yaw_degrees, 240.0);
        let velocity = location.velocity.unwrap();
        assert_eq!(velocity.azimuth_degrees, 60.0);
        assert_eq!(velocity.elevation_degrees, -20.0);
        assert_eq!(velocity.magnitude_meters_per_second, 10.0);
    }

    #[test]
    fn matches_legacy_phy_upstream_scenario_006_doppler_values() {
        let mut phy = PhyState::new();
        let velocity = |azimuth, magnitude| {
            Some(Velocity {
                azimuth_degrees: azimuth,
                elevation_degrees: 0.0,
                magnitude_meters_per_second: magnitude,
            })
        };
        phy.update_location(1, 40.025495, -74.312501, 3.0, None, velocity(0.0, 0.0));
        for (azimuth, expected_shift_hz) in [
            (45.0, 70.760_818),
            (90.0, 100.069_269),
            (135.0, 70.758_483),
            (180.0, -0.001_651),
            (225.0, -70.760_778),
            (270.0, -100.069_188),
            (315.0, -70.758_442),
            (360.0, 0.001_651),
        ] {
            phy.update_location(
                2,
                40.025495,
                -74.315441,
                3.0,
                None,
                velocity(azimuth, 120.0),
            );
            let shift_hz = phy.doppler_fraction(1, 2) * 250_000_000.0;
            assert!(
                (shift_hz - expected_shift_hz).abs() < 5.0e-7,
                "legacy Doppler mismatch at azimuth {azimuth}: {shift_hz}"
            );
        }

        phy.update_location(1, 40.025495, -74.312501, 3.0, None, velocity(90.0, 90.0));
        phy.update_location(2, 40.025495, -74.315441, 3.0, None, velocity(90.0, 30.0));
        assert!((phy.doppler_fraction(1, 2) * 250_000_000.0 + 50.034_604).abs() < 5.0e-7);

        phy.update_location(1, 40.025495, -74.312501, 3.0, None, velocity(90.0, 0.0));
        phy.update_location(2, 40.025495, -74.315441, 3.0, None, velocity(270.0, 60.0));
        assert!((phy.doppler_fraction(1, 2) * 250_000_000.0 + 50.034_604).abs() < 5.0e-7);
    }

    #[test]
    fn doppler_preserves_cpp_fractional_motion_values() {
        // Full-process profile-generated-360 reported these shifts in C++.
        let mut phy = PhyState::new();
        phy.update_location(
            1,
            40.000419820556274,
            -74.00019347043154,
            92.49956838433974,
            None,
            Some(Velocity {
                azimuth_degrees: 325.70177038704094,
                elevation_degrees: -37.921917976672745,
                magnitude_meters_per_second: 82.2564827258599,
            }),
        );
        phy.update_location(
            2,
            39.99956562175388,
            -74.00138103547113,
            79.59987818697655,
            None,
            Some(Velocity {
                azimuth_degrees: 138.03991623141204,
                elevation_degrees: -1.6545137412508737,
                magnitude_meters_per_second: 99.6619698790654,
            }),
        );
        let factor = 1.0 + phy.doppler_fraction(1, 2);
        assert_eq!(
            2_400_000_000.0 * factor - 2_400_000_000.0,
            -445.5124797821045
        );
        assert_eq!(
            2_410_000_000.0 * factor - 2_410_000_000.0,
            -447.3687815666199
        );
    }

    #[test]
    fn antenna_gain_cache_tracks_bandwidth_updates_before_path_processing() {
        let mut phy = PhyState::new();
        let mut antenna = MimoTxAntenna {
            antenna_index: 0,
            frequency_group_index: 0,
            spectral_mask_index: 0,
            bandwidth_hz: 1_000_000,
            pattern: AntennaPattern::IdealOmni { gain_db: 0.0 },
        };
        let gain = |phy: &mut PhyState| {
            phy.antenna_pair_gains(
                1,
                2,
                AntennaPattern::IdealOmni { gain_db: 0.0 },
                AntennaPattern::IdealOmni { gain_db: 0.0 },
            )
            .unwrap()
        };
        phy.update_gain_antenna(2, antenna);
        assert!(!gain(&mut phy).2);
        antenna.frequency_group_index = 2;
        antenna.spectral_mask_index = 3;
        phy.update_gain_antenna(2, antenna);
        assert!(gain(&mut phy).2);
        antenna.bandwidth_hz = 2_000_000;
        phy.update_gain_antenna(2, antenna);
        antenna.bandwidth_hz = 1_000_000;
        phy.update_gain_antenna(2, antenna);
        assert!(!gain(&mut phy).2);
        antenna.pattern = AntennaPattern::IdealOmni { gain_db: 0.000001 };
        phy.update_gain_antenna(2, antenna);
        assert_eq!(gain(&mut phy), (0.0, 0.0, true));
        phy.update_gain_antenna(1, antenna);
        assert!(!gain(&mut phy).2);
    }

    #[test]
    fn velocity_changes_invalidate_gain_pairs_even_for_omni_antennas() {
        let mut phy = PhyState::new();
        let gain = |phy: &mut PhyState| {
            phy.antenna_pair_gains(
                1,
                2,
                AntennaPattern::IdealOmni { gain_db: 3.0 },
                AntennaPattern::IdealOmni { gain_db: 0.0 },
            )
            .unwrap()
        };
        assert_eq!(gain(&mut phy), (3.0, 0.0, false));
        phy.update_location(1, 40.0, -74.0, 10.0, None, None);
        assert_eq!(gain(&mut phy), (3.0, 0.0, true));
        phy.update_location(2, 40.0, -74.001, 10.0, None, None);
        assert_eq!(gain(&mut phy), (3.0, 0.0, false));
        assert_eq!(gain(&mut phy), (3.0, 0.0, true));
        for speed in [0.0, 20.0, 0.0] {
            phy.update_location(
                2,
                40.0,
                -74.001,
                10.0,
                None,
                Some(Velocity {
                    azimuth_degrees: 90.0,
                    elevation_degrees: 0.0,
                    magnitude_meters_per_second: speed,
                }),
            );
            assert_eq!(gain(&mut phy), (3.0, 0.0, false));
            assert_eq!(gain(&mut phy), (3.0, 0.0, true));
        }
        phy.update_location(2, 40.0, -74.002, 10.0, None, None);
        phy.update_location(2, 40.0, -74.001, 10.0, None, None);
        assert_eq!(gain(&mut phy), (3.0, 0.0, false));
    }

    #[test]
    fn antenna_gain_cache_does_not_reuse_historical_pair_configurations() {
        let mut phy = PhyState::new();
        for (remote_gain, hit) in [(0.0, false), (0.0, true), (3.0, false), (0.0, false)] {
            assert_eq!(
                phy.antenna_pair_gains(
                    1,
                    2,
                    AntennaPattern::IdealOmni { gain_db: 0.0 },
                    AntennaPattern::IdealOmni {
                        gain_db: remote_gain
                    }
                ),
                Some((0.0, remote_gain, hit)),
            );
            assert_eq!(phy.gain_cache.len(), 1);
        }
    }

    #[test]
    fn explicit_mimo_omni_antennas_combine_both_endpoint_gains() {
        let mut phy = PhyState::new();
        assert_eq!(
            phy.antenna_pair_gain(
                1,
                2,
                AntennaPattern::IdealOmni { gain_db: 3.0 },
                AntennaPattern::IdealOmni { gain_db: -1.5 },
            ),
            Some(1.5)
        );
        assert_eq!(
            phy.antenna_pair_gains(
                1,
                2,
                AntennaPattern::IdealOmni { gain_db: 3.0 },
                AntennaPattern::IdealOmni { gain_db: -1.5 },
            ),
            Some((3.0, -1.5, true))
        );
    }

    #[test]
    fn phy_preserves_fixed_transmit_gain_as_antenna_metadata() {
        PHY_CAPTURE_TX_POWER_BITS.store(f64::NAN.to_bits(), Ordering::Relaxed);
        PHY_CAPTURE_TX_GAIN_BITS.store(f64::NAN.to_bits(), Ordering::Relaxed);
        let framework = FfiFrameworkService {
            framework_ctx: std::ptr::null_mut(),
            send_downstream_packet: phy_capture_packet,
            send_upstream_packet: phy_capture_packet,
            send_downstream_control: phy_capture_control,
            send_upstream_control: phy_capture_control,
            schedule_timed_event: phy_capture_schedule,
            cancel_timed_event: phy_capture_cancel,
            log: phy_capture_log,
            register_counter: phy_capture_register,
            register_counter32: phy_capture_register,
            increment_counter: phy_capture_increment,
            maximize_counter: phy_capture_increment,
            register_double: phy_capture_register_double,
            set_double: phy_capture_set_double,
            register_average: phy_capture_register_double,
            sample_average: phy_capture_set_double,
            register_table,
            set_table_row,
            clear_table,
            remove_table_row,
            table_generation,
            update_neighbor_tx,
            update_neighbor_rx,
            update_neighbor_status,
            register_queue_metric,
            update_queue_metric,
            publish_r2ri,
            register_rf_signal_table,
            configure_rf_signal_table,
            update_rf_signal_table,
            publish_event,
            register_file_descriptor,
            unregister_file_descriptor,
            query_spectrum_filter,
            query_spectrum,
        };
        let context = builtin_init(1, &framework, BuiltinKind::Phy);
        assert!(!context.is_null());
        let state = unsafe { &mut *(context as *mut BuiltinState) };
        state.phy.tx_power_dbm = 2.0;
        state.phy.fixed_antenna_gain_db = 6.0;
        state.phy.fixed_antenna_gain_enabled = true;
        assert!(builtin_start(context));

        let payload = [1u8];
        let packet = FfiPacket {
            info: FfiPacketInfo {
                uuid: [0; 16],
                source: 1,
                destination: 2,
                priority: 0,
                creation_time_sec: 0,
                creation_time_usec: 0,
            },
            payload: FfiSlice {
                data: payload.as_ptr(),
                len: payload.len(),
            },
        };
        builtin_downstream(context, &packet, std::ptr::null(), 0);
        assert_eq!(
            f64::from_bits(PHY_CAPTURE_TX_POWER_BITS.load(Ordering::Relaxed)),
            2.0
        );
        assert_eq!(
            f64::from_bits(PHY_CAPTURE_TX_GAIN_BITS.load(Ordering::Relaxed)),
            6.0
        );
        builtin_destroy(context);
    }

    #[test]
    fn profile_elevation_wraps_like_cpp_lookup_and_adjusted_orientation() {
        for (input, expected) in [
            (-360.0, 0.0),
            (-270.0, 90.0),
            (-120.0, 60.0),
            (-90.0, -90.0),
            (90.0, 90.0),
            (100.0, -80.0),
            (180.0, 0.0),
            (260.0, 80.0),
            (270.0, -90.0),
            (360.0, 0.0),
        ] {
            assert_eq!(normalize_elevation(input), expected);
        }
    }

    #[test]
    fn explicit_profile_receive_antenna_uses_pointing_relative_direction() {
        let mut phy = PhyState::new();
        let local = Location {
            latitude_degrees: 0.0,
            longitude_degrees: 0.0,
            altitude_meters: 10.0,
            velocity: None,
            orientation: Orientation::default(),
        };
        phy.locations.insert(1, local);
        phy.locations.insert(
            2,
            Location {
                longitude_degrees: 0.001,
                ..local
            },
        );
        let gain = phy.antenna_pair_gain_with(
            1,
            2,
            AntennaPattern::Profile(TxAntennaProfile {
                profile_id: 42,
                azimuth_degrees: 20.0,
                elevation_degrees: -5.0,
            }),
            AntennaPattern::IdealOmni { gain_db: 2.0 },
            |profile, bearing, elevation, reference_bearing, reference_elevation| {
                assert_eq!(profile.profile_id, 42);
                assert!((bearing - 70.0).abs() < 1.0e-9);
                assert!((elevation - 5.0).abs() < 1.0e-3);
                assert!((reference_bearing - 90.0).abs() < 1.0e-9);
                assert!(reference_elevation.abs() < 1.0e-3);
                Some(7.5)
            },
        );
        assert_eq!(gain, Some(9.5));
    }

    #[test]
    fn matches_legacy_gain_scenario_001_directional_geometry() {
        fn sector_gain(bearing: f64, elevation: f64, holes: bool) -> f64 {
            let bearing = normalize_azimuth(bearing).round() as i16;
            let bearing = if bearing == 360 { 0 } else { bearing };
            let elevation = elevation.round() as i16;
            let elevation_gain = match elevation {
                -15..=-11 | 11..=15 => 0.0,
                -10..=-6 | 6..=10 => 3.0,
                -5..=5 => 6.0,
                _ => return if holes { -327.0 } else { -200.0 },
            };
            let bearing_loss = match bearing {
                0..=5 | 355..=359 => 0.0,
                6..=10 | 350..=354 => -3.0,
                11..=15 | 345..=349 => -6.0,
                _ => return if holes { -327.0 } else { -200.0 },
            };
            elevation_gain + bearing_loss
        }

        fn blockage_gain(bearing: f64, elevation: f64) -> f64 {
            let bearing = normalize_azimuth(bearing).round() as i16;
            let bearing = if bearing == 360 { 0 } else { bearing };
            let elevation = elevation.round() as i16;
            if (90..=270).contains(&bearing) || elevation < -10 {
                -200.0
            } else if elevation < 0 {
                f64::from(elevation)
            } else {
                0.0
            }
        }

        fn profile_gain(
            profile: TxAntennaProfile,
            bearing: f64,
            elevation: f64,
            reference_bearing: f64,
            reference_elevation: f64,
        ) -> Option<f64> {
            Some(match profile.profile_id {
                1 | 2 => 5.0,
                3 => {
                    sector_gain(bearing, elevation, false)
                        + blockage_gain(reference_bearing, reference_elevation)
                }
                4 => sector_gain(bearing, elevation, false),
                5 => {
                    sector_gain(bearing, elevation, true)
                        + blockage_gain(reference_bearing, reference_elevation)
                }
                _ => return None,
            })
        }

        let location = |latitude, longitude, orientation, velocity| Location {
            latitude_degrees: latitude,
            longitude_degrees: longitude,
            altitude_meters: 3.0,
            orientation,
            velocity,
        };
        let orientation = |pitch, yaw| Orientation {
            pitch_degrees: pitch,
            yaw_degrees: yaw,
            ..Orientation::default()
        };
        let velocity = |azimuth, elevation, magnitude| {
            Some(Velocity {
                azimuth_degrees: azimuth,
                elevation_degrees: elevation,
                magnitude_meters_per_second: magnitude,
            })
        };
        let profile = |profile_id, azimuth, elevation| {
            AntennaPattern::Profile(TxAntennaProfile {
                profile_id,
                azimuth_degrees: azimuth,
                elevation_degrees: elevation,
            })
        };
        let fixed = |gain_db| AntennaPattern::IdealOmni { gain_db };
        let assert_gain = |phy: &PhyState, source, local_pattern, remote_pattern, expected: f64| {
            let actual =
                phy.antenna_pair_gain_with(1, source, local_pattern, remote_pattern, profile_gain);
            assert_eq!(
                actual,
                Some(expected),
                "legacy gain mismatch for source {source}, expected {expected}"
            );
        };

        let mut phy = PhyState::new();
        // Actions 14-17: baseline pointing and placement.
        phy.locations.insert(
            1,
            location(40.025495, -74.315441, Orientation::default(), None),
        );
        phy.locations.insert(
            2,
            location(40.025495, -74.312888, Orientation::default(), None),
        );
        phy.locations.insert(
            3,
            location(40.023235, -74.315437, Orientation::default(), None),
        );
        phy.locations.insert(
            4,
            location(40.023235, -74.312889, Orientation::default(), None),
        );
        assert_gain(&phy, 2, profile(3, 0.0, 0.0), fixed(0.0), -400.0);
        assert_gain(&phy, 3, profile(3, 0.0, 0.0), fixed(5.0), -395.0);
        assert_gain(&phy, 4, profile(3, 0.0, 0.0), profile(4, 0.0, 60.0), -600.0);

        // Actions 18-36: body orientation and antenna-pointing changes.
        phy.locations.get_mut(&1).unwrap().orientation = orientation(0.0, 90.0);
        assert_gain(&phy, 2, profile(3, 0.0, 0.0), fixed(0.0), 6.0);
        assert_gain(&phy, 3, profile(3, 0.0, 0.0), fixed(5.0), -395.0);
        assert_gain(&phy, 4, profile(3, 0.0, 0.0), profile(4, 0.0, 60.0), -400.0);
        assert_gain(&phy, 2, profile(3, 45.0, 0.0), fixed(0.0), -200.0);
        assert_gain(&phy, 3, profile(3, 45.0, 0.0), fixed(5.0), -395.0);
        assert_gain(&phy, 4, profile(3, 45.0, 0.0), profile(4, 330.0, 0.0), 6.0);
        phy.locations.get_mut(&1).unwrap().orientation = orientation(12.0, 90.0);
        assert_gain(&phy, 4, profile(3, 45.0, 0.0), profile(4, 330.0, 0.0), -5.0);
        assert_gain(
            &phy,
            4,
            profile(3, 45.0, -8.0),
            profile(4, 330.0, 0.0),
            -2.0,
        );
        phy.locations.get_mut(&1).unwrap().orientation = orientation(0.0, 300.0);
        assert_gain(
            &phy,
            4,
            profile(3, 0.0, 0.0),
            profile(4, 330.0, 0.0),
            -400.0,
        );
        assert_gain(&phy, 2, profile(3, 200.0, 0.0), fixed(0.0), -400.0);
        assert_gain(&phy, 3, profile(3, 200.0, 0.0), fixed(5.0), -395.0);
        assert_gain(
            &phy,
            4,
            profile(3, 200.0, 0.0),
            profile(4, 330.0, 0.0),
            -194.0,
        );

        // Actions 38-56: velocity-relative body pointing repeats the same oracle.
        *phy.locations.get_mut(&1).unwrap() = location(
            40.025495,
            -74.315441,
            orientation(0.0, 30.0),
            velocity(60.0, 0.0, 10.0),
        );
        assert_gain(&phy, 2, profile(3, 0.0, 0.0), fixed(0.0), 6.0);
        assert_gain(&phy, 3, profile(3, 0.0, 0.0), fixed(5.0), -395.0);
        assert_gain(&phy, 4, profile(3, 0.0, 0.0), profile(4, 0.0, 60.0), -400.0);
        assert_gain(&phy, 2, profile(3, 45.0, 0.0), fixed(0.0), -200.0);
        assert_gain(&phy, 3, profile(3, 45.0, 0.0), fixed(5.0), -395.0);
        assert_gain(&phy, 4, profile(3, 45.0, 0.0), profile(4, 330.0, 0.0), 6.0);
        *phy.locations.get_mut(&1).unwrap() = location(
            40.025495,
            -74.315441,
            orientation(32.0, 30.0),
            velocity(60.0, -20.0, 10.0),
        );
        assert_gain(&phy, 4, profile(3, 45.0, 0.0), profile(4, 330.0, 0.0), -5.0);
        assert_gain(
            &phy,
            4,
            profile(3, 45.0, -8.0),
            profile(4, 330.0, 0.0),
            -2.0,
        );
        *phy.locations.get_mut(&1).unwrap() = location(
            40.025495,
            -74.315441,
            orientation(0.0, 240.0),
            velocity(60.0, -20.0, 10.0),
        );
        assert_gain(
            &phy,
            4,
            profile(3, 0.0, 0.0),
            profile(4, 330.0, 0.0),
            -400.0,
        );
        assert_gain(&phy, 2, profile(3, 200.0, 0.0), fixed(0.0), -400.0);
        assert_gain(&phy, 3, profile(3, 200.0, 0.0), fixed(5.0), -395.0);
        assert_gain(
            &phy,
            4,
            profile(3, 200.0, 0.0),
            profile(4, 330.0, 0.0),
            -400.0,
        );

        // Actions 57-76: pattern holes use the legacy -327 dB DBM_MIN sentinel.
        *phy.locations.get_mut(&1).unwrap() = location(
            40.025495,
            -74.315441,
            orientation(0.0, 30.0),
            velocity(60.0, 0.0, 10.0),
        );
        assert_gain(&phy, 2, profile(5, 0.0, 0.0), fixed(0.0), 6.0);
        assert_gain(&phy, 3, profile(5, 0.0, 0.0), fixed(5.0), -522.0);
        assert_gain(&phy, 4, profile(5, 0.0, 0.0), profile(4, 0.0, 60.0), -527.0);
        assert_gain(&phy, 2, profile(5, 45.0, 0.0), fixed(0.0), -327.0);
        assert_gain(&phy, 3, profile(5, 45.0, 0.0), fixed(5.0), -522.0);
        assert_gain(&phy, 4, profile(5, 45.0, 0.0), profile(4, 330.0, 0.0), 6.0);
        *phy.locations.get_mut(&1).unwrap() = location(
            40.025495,
            -74.315441,
            orientation(32.0, 30.0),
            velocity(60.0, -20.0, 10.0),
        );
        assert_gain(&phy, 4, profile(5, 45.0, 0.0), profile(4, 330.0, 0.0), -5.0);
        assert_gain(
            &phy,
            4,
            profile(5, 45.0, -8.0),
            profile(4, 330.0, 0.0),
            -2.0,
        );
        phy.locations.get_mut(&1).unwrap().orientation = orientation(0.0, 240.0);
        assert_gain(
            &phy,
            4,
            profile(5, 0.0, 0.0),
            profile(4, 330.0, 0.0),
            -527.0,
        );
        assert_gain(&phy, 2, profile(5, 200.0, 0.0), fixed(0.0), -527.0);
        assert_gain(&phy, 3, profile(5, 200.0, 0.0), fixed(5.0), -522.0);
        assert_gain(
            &phy,
            4,
            profile(5, 200.0, 0.0),
            profile(4, 330.0, 0.0),
            -527.0,
        );
    }

    #[test]
    fn active_phy_reports_multiple_segments_and_combines_collaborative_transmitters() {
        PHY_CAPTURE_SEGMENTS.store(0, Ordering::Relaxed);
        PHY_CAPTURE_POWER_BITS.store(0, Ordering::Relaxed);
        PHY_CAPTURE_MIMO_INFOS.store(0, Ordering::Relaxed);
        PHY_CAPTURE_RX_ANTENNA.store(0, Ordering::Relaxed);
        let framework = FfiFrameworkService {
            framework_ctx: std::ptr::null_mut(),
            send_downstream_packet: phy_capture_packet,
            send_upstream_packet: phy_capture_packet,
            send_downstream_control: phy_capture_control,
            send_upstream_control: phy_capture_control,
            schedule_timed_event: phy_capture_schedule,
            cancel_timed_event: phy_capture_cancel,
            log: phy_capture_log,
            register_counter: phy_capture_register,
            register_counter32: phy_capture_register,
            increment_counter: phy_capture_increment,
            maximize_counter: phy_capture_increment,
            register_double: phy_capture_register_double,
            set_double: phy_capture_set_double,
            register_average: phy_capture_register_double,
            sample_average: phy_capture_set_double,
            register_table,
            set_table_row,
            clear_table,
            remove_table_row,
            table_generation,
            update_neighbor_tx,
            update_neighbor_rx,
            update_neighbor_status,
            register_queue_metric,
            update_queue_metric,
            publish_r2ri,
            register_rf_signal_table,
            configure_rf_signal_table,
            update_rf_signal_table,
            publish_event,
            register_file_descriptor,
            unregister_file_descriptor,
            query_spectrum_filter,
            query_spectrum,
        };
        let context = builtin_init(1, &framework, BuiltinKind::Phy);
        assert!(!context.is_null());
        let state = unsafe { &mut *(context as *mut BuiltinState) };
        state.phy.compatibility_mode = 2;
        state.phy.frequencies_of_interest = vec![2_400_000_000, 2_410_000_000];
        state.phy.pathloss.insert(2, HashMap::from([(0, 50.0)]));
        state.phy.pathloss.insert(3, HashMap::from([(0, 50.0)]));
        state.phy.initialize_monitor();
        assert!(builtin_start(context));

        let receive_antenna = RxAntennaAdd {
            antenna: MimoTxAntenna {
                frequency_group_index: 0,
                antenna_index: 7,
                bandwidth_hz: 1_000_000,
                spectral_mask_index: 0,
                pattern: AntennaPattern::IdealOmni { gain_db: 3.0 },
            },
            frequencies_hz: vec![2_400_000_000, 2_410_000_000],
        }
        .encode()
        .unwrap();
        let receive_control = FfiControlMessage {
            msg_type: CONTROL_RX_ANTENNA_ADD,
            payload: FfiSlice {
                data: receive_antenna.as_ptr(),
                len: receive_antenna.len(),
            },
        };
        builtin_downstream(context, std::ptr::null(), &receive_control, 1);

        let now = unix_time_microseconds();
        let tx = TxProperties {
            frequency_hz: 2_400_000_000,
            bandwidth_hz: 1_000_000,
            tx_power_dbm: 0.0,
            duration_microseconds: 100,
            offset_microseconds: 0,
            tx_time_microseconds: now,
            antenna_index: 0,
            spectral_mask_index: 0,
            sub_id: 1,
        }
        .encode();
        let mimo = MimoTxProperties {
            frequency_groups: vec![
                vec![MimoTxFrequencySegment {
                    frequency_hz: 2_400_000_000,
                    tx_power_dbm: Some(0.0),
                    duration_microseconds: 100,
                    offset_microseconds: 0,
                }],
                vec![MimoTxFrequencySegment {
                    frequency_hz: 2_410_000_000,
                    tx_power_dbm: Some(0.0),
                    duration_microseconds: 50,
                    offset_microseconds: 100,
                }],
            ],
            transmit_antennas: vec![
                MimoTxAntenna {
                    frequency_group_index: 0,
                    antenna_index: 1,
                    bandwidth_hz: 1_000_000,
                    spectral_mask_index: 0,
                    pattern: AntennaPattern::Default,
                },
                MimoTxAntenna {
                    frequency_group_index: 1,
                    antenna_index: 2,
                    bandwidth_hz: 1_000_000,
                    spectral_mask_index: 0,
                    pattern: AntennaPattern::Default,
                },
            ],
        }
        .encode()
        .unwrap();
        let transmitters = TxTransmitters {
            transmitters: vec![
                TxTransmitter {
                    nem_id: 2,
                    tx_power_dbm: 0.0,
                },
                TxTransmitter {
                    nem_id: 3,
                    tx_power_dbm: 0.0,
                },
            ],
        }
        .encode()
        .unwrap();
        let messages = [
            FfiControlMessage {
                msg_type: CONTROL_TX_PROPERTIES,
                payload: FfiSlice {
                    data: tx.as_ptr(),
                    len: tx.len(),
                },
            },
            FfiControlMessage {
                msg_type: CONTROL_MIMO_TX_PROPERTIES,
                payload: FfiSlice {
                    data: mimo.as_ptr(),
                    len: mimo.len(),
                },
            },
            FfiControlMessage {
                msg_type: CONTROL_TX_TRANSMITTERS,
                payload: FfiSlice {
                    data: transmitters.as_ptr(),
                    len: transmitters.len(),
                },
            },
        ];
        let payload = [1u8, 2, 3];
        let packet = FfiPacket {
            info: FfiPacketInfo {
                uuid: [0; 16],
                source: 2,
                destination: 1,
                priority: 0,
                creation_time_sec: 0,
                creation_time_usec: 0,
            },
            payload: FfiSlice {
                data: payload.as_ptr(),
                len: payload.len(),
            },
        };
        builtin_upstream(context, &packet, messages.as_ptr(), messages.len());
        assert_eq!(PHY_CAPTURE_SEGMENTS.load(Ordering::Relaxed), 2);
        assert_eq!(PHY_CAPTURE_MIMO_INFOS.load(Ordering::Relaxed), 2);
        assert_eq!(PHY_CAPTURE_RX_ANTENNA.load(Ordering::Relaxed), 7);
        let combined_power = f64::from_bits(PHY_CAPTURE_POWER_BITS.load(Ordering::Relaxed));
        assert!((combined_power - (-43.989_700_043)).abs() < 0.001);
        builtin_destroy(context);
    }

    #[test]
    fn location_models_compute_distance_and_nonnegative_pathloss() {
        let mut phy = PhyState::new();
        phy.locations.insert(
            1,
            Location {
                latitude_degrees: 40.0,
                longitude_degrees: -74.0,
                altitude_meters: 10.0,
                velocity: None,
                orientation: Orientation::default(),
            },
        );
        phy.locations.insert(
            2,
            Location {
                latitude_degrees: 40.001,
                longitude_degrees: -74.0,
                altitude_meters: 20.0,
                velocity: None,
                orientation: Orientation::default(),
            },
        );
        phy.propagation_model = PropagationModel::FreeSpace;
        let (pathloss, delay) = phy.propagation(1, 2, 2_347_000_000).unwrap();
        assert!(pathloss > 0.0);
        assert!(delay >= 0);
        phy.propagation_model = PropagationModel::TwoRay;
        assert!(phy.propagation(1, 2, 2_347_000_000).unwrap().0 >= 0.0);
    }

    #[test]
    fn doppler_uses_relative_velocity_and_can_be_disabled() {
        let mut phy = PhyState::new();
        phy.locations.insert(
            1,
            Location {
                latitude_degrees: 40.0,
                longitude_degrees: -74.0,
                altitude_meters: 10.0,
                velocity: Some(Velocity {
                    azimuth_degrees: 0.0,
                    elevation_degrees: 0.0,
                    magnitude_meters_per_second: 30.0,
                }),
                orientation: Orientation::default(),
            },
        );
        phy.locations.insert(
            2,
            Location {
                latitude_degrees: 40.01,
                longitude_degrees: -74.0,
                altitude_meters: 10.0,
                velocity: Some(Velocity {
                    azimuth_degrees: 0.0,
                    elevation_degrees: 0.0,
                    magnitude_meters_per_second: 0.0,
                }),
                orientation: Orientation::default(),
            },
        );
        assert!(phy.doppler_fraction(1, 2) > 0.0);
        phy.doppler_shift_enabled = false;
        assert_eq!(phy.doppler_fraction(1, 2), 0.0);
    }

    #[test]
    fn antenna_body_frame_applies_roll_pitch_and_yaw() {
        let local = Location {
            latitude_degrees: 0.0,
            longitude_degrees: 0.0,
            altitude_meters: 0.0,
            velocity: None,
            orientation: Orientation::default(),
        };
        let east = Location {
            longitude_degrees: 0.001,
            ..local
        };
        let (azimuth, elevation) = oriented_direction_angles(local, east).unwrap();
        assert!((azimuth - 90.0).abs() < 1.0e-9);
        assert!(elevation.abs() < 1.0e-3);

        let rolled = Location {
            orientation: Orientation {
                roll_degrees: 90.0,
                ..Orientation::default()
            },
            ..local
        };
        let (_, elevation) = oriented_direction_angles(rolled, east).unwrap();
        assert!((elevation - 90.0).abs() < 1.0e-3);
    }

    #[test]
    fn event_fading_requires_a_source_selection() {
        let mut phy = PhyState::new();
        phy.fading_mode = FadingMode::Event;
        assert_eq!(phy.apply_fading(1, 2, -50.0, 1), None);
        assert_eq!(
            phy.apply_fading_detailed(1, 2, -50.0, 1),
            Err(PhyPathError::FadeSelection)
        );
        phy.fading_selections.insert(2, FadingMode::None);
        assert_eq!(phy.apply_fading(1, 2, -50.0, 1), Some(-50.0));
    }

    #[test]
    fn phy_path_failures_preserve_legacy_drop_categories() {
        let mut phy = PhyState::new();
        assert_eq!(
            phy.propagation_detailed(1, 2, 2_400_000_000),
            Err(PhyPathError::Propagation)
        );
        phy.fixed_antenna_gain_enabled = false;
        assert_eq!(
            phy.antenna_pair_gains_detailed(
                1,
                2,
                AntennaPattern::Default,
                AntennaPattern::Default,
            ),
            Err(PhyPathError::GainProfile)
        );
        phy.fading_mode = FadingMode::Nakagami;
        assert_eq!(
            phy.apply_fading_detailed(1, 2, -50.0, 1),
            Err(PhyPathError::FadeLocation)
        );
        assert_eq!(PhyPathError::GainLocation.drop_code(), 4);
        assert_eq!(PhyPathError::GainHorizon.drop_code(), 5);
        assert_eq!(PhyPathError::FadeAlgorithm.drop_code(), 10);
    }

    #[test]
    fn phy_configuration_accepts_ported_features_and_mimo_mode() {
        let mut manager = NemManager::new([12; 16]);
        manager
            .add_layer_configured(
                1,
                "emanephy",
                2,
                &[
                    ("subid".to_string(), vec!["1".to_string()]),
                    ("compatibilitymode".to_string(), vec!["1".to_string()]),
                    ("processingpoolsize".to_string(), vec!["2".to_string()]),
                    (
                        "stats.receivepowertableenable".to_string(),
                        vec!["true".to_string()],
                    ),
                    (
                        "stats.observedpowertableenable".to_string(),
                        vec!["true".to_string()],
                    ),
                    (
                        "rxsensitivitypromiscuousmodeenable".to_string(),
                        vec!["false".to_string()],
                    ),
                    ("dopplershiftenable".to_string(), vec!["true".to_string()]),
                    ("fading.model".to_string(), vec!["nakagami".to_string()]),
                    (
                        "fading.nakagami.distance0".to_string(),
                        vec!["100".to_string()],
                    ),
                    (
                        "fading.nakagami.distance1".to_string(),
                        vec!["250".to_string()],
                    ),
                ],
            )
            .unwrap();
        manager
            .add_layer_configured(
                2,
                "emanephy",
                2,
                &[
                    ("subid".to_string(), vec!["1".to_string()]),
                    ("compatibilitymode".to_string(), vec!["2".to_string()]),
                ],
            )
            .unwrap();
        assert!(manager
            .add_layer_configured(
                3,
                "emanephy",
                2,
                &[
                    ("subid".to_string(), vec!["1".to_string()]),
                    ("compatibilitymode".to_string(), vec!["3".to_string()]),
                ],
            )
            .is_err());
    }

    #[test]
    fn native_neighbor_event_publication_reaches_other_nems() {
        extern "C" fn receive(context: *mut c_void, event: u16, _: *const u8, _: usize) {
            assert_eq!(event, 104);
            unsafe { &*(context as *const std::sync::atomic::AtomicUsize) }
                .fetch_add(1, Ordering::Relaxed);
        }
        let mut manager = NemManager::new([31; 16]);
        manager
            .add_layer_configured(
                120,
                "emanephy",
                2,
                &[("subid".to_string(), vec!["1".to_string()])],
            )
            .unwrap();
        let context = manager.layers[&120][0]._framework_context.as_ref() as *const FrameworkContext
            as *mut c_void;
        let received = std::sync::atomic::AtomicUsize::new(0);
        crate::event_service::register_native_user(
            65001,
            121,
            &received as *const _ as *mut c_void,
            receive,
        );
        assert!(emane_rs_event_service_register_event(65001, 104));
        let payload = [0x08, 120];
        assert!(publish_event(context, 104, payload.as_ptr(), payload.len()));
        crate::event_service::unregister_user(65001);
        assert_eq!(received.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn queue_metric_registration_preserves_idle_rows_without_delay_samples() {
        let mut manager = NemManager::new([35; 16]);
        manager
            .add_layer_configured(611, "emanephy", 2, &[("subid".into(), vec!["1".into()])])
            .unwrap();
        let framework = manager.layers[&611][0]._framework_context.as_ref();
        let ctx = framework as *const FrameworkContext as *mut c_void;
        assert!(register_queue_metric(ctx, 0, 3));
        assert!(!register_queue_metric(ctx, 0, 99));
        let idle = framework.queue_metrics.lock().unwrap().get_queue_metrics();
        assert_eq!(idle.len(), 1);
        assert_eq!(idle[0].queue_max_size, 3);
        assert_eq!(idle[0].avg_delay_microseconds, 0);
        update_queue_metric(ctx, 0, 3, 1, 0, 30);
        let sampled = framework.queue_metrics.lock().unwrap().get_queue_metrics();
        assert_eq!(sampled[0].avg_delay_microseconds, 30);
        let idle = framework.queue_metrics.lock().unwrap().get_queue_metrics();
        assert_eq!(idle.len(), 1);
        assert_eq!(idle[0].queue_current_depth_high_water, 0);
        assert_eq!(idle[0].avg_delay_microseconds, 0);
    }

    #[test]
    fn native_r2ri_service_publishes_self_queue_and_neighbor_controls() {
        R2RI_CAPTURE_COUNT.store(0, Ordering::Relaxed);
        let mut manager = NemManager::new([13; 16]);
        add_capture_transport(&mut manager, 20);
        manager
            .add_layer_configured(
                20,
                "emanephy",
                2,
                &[("subid".to_string(), vec!["1".to_string()])],
            )
            .unwrap();
        manager.start().unwrap();
        let context = manager.layers[&20][1]._framework_context.as_ref() as *const FrameworkContext
            as *mut c_void;
        let now = unix_time_microseconds().max(0) as u64;
        update_queue_metric(context, 1, 255, 4, 2, 30);
        update_neighbor_tx(context, 21, 1_000_000, now);
        update_neighbor_rx(
            context,
            21,
            7,
            [1u8; 16].as_ptr(),
            15.0,
            -100.0,
            now,
            200,
            2_000_000,
        );
        publish_r2ri(context, 1_000_000, 2_000_000, 500_000, 60_000_000);
        flush_test_layer(&manager, 20, 0);
        assert_eq!(R2RI_CAPTURE_COUNT.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn native_layer_statistics_are_manifested_and_track_packets() {
        use crate::statistics::{
            emane_rs_statistic_free_manifest, emane_rs_statistic_free_query_result,
            emane_rs_statistic_free_table_query_result, emane_rs_statistic_get_manifest,
            emane_rs_statistic_query, emane_rs_statistic_query_table, FfiStringArray,
        };

        let mut manager = NemManager::new([14; 16]);
        manager
            .add_layer_configured(
                30,
                "emanephy",
                2,
                &[("subid".to_string(), vec!["1".to_string()])],
            )
            .unwrap();
        manager.start().unwrap();
        let build_id = manager.layers[&30][0].event_build_id;
        let manifest = emane_rs_statistic_get_manifest(build_id);
        // Legacy CommonLayerStatistics publishes 26 scalar values (including
        // processing averages and generated-packet counters); FrameworkPHY
        // adds four counters, and NEMQueuedLayer adds eight counters plus four
        // queue/timer averages.
        assert_eq!(manifest.len, 42);
        emane_rs_statistic_free_manifest(manifest);

        let payload = [1u8, 2, 3, 4];
        let packet = FfiPacket {
            info: FfiPacketInfo {
                uuid: [0; 16],
                source: 30,
                destination: 31,
                priority: 0,
                creation_time_sec: 0,
                creation_time_usec: 0,
            },
            payload: FfiSlice {
                data: payload.as_ptr(),
                len: payload.len(),
            },
        };
        manager.process_downstream(30, &packet, &[]).unwrap();
        flush_test_layer(&manager, 30, 0);

        let name = CString::new("numDownstreamPacketsUnicastRx0").unwrap();
        let names = [name.as_ptr()];
        let mut error = [0i8; 64];
        let query = emane_rs_statistic_query(
            build_id,
            FfiStringArray {
                data: names.as_ptr(),
                len: names.len(),
            },
            error.as_mut_ptr(),
            error.len(),
        );
        assert_eq!(query.len, 1);
        assert_eq!(unsafe { &*query.data }.value.u64_value, 1);
        emane_rs_statistic_free_query_result(query);

        let name = CString::new("UnicastPacketAcceptTable0").unwrap();
        let names = [name.as_ptr()];
        let tables = emane_rs_statistic_query_table(
            build_id,
            FfiStringArray {
                data: names.as_ptr(),
                len: names.len(),
            },
            error.as_mut_ptr(),
            error.len(),
        );
        assert_eq!(tables.len, 1);
        let table = unsafe { &*tables.data };
        assert_eq!(table.rows_len, 1);
        let values = unsafe {
            let row = &*table.rows;
            std::slice::from_raw_parts(row.values.data, row.values.len)
        };
        assert_eq!(values.len(), 5);
        assert_eq!(values[0].u64_value, 30);
        assert_eq!(values[1].u64_value, 1);
        assert_eq!(values[2].u64_value, payload.len() as u64);
        assert_eq!(values[3].u64_value, 0);
        assert_eq!(values[4].u64_value, 0);
        emane_rs_statistic_free_table_query_result(tables);

        let dropped = FfiPacket {
            info: FfiPacketInfo {
                source: 31,
                destination: 30,
                ..packet.info
            },
            payload: packet.payload,
        };
        manager.layers[&30][0]
            .invocation
            .call(|api, context| (api.process_upstream)(context, &dropped, std::ptr::null(), 4097));
        let name = CString::new("UnicastPacketDropTable0").unwrap();
        let names = [name.as_ptr()];
        let tables = emane_rs_statistic_query_table(
            build_id,
            FfiStringArray {
                data: names.as_ptr(),
                len: names.len(),
            },
            error.as_mut_ptr(),
            error.len(),
        );
        assert_eq!(tables.len, 1);
        let table = unsafe { &*tables.data };
        assert_eq!(table.rows_len, 1);
        let values = unsafe {
            let row = &*table.rows;
            std::slice::from_raw_parts(row.values.data, row.values.len)
        };
        assert_eq!(values.len(), 15);
        assert_eq!(values[0].u64_value, 31);
        assert_eq!(values[14].u64_value, 1);
        emane_rs_statistic_free_table_query_result(tables);
        let model = ModelHeader {
            registration_id: emane_plugin_api::MAC_REGISTRATION_RFPIPE,
            sequence: 128,
            data_rate_bps: 1_000_000,
            category: 0,
            message_type: 0,
            flags: 0,
        }
        .encode();
        let controls = [FfiControlMessage {
            msg_type: CONTROL_MODEL_HEADER,
            payload: FfiSlice {
                data: model.as_ptr(),
                len: model.len(),
            },
        }];
        manager.process_downstream(30, &packet, &controls).unwrap();
        flush_test_layer(&manager, 30, 0);
        // First packet was four bytes without a MAC header. The second adds
        // seven bytes of CommonMAC framing (two-byte sequence varint).
        for statistic in [
            "numDownstreamBytesUnicastRx0",
            "numDownstreamBytesUnicastTx0",
        ] {
            let name = CString::new(statistic).unwrap();
            let names = [name.as_ptr()];
            let query = emane_rs_statistic_query(
                build_id,
                FfiStringArray {
                    data: names.as_ptr(),
                    len: names.len(),
                },
                error.as_mut_ptr(),
                error.len(),
            );
            assert_eq!(query.len, 1);
            assert_eq!(unsafe { &*query.data }.value.u64_value, 15);
            emane_rs_statistic_free_query_result(query);
        }
    }

    #[test]
    fn started_layer_queue_tracks_events_and_phy_event_info() {
        use crate::protobufs::emane_message::{location_event, LocationEvent};
        use crate::statistics::{
            emane_rs_statistic_free_query_result, emane_rs_statistic_free_table_query_result,
            emane_rs_statistic_query, emane_rs_statistic_query_table, FfiStringArray,
        };

        let mut manager = NemManager::new([16; 16]);
        manager
            .add_layer_configured(
                40,
                "emanephy",
                2,
                &[("subid".to_string(), vec!["1".to_string()])],
            )
            .unwrap();
        let build_id = manager.layers[&40][0].event_build_id;
        let invocation = manager.layers[&40][0].invocation;
        manager.start().unwrap();

        let event = LocationEvent {
            locations: vec![location_event::Location {
                nem_id: 41,
                position: location_event::location::Position {
                    latitude_degrees: 40.0,
                    longitude_degrees: -74.0,
                    altitude_meters: 10.0,
                },
                velocity: None,
                orientation: None,
            }],
        }
        .encode_to_vec();
        invocation.process_event(100, event.as_ptr(), event.len());

        // A processing counter increments before the callback finishes; wait behind it in the queue.
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        assert!(manager.layers[&40][0]
            .queue
            .enqueue(
                QueueTaskKind::FileDescriptor,
                Box::new(move || {
                    let _ = done_tx.send(());
                })
            )
            .is_ok());
        done_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        let processed = CString::new("processedEvents").unwrap();
        let requested = [processed.as_ptr()];
        let mut error = [0i8; 128];
        for _ in 0..100 {
            let result = emane_rs_statistic_query(
                build_id,
                FfiStringArray {
                    data: requested.as_ptr(),
                    len: requested.len(),
                },
                error.as_mut_ptr(),
                error.len(),
            );
            let complete = result.len == 1 && unsafe { &*result.data }.value.u64_value == 1;
            emane_rs_statistic_free_query_result(result);
            if complete {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }

        for (name, expected_columns) in [
            ("EventReceptionTable", 2usize),
            ("LocationEventInfoTable", 10),
        ] {
            let name = CString::new(name).unwrap();
            let requested = [name.as_ptr()];
            let result = emane_rs_statistic_query_table(
                build_id,
                FfiStringArray {
                    data: requested.as_ptr(),
                    len: requested.len(),
                },
                error.as_mut_ptr(),
                error.len(),
            );
            assert_eq!(result.len, 1);
            let table = unsafe { &*result.data };
            assert_eq!(table.rows_len, 1);
            assert_eq!(unsafe { &*table.rows }.values.len, expected_columns);
            emane_rs_statistic_free_table_query_result(result);
        }

        crate::native_configuration::update(
            build_id,
            vec![(
                "radiosilenceenable".to_string(),
                vec![crate::native_configuration::ConfigurationValue::Boolean(
                    true,
                )],
            )],
        )
        .unwrap();
        let processed = CString::new("processedConfiguration").unwrap();
        let requested = [processed.as_ptr()];
        let result = emane_rs_statistic_query(
            build_id,
            FfiStringArray {
                data: requested.as_ptr(),
                len: requested.len(),
            },
            error.as_mut_ptr(),
            error.len(),
        );
        assert_eq!(result.len, 1);
        assert_eq!(unsafe { &*result.data }.value.u64_value, 1);
        emane_rs_statistic_free_query_result(result);
        manager.stop();

        let late_event = LocationEvent {
            locations: vec![location_event::Location {
                nem_id: 42,
                position: location_event::location::Position {
                    latitude_degrees: 41.0,
                    longitude_degrees: -75.0,
                    altitude_meters: 20.0,
                },
                velocity: None,
                orientation: None,
            }],
        }
        .encode_to_vec();
        invocation.process_event(100, late_event.as_ptr(), late_event.len());

        let name = CString::new("LocationEventInfoTable").unwrap();
        let requested = [name.as_ptr()];
        let result = emane_rs_statistic_query_table(
            build_id,
            FfiStringArray {
                data: requested.as_ptr(),
                len: requested.len(),
            },
            error.as_mut_ptr(),
            error.len(),
        );
        assert_eq!(result.len, 1);
        assert_eq!(unsafe { &*result.data }.rows_len, 1);
        emane_rs_statistic_free_table_query_result(result);

        assert!(crate::native_configuration::update(
            build_id,
            vec![(
                "radiosilenceenable".to_string(),
                vec![crate::native_configuration::ConfigurationValue::Boolean(
                    false,
                )],
            )],
        )
        .is_ok());
        // The original queue accepts this update after stop, but its model
        // state stays unchanged because the worker no longer executes it.
        let state = unsafe { &*(invocation.context() as *const BuiltinState) };
        assert!(state.phy.radio_silence_enabled);
    }

    #[test]
    fn dynamic_rfpipe_updates_aggregated_native_signal_table() {
        let _guard = DYNAMIC_PLUGIN_TEST_LOCK.lock().unwrap();
        use crate::statistics::{
            emane_rs_statistic_clear_table, emane_rs_statistic_free_table_query_result,
            emane_rs_statistic_query_table, FfiStringArray,
        };
        use emane_plugin_api::{ModelHeader, CONTROL_MODEL_HEADER};

        let Ok(plugin) = resolve_plugin_path("rfpipemaclayer") else {
            return;
        };
        if !plugin.exists() {
            return;
        }
        let pcr_path = std::env::temp_dir().join(format!(
            "emane-rfpipe-pcr-{}-{}.xml",
            std::process::id(),
            unix_time_microseconds()
        ));
        std::fs::write(
            &pcr_path,
            r#"<pcr><table pktsize="0"><row sinr="-1000" por="100"/><row sinr="1000" por="100"/></table></pcr>"#,
        )
        .unwrap();
        let mut manager = NemManager::new([15; 16]);
        let config = [
            (
                "pcrcurveuri".to_string(),
                vec![format!("file://{}", pcr_path.display())],
            ),
            (
                "rfsignaltable.averageallantennas".to_string(),
                vec!["true".to_string()],
            ),
            (
                "rfsignaltable.averageallfrequencies".to_string(),
                vec!["true".to_string()],
            ),
        ];
        if let Err(error) = manager.add_layer_configured(1, plugin.to_str().unwrap(), 1, &config) {
            if error.contains("plugin ABI mismatch") {
                return;
            }
            panic!("{error}");
        }
        manager
            .add_layer_configured(
                1,
                "emanephy",
                2,
                &[
                    ("subid".into(), vec!["1".into()]),
                    (
                        "frequencyofinterest".into(),
                        vec!["2.4G".into(), "5.8G".into()],
                    ),
                    ("noisemode".into(), vec!["outofband".into()]),
                ],
            )
            .unwrap();
        let monitor = manager.runtime.spectrum_monitors.read().unwrap()[&(1, 0)]
            .upgrade()
            .unwrap();
        let layer = &manager.layers[&1][0];
        let build_id = layer.event_build_id;
        let invocation = layer.invocation;
        let header = ModelHeader {
            registration_id: emane_plugin_api::MAC_REGISTRATION_RFPIPE,
            sequence: 1,
            data_rate_bps: 1_000_000,
            category: 0,
            message_type: 0,
            flags: 0,
        }
        .encode();
        // Length-prefixed RF Pipe protobuf header (dataRate = 1,000,000)
        // followed by two bytes of model payload.
        let payload = [0u8, 4, 0x08, 0xc0, 0x84, 0x3d, 1, 2];
        let packet = FfiPacket {
            info: FfiPacketInfo {
                uuid: [0; 16],
                source: 2,
                destination: 1,
                priority: 0,
                creation_time_sec: 0,
                creation_time_usec: 0,
            },
            payload: FfiSlice {
                data: payload.as_ptr(),
                len: payload.len(),
            },
        };
        for (frequency_hz, rx_power_dbm, noise_floor_dbm) in
            [(2_400_000_000, -50.0, -60.0), (5_800_000_000, -70.0, -80.0)]
        {
            let start = unix_time_microseconds() - 2000;
            let segment = FfiFrequencySegment {
                frequency_hz,
                rx_power_dbm: noise_floor_dbm,
                duration_microsec: 1000,
                offset_microsec: 0,
            };
            monitor.lock().unwrap().update(
                start,
                start,
                0,
                0.0,
                &[segment],
                1_000_000,
                &[10.0f64.powf(noise_floor_dbm / 10.0)],
                false,
                &[3],
                2,
                0,
                0,
                std::ptr::null(),
                0,
            );
            let rx = RxProperties {
                frequency_hz,
                bandwidth_hz: 1_000_000,
                rx_power_dbm,
                noise_floor_dbm,
                tx_time_microseconds: start,
                propagation_microseconds: 0,
                duration_microseconds: 1000,
                antenna_index: 0,
                sub_id: 0,
                signal_in_noise: false,
            }
            .encode();
            let controls = [
                FfiControlMessage {
                    msg_type: CONTROL_MODEL_HEADER,
                    payload: FfiSlice {
                        data: header.as_ptr(),
                        len: header.len(),
                    },
                },
                FfiControlMessage {
                    msg_type: CONTROL_RX_PROPERTIES,
                    payload: FfiSlice {
                        data: rx.as_ptr(),
                        len: rx.len(),
                    },
                },
            ];
            invocation.call(|api, context| {
                (api.process_upstream)(context, &packet, controls.as_ptr(), controls.len())
            });
        }

        let table_name = CString::new("RFSignalTable").unwrap();
        let table_names = [table_name.as_ptr()];
        let requested = FfiStringArray {
            data: table_names.as_ptr(),
            len: table_names.len(),
        };
        let mut error = [0i8; 128];
        let result =
            emane_rs_statistic_query_table(build_id, requested, error.as_mut_ptr(), error.len());
        assert_eq!(result.len, 1);
        let table = unsafe { &*result.data };
        assert_eq!(table.rows_len, 1);
        let values = unsafe {
            let row = &*table.rows;
            std::slice::from_raw_parts(row.values.data, row.values.len)
        };
        assert_eq!(values[3].u64_value, 2);
        assert_eq!(values[4].d_value, -60.0);
        assert_eq!(values[5].d_value, -70.0);
        assert_eq!(values[6].d_value, 10.0);
        emane_rs_statistic_free_table_query_result(result);

        emane_rs_statistic_clear_table(build_id, requested, error.as_mut_ptr(), error.len());
        let result =
            emane_rs_statistic_query_table(build_id, requested, error.as_mut_ptr(), error.len());
        assert_ne!(error[0], 0, "C++ RFSignalTable is not externally clearable");
        assert_eq!(unsafe { &*result.data }.rows_len, 1);
        emane_rs_statistic_free_table_query_result(result);
        let _ = std::fs::remove_file(pcr_path);
    }

    #[test]
    fn local_ota_is_observed_by_every_other_nem() {
        LOCAL_OTA_HITS.store(0, Ordering::Relaxed);
        let invocation = Invocation {
            api: test_api() as *const PluginApi as usize,
            plugin_ctx: std::ptr::dangling_mut::<u8>() as usize,
            queue: 0,
        };
        let runtime = Runtime {
            uuid: [1; 16],
            invocations: RwLock::new(HashMap::from([
                (1, vec![invocation]),
                (2, vec![invocation]),
                (3, vec![invocation]),
            ])),
            boundaries: RwLock::new(HashMap::new()),
            phy_tx_sequences: Mutex::new(HashMap::new()),
            spectrum_monitors: RwLock::new(HashMap::new()),
        };
        let payload = [1u8];
        let packet = FfiPacket {
            info: FfiPacketInfo {
                uuid: [0; 16],
                source: 1,
                destination: 2,
                priority: 0,
                creation_time_sec: 0,
                creation_time_usec: 0,
            },
            payload: FfiSlice {
                data: payload.as_ptr(),
                len: payload.len(),
            },
        };
        runtime.route_downstream(1, 0, &packet, std::ptr::null(), 0);
        assert_eq!(LOCAL_OTA_HITS.load(Ordering::Relaxed), 2);

        let transmitters = TxTransmitters {
            transmitters: vec![TxTransmitter {
                nem_id: 2,
                tx_power_dbm: 0.0,
            }],
        }
        .encode()
        .unwrap();
        let control = FfiControlMessage {
            msg_type: CONTROL_TX_TRANSMITTERS,
            payload: FfiSlice {
                data: transmitters.as_ptr(),
                len: transmitters.len(),
            },
        };
        LOCAL_OTA_HITS.store(0, Ordering::Relaxed);
        runtime.route_downstream(1, 0, &packet, &control, 1);
        assert_eq!(LOCAL_OTA_HITS.load(Ordering::Relaxed), 1);

        let model = ModelHeader {
            registration_id: emane_plugin_api::MAC_REGISTRATION_RFPIPE,
            sequence: 1,
            data_rate_bps: 1_000_000,
            category: 0,
            message_type: 1,
            flags: 0,
        }
        .encode();
        let tx = TxProperties {
            frequency_hz: 2_400_000_000,
            bandwidth_hz: 1_000_000,
            tx_power_dbm: 0.0,
            duration_microseconds: 100,
            offset_microseconds: 0,
            tx_time_microseconds: 1,
            antenna_index: 0,
            spectral_mask_index: 0,
            sub_id: 1,
        }
        .encode();
        let mut controls = vec![control];
        for (kind, bytes) in [
            (CONTROL_MODEL_HEADER, model.as_slice()),
            (CONTROL_TX_PROPERTIES, tx.as_slice()),
        ] {
            controls.push(FfiControlMessage {
                msg_type: kind,
                payload: FfiSlice {
                    data: bytes.as_ptr(),
                    len: bytes.len(),
                },
            });
        }
        LOCAL_OTA_HITS.store(0, Ordering::Relaxed);
        runtime.route_downstream(1, 0, &packet, controls.as_ptr(), controls.len());
        assert_eq!(
            LOCAL_OTA_HITS.load(Ordering::Relaxed),
            2,
            "The full PHY transmitter list alone must not exclude local receivers"
        );
        let ats = LegacyOtaTransmitterSet {
            nem_ids: vec![2, 3],
        }
        .encode_to_vec();
        controls.push(FfiControlMessage {
            msg_type: CONTROL_OTA_TRANSMITTERS,
            payload: FfiSlice {
                data: ats.as_ptr(),
                len: ats.len(),
            },
        });
        LOCAL_OTA_HITS.store(0, Ordering::Relaxed);
        runtime.route_downstream(1, 0, &packet, controls.as_ptr(), controls.len());
        assert_eq!(LOCAL_OTA_HITS.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn ota_transmitter_controls_accept_original_encoding_and_reject_truncation() {
        // Original protobuf serializes the set {2,3} as packed uint32 values.
        let wire = [0, 1, 0, 108, 0, 4, 10, 2, 2, 3];
        assert_eq!(
            decode_legacy_ota_transmitters(&wire),
            Some(HashSet::from([2, 3]))
        );
        for length in 1..wire.len() {
            assert!(decode_legacy_ota_transmitters(&wire[..length]).is_none());
        }
        assert_eq!(decode_legacy_ota_transmitters(&[]), Some(HashSet::new()));
        assert_eq!(
            decode_legacy_ota_transmitters(&[0, 1, 0, 108, 0, 1, 10]),
            None,
            "A truncated protobuf length is rejected"
        );
        assert_eq!(
            decode_legacy_ota_transmitters(&[0, 1, 0, 109, 0, 1, 10]),
            Some(HashSet::new()),
            "Unknown control payloads are opaque to the OTA manager"
        );
    }

    #[test]
    fn legacy_ota_phy_and_mac_framing_round_trips_native_controls() {
        let payload = [9u8, 8, 7];
        let packet = FfiPacket {
            info: FfiPacketInfo {
                uuid: [0; 16],
                source: 1,
                destination: 2,
                priority: 0,
                creation_time_sec: 0,
                creation_time_usec: 0,
            },
            payload: FfiSlice {
                data: payload.as_ptr(),
                len: payload.len(),
            },
        };
        let model = ModelHeader {
            registration_id: emane_plugin_api::MAC_REGISTRATION_RFPIPE,
            sequence: 42,
            data_rate_bps: 1_000_000,
            category: 0,
            message_type: 1,
            flags: 0,
        }
        .encode();
        let tx = TxProperties {
            frequency_hz: 2_400_000_000,
            bandwidth_hz: 1_000_000,
            tx_power_dbm: 5.0,
            duration_microseconds: 100,
            offset_microseconds: 0,
            tx_time_microseconds: 123_456,
            antenna_index: 0,
            spectral_mask_index: 0,
            sub_id: 1,
        }
        .encode();
        let controls = [
            FfiControlMessage {
                msg_type: CONTROL_MODEL_HEADER,
                payload: FfiSlice {
                    data: model.as_ptr(),
                    len: model.len(),
                },
            },
            FfiControlMessage {
                msg_type: CONTROL_TX_PROPERTIES,
                payload: FfiSlice {
                    data: tx.as_ptr(),
                    len: tx.len(),
                },
            },
        ];
        let wire =
            encode_legacy_ota_payload(&packet, controls.as_ptr(), controls.len(), 7).unwrap();
        let phy_length = usize::from(u16::from_be_bytes(wire[..2].try_into().unwrap()));
        let phy = CommonPhyHeader::decode(&wire[2..2 + phy_length]).unwrap();
        assert_eq!(phy.sequence_number, 7);
        let decoded = decode_legacy_ota_payload(&wire, 1).unwrap();
        assert_eq!(decoded.payload, payload);
        let model = control_payload(decoded.controls(), CONTROL_MODEL_HEADER)
            .and_then(ModelHeader::decode)
            .unwrap();
        assert_eq!(
            model.registration_id,
            emane_plugin_api::MAC_REGISTRATION_RFPIPE
        );
        assert_eq!(model.sequence, 42);
        let tx = find_tx_properties(decoded.controls()).unwrap();
        assert_eq!(tx.frequency_hz, 2_400_000_000);
        assert_eq!(tx.bandwidth_hz, 1_000_000);
        assert_eq!(tx.tx_time_microseconds, 123_456);

        // OTA logical sources need not appear in the physical transmitter list.
        let decoded = decode_legacy_ota_payload(&wire, 19).unwrap();
        assert_eq!(decoded.payload, payload);
        assert_eq!(
            find_tx_transmitters(decoded.controls())
                .unwrap()
                .transmitters[0]
                .nem_id,
            1
        );

        let python_publisher_wire = &wire[..2 + phy_length];
        let decoded = decode_legacy_ota_payload(python_publisher_wire, 1).unwrap();
        assert!(decoded.payload.is_empty());
        assert!(control_payload(decoded.controls(), CONTROL_MODEL_HEADER).is_none());
        assert!(find_tx_properties(decoded.controls()).is_some());
    }

    #[test]
    fn legacy_commeffect_framing_round_trips_native_controls() {
        let payload = [1u8, 2, 3, 4];
        let packet = FfiPacket {
            info: FfiPacketInfo {
                uuid: [0; 16],
                source: 7,
                destination: 8,
                priority: 0,
                creation_time_sec: 0,
                creation_time_usec: 0,
            },
            payload: FfiSlice {
                data: payload.as_ptr(),
                len: payload.len(),
            },
        };
        let header = CommEffectHeader {
            group_id: 9,
            sequence: 10,
            tx_time_microseconds: 11,
        }
        .encode();
        let control = FfiControlMessage {
            msg_type: CONTROL_COMM_EFFECT_HEADER,
            payload: FfiSlice {
                data: header.as_ptr(),
                len: header.len(),
            },
        };
        let wire = encode_legacy_ota_payload(&packet, &control, 1, 0).unwrap();
        let decoded = decode_legacy_ota_payload(&wire, 7).unwrap();
        assert_eq!(decoded.payload, payload);
        let header = control_payload(decoded.controls(), CONTROL_COMM_EFFECT_HEADER)
            .and_then(CommEffectHeader::decode)
            .unwrap();
        assert_eq!(header.group_id, 9);
        assert_eq!(header.sequence, 10);
        assert_eq!(header.tx_time_microseconds, 11);
    }

    #[test]
    fn builtin_stack_lifecycle_and_routing() {
        let mut manager = NemManager::new([7; 16]);
        manager
            .add_layer_configured(
                1,
                "emanephy",
                2,
                &[("subid".to_string(), vec!["1".to_string()])],
            )
            .unwrap();
        manager
            .add_layer_configured(
                2,
                "emanephy",
                2,
                &[("subid".to_string(), vec!["1".to_string()])],
            )
            .unwrap();
        manager.start().unwrap();
        manager.post_start();
        let bytes = [1, 2, 3];
        let packet = FfiPacket {
            info: FfiPacketInfo {
                uuid: [0; 16],
                source: 1,
                destination: 2,
                priority: 0,
                creation_time_sec: 0,
                creation_time_usec: 0,
            },
            payload: FfiSlice {
                data: bytes.as_ptr(),
                len: bytes.len(),
            },
        };
        manager.process_downstream(1, &packet, &[]).unwrap();
        manager.stop();
    }

    #[test]
    fn dynamic_plugin_can_be_loaded_and_run_in_stack() {
        let _guard = DYNAMIC_PLUGIN_TEST_LOCK.lock().unwrap();
        let Ok(plugin) = resolve_plugin_path("dummy-mac") else {
            // Package-only test invocations do not necessarily build sibling
            // cdylibs; the workspace smoke test covers that configuration.
            return;
        };
        if !plugin.exists() {
            return;
        }
        let mut manager = NemManager::new([9; 16]);
        if let Err(error) = manager.add_layer_configured(1, plugin.to_str().unwrap(), 1, &[]) {
            // `cargo test` does not rebuild sibling cdylib artifacts. A stale
            // library is correctly rejected; the workspace build/smoke test
            // exercises the current artifact.
            if error.contains("plugin ABI mismatch") {
                return;
            }
            panic!("{error}");
        }
        manager
            .add_layer_configured(
                1,
                "emanephy",
                2,
                &[("subid".to_string(), vec!["1".to_string()])],
            )
            .unwrap();
        manager.start().unwrap();
        manager.post_start();
        manager.stop();
    }

    #[test]
    fn dynamic_bypass_stack_delivers_between_two_nems() {
        let _guard = DYNAMIC_PLUGIN_TEST_LOCK.lock().unwrap();
        let (Ok(mac), Ok(phy)) = (
            resolve_plugin_path("bypassmaclayer"),
            resolve_plugin_path("bypassphylayer"),
        ) else {
            return;
        };
        if !mac.exists() || !phy.exists() {
            return;
        }
        BYPASS_STACK_HITS.store(0, Ordering::Relaxed);
        BYPASS_STACK_BYTES.store(0, Ordering::Relaxed);
        let mut manager = NemManager::new([13; 16]);
        for nem_id in [1, 2] {
            add_capture_transport(&mut manager, nem_id);
            if let Err(error) = manager.add_layer_configured(nem_id, mac.to_str().unwrap(), 1, &[])
            {
                if error.contains("plugin ABI mismatch") {
                    return;
                }
                panic!("{error}");
            }
            manager
                .add_layer_configured(nem_id, phy.to_str().unwrap(), 2, &[])
                .unwrap();
        }
        manager.start().unwrap();
        manager.post_start();
        let payload = [4u8, 5, 6];
        let packet = FfiPacket {
            info: FfiPacketInfo {
                uuid: [0; 16],
                source: 1,
                destination: 2,
                priority: 0,
                creation_time_sec: 0,
                creation_time_usec: 0,
            },
            payload: FfiSlice {
                data: payload.as_ptr(),
                len: payload.len(),
            },
        };
        manager.process_downstream(1, &packet, &[]).unwrap();
        for _ in 0..100 {
            if BYPASS_STACK_HITS.load(Ordering::Acquire) != 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(BYPASS_STACK_HITS.load(Ordering::Relaxed), 1);
        assert_eq!(BYPASS_STACK_BYTES.load(Ordering::Relaxed), 15);
        manager.stop();
    }
    #[test]
    fn frequency_interest_zero_bandwidth_empty_set_and_compatibility_mode() {
        let mut manager = NemManager::new([31; 16]);
        for mode in [1, 2] {
            let id = 600 + mode;
            manager
                .add_layer_configured(
                    id,
                    "emanephy",
                    2,
                    &[
                        ("subid".into(), vec!["7".into()]),
                        ("compatibilitymode".into(), vec![mode.to_string()]),
                        ("bandwidth".into(), vec!["2M".into()]),
                        ("frequencyofinterest".into(), vec!["2.4G".into()]),
                    ],
                )
                .unwrap();
            let context = manager.layers[&id][0].invocation.context();
            for frequencies in [vec![2_500_000_000], Vec::new()] {
                let encoded = FrequencyOfInterest {
                    bandwidth_hz: 0,
                    frequencies_hz: frequencies.clone(),
                }
                .encode()
                .unwrap();
                let control = FfiControlMessage {
                    msg_type: CONTROL_FREQUENCY_INTEREST,
                    payload: FfiSlice {
                        data: encoded.as_ptr(),
                        len: encoded.len(),
                    },
                };
                builtin_downstream(context, std::ptr::null(), &control, 1);
                let state = unsafe { &*(context as *const BuiltinState) };
                assert_eq!(state.phy.bandwidth_hz, 2_000_000);
                assert_eq!(
                    state.phy.frequencies_of_interest,
                    if mode == 1 {
                        frequencies
                    } else {
                        vec![2_400_000_000]
                    }
                );
            }
        }
    }

    #[test]
    fn framework_spectrum_queries_share_live_phy_monitor_and_isolate_nems() {
        let mut manager = NemManager::new([29; 16]);
        let config = vec![
            ("subid".to_string(), vec!["7".to_string()]),
            ("noisemode".to_string(), vec!["outofband".to_string()]),
            ("frequency".to_string(), vec!["2.4G".to_string()]),
            ("frequencyofinterest".to_string(), vec!["2.4G".to_string()]),
            ("bandwidth".to_string(), vec!["1M".to_string()]),
        ];
        for id in [501, 502] {
            manager
                .add_layer_configured(id, "emanephy", 2, &config)
                .unwrap();
        }
        let monitor = manager.runtime.spectrum_monitors.read().unwrap()[&(501, 0)]
            .upgrade()
            .unwrap();
        let ctx =
            &*manager.layers[&501][0]._framework_context as *const FrameworkContext as *mut c_void;
        let other_ctx =
            &*manager.layers[&502][0]._framework_context as *const FrameworkContext as *mut c_void;
        let start = unix_time_microseconds() - 2_000;
        let query = FfiSpectrumQuery {
            frequency_hz: 2_400_000_000,
            start_time_microseconds: start,
            duration_microseconds: 1_000,
            rx_power_dbm: -50.0,
            antenna_index: 0,
        };
        let mut before = FfiSpectrumResult::default();
        assert!(query_spectrum(ctx, &query, &mut before));
        let mut monitor = monitor.lock().unwrap();
        let segment = FfiFrequencySegment {
            frequency_hz: 2_400_000_000,
            rx_power_dbm: -60.0,
            duration_microsec: 500,
            offset_microsec: 0,
        };
        monitor.update(
            start + 500,
            start + 500,
            0,
            0.0,
            &[segment],
            1_000_000,
            &[1e-6],
            false,
            &[3],
            9,
            0,
            0,
            std::ptr::null(),
            0,
        );
        drop(monitor);
        // Query from another layer thread without touching the mutable PHY state.
        let ctx_address = ctx as usize;
        let after = std::thread::spawn(move || {
            let mut result = FfiSpectrumResult::default();
            assert!(query_spectrum(
                ctx_address as *mut c_void,
                &query,
                &mut result
            ));
            result
        })
        .join()
        .unwrap();
        assert!((after.noise_floor_dbm + 60.0).abs() < 1e-6);
        assert!(after.noise_floor_dbm - before.noise_floor_dbm > 39.0);
        let mut other = FfiSpectrumResult::default();
        assert!(query_spectrum(other_ctx, &query, &mut other));
        assert_eq!(other.noise_floor_dbm, before.noise_floor_dbm);
        assert!(!query_spectrum(
            ctx,
            &FfiSpectrumQuery {
                frequency_hz: 1,
                ..query
            },
            &mut other
        ));
        assert!(!query_spectrum(
            ctx,
            &FfiSpectrumQuery {
                antenna_index: 99,
                ..query
            },
            &mut other
        ));
        assert!(!query_spectrum(ctx, std::ptr::null(), &mut other));
    }
    #[test]
    fn dynamic_wifi_stack_uses_phy_spectrum_service_and_configured_sub_id() {
        let _guard = DYNAMIC_PLUGIN_TEST_LOCK.lock().unwrap();
        let Ok(plugin) = resolve_plugin_path("ieee80211abgmaclayer") else {
            return;
        };
        if !plugin.exists() {
            return;
        }
        BYPASS_STACK_HITS.store(0, Ordering::Relaxed);
        BYPASS_STACK_BYTES.store(0, Ordering::Relaxed);
        let mut manager = NemManager::new([30; 16]);
        let pcr = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../plugins/ieee80211abg/tests/fixtures/ieee80211abg-pcr.xml");
        for nem_id in [1, 2] {
            add_capture_transport(&mut manager, nem_id);
            if let Err(error) = manager.add_layer_configured(
                nem_id,
                plugin.to_str().unwrap(),
                1,
                &[(
                    "pcrcurveuri".into(),
                    vec![pcr.to_string_lossy().into_owned()],
                )],
            ) {
                if error.contains("plugin ABI mismatch") {
                    return;
                }
                panic!("{error}");
            }
            manager
                .add_layer_configured(
                    nem_id,
                    "emanephy",
                    2,
                    &[
                        ("subid".into(), vec!["7".into()]),
                        ("noisemode".into(), vec!["outofband".into()]),
                    ],
                )
                .unwrap();
            let phy = manager.layers[&nem_id].last().unwrap().invocation;
            let state = unsafe { &mut *(phy.context() as *mut BuiltinState) };
            state
                .phy
                .pathloss
                .insert(if nem_id == 1 { 2 } else { 1 }, HashMap::from([(0, 50.0)]));
        }
        manager.start().unwrap();
        manager.post_start();
        let payload = [5u8; 128];
        let packet = FfiPacket {
            info: FfiPacketInfo {
                uuid: [0; 16],
                source: 1,
                destination: 2,
                priority: 0,
                creation_time_sec: 0,
                creation_time_usec: 0,
            },
            payload: FfiSlice {
                data: payload.as_ptr(),
                len: payload.len(),
            },
        };
        manager.process_downstream(1, &packet, &[]).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while BYPASS_STACK_HITS.load(Ordering::Acquire) == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        manager.stop();
        assert_eq!(BYPASS_STACK_HITS.load(Ordering::Relaxed), 1);
        assert_eq!(BYPASS_STACK_BYTES.load(Ordering::Relaxed), 640);
    }
}

#[cfg(test)]
#[path = "nem_parity_tests.rs"]
mod parity_tests;

#[cfg(test)]
#[path = "nem_receive_tests.rs"]
mod receive_regressions;

#[cfg(test)]
#[path = "nem_upstream_tests.rs"]
mod upstream_regressions;

#[cfg(test)]
#[path = "nem_lifecycle_tests.rs"]
mod lifecycle_tests;

#[cfg(test)]
#[path = "nem_dispatch_tests.rs"]
mod nem_dispatch_tests;

#[cfg(test)]
#[path = "nem_antenna_tests.rs"]
mod antenna_regressions;
