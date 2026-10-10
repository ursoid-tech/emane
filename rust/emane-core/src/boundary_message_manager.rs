use crate::plugin_interface::{FfiControlMessage, FfiPacket, FfiPacketInfo, FfiSlice};
use socket2::{Domain, Protocol, Socket, Type};
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DATA_MESSAGE: u16 = 1;
const CONTROL_MESSAGE: u16 = 2;
const HEADER_LENGTH: usize = 6;
const DATA_HEADER_LENGTH: usize = 13;
const CONTROL_HEADER_LENGTH: usize = 4;
const MAX_MESSAGE_LENGTH: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoundaryProtocol {
    Udp,
    TcpServer,
    TcpClient,
}

impl BoundaryProtocol {
    pub fn platform(value: &str) -> Result<Self, String> {
        match value {
            "udp" => Ok(Self::Udp),
            "tcp" => Ok(Self::TcpServer),
            _ => Err(format!("unsupported boundary protocol {value}")),
        }
    }

    pub fn transport(value: &str) -> Result<Self, String> {
        match value {
            "udp" => Ok(Self::Udp),
            "tcp" => Ok(Self::TcpClient),
            _ => Err(format!("unsupported boundary protocol {value}")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedControlMessage {
    pub message_type: u32,
    pub payload: Vec<u8>,
}

#[derive(Clone)]
pub struct BoundaryPacket {
    pub info: FfiPacketInfo,
    pub payload: Vec<u8>,
    pub controls: Vec<OwnedControlMessage>,
}

#[derive(Clone)]
pub enum BoundaryMessage {
    Packet(BoundaryPacket),
    Control(Vec<OwnedControlMessage>),
}

type MessageHandler = Arc<dyn Fn(BoundaryMessage) + Send + Sync + 'static>;

struct SharedState {
    cancel: AtomicBool,
    udp: Mutex<Option<UdpSocket>>,
    tcp: Mutex<Option<TcpStream>>,
    local: SocketAddr,
    remote: SocketAddr,
    handler: MessageHandler,
}

pub struct BoundaryMessageManager {
    shared: Arc<SharedState>,
    worker: Option<JoinHandle<()>>,
}

impl BoundaryMessageManager {
    pub fn open<F>(
        local: &str,
        remote: &str,
        protocol: BoundaryProtocol,
        handler: F,
    ) -> Result<Self, String>
    where
        F: Fn(BoundaryMessage) + Send + Sync + 'static,
    {
        let local = resolve_address(local, "local boundary endpoint")?;
        let remote =
            resolve_address_for_family(remote, local.is_ipv4(), "remote boundary endpoint")?;
        let shared = Arc::new(SharedState {
            cancel: AtomicBool::new(false),
            udp: Mutex::new(None),
            tcp: Mutex::new(None),
            local,
            remote,
            handler: Arc::new(handler),
        });

        let worker = match protocol {
            BoundaryProtocol::Udp => {
                let socket = UdpSocket::bind(local).map_err(|error| {
                    format!("failed to bind UDP boundary endpoint {local}: {error}")
                })?;
                socket
                    .set_read_timeout(Some(Duration::from_millis(100)))
                    .map_err(|error| {
                        format!("failed to configure UDP boundary endpoint: {error}")
                    })?;
                shared
                    .udp
                    .lock()
                    .map_err(|_| "UDP boundary lock poisoned".to_string())?
                    .replace(socket.try_clone().map_err(|error| {
                        format!("failed to clone UDP boundary socket: {error}")
                    })?);
                let state = Arc::clone(&shared);
                thread::Builder::new()
                    .name("emane-boundary-udp".to_string())
                    .spawn(move || receive_udp(state, socket))
                    .map_err(|error| format!("failed to start UDP boundary worker: {error}"))?
            }
            BoundaryProtocol::TcpServer => {
                let listener = TcpListener::bind(local).map_err(|error| {
                    format!("failed to bind TCP boundary endpoint {local}: {error}")
                })?;
                listener.set_nonblocking(true).map_err(|error| {
                    format!("failed to configure TCP boundary listener: {error}")
                })?;
                let state = Arc::clone(&shared);
                thread::Builder::new()
                    .name("emane-boundary-tcp-server".to_string())
                    .spawn(move || receive_tcp_server(state, listener))
                    .map_err(|error| format!("failed to start TCP boundary server: {error}"))?
            }
            BoundaryProtocol::TcpClient => {
                let state = Arc::clone(&shared);
                thread::Builder::new()
                    .name("emane-boundary-tcp-client".to_string())
                    .spawn(move || receive_tcp_client(state))
                    .map_err(|error| format!("failed to start TCP boundary client: {error}"))?
            }
        };

        Ok(Self {
            shared,
            worker: Some(worker),
        })
    }

    pub fn send_packet(
        &self,
        packet: &FfiPacket,
        controls: &[FfiControlMessage],
    ) -> Result<(), String> {
        let payload = ffi_slice(packet.payload)?;
        let controls = encode_controls(controls)?;
        let total = HEADER_LENGTH
            .checked_add(DATA_HEADER_LENGTH)
            .and_then(|length| length.checked_add(payload.len()))
            .and_then(|length| length.checked_add(controls.len()))
            .ok_or_else(|| "boundary packet length overflow".to_string())?;
        if total > MAX_MESSAGE_LENGTH || payload.len() > u32::MAX as usize {
            return Err("boundary packet exceeds protocol size limit".to_string());
        }
        let mut message = Vec::with_capacity(total);
        message.extend_from_slice(&DATA_MESSAGE.to_be_bytes());
        message.extend_from_slice(&(total as u32).to_be_bytes());
        message.extend_from_slice(&packet.info.source.to_be_bytes());
        message.extend_from_slice(&packet.info.destination.to_be_bytes());
        message.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        message.extend_from_slice(&(controls.len() as u32).to_be_bytes());
        message.push(packet.info.priority);
        message.extend_from_slice(payload);
        message.extend_from_slice(&controls);
        self.send(&message)
    }

    pub fn send_control(&self, controls: &[FfiControlMessage]) -> Result<(), String> {
        let controls = encode_controls(controls)?;
        let total = HEADER_LENGTH
            .checked_add(CONTROL_HEADER_LENGTH)
            .and_then(|length| length.checked_add(controls.len()))
            .ok_or_else(|| "boundary control-message length overflow".to_string())?;
        if total > MAX_MESSAGE_LENGTH {
            return Err("boundary control message exceeds protocol size limit".to_string());
        }
        let mut message = Vec::with_capacity(total);
        message.extend_from_slice(&CONTROL_MESSAGE.to_be_bytes());
        message.extend_from_slice(&(total as u32).to_be_bytes());
        message.extend_from_slice(&(controls.len() as u32).to_be_bytes());
        message.extend_from_slice(&controls);
        self.send(&message)
    }

    fn send(&self, data: &[u8]) -> Result<(), String> {
        if self.shared.cancel.load(Ordering::Acquire) {
            return Err("boundary endpoint is closed".to_string());
        }
        if let Some(socket) = self
            .shared
            .udp
            .lock()
            .map_err(|_| "UDP boundary lock poisoned".to_string())?
            .as_ref()
        {
            let sent = socket
                .send_to(data, self.shared.remote)
                .map_err(|error| format!("failed to send UDP boundary message: {error}"))?;
            return if sent == data.len() {
                Ok(())
            } else {
                Err(format!(
                    "short UDP boundary write: sent {sent} of {} bytes",
                    data.len()
                ))
            };
        }
        let mut stream = self
            .shared
            .tcp
            .lock()
            .map_err(|_| "TCP boundary lock poisoned".to_string())?;
        stream
            .as_mut()
            .ok_or_else(|| "TCP boundary endpoint is not connected".to_string())?
            .write_all(data)
            .map_err(|error| format!("failed to send TCP boundary message: {error}"))
    }

    pub fn close(&mut self) {
        self.shared.cancel.store(true, Ordering::Release);
        if let Ok(mut socket) = self.shared.udp.lock() {
            socket.take();
        }
        if let Ok(mut stream) = self.shared.tcp.lock() {
            if let Some(stream) = stream.take() {
                let _ = stream.shutdown(Shutdown::Both);
            }
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl Drop for BoundaryMessageManager {
    fn drop(&mut self) {
        self.close();
    }
}

fn resolve_address(endpoint: &str, description: &str) -> Result<SocketAddr, String> {
    endpoint
        .to_socket_addrs()
        .map_err(|error| format!("invalid {description} {endpoint}: {error}"))?
        .next()
        .ok_or_else(|| format!("{description} {endpoint} resolved to no addresses"))
}

fn resolve_address_for_family(
    endpoint: &str,
    ipv4: bool,
    description: &str,
) -> Result<SocketAddr, String> {
    endpoint
        .to_socket_addrs()
        .map_err(|error| format!("invalid {description} {endpoint}: {error}"))?
        .find(|address| address.is_ipv4() == ipv4)
        .ok_or_else(|| format!("{description} {endpoint} has no matching address family"))
}

fn ffi_slice(slice: FfiSlice) -> Result<&'static [u8], String> {
    if slice.len == 0 {
        return Ok(&[]);
    }
    if slice.data.is_null() {
        return Err("boundary message contains a null payload".to_string());
    }
    Ok(unsafe { std::slice::from_raw_parts(slice.data, slice.len) })
}

fn encode_controls(controls: &[FfiControlMessage]) -> Result<Vec<u8>, String> {
    if controls.len() > u16::MAX as usize {
        return Err("too many boundary control messages".to_string());
    }
    let mut data = vec![0, 0];
    let mut count = 0u16;
    for control in controls {
        let payload = ffi_slice(control.payload)?;
        let Some((message_type, payload)) =
            crate::legacy_controls::encode(control.msg_type, payload)?
        else {
            continue;
        };
        count += 1;
        if payload.len() > u16::MAX as usize {
            return Err(format!(
                "control message {message_type} exceeds legacy boundary size limit"
            ));
        }
        data.extend_from_slice(&message_type.to_be_bytes());
        data.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        data.extend_from_slice(&payload);
    }
    data[..2].copy_from_slice(&count.to_be_bytes());
    Ok(data)
}

fn decode_controls(mut data: &[u8]) -> Result<Vec<OwnedControlMessage>, String> {
    if data.len() < 2 {
        return Err("truncated boundary control-message count".to_string());
    }
    let count = u16::from_be_bytes([data[0], data[1]]) as usize;
    data = &data[2..];
    let mut controls = Vec::with_capacity(count);
    for _ in 0..count {
        if data.len() < 4 {
            return Err("truncated boundary control-message header".to_string());
        }
        let message_type = u16::from_be_bytes([data[0], data[1]]) as u32;
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;
        data = &data[4..];
        if data.len() < length {
            return Err("truncated boundary control-message payload".to_string());
        }
        let (message_type, payload) =
            crate::legacy_controls::decode(message_type as u16, &data[..length])
                .ok_or_else(|| format!("invalid legacy control {message_type}"))?;
        controls.push(OwnedControlMessage {
            message_type,
            payload,
        });
        data = &data[length..];
    }
    if !data.is_empty() {
        return Err("trailing bytes in boundary control-message payload".to_string());
    }
    Ok(controls)
}

fn decode_message(data: &[u8]) -> Result<BoundaryMessage, String> {
    if data.len() < HEADER_LENGTH {
        return Err("truncated boundary header".to_string());
    }
    let message_type = u16::from_be_bytes([data[0], data[1]]);
    let total = u32::from_be_bytes([data[2], data[3], data[4], data[5]]) as usize;
    if total != data.len() || total > MAX_MESSAGE_LENGTH {
        return Err("invalid boundary message length".to_string());
    }
    match message_type {
        DATA_MESSAGE => {
            if data.len() < HEADER_LENGTH + DATA_HEADER_LENGTH {
                return Err("truncated boundary packet header".to_string());
            }
            let header = &data[HEADER_LENGTH..HEADER_LENGTH + DATA_HEADER_LENGTH];
            let source = u16::from_be_bytes([header[0], header[1]]);
            let destination = u16::from_be_bytes([header[2], header[3]]);
            let payload_length =
                u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;
            let control_length =
                u32::from_be_bytes([header[8], header[9], header[10], header[11]]) as usize;
            let expected = HEADER_LENGTH
                .checked_add(DATA_HEADER_LENGTH)
                .and_then(|length| length.checked_add(payload_length))
                .and_then(|length| length.checked_add(control_length))
                .ok_or_else(|| "boundary packet length overflow".to_string())?;
            if expected != data.len() {
                return Err("boundary packet payload length mismatch".to_string());
            }
            let payload_start = HEADER_LENGTH + DATA_HEADER_LENGTH;
            let control_start = payload_start + payload_length;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default();
            Ok(BoundaryMessage::Packet(BoundaryPacket {
                info: FfiPacketInfo {
                    uuid: [0; 16],
                    source,
                    destination,
                    priority: header[12],
                    creation_time_sec: now.as_secs(),
                    creation_time_usec: now.subsec_micros(),
                },
                payload: data[payload_start..control_start].to_vec(),
                controls: decode_controls(&data[control_start..])?,
            }))
        }
        CONTROL_MESSAGE => {
            if data.len() < HEADER_LENGTH + CONTROL_HEADER_LENGTH {
                return Err("truncated boundary control header".to_string());
            }
            let length = u32::from_be_bytes([
                data[HEADER_LENGTH],
                data[HEADER_LENGTH + 1],
                data[HEADER_LENGTH + 2],
                data[HEADER_LENGTH + 3],
            ]) as usize;
            if HEADER_LENGTH + CONTROL_HEADER_LENGTH + length != data.len() {
                return Err("boundary control payload length mismatch".to_string());
            }
            Ok(BoundaryMessage::Control(decode_controls(
                &data[HEADER_LENGTH + CONTROL_HEADER_LENGTH..],
            )?))
        }
        _ => Err(format!("unknown boundary message type {message_type}")),
    }
}

fn dispatch(shared: &SharedState, data: &[u8]) {
    if let Ok(message) = decode_message(data) {
        (shared.handler)(message);
    }
}

fn receive_udp(shared: Arc<SharedState>, socket: UdpSocket) {
    let mut buffer = vec![0u8; u16::MAX as usize + 1];
    while !shared.cancel.load(Ordering::Acquire) {
        match socket.recv_from(&mut buffer) {
            Ok((length, _)) => dispatch(&shared, &buffer[..length]),
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(_) => break,
        }
    }
}

fn configure_stream(stream: &TcpStream) -> std::io::Result<()> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_millis(100)))
}

fn receive_stream(shared: &Arc<SharedState>, mut stream: TcpStream) {
    let mut received = Vec::new();
    let mut buffer = [0u8; 64 * 1024];
    while !shared.cancel.load(Ordering::Acquire) {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(length) => {
                received.extend_from_slice(&buffer[..length]);
                loop {
                    if received.len() < HEADER_LENGTH {
                        break;
                    }
                    let total =
                        u32::from_be_bytes([received[2], received[3], received[4], received[5]])
                            as usize;
                    if !(HEADER_LENGTH..=MAX_MESSAGE_LENGTH).contains(&total) {
                        return;
                    }
                    if received.len() < total {
                        break;
                    }
                    dispatch(shared, &received[..total]);
                    received.drain(..total);
                }
            }
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(_) => break,
        }
    }
}

fn set_active_stream(shared: &SharedState, stream: &TcpStream) -> bool {
    let Ok(clone) = stream.try_clone() else {
        return false;
    };
    let Ok(mut active) = shared.tcp.lock() else {
        return false;
    };
    active.replace(clone);
    true
}

fn clear_active_stream(shared: &SharedState) {
    if let Ok(mut active) = shared.tcp.lock() {
        active.take();
    }
}

fn receive_tcp_server(shared: Arc<SharedState>, listener: TcpListener) {
    while !shared.cancel.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _)) => {
                if configure_stream(&stream).is_ok() && set_active_stream(&shared, &stream) {
                    receive_stream(&shared, stream);
                    clear_active_stream(&shared);
                }
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(_) => break,
        }
    }
}

fn receive_tcp_client(shared: Arc<SharedState>) {
    while !shared.cancel.load(Ordering::Acquire) {
        match connect_tcp_client(shared.local, shared.remote) {
            Ok(stream) => {
                if configure_stream(&stream).is_ok() && set_active_stream(&shared, &stream) {
                    receive_stream(&shared, stream);
                    clear_active_stream(&shared);
                }
            }
            Err(_) => thread::sleep(Duration::from_millis(100)),
        }
    }
}

fn connect_tcp_client(local: SocketAddr, remote: SocketAddr) -> std::io::Result<TcpStream> {
    let domain = if local.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.bind(&local.into())?;
    socket.connect_timeout(&remote.into(), Duration::from_millis(200))?;
    Ok(socket.into())
}

pub fn with_ffi_messages<T>(
    controls: &[OwnedControlMessage],
    f: impl FnOnce(&[FfiControlMessage]) -> T,
) -> T {
    let messages = controls
        .iter()
        .map(|control| FfiControlMessage {
            msg_type: control.message_type,
            payload: FfiSlice {
                data: control.payload.as_ptr(),
                len: control.payload.len(),
            },
        })
        .collect::<Vec<_>>();
    f(&messages)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    fn packet(payload: &[u8]) -> FfiPacket {
        FfiPacket {
            info: FfiPacketInfo {
                uuid: [0; 16],
                source: 1,
                destination: 2,
                priority: 3,
                creation_time_sec: 0,
                creation_time_usec: 0,
            },
            payload: FfiSlice {
                data: payload.as_ptr(),
                len: payload.len(),
            },
        }
    }

    #[test]
    fn legacy_wire_round_trip() {
        let payload = b"payload";
        let control_payload = &emane_plugin_api::FlowControlToken { tokens: 10 }.encode();
        let control = FfiControlMessage {
            msg_type: emane_plugin_api::CONTROL_FLOW_CONTROL_TOKEN,
            payload: FfiSlice {
                data: control_payload.as_ptr(),
                len: control_payload.len(),
            },
        };
        let controls = encode_controls(&[control]).unwrap();
        let total = HEADER_LENGTH + DATA_HEADER_LENGTH + payload.len() + controls.len();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&DATA_MESSAGE.to_be_bytes());
        bytes.extend_from_slice(&(total as u32).to_be_bytes());
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes.extend_from_slice(&2u16.to_be_bytes());
        bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&(controls.len() as u32).to_be_bytes());
        bytes.push(3);
        bytes.extend_from_slice(payload);
        bytes.extend_from_slice(&controls);
        let BoundaryMessage::Packet(decoded) = decode_message(&bytes).unwrap() else {
            panic!("expected packet");
        };
        assert_eq!(decoded.info.source, 1);
        assert_eq!(decoded.info.destination, 2);
        assert_eq!(decoded.info.priority, 3);
        assert_eq!(decoded.payload, payload);
        assert_eq!(
            decoded.controls[0].message_type,
            emane_plugin_api::CONTROL_FLOW_CONTROL_TOKEN
        );
        assert_eq!(decoded.controls[0].payload, control_payload);
    }

    #[test]
    fn udp_endpoints_exchange_packets() {
        let first_socket = match UdpSocket::bind("127.0.0.1:0") {
            Ok(socket) => socket,
            Err(error) if error.kind() == ErrorKind::PermissionDenied => return,
            Err(error) => panic!("failed to create first UDP test socket: {error}"),
        };
        let first = first_socket.local_addr().unwrap();
        drop(first_socket);
        let second_socket = match UdpSocket::bind("127.0.0.1:0") {
            Ok(socket) => socket,
            Err(error) if error.kind() == ErrorKind::PermissionDenied => return,
            Err(error) => panic!("failed to create second UDP test socket: {error}"),
        };
        let second = second_socket.local_addr().unwrap();
        drop(second_socket);
        let (sender, receiver) = mpsc::channel();
        let mut platform = BoundaryMessageManager::open(
            &first.to_string(),
            &second.to_string(),
            BoundaryProtocol::Udp,
            move |message| {
                sender.send(message).unwrap();
            },
        )
        .unwrap();
        let mut transport = BoundaryMessageManager::open(
            &second.to_string(),
            &first.to_string(),
            BoundaryProtocol::Udp,
            |_| {},
        )
        .unwrap();
        let payload = b"hello";
        transport.send_packet(&packet(payload), &[]).unwrap();
        let BoundaryMessage::Packet(received) =
            receiver.recv_timeout(Duration::from_secs(2)).unwrap()
        else {
            panic!("expected packet");
        };
        assert_eq!(received.payload, payload);
        platform.close();
        transport.close();
    }

    #[test]
    fn tcp_endpoints_preserve_framing_and_exchange_packets() {
        let reservation = match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(error) if error.kind() == ErrorKind::PermissionDenied => return,
            Err(error) => panic!("failed to reserve TCP test endpoint: {error}"),
        };
        let server_address = reservation.local_addr().unwrap();
        drop(reservation);
        let (sender, receiver) = mpsc::channel();
        let mut platform = BoundaryMessageManager::open(
            &server_address.to_string(),
            "127.0.0.1:1",
            BoundaryProtocol::TcpServer,
            move |message| {
                sender.send(message).unwrap();
            },
        )
        .unwrap();
        let mut transport = BoundaryMessageManager::open(
            "127.0.0.1:0",
            &server_address.to_string(),
            BoundaryProtocol::TcpClient,
            |_| {},
        )
        .unwrap();
        let first = b"first";
        let second = b"second";
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            match transport.send_packet(&packet(first), &[]) {
                Ok(()) => break,
                Err(error)
                    if error.contains("not connected") && std::time::Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("failed to send TCP boundary packet: {error}"),
            }
        }
        transport.send_packet(&packet(second), &[]).unwrap();
        for expected in [first.as_slice(), second.as_slice()] {
            let BoundaryMessage::Packet(received) =
                receiver.recv_timeout(Duration::from_secs(2)).unwrap()
            else {
                panic!("expected packet");
            };
            assert_eq!(received.payload, expected);
        }
        platform.close();
        transport.close();
    }
}
