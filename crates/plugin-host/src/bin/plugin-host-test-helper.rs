// SPDX-License-Identifier: Apache-2.0
//! Deterministic worker used only by `tests/supervisor.rs`.

use jmeter_rs_bridge_protocol::{Frame, FrameCodec, HEADER_LEN, MessageKind};
use jmeter_rs_plugin_host::{CapabilityDeclarations, PluginResponse, decode_handshake};
use serde_json::Value;
#[cfg(target_os = "linux")]
use std::process::Command;
use std::{
    collections::BTreeMap,
    io::{self, Read, Write},
    process,
};

fn read_frame(reader: &mut impl Read, codec: &FrameCodec) -> io::Result<Frame> {
    let mut header = [0_u8; HEADER_LEN];
    reader.read_exact(&mut header)?;
    let metadata_len = u32::from_be_bytes(
        header[28..32]
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "metadata header"))?,
    ) as usize;
    let payload_len = u32::from_be_bytes(
        header[32..36]
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "payload header"))?,
    ) as usize;
    let mut bytes = header.to_vec();
    bytes.resize(HEADER_LEN + metadata_len + payload_len, 0);
    reader.read_exact(&mut bytes[HEADER_LEN..])?;
    codec
        .decode_exact(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
}

fn write_frame(writer: &mut impl Write, codec: &FrameCodec, frame: &Frame) -> io::Result<()> {
    let bytes = codec
        .encode(frame)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    writer.write_all(&bytes)?;
    writer.flush()
}

#[cfg(target_os = "linux")]
fn process_start_time(pid: u32) -> Option<u64> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let close = text.rfind(')')?;
    text.get(close + 2..)?
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

fn identity_metadata() -> BTreeMap<String, Value> {
    let mut metadata = BTreeMap::new();
    metadata.insert("worker_pid".to_owned(), Value::from(process::id()));
    #[cfg(target_os = "linux")]
    if let Some(start_time) = process_start_time(process::id()) {
        metadata.insert("worker_start_time".to_owned(), Value::from(start_time));
    }
    metadata
}

fn main() -> io::Result<()> {
    let mode = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "normal".to_owned());
    let mut stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();
    let codec = FrameCodec::default();
    let hello = read_frame(&mut stdin, &codec)?;
    let hello_bytes = codec
        .encode(&hello)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    let mut info = decode_handshake(&codec, &hello_bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    match mode.as_str() {
        "protocol" => {
            info.protocol.min = 2;
            info.protocol.max = 2;
        }
        "profile" => info.profiles = vec!["other-profile".to_owned()],
        "capability" => info.capabilities = CapabilityDeclarations::default(),
        "preservation" => info.preservation.raw_subtree = false,
        _ => {}
    }
    let payload = serde_json::to_vec(&info)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    let capabilities = info
        .capabilities
        .iter()
        .map(|(_, declaration)| declaration.id.clone())
        .collect();
    let handshake = Frame {
        payload,
        ..Frame::handshake(0, info.profiles[0].clone(), capabilities)
    };
    let handshake_bytes = codec
        .encode(&handshake)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    if mode == "partial" {
        stdout.write_all(&handshake_bytes[..handshake_bytes.len().min(8)])?;
        stdout.flush()?;
        return Ok(());
    }
    write_frame(&mut stdout, &codec, &handshake)?;
    #[cfg(target_os = "linux")]
    let mut grandchild = None;
    if mode == "grandchild" {
        #[cfg(target_os = "linux")]
        {
            let child = Command::new("/bin/sleep").arg("60").spawn()?;
            grandchild = Some(child);
        }
    }
    if mode == "no-read" {
        loop {
            std::hint::spin_loop();
        }
    }
    let _request = read_frame(&mut stdin, &codec)?;
    if mode == "crash" {
        process::exit(7);
    }
    if mode == "oversize" {
        let bytes = vec![b'x'; 2 * 1024 * 1024];
        let mut stderr = io::stderr().lock();
        stderr.write_all(&bytes)?;
        stderr.flush()?;
        loop {
            std::hint::spin_loop();
        }
    }
    if mode == "timeout" {
        loop {
            std::hint::spin_loop();
        }
    }
    #[cfg(target_os = "linux")]
    let mut metadata = identity_metadata();
    #[cfg(not(target_os = "linux"))]
    let metadata = identity_metadata();
    #[cfg(target_os = "linux")]
    if let Some(child) = grandchild.as_ref() {
        metadata.insert("grandchild_pid".to_owned(), Value::from(child.id()));
        if let Some(start_time) = process_start_time(child.id()) {
            metadata.insert("grandchild_start_time".to_owned(), Value::from(start_time));
        }
    }
    let response = PluginResponse {
        output: b"ok".to_vec(),
        metadata,
    };
    let response_payload = serde_json::to_vec(&response)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    write_frame(
        &mut stdout,
        &codec,
        &Frame::new(MessageKind::Response, 1, response_payload),
    )?;
    if mode == "cleanup" || mode == "grandchild" {
        loop {
            std::hint::spin_loop();
        }
    }
    Ok(())
}
