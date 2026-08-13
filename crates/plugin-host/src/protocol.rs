// SPDX-License-Identifier: Apache-2.0

use crate::{
    error::{PluginError, PluginErrorCode},
    manifest::{
        CapabilityDeclarations, CapabilityReference, PluginId, PluginManifest, PluginRequest,
        PluginResponse, PluginVersion, PreservationContract, ProtocolRange,
    },
};
use jmeter_rs_bridge_protocol::{
    Cancellation, DecodeError, EncodeError, Frame, FrameCodec, MessageKind, PROTOCOL_VERSION,
    RemoteErrorCode,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const MAX_PROTOCOL_JSON_DEPTH: usize = 32;
const MAX_PROTOCOL_JSON_FIELDS: usize = 16 * 1024;
const MAX_PROTOCOL_JSON_ARRAY_ITEMS: usize = 1024 * 1024;
const MAX_PROTOCOL_JSON_STRING_BYTES: usize = 8 * 1024 * 1024;
const MAX_PROTOCOL_JSON_AGGREGATE_STRING_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JsonPreflightError {
    Limit(&'static str),
    Malformed(&'static str),
}

struct JsonScanner<'a> {
    input: &'a [u8],
    offset: usize,
    depth: usize,
    fields: usize,
    array_items: usize,
    string_bytes: usize,
    maximum: usize,
}

impl<'a> JsonScanner<'a> {
    fn new(input: &'a [u8], maximum: usize) -> Self {
        Self {
            input,
            offset: 0,
            depth: 0,
            fields: 0,
            array_items: 0,
            string_bytes: 0,
            maximum,
        }
    }

    fn scan(mut self) -> Result<(), JsonPreflightError> {
        if self.input.len() > self.maximum {
            return Err(JsonPreflightError::Limit(
                "JSON payload exceeds its byte budget",
            ));
        }
        self.skip_whitespace();
        self.value()?;
        self.skip_whitespace();
        if self.offset != self.input.len() {
            return Err(JsonPreflightError::Malformed(
                "JSON payload has trailing bytes",
            ));
        }
        Ok(())
    }

    fn value(&mut self) -> Result<(), JsonPreflightError> {
        self.skip_whitespace();
        let Some(byte) = self.input.get(self.offset).copied() else {
            return Err(JsonPreflightError::Malformed("JSON value is incomplete"));
        };
        match byte {
            b'{' => self.object(),
            b'[' => self.array(),
            b'"' => self.string().map(|_| ()),
            b't' => self.literal(b"true"),
            b'f' => self.literal(b"false"),
            b'n' => self.literal(b"null"),
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err(JsonPreflightError::Malformed(
                "JSON value has an invalid token",
            )),
        }
    }

    fn object(&mut self) -> Result<(), JsonPreflightError> {
        self.enter()?;
        self.offset += 1;
        self.skip_whitespace();
        if self.consume(b'}') {
            self.leave();
            return Ok(());
        }
        // Keep bounded decoded keys so escaped-equivalent names cannot be
        // last-write-wins collapsed by serde maps, including keys carried by
        // flattened extension maps.
        let mut keys: Vec<Vec<u8>> = Vec::new();
        loop {
            if self.fields >= MAX_PROTOCOL_JSON_FIELDS {
                return Err(JsonPreflightError::Limit(
                    "JSON object field count exceeds its bound",
                ));
            }
            if self.input.get(self.offset) != Some(&b'"') {
                return Err(JsonPreflightError::Malformed(
                    "JSON object key must be a string",
                ));
            }
            let key_start = self.offset;
            let _ = self.string()?;
            let key_end = self.offset;
            let key = Self::decode_json_key(&self.input[key_start..key_end])?;
            if keys.iter().any(|existing| existing == &key) {
                return Err(JsonPreflightError::Malformed(
                    "JSON object contains a duplicate key",
                ));
            }
            keys.push(key);
            self.fields += 1;
            self.skip_whitespace();
            if !self.consume(b':') {
                return Err(JsonPreflightError::Malformed(
                    "JSON object key is missing a colon",
                ));
            }
            self.value()?;
            self.skip_whitespace();
            if self.consume(b'}') {
                self.leave();
                return Ok(());
            }
            if !self.consume(b',') {
                return Err(JsonPreflightError::Malformed(
                    "JSON object is missing a comma",
                ));
            }
            self.skip_whitespace();
        }
    }

    fn array(&mut self) -> Result<(), JsonPreflightError> {
        self.enter()?;
        self.offset += 1;
        self.skip_whitespace();
        if self.consume(b']') {
            self.leave();
            return Ok(());
        }
        loop {
            if self.array_items >= MAX_PROTOCOL_JSON_ARRAY_ITEMS {
                return Err(JsonPreflightError::Limit(
                    "JSON array item count exceeds its bound",
                ));
            }
            self.array_items += 1;
            self.value()?;
            self.skip_whitespace();
            if self.consume(b']') {
                self.leave();
                return Ok(());
            }
            if !self.consume(b',') {
                return Err(JsonPreflightError::Malformed(
                    "JSON array is missing a comma",
                ));
            }
            self.skip_whitespace();
        }
    }

    fn string(&mut self) -> Result<usize, JsonPreflightError> {
        if !self.consume(b'"') {
            return Err(JsonPreflightError::Malformed(
                "JSON string is missing a quote",
            ));
        }
        let start = self.offset;
        loop {
            let Some(byte) = self.input.get(self.offset).copied() else {
                return Err(JsonPreflightError::Malformed("JSON string is incomplete"));
            };
            match byte {
                b'"' => {
                    let length = self.offset.saturating_sub(start);
                    self.offset += 1;
                    if length > MAX_PROTOCOL_JSON_STRING_BYTES {
                        return Err(JsonPreflightError::Limit(
                            "JSON string exceeds its field bound",
                        ));
                    }
                    self.string_bytes =
                        self.string_bytes
                            .checked_add(length)
                            .ok_or(JsonPreflightError::Limit(
                                "JSON string aggregate exceeds its bound",
                            ))?;
                    if self.string_bytes
                        > MAX_PROTOCOL_JSON_AGGREGATE_STRING_BYTES.min(self.maximum)
                    {
                        return Err(JsonPreflightError::Limit(
                            "JSON string aggregate exceeds its bound",
                        ));
                    }
                    return Ok(length);
                }
                b'\\' => {
                    self.offset += 1;
                    let Some(escape) = self.input.get(self.offset).copied() else {
                        return Err(JsonPreflightError::Malformed("JSON escape is incomplete"));
                    };
                    if escape == b'u' {
                        self.offset += 1;
                        for _ in 0..4 {
                            let Some(hex) = self.input.get(self.offset).copied() else {
                                return Err(JsonPreflightError::Malformed(
                                    "JSON unicode escape is incomplete",
                                ));
                            };
                            if !hex.is_ascii_hexdigit() {
                                return Err(JsonPreflightError::Malformed(
                                    "JSON unicode escape is invalid",
                                ));
                            }
                            self.offset += 1;
                        }
                    } else if matches!(
                        escape,
                        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't'
                    ) {
                        self.offset += 1;
                    } else {
                        return Err(JsonPreflightError::Malformed("JSON escape is invalid"));
                    }
                }
                0..=0x1f => {
                    return Err(JsonPreflightError::Malformed(
                        "JSON string contains a control byte",
                    ));
                }
                _ => self.offset += 1,
            }
        }
    }

    fn decode_json_key(encoded: &[u8]) -> Result<Vec<u8>, JsonPreflightError> {
        if encoded.first() != Some(&b'"') || encoded.last() != Some(&b'"') {
            return Err(JsonPreflightError::Malformed(
                "JSON object key is not a complete string",
            ));
        }
        let mut decoded = Vec::with_capacity(encoded.len().saturating_sub(2));
        let mut offset = 1;
        while offset < encoded.len() {
            let byte = encoded[offset];
            offset += 1;
            match byte {
                b'\\' => {
                    let Some(escape) = encoded.get(offset).copied() else {
                        return Err(JsonPreflightError::Malformed(
                            "JSON key escape is incomplete",
                        ));
                    };
                    offset += 1;
                    match escape {
                        b'"' | b'\\' | b'/' => decoded.push(escape),
                        b'b' => decoded.push(0x08),
                        b'f' => decoded.push(0x0c),
                        b'n' => decoded.push(b'\n'),
                        b'r' => decoded.push(b'\r'),
                        b't' => decoded.push(b'\t'),
                        b'u' => {
                            let high = Self::decode_json_code_unit(encoded, &mut offset)?;
                            let codepoint = if (0xd800..=0xdbff).contains(&high) {
                                if encoded.get(offset..offset.saturating_add(2)) != Some(b"\\u") {
                                    return Err(JsonPreflightError::Malformed(
                                        "JSON key has an unpaired high surrogate",
                                    ));
                                }
                                offset += 2;
                                let low = Self::decode_json_code_unit(encoded, &mut offset)?;
                                if !(0xdc00..=0xdfff).contains(&low) {
                                    return Err(JsonPreflightError::Malformed(
                                        "JSON key has an invalid surrogate pair",
                                    ));
                                }
                                0x1_0000
                                    + (u32::from(high - 0xd800) << 10)
                                    + u32::from(low - 0xdc00)
                            } else if (0xdc00..=0xdfff).contains(&high) {
                                return Err(JsonPreflightError::Malformed(
                                    "JSON key has an unpaired low surrogate",
                                ));
                            } else {
                                u32::from(high)
                            };
                            let Some(character) = char::from_u32(codepoint) else {
                                return Err(JsonPreflightError::Malformed(
                                    "JSON key has an invalid Unicode scalar",
                                ));
                            };
                            let mut buffer = [0_u8; 4];
                            decoded
                                .extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
                        }
                        _ => {
                            return Err(JsonPreflightError::Malformed(
                                "JSON key escape is invalid",
                            ));
                        }
                    }
                }
                b'"' => {
                    if offset != encoded.len() {
                        return Err(JsonPreflightError::Malformed(
                            "JSON object key has trailing bytes",
                        ));
                    }
                    if std::str::from_utf8(&decoded).is_err() {
                        return Err(JsonPreflightError::Malformed("JSON key is not valid UTF-8"));
                    }
                    return Ok(decoded);
                }
                _ => decoded.push(byte),
            }
        }
        Err(JsonPreflightError::Malformed("JSON key is incomplete"))
    }

    fn decode_json_code_unit(
        encoded: &[u8],
        offset: &mut usize,
    ) -> Result<u16, JsonPreflightError> {
        let end = offset
            .checked_add(4)
            .ok_or(JsonPreflightError::Malformed("JSON key escape overflows"))?;
        let Some(bytes) = encoded.get(*offset..end) else {
            return Err(JsonPreflightError::Malformed(
                "JSON key Unicode escape is incomplete",
            ));
        };
        let mut code_unit = 0_u16;
        for byte in bytes {
            let value = match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => {
                    return Err(JsonPreflightError::Malformed(
                        "JSON key Unicode escape is invalid",
                    ));
                }
            };
            code_unit = (code_unit << 4) | u16::from(value);
        }
        *offset = end;
        Ok(code_unit)
    }

    fn literal(&mut self, literal: &[u8]) -> Result<(), JsonPreflightError> {
        let end = self
            .offset
            .checked_add(literal.len())
            .ok_or(JsonPreflightError::Malformed("JSON literal overflows"))?;
        if self.input.get(self.offset..end) != Some(literal) {
            return Err(JsonPreflightError::Malformed("JSON literal is invalid"));
        }
        self.offset = end;
        Ok(())
    }

    fn number(&mut self) -> Result<(), JsonPreflightError> {
        let start = self.offset;
        while let Some(byte) = self.input.get(self.offset).copied() {
            if matches!(byte, b',' | b']' | b'}' | b' ' | b'\n' | b'\r' | b'\t') {
                break;
            }
            self.offset += 1;
        }
        if self.offset == start {
            return Err(JsonPreflightError::Malformed("JSON number is incomplete"));
        }
        Ok(())
    }

    fn enter(&mut self) -> Result<(), JsonPreflightError> {
        if self.depth >= MAX_PROTOCOL_JSON_DEPTH {
            return Err(JsonPreflightError::Limit("JSON nesting exceeds its bound"));
        }
        self.depth += 1;
        Ok(())
    }

    fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn consume(&mut self, expected: u8) -> bool {
        if self.input.get(self.offset) == Some(&expected) {
            self.offset += 1;
            true
        } else {
            false
        }
    }

    fn skip_whitespace(&mut self) {
        while self
            .input
            .get(self.offset)
            .is_some_and(|byte| matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
        {
            self.offset += 1;
        }
    }
}

/// Checks JSON structure and resource bounds without constructing a serde
/// value.  Discovery uses the same scanner before deserializing manifests.
pub(crate) fn preflight_json(bytes: &[u8], maximum: usize) -> Result<(), PluginError> {
    JsonScanner::new(bytes, maximum)
        .scan()
        .map_err(|error| match error {
            JsonPreflightError::Limit(detail) => {
                PluginError::new(PluginErrorCode::WorkerMessageLimit, detail)
            }
            JsonPreflightError::Malformed(detail) => {
                PluginError::new(PluginErrorCode::WorkerProtocol, detail)
            }
        })
}

struct JsonBudgetWriter {
    written: usize,
    maximum: usize,
    exceeded: bool,
}

impl std::io::Write for JsonBudgetWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let next = self.written.saturating_add(bytes.len());
        if next > self.maximum {
            self.exceeded = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "JSON payload budget exceeded",
            ));
        }
        self.written = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn preflight_serialized_json<T: Serialize>(value: &T, maximum: usize) -> Result<(), PluginError> {
    let mut writer = JsonBudgetWriter {
        written: 0,
        maximum,
        exceeded: false,
    };
    match serde_json::to_writer(&mut writer, value) {
        Ok(()) => Ok(()),
        Err(_error) if writer.exceeded => Err(PluginError::new(
            PluginErrorCode::WorkerMessageLimit,
            "JSON payload exceeds its message budget",
        )),
        Err(_error) => Err(PluginError::new(
            PluginErrorCode::WorkerProtocol,
            "could not encode JSON payload",
        )),
    }
}

fn map_encode_error(error: EncodeError, context: &str) -> PluginError {
    let code = match &error {
        EncodeError::PayloadTooLarge { .. }
        | EncodeError::MetadataTooLarge { .. }
        | EncodeError::ProfileTooLong { .. }
        | EncodeError::TooManyCapabilities { .. }
        | EncodeError::CapabilityTooLong { .. }
        | EncodeError::ErrorMessageTooLong { .. }
        | EncodeError::FrameTooLarge { .. }
        | EncodeError::CapabilityBytesTooLarge { .. }
        | EncodeError::InvalidLimits(_) => PluginErrorCode::WorkerMessageLimit,
        EncodeError::EmptyProfile
        | EncodeError::EmptyCapability { .. }
        | EncodeError::InvalidFrame(_)
        | EncodeError::LengthOverflow
        | EncodeError::ReservedRemoteErrorCode { .. }
        | EncodeError::DuplicateCapability { .. }
        | EncodeError::Handshake(_) => PluginErrorCode::WorkerProtocol,
    };
    PluginError::new(code, format!("{context}: {error}"))
}

fn validate_operation_request_id(request_id: u64) -> Result<(), PluginError> {
    if request_id == 0 {
        return Err(PluginError::new(
            PluginErrorCode::WorkerRequestMismatch,
            "plugin operation request ID must be non-zero",
        ));
    }
    Ok(())
}

/// Handshake identity and capabilities exchanged by a plugin worker.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandshakeInfo {
    /// Stable plugin ID.
    pub plugin_id: PluginId,
    /// Stable plugin release version.
    pub plugin_version: PluginVersion,
    /// Protocol versions supported by the worker.
    pub protocol: ProtocolRange,
    /// Compatibility profiles supported by the worker.
    pub profiles: Vec<String>,
    /// Element/function declarations supported by the worker.
    pub capabilities: CapabilityDeclarations,
    /// Unknown JMX preservation contract.
    pub preservation: PreservationContract,
}

impl HandshakeInfo {
    fn validate(&self) -> Result<(), PluginError> {
        PluginId::parse(self.plugin_id.as_str().to_owned())?;
        PluginVersion::parse(self.plugin_version.as_str().to_owned())?;
        self.protocol.validate()?;
        if self.profiles.is_empty() {
            return Err(PluginError::new(
                PluginErrorCode::ProtocolMismatch,
                "worker handshake declares no compatibility profiles",
            ));
        }
        let mut profiles = BTreeSet::new();
        for profile in &self.profiles {
            // Profile IDs share the host's bounded ASCII identifier grammar;
            // rejecting malformed or repeated entries keeps selection
            // deterministic and prevents an identity handshake from
            // advertising ambiguous aliases.
            PluginId::parse(profile.clone())?;
            if !profiles.insert(profile) {
                return Err(PluginError::new(
                    PluginErrorCode::ProtocolMismatch,
                    "worker handshake declares a duplicate compatibility profile",
                ));
            }
        }
        self.capabilities.validate()?;
        self.preservation.validate()
    }
}

/// Creates the first framed handshake bytes for a manifest.
pub fn encode_handshake(
    codec: &FrameCodec,
    manifest: &PluginManifest,
) -> Result<Vec<u8>, PluginError> {
    manifest.validate()?;
    let info = manifest.handshake_info();
    preflight_serialized_json(&info, codec.limits().max_payload_len)?;
    let payload = serde_json::to_vec(&info).map_err(|error| {
        PluginError::new(
            PluginErrorCode::WorkerProtocol,
            format!("could not encode plugin handshake: {error}"),
        )
    })?;
    let profile = info.profiles.first().cloned().ok_or_else(|| {
        PluginError::new(PluginErrorCode::ManifestInvalid, "no profile in manifest")
    })?;
    let capabilities = info
        .capabilities
        .iter()
        .map(|(_, declaration)| declaration.id.clone())
        .collect();
    let mut capability_ids = BTreeSet::new();
    for capability in &capabilities {
        if !capability_ids.insert(capability) {
            return Err(PluginError::new(
                PluginErrorCode::ManifestInvalid,
                "element and function capability IDs must be unique in handshake metadata",
            ));
        }
    }
    let frame = Frame::handshake(0, profile, capabilities).with_profile(info.profiles[0].clone());
    let frame = Frame { payload, ..frame };
    codec
        .encode(&frame)
        .map_err(|error| map_encode_error(error, "could not encode plugin handshake"))
}

/// Decodes a complete bridge handshake frame for a worker implementation or
/// deterministic fixture.
pub fn decode_handshake(codec: &FrameCodec, bytes: &[u8]) -> Result<HandshakeInfo, PluginError> {
    let frame = codec.decode_exact(bytes).map_err(decode_error)?;
    decode_handshake_frame_with_limit(&frame, codec.limits().max_payload_len)
}

/// Validates an already decoded worker handshake frame.
pub(crate) fn decode_handshake_frame(frame: &Frame) -> Result<HandshakeInfo, PluginError> {
    decode_handshake_frame_with_limit(frame, crate::manifest::HARD_MAX_MESSAGE_BYTES)
}

fn decode_handshake_frame_with_limit(
    frame: &Frame,
    maximum: usize,
) -> Result<HandshakeInfo, PluginError> {
    if frame.kind != MessageKind::Handshake {
        return Err(PluginError::new(
            PluginErrorCode::WorkerProtocol,
            format!("expected handshake frame, got {}", frame.kind),
        ));
    }
    if frame.request_id != 0 {
        return Err(PluginError::new(
            PluginErrorCode::WorkerRequestMismatch,
            "worker handshake request ID must be zero",
        ));
    }
    if frame.cancellation != Cancellation::None {
        return Err(PluginError::new(
            PluginErrorCode::WorkerProtocol,
            "worker handshake carries an invalid cancellation state",
        ));
    }
    let Some(frame_profile) = frame.profile.as_ref() else {
        return Err(PluginError::new(
            PluginErrorCode::WorkerProtocol,
            "worker handshake is missing profile metadata",
        ));
    };
    preflight_json(&frame.payload, maximum)?;
    let info: HandshakeInfo = serde_json::from_slice(&frame.payload).map_err(|error| {
        PluginError::new(
            PluginErrorCode::WorkerProtocol,
            format!("invalid worker handshake payload: {error}"),
        )
    })?;
    info.validate()?;
    if !info.profiles.iter().any(|item| item == frame_profile) {
        return Err(PluginError::new(
            PluginErrorCode::WorkerProtocol,
            "worker handshake profile metadata disagrees with payload",
        ));
    }
    let advertised_capabilities = info
        .capabilities
        .iter()
        .map(|(_, declaration)| declaration.id.clone())
        .collect::<Vec<_>>();
    let mut capability_ids = BTreeSet::new();
    for capability in &advertised_capabilities {
        if !capability_ids.insert(capability) {
            return Err(PluginError::new(
                PluginErrorCode::WorkerProtocol,
                "worker handshake has duplicate capability IDs in frame metadata",
            ));
        }
    }
    if frame.capabilities != advertised_capabilities {
        return Err(PluginError::new(
            PluginErrorCode::WorkerProtocol,
            "worker handshake capability metadata disagrees with payload",
        ));
    }
    Ok(info)
}

/// Checks a worker response against the installed manifest and requested JMX
/// capability.
pub(crate) fn negotiate_worker(
    expected: &PluginManifest,
    worker: &HandshakeInfo,
    profile: &str,
    capability: &CapabilityReference,
) -> Result<(), PluginError> {
    if worker.plugin_id != expected.id || worker.plugin_version != expected.version {
        return Err(PluginError::new(
            PluginErrorCode::ProtocolMismatch,
            "worker identity does not match its installed manifest",
        ));
    }
    if !expected.protocol.overlaps(worker.protocol)
        || !expected.protocol.supports(u16::from(PROTOCOL_VERSION))
        || !worker.protocol.supports(u16::from(PROTOCOL_VERSION))
    {
        return Err(PluginError::new(
            PluginErrorCode::ProtocolMismatch,
            "worker protocol range does not support bridge protocol version 1",
        ));
    }
    if !expected.supports_profile(profile) || !worker.profiles.iter().any(|item| item == profile) {
        return Err(PluginError::new(
            PluginErrorCode::ProfileMismatch,
            format!("plugin does not support compatibility profile {profile}"),
        ));
    }
    if worker.preservation != expected.preservation {
        return Err(PluginError::new(
            PluginErrorCode::CapabilityMismatch,
            "worker unknown-JMX preservation contract differs from its installed manifest",
        ));
    }
    let Some(expected_capability) = expected.find_capability(capability) else {
        return Err(PluginError::new(
            PluginErrorCode::CapabilityMismatch,
            format!(
                "manifest does not declare {} capability {}",
                capability.kind.as_str(),
                capability.name
            ),
        ));
    };
    let Some(worker_capability) = worker.capabilities.find(capability.kind, &capability.name)
    else {
        return Err(PluginError::new(
            PluginErrorCode::CapabilityMismatch,
            format!(
                "worker does not advertise {} capability {}",
                capability.kind.as_str(),
                capability.name
            ),
        ));
    };
    if worker_capability.id != expected_capability.id {
        return Err(PluginError::new(
            PluginErrorCode::CapabilityMismatch,
            "worker capability alias resolves to a different canonical ID",
        ));
    }
    Ok(())
}

/// Encodes a bounded plugin request payload.
pub(crate) fn encode_request(
    codec: &FrameCodec,
    request: &PluginRequest,
) -> Result<Vec<u8>, PluginError> {
    request.validate_for_message_limit(codec.limits().max_payload_len)?;
    let payload = serde_json::to_vec(request).map_err(|error| {
        PluginError::new(
            PluginErrorCode::InvalidJmx,
            format!("could not encode plugin request: {error}"),
        )
    })?;
    if payload.len() > codec.limits().max_payload_len {
        return Err(PluginError::new(
            PluginErrorCode::WorkerMessageLimit,
            "plugin request exceeds the manifest message limit",
        ));
    }
    Ok(payload)
}

/// Encodes a response frame for a worker fixture or test helper.
pub fn encode_response(
    codec: &FrameCodec,
    request_id: u64,
    response: &PluginResponse,
) -> Result<Vec<u8>, PluginError> {
    validate_operation_request_id(request_id)?;
    preflight_serialized_json(response, codec.limits().max_payload_len)?;
    let payload = serde_json::to_vec(response).map_err(|error| {
        PluginError::new(
            PluginErrorCode::WorkerProtocol,
            format!("could not encode plugin response: {error}"),
        )
    })?;
    let frame = Frame::new(MessageKind::Response, request_id, payload);
    codec
        .encode(&frame)
        .map_err(|error| map_encode_error(error, "could not encode plugin response"))
}

/// Decodes a successful plugin response frame.
pub(crate) fn decode_response(
    codec: &FrameCodec,
    frame: &Frame,
    request_id: u64,
) -> Result<PluginResponse, PluginError> {
    validate_operation_request_id(request_id)?;
    if frame.request_id != request_id {
        return Err(PluginError::new(
            PluginErrorCode::WorkerRequestMismatch,
            format!(
                "expected response for request {request_id}, got {}",
                frame.request_id
            ),
        ));
    }
    let invalid_cancellation = match frame.kind {
        MessageKind::Response => frame.cancellation == Cancellation::Requested,
        MessageKind::Error => frame.cancellation != Cancellation::None,
        _ => false,
    };
    if frame.profile.is_some() || !frame.capabilities.is_empty() || invalid_cancellation {
        return Err(PluginError::new(
            PluginErrorCode::WorkerProtocol,
            "worker response carries metadata or cancellation not allowed for responses",
        ));
    }
    match frame.kind {
        MessageKind::Response => {
            preflight_json(&frame.payload, codec.limits().max_payload_len)?;
            serde_json::from_slice(&frame.payload).map_err(|error| {
                PluginError::new(
                    PluginErrorCode::WorkerProtocol,
                    format!("invalid plugin response payload: {error}"),
                )
            })
        }
        MessageKind::Error => {
            let remote = codec.decode_remote_error(frame).map_err(|error| {
                PluginError::new(
                    PluginErrorCode::WorkerProtocol,
                    format!("invalid plugin error payload: {error}"),
                )
            })?;
            Err(map_remote_error(remote.code, remote.message))
        }
        kind => Err(PluginError::new(
            PluginErrorCode::WorkerProtocol,
            format!("unexpected worker frame kind {kind}"),
        )),
    }
}

/// Maps a structured bridge error to the host's stable taxonomy.
pub(crate) fn map_remote_error(code: RemoteErrorCode, _message: String) -> PluginError {
    let host_code = match code {
        RemoteErrorCode::CapabilityUnavailable => PluginErrorCode::CapabilityMismatch,
        RemoteErrorCode::ProfileMismatch => PluginErrorCode::ProfileMismatch,
        RemoteErrorCode::UnsupportedVersion | RemoteErrorCode::UnsupportedMessageKind => {
            PluginErrorCode::ProtocolMismatch
        }
        RemoteErrorCode::WorkerUnavailable => PluginErrorCode::PluginUnavailable,
        RemoteErrorCode::WorkerCrashed => PluginErrorCode::WorkerCrashed,
        RemoteErrorCode::WorkerLimitExceeded => PluginErrorCode::WorkerResourceLimit,
        RemoteErrorCode::DeadlineExceeded => PluginErrorCode::WorkerTimeout,
        RemoteErrorCode::Cancelled => PluginErrorCode::WorkerCancelled,
        RemoteErrorCode::ProtocolViolation => PluginErrorCode::WorkerProtocol,
        RemoteErrorCode::InvalidRequest | RemoteErrorCode::InvalidPayload => {
            PluginErrorCode::InvalidJmx
        }
        RemoteErrorCode::Internal | RemoteErrorCode::Unknown(_) => PluginErrorCode::WorkerRejected,
    };
    PluginError::new(
        host_code,
        "worker returned a structured error; diagnostic text redacted",
    )
}

/// Maps bridge decoder failures while preserving the message-limit boundary.
pub(crate) fn decode_error(error: DecodeError) -> PluginError {
    let detail = error.to_string();
    let code = match &error {
        DecodeError::PayloadTooLarge { .. }
        | DecodeError::MetadataTooLarge { .. }
        | DecodeError::ProfileTooLong { .. }
        | DecodeError::TooManyCapabilities { .. }
        | DecodeError::CapabilityTooLong { .. }
        | DecodeError::FrameTooLarge { .. }
        | DecodeError::ErrorPayloadTooLarge { .. }
        | DecodeError::CapabilityBytesTooLarge { .. }
        | DecodeError::InvalidLimits(_) => PluginErrorCode::WorkerMessageLimit,
        _ => PluginErrorCode::WorkerProtocol,
    };
    PluginError::new(code, detail)
}

/// Attempts to pull one complete frame from a caller-owned bounded buffer.
pub(crate) fn decode_next_frame(
    codec: &FrameCodec,
    buffer: &mut Vec<u8>,
) -> Result<Option<Frame>, PluginError> {
    let mut input = buffer.as_slice();
    let decoded = codec.decode_next(&mut input).map_err(decode_error)?;
    let consumed = buffer.len().saturating_sub(input.len());
    if consumed > 0 {
        buffer.drain(..consumed);
    }
    Ok(decoded)
}

/// Builds a cancellation frame for an outstanding request.
pub(crate) fn cancellation_frame(
    codec: &FrameCodec,
    request_id: u64,
) -> Result<Vec<u8>, PluginError> {
    validate_operation_request_id(request_id)?;
    let frame = Frame::new(MessageKind::Cancel, request_id, Vec::new())
        .with_cancellation(Cancellation::Requested);
    codec
        .encode(&frame)
        .map_err(|error| map_encode_error(error, "could not encode cancellation frame"))
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "protocol tests assert deterministic fixture construction"
)]
mod tests {
    use super::*;
    use crate::manifest::{
        CapabilityDeclaration, CapabilityKind, CapabilityReference, JmxElementMetadata, PluginId,
        PluginVersion, ResourceLimits, UnknownJmxProperty,
    };
    use std::collections::BTreeMap;

    fn manifest() -> PluginManifest {
        let mut manifest = PluginManifest::new(
            PluginId::parse("example.plugin").expect("plugin ID"),
            PluginVersion::parse("1.0.0").expect("version"),
            "/tmp/example-plugin",
        );
        manifest.profiles = vec!["jmeter-5.6.3".to_owned()];
        manifest.capabilities.elements = vec![CapabilityDeclaration::new("example.element")];
        manifest.limits = ResourceLimits::default();
        manifest
    }

    #[test]
    fn handshake_round_trip_and_worker_negotiation_are_explicit() {
        let manifest = manifest();
        let codec = FrameCodec::new(manifest.limits.max_message_bytes);
        let bytes = encode_handshake(&codec, &manifest).expect("handshake encodes");
        let decoded = decode_handshake(&codec, &bytes).expect("handshake decodes");
        assert_eq!(decoded, manifest.handshake_info());
        negotiate_worker(
            &manifest,
            &decoded,
            "jmeter-5.6.3",
            &CapabilityReference::new(CapabilityKind::Element, "example.element"),
        )
        .expect("worker negotiates");
    }

    #[test]
    fn handshake_mismatch_has_stable_protocol_profile_and_capability_codes() {
        let manifest = manifest();
        let mut worker = manifest.handshake_info();
        worker.protocol = ProtocolRange { min: 2, max: 2 };
        assert_eq!(
            negotiate_worker(
                &manifest,
                &worker,
                "jmeter-5.6.3",
                &CapabilityReference::new(CapabilityKind::Element, "example.element"),
            )
            .expect_err("protocol mismatch")
            .code(),
            PluginErrorCode::ProtocolMismatch
        );
        worker.protocol = ProtocolRange { min: 1, max: 1 };
        worker.profiles = vec!["other-profile".to_owned()];
        assert_eq!(
            negotiate_worker(
                &manifest,
                &worker,
                "jmeter-5.6.3",
                &CapabilityReference::new(CapabilityKind::Element, "example.element"),
            )
            .expect_err("profile mismatch")
            .code(),
            PluginErrorCode::ProfileMismatch
        );
        worker.profiles = vec!["jmeter-5.6.3".to_owned()];
        worker.capabilities.elements.clear();
        assert_eq!(
            negotiate_worker(
                &manifest,
                &worker,
                "jmeter-5.6.3",
                &CapabilityReference::new(CapabilityKind::Element, "example.element"),
            )
            .expect_err("capability mismatch")
            .code(),
            PluginErrorCode::CapabilityMismatch
        );
    }

    #[test]
    fn handshake_rejects_ambiguous_capability_inventory_before_advertising() {
        let mut ambiguous_manifest = manifest();
        ambiguous_manifest
            .capabilities
            .elements
            .push(CapabilityDeclaration {
                id: "example.other".to_owned(),
                aliases: vec!["example.element".to_owned()],
                extensions: BTreeMap::new(),
            });
        let codec = FrameCodec::new(ambiguous_manifest.limits.max_message_bytes);
        assert_eq!(
            encode_handshake(&codec, &ambiguous_manifest)
                .expect_err("ambiguous manifest must not be advertised")
                .code(),
            PluginErrorCode::ManifestInvalid
        );

        let mut worker = manifest();
        worker.capabilities.elements.push(CapabilityDeclaration {
            id: "example.other".to_owned(),
            aliases: vec!["example.element".to_owned()],
            extensions: BTreeMap::new(),
        });
        let info = worker.handshake_info();
        let frame = Frame {
            payload: serde_json::to_vec(&info).expect("ambiguous handshake payload"),
            ..Frame::handshake(0, "jmeter-5.6.3", Vec::new())
        };
        let bytes = codec.encode(&frame).expect("ambiguous handshake frame");
        assert_eq!(
            decode_handshake(&codec, &bytes)
                .expect_err("worker ambiguity must fail during handshake validation")
                .code(),
            PluginErrorCode::ManifestInvalid
        );
    }

    #[test]
    fn handshake_wire_metadata_is_required_and_matches_the_payload_exactly() {
        let manifest = manifest();
        let codec = FrameCodec::new(manifest.limits.max_message_bytes);
        let info = manifest.handshake_info();
        let payload = serde_json::to_vec(&info).expect("handshake payload");

        let missing_profile = Frame {
            payload: payload.clone(),
            ..Frame::new(MessageKind::Handshake, 0, payload.clone())
        };
        assert_eq!(
            decode_handshake_frame_with_limit(&missing_profile, codec.limits().max_payload_len)
                .expect_err("handshake profile is mandatory")
                .code(),
            PluginErrorCode::WorkerProtocol
        );

        let wrong_capabilities = Frame {
            payload,
            ..Frame::handshake(0, "jmeter-5.6.3", vec!["other.capability".to_owned()])
        };
        assert_eq!(
            decode_handshake_frame_with_limit(&wrong_capabilities, codec.limits().max_payload_len,)
                .expect_err("metadata must enumerate the payload declarations")
                .code(),
            PluginErrorCode::WorkerProtocol
        );
    }

    #[test]
    fn capability_ids_are_unique_across_wire_namespaces() {
        let mut manifest = manifest();
        manifest
            .capabilities
            .functions
            .push(CapabilityDeclaration::new("example.element"));
        let codec = FrameCodec::new(manifest.limits.max_message_bytes);
        assert_eq!(
            encode_handshake(&codec, &manifest)
                .expect_err("wire metadata cannot represent cross-kind duplicate IDs")
                .code(),
            PluginErrorCode::ManifestInvalid
        );
    }

    #[test]
    fn unknown_jmx_metadata_is_serialized_without_drop() {
        let mut jmx = JmxElementMetadata::unknown("plugin.Unknown", b"<unknown/>".to_vec());
        jmx.unknown_properties.push(UnknownJmxProperty {
            name: "plugin.property".to_owned(),
            raw_value: vec![0, 255, 1],
        });
        jmx.properties
            .insert("known".to_owned(), serde_json::json!("value"));
        let request = PluginRequest {
            capability: CapabilityReference::new(CapabilityKind::Element, "example.element"),
            jmx: jmx.clone(),
            input: Vec::new(),
            extensions: BTreeMap::new(),
        };
        let decoded: PluginRequest =
            serde_json::from_slice(&serde_json::to_vec(&request).expect("request encodes"))
                .expect("request decodes");
        assert_eq!(decoded.jmx, jmx);
        assert_eq!(
            decoded.jmx.raw_subtree.as_deref(),
            Some(b"<unknown/>".as_slice())
        );
        assert_eq!(decoded.jmx.unknown_properties[0].raw_value, vec![0, 255, 1]);
    }

    #[test]
    fn jmx_property_order_survives_wire_round_trip() {
        let mut jmx = JmxElementMetadata::unknown("plugin.Ordered", b"<ordered/>".to_vec());
        jmx.properties
            .insert("z-last".to_owned(), serde_json::json!(1));
        jmx.properties
            .insert("a-first".to_owned(), serde_json::json!(2));
        let request = PluginRequest {
            capability: CapabilityReference::new(CapabilityKind::Element, "example.element"),
            jmx,
            input: Vec::new(),
            extensions: BTreeMap::new(),
        };
        let encoded = serde_json::to_vec(&request).expect("request encodes");
        let z = encoded
            .windows(b"z-last".len())
            .position(|window| window == b"z-last")
            .expect("first property key");
        let a = encoded
            .windows(b"a-first".len())
            .position(|window| window == b"a-first")
            .expect("second property key");
        assert!(z < a, "wire property order must follow insertion order");
        let decoded: PluginRequest = serde_json::from_slice(&encoded).expect("request decodes");
        let names = decoded
            .jmx
            .properties
            .iter()
            .map(|(name, _)| name)
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["z-last", "a-first"]);
    }

    #[test]
    fn mixed_jmx_wire_categories_without_raw_order_are_rejected() {
        for payload in [
            br#"{"test_class":"plugin.Mixed","properties":{"typed":1},"unknown_properties":[{"name":"opaque","raw_value":[1]}]}"#
                .as_slice(),
            br#"{"test_class":"plugin.Mixed","unknown_properties":[{"name":"opaque","raw_value":[1]}],"properties":{"typed":1}}"#
                .as_slice(),
        ] {
            let metadata: JmxElementMetadata =
                serde_json::from_slice(payload).expect("wire object itself is well formed");
            assert_eq!(
                metadata
                    .validate()
                    .expect_err("cross-kind order must be explicit")
                    .code(),
                PluginErrorCode::InvalidJmx
            );
        }
    }

    #[test]
    fn duplicate_json_property_keys_are_rejected_before_request_use() {
        let duplicate_nested =
            br#"{"test_class":"plugin.Duplicate","properties":{"same":1,"same":2}}"#;
        assert!(serde_json::from_slice::<JmxElementMetadata>(duplicate_nested).is_err());

        let escaped_duplicate_nested =
            br#"{"test_class":"plugin.Duplicate","properties":{"same":1,"\u0073ame":2}}"#;
        assert!(serde_json::from_slice::<JmxElementMetadata>(escaped_duplicate_nested).is_err());

        let duplicate_top_level =
            br#"{"test_class":"plugin.Duplicate","test_class":"plugin.Other"}"#;
        assert!(serde_json::from_slice::<JmxElementMetadata>(duplicate_top_level).is_err());

        let duplicate_extension = br#"{"output":[],"metadata":{"same":1,"same":2}}"#;
        assert_eq!(
            preflight_json(duplicate_extension, 1024)
                .expect_err("duplicate map key must fail before serde allocation")
                .code(),
            PluginErrorCode::WorkerProtocol
        );

        // The preflight scanner runs before serde for every object, including
        // flattened extension and metadata maps.  Compare decoded key
        // semantics so an escaped spelling cannot collapse into the same map
        // entry after serde allocation.
        for payload in [
            br#"{"output":[],"metadata":{"same":1,"\u0073ame":2}}"#.as_slice(),
            br#"{"future":{"same":1,"\u0073ame":2}}"#.as_slice(),
            br#"{"jmx":{"extensions":{"same":1,"\u0073ame":2}}}"#.as_slice(),
            r#"{"metadata":{"\u00e9":1,"é":2}}"#.as_bytes(),
            r#"{"metadata":{"😀":1,"\ud83d\ude00":2}}"#.as_bytes(),
        ] {
            assert_eq!(
                preflight_json(payload, 1024)
                    .expect_err("escaped-equivalent map key must fail before serde allocation")
                    .code(),
                PluginErrorCode::WorkerProtocol
            );
        }

        // Different decoded names remain valid; this guards against treating
        // all escaped keys as duplicates rather than canonicalizing them.
        preflight_json(br#"{"metadata":{"same":1,"\u0074ame":2}}"#, 1024)
            .expect("distinct decoded map keys are valid");
    }

    #[test]
    fn unknown_handshake_fields_are_rejected_instead_of_dropped() {
        let manifest = manifest();
        let codec = FrameCodec::new(manifest.limits.max_message_bytes);
        let mut value = serde_json::to_value(manifest.handshake_info()).expect("handshake value");
        value
            .as_object_mut()
            .expect("handshake object")
            .insert("future_field".to_owned(), serde_json::json!("opaque"));
        let frame = Frame::handshake(0, "jmeter-5.6.3", Vec::new());
        let frame = Frame {
            payload: serde_json::to_vec(&value).expect("handshake payload"),
            ..frame
        };
        let error = decode_handshake_frame_with_limit(&frame, codec.limits().max_payload_len)
            .expect_err("unknown protocol field must be explicit");
        assert_eq!(error.code(), PluginErrorCode::WorkerProtocol);
    }

    #[test]
    fn unknown_nested_handshake_fields_are_rejected_instead_of_dropped() {
        let manifest = manifest();
        let codec = FrameCodec::new(manifest.limits.max_message_bytes);
        let mut value = serde_json::to_value(manifest.handshake_info()).expect("handshake value");
        value
            .get_mut("protocol")
            .and_then(serde_json::Value::as_object_mut)
            .expect("protocol object")
            .insert("future_version_field".to_owned(), serde_json::json!(1));
        let frame = Frame::handshake(0, "jmeter-5.6.3", Vec::new());
        let frame = Frame {
            payload: serde_json::to_vec(&value).expect("handshake payload"),
            ..frame
        };
        let error = decode_handshake_frame_with_limit(&frame, codec.limits().max_payload_len)
            .expect_err("unknown nested protocol field must be explicit");
        assert_eq!(error.code(), PluginErrorCode::WorkerProtocol);
    }

    #[test]
    fn every_closed_nested_handshake_object_rejects_unknown_fields() {
        let manifest = manifest();
        let codec = FrameCodec::new(manifest.limits.max_message_bytes);
        for field in ["capabilities", "preservation"] {
            let mut value =
                serde_json::to_value(manifest.handshake_info()).expect("handshake value");
            value
                .get_mut(field)
                .and_then(serde_json::Value::as_object_mut)
                .expect("nested object")
                .insert("future_nested_field".to_owned(), serde_json::json!(true));
            let frame = Frame::handshake(0, "jmeter-5.6.3", Vec::new());
            let frame = Frame {
                payload: serde_json::to_vec(&value).expect("handshake payload"),
                ..frame
            };
            let error = decode_handshake_frame_with_limit(&frame, codec.limits().max_payload_len)
                .expect_err("closed nested object must reject unknown field");
            assert_eq!(
                error.code(),
                PluginErrorCode::WorkerProtocol,
                "field {field}"
            );
        }
    }

    #[test]
    fn response_json_is_preflighted_before_serde_and_unknown_fields_rejected() {
        let codec = FrameCodec::new(1024);
        let payload = br#"{"output":[],"metadata":{},"future":"opaque"}"#;
        let frame = Frame::new(MessageKind::Response, 1, payload.to_vec());
        let error = decode_response(&codec, &frame, 1).expect_err("unknown field");
        assert_eq!(error.code(), PluginErrorCode::WorkerProtocol);

        let mut oversized = br#"{"output":""#.to_vec();
        oversized.extend(std::iter::repeat_n(
            b'a',
            MAX_PROTOCOL_JSON_STRING_BYTES + 1,
        ));
        oversized.extend_from_slice(br#""}"#);
        let frame = Frame::new(MessageKind::Response, 1, oversized);
        let error = decode_response(
            &FrameCodec::new(MAX_PROTOCOL_JSON_STRING_BYTES + 1024),
            &frame,
            1,
        )
        .expect_err("oversized JSON field");
        assert_eq!(error.code(), PluginErrorCode::WorkerMessageLimit);
    }

    #[test]
    fn worker_error_text_is_redacted_but_code_is_stable() {
        let error = map_remote_error(
            RemoteErrorCode::WorkerUnavailable,
            "secret worker environment".to_owned(),
        );
        assert_eq!(error.code(), PluginErrorCode::PluginUnavailable);
        assert!(!error.detail().contains("secret worker environment"));
    }

    #[test]
    fn operation_frames_reject_zero_ids_and_preserve_mismatch_codes() {
        let codec = FrameCodec::new(1024);
        assert_eq!(
            encode_response(
                &codec,
                0,
                &PluginResponse {
                    output: Vec::new(),
                    metadata: BTreeMap::new(),
                },
            )
            .expect_err("response IDs are never reserved for operations")
            .code(),
            PluginErrorCode::WorkerRequestMismatch
        );
        assert_eq!(
            cancellation_frame(&codec, 0)
                .expect_err("cancellation IDs are never reserved for operations")
                .code(),
            PluginErrorCode::WorkerRequestMismatch
        );
        let frame = Frame::new(MessageKind::Response, 2, br#"{"output":[]}"#.to_vec());
        assert_eq!(
            decode_response(&codec, &frame, 1)
                .expect_err("a response for another request is a correlation failure")
                .code(),
            PluginErrorCode::WorkerRequestMismatch
        );
        let metadata_frame = Frame::new(MessageKind::Response, 1, br#"{"output":[]}"#.to_vec())
            .with_profile("unexpected-profile");
        assert_eq!(
            decode_response(&codec, &metadata_frame, 1)
                .expect_err("response metadata must be rejected")
                .code(),
            PluginErrorCode::WorkerProtocol
        );
        let cancelled_error = Frame::new(MessageKind::Error, 1, vec![0; 5])
            .with_cancellation(Cancellation::Cancelled);
        assert_eq!(
            decode_response(&codec, &cancelled_error, 1)
                .expect_err("error cancellation metadata must be rejected")
                .code(),
            PluginErrorCode::WorkerProtocol
        );
    }

    #[test]
    fn generic_worker_quota_is_not_misreported_as_output_or_message_quota() {
        let error = map_remote_error(
            RemoteErrorCode::WorkerLimitExceeded,
            "worker quota detail".to_owned(),
        );
        assert_eq!(error.code(), PluginErrorCode::WorkerResourceLimit);
    }

    #[test]
    fn all_bridge_frame_quota_failures_map_to_message_limit() {
        let errors = [
            DecodeError::FrameTooLarge {
                declared: 2,
                maximum: 1,
            },
            DecodeError::ErrorPayloadTooLarge {
                declared: 2,
                maximum: 1,
            },
            DecodeError::CapabilityBytesTooLarge {
                declared: 2,
                maximum: 1,
            },
            DecodeError::InvalidLimits(
                jmeter_rs_bridge_protocol::FrameLimitsError::MessageExceedsFrame {
                    message: 2,
                    frame: 1,
                },
            ),
        ];
        for error in errors {
            assert_eq!(
                decode_error(error).code(),
                PluginErrorCode::WorkerMessageLimit
            );
        }
    }
}
