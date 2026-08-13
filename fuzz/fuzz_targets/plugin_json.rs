#![no_main]

//! Bounded plugin JSON and frame-boundary fuzz target.
//!
//! The target stays on the pure side of the plugin boundary.  It generates
//! manifest-derived handshake JSON, malformed JSON, duplicate decoded keys,
//! capability inventories, preservation metadata, and opaque request frames.
//! No generated value is passed to a process, executable, JVM, filesystem, or
//! network operation.
//!
//! Invariants:
//!
//! - `PLUG-003-JSON-001`: malformed and unknown protocol JSON fails with a
//!   stable typed protocol error rather than panicking or silently accepting a
//!   closed field.
//! - `PLUG-003-NODROP-001`: accepted capability and preservation inventories
//!   survive the public framed handshake round trip, including flattened
//!   declaration metadata.
//! - `TEST-003-BOUND-001`: capability, request, response, and frame payload
//!   bounds reject with the appropriate typed quota category before any worker
//!   boundary is reachable.
//!
//! Source-side coverage: manifest capability names, preservation flags, JSON
//! keys, and opaque frame payload bytes are compared as independent fields.
//! I/O policy: none; the public preflight and frame codec are in-memory only.

use std::{collections::BTreeMap, path::PathBuf};

use jmeter_rs_bridge_protocol::{Frame, FrameCodec, MessageKind};
use jmeter_rs_plugin_host::{
    CapabilityDeclaration, CapabilityDeclarations, CapabilityKind, CapabilityReference,
    HandshakeInfo, JmxElementMetadata, MAX_DECLARED_CAPABILITIES, PluginError, PluginErrorCode,
    PluginId, PluginManifest, PluginRequest, PluginResponse, PluginVersion, PreservationContract,
    ProtocolRange, UnknownJmxProperty,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 64 * 1024;
const MAX_MESSAGE_BYTES: usize = 32 * 1024;
const MAX_RAW_BYTES: usize = 48 * 1024;
const WIDE_CODEC_BYTES: usize = MAX_RAW_BYTES + 1024;

fn bounded_hex(data: &[u8], maximum_bytes: usize) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let length = data.len().min(maximum_bytes);
    let mut output = String::with_capacity(length.saturating_mul(2).max(4));
    for byte in data.iter().take(length) {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    if output.is_empty() {
        output.push_str("fuzz");
    }
    output
}

fn indexed_name(prefix: char, index: usize) -> String {
    format!("{prefix}{index:x}")
}

fn assert_typed_json_rejection(codec: &FrameCodec, payload: &[u8]) {
    let error = decode_handshake_json(codec, payload)
        .expect_err("malformed or closed-field JSON must be rejected");
    if !matches!(
        error.code(),
        PluginErrorCode::WorkerProtocol
            | PluginErrorCode::WorkerMessageLimit
            | PluginErrorCode::ManifestInvalid
            | PluginErrorCode::ProtocolMismatch
    ) {
        panic!(
            "plugin JSON returned an unrelated error code: {}",
            error.code()
        );
    }
}

fn decode_handshake_json(codec: &FrameCodec, payload: &[u8]) -> Result<HandshakeInfo, PluginError> {
    let mut frame = Frame::handshake(0, "jmeter-5.6.3", Vec::new());
    frame.payload = payload.to_vec();

    // A wider encoder lets the smaller consumer exercise its typed payload
    // limit without truncating the fuzz input.  Both bounds are far below the
    // bridge hard frame cap and the payload was capped before this function.
    let encoder = FrameCodec::new(WIDE_CODEC_BYTES);
    let bytes = encoder
        .encode(&frame)
        .expect("bounded synthetic handshake frame must encode");
    jmeter_rs_plugin_host::decode_handshake(codec, &bytes)
}

fn append_capability_list(
    output: &mut String,
    prefix: char,
    count: usize,
    declaration_extension: bool,
) {
    output.push('[');
    for index in 0..count {
        if index > 0 {
            output.push(',');
        }
        output.push_str(r#"{"id":"#);
        output.push_str(&indexed_name(prefix, index));
        output.push_str(r#"","aliases":[]"#);
        if declaration_extension && index == 0 {
            // CapabilityDeclaration has an explicit flattened extension map.
            // The receiver must retain this bounded unknown field rather than
            // silently treating it as a capability alias or ID.
            output.push_str(r#", "future_metadata":"opaque"#);
        }
        output.push('}');
    }
    output.push(']');
}

/// Builds a bounded handshake-shaped JSON document.  The public host API
/// exposes manifest-derived handshake decoding rather than a standalone JSON
/// manifest parser, so this is the pure wire path used to exercise the same
/// preflight and closed nested serde structs.
fn handshake_json(
    element_count: usize,
    function_count: usize,
    declaration_extension: bool,
    unknown_field: u8,
) -> Vec<u8> {
    let total = element_count.saturating_add(function_count);
    let mut output = String::with_capacity(256usize.saturating_add(total.saturating_mul(28)));
    output.push('{');
    output.push_str(
        r#""plugin_id":"fuzz.plugin","plugin_version":"1.0.0","protocol":{"min":1,"max":1"#,
    );
    if unknown_field == 1 {
        output.push_str(r#", "future_protocol":true"#);
    }
    output.push_str(r#"},"profiles":["jmeter-5.6.3"],"capabilities":{"elements":"#);
    append_capability_list(&mut output, 'e', element_count, declaration_extension);
    output.push_str(r#", "functions":"#);
    append_capability_list(
        &mut output,
        'f',
        function_count,
        declaration_extension && element_count == 0,
    );
    if unknown_field == 2 {
        output.push_str(r#", "future_capabilities":true"#);
    }
    output.push_str(r#"},"preservation":{"contract_version":1,"unknown_elements":true,"unknown_properties":true,"raw_subtree":true"#);
    if unknown_field == 3 {
        output.push_str(r#", "future_preservation":true"#);
    }
    output.push('}');
    if unknown_field == 4 {
        output.push_str(r#", "future_top_level":true"#);
    }
    output.push('}');
    output.into_bytes()
}

fn round_trip_manifest_inventory(data: &[u8]) {
    let suffix = bounded_hex(data, 16);
    let plugin_id = PluginId::parse(format!("fuzz.{suffix}")).expect("bounded synthetic ID");
    let mut capabilities = CapabilityDeclarations::default();
    let mut element = CapabilityDeclaration::new(indexed_name('e', 0));
    element.aliases.push(indexed_name('a', 0));
    capabilities.elements.push(element);
    capabilities
        .functions
        .push(CapabilityDeclaration::new(indexed_name('f', 0)));

    let contracts = [
        PreservationContract {
            contract_version: 1,
            unknown_elements: false,
            unknown_properties: false,
            raw_subtree: false,
        },
        PreservationContract {
            contract_version: 1,
            unknown_elements: true,
            unknown_properties: true,
            raw_subtree: true,
        },
    ];
    for preservation in contracts {
        let mut manifest = PluginManifest::new(
            plugin_id.clone(),
            PluginVersion::parse("1.0.0").expect("synthetic plugin version"),
            PathBuf::from("/fuzz/plugin-host"),
        );
        manifest.profiles.push("jmeter-5.6.3".to_owned());
        manifest.protocol = ProtocolRange::new(1, 1).expect("synthetic protocol range");
        manifest.capabilities = capabilities.clone();
        manifest.preservation = preservation.clone();
        manifest
            .validate()
            .expect("synthetic manifest inventory must validate");

        let codec = FrameCodec::new(MAX_MESSAGE_BYTES);
        let encoded = jmeter_rs_plugin_host::encode_handshake(&codec, &manifest)
            .expect("synthetic plugin handshake must satisfy codec bounds");
        let decoded = jmeter_rs_plugin_host::decode_handshake(&codec, &encoded)
            .expect("synthetic plugin handshake must decode");
        if decoded.plugin_id != manifest.id
            || decoded.plugin_version != manifest.version
            || decoded.protocol != manifest.protocol
            || decoded.profiles != manifest.profiles
            || decoded.capabilities != manifest.capabilities
            || decoded.preservation != manifest.preservation
        {
            panic!("plugin handshake dropped manifest inventory or preservation metadata");
        }
    }
}

fn exercise_generated_handshake_json(data: &[u8], codec: &FrameCodec) {
    let selector = data.first().copied().unwrap_or(0);
    let total = usize::from(selector) % (MAX_DECLARED_CAPABILITIES + 2);
    let element_count = total / 2;
    let function_count = total.saturating_sub(element_count);

    let generated = handshake_json(element_count, function_count, false, u8::MAX);
    match decode_handshake_json(codec, &generated) {
        Ok(info) => {
            if total > MAX_DECLARED_CAPABILITIES {
                panic!("oversized generated capability inventory was accepted");
            }
            if info.capabilities.elements.len() != element_count
                || info.capabilities.functions.len() != function_count
            {
                panic!("accepted capability inventory changed during handshake decode");
            }
        }
        Err(error) if total > MAX_DECLARED_CAPABILITIES => {
            assert_eq!(error.code(), PluginErrorCode::ManifestInvalid);
        }
        Err(error) => panic!(
            "bounded generated capability inventory was unexpectedly rejected: {}",
            error.code()
        ),
    }

    // Always exercise the exact aggregate boundary, independent of the first
    // fuzz byte.  The short IDs keep this maximal JSON document below the
    // target's 32 KiB frame budget while still forcing the host count check.
    let oversized = handshake_json(
        MAX_DECLARED_CAPABILITIES / 2,
        MAX_DECLARED_CAPABILITIES - MAX_DECLARED_CAPABILITIES / 2 + 1,
        false,
        u8::MAX,
    );
    let error = decode_handshake_json(codec, &oversized)
        .expect_err("capability aggregate bound must reject before worker use");
    assert_eq!(error.code(), PluginErrorCode::ManifestInvalid);

    let extension_payload = handshake_json(1, 0, true, u8::MAX);
    let info = decode_handshake_json(codec, &extension_payload)
        .expect("flattened declaration metadata must be accepted");
    let declaration = info
        .capabilities
        .elements
        .first()
        .expect("extension probe declaration");
    if !declaration.extensions.contains_key("future_metadata") {
        panic!("flattened declaration metadata was silently dropped");
    }

    for unknown_field in 1..=4 {
        let payload = handshake_json(1, 0, false, unknown_field);
        assert_typed_json_rejection(codec, &payload);
    }
}

fn exercise_duplicate_json_keys(codec: &FrameCodec) {
    let payloads: [&[u8]; 6] = [
        br#"{"plugin_id":"fuzz.plugin","\u0070lugin_id":"fuzz.plugin","plugin_version":"1.0.0","protocol":{"min":1,"max":1},"profiles":["jmeter-5.6.3"],"capabilities":{"elements":[],"functions":[]},"preservation":{"contract_version":1,"unknown_elements":false,"unknown_properties":false,"raw_subtree":false}}"#,
        br#"{"plugin_id":"fuzz.plugin","plugin_version":"1.0.0","protocol":{"min":1,"\u006din":1,"max":1},"profiles":["jmeter-5.6.3"],"capabilities":{"elements":[],"functions":[]},"preservation":{"contract_version":1,"unknown_elements":false,"unknown_properties":false,"raw_subtree":false}}"#,
        br#"{"plugin_id":"fuzz.plugin","plugin_version":"1.0.0","protocol":{"min":1,"max":1},"profiles":["jmeter-5.6.3"],"capabilities":{"elements":[],"\u0065lements":[],"functions":[]},"preservation":{"contract_version":1,"unknown_elements":false,"unknown_properties":false,"raw_subtree":false}}"#,
        br#"{"plugin_id":"fuzz.plugin","plugin_version":"1.0.0","protocol":{"min":1,"max":1},"profiles":["jmeter-5.6.3"],"capabilities":{"elements":[],"functions":[]},"preservation":{"contract_version":1,"unknown_elements":false,"unknown_properties":false,"raw_subtree":false,"\u0072aw_subtree":false}}"#,
        br#"{"plugin_id":"fuzz.plugin","plugin_version":"1.0.0","protocol":{"min":1,"max":1},"profiles":["jmeter-5.6.3"],"capabilities":{"elements":[{"id":"e0","aliases":[],"future_metadata":"one","\u0066uture_metadata":"two"}],"functions":[]},"preservation":{"contract_version":1,"unknown_elements":false,"unknown_properties":false,"raw_subtree":false}}"#,
        br#"{"capability":{"kind":"element","name":"fuzz.element"},"jmx":{"test_class":"fuzz.Element","extensions":{"same":1,"\u0073ame":2}},"input":[]}"#,
    ];
    for payload in payloads {
        let error = decode_handshake_json(codec, payload)
            .expect_err("escaped-equivalent JSON keys must fail before serde map collapse");
        assert_eq!(error.code(), PluginErrorCode::WorkerProtocol);
    }
}

fn exercise_malformed_json(codec: &FrameCodec, data: &[u8]) {
    let raw = data[..data.len().min(MAX_RAW_BYTES)].to_vec();
    let result = decode_handshake_json(codec, &raw);
    if let Err(error) = result
        && !matches!(
            error.code(),
            PluginErrorCode::WorkerProtocol
                | PluginErrorCode::WorkerMessageLimit
                | PluginErrorCode::ManifestInvalid
                | PluginErrorCode::ProtocolMismatch
        )
    {
        panic!("malformed plugin JSON returned an unrelated error code");
    }

    for payload in [b"{".as_slice(), b"[]".as_slice(), b"null".as_slice()] {
        assert_typed_json_rejection(codec, payload);
    }
}

fn exercise_request_and_response_frames(data: &[u8], codec: &FrameCodec) {
    let raw = data[..data.len().min(MAX_RAW_BYTES)].to_vec();
    let request = PluginRequest {
        capability: CapabilityReference::new(CapabilityKind::Element, "fuzz.element"),
        jmx: JmxElementMetadata {
            test_class: "fuzz.Element".to_owned(),
            gui_class: Some("fuzz.Gui".to_owned()),
            name: Some("fuzz".to_owned()),
            properties: Default::default(),
            unknown_properties: vec![UnknownJmxProperty {
                name: "fuzz.raw".to_owned(),
                raw_value: raw.clone(),
            }],
            raw_subtree: Some(b"<fuzz.Element/>".to_vec()),
            extensions: BTreeMap::new(),
        },
        input: raw.clone(),
        extensions: BTreeMap::new(),
    };
    match request.validate_for_message_limit(MAX_MESSAGE_BYTES) {
        Ok(()) => {}
        Err(error)
            if matches!(
                error.code(),
                PluginErrorCode::WorkerMessageLimit | PluginErrorCode::InvalidJmx
            ) =>
        {
            if error.code() == PluginErrorCode::InvalidJmx {
                panic!("bounded synthetic plugin request became invalid JMX");
            }
        }
        Err(error) => panic!(
            "request preflight returned an unrelated error: {}",
            error.code()
        ),
    }

    let request_json_data = bounded_hex(data, 2 * 1024);
    let mut request_payload = String::from(
        r#"{"capability":{"kind":"element","name":"fuzz.element"},"jmx":{"test_class":"fuzz.Element","extensions":{"future":"#,
    );
    request_payload.push_str(&request_json_data);
    request_payload.push_str(r#""}},"input":[],"future_request":"opaque"}"#);
    let request_frame = Frame::new(MessageKind::Request, 1, request_payload.into_bytes());
    let encoded_request = codec
        .encode(&request_frame)
        .expect("bounded synthetic request frame must encode");
    let decoded_request = codec
        .decode_exact(&encoded_request)
        .expect("bounded synthetic request frame must decode");
    if decoded_request != request_frame {
        panic!("request frame changed opaque JSON or metadata");
    }

    let response = PluginResponse {
        output: data[..data.len().min(4 * 1024)].to_vec(),
        metadata: BTreeMap::new(),
    };
    match jmeter_rs_plugin_host::encode_response(codec, 1, &response) {
        Ok(encoded_response) => {
            let decoded_response = codec
                .decode_exact(&encoded_response)
                .expect("bounded synthetic response frame must decode");
            if decoded_response.kind != MessageKind::Response || decoded_response.request_id != 1 {
                panic!("response frame changed kind or request identity");
            }
        }
        Err(error)
            if matches!(
                error.code(),
                PluginErrorCode::WorkerMessageLimit | PluginErrorCode::WorkerProtocol
            ) => {}
        Err(error) => panic!(
            "response preflight returned an unrelated error: {}",
            error.code()
        ),
    }
}

fuzz_target!(|data: &[u8]| {
    round_trip_manifest_inventory(data);
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let codec = FrameCodec::new(MAX_MESSAGE_BYTES);
    exercise_generated_handshake_json(data, &codec);
    exercise_duplicate_json_keys(&codec);
    exercise_malformed_json(&codec, data);
    exercise_request_and_response_frames(data, &codec);
});
