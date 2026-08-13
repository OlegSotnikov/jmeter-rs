#![no_main]

//! Bounded bridge-frame decoder/encoder target.
//!
//! Raw input is never sliced into a smaller payload.  A complete decoded
//! frame is round-tripped as-is, while bounded synthetic frames exercise every
//! message kind and each version-1 metadata state without opening a transport
//! or interpreting payload contents.
//!
//! Invariants: `BRIDGE-FRAME-ROUNDTRIP-001` preserves complete frames,
//! `BRIDGE-METADATA-001` covers deadlines/cancellation/profile/capabilities and
//! structured errors, and `BRIDGE-LIMIT-001` rejects or reports full oversized
//! input without an undocumented truncation path.
//! Source-side coverage: complete-frame bytes, decoded metadata, structured
//! handshake fields, and bounded payload bytes are compared from the input.
//! I/O policy: none; this target stays on in-memory frame codecs.

use jmeter_rs_bridge_protocol::{
    Cancellation, Deadline, DecodeError, DecodeResult, Frame, FrameCodec, HEADER_LEN, Handshake,
    HandshakeDecodeError, HandshakeEncodeError, HandshakeField, MessageKind, PROTOCOL_VERSION,
    PeerIdentity, PreservationContract, PreservationContractError, ProtocolVersionRange,
    RemoteError, RemoteErrorCode, RemoteErrorDecodeError, TrailingPolicy, Utf8Field,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 256 * 1024;
const MAX_PAYLOAD_BYTES: usize = 64 * 1024;
const HANDSHAKE_FIXED_BYTES: usize = 37;

fn round_trip(codec: &FrameCodec, frame: &Frame) {
    let encoded = codec
        .encode(frame)
        .expect("synthetic bridge frame must satisfy codec bounds");
    let decoded = codec
        .decode_exact(&encoded)
        .expect("codec rejected its own complete frame");
    if decoded != *frame {
        panic!("bridge frame round-trip changed metadata or payload");
    }
}

fn round_trip_handshake(codec: &FrameCodec) {
    let preservation_contracts = [
        PreservationContract::full(),
        PreservationContract::default(),
        PreservationContract {
            unknown_messages: false,
            unknown_fields: false,
            opaque_payloads: true,
            unknown_capabilities: false,
        },
        PreservationContract {
            unknown_messages: false,
            unknown_fields: false,
            opaque_payloads: false,
            unknown_capabilities: true,
        },
    ];
    for preservation in preservation_contracts {
        let handshake = Handshake::new(
            PeerIdentity::worker("fuzz-worker", "1.0"),
            ProtocolVersionRange {
                minimum: 1,
                maximum: 1,
            },
        )
        .with_capabilities(["jmx", "jtl"])
        .with_supported_kinds([
            MessageKind::Handshake,
            MessageKind::Request,
            MessageKind::Response,
            MessageKind::Cancel,
            MessageKind::Error,
        ])
        .with_preservation(preservation);
        let encoded = handshake
            .encode_frame(codec)
            .expect("synthetic structured handshake must satisfy codec bounds");
        let frame = codec
            .decode_exact(&encoded)
            .expect("structured handshake frame must decode");
        let decoded = Handshake::from_frame(&frame).expect("structured handshake must decode");
        if decoded != handshake || decoded.preservation != preservation {
            panic!("structured bridge handshake changed preservation metadata");
        }

        let peer = PreservationContract {
            unknown_messages: false,
            unknown_fields: true,
            opaque_payloads: false,
            unknown_capabilities: true,
        };
        let expected = PreservationContract {
            unknown_messages: preservation.unknown_messages && peer.unknown_messages,
            unknown_fields: preservation.unknown_fields && peer.unknown_fields,
            opaque_payloads: preservation.opaque_payloads && peer.opaque_payloads,
            unknown_capabilities: preservation.unknown_capabilities && peer.unknown_capabilities,
        };
        if preservation.intersect(peer) != expected {
            panic!("bridge preservation-contract intersection changed semantics");
        }
    }
}

fn exercise_unsupported_preservation(data: &[u8]) {
    let valid = Handshake::worker("fuzz-worker", "1.0", "jmeter-5.6.3");
    let payload = valid
        .encode_payload()
        .expect("synthetic handshake must provide a valid mutation base");

    let mut unknown_messages = payload.clone();
    unknown_messages[5] |= 0x02;
    assert!(matches!(
        Handshake::decode_payload(&unknown_messages),
        Err(HandshakeDecodeError::UnsupportedPreservation(
            PreservationContractError::UnknownMessagesUnsupported
        ))
    ));

    let mut unknown_fields = payload.clone();
    unknown_fields[5] |= 0x04;
    assert!(matches!(
        Handshake::decode_payload(&unknown_fields),
        Err(HandshakeDecodeError::UnsupportedPreservation(
            PreservationContractError::UnknownFieldsUnsupported
        ))
    ));

    let unsupported_messages = valid.clone().with_preservation(PreservationContract {
        unknown_messages: true,
        unknown_fields: false,
        opaque_payloads: false,
        unknown_capabilities: false,
    });
    assert!(matches!(
        unsupported_messages.encode_payload(),
        Err(HandshakeEncodeError::UnsupportedPreservation(
            PreservationContractError::UnknownMessagesUnsupported
        ))
    ));

    let unsupported_fields = valid.with_preservation(PreservationContract {
        unknown_messages: false,
        unknown_fields: true,
        opaque_payloads: false,
        unknown_capabilities: false,
    });
    assert!(matches!(
        unsupported_fields.encode_payload(),
        Err(HandshakeEncodeError::UnsupportedPreservation(
            PreservationContractError::UnknownFieldsUnsupported
        ))
    ));

    // Let the fuzzer select either rejected preservation bit as well.  The
    // rejection is intentionally matched, never unwrapped as a valid frame.
    if let Some(first) = data.first().copied() {
        let mut fuzzed = payload;
        fuzzed[5] |= if first & 1 == 0 { 0x02 } else { 0x04 };
        assert!(matches!(
            Handshake::decode_payload(&fuzzed),
            Err(HandshakeDecodeError::UnsupportedPreservation(_))
        ));
    }
}

fn exercise_valid_binary_frames(codec: &FrameCodec) {
    let binary_payload = vec![0x00, 0xff, 0x10, 0x00, b'J', b'M', b'B', b'P'];

    let mut handshake = Frame::handshake(0, "jmeter-5.6.3", vec!["opaque".to_owned()]);
    handshake.payload = binary_payload.clone();
    round_trip(codec, &handshake);

    let request = Frame::new(MessageKind::Request, 1, binary_payload.clone())
        .with_deadline(Deadline::at_unix_millis(1_700_000_000_010))
        .with_cancellation(Cancellation::Requested)
        .with_profile("jmeter-5.6.3")
        .with_capabilities(vec!["opaque".to_owned()]);
    round_trip(codec, &request);

    let response = Frame::new(MessageKind::Response, 1, binary_payload.clone())
        .with_deadline(Deadline::at_unix_millis(1_700_000_000_011))
        .with_cancellation(Cancellation::Cancelled);
    round_trip(codec, &response);

    let cancel = Frame::new(MessageKind::Cancel, 1, binary_payload.clone())
        .with_deadline(Deadline::at_unix_millis(1_700_000_000_012))
        .with_cancellation(Cancellation::Requested);
    round_trip(codec, &cancel);

    let error = Frame::new(MessageKind::Error, 1, binary_payload);
    round_trip(codec, &error);
}

fn exercise_malformed_binary_frames(codec: &FrameCodec) {
    let valid = codec
        .encode(&Frame::new(MessageKind::Request, 1, vec![0x00, 0xff, 0x10]))
        .expect("synthetic request must provide a valid frame mutation base");

    let mut invalid_magic = valid.clone();
    invalid_magic[0] ^= 0xff;
    assert!(matches!(
        codec.decode(&invalid_magic),
        Err(DecodeError::InvalidMagic { .. })
    ));

    let mut unsupported_version = valid.clone();
    unsupported_version[4] = PROTOCOL_VERSION.wrapping_add(1);
    assert!(matches!(
        codec.decode(&unsupported_version),
        Err(DecodeError::UnsupportedVersion(_))
    ));

    let mut unknown_kind = valid.clone();
    unknown_kind[5] = 0xff;
    assert_eq!(
        codec.decode(&unknown_kind),
        Err(DecodeError::UnknownMessageKind(0xff))
    );

    let mut unknown_flags = valid.clone();
    unknown_flags[6] = 0x80;
    assert_eq!(
        codec.decode(&unknown_flags),
        Err(DecodeError::UnknownFlags(0x8000))
    );

    let mut invalid_cancellation = valid.clone();
    invalid_cancellation[7] |= 0x03;
    assert_eq!(
        codec.decode(&invalid_cancellation),
        Err(DecodeError::InvalidCancellationFlags)
    );

    let mut zero_request = valid.clone();
    zero_request[8..16].fill(0);
    assert!(matches!(
        codec.decode(&zero_request),
        Err(DecodeError::InvalidFrame(_))
    ));

    for length in 0..HEADER_LEN {
        let input = &valid[..length];
        assert_eq!(
            codec.decode(input),
            Ok(DecodeResult::Incomplete {
                needed: HEADER_LEN - length,
            })
        );
        let mut cursor = input;
        match codec.decode_next(&mut cursor) {
            Ok(None) => {}
            other => panic!("truncated frame advanced or failed: {other:?}"),
        }
        assert_eq!(cursor, input);
    }

    let mut truncated_payload = valid[..HEADER_LEN].to_vec();
    truncated_payload[32..36].copy_from_slice(&6_u32.to_be_bytes());
    assert_eq!(
        codec.decode(&truncated_payload),
        Ok(DecodeResult::Incomplete { needed: 6 })
    );

    let mut oversized_payload = valid[..HEADER_LEN].to_vec();
    oversized_payload[32..36].copy_from_slice(
        &u32::try_from(MAX_PAYLOAD_BYTES + 1)
            .expect("fuzz bound fits u32")
            .to_be_bytes(),
    );
    match codec.decode(&oversized_payload) {
        Err(DecodeError::PayloadTooLarge { declared, maximum }) => {
            assert_eq!(declared, MAX_PAYLOAD_BYTES + 1);
            assert_eq!(maximum, MAX_PAYLOAD_BYTES);
        }
        other => panic!("oversized payload was not rejected at the bound: {other:?}"),
    }

    let profiled = codec
        .encode(&Frame::new(MessageKind::Request, 1, vec![0x01]).with_profile("jmeter-5.6.3"))
        .expect("profiled request must provide a valid UTF-8 mutation base");
    let mut malformed_profile = profiled;
    malformed_profile[HEADER_LEN] = 0xff;
    assert_eq!(
        codec.decode(&malformed_profile),
        Err(DecodeError::MalformedUtf8 {
            field: Utf8Field::Profile,
        })
    );

    let mut profile_flag_mismatch = valid.clone();
    profile_flag_mismatch[7] |= 0x04;
    assert!(matches!(
        codec.decode(&profile_flag_mismatch),
        Err(DecodeError::ProfileFlagMismatch { .. })
    ));

    let mut trailing = valid.clone();
    trailing.extend_from_slice(&[0xaa, 0xbb]);
    match codec.decode(&trailing) {
        Ok(DecodeResult::Complete { consumed, .. }) => assert_eq!(consumed, valid.len()),
        other => panic!("valid frame with trailing bytes did not decode: {other:?}"),
    }
    assert_eq!(
        codec.decode_with_policy(&trailing, TrailingPolicy::Reject),
        Err(DecodeError::TrailingBytes { count: 2 })
    );
}

fn exercise_malformed_handshakes(data: &[u8]) {
    let valid = Handshake::worker("fuzz-worker", "1.0", "jmeter-5.6.3")
        .with_capabilities(["jmx"])
        .with_supported_kinds([
            MessageKind::Handshake,
            MessageKind::Request,
            MessageKind::Response,
            MessageKind::Cancel,
            MessageKind::Error,
        ])
        .with_preservation(PreservationContract::full());
    let payload = valid
        .encode_payload()
        .expect("synthetic handshake must provide a valid payload mutation base");

    assert!(matches!(
        Handshake::decode_payload(&[]),
        Err(HandshakeDecodeError::Truncated { .. })
    ));

    let mut invalid_magic = payload.clone();
    invalid_magic[0] ^= 0xff;
    assert!(matches!(
        Handshake::decode_payload(&invalid_magic),
        Err(HandshakeDecodeError::InvalidMagic { .. })
    ));

    let mut unsupported_version = payload.clone();
    unsupported_version[4] = 2;
    assert_eq!(
        Handshake::decode_payload(&unsupported_version),
        Err(HandshakeDecodeError::UnsupportedPayloadVersion(2))
    );

    let mut unknown_flags = payload.clone();
    unknown_flags[5] |= 0x80;
    assert_eq!(
        Handshake::decode_payload(&unknown_flags),
        Err(HandshakeDecodeError::UnknownFlags(0x80))
    );

    let mut invalid_versions = payload.clone();
    invalid_versions[6..8].copy_from_slice(&2_u16.to_be_bytes());
    assert!(matches!(
        Handshake::decode_payload(&invalid_versions),
        Err(HandshakeDecodeError::InvalidVersionRange(_))
    ));

    let mut selected_missing = payload.clone();
    selected_missing[5] |= 0x01;
    assert_eq!(
        Handshake::decode_payload(&selected_missing),
        Err(HandshakeDecodeError::SelectedVersionMissing)
    );

    let mut unknown_peer = payload.clone();
    unknown_peer[12] = 0xff;
    assert_eq!(
        Handshake::decode_payload(&unknown_peer),
        Err(HandshakeDecodeError::UnknownPeerKind(0xff))
    );

    let mut empty_name = payload.clone();
    empty_name[13..15].fill(0);
    assert!(matches!(
        Handshake::decode_payload(&empty_name),
        Err(HandshakeDecodeError::InvalidDeclaration(
            HandshakeEncodeError::EmptyField("identity name")
        ))
    ));

    let mut empty_version = payload.clone();
    empty_version[15..17].fill(0);
    assert!(matches!(
        Handshake::decode_payload(&empty_version),
        Err(HandshakeDecodeError::InvalidDeclaration(
            HandshakeEncodeError::EmptyField("identity version")
        ))
    ));

    let mut no_kinds = payload.clone();
    no_kinds[17..19].fill(0);
    assert!(matches!(
        Handshake::decode_payload(&no_kinds),
        Err(HandshakeDecodeError::InvalidDeclaration(
            HandshakeEncodeError::NoMessageKinds
        ))
    ));

    let mut malformed_limits = payload.clone();
    malformed_limits[19..23].fill(0);
    assert!(matches!(
        Handshake::decode_payload(&malformed_limits),
        Err(HandshakeDecodeError::InvalidLimits(_))
    ));

    let mut length_mismatch = payload.clone();
    length_mismatch.pop();
    assert!(matches!(
        Handshake::decode_payload(&length_mismatch),
        Err(HandshakeDecodeError::LengthMismatch { .. })
    ));

    let name_len = valid.identity.name.len();
    let version_len = valid.identity.version.len();
    let mut malformed_name = payload.clone();
    malformed_name[HANDSHAKE_FIXED_BYTES] = 0xff;
    assert_eq!(
        Handshake::decode_payload(&malformed_name),
        Err(HandshakeDecodeError::MalformedUtf8(
            HandshakeField::IdentityName
        ))
    );

    let mut malformed_version = payload.clone();
    malformed_version[HANDSHAKE_FIXED_BYTES + name_len] = 0xff;
    assert_eq!(
        Handshake::decode_payload(&malformed_version),
        Err(HandshakeDecodeError::MalformedUtf8(
            HandshakeField::IdentityVersion
        ))
    );

    let kinds_start = HANDSHAKE_FIXED_BYTES + name_len + version_len;
    let mut unknown_kind = payload.clone();
    unknown_kind[kinds_start] = 0xff;
    assert_eq!(
        Handshake::decode_payload(&unknown_kind),
        Err(HandshakeDecodeError::UnknownMessageKind {
            index: 0,
            wire: 0xff,
        })
    );

    let mut duplicate_kind = payload.clone();
    duplicate_kind[kinds_start + 4] = duplicate_kind[kinds_start];
    assert_eq!(
        Handshake::decode_payload(&duplicate_kind),
        Err(HandshakeDecodeError::DuplicateMessageKind)
    );

    let mut extra_byte = payload.clone();
    extra_byte.push(0);
    assert!(matches!(
        Handshake::decode_payload(&extra_byte),
        Err(HandshakeDecodeError::LengthMismatch { .. })
    ));

    let valid_frame = valid
        .to_frame()
        .expect("synthetic handshake frame must be encodable");
    let mut wrong_id = valid_frame.clone();
    wrong_id.request_id = 1;
    assert_eq!(
        Handshake::from_frame(&wrong_id),
        Err(HandshakeDecodeError::RequestIdMustBeZero(1))
    );

    let mut cancellation = valid_frame.clone();
    cancellation.cancellation = Cancellation::Requested;
    assert_eq!(
        Handshake::from_frame(&cancellation),
        Err(HandshakeDecodeError::InvalidCancellation(
            Cancellation::Requested
        ))
    );

    let mut missing_profile = valid_frame.clone();
    missing_profile.profile = None;
    assert_eq!(
        Handshake::from_frame(&missing_profile),
        Err(HandshakeDecodeError::MissingProfile)
    );

    let wrong_kind = Frame::new(MessageKind::Request, 1, payload);
    assert_eq!(
        Handshake::from_frame(&wrong_kind),
        Err(HandshakeDecodeError::WrongMessageKind(MessageKind::Request))
    );

    // Mutate one bounded byte selected by the input so the decoder also sees
    // arbitrary structured-handshake damage without an unchecked index.
    if let Some(first) = data.first().copied() {
        let mut fuzzed = valid_frame.payload.clone();
        let index = usize::from(first) % fuzzed.len();
        fuzzed[index] ^= data.get(1).copied().unwrap_or(1).max(1);
        let _ = Handshake::decode_payload(&fuzzed);
    }
}

fn exercise_malformed_errors(codec: &FrameCodec) {
    assert!(matches!(
        RemoteError::decode_payload(&[]),
        Err(RemoteErrorDecodeError::Truncated { .. })
    ));

    let unknown_flags = vec![0, 1, 0x80, 0, 0];
    assert_eq!(
        RemoteError::decode_payload(&unknown_flags),
        Err(RemoteErrorDecodeError::UnknownFlags(0x80))
    );

    let length_mismatch = vec![0, 1, 0, 0, 1];
    assert!(matches!(
        RemoteError::decode_payload(&length_mismatch),
        Err(RemoteErrorDecodeError::LengthMismatch {
            declared: 1,
            actual: 0
        })
    ));

    let malformed_utf8 = vec![0, 1, 0, 0, 1, 0xff];
    assert_eq!(
        RemoteError::decode_payload(&malformed_utf8),
        Err(RemoteErrorDecodeError::MalformedUtf8)
    );

    let mut too_long = vec![0, 1, 0, 0, 0];
    too_long[3..5].copy_from_slice(
        &u16::try_from(4097)
            .expect("error bound fits u16")
            .to_be_bytes(),
    );
    assert!(matches!(
        RemoteError::decode_payload(&too_long),
        Err(RemoteErrorDecodeError::MessageTooLong { declared: 4097, .. })
    ));

    let wrong_kind = Frame::new(MessageKind::Request, 1, Vec::new());
    assert_eq!(
        codec.decode_remote_error(&wrong_kind),
        Err(RemoteErrorDecodeError::WrongMessageKind(
            MessageKind::Request
        ))
    );

    let malformed_frame = Frame::new(MessageKind::Error, 1, unknown_flags);
    let encoded = codec
        .encode(&malformed_frame)
        .expect("malformed structured error still has a valid frame envelope");
    let decoded = codec
        .decode_exact(&encoded)
        .expect("malformed structured error envelope must decode");
    assert_eq!(
        codec.decode_remote_error(&decoded),
        Err(RemoteErrorDecodeError::UnknownFlags(0x80))
    );
}

fn validate_unknown_header_fields(codec: &FrameCodec) {
    let encoded = codec
        .encode(&Frame::new(MessageKind::Request, 1, Vec::new()))
        .expect("synthetic request must satisfy codec bounds");

    let mut unknown_kind = encoded.clone();
    unknown_kind[5] = 0xff;
    if codec.decode(&unknown_kind) != Err(DecodeError::UnknownMessageKind(0xff)) {
        panic!("bridge accepted an unknown message kind");
    }

    let mut unknown_flags = encoded;
    unknown_flags[6] = 0x80;
    if codec.decode(&unknown_flags) != Err(DecodeError::UnknownFlags(0x8000)) {
        panic!("bridge accepted an unknown frame flag");
    }
}

fuzz_target!(|data: &[u8]| {
    let codec = FrameCodec::new(MAX_PAYLOAD_BYTES);

    round_trip_handshake(&codec);
    exercise_unsupported_preservation(data);
    validate_unknown_header_fields(&codec);
    exercise_valid_binary_frames(&codec);
    exercise_malformed_binary_frames(&codec);
    exercise_malformed_handshakes(data);
    exercise_malformed_errors(&codec);

    if data.len() > MAX_INPUT_BYTES {
        // Decode the complete supplied input so the protocol observes its own
        // frame limit.  In particular, do not truncate a declared payload at
        // the fuzz target boundary.
        match codec.decode_with_policy(data, TrailingPolicy::Reject) {
            Err(_) | Ok(DecodeResult::Incomplete { .. }) => {}
            Ok(DecodeResult::Complete { .. }) => {
                panic!("oversized bridge input was accepted as one complete frame")
            }
        }
        return;
    }

    // Any complete input frame must preserve every decoded header and its
    // exact consumed prefix, including metadata unknown to the payload path.
    if let Ok(DecodeResult::Complete { frame, consumed }) = codec.decode(data) {
        let prefix = &data[..consumed];
        let exact = codec
            .decode_exact(prefix)
            .expect("complete bridge prefix was not accepted by exact decode");
        if exact != frame {
            panic!("exact bridge decode changed a complete frame");
        }
        round_trip(&codec, &frame);
    }

    if data.len() > MAX_PAYLOAD_BYTES {
        // The synthetic path has no permission to truncate arbitrary bytes.
        return;
    }
    let payload = data.to_vec();

    let handshake = Frame::new(MessageKind::Handshake, 0, payload.clone())
        .with_deadline(Deadline::at_unix_millis(1_700_000_000_000))
        .with_profile("jmeter-5.6.3")
        .with_capabilities(vec!["jmx".to_owned(), "jtl".to_owned()]);
    round_trip(&codec, &handshake);

    let request_id = u64::try_from(data.len())
        .ok()
        .filter(|value| *value != 0)
        .unwrap_or(1);
    let request = Frame::new(MessageKind::Request, request_id, payload.clone())
        .with_deadline(Deadline::at_unix_millis(1_700_000_000_001))
        .with_cancellation(Cancellation::Requested)
        .with_profile("jmeter-5.6.3")
        .with_capabilities(vec!["jmx".to_owned(), "bridge.v1".to_owned()]);
    round_trip(&codec, &request);

    let response = Frame::new(MessageKind::Response, request_id, payload.clone())
        .with_deadline(Deadline::at_unix_millis(1_700_000_000_002))
        .with_cancellation(Cancellation::Cancelled);
    round_trip(&codec, &response);

    let cancel = Frame::new(MessageKind::Cancel, request_id, payload)
        .with_deadline(Deadline::at_unix_millis(1_700_000_000_003))
        .with_cancellation(Cancellation::Requested);
    round_trip(&codec, &cancel);

    let remote_error = RemoteError::new(
        RemoteErrorCode::Unknown(0x4321),
        true,
        "synthetic bridge error",
    );
    let error = codec
        .error_frame(request_id, remote_error.clone())
        .expect("synthetic remote error must satisfy codec bounds");
    round_trip(&codec, &error);
    let decoded_error = codec
        .decode_remote_error(&error)
        .expect("synthetic remote error payload must decode");
    if decoded_error != remote_error {
        panic!("bridge remote-error metadata changed during round-trip");
    }
});
