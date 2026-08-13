#![no_main]

//! Bounded remote codec and worker-state target.
//!
//! The remote crate is transport-neutral.  This target never opens a socket
//! or starts a worker; it exercises bounded envelope encoding/decoding and a
//! deterministic worker lifecycle using small synthetic events.
//!
//! Invariants: `REMOTE-CODEC-ROUNDTRIP-001` preserves each typed envelope;
//! `REMOTE-STATE-001` keeps profile/plan/property/start/sample state ordered;
//! and `REMOTE-BOUNDS-001` keeps payload, property, and sample limits finite.
//! Source-side coverage: envelope fields, property maps, plan bytes, and
//! worker lifecycle events are generated as an independent state inventory.
//! I/O policy: none; the transport-neutral codec and state machine are local.

use jmeter_rs_remote::{
    PlanDescriptor, ProfileDescriptor, PropertySet, ProtocolError, REMOTE_PROTOCOL_VERSION,
    RemoteCodec, RemoteEnvelope, RemoteLimits, RemoteMessage, RemoteWorker, SampleSenderMode,
    WorkerId, sample_envelope_request_id,
};
use jmeter_rs_results::{
    HostIdentity, SampleEvent, SampleResult, ThreadIdentity, VariableSnapshot,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 64 * 1024;
const MAX_FIELD_BYTES: usize = 4096;

fn bounded_text(data: &[u8]) -> String {
    String::from_utf8_lossy(&data[..data.len().min(MAX_FIELD_BYTES)]).into_owned()
}

fn event() -> SampleEvent {
    SampleEvent::new(
        SampleResult::new("fuzz"),
        "run",
        ThreadIdentity::new("thread"),
        HostIdentity::new("host"),
        VariableSnapshot::new(),
    )
}

fn expect_protocol_error<F>(codec: &RemoteCodec, bytes: &[u8], label: &str, predicate: F)
where
    F: FnOnce(&ProtocolError) -> bool,
{
    match codec.decode(bytes) {
        Err(error) if predicate(&error) => {}
        Err(error) => panic!("remote malformed {label} returned {error}"),
        Ok(_) => panic!("remote malformed {label} was accepted"),
    }
}

fn exercise_malformed_envelopes(codec: &RemoteCodec, envelope: &RemoteEnvelope) {
    let encoded = codec
        .encode(envelope)
        .expect("baseline remote envelope must encode");

    let mut invalid_magic = encoded.clone();
    invalid_magic[0] ^= 1;
    expect_protocol_error(codec, &invalid_magic, "magic", |error| {
        matches!(error, ProtocolError::InvalidMagic { .. })
    });

    let mut unsupported_version = encoded.clone();
    unsupported_version[4..6].copy_from_slice(&(REMOTE_PROTOCOL_VERSION + 1).to_be_bytes());
    expect_protocol_error(codec, &unsupported_version, "version", |error| {
        matches!(error, ProtocolError::UnsupportedVersion(_))
    });

    let mut unknown_kind = encoded.clone();
    unknown_kind[6] = u8::MAX;
    expect_protocol_error(codec, &unknown_kind, "kind", |error| {
        matches!(error, ProtocolError::UnknownMessageKind(u8::MAX))
    });

    let mut unknown_flags = encoded.clone();
    unknown_flags[7] = 1;
    expect_protocol_error(codec, &unknown_flags, "flags", |error| {
        matches!(error, ProtocolError::UnknownFlags(1))
    });

    let mut zero_request_id = encoded.clone();
    zero_request_id[8..16].fill(0);
    expect_protocol_error(codec, &zero_request_id, "request id", |error| {
        matches!(
            error,
            ProtocolError::InvalidValue {
                field: "request id",
                value: 0
            }
        )
    });

    let mut too_large = encoded.clone();
    too_large[16..20].copy_from_slice(&u32::MAX.to_be_bytes());
    expect_protocol_error(codec, &too_large, "declared length", |error| {
        matches!(error, ProtocolError::MessageTooLarge { .. })
    });

    let truncated = &encoded[..encoded.len() - 1];
    expect_protocol_error(codec, truncated, "truncated payload", |error| {
        matches!(error, ProtocolError::Incomplete { .. })
    });

    let mut trailing = encoded.clone();
    trailing.push(0);
    expect_protocol_error(codec, &trailing, "trailing bytes", |error| {
        matches!(error, ProtocolError::TrailingBytes { count: 1 })
    });
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }
    let text = bounded_text(data);
    let worker_id = WorkerId::new(7);
    let profile = ProfileDescriptor::new("jmeter-5.6.3", "fuzz");
    let mut properties = PropertySet::new();
    properties.insert("fuzz.property", text.clone());
    let plan = PlanDescriptor::new(data[..data.len().min(MAX_FIELD_BYTES)].to_vec());
    let limits = RemoteLimits::new(128 * 1024)
        .with_max_field_bytes(MAX_FIELD_BYTES)
        .with_max_plan_bytes(MAX_FIELD_BYTES)
        .with_max_properties(8)
        .with_max_references(8)
        .with_max_capabilities(8)
        .with_max_samples(8)
        .with_sample_limits(8, 64);
    let codec = RemoteCodec::new(limits);

    let control = [
        RemoteEnvelope::new(
            1,
            RemoteMessage::Profile {
                profile: profile.clone(),
            },
        ),
        RemoteEnvelope::new(2, RemoteMessage::Plan { plan: plan.clone() }),
        RemoteEnvelope::new(
            3,
            RemoteMessage::Properties {
                properties: properties.clone(),
            },
        ),
        RemoteEnvelope::new(
            4,
            RemoteMessage::Start {
                run_id: 9,
                thread_count: 1,
                sender_mode: SampleSenderMode::Standard,
            },
        ),
        RemoteEnvelope::new(
            5,
            RemoteMessage::Ack {
                worker: worker_id,
                stage: jmeter_rs_remote::AckStage::Started,
                run_id: Some(9),
                thread_count: Some(1),
                sample_watermark: None,
            },
        ),
        RemoteEnvelope::new(
            6,
            RemoteMessage::Ack {
                worker: worker_id,
                stage: jmeter_rs_remote::AckStage::Stopped,
                run_id: Some(9),
                thread_count: Some(1),
                sample_watermark: Some(1),
            },
        ),
        RemoteEnvelope::new(
            7,
            RemoteMessage::Failure {
                worker: worker_id,
                run_id: Some(9),
                error: jmeter_rs_remote::RemoteError::new(
                    jmeter_rs_remote::RemoteErrorCode::WorkerFailure,
                    true,
                    "fuzz failure",
                ),
            },
        ),
    ];
    // REMOTE-CODEC-ROUNDTRIP-001 also requires malformed headers to produce
    // typed protocol errors rather than being accepted or silently ignored.
    exercise_malformed_envelopes(&codec, &control[0]);
    for envelope in control {
        let Ok(encoded) = codec.encode(&envelope) else {
            return;
        };
        let decoded = codec
            .decode(&encoded)
            .expect("remote codec must decode its output");
        if decoded != envelope {
            panic!("remote envelope changed during codec round-trip");
        }
    }

    let sample_id = sample_envelope_request_id(worker_id, 1).expect("sample ID bound");
    let sample = RemoteEnvelope::new(
        sample_id,
        RemoteMessage::Sample {
            sample: jmeter_rs_remote::RemoteSample::new(9, worker_id, 0, event()),
        },
    );
    let encoded = codec.encode(&sample).expect("bounded sample must encode");
    if codec.decode(&encoded).expect("bounded sample must decode") != sample {
        panic!("remote sample changed during codec round-trip");
    }

    let mut worker = RemoteWorker::new(worker_id, profile.clone());
    worker
        .apply(RemoteEnvelope::new(1, RemoteMessage::Profile { profile }))
        .expect("worker profile transition");
    worker
        .apply(RemoteEnvelope::new(2, RemoteMessage::Plan { plan }))
        .expect("worker plan transition");
    worker
        .apply(RemoteEnvelope::new(
            3,
            RemoteMessage::Properties { properties },
        ))
        .expect("worker properties transition");
    worker
        .apply(RemoteEnvelope::new(
            4,
            RemoteMessage::Start {
                run_id: 9,
                thread_count: 1,
                sender_mode: SampleSenderMode::Standard,
            },
        ))
        .expect("worker start transition");
    let emitted = worker
        .emit_sample(event())
        .expect("worker sample transition");
    for envelope in emitted {
        let bytes = codec
            .encode(&envelope)
            .expect("worker output must be bounded");
        codec.decode(&bytes).expect("worker output must decode");
    }
});
