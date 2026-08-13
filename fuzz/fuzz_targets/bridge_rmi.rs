#![no_main]

//! Pure RMI stream codec/state-machine fuzz target.
//!
//! This target deliberately stops at the Rust-native `bridge-protocol::rmi`
//! contract.  It does not load Java classes, create an RMI transport, start a
//! process, or open a socket.  The generated traces cover the fields that are
//! present in the version-1 schema: lifecycle overload/host presence, sender
//! modes, independent callback and delivery ordinals, ProcessBatch item
//! sequences, two-dimensional queue credit, acknowledgements, terminal proof,
//! replay/gap rejection, remaining-duration propagation, and resource caps.
//!
//! The revision-3 architecture describes additional helper observations (for
//! example statistical-correlation details) that are not separate fields in
//! this Rust schema.  `SenderMode::Statistical` and the existing stream
//! accounting are therefore exercised here without manufacturing a field or
//! silently treating an absent field as supported.
//!
//! Invariants: `BRIDGE-RMI-CODEC-001` preserves complete message fields and
//! incremental frame boundaries; `BRIDGE-RMI-STATE-001` covers lifecycle,
//! ordinals, sender modes, replay/gap, and terminal ordering;
//! `BRIDGE-RMI-BACKPRESSURE-001` covers two-dimensional credit/ack admission;
//! and `BRIDGE-RMI-LIMIT-001` rejects bounded malformed, oversized, and deep
//! state inputs.
//! Source-side coverage: generated message fields, callback/delivery ordinals,
//! queue credits, terminal proof, and bounded error inputs are the independent
//! state/property inventory for this target.
//! I/O policy: none; this target stays on the in-memory Rust RMI codec/state.

use jmeter_rs_bridge_protocol::Cancellation;
use jmeter_rs_bridge_protocol::rmi::RmiRole;
use jmeter_rs_bridge_protocol::rmi::{
    Ack, ArtifactIdentity, BackpressurePolicy, Batch, BatchItem, BridgeIdentity, Capability,
    Credit, DeliveryKind, FailurePhase, HostPresence, JtlMetadata, LifecycleOverload,
    OutcomeCertainty, Preservation, ProfileIdentity, QueueAdmission, QueueCredit, QueueError,
    QueueState, RemainingDuration, RetryDisposition, RetryPhase, RmiCodec, RmiDecodeResult,
    RmiLimits, RmiTrailingPolicy, SampleEvent, SampleEventSnapshot, SampleOccurred, SampleStarted,
    SampleStopOutcome, SampleStopped, SchemaVersion, SenderDrainEvidence, SenderDrainProof,
    SenderMode, Sha256Digest, Sha512Digest, StreamAcceptance, StreamEvent, StreamMessage,
    StreamState, StreamStateError, Terminal, TerminalStatus, TestEnded, TestEndedAbsenceReason,
    TestStarted, WireSampleResult, WorkerFailure, WorkerFailureCode,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 256 * 1024;
const MAX_STEPS: usize = 96;
const RUN_ID: &str = "fuzz-run";
const WORKER_ID: &str = "worker-1";

// Compile-time references to the closed schema keep this target honest if a
// future edit removes a surface it is meant to cover.  These are not claims
// that the Rust crate implements Java-side revision-3 behavior.
const _: SenderMode = SenderMode::Statistical;
const _: DeliveryKind = DeliveryKind::ProcessBatch;
const _: TerminalStatus = TerminalStatus::ProtocolError;

fn limits() -> RmiLimits {
    RmiLimits {
        max_frame_bytes: 64 * 1024,
        max_string_bytes: 256,
        max_bytes_field: 4096,
        max_event_count: 128,
        max_batch_items: 8,
        max_sample_depth: 8,
        max_sample_nodes: 64,
        max_assertions: 8,
        max_variables: 8,
        max_attributes: 8,
        max_children: 8,
        max_dependencies: 4,
        max_capabilities: 4,
        max_queue_credits: 32,
        max_operation_duration_millis: 60_000,
        max_stream_events: 128,
        max_stream_bytes: 64 * 1024,
    }
}

fn digest256(value: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([value; 32])
}

fn digest512(value: u8) -> Sha512Digest {
    Sha512Digest::from_bytes([value; 64])
}

fn identity() -> BridgeIdentity {
    BridgeIdentity {
        profile: ProfileIdentity::new("jmeter-5.6.3", 1, digest256(0x11)),
        artifact: ArtifactIdentity {
            jmeter_archive_sha512: digest512(0x22),
            jmeter_source_commit: "pinned-source".to_owned(),
            helper_source_sha256: digest256(0x33),
            helper_build_sha256: digest256(0x44),
            java_compiler: "pinned-java".to_owned(),
            java_runtime: "pinned-runtime".to_owned(),
            jmeter_rs_commit: "pinned-rs".to_owned(),
            platform_profile: "test-platform".to_owned(),
            target: "x86_64-unknown-linux-gnu".to_owned(),
            os: "test-os".to_owned(),
            dependencies: Vec::new(),
        },
        role: RmiRole::Worker,
        worker_id: WORKER_ID.to_owned(),
        capabilities: vec![Capability::new("rmi.v1", "1")],
        preservation: Preservation::default(),
    }
}

fn queue(limits: RmiLimits, available: u64, bytes_available: u64) -> QueueCredit {
    QueueCredit {
        capacity: 16,
        available,
        bytes_capacity: limits.max_frame_bytes as u64,
        bytes_available,
    }
}

fn host_for(overload: LifecycleOverload, selector: u8) -> HostPresence {
    match overload {
        LifecycleOverload::NoHost => HostPresence::Absent,
        LifecycleOverload::HostArgument if selector & 1 == 0 => HostPresence::Null,
        LifecycleOverload::HostArgument => HostPresence::Present("fuzz-host".to_owned()),
    }
}

fn started_event(sample_id: u64, callback: u64, delivered: u64) -> SampleEvent {
    SampleEvent::Started(SampleStarted {
        callback_invocation_ordinal: callback,
        delivered_event_ordinal: delivered,
        delivery_kind: DeliveryKind::SampleOccurred,
        sample_id,
        parent_id: None,
        label: Some("fuzz-sample".to_owned()),
        snapshot: SampleEventSnapshot::default(),
    })
}

fn occurred_event(sample_id: u64, callback: u64, delivered: u64) -> SampleEvent {
    SampleEvent::Occurred(SampleOccurred {
        callback_invocation_ordinal: callback,
        delivered_event_ordinal: delivered,
        delivery_kind: DeliveryKind::SampleOccurred,
        sample_id,
        result: WireSampleResult {
            label: Some("fuzz-result".to_owned()),
            success: Some(true),
            jtl: JtlMetadata::default(),
            ..WireSampleResult::default()
        },
        snapshot: SampleEventSnapshot::default(),
    })
}

fn stopped_event(sample_id: u64, callback: u64, delivered: u64) -> SampleEvent {
    SampleEvent::Stopped(SampleStopped {
        callback_invocation_ordinal: callback,
        delivered_event_ordinal: delivered,
        delivery_kind: DeliveryKind::SampleOccurred,
        sample_id,
        outcome: SampleStopOutcome::Completed,
        cancellation: Cancellation::None,
        snapshot: SampleEventSnapshot::default(),
    })
}

fn batch_item(sequence: u64, request_id: u64, event: SampleEvent) -> BatchItem {
    BatchItem {
        sequence,
        request_id,
        remaining_duration: RemainingDuration::from_millis(250),
        cancellation: Cancellation::None,
        event: match event {
            SampleEvent::Started(mut value) => {
                value.callback_invocation_ordinal = 0;
                value.delivered_event_ordinal = 0;
                value.delivery_kind = DeliveryKind::ProcessBatch;
                SampleEvent::Started(value)
            }
            SampleEvent::Occurred(mut value) => {
                value.callback_invocation_ordinal = 0;
                value.delivered_event_ordinal = 0;
                value.delivery_kind = DeliveryKind::ProcessBatch;
                SampleEvent::Occurred(value)
            }
            SampleEvent::Stopped(mut value) => {
                value.callback_invocation_ordinal = 0;
                value.delivered_event_ordinal = 0;
                value.delivery_kind = DeliveryKind::ProcessBatch;
                SampleEvent::Stopped(value)
            }
        },
    }
}

fn message(sequence: u64, request_id: u64, event: StreamEvent) -> StreamMessage {
    StreamMessage::new(
        SchemaVersion::V1,
        RUN_ID,
        WORKER_ID,
        1,
        sequence,
        request_id,
        event,
    )
}

fn with_budget(mut value: StreamMessage, selector: u8) -> StreamMessage {
    value = value.with_remaining_duration(if selector & 1 == 0 {
        RemainingDuration::NONE
    } else {
        RemainingDuration::from_millis(u64::from(selector))
    });
    if selector & 2 != 0 {
        value = value.with_diagnostic_wall_time(1_700_000_000_000 + u64::from(selector));
    }
    if selector & 4 != 0 {
        value = value.with_cancellation(Cancellation::Requested);
    }
    value
}

fn round_trip(codec: &RmiCodec, value: &StreamMessage) -> Vec<u8> {
    let encoded = codec
        .encode(value)
        .expect("synthetic RMI message must satisfy its negotiated limits");
    let decoded = codec
        .decode_exact(&encoded)
        .expect("RMI codec rejected its own complete message");
    assert_eq!(decoded, *value, "RMI codec changed a complete message");

    let mut joined = encoded.clone();
    joined.extend_from_slice(&encoded);
    let mut input = joined.as_slice();
    let first = codec
        .decode_next(&mut input)
        .expect("first incremental RMI decode failed")
        .expect("first incremental RMI message was incomplete");
    let second = codec
        .decode_next(&mut input)
        .expect("second incremental RMI decode failed")
        .expect("second incremental RMI message was incomplete");
    assert_eq!(first, *value);
    assert_eq!(second, *value);
    assert!(
        input.is_empty(),
        "incremental RMI decode left trailing bytes"
    );
    encoded
}

fn ready_message(sender: SenderMode, limits: RmiLimits) -> StreamMessage {
    message(
        1,
        1,
        StreamEvent::Ready(jmeter_rs_bridge_protocol::rmi::Ready {
            identity: identity(),
            sender,
            queue: queue(limits, 16, limits.max_frame_bytes as u64),
            backpressure: BackpressurePolicy::WaitUntilDeadline,
        }),
    )
}

fn test_started_message(
    overload: LifecycleOverload,
    selector: u8,
    limits: RmiLimits,
) -> StreamMessage {
    message(
        2,
        2,
        StreamEvent::TestStarted(TestStarted {
            overload,
            host: host_for(overload, selector),
            callback_invocation_ordinal: 1,
            test_id: "fuzz-test".to_owned(),
            plan_sha256: digest256(0x55),
            queue: queue(limits, 15, limits.max_frame_bytes as u64),
        }),
    )
}

fn run_trace(sender: SenderMode, use_batch: bool, selector: u8) {
    let limits = limits();
    let codec = RmiCodec::new(limits).expect("fuzz limits are valid");
    let overload = if selector & 8 == 0 {
        LifecycleOverload::NoHost
    } else {
        LifecycleOverload::HostArgument
    };
    let mut state = StreamState::new(RUN_ID, WORKER_ID, 1, limits).expect("state is constructible");

    let ready = with_budget(ready_message(sender, limits), selector);
    let started = with_budget(
        test_started_message(overload, selector, limits),
        selector.rotate_left(1),
    );
    round_trip(&codec, &ready);
    round_trip(&codec, &started);
    assert_eq!(state.accept(&ready), Ok(StreamAcceptance::Accepted));
    assert_eq!(state.accept(&started), Ok(StreamAcceptance::Accepted));

    if use_batch {
        let batch = Batch {
            sender,
            callback_invocation_ordinal: 2,
            first_delivered_event_ordinal: 1,
            batch_id: 1,
            delivery_kind: DeliveryKind::ProcessBatch,
            event_count: 3,
            items: vec![
                batch_item(3, 3, started_event(100, 0, 0)),
                batch_item(4, 4, occurred_event(100, 0, 0)),
                batch_item(5, 5, stopped_event(100, 0, 0)),
            ],
        };
        let value = with_budget(message(3, 6, StreamEvent::Batch(batch)), selector);
        round_trip(&codec, &value);
        assert_eq!(state.accept(&value), Ok(StreamAcceptance::Accepted));
    } else {
        let values = [
            with_budget(
                message(
                    3,
                    3,
                    StreamEvent::SampleStarted(match started_event(100, 2, 1) {
                        SampleEvent::Started(value) => value,
                        _ => unreachable!("started_event has a stable variant"),
                    }),
                ),
                selector,
            ),
            with_budget(
                message(
                    4,
                    4,
                    StreamEvent::SampleOccurred(match occurred_event(100, 3, 2) {
                        SampleEvent::Occurred(value) => value,
                        _ => unreachable!("occurred_event has a stable variant"),
                    }),
                ),
                selector.rotate_left(2),
            ),
            with_budget(
                message(
                    5,
                    5,
                    StreamEvent::SampleStopped(match stopped_event(100, 4, 3) {
                        SampleEvent::Stopped(value) => value,
                        _ => unreachable!("stopped_event has a stable variant"),
                    }),
                ),
                selector.rotate_left(3),
            ),
        ];
        for value in &values {
            round_trip(&codec, value);
            assert_eq!(state.accept(value), Ok(StreamAcceptance::Accepted));
        }
    }

    let accounting = state.accounting();
    assert!(accounting.accepted_events > 0);
    assert!(accounting.accepted_bytes > 0);
    let ack_sequence = state.next_sequence() - 1;
    let ack = with_budget(
        message(
            state.next_sequence(),
            1000,
            StreamEvent::Ack(Ack {
                acknowledged_sequence: ack_sequence,
                acknowledged_events: accounting.accepted_events,
                acknowledged_bytes: accounting.accepted_bytes,
            }),
        ),
        selector.rotate_left(4),
    );
    round_trip(&codec, &ack);
    assert_eq!(state.accept(&ack), Ok(StreamAcceptance::Accepted));

    let credit = with_budget(
        message(
            state.next_sequence(),
            1001,
            StreamEvent::Credit(Credit {
                queue: queue(limits, 16, limits.max_frame_bytes as u64),
            }),
        ),
        selector.rotate_left(5),
    );
    round_trip(&codec, &credit);
    assert_eq!(state.accept(&credit), Ok(StreamAcceptance::Accepted));

    exercise_replay_and_gap(&codec, &state, &credit);

    let ended_sequence = state.next_sequence();
    let accounting = state.accounting();
    let ended = with_budget(
        message(
            ended_sequence,
            1002,
            StreamEvent::TestEnded(TestEnded {
                overload,
                host: host_for(overload, selector.rotate_left(1)),
                callback_invocation_ordinal: state.next_callback_invocation_ordinal(),
                accounting,
                queue: queue(limits, 16, limits.max_frame_bytes as u64),
            }),
        ),
        selector.rotate_left(6),
    );
    round_trip(&codec, &ended);
    assert_eq!(state.accept(&ended), Ok(StreamAcceptance::Accepted));

    let accounting = state.accounting();
    let terminal = with_budget(
        message(
            state.next_sequence(),
            1003,
            StreamEvent::Terminal(Terminal {
                status: TerminalStatus::Succeeded,
                failure: None,
                accounting,
                sender_proof: SenderDrainProof::Proven(SenderDrainEvidence {
                    sender,
                    generation: 1,
                    final_delivered_event_ordinal: state.next_delivered_event_ordinal() - 1,
                    emitted_events: accounting.delivered_events,
                    accepted_events: accounting.accepted_events,
                    acknowledged_events: accounting.acknowledged_events,
                    emitted_bytes: accounting.delivered_bytes,
                    accepted_bytes: accounting.accepted_bytes,
                    acknowledged_bytes: accounting.acknowledged_bytes,
                    pending_sender_events: 0,
                    pending_disk_events: 0,
                    completion_hook: "fuzz-completion".to_owned(),
                    proof_digest: digest256(0x66),
                }),
                test_ended_callback_ordinal: Some(state.next_callback_invocation_ordinal() - 1),
                test_ended_absence_reason: None,
                router_finalization_digest: Some(digest256(0x77)),
                queue: queue(limits, 16, limits.max_frame_bytes as u64),
            }),
        ),
        selector.rotate_left(7),
    );
    round_trip(&codec, &terminal);
    assert_eq!(
        state.accept(&terminal),
        Ok(StreamAcceptance::TerminalAccepted)
    );
    assert!(state.is_terminal());

    let duplicate = terminal.clone();
    assert!(matches!(
        state.accept(&duplicate),
        Err(StreamStateError::DuplicateOrReplay { .. })
    ));
}

fn exercise_replay_and_gap(codec: &RmiCodec, state: &StreamState, accepted: &StreamMessage) {
    let mut replay = accepted.clone();
    replay.sequence = state.next_sequence() - 1;
    assert!(matches!(
        state.clone().accept(&replay),
        Err(StreamStateError::DuplicateOrReplay { .. })
    ));
    let mut gap = accepted.clone();
    gap.sequence = state.next_sequence() + 1;
    gap.request_id = 2000;
    let _ = codec.encode(&gap);
    assert!(matches!(
        state.clone().accept(&gap),
        Err(StreamStateError::OutOfOrder { .. })
    ));
}

fn failure_message(selector: u8) -> StreamMessage {
    message(
        3,
        3,
        StreamEvent::WorkerFailure(WorkerFailure {
            worker_id: WORKER_ID.to_owned(),
            code: if selector & 1 == 0 {
                WorkerFailureCode::Protocol
            } else {
                WorkerFailureCode::QueueFull
            },
            phase: FailurePhase::Failed,
            retry: RetryDisposition::FinalNonRetryable {
                phase: RetryPhase::Callback,
                outcome_certainty: OutcomeCertainty::Started,
            },
            message: Some("redacted synthetic diagnostic".to_owned()),
        }),
    )
}

fn exercise_failure_terminals(data: &[u8]) {
    let limits = limits();
    let codec = RmiCodec::with_limits(limits);
    let started = with_budget(
        test_started_message(LifecycleOverload::NoHost, 0, limits),
        data.first().copied().unwrap_or(0),
    );
    let failure = with_budget(failure_message(data.get(1).copied().unwrap_or(0)), 0);
    let encoded_failure = codec
        .encode(&failure)
        .expect("bounded failure should encode");
    let debug = format!("{:?}", failure);
    assert!(
        !debug.contains("redacted synthetic diagnostic"),
        "WorkerFailure debug output leaked diagnostic text"
    );
    assert!(!encoded_failure.is_empty());

    let terminal_statuses = [
        TerminalStatus::Failed,
        TerminalStatus::Cancelled,
        TerminalStatus::TimedOut,
        TerminalStatus::ProtocolError,
        TerminalStatus::Crashed,
        TerminalStatus::Aborted,
    ];
    for (index, status) in terminal_statuses.into_iter().enumerate() {
        let mut state = StreamState::new(RUN_ID, WORKER_ID, 1, limits).expect("state is valid");
        let ready = ready_message(SenderMode::Standard, limits);
        assert_eq!(state.accept(&ready), Ok(StreamAcceptance::Accepted));
        if index == 0 {
            assert_eq!(state.accept(&started), Ok(StreamAcceptance::Accepted));
            assert_eq!(state.accept(&failure), Ok(StreamAcceptance::Accepted));
        }
        let accounting = state.accounting();
        let terminal = message(
            state.next_sequence(),
            3000 + u64::try_from(index).expect("small terminal index"),
            StreamEvent::Terminal(Terminal {
                status,
                failure: if index == 0 {
                    Some(match &failure.event {
                        StreamEvent::WorkerFailure(value) => value.clone(),
                        _ => unreachable!("failure message has a failure event"),
                    })
                } else {
                    None
                },
                accounting,
                sender_proof: SenderDrainProof::Unavailable {
                    sender: SenderMode::Standard,
                    reason: match status {
                        TerminalStatus::Cancelled => {
                            jmeter_rs_bridge_protocol::rmi::SenderProofAbsenceReason::Cancelled
                        }
                        TerminalStatus::TimedOut => {
                            jmeter_rs_bridge_protocol::rmi::SenderProofAbsenceReason::TimedOut
                        }
                        TerminalStatus::Crashed => {
                            jmeter_rs_bridge_protocol::rmi::SenderProofAbsenceReason::WorkerCrashed
                        }
                        _ => jmeter_rs_bridge_protocol::rmi::SenderProofAbsenceReason::SenderFailed,
                    },
                },
                test_ended_callback_ordinal: None,
                test_ended_absence_reason: Some(match status {
                    TerminalStatus::Cancelled => TestEndedAbsenceReason::CancelledBeforeCallback,
                    TerminalStatus::TimedOut => TestEndedAbsenceReason::TimedOutBeforeCallback,
                    TerminalStatus::Crashed => TestEndedAbsenceReason::CrashedBeforeCallback,
                    TerminalStatus::Aborted => TestEndedAbsenceReason::AbortedBeforeCallback,
                    _ => TestEndedAbsenceReason::WorkerFailure,
                }),
                router_finalization_digest: None,
                queue: queue(limits, 16, limits.max_frame_bytes as u64),
            }),
        );
        assert!(codec.encode(&terminal).is_ok());
        assert_eq!(
            state.accept(&terminal),
            Ok(StreamAcceptance::TerminalAccepted)
        );
    }
}

fn exercise_backpressure(data: &[u8]) {
    let limits = limits();
    let policies = [
        BackpressurePolicy::Reject,
        BackpressurePolicy::WaitUntilDeadline,
        BackpressurePolicy::DrainThenReject,
    ];
    for (index, policy) in policies.into_iter().enumerate() {
        let mut queue = QueueState::new(QueueCredit::new(2, 32), policy, limits)
            .expect("synthetic queue credit is valid");
        assert_eq!(
            queue.try_accept(
                16 + usize::from(data.get(index).copied().unwrap_or(0) & 3),
                limits
            ),
            Ok(QueueAdmission::Accepted)
        );
        let before_full = queue.credit;
        let admission = queue.try_accept(17, limits);
        if admission == Ok(QueueAdmission::Full) {
            assert_eq!(
                queue.credit, before_full,
                "full queue dropped or consumed credit"
            );
        }
        let _ = queue.credit.release(16, limits);
        queue.close();
        assert_eq!(queue.try_accept(1, limits), Err(QueueError::Closed));
        queue.cancel();
        assert_eq!(queue.try_accept(1, limits), Err(QueueError::Cancelled));
    }
}

fn exercise_bounds_and_metadata(data: &[u8]) {
    let limits = limits();
    let codec = RmiCodec::with_limits(limits);
    let valid = ready_message(SenderMode::Standard, limits);
    let encoded = codec.encode(&valid).expect("ready message should encode");

    let mut malformed = encoded.clone();
    malformed[0] ^= data.first().copied().unwrap_or(0).max(1);
    let _ = codec.decode_exact(&malformed);
    let mut unsupported_wire = encoded.clone();
    unsupported_wire[4] = 0xff;
    assert!(codec.decode_exact(&unsupported_wire).is_err());
    let mut unsupported_schema = encoded.clone();
    unsupported_schema[10] = 0;
    unsupported_schema[11] = 2;
    assert!(codec.decode_exact(&unsupported_schema).is_err());
    let mut unknown_flags = encoded.clone();
    unknown_flags[12] = 0;
    unknown_flags[13] = 1;
    assert!(codec.decode_exact(&unknown_flags).is_err());
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(matches!(
        codec.decode_with_policy(&trailing, RmiTrailingPolicy::Reject),
        Err(jmeter_rs_bridge_protocol::rmi::RmiDecodeError::TrailingBytes { .. })
    ));

    let overlong = StreamMessage::new(
        SchemaVersion::V1,
        "x".repeat(limits.max_string_bytes + 1),
        WORKER_ID,
        1,
        1,
        1,
        StreamEvent::Ready(jmeter_rs_bridge_protocol::rmi::Ready {
            identity: identity(),
            sender: SenderMode::Standard,
            queue: queue(limits, 16, limits.max_frame_bytes as u64),
            backpressure: BackpressurePolicy::Reject,
        }),
    );
    assert!(overlong.validate(limits).is_err());

    let mut deep = WireSampleResult::default();
    for _ in 0..=limits.max_sample_depth {
        deep = WireSampleResult {
            sub_results: vec![deep],
            ..WireSampleResult::default()
        };
    }
    let deep_message = message(
        1,
        1,
        StreamEvent::SampleOccurred(SampleOccurred {
            callback_invocation_ordinal: 1,
            delivered_event_ordinal: 1,
            delivery_kind: DeliveryKind::SampleOccurred,
            sample_id: 1,
            result: deep,
            snapshot: SampleEventSnapshot::default(),
        }),
    );
    assert!(deep_message.validate(limits).is_err());

    let mut oversized_batch = Vec::new();
    for index in 0..=limits.max_batch_items {
        let id = u64::try_from(index + 1).expect("bounded batch index");
        oversized_batch.push(batch_item(id, id, started_event(id, 0, 0)));
    }
    let batch_message = message(
        1,
        100,
        StreamEvent::Batch(Batch {
            sender: SenderMode::Standard,
            callback_invocation_ordinal: 1,
            first_delivered_event_ordinal: 1,
            batch_id: 1,
            delivery_kind: DeliveryKind::ProcessBatch,
            event_count: u64::try_from(oversized_batch.len()).expect("bounded batch count"),
            items: oversized_batch,
        }),
    );
    assert!(batch_message.validate(limits).is_err());

    let mut invalid_limits = limits;
    invalid_limits.max_frame_bytes = jmeter_rs_bridge_protocol::rmi::MAX_RMI_FRAME_BYTES + 1;
    assert!(RmiCodec::new(invalid_limits).is_err());
    let mut raw = data.to_vec();
    if raw.len() <= MAX_INPUT_BYTES {
        raw.extend_from_slice(&encoded);
        let _ = codec.decode_with_policy(&raw, RmiTrailingPolicy::Allow);
    }
}

fn exercise_arbitrary_codec_input(data: &[u8]) {
    let codec = RmiCodec::with_limits(limits());
    match codec.decode(data) {
        Ok(RmiDecodeResult::Incomplete { .. }) | Err(_) => {}
        Ok(RmiDecodeResult::Complete { message, consumed }) => {
            assert!(consumed <= data.len());
            let prefix = &data[..consumed];
            let exact = codec
                .decode_exact(prefix)
                .expect("complete RMI prefix must exact-decode");
            assert_eq!(exact, message);
            let _ = codec.encode(&message);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    // Codec parsing is itself bounded by the negotiated frame cap.  Keep the
    // generated state traces finite even when a harness supplies a very large
    // input buffer.
    let bounded = &data[..data.len().min(MAX_INPUT_BYTES)];
    exercise_arbitrary_codec_input(data);
    exercise_bounds_and_metadata(bounded);
    exercise_backpressure(bounded);
    exercise_failure_terminals(bounded);

    let selector = bounded.first().copied().unwrap_or(0);
    let sender_modes = [
        SenderMode::Standard,
        SenderMode::Batch,
        SenderMode::Statistical,
        SenderMode::Stripped,
        SenderMode::StrippedBatch,
        SenderMode::Asynch,
        SenderMode::StrippedAsynch,
        SenderMode::DiskStore,
        SenderMode::StrippedDiskStore,
    ];
    for (index, sender) in sender_modes.into_iter().enumerate() {
        if index >= MAX_STEPS {
            break;
        }
        let byte = bounded.get(index + 1).copied().unwrap_or(selector);
        run_trace(
            sender,
            (byte ^ selector) & 1 != 0,
            byte.rotate_left((index % 8) as u32),
        );
    }
});
