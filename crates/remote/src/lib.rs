// SPDX-License-Identifier: Apache-2.0
//! Rust-native remote execution protocol and orchestration boundary.
//!
//! The public API is intentionally transport-neutral. It models the bounded
//! versioned messages, deterministic coordinator/worker lifecycle, sample
//! sender backpressure, thread multiplication, plan-only transfer, and
//! idempotent result collection required by the distributed compatibility
//! surface. It is not Java RMI and never opens a socket or starts a process.
//!
//! Wire envelopes do not serialize deadlines or cancellation. A transport
//! adapter must retain [`RemoteRequestContext`] alongside encoded bytes and use [`RemoteCodec::encode_for_adapter`],
//! [`RemoteCodec::decode_for_adapter`], and the state-machine `*_with_context`
//! methods. Omitting that context returns
//! [`RemoteErrorCode::ContextUnavailable`].

#![forbid(unsafe_code)]

mod error;
mod protocol;
mod sender;
mod state;

pub use error::{MAX_WIRE_FAILURE_MESSAGE_BYTES, ProtocolError, RemoteError, RemoteErrorCode};
pub use protocol::{
    AckStage, Cancellation, Codec, DEFAULT_MAX_FIELD_BYTES, DEFAULT_MAX_MESSAGE_BYTES,
    DataReference, Deadline, DependencyReference, Envelope, FailurePolicy,
    MAX_REMOTE_PROTOCOL_VERSION, Message, MessageKind, Plan, PlanDescriptor, Profile,
    ProfileDescriptor, Properties, PropertySet, REMOTE_HEADER_LEN, REMOTE_MAGIC,
    REMOTE_PROTOCOL_VERSION, RESULT_WIRE_METADATA_CAPABILITY, RemoteCancellation, RemoteCodec,
    RemoteConfigurationLimits, RemoteDeadline, RemoteEnvelope, RemoteLimits, RemoteMessage,
    RemoteRequestContext, RemoteSample, RequestId, RunId, SampleKey, SampleSenderMode, StopMode,
    WireLimits, WorkerId, is_sample_envelope_request_id, sample_envelope_request_id,
    sample_envelope_worker,
};
pub use sender::{
    CustomSenderDescriptor, DiskStore, ManualSenderScheduler, MemorySampleStore, SampleSender,
    SampleStore, SendOutcome, SenderConfig, SenderDescriptor, SenderScheduler, StatisticalKeyMode,
};
pub use state::{
    Coordinator, CoordinatorPhase, RecordOutcome, RemoteCoordinator, RemoteWorker, RetryPolicy,
    Worker, WorkerPhase, WorkerRecord, WorkerResources,
};

/// Compatibility aliases for integrations that call a sample sender mode a
/// backpressure mode.
pub type BackpressureMode = SampleSenderMode;
/// Compatibility alias for a worker-side sample value.
pub type Sample = RemoteSample;
