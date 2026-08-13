// SPDX-License-Identifier: Apache-2.0
//! Concrete Rust-native HTTP transport edge.
//!
//! The first materialized capability is deliberately small: one direct,
//! plain HTTP/1.1 attempt with explicit limits and close-delimited framing.
//! TLS, proxy routing, HTTP/2, transparent retries, and decompression are
//! separate capabilities and fail closed during transport preflight.
//!
//! Native V2 subordinate identities are exported with their exact policy
//! names: `http.dns.explicit/1` and `http.tls.explicit-rustls-ring/1`.
//! The enclosing `http.native/2` identity is defined only by `transport_v2`.

#![forbid(unsafe_code)]

pub mod decompression;
pub mod dns;
pub mod dns_hickory;
pub mod pool;
mod provider;
pub mod proxy;
pub mod tls;
pub mod transport_v2;
mod wire;

pub mod config;
pub mod transport;

pub use config::{DEFAULT_MAX_LINE_BYTES, NativeTransportLimits};
pub use dns::{
    CanonicalName, DNS_EXPLICIT_CAPABILITY_ID, DnsCancellationToken, DnsError, DnsErrorCode,
    DnsFuture, DnsQuery, DnsResolver, DnsResponse, FakeDnsOutcome, FakeDnsResolver,
    StaticDnsResolver,
};
pub use provider::NativeHttpTransport;
pub use tls::{
    AlpnPolicy, MAX_TLS_APPLICATION_BYTES, MAX_TLS_BUFFER_BYTES, MAX_TLS_CLIENT_CERTIFICATE_BYTES,
    MAX_TLS_CLIENT_CERTIFICATES, MAX_TLS_CLIENT_IDENTITY_BYTES, MAX_TLS_INPUT_BYTES,
    MAX_TLS_PRIVATE_KEY_BYTES, MAX_TLS_ROOT_BYTES, MAX_TLS_ROOT_CERTIFICATE_BYTES,
    MAX_TLS_ROOT_CERTIFICATES, MAX_TLS_TIMEOUT, NativeClientIdentity, NativeTlsConfig,
    NativeTlsConfigBuilder, NativeTlsStream, NativeTlsVersion, ServerNameKind, SniPolicy,
    TLS_EXPLICIT_RUSTLS_RING_CAPABILITY_ID, TlsDeadline, TlsError, TlsErrorCode, TlsIo,
    TlsIoAdapter, TlsNegotiated, TlsPhase, TlsProtocolVersion, TlsStream,
};
pub use transport::NativeTransport;
pub use transport_v2::NativeTransportV2;

/// Stable identity of the independently named native HTTP capability.
pub const CAPABILITY_ID: &str = "http.native/1";
