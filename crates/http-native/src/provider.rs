// SPDX-License-Identifier: Apache-2.0
//! Explicit selection between the versioned native HTTP providers.
//!
//! The provider is deliberately an enum rather than a dynamically dispatched
//! transport.  A selected capability is immutable for the lifetime of this
//! value: dispatching a request can only reach the concrete implementation
//! stored in its selected variant.  In particular, registering a resolver or
//! TLS configuration on a V2 transport cannot upgrade a V1 value, and a V2
//! limitation cannot downgrade it to V1.

use crate::{DnsResolver, NativeTlsConfig};
use crate::{NativeTransport, NativeTransportLimits, NativeTransportV2};
use jmeter_rs_http::{
    Request, Response, Transport, TransportContext, TransportError, TransportResponse,
};
use std::sync::Arc;

/// The versioned native HTTP provider selected for an execution path.
///
/// The two variants intentionally retain their concrete transport types.  No
/// provider is inferred from request details and no failed operation is
/// retried through the other variant.
#[derive(Clone, Debug)]
pub enum NativeHttpTransport {
    /// Direct numeric-address plain HTTP/1.1 (`http.native/1`).
    V1(NativeTransport),
    /// Direct HTTP/1.1 with explicit DNS and optional explicit-root TLS
    /// (`http.native/2`).
    V2(NativeTransportV2),
}

impl NativeHttpTransport {
    /// Stable identity of the V1 native capability.
    pub const V1_CAPABILITY_ID: &'static str = "http.native/1";
    /// Stable identity of the V2 native capability.
    pub const V2_CAPABILITY_ID: &'static str = "http.native/2";

    /// Wraps an already validated V1 transport.
    #[must_use]
    pub fn v1(transport: NativeTransport) -> Self {
        Self::V1(transport)
    }

    /// Wraps an already validated V2 transport.
    #[must_use]
    pub fn v2(transport: NativeTransportV2) -> Self {
        Self::V2(transport)
    }

    /// Alias for [`Self::v1`] useful at provider-construction call sites.
    #[must_use]
    pub fn from_v1(transport: NativeTransport) -> Self {
        Self::v1(transport)
    }

    /// Alias for [`Self::v2`] useful at provider-construction call sites.
    #[must_use]
    pub fn from_v2(transport: NativeTransportV2) -> Self {
        Self::v2(transport)
    }

    /// Constructs a V1 provider with explicit bounded limits.
    pub fn new_v1(limits: NativeTransportLimits) -> Result<Self, TransportError> {
        NativeTransport::new(limits).map(Self::V1)
    }

    /// Constructs a V2 provider with explicit bounded limits and capabilities.
    pub fn new_v2(
        limits: NativeTransportLimits,
        resolver: Arc<dyn DnsResolver>,
        tls: Option<NativeTlsConfig>,
    ) -> Result<Self, TransportError> {
        NativeTransportV2::new(limits, resolver, tls).map(Self::V2)
    }

    /// Constructs a V1 provider with the concrete transport's default limits.
    pub fn with_defaults_v1() -> Result<Self, TransportError> {
        NativeTransport::with_defaults().map(Self::V1)
    }

    /// Constructs a V2 provider with the concrete transport's default limits.
    pub fn with_defaults_v2(
        resolver: Arc<dyn DnsResolver>,
        tls: Option<NativeTlsConfig>,
    ) -> Result<Self, TransportError> {
        NativeTransportV2::with_defaults(resolver, tls).map(Self::V2)
    }

    /// Returns the exact versioned capability identity for this variant.
    #[must_use]
    pub const fn capability_id(&self) -> &'static str {
        match self {
            Self::V1(_) => Self::V1_CAPABILITY_ID,
            Self::V2(_) => Self::V2_CAPABILITY_ID,
        }
    }

    /// Returns the immutable limits of the selected concrete transport.
    #[must_use]
    pub const fn limits(&self) -> &NativeTransportLimits {
        match self {
            Self::V1(transport) => transport.limits(),
            Self::V2(transport) => transport.limits(),
        }
    }

    /// Returns the immutable limits of the selected concrete transport.
    ///
    /// This spelling makes it explicit that the returned policy is a view of
    /// the selected provider, not a mutable choice that can change its
    /// capability identity.
    #[must_use]
    pub const fn as_limits(&self) -> &NativeTransportLimits {
        self.limits()
    }

    /// Returns whether this value contains the V1 provider.
    #[must_use]
    pub const fn is_v1(&self) -> bool {
        matches!(self, Self::V1(_))
    }

    /// Returns whether this value contains the V2 provider.
    #[must_use]
    pub const fn is_v2(&self) -> bool {
        matches!(self, Self::V2(_))
    }

    /// Borrows the V1 transport when this value selected V1.
    #[must_use]
    pub const fn as_v1(&self) -> Option<&NativeTransport> {
        match self {
            Self::V1(transport) => Some(transport),
            Self::V2(_) => None,
        }
    }

    /// Borrows the V2 transport when this value selected V2.
    #[must_use]
    pub const fn as_v2(&self) -> Option<&NativeTransportV2> {
        match self {
            Self::V1(_) => None,
            Self::V2(transport) => Some(transport),
        }
    }
}

impl From<NativeTransport> for NativeHttpTransport {
    fn from(transport: NativeTransport) -> Self {
        Self::V1(transport)
    }
}

impl From<NativeTransportV2> for NativeHttpTransport {
    fn from(transport: NativeTransportV2) -> Self {
        Self::V2(transport)
    }
}

impl Transport for NativeHttpTransport {
    fn send(
        &mut self,
        request: &Request,
        context: &TransportContext,
    ) -> Result<Response, TransportError> {
        match self {
            Self::V1(transport) => transport.send(request, context),
            Self::V2(transport) => transport.send(request, context),
        }
    }

    fn send_stream(
        &mut self,
        request: &Request,
        context: &TransportContext,
    ) -> Result<TransportResponse, TransportError> {
        match self {
            Self::V1(transport) => transport.send_stream(request, context),
            Self::V2(transport) => transport.send_stream(request, context),
        }
    }

    fn send_with_control(
        &mut self,
        request: &Request,
        context: &TransportContext,
    ) -> Result<TransportResponse, TransportError> {
        match self {
            Self::V1(transport) => transport.send_with_control(request, context),
            Self::V2(transport) => transport.send_with_control(request, context),
        }
    }
}
