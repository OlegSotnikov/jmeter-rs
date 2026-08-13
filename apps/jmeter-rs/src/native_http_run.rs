// SPDX-License-Identifier: Apache-2.0
//! Run-scoped ownership for the selected standalone native HTTP provider.
//!
//! This module is the application edge between already-admitted plan facts and
//! the concrete `jmeter-rs-http-native` transport.  It deliberately does not
//! inspect a plan, resolve a path, or infer a provider from a request.  The
//! caller supplies the closed `/1` or `/2` selection, the complete HTTP plan
//! requirements, the direct NativeV2 properties, and (when required) bytes
//! read through an already-rooted bounded filesystem capability.
//!
//! A run owns at most one Hickory resolver actor.  Per-user code receives only
//! a clone of the selected immutable transport; it never receives the resolver
//! owner or a mutable provider choice.  NativeV1 is never upgraded and
//! NativeV2 is never downgraded.  In particular, the numeric-only V2 path uses
//! a local fail-closed resolver solely to satisfy the V2 transport contract;
//! it can never perform an ambient lookup.
//!
//! Resolver teardown relies on the lower Hickory owner contract: its actor
//! uses bounded per-attempt work and aborts active tasks before joining the
//! exact thread.  This module never adds a sleep or an unbounded wait; the
//! explicit finalizer and the safety `Drop` path both use that finite provider
//! shutdown/join operation.

#![forbid(unsafe_code)]
#![allow(
    clippy::module_name_repetitions,
    reason = "the application boundary names its run/recipe/identity types explicitly"
)]

use std::collections::BTreeSet;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use jmeter_rs_http::TransportError;
use jmeter_rs_http_native::dns::{
    DNS_EXPLICIT_CAPABILITY_ID, DnsError, DnsErrorCode, DnsFuture, DnsQuery, DnsResolver,
};
use jmeter_rs_http_native::dns_hickory::{
    HickoryDnsConfig, HickoryDnsResolver, HickoryDnsResolverOwner, MAX_DNS_NAMESERVERS,
};
use jmeter_rs_http_native::tls::{
    MAX_TLS_INPUT_BYTES, NativeTlsConfig, TLS_EXPLICIT_RUSTLS_RING_CAPABILITY_ID, TlsError,
    TlsErrorCode,
};
use jmeter_rs_http_native::{
    NativeHttpTransport, NativeTransport, NativeTransportLimits, NativeTransportV2,
};

use crate::{
    HTTP_NATIVE_V1_CAPABILITY, HTTP_NATIVE_V2_CAPABILITY, HttpCapabilitySelector,
    HttpCapabilitySelectorSource, HttpNativeV2Properties,
};

/// Maximum bytes accepted from the already-rooted CA-file handoff.
///
/// This is the parser input ceiling from the native TLS edge.  The recipe
/// checks it before copying bytes, and the TLS builder applies its stricter
/// certificate-count/aggregate checks while parsing the PEM bundle.
pub const MAX_NATIVE_HTTP_CA_BYTES: usize = MAX_TLS_INPUT_BYTES;

/// The explicit DNS subordinate identity used by hostname-capable V2 runs.
pub const NATIVE_HTTP_DNS_IDENTITY: &str = DNS_EXPLICIT_CAPABILITY_ID;

/// The explicit rustls subordinate identity used by HTTPS-capable V2 runs.
pub const NATIVE_HTTP_TLS_IDENTITY: &str = TLS_EXPLICIT_RUSTLS_RING_CAPABILITY_ID;

/// Already-admitted plan facts consumed by the native HTTP resource recipe.
///
/// These flags are facts from whole-plan admission, not request-time guesses.
/// `has_hostname` means at least one admitted native HTTP origin uses a DNS
/// hostname; `has_https` means at least one admitted origin uses HTTPS.  The
/// owner does not inspect URL strings or JMX properties.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeHttpRunRequirements {
    /// Whether the admitted plan contains one or more native HTTP samplers.
    pub has_http: bool,
    /// Whether an admitted sampler needs explicit hostname resolution.
    pub has_hostname: bool,
    /// Whether an admitted sampler needs explicit-root TLS.
    pub has_https: bool,
}

impl NativeHttpRunRequirements {
    /// Creates an admitted requirements value.
    #[must_use]
    pub const fn new(has_http: bool, has_hostname: bool, has_https: bool) -> Self {
        Self {
            has_http,
            has_hostname,
            has_https,
        }
    }

    fn validate(self) -> Result<(), NativeHttpRunError> {
        if !self.has_http && (self.has_hostname || self.has_https) {
            return Err(NativeHttpRunError::InvalidRequirements);
        }
        if !self.has_http {
            return Err(NativeHttpRunError::NoHttpPlan);
        }
        Ok(())
    }
}

/// Immutable subordinate identities attached to one selected native provider.
///
/// The flags are intentionally booleans over fixed identities rather than
/// copied configuration.  No hostname, nameserver, path, or certificate bytes
/// can enter this value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeHttpSubordinateIdentities {
    /// Whether the run owns `http.dns.explicit/1`.
    pub explicit_dns: bool,
    /// Whether the run retains `http.tls.explicit-rustls-ring/1`.
    pub explicit_tls: bool,
}

impl NativeHttpSubordinateIdentities {
    /// Returns the DNS subordinate identity when enabled.
    #[must_use]
    pub const fn dns_identity(self) -> Option<&'static str> {
        if self.explicit_dns {
            Some(NATIVE_HTTP_DNS_IDENTITY)
        } else {
            None
        }
    }

    /// Returns the TLS subordinate identity when enabled.
    #[must_use]
    pub const fn tls_identity(self) -> Option<&'static str> {
        if self.explicit_tls {
            Some(NATIVE_HTTP_TLS_IDENTITY)
        } else {
            None
        }
    }
}

/// Exact non-secret identity of one prepared native HTTP run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeHttpRunIdentity {
    capability: &'static str,
    subordinate: NativeHttpSubordinateIdentities,
}

impl NativeHttpRunIdentity {
    /// Returns the immutable selected provider identity.
    #[must_use]
    pub const fn capability_id(self) -> &'static str {
        self.capability
    }

    /// Returns the subordinate DNS/TLS flags.
    #[must_use]
    pub const fn subordinate(self) -> NativeHttpSubordinateIdentities {
        self.subordinate
    }

    /// Returns the explicit DNS identity, when this run owns a resolver.
    #[must_use]
    pub const fn dns_identity(self) -> Option<&'static str> {
        self.subordinate.dns_identity()
    }

    /// Returns the explicit TLS identity, when this run retains TLS state.
    #[must_use]
    pub const fn tls_identity(self) -> Option<&'static str> {
        self.subordinate.tls_identity()
    }
}

/// Stable, redacted construction/finalization errors for a native HTTP run.
///
/// Only closed codes and provider error categories cross this boundary.  No
/// variant stores the direct CA path, hostname, nameserver spelling, or
/// certificate bytes.  Provider diagnostics are deliberately reduced to their
/// typed code before they leave the lower edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeHttpRunError {
    /// The provider selector was absent; the owner never infers a native path.
    SelectionRequired,
    /// The requirements contain an impossible or incomplete admitted state.
    InvalidRequirements,
    /// The admitted plan contains no HTTP sampler for this owner.
    NoHttpPlan,
    /// NativeV1 cannot satisfy an admitted hostname or HTTPS requirement.
    V1RequirementsProvided,
    /// NativeV1 was supplied a NativeV2 property or CA handoff.
    V1PropertiesProvided,
    /// V2 hostname admission did not provide the direct nameserver property.
    DnsNameserversRequired,
    /// A nameserver property was supplied to a numeric-only V2 run.
    DnsNameserversUnused,
    /// The supplied nameserver vector violates the checked numeric bound.
    DnsNameserversInvalid,
    /// V2 HTTPS admission did not provide the direct CA property.
    CaPropertyRequired,
    /// V2 HTTPS admission did not provide rooted CA bytes.
    CaBytesRequired,
    /// A CA property/bytes pair was supplied to a non-HTTPS V2 run.
    CaMaterialUnused,
    /// A CA property and rooted bytes were supplied with mismatched presence.
    CaMaterialMismatch,
    /// The rooted CA handoff exceeded its finite bound.
    CaInputLimit,
    /// The rooted CA handoff was not a bounded PEM certificate bundle.
    CaMalformed,
    /// The immutable rustls configuration could not be validated/built.
    Tls(TlsErrorCode),
    /// The explicit Hickory resolver could not be started.
    Resolver(DnsErrorCode),
    /// The selected native transport could not be built with the checked
    /// limits.  The nested code is static and contains no provider detail.
    Transport(&'static str),
    /// Transport construction failed and exact resolver cleanup also failed.
    /// The primary transport category is retained alongside the cleanup code.
    ConstructionCleanup {
        /// Stable primary transport category.
        primary: &'static str,
        /// Stable cleanup failure category.
        cleanup: DnsErrorCode,
    },
    /// Finalization of the exact resolver owner failed.
    Finalize(DnsErrorCode),
}

impl NativeHttpRunError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::SelectionRequired => "app.native-http.selection-required",
            Self::InvalidRequirements => "app.native-http.requirements-invalid",
            Self::NoHttpPlan => "app.native-http.no-http",
            Self::V1RequirementsProvided => "app.native-http.v1-requirements",
            Self::V1PropertiesProvided => "app.native-http.v1-v2-properties",
            Self::DnsNameserversRequired => "app.native-http.dns-nameservers-required",
            Self::DnsNameserversUnused => "app.native-http.dns-nameservers-unused",
            Self::DnsNameserversInvalid => "app.native-http.dns-nameservers-invalid",
            Self::CaPropertyRequired => "app.native-http.ca-property-required",
            Self::CaBytesRequired => "app.native-http.ca-bytes-required",
            Self::CaMaterialUnused => "app.native-http.ca-material-unused",
            Self::CaMaterialMismatch => "app.native-http.ca-material-mismatch",
            Self::CaInputLimit => "app.native-http.ca-input-limit",
            Self::CaMalformed => "app.native-http.ca-malformed",
            Self::Tls(_) => "app.native-http.tls",
            Self::Resolver(_) => "app.native-http.resolver",
            Self::Transport(_) => "app.native-http.transport",
            Self::ConstructionCleanup { .. } => "app.native-http.transport-cleanup",
            Self::Finalize(_) => "app.native-http.finalize",
        }
    }

    /// Returns the lower-edge TLS category, when one caused this error.
    #[must_use]
    pub const fn tls_code(self) -> Option<TlsErrorCode> {
        match self {
            Self::Tls(code) => Some(code),
            _ => None,
        }
    }

    /// Returns the lower-edge DNS category, when one caused this error.
    #[must_use]
    pub const fn dns_code(self) -> Option<DnsErrorCode> {
        match self {
            Self::Resolver(code) | Self::Finalize(code) => Some(code),
            Self::ConstructionCleanup { cleanup, .. } => Some(cleanup),
            _ => None,
        }
    }

    /// Returns the preserved primary transport category for a construction
    /// cleanup failure.
    #[must_use]
    pub const fn primary_code(self) -> Option<&'static str> {
        match self {
            Self::ConstructionCleanup { primary, .. } => Some(primary),
            _ => None,
        }
    }

    /// Returns the preserved cleanup category for a construction cleanup
    /// failure.
    #[must_use]
    pub const fn cleanup_code(self) -> Option<DnsErrorCode> {
        match self {
            Self::ConstructionCleanup { cleanup, .. } => Some(cleanup),
            _ => None,
        }
    }
}

impl fmt::Display for NativeHttpRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())?;
        match self {
            Self::Tls(code) => write!(formatter, ": {code}"),
            Self::Resolver(code) | Self::Finalize(code) => write!(formatter, ": {code}"),
            Self::Transport(code) => write!(formatter, ": {code}"),
            Self::ConstructionCleanup { primary, cleanup } => {
                write!(formatter, ": primary={primary}; cleanup={cleanup}")
            }
            _ => Ok(()),
        }
    }
}

impl std::error::Error for NativeHttpRunError {}

/// Typed recipe for one native HTTP run resource transaction.
///
/// The recipe owns only bounded handoff bytes until construction.  Successful
/// HTTPS construction parses those bytes into the immutable TLS policy and
/// drops the original PEM buffer; HTTP-only and V1 construction retain no CA
/// material.  Its custom `Debug` implementation reports only presence/counts.
pub struct NativeHttpRunRecipe {
    selection: HttpCapabilitySelector,
    requirements: NativeHttpRunRequirements,
    v2_properties: HttpNativeV2Properties,
    rooted_ca_bytes: Option<Vec<u8>>,
    transport_limits: NativeTransportLimits,
}

impl Clone for NativeHttpRunRecipe {
    fn clone(&self) -> Self {
        Self {
            selection: self.selection,
            requirements: self.requirements,
            v2_properties: self.v2_properties.clone(),
            rooted_ca_bytes: self.rooted_ca_bytes.clone(),
            transport_limits: self.transport_limits,
        }
    }
}

impl fmt::Debug for NativeHttpRunRecipe {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeHttpRunRecipe")
            .field("selection", &self.selection.as_str())
            .field("requirements", &self.requirements)
            .field(
                "dns_nameservers_present",
                &self.v2_properties.dns_nameservers.is_some(),
            )
            .field(
                "tls_ca_file_present",
                &self.v2_properties.tls_ca_file.is_some(),
            )
            .field("rooted_ca_bytes_present", &self.rooted_ca_bytes.is_some())
            .field(
                "rooted_ca_bytes_len",
                &self.rooted_ca_bytes.as_ref().map_or(0, Vec::len),
            )
            .field("transport_limits", &self.transport_limits)
            .finish()
    }
}

impl NativeHttpRunRecipe {
    /// Creates a recipe with the native transport's checked default limits.
    pub fn new(
        selection: HttpCapabilitySelector,
        requirements: NativeHttpRunRequirements,
        v2_properties: HttpNativeV2Properties,
        rooted_ca_bytes: Option<Vec<u8>>,
    ) -> Result<Self, NativeHttpRunError> {
        Self::with_limits(
            selection,
            requirements,
            v2_properties,
            rooted_ca_bytes,
            NativeTransportLimits::default(),
        )
    }

    /// Creates a recipe with explicit already-bounded native HTTP limits.
    pub fn with_limits(
        selection: HttpCapabilitySelector,
        requirements: NativeHttpRunRequirements,
        v2_properties: HttpNativeV2Properties,
        rooted_ca_bytes: Option<Vec<u8>>,
        transport_limits: NativeTransportLimits,
    ) -> Result<Self, NativeHttpRunError> {
        let recipe = Self {
            selection,
            requirements,
            v2_properties,
            rooted_ca_bytes,
            transport_limits,
        };
        recipe.validate()?;
        Ok(recipe)
    }

    /// Returns the selected plan-wide provider choice.
    #[must_use]
    pub const fn selection(&self) -> HttpCapabilitySelector {
        self.selection
    }

    /// Returns already-admitted plan facts.
    #[must_use]
    pub const fn requirements(&self) -> NativeHttpRunRequirements {
        self.requirements
    }

    /// Returns whether a rooted CA handoff is present without exposing bytes.
    #[must_use]
    pub fn has_rooted_ca_bytes(&self) -> bool {
        self.rooted_ca_bytes.is_some()
    }

    /// Returns the rooted CA handoff length without exposing bytes.
    #[must_use]
    pub fn rooted_ca_bytes_len(&self) -> usize {
        self.rooted_ca_bytes.as_ref().map_or(0, Vec::len)
    }

    fn validate(&self) -> Result<(), NativeHttpRunError> {
        self.requirements.validate()?;
        if matches!(self.selection, HttpCapabilitySelector::NativeV1)
            && (self.requirements.has_hostname || self.requirements.has_https)
        {
            return Err(NativeHttpRunError::V1RequirementsProvided);
        }
        if matches!(self.selection, HttpCapabilitySelector::Absent) {
            return Err(NativeHttpRunError::SelectionRequired);
        }
        self.transport_limits
            .validate()
            .map_err(map_transport_error)?;
        validate_direct_properties(&self.v2_properties)?;
        if let Some(bytes) = &self.rooted_ca_bytes
            && (bytes.is_empty() || bytes.len() > MAX_NATIVE_HTTP_CA_BYTES)
        {
            return Err(NativeHttpRunError::CaInputLimit);
        }
        Ok(())
    }
}

/// One run-owned native HTTP provider and its optional exact resolver owner.
pub struct NativeHttpRunOwner {
    identity: NativeHttpRunIdentity,
    transport: NativeHttpTransport,
    resolver_owner: Option<HickoryDnsResolverOwner>,
    finalization: Option<Result<(), NativeHttpRunError>>,
}

impl fmt::Debug for NativeHttpRunOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeHttpRunOwner")
            .field("capability", &self.identity.capability_id())
            .field("subordinate", &self.identity.subordinate())
            .field("resolver_owner", &self.resolver_owner.is_some())
            .field("finalized", &self.finalization.is_some())
            .finish()
    }
}

impl NativeHttpRunOwner {
    /// Constructs one immutable provider and all required run-owned resources.
    ///
    /// TLS configuration is parsed and fully built before the Hickory actor is
    /// started.  A construction failure after actor startup performs exact
    /// shutdown/join before returning the primary typed failure, preserving a
    /// bounded primary-plus-cleanup code when that join also fails.
    pub fn new(recipe: NativeHttpRunRecipe) -> Result<Self, NativeHttpRunError> {
        recipe.validate()?;

        let (explicit_dns, explicit_tls) = match recipe.selection {
            HttpCapabilitySelector::NativeV1 => {
                if !recipe.v2_properties.is_empty() || recipe.rooted_ca_bytes.is_some() {
                    return Err(NativeHttpRunError::V1PropertiesProvided);
                }
                let transport =
                    NativeTransport::new(recipe.transport_limits).map_err(map_transport_error)?;
                return Ok(Self {
                    identity: NativeHttpRunIdentity {
                        capability: HTTP_NATIVE_V1_CAPABILITY,
                        subordinate: NativeHttpSubordinateIdentities {
                            explicit_dns: false,
                            explicit_tls: false,
                        },
                    },
                    transport: NativeHttpTransport::from_v1(transport),
                    resolver_owner: None,
                    finalization: None,
                });
            }
            HttpCapabilitySelector::NativeV2 => (
                recipe.requirements.has_hostname,
                recipe.requirements.has_https,
            ),
            HttpCapabilitySelector::Absent => return Err(NativeHttpRunError::SelectionRequired),
        };

        let resolver_nameservers = if explicit_dns {
            let nameservers = recipe
                .v2_properties
                .dns_nameservers
                .as_ref()
                .ok_or(NativeHttpRunError::DnsNameserversRequired)?;
            validate_nameservers(&nameservers.nameservers)?;
            Some(nameservers.nameservers.clone())
        } else {
            if recipe.v2_properties.dns_nameservers.is_some() {
                return Err(NativeHttpRunError::DnsNameserversUnused);
            }
            None
        };

        // A CA property and rooted bytes are a pair.  Presence is checked
        // before parsing so a runner cannot accidentally associate one
        // sampler's rooted material with another property selection.
        let tls = if explicit_tls {
            if recipe.v2_properties.tls_ca_file.is_none() {
                return Err(NativeHttpRunError::CaPropertyRequired);
            }
            let bytes = recipe
                .rooted_ca_bytes
                .as_deref()
                .ok_or(NativeHttpRunError::CaBytesRequired)?;
            build_tls_config(bytes)?
        } else {
            if recipe.v2_properties.tls_ca_file.is_some() || recipe.rooted_ca_bytes.is_some() {
                return Err(NativeHttpRunError::CaMaterialUnused);
            }
            None
        };

        // The complete TLS recipe is now immutable and validated.  Only this
        // point may create the optional DNS actor.
        let (resolver, resolver_owner) = match resolver_nameservers {
            Some(nameservers) => {
                let configuration = HickoryDnsConfig {
                    nameservers,
                    ..HickoryDnsConfig::default()
                };
                let (resolver, owner) = HickoryDnsResolver::start(configuration)
                    .map_err(|error| NativeHttpRunError::Resolver(error.code()))?;
                (Arc::new(resolver) as Arc<dyn DnsResolver>, Some(owner))
            }
            None => (Arc::new(FailClosedResolver) as Arc<dyn DnsResolver>, None),
        };

        let (transport, resolver_owner) =
            construct_v2_transport(recipe.transport_limits, resolver, tls, resolver_owner)?;

        Ok(Self {
            identity: NativeHttpRunIdentity {
                capability: HTTP_NATIVE_V2_CAPABILITY,
                subordinate: NativeHttpSubordinateIdentities {
                    explicit_dns,
                    explicit_tls,
                },
            },
            transport: NativeHttpTransport::from_v2(transport),
            resolver_owner,
            finalization: None,
        })
    }

    /// Returns the exact provider identity and subordinate flags.
    #[must_use]
    pub const fn identity(&self) -> NativeHttpRunIdentity {
        self.identity
    }

    /// Returns a cloneable selected transport for one virtual-user client.
    #[must_use]
    pub fn transport(&self) -> NativeHttpTransport {
        self.transport.clone()
    }

    /// Returns whether this run owns an explicit Hickory resolver actor.
    #[must_use]
    pub fn has_resolver_owner(&self) -> bool {
        self.resolver_owner.is_some()
    }

    /// Returns whether the selected run retains a TLS policy.
    #[must_use]
    pub const fn has_tls_state(&self) -> bool {
        self.identity.subordinate.explicit_tls
    }

    /// Returns whether the selected run is already finalized.
    #[must_use]
    pub fn is_finalized(&self) -> bool {
        self.finalization.is_some()
    }

    /// Shuts down and joins the exact optional resolver owner once.
    ///
    /// Repeated calls return the first result.  The transport remains a safe
    /// cloneable value after finalization, but any later hostname operation
    /// observes the resolver's typed stopped state; no provider fallback is
    /// introduced.  Hickory's finite shutdown/join contract is the only
    /// blocking operation here; this method never sleeps or publishes output.
    pub fn finalize(&mut self) -> Result<(), NativeHttpRunError> {
        if let Some(result) = &self.finalization {
            return *result;
        }
        let result = match self.resolver_owner.take() {
            Some(owner) => map_finalize_result(owner.shutdown_and_join()),
            None => Ok(()),
        };
        self.finalization = Some(result);
        result
    }
}

impl Drop for NativeHttpRunOwner {
    fn drop(&mut self) {
        // Drop cannot publish success or return a diagnostic.  It still
        // requests shutdown and joins the exact actor through the lower
        // provider's finite owner contract so a caller abandoning a run
        // cannot leak the thread. Explicit `finalize` is the only path that
        // can publish a typed cleanup failure to its caller.
        if let Some(owner) = self.resolver_owner.take() {
            match owner.shutdown_and_join() {
                Ok(()) => {}
                // There is no error channel in Drop. The exact owner has
                // still been consumed/reaped; explicit finalize is required
                // when the caller needs this typed failure.
                Err(_error) => {}
            }
        }
    }
}

/// Explicitly fail-closed V2 resolver for numeric-only plans.
///
/// `NativeTransportV2` resolves only when a request host is not numeric.  A
/// numeric-only run therefore never polls this value, while an accidental
/// hostname request receives a typed failure without touching a system
/// resolver, hosts file, network, or ambient cache.
#[derive(Clone, Copy, Debug, Default)]
struct FailClosedResolver;

impl DnsResolver for FailClosedResolver {
    fn resolve(&self, _query: DnsQuery) -> DnsFuture<'static> {
        Box::pin(std::future::ready(Err(DnsError::new(
            DnsErrorCode::NoNameservers,
        ))))
    }
}

fn construct_v2_transport(
    limits: NativeTransportLimits,
    resolver: Arc<dyn DnsResolver>,
    tls: Option<NativeTlsConfig>,
    resolver_owner: Option<HickoryDnsResolverOwner>,
) -> Result<(NativeTransportV2, Option<HickoryDnsResolverOwner>), NativeHttpRunError> {
    construct_v2_transport_with(
        limits,
        resolver,
        tls,
        resolver_owner,
        NativeTransportV2::new,
        |owner| owner.shutdown_and_join(),
    )
}

/// Construction seam used to prove that a primary transport failure never
/// erases an exact resolver cleanup failure. The production callbacks are
/// concrete constructors/owners; tests inject bounded failures without
/// issuing a network query.
fn construct_v2_transport_with<F, C>(
    limits: NativeTransportLimits,
    resolver: Arc<dyn DnsResolver>,
    tls: Option<NativeTlsConfig>,
    resolver_owner: Option<HickoryDnsResolverOwner>,
    constructor: F,
    cleanup: C,
) -> Result<(NativeTransportV2, Option<HickoryDnsResolverOwner>), NativeHttpRunError>
where
    F: FnOnce(
        NativeTransportLimits,
        Arc<dyn DnsResolver>,
        Option<NativeTlsConfig>,
    ) -> Result<NativeTransportV2, TransportError>,
    C: FnOnce(HickoryDnsResolverOwner) -> Result<(), DnsError>,
{
    let transport = match constructor(limits, resolver, tls) {
        Ok(transport) => transport,
        Err(error) => {
            let primary = map_transport_error(error);
            let Some(owner) = resolver_owner else {
                return Err(primary);
            };
            return match cleanup(owner) {
                Ok(()) => Err(primary),
                Err(error) => Err(NativeHttpRunError::ConstructionCleanup {
                    primary: transport_detail_code(primary),
                    cleanup: error.code(),
                }),
            };
        }
    };
    Ok((transport, resolver_owner))
}

fn validate_direct_properties(
    properties: &HttpNativeV2Properties,
) -> Result<(), NativeHttpRunError> {
    if let Some(nameservers) = &properties.dns_nameservers {
        if nameservers.origin.source != HttpCapabilitySelectorSource::DirectJmeterProperty {
            return Err(NativeHttpRunError::V1PropertiesProvided);
        }
        validate_nameservers(&nameservers.nameservers)?;
    }
    if let Some(ca_file) = &properties.tls_ca_file
        && (ca_file.origin.source != HttpCapabilitySelectorSource::DirectJmeterProperty
            || ca_file.path.as_str().is_empty())
    {
        return Err(NativeHttpRunError::CaMaterialMismatch);
    }
    Ok(())
}

fn validate_nameservers(nameservers: &[SocketAddr]) -> Result<(), NativeHttpRunError> {
    if nameservers.is_empty() || nameservers.len() > MAX_DNS_NAMESERVERS {
        return Err(NativeHttpRunError::DnsNameserversInvalid);
    }
    let mut unique = BTreeSet::new();
    for endpoint in nameservers {
        if endpoint.port() != 53 || endpoint.ip().is_unspecified() {
            return Err(NativeHttpRunError::DnsNameserversInvalid);
        }
        if !unique.insert(*endpoint) {
            return Err(NativeHttpRunError::DnsNameserversInvalid);
        }
    }
    Ok(())
}

fn build_tls_config(bytes: &[u8]) -> Result<Option<NativeTlsConfig>, NativeHttpRunError> {
    if bytes.is_empty() || bytes.len() > MAX_NATIVE_HTTP_CA_BYTES {
        return Err(NativeHttpRunError::CaInputLimit);
    }
    let mut config = NativeTlsConfig::builder();
    config.add_root_pem(bytes).map_err(map_tls_error)?;
    config.validate().map_err(map_tls_error)?;
    // Force preparation before any resolver actor starts.  This validates the
    // immutable provider config, root store, ring provider, protocol versions,
    // and fixed HTTP/1.1 ALPN policy at the transaction boundary.
    config.build_client_config().map_err(map_tls_error)?;
    Ok(Some(config))
}

fn map_tls_error(error: TlsError) -> NativeHttpRunError {
    match error.code() {
        TlsErrorCode::InputLimit => NativeHttpRunError::CaInputLimit,
        TlsErrorCode::MalformedCertificate => NativeHttpRunError::CaMalformed,
        code => NativeHttpRunError::Tls(code),
    }
}

fn map_transport_error(error: TransportError) -> NativeHttpRunError {
    NativeHttpRunError::Transport(error.code())
}

fn transport_detail_code(error: NativeHttpRunError) -> &'static str {
    match error {
        NativeHttpRunError::Transport(code) => code,
        _ => error.code(),
    }
}

fn map_finalize_result(result: Result<(), DnsError>) -> Result<(), NativeHttpRunError> {
    result.map_err(|error| NativeHttpRunError::Finalize(error.code()))
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "resource-owner tests use explicit assertion setup"
)]
mod tests {
    use super::*;

    // rcgen is used only in tests. The certificate and ephemeral private key
    // are generated in memory for each call; no generated key or certificate
    // is persisted. Fixed parameters keep the fixture's semantic inputs
    // deterministic while rcgen's cryptographic randomness remains ephemeral.
    fn test_ca_pem() -> Vec<u8> {
        let mut parameters =
            rcgen::CertificateParams::new(vec!["native-http-test.example".to_owned()])
                .expect("test CA parameters");
        parameters.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key_pair = rcgen::KeyPair::generate().expect("test CA key generation");
        let certificate = parameters
            .self_signed(&key_pair)
            .expect("test CA certificate");
        pem_certificate(certificate.der().as_ref())
    }

    fn pem_certificate(der: &[u8]) -> Vec<u8> {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut pem = b"-----BEGIN CERTIFICATE-----\n".to_vec();
        let mut line_len = 0usize;
        for chunk in der.chunks(3) {
            let first = chunk[0];
            let second = chunk.get(1).copied();
            let third = chunk.get(2).copied();
            let sextets = [
                first >> 2,
                ((first & 0x03) << 4) | second.map_or(0, |value| value >> 4),
                second.map_or(0, |value| (value & 0x0f) << 2 | third.map_or(0, |v| v >> 6)),
                third.map_or(0, |value| value & 0x3f),
            ];
            let output = [
                TABLE[usize::from(sextets[0])],
                TABLE[usize::from(sextets[1])],
                second.map_or(b'=', |_| TABLE[usize::from(sextets[2])]),
                third.map_or(b'=', |_| TABLE[usize::from(sextets[3])]),
            ];
            for byte in output {
                pem.push(byte);
                line_len += 1;
                if line_len == 64 {
                    pem.push(b'\n');
                    line_len = 0;
                }
            }
        }
        if line_len != 0 {
            pem.push(b'\n');
        }
        pem.extend_from_slice(b"-----END CERTIFICATE-----\n");
        pem
    }

    fn requirements(hostname: bool, https: bool) -> NativeHttpRunRequirements {
        NativeHttpRunRequirements::new(true, hostname, https)
    }

    fn empty_properties() -> HttpNativeV2Properties {
        HttpNativeV2Properties::default()
    }

    fn direct_v2_properties(arguments: &[&str]) -> HttpNativeV2Properties {
        let invocation = crate::parse(arguments.iter().copied()).expect("direct property parse");
        invocation
            .resolve_http_native_v2_properties()
            .expect("direct NativeV2 property parse")
    }

    #[test]
    fn requirements_matrix_selects_v1_and_v2_without_fallback() {
        let v1_recipe = NativeHttpRunRecipe::new(
            HttpCapabilitySelector::NativeV1,
            requirements(false, false),
            empty_properties(),
            None,
        )
        .expect("V1 recipe");
        let mut v1 = NativeHttpRunOwner::new(v1_recipe).expect("V1 owner");
        assert_eq!(v1.identity().capability_id(), HTTP_NATIVE_V1_CAPABILITY);
        assert_eq!(
            v1.identity().subordinate(),
            NativeHttpSubordinateIdentities {
                explicit_dns: false,
                explicit_tls: false,
            }
        );
        assert!(!v1.has_resolver_owner());
        assert!(!v1.has_tls_state());
        assert!(v1.transport().is_v1());
        v1.finalize().expect("V1 finalize");

        let v2_numeric_recipe = NativeHttpRunRecipe::new(
            HttpCapabilitySelector::NativeV2,
            requirements(false, false),
            empty_properties(),
            None,
        )
        .expect("numeric V2 recipe");
        let mut v2_numeric = NativeHttpRunOwner::new(v2_numeric_recipe).expect("numeric V2 owner");
        assert_eq!(
            v2_numeric.identity().capability_id(),
            HTTP_NATIVE_V2_CAPABILITY
        );
        assert!(!v2_numeric.has_resolver_owner());
        assert!(!v2_numeric.has_tls_state());
        assert!(v2_numeric.transport().is_v2());
        v2_numeric.finalize().expect("numeric V2 finalize");

        let hostname_properties =
            direct_v2_properties(&["-Jjmeter-rs.http.dns.nameservers=192.0.2.53:53"]);
        let hostname_recipe = NativeHttpRunRecipe::new(
            HttpCapabilitySelector::NativeV2,
            requirements(true, false),
            hostname_properties,
            None,
        )
        .expect("hostname V2 recipe");
        let mut hostname = NativeHttpRunOwner::new(hostname_recipe).expect("hostname V2 owner");
        assert!(hostname.has_resolver_owner());
        assert_eq!(
            hostname.identity().dns_identity(),
            Some(NATIVE_HTTP_DNS_IDENTITY)
        );
        assert_eq!(hostname.identity().tls_identity(), None);
        hostname.finalize().expect("hostname V2 finalize");
    }

    #[test]
    fn full_requirement_and_property_mismatch_matrix_fails_closed() {
        let v2 = HttpCapabilitySelector::NativeV2;
        for admitted in [
            requirements(true, false),
            requirements(false, true),
            requirements(true, true),
        ] {
            assert_eq!(
                NativeHttpRunRecipe::new(
                    HttpCapabilitySelector::NativeV1,
                    admitted,
                    empty_properties(),
                    None,
                )
                .expect_err("V1 must reject hostname/HTTPS requirements"),
                NativeHttpRunError::V1RequirementsProvided
            );
        }

        let v1_ca_recipe = NativeHttpRunRecipe::new(
            HttpCapabilitySelector::NativeV1,
            requirements(false, false),
            empty_properties(),
            Some(vec![1]),
        )
        .expect("recipe validation allows handoff inspection");
        assert_eq!(
            NativeHttpRunOwner::new(v1_ca_recipe).expect_err("V1 CA handoff must reject"),
            NativeHttpRunError::V1PropertiesProvided
        );

        assert_eq!(
            NativeHttpRunOwner::new(
                NativeHttpRunRecipe::new(v2, requirements(true, false), empty_properties(), None)
                    .expect("recipe"),
            )
            .expect_err("hostname needs nameservers"),
            NativeHttpRunError::DnsNameserversRequired
        );

        let nameservers = direct_v2_properties(&["-Jjmeter-rs.http.dns.nameservers=192.0.2.53:53"]);
        assert_eq!(
            NativeHttpRunOwner::new(
                NativeHttpRunRecipe::new(v2, requirements(false, false), nameservers, None)
                    .expect("recipe"),
            )
            .expect_err("numeric-only V2 rejects unused nameservers"),
            NativeHttpRunError::DnsNameserversUnused
        );

        assert_eq!(
            NativeHttpRunOwner::new(
                NativeHttpRunRecipe::new(v2, requirements(false, true), empty_properties(), None)
                    .expect("recipe"),
            )
            .expect_err("HTTPS needs CA property"),
            NativeHttpRunError::CaPropertyRequired
        );

        let ca_properties = direct_v2_properties(&["-Jjmeter-rs.http.tls.ca-file=ca.pem"]);
        assert_eq!(
            NativeHttpRunOwner::new(
                NativeHttpRunRecipe::new(v2, requirements(false, true), ca_properties, None)
                    .expect("recipe"),
            )
            .expect_err("HTTPS needs rooted CA bytes"),
            NativeHttpRunError::CaBytesRequired
        );

        let ca_properties = direct_v2_properties(&["-Jjmeter-rs.http.tls.ca-file=ca.pem"]);
        assert_eq!(
            NativeHttpRunOwner::new(
                NativeHttpRunRecipe::new(
                    v2,
                    requirements(false, false),
                    ca_properties,
                    Some(test_ca_pem()),
                )
                .expect("recipe"),
            )
            .expect_err("HTTP-only V2 rejects CA material"),
            NativeHttpRunError::CaMaterialUnused
        );
    }

    #[test]
    fn https_builds_immutable_tls_before_optional_dns() {
        let properties = direct_v2_properties(&["-Jjmeter-rs.http.tls.ca-file=ca.pem"]);
        let recipe = NativeHttpRunRecipe::new(
            HttpCapabilitySelector::NativeV2,
            requirements(false, true),
            properties,
            Some(test_ca_pem()),
        )
        .expect("HTTPS recipe");
        let mut owner = NativeHttpRunOwner::new(recipe).expect("HTTPS owner");
        assert!(owner.has_tls_state());
        assert!(!owner.has_resolver_owner());
        assert_eq!(
            owner.identity().tls_identity(),
            Some(NATIVE_HTTP_TLS_IDENTITY)
        );
        assert!(owner.transport().is_v2());
        owner.finalize().expect("HTTPS finalize");
    }

    #[test]
    fn pem_malformed_and_input_limits_are_typed_and_redacted() {
        let properties = direct_v2_properties(&["-Jjmeter-rs.http.tls.ca-file=secret-ca.pem"]);
        let malformed = NativeHttpRunOwner::new(
            NativeHttpRunRecipe::new(
                HttpCapabilitySelector::NativeV2,
                requirements(false, true),
                properties.clone(),
                Some(b"not a PEM certificate".to_vec()),
            )
            .expect("malformed recipe"),
        )
        .expect_err("malformed PEM");
        assert_eq!(malformed, NativeHttpRunError::CaMalformed);
        assert!(!malformed.to_string().contains("secret-ca.pem"));

        let non_certificate = NativeHttpRunOwner::new(
            NativeHttpRunRecipe::new(
                HttpCapabilitySelector::NativeV2,
                requirements(false, true),
                properties.clone(),
                Some(b"-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n".to_vec()),
            )
            .expect("non-certificate recipe"),
        )
        .expect_err("CA handoff accepts certificates only");
        assert_eq!(
            non_certificate,
            NativeHttpRunError::Tls(TlsErrorCode::Unsupported)
        );

        let oversized = NativeHttpRunRecipe::new(
            HttpCapabilitySelector::NativeV2,
            requirements(false, true),
            properties,
            Some(vec![0; MAX_NATIVE_HTTP_CA_BYTES + 1]),
        )
        .expect_err("oversized rooted bytes");
        assert_eq!(oversized, NativeHttpRunError::CaInputLimit);
        assert!(!format!("{oversized:?}").contains("secret-ca.pem"));
    }

    #[test]
    fn identity_debug_and_errors_never_include_sensitive_inputs() {
        // Use a valid bounded token for this identity test; the direct parser
        // rejects parent-containing CA paths before this owner boundary.
        let properties = direct_v2_properties(&[
            "-Jjmeter-rs.http.dns.nameservers=192.0.2.53:53",
            "-Jjmeter-rs.http.tls.ca-file=secret-ca.pem",
        ]);
        let recipe = NativeHttpRunRecipe::new(
            HttpCapabilitySelector::NativeV2,
            requirements(true, false),
            properties,
            None,
        )
        .expect("hostname recipe");
        let debug = format!("{recipe:?}");
        assert!(!debug.contains("secret-ca.pem"));
        assert!(!debug.contains("192.0.2.53"));
        let owner = NativeHttpRunOwner::new(recipe).expect_err("CA material unused");
        assert!(!owner.to_string().contains("secret-ca.pem"));
        assert!(!format!("{owner:?}").contains("192.0.2.53"));
    }

    #[test]
    fn finalize_is_idempotent_and_maps_exact_resolver_errors() {
        let properties = direct_v2_properties(&["-Jjmeter-rs.http.dns.nameservers=192.0.2.53:53"]);
        let recipe = NativeHttpRunRecipe::new(
            HttpCapabilitySelector::NativeV2,
            requirements(true, false),
            properties,
            None,
        )
        .expect("hostname recipe");
        let mut owner = NativeHttpRunOwner::new(recipe).expect("hostname owner");
        assert_eq!(owner.finalize(), Ok(()));
        assert_eq!(owner.finalize(), Ok(()));
        assert!(owner.is_finalized());
        assert!(!owner.has_resolver_owner());
        assert_eq!(
            map_finalize_result(Err(DnsError::new(DnsErrorCode::Internal))),
            Err(NativeHttpRunError::Finalize(DnsErrorCode::Internal))
        );
    }

    #[test]
    fn construction_cleanup_preserves_primary_and_cleanup_codes() {
        let configuration = HickoryDnsConfig {
            nameservers: vec!["192.0.2.53:53".parse().expect("numeric nameserver")],
            ..HickoryDnsConfig::default()
        };
        let (resolver, owner) = HickoryDnsResolver::start(configuration).expect("resolver actor");
        let error = construct_v2_transport_with(
            NativeTransportLimits::default(),
            Arc::new(resolver) as Arc<dyn DnsResolver>,
            None,
            Some(owner),
            |_limits, _resolver, _tls| {
                Err(TransportError::adapter(
                    "test.primary",
                    "redacted construction failure",
                ))
            },
            |_owner| Err(DnsError::new(DnsErrorCode::Internal)),
        )
        .expect_err("injected construction failure");

        assert_eq!(
            error,
            NativeHttpRunError::ConstructionCleanup {
                primary: "http.transport.adapter",
                cleanup: DnsErrorCode::Internal,
            }
        );
        assert_eq!(error.primary_code(), Some("http.transport.adapter"));
        assert_eq!(error.cleanup_code(), Some(DnsErrorCode::Internal));
        assert_eq!(error.dns_code(), Some(DnsErrorCode::Internal));
        assert!(!error.to_string().contains("test.primary"));
        assert!(!error.to_string().contains("redacted construction failure"));
    }
}
