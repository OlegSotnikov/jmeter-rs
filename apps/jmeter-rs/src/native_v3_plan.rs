// SPDX-License-Identifier: Apache-2.0
//! Pure whole-plan Native HTTP V3 JMX compilation.
//!
//! This module is intentionally not registered by the application yet.  It
//! is an admission boundary for the next native HTTP capability: it reads an
//! already decoded semantic JMX tree, preserves source identity and scope
//! order, and emits an immutable plan descriptor.  It never resolves
//! expressions, reads a file, performs DNS/TLS work, consults process state,
//! or starts a transport.
//!
//! The compiler is deliberately strict.  The JMeter 5.6.3 class/property
//! vocabulary below is an exact allowlist.  Unknown, opaque, duplicate,
//! provider-specific, or ambiguous enabled input is an error; a disabled
//! branch is not decoded and cannot make an otherwise unused capability fail.

#![forbid(unsafe_code)]
#![allow(
    clippy::module_name_repetitions,
    reason = "the application boundary uses explicit NativeV3 HTTP type names"
)]

use std::collections::BTreeSet;
use std::fmt;
use std::mem;
use std::net::IpAddr;

use jmeter_rs_http::{
    AuthConfiguration, AuthEntry, AuthMechanism, CacheConfiguration, CookieConfiguration,
    DecompressionPolicy, DnsConfiguration, HeaderManager, HttpArgument, HttpRequestDefaults,
    HttpSamplerRequest, HttpVersionPolicy, Method, OptionalBool, OptionalString,
    ProxyConfiguration, RedirectPolicy, RequestBodySource, RequestReplayability, StaticDnsHost,
    TlsConfig, TlsTrustSource, TlsVerification,
};
use jmeter_rs_jmx::SemanticPlan;
use jmeter_rs_model::{ElementTree, NodeId, Properties, PropertyEntry, PropertyValue, TestElement};

/// Independently versioned Native HTTP V3 execution capability.
pub const NATIVE_V3_HTTP_CAPABILITY: &str = "http.native/3";
/// The executed provider recorded beside every compiled V3 plan.
pub const NATIVE_V3_EXECUTED_PROVIDER: &str = NATIVE_V3_HTTP_CAPABILITY;
/// Explicit resolver identity used by this compiler.
pub const NATIVE_V3_EXPLICIT_RESOLVER: &str = "http.execution/explicit-selector/1";
/// Auto-resolution identity, retained only so callers can reject it clearly.
pub const NATIVE_V3_AUTO_RESOLVER: &str = "http.execution/auto/1";

const MAX_TEXT_BYTES: usize = 128 * 1024;
const MAX_PLAN_NODES: usize = 100_000;
const MAX_SAMPLERS: usize = 100_000;
const MAX_SCOPE_COMPONENTS: usize = 65_536;
const MAX_ARGUMENTS: usize = 65_536;
const MAX_MULTIPART_PARTS: usize = 4_096;
const MAX_MANAGER_ENTRIES: usize = 65_536;
const MAX_TREE_DEPTH: usize = 256;
const MAX_AGGREGATE_BYTES: usize = 256 * 1024 * 1024;
const MAX_TIMEOUT_MS: u64 = 86_400_000;
const MAX_OPAQUE_WALK_VALUES: usize = MAX_MANAGER_ENTRIES;

/// Finite bounds applied before any compiler-owned output allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeV3HttpCompileLimits {
    /// Maximum semantic source nodes inspected.
    pub max_nodes: usize,
    /// Maximum enabled HTTP sampler descriptors emitted.
    pub max_samplers: usize,
    /// Maximum source nodes in one identity path.
    pub max_tree_depth: usize,
    /// Maximum configuration/manager descriptors attached to one sampler.
    pub max_scope_components: usize,
    /// Maximum scalar text retained from one source field.
    pub max_text_bytes: usize,
    /// Maximum HTTP arguments on one sampler.
    pub max_arguments: usize,
    /// Maximum file or text multipart parts on one sampler.
    pub max_multipart_parts: usize,
    /// Maximum entries in one manager descriptor.
    pub max_manager_entries: usize,
    /// Maximum aggregate bytes retained by compiler-owned descriptors.
    pub max_aggregate_bytes: usize,
}

impl Default for NativeV3HttpCompileLimits {
    fn default() -> Self {
        Self {
            max_nodes: MAX_PLAN_NODES,
            max_samplers: MAX_SAMPLERS,
            max_tree_depth: MAX_TREE_DEPTH,
            max_scope_components: MAX_SCOPE_COMPONENTS,
            max_text_bytes: MAX_TEXT_BYTES,
            max_arguments: MAX_ARGUMENTS,
            max_multipart_parts: MAX_MULTIPART_PARTS,
            max_manager_entries: MAX_MANAGER_ENTRIES,
            max_aggregate_bytes: MAX_AGGREGATE_BYTES,
        }
    }
}

impl NativeV3HttpCompileLimits {
    fn validate(self) -> Result<(), NativeV3HttpCompileError> {
        let checks = [
            ("max_nodes", self.max_nodes, MAX_PLAN_NODES),
            ("max_samplers", self.max_samplers, MAX_SAMPLERS),
            ("max_tree_depth", self.max_tree_depth, MAX_TREE_DEPTH),
            (
                "max_scope_components",
                self.max_scope_components,
                MAX_SCOPE_COMPONENTS,
            ),
            ("max_text_bytes", self.max_text_bytes, MAX_TEXT_BYTES),
            ("max_arguments", self.max_arguments, MAX_ARGUMENTS),
            (
                "max_multipart_parts",
                self.max_multipart_parts,
                MAX_MULTIPART_PARTS,
            ),
            (
                "max_manager_entries",
                self.max_manager_entries,
                MAX_MANAGER_ENTRIES,
            ),
            (
                "max_aggregate_bytes",
                self.max_aggregate_bytes,
                MAX_AGGREGATE_BYTES,
            ),
        ];
        for (dimension, observed, maximum) in checks {
            if observed == 0 || observed > maximum {
                return Err(NativeV3HttpCompileError::Limit {
                    dimension,
                    observed,
                    maximum,
                });
            }
        }
        Ok(())
    }
}

/// Redacted source coordinates retained with a compiler diagnostic.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NativeV3SourceLocation {
    /// Zero-based source byte offset, when known.
    pub byte_offset: Option<u64>,
    /// One-based source line, when known.
    pub line: Option<u32>,
    /// One-based source column, when known.
    pub column: Option<u32>,
}

/// Identity and redacted source location for one compiler error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeV3ErrorSource {
    /// Document-local node identity.
    pub node_id: NodeId,
    /// Root-to-node source identity path.
    pub path: Vec<NodeId>,
    /// Redacted source coordinates.
    pub location: NativeV3SourceLocation,
}

impl NativeV3ErrorSource {
    fn new(node_id: NodeId, path: &[NodeId], element: &TestElement) -> Self {
        Self {
            node_id,
            path: path.to_vec(),
            location: NativeV3SourceLocation {
                byte_offset: element.source().byte_offset(),
                line: element.source().line(),
                column: element.source().column(),
            },
        }
    }
}

fn element_location(element: &TestElement) -> NativeV3SourceLocation {
    NativeV3SourceLocation {
        byte_offset: element.source().byte_offset(),
        line: element.source().line(),
        column: element.source().column(),
    }
}

/// Stable failure from the pure whole-plan compiler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeV3HttpCompileError {
    /// The identity tree is malformed or an expected node is absent.
    Tree {
        /// Node identity, when one was available.
        node_id: Option<NodeId>,
        /// Bounded source path, when one was available.
        path: Vec<NodeId>,
        /// Stable topology reason.
        reason: &'static str,
    },
    /// An enabled source class is outside the exact V3 projection.
    UnsupportedElement {
        /// Source identity and location.
        source: NativeV3ErrorSource,
        /// Number of bytes in the exact testclass spelling.
        class_bytes: usize,
    },
    /// A source property is not on the exact class/property allowlist.
    UnsupportedProperty {
        /// Source identity and location.
        source: NativeV3ErrorSource,
        /// Exact property name; no property value is retained.
        property: String,
    },
    /// A property name was repeated in one semantic element.
    DuplicateProperty {
        /// Source identity and location.
        source: NativeV3ErrorSource,
        /// Exact duplicated property name.
        property: String,
    },
    /// An opaque element/property/extension cannot be interpreted safely.
    OpaqueData {
        /// Source identity and location.
        source: NativeV3ErrorSource,
        /// Stable opaque-data category.
        kind: &'static str,
    },
    /// A scalar has a different semantic type than its allowlisted wire type.
    InvalidProperty {
        /// Source identity and location.
        source: NativeV3ErrorSource,
        /// Exact source property name.
        property: String,
        /// Expected semantic kind, never the supplied value.
        expected: &'static str,
    },
    /// A required field is absent or explicitly empty.
    MissingProperty {
        /// Source identity and location.
        source: NativeV3ErrorSource,
        /// Exact source property name.
        property: String,
    },
    /// A scalar exceeded a finite source bound.
    ValueLimit {
        /// Source identity and location.
        source: NativeV3ErrorSource,
        /// Exact source property name.
        property: String,
        /// Observed byte count.
        observed: usize,
        /// Maximum accepted byte count.
        maximum: usize,
    },
    /// A provider identity is dynamic, unknown, or cannot be selected.
    UnsupportedProvider {
        /// Source identity and location.
        source: NativeV3ErrorSource,
        /// Stable provider failure category.
        capability: &'static str,
    },
    /// A known field requests an unavailable subordinate capability.
    UnsupportedCapability {
        /// Source identity and location.
        source: NativeV3ErrorSource,
        /// Stable capability identity.
        capability: &'static str,
    },
    /// More than one special manager would apply to one sampler.
    AmbiguousManager {
        /// Sampler/source identity and location.
        source: NativeV3ErrorSource,
        /// Stable manager identity.
        manager: &'static str,
        /// Number of applicable declarations.
        occurrences: usize,
    },
    /// A lower pure HTTP descriptor rejected a typed value.
    Http {
        /// Source identity and location.
        source: NativeV3ErrorSource,
        /// Property that triggered the lower edge, when known.
        property: Option<String>,
        /// Stable lower-edge code; details are deliberately omitted.
        code: &'static str,
    },
    /// A compiler resource bound was exceeded.
    Limit {
        /// Stable bounded dimension.
        dimension: &'static str,
        /// Observed count/bytes.
        observed: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// Explicit automatic resolver selection was requested.
    AutoResolutionDisabled,
}

impl NativeV3HttpCompileError {
    /// Stable machine-readable compiler error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Tree { .. } => "native.v3.tree",
            Self::UnsupportedElement { .. } => "native.v3.unsupported-element",
            Self::UnsupportedProperty { .. } => "native.v3.unsupported-property",
            Self::DuplicateProperty { .. } => "native.v3.duplicate-property",
            Self::OpaqueData { .. } => "native.v3.opaque-data",
            Self::InvalidProperty { .. } => "native.v3.invalid-property",
            Self::MissingProperty { .. } => "native.v3.missing-property",
            Self::ValueLimit { .. } => "native.v3.value-limit",
            Self::UnsupportedProvider { .. } => "native.v3.unsupported-provider",
            Self::UnsupportedCapability { .. } => "native.v3.unsupported-capability",
            Self::AmbiguousManager { .. } => "native.v3.ambiguous-manager",
            Self::Http { .. } => "native.v3.http",
            Self::Limit { .. } => "native.v3.limit",
            Self::AutoResolutionDisabled => "native.v3.auto-resolution-disabled",
        }
    }
}

impl fmt::Display for NativeV3HttpCompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())?;
        match self {
            Self::Tree {
                node_id,
                path,
                reason,
            } => write!(
                formatter,
                ": node={node_id:?}, path_len={}, reason={reason}",
                path.len()
            ),
            Self::UnsupportedElement {
                source,
                class_bytes,
            } => write!(
                formatter,
                ": node={}, path_len={}, class_bytes={class_bytes}",
                source.node_id,
                source.path.len()
            ),
            Self::UnsupportedProperty { source, property }
            | Self::DuplicateProperty { source, property }
            | Self::MissingProperty { source, property } => write!(
                formatter,
                ": node={}, path_len={}, property={property:?}",
                source.node_id,
                source.path.len()
            ),
            Self::OpaqueData { source, kind } => write!(
                formatter,
                ": node={}, path_len={}, kind={kind}",
                source.node_id,
                source.path.len()
            ),
            Self::InvalidProperty {
                source,
                property,
                expected,
            } => write!(
                formatter,
                ": node={}, path_len={}, property={property:?}, expected={expected}",
                source.node_id,
                source.path.len()
            ),
            Self::ValueLimit {
                source,
                property,
                observed,
                maximum,
            } => write!(
                formatter,
                ": node={}, path_len={}, property={property:?}, observed={observed}, maximum={maximum}",
                source.node_id,
                source.path.len()
            ),
            Self::UnsupportedProvider {
                source, capability, ..
            }
            | Self::UnsupportedCapability {
                source, capability, ..
            } => write!(
                formatter,
                ": node={}, path_len={}, capability={capability}",
                source.node_id,
                source.path.len()
            ),
            Self::AmbiguousManager {
                source,
                manager,
                occurrences,
            } => write!(
                formatter,
                ": node={}, manager={manager}, occurrences={occurrences}",
                source.node_id
            ),
            Self::Http {
                source,
                property,
                code,
                ..
            } => write!(
                formatter,
                ": node={}, property={property:?}, lower_edge={code}",
                source.node_id
            ),
            Self::Limit {
                dimension,
                observed,
                maximum,
            } => write!(formatter, ": {dimension}={observed}, maximum={maximum}"),
            Self::AutoResolutionDisabled => formatter.write_str(": explicit selector required"),
        }
    }
}

impl std::error::Error for NativeV3HttpCompileError {}

/// Source-side JMeter HTTP provider provenance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeV3SourceProvider {
    /// No implementation property was present; JMeter 5.6.3 defaults to HC4.
    JmeterDefaultHttpClient4,
    /// Explicit Java URLConnection source provider.
    Java,
    /// Explicit HttpClient4 source provider.
    HttpClient4,
}

impl NativeV3SourceProvider {
    /// Returns the source capability identity, retaining JMeter provenance.
    #[must_use]
    pub const fn capability_id(self) -> &'static str {
        match self {
            Self::JmeterDefaultHttpClient4 => "http.jmeter-httpclient4/5.6.3",
            Self::Java => "http.jmeter-java/5.6.3",
            Self::HttpClient4 => "http.jmeter-httpclient4/5.6.3",
        }
    }

    /// Returns the exact source wire spelling, if one was present.
    #[must_use]
    pub const fn wire_name(self) -> Option<&'static str> {
        match self {
            Self::JmeterDefaultHttpClient4 => None,
            Self::Java => Some("Java"),
            Self::HttpClient4 => Some("HttpClient4"),
        }
    }
}

/// Resolver identity for a complete V3 plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeV3ResolverIdentity {
    /// The caller explicitly selected NativeV3.
    ExplicitSelectorV1,
    /// Auto resolution is represented for diagnostics but rejected.
    AutoV1,
}

impl NativeV3ResolverIdentity {
    /// Returns the stable resolver identity.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExplicitSelectorV1 => NATIVE_V3_EXPLICIT_RESOLVER,
            Self::AutoV1 => NATIVE_V3_AUTO_RESOLVER,
        }
    }
}

/// Source and execution provider identities recorded for one sampler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeV3ProviderIdentity {
    /// JMeter source implementation provenance.
    pub source: NativeV3SourceProvider,
    /// Resolver identity selected by the caller.
    pub resolver: NativeV3ResolverIdentity,
    /// Executed native provider identity.
    pub executed: &'static str,
}

/// Bounded source text with explicit presence metadata.
#[derive(Clone, Eq, PartialEq)]
pub struct NativeV3Text {
    value: String,
    explicit: bool,
}

impl fmt::Debug for NativeV3Text {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeV3Text")
            .field("value", &"<redacted>")
            .field("value_bytes", &self.value.len())
            .field("explicit", &self.explicit)
            .finish()
    }
}

impl NativeV3Text {
    fn new(value: String, explicit: bool) -> Self {
        Self { value, explicit }
    }

    /// Returns the exact retained source text.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Returns whether the source field was present.
    #[must_use]
    pub const fn explicit(&self) -> bool {
        self.explicit
    }
}

/// Effective port identity, preserving dynamic source templates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeV3PortTemplate {
    /// No source port was present.
    Implicit,
    /// A source port field was present but explicitly empty; the protocol
    /// default remains selected without manufacturing port zero.
    ExplicitEmpty,
    /// A literal decimal port; zero preserves JMeter's explicit
    /// unspecified-port spelling and is omitted by URL materialization.
    Literal(u16),
    /// A bounded runtime expression; no resolution is performed here.
    Template(NativeV3Text),
}

/// Source argument with an exact pure-core projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeV3Argument {
    /// Name, preserving an absent name from raw-body arguments.
    pub name: Option<NativeV3Text>,
    /// Value, including explicit empty values.
    pub value: NativeV3Text,
    /// Separator metadata, including explicit empty metadata.
    pub metadata: NativeV3Text,
    /// URL-encoding flag and source presence.
    pub always_encode: bool,
    /// Whether `always_encode` was explicitly authored.
    pub always_encode_explicit: bool,
    /// Equals-separator flag and source presence.
    pub use_equals: bool,
    /// Whether `use_equals` was explicitly authored.
    pub use_equals_explicit: bool,
    /// Exact pure HTTP argument used by materialized request descriptors.
    pub http: HttpArgument,
}

/// File capability metadata; no path is opened or retained as a filesystem
/// authority by this pure compiler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeV3FilePart {
    /// Whether `File.path` was present on the wire.
    pub path_present: bool,
    /// Number of source path bytes, never the path itself.
    pub path_bytes: usize,
    /// Optional multipart parameter name.
    pub parameter: Option<NativeV3Text>,
    /// Optional adapter-supplied filename; the JMX file path is never
    /// retained by this pure compiler.
    pub filename: Option<NativeV3Text>,
    /// Optional MIME type.
    pub content_type: Option<NativeV3Text>,
    /// Capability is replayable only when the application proves it later.
    pub replayability: RequestReplayability,
    /// Existing pure-core marker for the file source.
    pub source: RequestBodySource,
}

/// Body mode retained independently from body presence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeV3BodyMode {
    /// Raw concatenated argument values.
    Raw,
    /// URL-encoded form argument mode.
    Form,
    /// Multipart argument/file mode.
    Multipart,
}

/// Immutable request-body descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeV3BodyPlan {
    /// The source had no body property/content.
    Missing,
    /// The source explicitly selected a body mode but retained zero bytes or
    /// zero arguments; this is distinct from [`Self::Missing`].
    PresentEmpty {
        /// Explicit body mode.
        mode: NativeV3BodyMode,
    },
    /// Raw body arguments.
    Raw {
        /// Ordered arguments.
        arguments: Vec<NativeV3Argument>,
    },
    /// URL-encoded form arguments.
    Form {
        /// Ordered arguments.
        arguments: Vec<NativeV3Argument>,
    },
    /// Multipart arguments and file capability parts.
    Multipart {
        /// Ordered text arguments.
        arguments: Vec<NativeV3Argument>,
        /// Ordered file capabilities.
        files: Vec<NativeV3FilePart>,
    },
}

impl NativeV3BodyPlan {
    /// Returns the explicit body mode, when the source selected one.
    #[must_use]
    pub const fn mode(&self) -> Option<NativeV3BodyMode> {
        match self {
            Self::Missing => None,
            Self::PresentEmpty { mode } => Some(*mode),
            Self::Raw { .. } => Some(NativeV3BodyMode::Raw),
            Self::Form { .. } => Some(NativeV3BodyMode::Form),
            Self::Multipart { .. } => Some(NativeV3BodyMode::Multipart),
        }
    }

    /// Returns whether a body was explicitly present.
    #[must_use]
    pub const fn is_present(&self) -> bool {
        !matches!(self, Self::Missing)
    }
}

/// Immutable HTTP request template.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeV3RequestTemplate {
    /// Effective method.
    pub method: Method,
    /// Whether the method was explicitly authored.
    pub method_explicit: bool,
    /// Effective protocol template.
    pub protocol: NativeV3Text,
    /// Effective host/domain template.
    pub host: NativeV3Text,
    /// Effective port template.
    pub port: NativeV3PortTemplate,
    /// Effective path template.
    pub path: NativeV3Text,
    /// Effective content encoding.
    pub content_encoding: NativeV3Text,
    /// Effective redirect switch.
    pub follow_redirects: bool,
    /// Whether redirects were explicitly authored.
    pub follow_redirects_explicit: bool,
    /// Automatic redirect switch; V3 rejects it when true.
    pub auto_redirects: bool,
    /// Whether automatic redirects were explicitly authored.
    pub auto_redirects_explicit: bool,
    /// Effective keep-alive switch.
    pub use_keepalive: bool,
    /// Whether keep-alive was explicitly authored.
    pub use_keepalive_explicit: bool,
    /// Optional connect timeout.
    pub connect_timeout_ms: Option<u64>,
    /// Whether connect timeout was explicitly authored.
    pub connect_timeout_explicit: bool,
    /// Optional response timeout.
    pub response_timeout_ms: Option<u64>,
    /// Whether response timeout was explicitly authored.
    pub response_timeout_explicit: bool,
    /// Effective embedded pool setting.
    pub concurrent_pool: Option<u16>,
    /// Whether embedded pool was explicitly authored.
    pub concurrent_pool_explicit: bool,
    /// Effective explicit proxy source fields, preserving present-empty
    /// values even when they do not form an enabled route.
    pub proxy: NativeV3ProxyTemplate,
    /// Immutable request body.
    pub body: NativeV3BodyPlan,
    /// Exact pure-core materialization when all source capabilities permit it.
    pub materialized: Option<HttpSamplerRequest>,
}

/// Scope category for manager/default provenance.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum NativeV3ScopeKind {
    /// Test-plan branch.
    TestPlan,
    /// Thread-group branch.
    ThreadGroup,
    /// Controller branch.
    Controller,
    /// Sampler-local companion branch.
    Sampler,
}

/// Source identity attached to one scoped descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeV3ScopeOrigin {
    /// Manager/default node identity.
    pub node_id: NodeId,
    /// Root-to-manager source path.
    pub path: Vec<NodeId>,
    /// Source coordinates for manager/default diagnostics.
    pub location: NativeV3SourceLocation,
    /// Branch scope category.
    pub scope: NativeV3ScopeKind,
}

/// Generic immutable scoped descriptor.
#[derive(Clone, Eq, PartialEq)]
pub struct NativeV3Scoped<T> {
    /// Source provenance.
    pub origin: NativeV3ScopeOrigin,
    /// Typed descriptor payload.
    pub value: T,
}

impl<T> fmt::Debug for NativeV3Scoped<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeV3Scoped")
            .field("origin", &self.origin)
            .field("value_present", &true)
            .finish()
    }
}

/// Native V3 request-default descriptor. The `wire` projection reuses the
/// pure HTTP defaults type wherever the source values are representable;
/// templates preserve dynamic ports without inventing a native default.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeV3RequestDefaults {
    /// HTTP core descriptor for exact static fields.
    pub wire: HttpRequestDefaults,
    /// Domain template.
    pub domain: Option<NativeV3Text>,
    /// Port template.
    pub port: Option<NativeV3Text>,
    /// Protocol template.
    pub protocol: Option<NativeV3Text>,
    /// Content-encoding template.
    pub content_encoding: Option<NativeV3Text>,
    /// Path template.
    pub path: Option<NativeV3Text>,
    /// Method template.
    pub method: Option<NativeV3Text>,
    /// Redirect switch.
    pub follow_redirects: Option<bool>,
    /// Automatic redirect switch.
    pub auto_redirects: Option<bool>,
    /// Keep-alive switch.
    pub use_keepalive: Option<bool>,
    /// Embedded concurrency switch.
    pub concurrent_downloads: Option<bool>,
    /// Embedded include expression.
    pub embedded_url_regex: Option<NativeV3Text>,
    /// Embedded exclusion expression.
    pub embedded_url_exclude_regex: Option<NativeV3Text>,
    /// Connect timeout.
    pub connect_timeout_ms: Option<u64>,
    /// Response timeout.
    pub response_timeout_ms: Option<u64>,
    /// Embedded pool size.
    pub concurrent_pool: Option<u16>,
    /// Explicit proxy source descriptor.
    pub proxy: NativeV3ProxyTemplate,
}

/// Explicit proxy fields with presence and source-template preservation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NativeV3ProxyTemplate {
    /// Proxy scheme.
    pub scheme: Option<NativeV3Text>,
    /// Proxy host.
    pub host: Option<NativeV3Text>,
    /// Proxy port.
    pub port: Option<NativeV3Text>,
    /// Username; value presence only is retained in diagnostics.
    pub username: Option<NativeV3Text>,
    /// Password presence; plaintext is never retained.
    pub password_present: Option<bool>,
    /// Non-proxy hosts.
    pub non_proxy_hosts: Option<NativeV3Text>,
}

/// Reset state with explicit source provenance.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NativeV3ResetProvenance {
    /// Cookie manager reset descriptor, if present.
    pub cookie: Option<NativeV3ResetRule>,
    /// Cache manager reset descriptor, if present.
    pub cache: Option<NativeV3ResetRule>,
    /// Auth manager reset descriptor, if present.
    pub auth: Option<NativeV3ResetRule>,
    /// DNS manager reset descriptor, if present.
    pub dns: Option<NativeV3ResetRule>,
}

/// One reset rule and the manager that supplied it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeV3ResetRule {
    /// Clear at every iteration.
    pub clear_each_iteration: Option<bool>,
    /// Clear at a thread-group boundary.
    pub thread_boundary: Option<bool>,
    /// Source manager provenance.
    pub origin: NativeV3ScopeOrigin,
}

/// All effective branch-scoped manager/default descriptors for one sampler.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NativeV3ManagerScope {
    /// Request defaults in outer-to-inner merge order.
    pub request_defaults: Vec<NativeV3Scoped<NativeV3RequestDefaults>>,
    /// Header managers in outer-to-inner merge order.
    pub headers: Vec<NativeV3Scoped<HeaderManager>>,
    /// At most one effective Cookie Manager; duplicates are ambiguous.
    pub cookie: Option<NativeV3Scoped<CookieConfiguration>>,
    /// At most one effective Cache Manager; duplicates are ambiguous.
    pub cache: Option<NativeV3Scoped<CacheConfiguration>>,
    /// At most one effective Auth Manager; duplicates are ambiguous.
    pub auth: Option<NativeV3Scoped<AuthConfiguration>>,
    /// At most one effective DNS Cache Manager; duplicates are ambiguous.
    pub dns: Option<NativeV3Scoped<DnsConfiguration>>,
    /// Explicit reset/ownership provenance.
    pub reset: NativeV3ResetProvenance,
    /// Effective merged header manager, when any header manager is present.
    pub effective_headers: Option<HeaderManager>,
}

/// DNS requirement; the runtime must supply an explicit resolver capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeV3DnsRequirement {
    /// No hostname appears in the effective request origins.
    NotRequired,
    /// An explicit bounded resolver must be selected by the execution edge.
    ExplicitResolverRequired {
        /// Versioned subordinate capability identity.
        capability: &'static str,
    },
}

/// TLS requirement and explicit trust/client material policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeV3TlsRequirement {
    /// Whether an HTTPS origin is present.
    pub enabled: bool,
    /// Typed pure TLS policy; no platform roots/private keys are synthesized.
    pub config: TlsConfig,
    /// Subordinate capability required for trust roots.
    pub trust_capability: Option<&'static str>,
    /// Client private-key capability is never enabled by this compiler.
    pub client_identity_capability: Option<&'static str>,
}

/// Redirect requirement and semantic policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeV3RedirectRequirement {
    /// Typed manual redirect policy.
    pub policy: RedirectPolicy,
    /// Whether the source requested automatic provider redirects.
    pub automatic_requested: bool,
}

/// Pooling requirement; the transport edge chooses the concrete pool.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeV3PoolingRequirement {
    /// Whether persistent connections are requested.
    pub enabled: bool,
    /// Explicit source setting, if present.
    pub source_explicit: bool,
    /// Versioned subordinate pool capability.
    pub capability: &'static str,
}

/// Response decompression requirement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeV3DecompressionRequirement {
    /// Typed bounded codec policy.
    pub policy: DecompressionPolicy,
    /// Whether source headers requested compressed response coding.
    pub requested_by_accept_encoding: bool,
    /// Versioned subordinate capability when enabled.
    pub capability: Option<&'static str>,
}

/// Embedded-resource requirement. Enabled extraction is rejected because the
/// subordinate parser/scheduler is not part of this pure compiler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeV3EmbeddedRequirement {
    /// Whether embedded extraction was requested.
    pub enabled: bool,
    /// Include/exclude source field presence.
    pub pattern_present: bool,
    /// Whether concurrent embedded downloads were explicitly present and
    /// false; a true value is rejected as unsupported.
    pub concurrent_downloads_present: bool,
    /// Whether image parsing was explicitly present and false; a true value
    /// is rejected as unsupported.
    pub image_parser_present: bool,
    /// Versioned subordinate parser identity.
    pub capability: Option<&'static str>,
}

/// Proxy requirement with an explicit policy and no ambient discovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeV3ProxyRequirement {
    /// Whether an explicit source proxy was present.
    pub enabled: bool,
    /// Typed pure route policy.
    pub policy: jmeter_rs_http::ProxyPolicy,
    /// Versioned explicit route capability.
    pub capability: Option<&'static str>,
}

/// Transport/resource requirements attached to one sampler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeV3TransportRequirements {
    /// Redirect handling.
    pub redirects: NativeV3RedirectRequirement,
    /// Response decompression.
    pub decompression: NativeV3DecompressionRequirement,
    /// Connection pooling.
    pub pooling: NativeV3PoolingRequirement,
    /// Explicit proxy route.
    pub proxy: NativeV3ProxyRequirement,
    /// TLS trust/client policy.
    pub tls: NativeV3TlsRequirement,
    /// Explicit DNS requirement.
    pub dns: NativeV3DnsRequirement,
    /// HTTP/1.1-only policy; HTTP/2 is not enabled by this compiler.
    pub http_version: HttpVersionPolicy,
    /// Optional phase timeout values.
    pub connect_timeout_ms: Option<u64>,
    /// Optional phase timeout values.
    pub response_timeout_ms: Option<u64>,
    /// Embedded resource extraction requirement.
    pub embedded: NativeV3EmbeddedRequirement,
}

/// One immutable Native V3 HTTP sampler descriptor.
#[derive(Clone, Eq, PartialEq)]
pub struct NativeV3SamplerPlan {
    /// Source node identity.
    pub node_id: NodeId,
    /// Root-to-sampler source path.
    pub path: Vec<NodeId>,
    /// Source element name (bounded and redacted by Debug).
    pub name: String,
    /// Source/resolver/executed provider identity.
    pub provider: NativeV3ProviderIdentity,
    /// Effective manager/default provenance.
    pub scope: NativeV3ManagerScope,
    /// Effective request template/body.
    pub request: NativeV3RequestTemplate,
    /// Transport/resource requirements.
    pub requirements: NativeV3TransportRequirements,
}

impl fmt::Debug for NativeV3SamplerPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeV3SamplerPlan")
            .field("node_id", &self.node_id)
            .field("path_len", &self.path.len())
            .field("name", &"<redacted>")
            .field("name_bytes", &self.name.len())
            .field("provider", &self.provider)
            .field("scope", &self.scope)
            .field("request", &self.request)
            .field("requirements", &self.requirements)
            .finish()
    }
}

/// Whole-plan resource facts.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NativeV3PlanRequirements {
    /// Whether at least one HTTP sampler exists.
    pub has_http: bool,
    /// Whether any origin may require DNS.
    pub has_hostname: bool,
    /// Whether any origin uses HTTPS.
    pub has_https: bool,
    /// Whether any explicit proxy exists.
    pub has_proxy: bool,
    /// Whether any sampler follows redirects.
    pub has_redirects: bool,
    /// Whether any sampler requests compressed response coding.
    pub has_decompression: bool,
    /// Whether any sampler requests pooling.
    pub has_pooling: bool,
    /// Enabled HTTP sampler count.
    pub sampler_count: usize,
    /// Bounded subordinate capability identities required by the plan.
    pub subordinate_capabilities: Vec<&'static str>,
}

impl NativeV3PlanRequirements {
    fn record(&mut self, requirements: &NativeV3TransportRequirements) {
        self.has_hostname |= !matches!(requirements.dns, NativeV3DnsRequirement::NotRequired);
        self.has_https |= requirements.tls.enabled;
        self.has_proxy |= requirements.proxy.enabled;
        self.has_redirects |= requirements.redirects.policy.follow;
        self.has_decompression |= requirements.decompression.policy.is_enabled();
        self.has_pooling |= requirements.pooling.enabled;
        for capability in [
            requirements.dns.capability(),
            requirements.proxy.capability,
            requirements.tls.trust_capability,
            requirements.decompression.capability,
            requirements.embedded.capability,
            requirements
                .pooling
                .enabled
                .then_some(requirements.pooling.capability),
        ]
        .into_iter()
        .flatten()
        {
            if !self.subordinate_capabilities.contains(&capability) {
                self.subordinate_capabilities.push(capability);
            }
        }
        self.subordinate_capabilities.sort_unstable();
    }
}

impl NativeV3DnsRequirement {
    fn capability(&self) -> Option<&'static str> {
        match self {
            Self::NotRequired => None,
            Self::ExplicitResolverRequired { capability } => Some(*capability),
        }
    }
}

/// An enabled semantic node preserved in source preorder.
#[derive(Clone, Eq, PartialEq)]
pub struct NativeV3PlanNode {
    /// Source node identity.
    pub node_id: NodeId,
    /// Root-to-node identity path.
    pub path: Vec<NodeId>,
    /// Exact source testclass spelling.
    pub test_class: String,
    /// Exact source element name.
    pub name: String,
}

impl fmt::Debug for NativeV3PlanNode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeV3PlanNode")
            .field("node_id", &self.node_id)
            .field("path_len", &self.path.len())
            .field("test_class", &"<redacted>")
            .field("test_class_bytes", &self.test_class.len())
            .field("name", &"<redacted>")
            .field("name_bytes", &self.name.len())
            .finish()
    }
}

/// Immutable complete Native V3 HTTP plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledNativeV3HttpPlan {
    /// Executed provider identity.
    pub provider: &'static str,
    /// Resolver identity selected at admission.
    pub resolver: NativeV3ResolverIdentity,
    /// Enabled semantic nodes retained in source order.
    pub nodes: Vec<NativeV3PlanNode>,
    /// HTTP sampler descriptors in source preorder.
    pub samplers: Vec<NativeV3SamplerPlan>,
    /// Whole-plan resource facts.
    pub requirements: NativeV3PlanRequirements,
}

impl CompiledNativeV3HttpPlan {
    /// Returns a sampler by source identity.
    #[must_use]
    pub fn sampler(&self, node_id: NodeId) -> Option<&NativeV3SamplerPlan> {
        self.samplers
            .iter()
            .find(|sampler| sampler.node_id == node_id)
    }
}

/// Standalone pure V3 JMX compiler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeV3HttpPlanCompiler {
    limits: NativeV3HttpCompileLimits,
    resolver: NativeV3ResolverIdentity,
}

impl Default for NativeV3HttpPlanCompiler {
    fn default() -> Self {
        Self::new()
    }
}

impl NativeV3HttpPlanCompiler {
    /// Creates a compiler using the explicit-selector resolver identity.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            limits: NativeV3HttpCompileLimits {
                max_nodes: MAX_PLAN_NODES,
                max_samplers: MAX_SAMPLERS,
                max_tree_depth: MAX_TREE_DEPTH,
                max_scope_components: MAX_SCOPE_COMPONENTS,
                max_text_bytes: MAX_TEXT_BYTES,
                max_arguments: MAX_ARGUMENTS,
                max_multipart_parts: MAX_MULTIPART_PARTS,
                max_manager_entries: MAX_MANAGER_ENTRIES,
                max_aggregate_bytes: MAX_AGGREGATE_BYTES,
            },
            resolver: NativeV3ResolverIdentity::ExplicitSelectorV1,
        }
    }

    /// Creates a compiler with explicit finite limits.
    #[must_use]
    pub const fn with_limits(limits: NativeV3HttpCompileLimits) -> Self {
        Self {
            limits,
            resolver: NativeV3ResolverIdentity::ExplicitSelectorV1,
        }
    }

    /// Sets the resolver identity; auto resolution fails at compile time.
    #[must_use]
    pub const fn with_resolver(mut self, resolver: NativeV3ResolverIdentity) -> Self {
        self.resolver = resolver;
        self
    }

    /// Returns compiler limits.
    #[must_use]
    pub const fn limits(self) -> NativeV3HttpCompileLimits {
        self.limits
    }

    /// Returns resolver identity.
    #[must_use]
    pub const fn resolver(self) -> NativeV3ResolverIdentity {
        self.resolver
    }

    /// Compiles one complete enabled semantic plan atomically.
    pub fn compile(
        self,
        plan: &SemanticPlan,
    ) -> Result<CompiledNativeV3HttpPlan, NativeV3HttpCompileError> {
        self.limits.validate()?;
        if matches!(self.resolver, NativeV3ResolverIdentity::AutoV1) {
            return Err(NativeV3HttpCompileError::AutoResolutionDisabled);
        }
        let tree = plan.tree();
        if tree.len() > self.limits.max_nodes {
            return Err(NativeV3HttpCompileError::Limit {
                dimension: "source-nodes",
                observed: tree.len(),
                maximum: self.limits.max_nodes,
            });
        }
        self.reject_active_duplicate_diagnostics(plan)?;
        let mut state = CompileState {
            output_nodes: Vec::new(),
            output_samplers: Vec::new(),
            requirements: NativeV3PlanRequirements::default(),
            accounting: Accounting::new(self.limits.max_aggregate_bytes),
        };
        let roots = tree.root_ids();
        if roots.len() > self.limits.max_nodes {
            return Err(NativeV3HttpCompileError::Limit {
                dimension: "source-roots",
                observed: roots.len(),
                maximum: self.limits.max_nodes,
            });
        }
        for root_id in roots {
            let root = tree.get(*root_id).ok_or(NativeV3HttpCompileError::Tree {
                node_id: Some(*root_id),
                path: Vec::new(),
                reason: "root-node-missing",
            })?;
            let path = vec![*root_id];
            if !root.value().is_enabled() {
                continue;
            }
            let root_class = classify_class(root.value().test_class());
            if !matches!(
                root_class,
                Some(ClassKind::Structural | ClassKind::SourceContainer)
            ) {
                return Err(self.unsupported_element(*root_id, &path, root.value()));
            }
            self.account_path(&mut state.accounting, &path)?;
            account_element_source(
                *root_id,
                &path,
                root.value(),
                self.limits,
                &mut state.accounting,
            )?;
            state.output_nodes.push(NativeV3PlanNode {
                node_id: *root_id,
                path: path.clone(),
                test_class: bounded_owned(
                    *root_id,
                    &path,
                    root.value(),
                    "testclass",
                    root.value().test_class(),
                    self.limits.max_text_bytes,
                    &mut state.accounting,
                )?,
                name: bounded_owned(
                    *root_id,
                    &path,
                    root.value(),
                    "testname",
                    root.value().name(),
                    self.limits.max_text_bytes,
                    &mut state.accounting,
                )?,
            });
            self.validate_structural_properties(*root_id, &path, root.value())?;
            if matches!(root_class, Some(ClassKind::SourceContainer)) {
                continue;
            }
            self.walk_branch(
                tree,
                root.children(),
                &path,
                &ScopeAccumulator::default(),
                root.value().test_class(),
                &mut state,
            )?;
        }
        state.requirements.has_http = !state.output_samplers.is_empty();
        state.requirements.sampler_count = state.output_samplers.len();
        Ok(CompiledNativeV3HttpPlan {
            provider: NATIVE_V3_EXECUTED_PROVIDER,
            resolver: self.resolver,
            nodes: state.output_nodes,
            samplers: state.output_samplers,
            requirements: state.requirements,
        })
    }

    fn reject_active_duplicate_diagnostics(
        self,
        plan: &SemanticPlan,
    ) -> Result<(), NativeV3HttpCompileError> {
        for diagnostic in plan.diagnostics() {
            if diagnostic.code != "jmx.semantic.duplicate_property" {
                continue;
            }
            let Some(node_id) = diagnostic.node_id else {
                continue;
            };
            let Some(node) = plan.tree().get(node_id) else {
                continue;
            };
            if !node.value().is_enabled() {
                continue;
            }
            let path = plan
                .tree()
                .path_to_bounded(node_id, self.limits.max_tree_depth)
                .map_err(|_| NativeV3HttpCompileError::Tree {
                    node_id: Some(node_id),
                    path: Vec::new(),
                    reason: "duplicate-diagnostic-path",
                })?;
            let mut active = true;
            for ancestor in &path {
                let Some(ancestor_node) = plan.tree().get(*ancestor) else {
                    active = false;
                    break;
                };
                if !ancestor_node.value().is_enabled() {
                    active = false;
                    break;
                }
            }
            if !active {
                continue;
            }
            return Err(NativeV3HttpCompileError::DuplicateProperty {
                source: NativeV3ErrorSource::new(node_id, &path, node.value()),
                property: "<duplicate-wire-property>".to_owned(),
            });
        }
        Ok(())
    }

    fn walk_branch(
        self,
        tree: &ElementTree,
        children: &[NodeId],
        parent_path: &[NodeId],
        inherited: &ScopeAccumulator,
        owner_class: &str,
        state: &mut CompileState,
    ) -> Result<(), NativeV3HttpCompileError> {
        if parent_path.len() >= self.limits.max_tree_depth {
            return Err(NativeV3HttpCompileError::Limit {
                dimension: "tree-depth",
                observed: parent_path.len().saturating_add(1),
                maximum: self.limits.max_tree_depth,
            });
        }
        if children.len() > self.limits.max_nodes {
            return Err(NativeV3HttpCompileError::Limit {
                dimension: "branch-children",
                observed: children.len(),
                maximum: self.limits.max_nodes,
            });
        }
        let mut items = Vec::with_capacity(children.len());
        for id in children {
            let node = tree.get(*id).ok_or(NativeV3HttpCompileError::Tree {
                node_id: Some(*id),
                path: parent_path.to_vec(),
                reason: "child-node-missing",
            })?;
            if !node.value().is_enabled() {
                continue;
            }
            let path = path_with(parent_path, *id, self.limits.max_tree_depth)?;
            self.account_path(&mut state.accounting, &path)?;
            account_element_source(*id, &path, node.value(), self.limits, &mut state.accounting)?;
            let component = self.parse_component(*id, &path, node.value())?;
            state.output_nodes.push(NativeV3PlanNode {
                node_id: *id,
                path: path.clone(),
                test_class: bounded_owned(
                    *id,
                    &path,
                    node.value(),
                    "testclass",
                    node.value().test_class(),
                    self.limits.max_text_bytes,
                    &mut state.accounting,
                )?,
                name: bounded_owned(
                    *id,
                    &path,
                    node.value(),
                    "testname",
                    node.value().name(),
                    self.limits.max_text_bytes,
                    &mut state.accounting,
                )?,
            });
            items.push(BranchItem {
                id: *id,
                path,
                component,
            });
        }

        let branch_scope_kind = scope_kind(owner_class, false);
        let mut branch_scope = inherited.clone();
        for item in &items {
            if let Component::Declaration(declaration) = &item.component {
                self.add_declaration(&mut branch_scope, declaration, branch_scope_kind, state)?;
            }
        }

        for item in items {
            let node = tree.get(item.id).ok_or(NativeV3HttpCompileError::Tree {
                node_id: Some(item.id),
                path: item.path.clone(),
                reason: "parsed-node-missing",
            })?;
            match item.component {
                Component::Sampler(fields) => {
                    if state.output_samplers.len() >= self.limits.max_samplers {
                        return Err(NativeV3HttpCompileError::Limit {
                            dimension: "samplers",
                            observed: state.output_samplers.len().saturating_add(1),
                            maximum: self.limits.max_samplers,
                        });
                    }
                    let mut local_scope = branch_scope.clone();
                    self.collect_sampler_children(
                        tree,
                        item.id,
                        &item.path,
                        &mut local_scope,
                        state,
                    )?;
                    let sampler = self.compile_sampler(
                        item.id,
                        item.path,
                        *fields,
                        local_scope,
                        node.value(),
                        state,
                    )?;
                    state.requirements.record(&sampler.requirements);
                    state.output_samplers.push(sampler);
                }
                Component::Structural => {
                    self.validate_structural_properties(item.id, &item.path, node.value())?;
                    self.walk_branch(
                        tree,
                        node.children(),
                        &item.path,
                        &branch_scope,
                        node.value().test_class(),
                        state,
                    )?;
                }
                Component::SourceContainer => {}
                Component::Declaration(_) => {
                    if !node.children().is_empty() {
                        return Err(NativeV3HttpCompileError::Tree {
                            node_id: Some(item.id),
                            path: item.path,
                            reason: "manager-has-executable-children",
                        });
                    }
                }
            }
        }
        Ok(())
    }

    fn collect_sampler_children(
        self,
        tree: &ElementTree,
        sampler_id: NodeId,
        sampler_path: &[NodeId],
        scope: &mut ScopeAccumulator,
        state: &mut CompileState,
    ) -> Result<(), NativeV3HttpCompileError> {
        let sampler = tree.get(sampler_id).ok_or(NativeV3HttpCompileError::Tree {
            node_id: Some(sampler_id),
            path: sampler_path.to_vec(),
            reason: "sampler-node-missing",
        })?;
        for child_id in sampler.children() {
            let child = tree.get(*child_id).ok_or(NativeV3HttpCompileError::Tree {
                node_id: Some(*child_id),
                path: sampler_path.to_vec(),
                reason: "sampler-child-missing",
            })?;
            if !child.value().is_enabled() {
                continue;
            }
            let path = path_with(sampler_path, *child_id, self.limits.max_tree_depth)?;
            self.account_path(&mut state.accounting, &path)?;
            account_element_source(
                *child_id,
                &path,
                child.value(),
                self.limits,
                &mut state.accounting,
            )?;
            let component = self.parse_component(*child_id, &path, child.value())?;
            match component {
                Component::Declaration(declaration) => {
                    self.add_declaration(scope, &declaration, NativeV3ScopeKind::Sampler, state)?;
                }
                Component::SourceContainer => {}
                Component::Sampler(_) | Component::Structural => {
                    return Err(NativeV3HttpCompileError::UnsupportedCapability {
                        source: NativeV3ErrorSource::new(*child_id, &path, child.value()),
                        capability: "http.sampler-child-executable",
                    });
                }
            }
        }
        Ok(())
    }

    fn parse_component(
        self,
        node_id: NodeId,
        path: &[NodeId],
        element: &TestElement,
    ) -> Result<Component, NativeV3HttpCompileError> {
        if !element.opaque_extensions.is_empty() {
            return Err(NativeV3HttpCompileError::OpaqueData {
                source: NativeV3ErrorSource::new(node_id, path, element),
                kind: "element-extension",
            });
        }
        let Some(kind) = classify_class(element.test_class()) else {
            return Err(self.unsupported_element(node_id, path, element));
        };
        match kind {
            ClassKind::Sampler => Ok(Component::Sampler(Box::new(parse_sampler_fields(
                node_id,
                path,
                element,
                self.limits,
            )?))),
            ClassKind::Defaults => Ok(Component::Declaration(Declaration::Defaults(Box::new(
                parse_defaults(node_id, path, element, self.limits)?,
            )))),
            ClassKind::Header => Ok(Component::Declaration(Declaration::Header(
                parse_header_manager(node_id, path, element, self.limits)?,
            ))),
            ClassKind::Cookie => Ok(Component::Declaration(Declaration::Cookie(
                parse_cookie_manager(node_id, path, element, self.limits)?,
            ))),
            ClassKind::Cache => Ok(Component::Declaration(Declaration::Cache(
                parse_cache_manager(node_id, path, element, self.limits)?,
            ))),
            ClassKind::Auth => Ok(Component::Declaration(Declaration::Auth(
                parse_auth_manager(node_id, path, element, self.limits)?,
            ))),
            ClassKind::Dns => Ok(Component::Declaration(Declaration::Dns(parse_dns_manager(
                node_id,
                path,
                element,
                self.limits,
            )?))),
            ClassKind::Tls => Err(NativeV3HttpCompileError::UnsupportedCapability {
                source: NativeV3ErrorSource::new(node_id, path, element),
                capability: "http.tls.jvm-keystore-provider",
            }),
            ClassKind::Structural => {
                self.validate_structural_properties(node_id, path, element)?;
                Ok(Component::Structural)
            }
            ClassKind::SourceContainer => Ok(Component::SourceContainer),
        }
    }

    fn add_declaration(
        self,
        scope: &mut ScopeAccumulator,
        declaration: &Declaration,
        scope_kind: NativeV3ScopeKind,
        state: &mut CompileState,
    ) -> Result<(), NativeV3HttpCompileError> {
        let (node_id, path) = declaration.identity();
        let location = declaration.location();
        if scope.component_count() >= self.limits.max_scope_components {
            return Err(NativeV3HttpCompileError::Limit {
                dimension: "scope-components",
                observed: scope.component_count().saturating_add(1),
                maximum: self.limits.max_scope_components,
            });
        }
        let origin = NativeV3ScopeOrigin {
            node_id,
            path: path.to_vec(),
            location,
            scope: scope_kind,
        };
        self.account_path(&mut state.accounting, path)?;
        match declaration {
            Declaration::Defaults(value) => scope.defaults.push(NativeV3Scoped {
                origin,
                value: value.value.clone(),
            }),
            Declaration::Header(value) => scope.headers.push(NativeV3Scoped {
                origin,
                value: value.value.clone(),
            }),
            Declaration::Cookie(value) => {
                scope.cookie = some_or_ambiguous(
                    scope.cookie.take(),
                    NativeV3Scoped {
                        origin,
                        value: value.value.clone(),
                    },
                    "http.cookie-manager",
                    node_id,
                    path,
                    location,
                )?;
            }
            Declaration::Cache(value) => {
                scope.cache = some_or_ambiguous(
                    scope.cache.take(),
                    NativeV3Scoped {
                        origin,
                        value: value.value.clone(),
                    },
                    "http.cache-manager",
                    node_id,
                    path,
                    location,
                )?;
            }
            Declaration::Auth(value) => {
                scope.auth = some_or_ambiguous(
                    scope.auth.take(),
                    NativeV3Scoped {
                        origin,
                        value: value.value.clone(),
                    },
                    "http.auth-manager",
                    node_id,
                    path,
                    location,
                )?;
            }
            Declaration::Dns(value) => {
                scope.dns = some_or_ambiguous(
                    scope.dns.take(),
                    NativeV3Scoped {
                        origin,
                        value: value.value.clone(),
                    },
                    "http.dns-manager",
                    node_id,
                    path,
                    location,
                )?;
            }
        }
        scope.recompute_effective_headers()?;
        scope.recompute_reset();
        Ok(())
    }

    fn compile_sampler(
        self,
        node_id: NodeId,
        path: Vec<NodeId>,
        fields: SamplerFields,
        scope: ScopeAccumulator,
        element: &TestElement,
        state: &mut CompileState,
    ) -> Result<NativeV3SamplerPlan, NativeV3HttpCompileError> {
        let effective = merge_effective_fields(&scope.defaults, &fields.request)?;
        let source = parse_source_provider(node_id, &path, &effective.implementation, element)?;
        let protocol = effective
            .protocol
            .clone()
            .unwrap_or_else(|| NativeV3Text::new("http".to_owned(), false));
        if protocol.value().is_empty()
            || (!protocol.value().eq_ignore_ascii_case("http")
                && !protocol.value().eq_ignore_ascii_case("https"))
        {
            return Err(NativeV3HttpCompileError::UnsupportedCapability {
                source: NativeV3ErrorSource::new(node_id, &path, element),
                capability: "http.protocol",
            });
        }
        if is_expression(protocol.value()) {
            return Err(NativeV3HttpCompileError::UnsupportedCapability {
                source: NativeV3ErrorSource::new(node_id, &path, element),
                capability: "http.dynamic-protocol",
            });
        }
        let host = effective
            .domain
            .clone()
            .filter(|value| !value.value().is_empty())
            .ok_or_else(|| NativeV3HttpCompileError::MissingProperty {
                source: NativeV3ErrorSource::new(node_id, &path, element),
                property: "HTTPSampler.domain".to_owned(),
            })?;
        if host.value().bytes().any(|byte| byte.is_ascii_whitespace()) {
            return Err(NativeV3HttpCompileError::InvalidProperty {
                source: NativeV3ErrorSource::new(node_id, &path, element),
                property: "HTTPSampler.domain".to_owned(),
                expected: "HTTP host without whitespace",
            });
        }
        let method_text = effective
            .method
            .clone()
            .unwrap_or_else(|| NativeV3Text::new("GET".to_owned(), false));
        if is_expression(method_text.value()) {
            return Err(NativeV3HttpCompileError::UnsupportedCapability {
                source: NativeV3ErrorSource::new(node_id, &path, element),
                capability: "http.dynamic-method",
            });
        }
        let method = Method::parse(method_text.value()).map_err(|error| {
            http_error(
                node_id,
                &path,
                element,
                Some("HTTPSampler.method"),
                error.stable_code(),
            )
        })?;
        let encoding = effective
            .content_encoding
            .clone()
            .unwrap_or_else(|| NativeV3Text::new("UTF-8".to_owned(), false));
        if is_expression(encoding.value()) {
            return Err(NativeV3HttpCompileError::UnsupportedCapability {
                source: NativeV3ErrorSource::new(node_id, &path, element),
                capability: "http.dynamic-content-encoding",
            });
        }
        let path_template = match effective.path.clone() {
            Some(value) if value.value().is_empty() => {
                NativeV3Text::new("/".to_owned(), value.explicit())
            }
            Some(value) if !value.value().starts_with('/') && !is_expression(value.value()) => {
                return Err(NativeV3HttpCompileError::InvalidProperty {
                    source: NativeV3ErrorSource::new(node_id, &path, element),
                    property: "HTTPSampler.path".to_owned(),
                    expected: "origin-form path",
                });
            }
            Some(value) => value,
            None => NativeV3Text::new("/".to_owned(), false),
        };
        if path_template.value().contains('#') {
            return Err(NativeV3HttpCompileError::InvalidProperty {
                source: NativeV3ErrorSource::new(node_id, &path, element),
                property: "HTTPSampler.path".to_owned(),
                expected: "origin-form path without fragment",
            });
        }
        let auto_redirects = effective.auto_redirects.unwrap_or(false);
        if auto_redirects {
            return Err(NativeV3HttpCompileError::UnsupportedCapability {
                source: NativeV3ErrorSource::new(node_id, &path, element),
                capability: "http.automatic-redirects",
            });
        }
        let follow_redirects = effective.follow_redirects.unwrap_or(true);
        let keepalive = effective.use_keepalive.unwrap_or(true);
        let body = parse_body_plan(
            node_id,
            &path,
            element,
            fields.body,
            self.limits,
            &mut state.accounting,
        )?;
        let proxy = effective_proxy(node_id, &path, element, &effective.proxy)?;
        let headers = scope.effective_headers.as_ref();
        let compressed = headers.is_some_and(accepts_compressed_response);
        let decompression = NativeV3DecompressionRequirement {
            policy: if compressed {
                DecompressionPolicy::common()
            } else {
                DecompressionPolicy::Disabled
            },
            requested_by_accept_encoding: compressed,
            capability: compressed.then_some("http.decompression/1"),
        };
        let embedded_enabled = effective.concurrent_downloads.unwrap_or(false)
            || effective
                .embedded_url_regex
                .as_ref()
                .is_some_and(|value| !value.value().is_empty())
            || effective
                .embedded_url_exclude_regex
                .as_ref()
                .is_some_and(|value| !value.value().is_empty())
            || fields.image_parser.unwrap_or(false);
        if embedded_enabled {
            return Err(NativeV3HttpCompileError::UnsupportedCapability {
                source: NativeV3ErrorSource::new(node_id, &path, element),
                capability: "http.embedded/1",
            });
        }
        let embedded = NativeV3EmbeddedRequirement {
            enabled: false,
            pattern_present: effective.embedded_url_regex.is_some()
                || effective.embedded_url_exclude_regex.is_some(),
            concurrent_downloads_present: effective.concurrent_downloads.is_some(),
            image_parser_present: fields.image_parser.is_some(),
            capability: None,
        };
        let tls_enabled = protocol.value().eq_ignore_ascii_case("https");
        let tls = NativeV3TlsRequirement {
            enabled: tls_enabled,
            config: TlsConfig {
                trust_source: TlsTrustSource::Explicit,
                verification: TlsVerification::Verify,
                ..TlsConfig::default()
            },
            trust_capability: tls_enabled.then_some("http.tls.explicit-roots/1"),
            client_identity_capability: None,
        };
        let dns = if is_ip_literal(host.value()) {
            NativeV3DnsRequirement::NotRequired
        } else {
            NativeV3DnsRequirement::ExplicitResolverRequired {
                capability: "http.dns.explicit/1",
            }
        };
        if effective
            .concurrent_pool
            .is_some_and(|pool| pool == 0 || pool > 256)
        {
            return Err(NativeV3HttpCompileError::Limit {
                dimension: "embedded-pool",
                observed: effective.concurrent_pool.unwrap_or_default() as usize,
                maximum: 256,
            });
        }
        let requirements = NativeV3TransportRequirements {
            redirects: NativeV3RedirectRequirement {
                policy: RedirectPolicy {
                    follow: follow_redirects,
                    ..RedirectPolicy::default()
                },
                automatic_requested: false,
            },
            decompression,
            pooling: NativeV3PoolingRequirement {
                enabled: keepalive,
                source_explicit: effective.use_keepalive.is_some(),
                capability: "http.pool/1",
            },
            proxy,
            tls,
            dns,
            http_version: HttpVersionPolicy::Http11Only,
            connect_timeout_ms: effective.connect_timeout_ms,
            response_timeout_ms: effective.response_timeout_ms,
            embedded,
        };
        let request = NativeV3RequestTemplate {
            method,
            method_explicit: effective.method.is_some(),
            protocol,
            host,
            port: effective
                .port
                .map_or(Ok(NativeV3PortTemplate::Implicit), parse_port_template)
                .map_err(|_| NativeV3HttpCompileError::InvalidProperty {
                    source: NativeV3ErrorSource::new(node_id, &path, element),
                    property: "HTTPSampler.port".to_owned(),
                    expected: "u16 or expression",
                })?,
            path: path_template,
            content_encoding: encoding,
            follow_redirects,
            follow_redirects_explicit: effective.follow_redirects.is_some(),
            auto_redirects,
            auto_redirects_explicit: effective.auto_redirects.is_some(),
            use_keepalive: keepalive,
            use_keepalive_explicit: effective.use_keepalive.is_some(),
            connect_timeout_ms: effective.connect_timeout_ms,
            connect_timeout_explicit: effective.connect_timeout_explicit,
            response_timeout_ms: effective.response_timeout_ms,
            response_timeout_explicit: effective.response_timeout_explicit,
            concurrent_pool: effective.concurrent_pool,
            concurrent_pool_explicit: effective.concurrent_pool_explicit,
            proxy: effective.proxy,
            body,
            materialized: None,
        };
        let mut request = request;
        request.materialized = materialize_request(&request, headers, node_id, &path, element)?;
        let name = bounded_owned(
            node_id,
            &path,
            element,
            "testname",
            element.name(),
            self.limits.max_text_bytes,
            &mut state.accounting,
        )?;
        Ok(NativeV3SamplerPlan {
            node_id,
            path,
            name,
            provider: NativeV3ProviderIdentity {
                source,
                resolver: self.resolver,
                executed: NATIVE_V3_EXECUTED_PROVIDER,
            },
            scope: scope.into_public(),
            request,
            requirements,
        })
    }

    fn validate_structural_properties(
        self,
        node_id: NodeId,
        path: &[NodeId],
        element: &TestElement,
    ) -> Result<(), NativeV3HttpCompileError> {
        validate_properties(node_id, path, element)?;
        if !element.opaque_extensions.is_empty() {
            return Err(NativeV3HttpCompileError::OpaqueData {
                source: NativeV3ErrorSource::new(node_id, path, element),
                kind: "structural-extension",
            });
        }
        let class = element.test_class();
        for entry in element.properties.iter() {
            if !structural_property_allowed(class, entry.name.as_str()) {
                return Err(NativeV3HttpCompileError::UnsupportedProperty {
                    source: NativeV3ErrorSource::new(node_id, path, element),
                    property: entry.name.clone(),
                });
            }
            reject_opaque_value(node_id, path, element, &entry.value, "structural-opaque")?;
            validate_structural_scalar(
                node_id,
                path,
                element,
                class,
                entry.name.as_str(),
                &entry.value,
                self.limits,
            )?;
            if let PropertyValue::Element(nested) = &entry.value {
                validate_structural_nested(node_id, path, element, entry.name.as_str(), nested)?;
            }
        }
        if !element.temporary_properties.is_empty() {
            return Err(NativeV3HttpCompileError::UnsupportedProperty {
                source: NativeV3ErrorSource::new(node_id, path, element),
                property: "temporary-properties".to_owned(),
            });
        }
        Ok(())
    }

    fn unsupported_element(
        self,
        node_id: NodeId,
        path: &[NodeId],
        element: &TestElement,
    ) -> NativeV3HttpCompileError {
        NativeV3HttpCompileError::UnsupportedElement {
            source: NativeV3ErrorSource::new(node_id, path, element),
            class_bytes: element.test_class().len(),
        }
    }

    fn account_path(
        self,
        accounting: &mut Accounting,
        path: &[NodeId],
    ) -> Result<(), NativeV3HttpCompileError> {
        let bytes = path.len().checked_mul(mem::size_of::<NodeId>()).ok_or(
            NativeV3HttpCompileError::Limit {
                dimension: "aggregate-bytes",
                observed: usize::MAX,
                maximum: accounting.maximum,
            },
        )?;
        accounting.charge(bytes)
    }
}

/// Convenience function using the explicit NativeV3 selector identity.
pub fn compile_native_v3_http_plan(
    plan: &SemanticPlan,
) -> Result<CompiledNativeV3HttpPlan, NativeV3HttpCompileError> {
    NativeV3HttpPlanCompiler::new().compile(plan)
}

struct CompileState {
    output_nodes: Vec<NativeV3PlanNode>,
    output_samplers: Vec<NativeV3SamplerPlan>,
    requirements: NativeV3PlanRequirements,
    accounting: Accounting,
}

struct Accounting {
    used: usize,
    maximum: usize,
}

impl Accounting {
    const fn new(maximum: usize) -> Self {
        Self { used: 0, maximum }
    }

    fn charge(&mut self, bytes: usize) -> Result<(), NativeV3HttpCompileError> {
        let next = self
            .used
            .checked_add(bytes)
            .ok_or(NativeV3HttpCompileError::Limit {
                dimension: "aggregate-bytes",
                observed: usize::MAX,
                maximum: self.maximum,
            })?;
        if next > self.maximum {
            return Err(NativeV3HttpCompileError::Limit {
                dimension: "aggregate-bytes",
                observed: next,
                maximum: self.maximum,
            });
        }
        self.used = next;
        Ok(())
    }
}

/// Charges source text/metadata before a known element is decoded into
/// compiler-owned descriptors.  The semantic model has already bounded the
/// input at its parser boundary, but this admission pass keeps the V3 output
/// budget independent and checked before request/manager clones occur.
fn account_element_source(
    node_id: NodeId,
    path: &[NodeId],
    element: &TestElement,
    limits: NativeV3HttpCompileLimits,
    accounting: &mut Accounting,
) -> Result<(), NativeV3HttpCompileError> {
    for entry in element.properties.iter() {
        account_source_text(
            node_id,
            path,
            element,
            &entry.name,
            &entry.name,
            limits,
            accounting,
        )?;
        account_property_value(
            node_id,
            path,
            element,
            &entry.name,
            &entry.value,
            0,
            limits,
            accounting,
        )?;
    }
    Ok(())
}

fn validate_structural_scalar(
    node_id: NodeId,
    path: &[NodeId],
    element: &TestElement,
    _class: &str,
    property: &str,
    value: &PropertyValue,
    limits: NativeV3HttpCompileLimits,
) -> Result<(), NativeV3HttpCompileError> {
    match property {
        "TestPlan.comments"
        | "TestPlan.user_define_classpath"
        | "ThreadGroup.on_sample_error"
        | "ThreadGroup.num_threads"
        | "ThreadGroup.ramp_time"
        | "ThreadGroup.duration"
        | "ThreadGroup.delay"
        | "LoopController.loops"
        | "LoopController.num_loops"
        | "IfController.condition"
        | "WhileController.condition"
        | "ForeachController.inputVal"
        | "ForeachController.returnVal"
        | "ModuleController.node_path"
        | "IncludeController.includepath"
        | "RuntimeController.seconds"
        | "RunTime" => {
            let text =
                value
                    .as_string()
                    .map_err(|_| NativeV3HttpCompileError::InvalidProperty {
                        source: NativeV3ErrorSource::new(node_id, path, element),
                        property: property.to_owned(),
                        expected: "string",
                    })?;
            if matches!(
                property,
                "TestPlan.user_define_classpath"
                    | "IncludeController.includepath"
                    | "ModuleController.node_path"
            ) && !text.is_empty()
            {
                return Err(NativeV3HttpCompileError::UnsupportedCapability {
                    source: NativeV3ErrorSource::new(node_id, path, element),
                    capability: "test.external-plan-reference",
                });
            }
            if text.len() > limits.max_text_bytes {
                return Err(NativeV3HttpCompileError::ValueLimit {
                    source: NativeV3ErrorSource::new(node_id, path, element),
                    property: property.to_owned(),
                    observed: text.len(),
                    maximum: limits.max_text_bytes,
                });
            }
        }
        "TestPlan.functional_mode"
        | "TestPlan.serialize_threadgroups"
        | "ThreadGroup.scheduler"
        | "ThreadGroup.same_user_on_next_iteration"
        | "LoopController.continue_forever"
        | "TransactionController.includeTimers"
        | "TransactionController.parent"
        | "IfController.evaluateAll"
        | "IfController.useExpression"
        | "ForeachController.useSeparator"
        | "ThroughputController.perThread" => {
            if !matches!(value, PropertyValue::Boolean(_)) {
                return Err(NativeV3HttpCompileError::InvalidProperty {
                    source: NativeV3ErrorSource::new(node_id, path, element),
                    property: property.to_owned(),
                    expected: "boolean",
                });
            }
        }
        "TestPlan.thread_groups" => match value {
            PropertyValue::Collection(values) if values.is_empty() => {}
            PropertyValue::NamedCollection(values) if values.is_empty() => {}
            PropertyValue::Map(values) if values.is_empty() => {}
            PropertyValue::Collection(_)
            | PropertyValue::NamedCollection(_)
            | PropertyValue::Map(_) => {
                return Err(NativeV3HttpCompileError::UnsupportedCapability {
                    source: NativeV3ErrorSource::new(node_id, path, element),
                    capability: "test.thread-group-list",
                });
            }
            _ => {
                return Err(NativeV3HttpCompileError::InvalidProperty {
                    source: NativeV3ErrorSource::new(node_id, path, element),
                    property: property.to_owned(),
                    expected: "empty collection",
                });
            }
        },
        "InterleaveControl.style" | "ThroughputController.style" => {
            if !matches!(
                value,
                PropertyValue::String(_) | PropertyValue::Integer(_) | PropertyValue::Long(_)
            ) {
                return Err(NativeV3HttpCompileError::InvalidProperty {
                    source: NativeV3ErrorSource::new(node_id, path, element),
                    property: property.to_owned(),
                    expected: "string or integer",
                });
            }
        }
        "ThroughputController.maxThroughput" => {
            if !matches!(
                value,
                PropertyValue::String(_)
                    | PropertyValue::Integer(_)
                    | PropertyValue::Long(_)
                    | PropertyValue::Float(_)
                    | PropertyValue::Double(_)
            ) {
                return Err(NativeV3HttpCompileError::InvalidProperty {
                    source: NativeV3ErrorSource::new(node_id, path, element),
                    property: property.to_owned(),
                    expected: "numeric value",
                });
            }
        }
        "ThreadGroup.start_time" | "ThreadGroup.end_time"
            if !matches!(
                value,
                PropertyValue::Integer(_) | PropertyValue::Long(_) | PropertyValue::String(_)
            ) =>
        {
            return Err(NativeV3HttpCompileError::InvalidProperty {
                source: NativeV3ErrorSource::new(node_id, path, element),
                property: property.to_owned(),
                expected: "integer or string",
            });
        }
        _ => {}
    }
    Ok(())
}

fn account_source_text(
    node_id: NodeId,
    path: &[NodeId],
    element: &TestElement,
    property: &str,
    value: &str,
    limits: NativeV3HttpCompileLimits,
    accounting: &mut Accounting,
) -> Result<(), NativeV3HttpCompileError> {
    if value.len() > limits.max_text_bytes {
        return Err(NativeV3HttpCompileError::ValueLimit {
            source: NativeV3ErrorSource::new(node_id, path, element),
            property: property.to_owned(),
            observed: value.len(),
            maximum: limits.max_text_bytes,
        });
    }
    accounting.charge(value.len())
}

#[allow(
    clippy::too_many_arguments,
    reason = "source-accounting keeps the diagnostic source and independent limits explicit"
)]
fn account_property_value(
    node_id: NodeId,
    path: &[NodeId],
    element: &TestElement,
    property: &str,
    value: &PropertyValue,
    depth: usize,
    limits: NativeV3HttpCompileLimits,
    accounting: &mut Accounting,
) -> Result<(), NativeV3HttpCompileError> {
    if depth > MAX_TREE_DEPTH {
        return Err(NativeV3HttpCompileError::Limit {
            dimension: "source-value-depth",
            observed: depth,
            maximum: MAX_TREE_DEPTH,
        });
    }
    let mut stack = vec![(value, depth)];
    while let Some((value, depth)) = stack.pop() {
        if depth > MAX_TREE_DEPTH {
            return Err(NativeV3HttpCompileError::Limit {
                dimension: "source-value-depth",
                observed: depth,
                maximum: MAX_TREE_DEPTH,
            });
        }
        match value {
            PropertyValue::String(value) => {
                account_source_text(node_id, path, element, property, value, limits, accounting)?
            }
            PropertyValue::Collection(values) => {
                if values.len() > MAX_OPAQUE_WALK_VALUES {
                    return Err(NativeV3HttpCompileError::Limit {
                        dimension: "source-value-count",
                        observed: values.len(),
                        maximum: MAX_OPAQUE_WALK_VALUES,
                    });
                }
                for child in values {
                    if stack.len() >= MAX_OPAQUE_WALK_VALUES {
                        return Err(NativeV3HttpCompileError::Limit {
                            dimension: "source-value-count",
                            observed: stack.len().saturating_add(1),
                            maximum: MAX_OPAQUE_WALK_VALUES,
                        });
                    }
                    stack.push((child, depth.saturating_add(1)));
                }
            }
            PropertyValue::NamedCollection(values) | PropertyValue::Map(values) => {
                if values.len() > MAX_OPAQUE_WALK_VALUES {
                    return Err(NativeV3HttpCompileError::Limit {
                        dimension: "source-value-count",
                        observed: values.len(),
                        maximum: MAX_OPAQUE_WALK_VALUES,
                    });
                }
                for entry in values {
                    account_source_text(
                        node_id,
                        path,
                        element,
                        property,
                        &entry.name,
                        limits,
                        accounting,
                    )?;
                    if stack.len() >= MAX_OPAQUE_WALK_VALUES {
                        return Err(NativeV3HttpCompileError::Limit {
                            dimension: "source-value-count",
                            observed: stack.len().saturating_add(1),
                            maximum: MAX_OPAQUE_WALK_VALUES,
                        });
                    }
                    stack.push((&entry.value, depth.saturating_add(1)));
                }
            }
            PropertyValue::Element(nested) => {
                account_source_text(
                    node_id,
                    path,
                    element,
                    property,
                    &nested.name,
                    limits,
                    accounting,
                )?;
                if let Some(class_name) = nested.class_name() {
                    account_source_text(
                        node_id, path, element, property, class_name, limits, accounting,
                    )?;
                }
                if nested.properties.len() > MAX_OPAQUE_WALK_VALUES {
                    return Err(NativeV3HttpCompileError::Limit {
                        dimension: "source-value-count",
                        observed: nested.properties.len(),
                        maximum: MAX_OPAQUE_WALK_VALUES,
                    });
                }
                for entry in nested.properties.iter() {
                    account_source_text(
                        node_id,
                        path,
                        element,
                        property,
                        &entry.name,
                        limits,
                        accounting,
                    )?;
                    if stack.len() >= MAX_OPAQUE_WALK_VALUES {
                        return Err(NativeV3HttpCompileError::Limit {
                            dimension: "source-value-count",
                            observed: stack.len().saturating_add(1),
                            maximum: MAX_OPAQUE_WALK_VALUES,
                        });
                    }
                    stack.push((&entry.value, depth.saturating_add(1)));
                }
            }
            PropertyValue::Object(value) => {
                if value.raw.len() > limits.max_aggregate_bytes {
                    return Err(NativeV3HttpCompileError::Limit {
                        dimension: "source-object-bytes",
                        observed: value.raw.len(),
                        maximum: limits.max_aggregate_bytes,
                    });
                }
                accounting.charge(value.raw.len())?;
                if let Some(class_name) = value.class_name() {
                    account_source_text(
                        node_id, path, element, property, class_name, limits, accounting,
                    )?;
                }
                for attribute in &value.attributes {
                    account_source_text(
                        node_id,
                        path,
                        element,
                        property,
                        &attribute.name,
                        limits,
                        accounting,
                    )?;
                    account_source_text(
                        node_id,
                        path,
                        element,
                        property,
                        &attribute.value,
                        limits,
                        accounting,
                    )?;
                }
            }
            PropertyValue::Null
            | PropertyValue::Boolean(_)
            | PropertyValue::Integer(_)
            | PropertyValue::Long(_)
            | PropertyValue::Float(_)
            | PropertyValue::Double(_)
            | PropertyValue::Opaque(_) => {}
        }
    }
    Ok(())
}

#[derive(Clone)]
struct BranchItem {
    id: NodeId,
    path: Vec<NodeId>,
    component: Component,
}

#[derive(Clone)]
enum Component {
    Sampler(Box<SamplerFields>),
    Structural,
    SourceContainer,
    Declaration(Declaration),
}

#[derive(Clone)]
struct SamplerFields {
    request: RequestFields,
    body: BodyFields,
    image_parser: Option<bool>,
}

#[derive(Clone, Default)]
struct RequestFields {
    domain: Option<NativeV3Text>,
    port: Option<NativeV3Text>,
    protocol: Option<NativeV3Text>,
    content_encoding: Option<NativeV3Text>,
    path: Option<NativeV3Text>,
    method: Option<NativeV3Text>,
    implementation: Option<NativeV3Text>,
    follow_redirects: Option<bool>,
    auto_redirects: Option<bool>,
    use_keepalive: Option<bool>,
    concurrent_downloads: Option<bool>,
    embedded_url_regex: Option<NativeV3Text>,
    embedded_url_exclude_regex: Option<NativeV3Text>,
    connect_timeout_ms: Option<u64>,
    connect_timeout_explicit: bool,
    response_timeout_ms: Option<u64>,
    response_timeout_explicit: bool,
    concurrent_pool: Option<u16>,
    concurrent_pool_explicit: bool,
    proxy: NativeV3ProxyTemplate,
}

#[derive(Clone, Default)]
struct BodyFields {
    present: bool,
    post_body_raw: Option<bool>,
    multipart: Option<bool>,
    arguments: Vec<NativeV3Argument>,
    files: Vec<NativeV3FilePart>,
}

#[derive(Clone)]
enum Declaration {
    Defaults(Box<ParsedDeclaration<NativeV3RequestDefaults>>),
    Header(ParsedDeclaration<HeaderManager>),
    Cookie(ParsedDeclaration<CookieConfiguration>),
    Cache(ParsedDeclaration<CacheConfiguration>),
    Auth(ParsedDeclaration<AuthConfiguration>),
    Dns(ParsedDeclaration<DnsConfiguration>),
}

#[derive(Clone)]
struct ParsedDeclaration<T> {
    node_id: NodeId,
    path: Vec<NodeId>,
    location: NativeV3SourceLocation,
    value: T,
}

impl Declaration {
    fn identity(&self) -> (NodeId, &Vec<NodeId>) {
        match self {
            Self::Defaults(value) => (value.node_id, &value.path),
            Self::Header(value) => (value.node_id, &value.path),
            Self::Cookie(value) => (value.node_id, &value.path),
            Self::Cache(value) => (value.node_id, &value.path),
            Self::Auth(value) => (value.node_id, &value.path),
            Self::Dns(value) => (value.node_id, &value.path),
        }
    }

    fn location(&self) -> NativeV3SourceLocation {
        match self {
            Self::Defaults(value) => value.location,
            Self::Header(value) => value.location,
            Self::Cookie(value) => value.location,
            Self::Cache(value) => value.location,
            Self::Auth(value) => value.location,
            Self::Dns(value) => value.location,
        }
    }
}

#[derive(Clone, Default)]
struct ScopeAccumulator {
    defaults: Vec<NativeV3Scoped<NativeV3RequestDefaults>>,
    headers: Vec<NativeV3Scoped<HeaderManager>>,
    cookie: Option<NativeV3Scoped<CookieConfiguration>>,
    cache: Option<NativeV3Scoped<CacheConfiguration>>,
    auth: Option<NativeV3Scoped<AuthConfiguration>>,
    dns: Option<NativeV3Scoped<DnsConfiguration>>,
    effective_headers: Option<HeaderManager>,
    reset: NativeV3ResetProvenance,
}

impl ScopeAccumulator {
    fn component_count(&self) -> usize {
        self.defaults.len()
            + self.headers.len()
            + usize::from(self.cookie.is_some())
            + usize::from(self.cache.is_some())
            + usize::from(self.auth.is_some())
            + usize::from(self.dns.is_some())
    }

    fn recompute_effective_headers(&mut self) -> Result<(), NativeV3HttpCompileError> {
        let mut merged: Option<HeaderManager> = None;
        for item in &self.headers {
            if let Some(current) = &mut merged {
                current.merge_ordered(&item.value).map_err(|error| {
                    NativeV3HttpCompileError::Http {
                        source: NativeV3ErrorSource {
                            node_id: item.origin.node_id,
                            path: item.origin.path.clone(),
                            location: item.origin.location,
                        },
                        property: None,
                        code: error.stable_code(),
                    }
                })?;
            } else {
                merged = Some(item.value.clone());
            }
        }
        self.effective_headers = merged;
        Ok(())
    }

    fn recompute_reset(&mut self) {
        self.reset = NativeV3ResetProvenance {
            cookie: self.cookie.as_ref().map(|item| NativeV3ResetRule {
                clear_each_iteration: item.value.clear_each_iteration.value(),
                thread_boundary: item.value.controlled_by_thread_group.value(),
                origin: item.origin.clone(),
            }),
            cache: self.cache.as_ref().map(|item| NativeV3ResetRule {
                clear_each_iteration: item.value.clear_each_iteration.value(),
                thread_boundary: item.value.controlled_by_thread.value(),
                origin: item.origin.clone(),
            }),
            auth: self.auth.as_ref().map(|item| NativeV3ResetRule {
                clear_each_iteration: item.value.clear_each_iteration.value(),
                thread_boundary: item.value.controlled_by_thread_group.value(),
                origin: item.origin.clone(),
            }),
            dns: self.dns.as_ref().map(|item| NativeV3ResetRule {
                clear_each_iteration: item.value.clear_each_iteration.value(),
                thread_boundary: None,
                origin: item.origin.clone(),
            }),
        };
    }

    fn into_public(self) -> NativeV3ManagerScope {
        NativeV3ManagerScope {
            request_defaults: self.defaults,
            headers: self.headers,
            cookie: self.cookie,
            cache: self.cache,
            auth: self.auth,
            dns: self.dns,
            reset: self.reset,
            effective_headers: self.effective_headers,
        }
    }
}

fn some_or_ambiguous<T>(
    previous: Option<NativeV3Scoped<T>>,
    current: NativeV3Scoped<T>,
    manager: &'static str,
    node_id: NodeId,
    path: &[NodeId],
    location: NativeV3SourceLocation,
) -> Result<Option<NativeV3Scoped<T>>, NativeV3HttpCompileError> {
    if previous.is_some() {
        return Err(NativeV3HttpCompileError::AmbiguousManager {
            source: NativeV3ErrorSource {
                node_id,
                path: path.to_vec(),
                location,
            },
            manager,
            occurrences: 2,
        });
    }
    Ok(Some(current))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClassKind {
    Sampler,
    Defaults,
    Header,
    Cookie,
    Cache,
    Auth,
    Dns,
    Tls,
    Structural,
    SourceContainer,
}

fn classify_class(class: &str) -> Option<ClassKind> {
    const SAMPLER: &[&str] = &[
        "HTTPSamplerProxy",
        "org.apache.jmeter.protocol.http.sampler.HTTPSamplerProxy",
    ];
    const DEFAULTS: &[&str] = &[
        "ConfigTestElement",
        "org.apache.jmeter.config.ConfigTestElement",
    ];
    const HEADER: &[&str] = &[
        "HeaderManager",
        "HTTPHeaderManager",
        "org.apache.jmeter.protocol.http.control.HeaderManager",
    ];
    const COOKIE: &[&str] = &[
        "CookieManager",
        "org.apache.jmeter.protocol.http.control.CookieManager",
    ];
    const CACHE: &[&str] = &[
        "CacheManager",
        "org.apache.jmeter.protocol.http.control.CacheManager",
    ];
    const AUTH: &[&str] = &[
        "AuthManager",
        "org.apache.jmeter.protocol.http.control.AuthManager",
    ];
    const DNS: &[&str] = &[
        "DNSCacheManager",
        "org.apache.jmeter.protocol.http.control.DNSCacheManager",
    ];
    const TLS: &[&str] = &[
        "SSLManager",
        "org.apache.jmeter.protocol.http.config.KeystoreConfig",
        "KeystoreConfig",
        "KeystoreConfiguration",
    ];
    const SOURCE: &[&str] = &[
        "WorkBench",
        "org.apache.jmeter.testelement.WorkBench",
        "TestFragmentController",
        "org.apache.jmeter.control.TestFragmentController",
    ];
    const STRUCTURAL: &[&str] = &[
        "TestPlan",
        "org.apache.jmeter.testelement.TestPlan",
        "ThreadGroup",
        "org.apache.jmeter.threads.ThreadGroup",
        "setUpTestGroup",
        "tearDownTestGroup",
        "SetupThreadGroup",
        "TeardownThreadGroup",
        "LoopController",
        "org.apache.jmeter.control.LoopController",
        "GenericController",
        "org.apache.jmeter.control.GenericController",
        "SimpleController",
        "org.apache.jmeter.control.GenericController",
        "TransactionController",
        "org.apache.jmeter.control.TransactionController",
        "IfController",
        "org.apache.jmeter.control.IfController",
        "WhileController",
        "org.apache.jmeter.control.WhileController",
        "ForEachController",
        "org.apache.jmeter.control.ForEachController",
        "OnceOnlyController",
        "org.apache.jmeter.control.OnceOnlyController",
        "InterleaveControl",
        "org.apache.jmeter.control.InterleaveControl",
        "RandomOrderController",
        "org.apache.jmeter.control.RandomOrderController",
        "ThroughputController",
        "org.apache.jmeter.control.ThroughputController",
        "ModuleController",
        "org.apache.jmeter.control.ModuleController",
        "IncludeController",
        "org.apache.jmeter.control.IncludeController",
        "RuntimeController",
        "org.apache.jmeter.control.RuntimeController",
    ];
    if SAMPLER.contains(&class) {
        Some(ClassKind::Sampler)
    } else if DEFAULTS.contains(&class) {
        Some(ClassKind::Defaults)
    } else if HEADER.contains(&class) {
        Some(ClassKind::Header)
    } else if COOKIE.contains(&class) {
        Some(ClassKind::Cookie)
    } else if CACHE.contains(&class) {
        Some(ClassKind::Cache)
    } else if AUTH.contains(&class) {
        Some(ClassKind::Auth)
    } else if DNS.contains(&class) {
        Some(ClassKind::Dns)
    } else if TLS.contains(&class) {
        Some(ClassKind::Tls)
    } else if SOURCE.contains(&class) {
        Some(ClassKind::SourceContainer)
    } else if STRUCTURAL.contains(&class) {
        Some(ClassKind::Structural)
    } else {
        None
    }
}

fn scope_kind(owner_class: &str, sampler: bool) -> NativeV3ScopeKind {
    if sampler {
        return NativeV3ScopeKind::Sampler;
    }
    if owner_class.contains("TestPlan") || owner_class == "TestPlan" {
        NativeV3ScopeKind::TestPlan
    } else if owner_class.contains("ThreadGroup")
        || owner_class == "setUpTestGroup"
        || owner_class == "tearDownTestGroup"
    {
        NativeV3ScopeKind::ThreadGroup
    } else {
        NativeV3ScopeKind::Controller
    }
}

fn structural_property_allowed(class: &str, property: &str) -> bool {
    match class {
        "TestPlan" | "org.apache.jmeter.testelement.TestPlan" => matches!(
            property,
            "TestPlan.comments"
                | "TestPlan.functional_mode"
                | "TestPlan.serialize_threadgroups"
                | "TestPlan.thread_groups"
                | "TestPlan.user_defined_variables"
                | "TestPlan.user_define_classpath"
        ),
        "ThreadGroup"
        | "org.apache.jmeter.threads.ThreadGroup"
        | "setUpTestGroup"
        | "tearDownTestGroup"
        | "SetupThreadGroup"
        | "TeardownTestGroup" => matches!(
            property,
            "ThreadGroup.on_sample_error"
                | "ThreadGroup.main_controller"
                | "ThreadGroup.num_threads"
                | "ThreadGroup.ramp_time"
                | "ThreadGroup.start_time"
                | "ThreadGroup.end_time"
                | "ThreadGroup.scheduler"
                | "ThreadGroup.duration"
                | "ThreadGroup.delay"
                | "ThreadGroup.same_user_on_next_iteration"
                | "ThreadGroup.loops"
                | "ThreadGroup.loop_controller"
        ),
        "LoopController" | "org.apache.jmeter.control.LoopController" => matches!(
            property,
            "LoopController.continue_forever" | "LoopController.loops" | "LoopController.num_loops"
        ),
        "TransactionController" | "org.apache.jmeter.control.TransactionController" => {
            matches!(
                property,
                "TransactionController.includeTimers" | "TransactionController.parent"
            )
        }
        "IfController" | "org.apache.jmeter.control.IfController" => matches!(
            property,
            "IfController.condition" | "IfController.evaluateAll" | "IfController.useExpression"
        ),
        "WhileController" | "org.apache.jmeter.control.WhileController" => {
            property == "WhileController.condition"
        }
        "ForEachController" | "org.apache.jmeter.control.ForEachController" => matches!(
            property,
            "ForeachController.inputVal"
                | "ForeachController.returnVal"
                | "ForeachController.useSeparator"
        ),
        "ThroughputController" | "org.apache.jmeter.control.ThroughputController" => matches!(
            property,
            "ThroughputController.style"
                | "ThroughputController.perThread"
                | "ThroughputController.maxThroughput"
        ),
        "ModuleController" | "org.apache.jmeter.control.ModuleController" => {
            property == "ModuleController.node_path"
        }
        "IncludeController" | "org.apache.jmeter.control.IncludeController" => {
            property == "IncludeController.includepath"
        }
        "RuntimeController" | "org.apache.jmeter.control.RuntimeController" => {
            property == "RunTime" || property == "RuntimeController.seconds"
        }
        "InterleaveControl" | "org.apache.jmeter.control.InterleaveControl" => {
            property == "InterleaveControl.style"
        }
        _ => false,
    }
}

fn validate_structural_nested(
    node_id: NodeId,
    path: &[NodeId],
    element: &TestElement,
    property: &str,
    nested: &jmeter_rs_model::ElementProperty,
) -> Result<(), NativeV3HttpCompileError> {
    if !nested.opaque_extensions.is_empty() {
        return Err(NativeV3HttpCompileError::OpaqueData {
            source: NativeV3ErrorSource::new(node_id, path, element),
            kind: "structural-nested-extension",
        });
    }
    match property {
        "TestPlan.user_defined_variables" => {
            if nested.name != "TestPlan.user_defined_variables" {
                return Err(NativeV3HttpCompileError::InvalidProperty {
                    source: NativeV3ErrorSource::new(node_id, path, element),
                    property: property.to_owned(),
                    expected: "Arguments element",
                });
            }
            validate_nested_allowlist(
                node_id,
                path,
                element,
                &nested.properties,
                &["Arguments.arguments"],
            )?;
            if let Some(value) = nested.properties.get("Arguments.arguments") {
                let values = collection_values(
                    node_id,
                    path,
                    element,
                    value,
                    "Arguments.arguments",
                    MAX_ARGUMENTS,
                    "structural-variable-arguments",
                )?;
                if !values.is_empty() {
                    return Err(NativeV3HttpCompileError::UnsupportedCapability {
                        source: NativeV3ErrorSource::new(node_id, path, element),
                        capability: "test.variables",
                    });
                }
            }
        }
        "ThreadGroup.main_controller" | "ThreadGroup.loop_controller" => {
            let class = nested.class_name().unwrap_or_default();
            if class != "LoopController" && class != "org.apache.jmeter.control.LoopController" {
                return Err(NativeV3HttpCompileError::UnsupportedCapability {
                    source: NativeV3ErrorSource::new(node_id, path, element),
                    capability: "test.thread-controller",
                });
            }
            validate_nested_allowlist(
                node_id,
                path,
                element,
                &nested.properties,
                &[
                    "LoopController.continue_forever",
                    "LoopController.loops",
                    "LoopController.num_loops",
                ],
            )?;
        }
        _ => {
            return Err(NativeV3HttpCompileError::UnsupportedProperty {
                source: NativeV3ErrorSource::new(node_id, path, element),
                property: property.to_owned(),
            });
        }
    }
    Ok(())
}

fn path_with(
    parent: &[NodeId],
    id: NodeId,
    maximum: usize,
) -> Result<Vec<NodeId>, NativeV3HttpCompileError> {
    if parent.len() >= maximum {
        return Err(NativeV3HttpCompileError::Limit {
            dimension: "tree-depth",
            observed: parent.len().saturating_add(1),
            maximum,
        });
    }
    let mut path = Vec::with_capacity(parent.len().saturating_add(1));
    path.extend_from_slice(parent);
    path.push(id);
    Ok(path)
}

fn validate_properties(
    node_id: NodeId,
    path: &[NodeId],
    element: &TestElement,
) -> Result<(), NativeV3HttpCompileError> {
    let mut names = BTreeSet::new();
    for entry in element.properties.iter() {
        if !names.insert(entry.name.as_str()) {
            return Err(NativeV3HttpCompileError::DuplicateProperty {
                source: NativeV3ErrorSource::new(node_id, path, element),
                property: entry.name.clone(),
            });
        }
    }
    if !element.temporary_properties.is_empty() {
        return Err(NativeV3HttpCompileError::UnsupportedProperty {
            source: NativeV3ErrorSource::new(node_id, path, element),
            property: "temporary-properties".to_owned(),
        });
    }
    Ok(())
}

fn validate_allowlist(
    node_id: NodeId,
    path: &[NodeId],
    element: &TestElement,
    allowed: &[&str],
) -> Result<(), NativeV3HttpCompileError> {
    validate_properties(node_id, path, element)?;
    for entry in element.properties.iter() {
        if !allowed.contains(&entry.name.as_str()) {
            return Err(NativeV3HttpCompileError::UnsupportedProperty {
                source: NativeV3ErrorSource::new(node_id, path, element),
                property: entry.name.clone(),
            });
        }
        reject_opaque_value(node_id, path, element, &entry.value, "property-opaque")?;
    }
    Ok(())
}

fn reject_opaque_value(
    node_id: NodeId,
    path: &[NodeId],
    element: &TestElement,
    value: &PropertyValue,
    kind: &'static str,
) -> Result<(), NativeV3HttpCompileError> {
    let mut stack = vec![(value, 0usize)];
    while let Some((value, depth)) = stack.pop() {
        if depth > MAX_TREE_DEPTH {
            return Err(NativeV3HttpCompileError::Limit {
                dimension: "opaque-value-depth",
                observed: depth,
                maximum: MAX_TREE_DEPTH,
            });
        }
        match value {
            PropertyValue::Opaque(_) | PropertyValue::Object(_) => {
                return Err(NativeV3HttpCompileError::OpaqueData {
                    source: NativeV3ErrorSource::new(node_id, path, element),
                    kind,
                });
            }
            PropertyValue::Collection(values) => {
                if values.len() > MAX_OPAQUE_WALK_VALUES {
                    return Err(NativeV3HttpCompileError::Limit {
                        dimension: "opaque-value-count",
                        observed: values.len(),
                        maximum: MAX_OPAQUE_WALK_VALUES,
                    });
                }
                for child in values {
                    if stack.len() >= MAX_OPAQUE_WALK_VALUES {
                        return Err(NativeV3HttpCompileError::Limit {
                            dimension: "opaque-value-count",
                            observed: stack.len().saturating_add(1),
                            maximum: MAX_OPAQUE_WALK_VALUES,
                        });
                    }
                    stack.push((child, depth.saturating_add(1)));
                }
            }
            PropertyValue::NamedCollection(values) | PropertyValue::Map(values) => {
                if values.len() > MAX_OPAQUE_WALK_VALUES {
                    return Err(NativeV3HttpCompileError::Limit {
                        dimension: "opaque-value-count",
                        observed: values.len(),
                        maximum: MAX_OPAQUE_WALK_VALUES,
                    });
                }
                for entry in values {
                    if stack.len() >= MAX_OPAQUE_WALK_VALUES {
                        return Err(NativeV3HttpCompileError::Limit {
                            dimension: "opaque-value-count",
                            observed: stack.len().saturating_add(1),
                            maximum: MAX_OPAQUE_WALK_VALUES,
                        });
                    }
                    stack.push((&entry.value, depth.saturating_add(1)));
                }
            }
            PropertyValue::Element(nested) => {
                if !nested.opaque_extensions.is_empty() {
                    return Err(NativeV3HttpCompileError::OpaqueData {
                        source: NativeV3ErrorSource::new(node_id, path, element),
                        kind,
                    });
                }
                if nested.properties.len() > MAX_OPAQUE_WALK_VALUES {
                    return Err(NativeV3HttpCompileError::Limit {
                        dimension: "opaque-value-count",
                        observed: nested.properties.len(),
                        maximum: MAX_OPAQUE_WALK_VALUES,
                    });
                }
                for child in nested.properties.values() {
                    if stack.len() >= MAX_OPAQUE_WALK_VALUES {
                        return Err(NativeV3HttpCompileError::Limit {
                            dimension: "opaque-value-count",
                            observed: stack.len().saturating_add(1),
                            maximum: MAX_OPAQUE_WALK_VALUES,
                        });
                    }
                    stack.push((child, depth.saturating_add(1)));
                }
            }
            PropertyValue::Null
            | PropertyValue::String(_)
            | PropertyValue::Boolean(_)
            | PropertyValue::Integer(_)
            | PropertyValue::Long(_)
            | PropertyValue::Float(_)
            | PropertyValue::Double(_) => {}
        }
    }
    Ok(())
}

fn bounded_text(
    node_id: NodeId,
    path: &[NodeId],
    element: &TestElement,
    property: &str,
    value: &str,
    maximum: usize,
) -> Result<String, NativeV3HttpCompileError> {
    if value.len() > maximum {
        return Err(NativeV3HttpCompileError::ValueLimit {
            source: NativeV3ErrorSource::new(node_id, path, element),
            property: property.to_owned(),
            observed: value.len(),
            maximum,
        });
    }
    if value.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return Err(NativeV3HttpCompileError::InvalidProperty {
            source: NativeV3ErrorSource::new(node_id, path, element),
            property: property.to_owned(),
            expected: "UTF-8 text without control bytes",
        });
    }
    Ok(value.to_owned())
}

fn bounded_owned(
    node_id: NodeId,
    path: &[NodeId],
    element: &TestElement,
    property: &str,
    value: &str,
    maximum: usize,
    accounting: &mut Accounting,
) -> Result<String, NativeV3HttpCompileError> {
    let value = bounded_text(node_id, path, element, property, value, maximum)?;
    accounting.charge(value.len())?;
    Ok(value)
}

fn text_entry(
    node_id: NodeId,
    path: &[NodeId],
    element: &TestElement,
    entry: &PropertyEntry,
    limits: NativeV3HttpCompileLimits,
) -> Result<NativeV3Text, NativeV3HttpCompileError> {
    let value = entry
        .value
        .as_string()
        .map_err(|_| NativeV3HttpCompileError::InvalidProperty {
            source: NativeV3ErrorSource::new(node_id, path, element),
            property: entry.name.clone(),
            expected: "string",
        })?;
    Ok(NativeV3Text::new(
        bounded_text(
            node_id,
            path,
            element,
            &entry.name,
            value,
            limits.max_text_bytes,
        )?,
        true,
    ))
}

fn body_text_entry(
    node_id: NodeId,
    path: &[NodeId],
    element: &TestElement,
    entry: &PropertyEntry,
    limits: NativeV3HttpCompileLimits,
) -> Result<NativeV3Text, NativeV3HttpCompileError> {
    let value = entry
        .value
        .as_string()
        .map_err(|_| NativeV3HttpCompileError::InvalidProperty {
            source: NativeV3ErrorSource::new(node_id, path, element),
            property: entry.name.clone(),
            expected: "string",
        })?;
    if value.len() > limits.max_text_bytes {
        return Err(NativeV3HttpCompileError::ValueLimit {
            source: NativeV3ErrorSource::new(node_id, path, element),
            property: entry.name.clone(),
            observed: value.len(),
            maximum: limits.max_text_bytes,
        });
    }
    if value
        .bytes()
        .any(|byte| (byte < 0x20 && !matches!(byte, b'\t' | b'\n' | b'\r')) || byte == 0x7f)
    {
        return Err(NativeV3HttpCompileError::InvalidProperty {
            source: NativeV3ErrorSource::new(node_id, path, element),
            property: entry.name.clone(),
            expected: "UTF-8 body text without unsafe control bytes",
        });
    }
    Ok(NativeV3Text::new(value.to_owned(), true))
}

fn bool_entry(
    node_id: NodeId,
    path: &[NodeId],
    element: &TestElement,
    entry: &PropertyEntry,
) -> Result<bool, NativeV3HttpCompileError> {
    entry
        .value
        .as_boolean()
        .map_err(|_| NativeV3HttpCompileError::InvalidProperty {
            source: NativeV3ErrorSource::new(node_id, path, element),
            property: entry.name.clone(),
            expected: "boolean",
        })
}

fn integer_entry(
    node_id: NodeId,
    path: &[NodeId],
    element: &TestElement,
    entry: &PropertyEntry,
    limits: NativeV3HttpCompileLimits,
    allow_empty: bool,
) -> Result<Option<u64>, NativeV3HttpCompileError> {
    let value = match &entry.value {
        PropertyValue::Integer(value) => u64::try_from(i64::from(*value)).map_err(|_| {
            NativeV3HttpCompileError::InvalidProperty {
                source: NativeV3ErrorSource::new(node_id, path, element),
                property: entry.name.clone(),
                expected: "non-negative integer",
            }
        })?,
        PropertyValue::Long(value) => {
            u64::try_from(*value).map_err(|_| NativeV3HttpCompileError::InvalidProperty {
                source: NativeV3ErrorSource::new(node_id, path, element),
                property: entry.name.clone(),
                expected: "non-negative integer",
            })?
        }
        PropertyValue::String(value) => {
            let value = bounded_text(
                node_id,
                path,
                element,
                &entry.name,
                value,
                limits.max_text_bytes,
            )?;
            if value.is_empty() && allow_empty {
                return Ok(None);
            }
            value
                .parse::<u64>()
                .map_err(|_| NativeV3HttpCompileError::InvalidProperty {
                    source: NativeV3ErrorSource::new(node_id, path, element),
                    property: entry.name.clone(),
                    expected: "non-negative integer or empty string",
                })?
        }
        _ => {
            return Err(NativeV3HttpCompileError::InvalidProperty {
                source: NativeV3ErrorSource::new(node_id, path, element),
                property: entry.name.clone(),
                expected: "integer or string",
            });
        }
    };
    if value > MAX_TIMEOUT_MS && (entry.name.contains("timeout") || entry.name.contains("Timeout"))
    {
        return Err(NativeV3HttpCompileError::ValueLimit {
            source: NativeV3ErrorSource::new(node_id, path, element),
            property: entry.name.clone(),
            observed: value as usize,
            maximum: MAX_TIMEOUT_MS as usize,
        });
    }
    Ok(Some(value))
}

fn optional_text(
    node_id: NodeId,
    path: &[NodeId],
    element: &TestElement,
    properties: &Properties,
    name: &'static str,
    limits: NativeV3HttpCompileLimits,
) -> Result<Option<NativeV3Text>, NativeV3HttpCompileError> {
    properties
        .get_entry(name)
        .map(|entry| text_entry(node_id, path, element, entry, limits))
        .transpose()
}

fn parse_sampler_fields(
    node_id: NodeId,
    path: &[NodeId],
    element: &TestElement,
    limits: NativeV3HttpCompileLimits,
) -> Result<SamplerFields, NativeV3HttpCompileError> {
    let (request, body, image_parser) = parse_request_fields(node_id, path, element, limits, true)?;
    Ok(SamplerFields {
        request,
        body,
        image_parser,
    })
}

fn parse_defaults(
    node_id: NodeId,
    path: &[NodeId],
    element: &TestElement,
    limits: NativeV3HttpCompileLimits,
) -> Result<ParsedDeclaration<NativeV3RequestDefaults>, NativeV3HttpCompileError> {
    if !element.gui_class().is_empty() && element.gui_class() != "HttpDefaultsGui" {
        return Err(NativeV3HttpCompileError::UnsupportedElement {
            source: NativeV3ErrorSource::new(node_id, path, element),
            class_bytes: element.test_class().len(),
        });
    }
    let (fields, body, image_parser) = parse_request_fields(node_id, path, element, limits, false)?;
    if body.post_body_raw.is_some() || body.multipart.is_some() {
        return Err(NativeV3HttpCompileError::UnsupportedCapability {
            source: NativeV3ErrorSource::new(node_id, path, element),
            capability: "http.defaults.body-mode",
        });
    }
    if body.present && (!body.arguments.is_empty() || !body.files.is_empty()) {
        return Err(NativeV3HttpCompileError::UnsupportedCapability {
            source: NativeV3ErrorSource::new(node_id, path, element),
            capability: "http.defaults.arguments",
        });
    }
    if image_parser.is_some_and(|value| value) {
        return Err(NativeV3HttpCompileError::UnsupportedCapability {
            source: NativeV3ErrorSource::new(node_id, path, element),
            capability: "http.embedded/1",
        });
    }
    if fields.auto_redirects.is_some_and(|value| value) {
        return Err(NativeV3HttpCompileError::UnsupportedCapability {
            source: NativeV3ErrorSource::new(node_id, path, element),
            capability: "http.automatic-redirects",
        });
    }
    if fields.concurrent_downloads.is_some_and(|value| value)
        || fields
            .embedded_url_regex
            .as_ref()
            .is_some_and(|value| !value.value().is_empty())
        || fields
            .embedded_url_exclude_regex
            .as_ref()
            .is_some_and(|value| !value.value().is_empty())
    {
        return Err(NativeV3HttpCompileError::UnsupportedCapability {
            source: NativeV3ErrorSource::new(node_id, path, element),
            capability: "http.embedded/1",
        });
    }
    if let Some(port) = &fields.port
        && !port.value().is_empty()
        && !is_expression(port.value())
        && port.value().parse::<u16>().is_err()
    {
        return Err(NativeV3HttpCompileError::InvalidProperty {
            source: NativeV3ErrorSource::new(node_id, path, element),
            property: "HTTPSampler.port".to_owned(),
            expected: "u16 or expression",
        });
    }
    if fields.implementation.is_some() {
        let _ = parse_source_provider(node_id, path, &fields.implementation, element)?;
    }
    let _ = effective_proxy(node_id, path, element, &fields.proxy)?;
    let wire = fields_to_http_defaults(&fields).map_err(|code| NativeV3HttpCompileError::Http {
        source: NativeV3ErrorSource::new(node_id, path, element),
        property: None,
        code,
    })?;
    Ok(ParsedDeclaration {
        node_id,
        path: path.to_vec(),
        location: element_location(element),
        value: NativeV3RequestDefaults {
            wire,
            domain: fields.domain,
            port: fields.port,
            protocol: fields.protocol,
            content_encoding: fields.content_encoding,
            path: fields.path,
            method: fields.method,
            follow_redirects: fields.follow_redirects,
            auto_redirects: fields.auto_redirects,
            use_keepalive: fields.use_keepalive,
            concurrent_downloads: fields.concurrent_downloads,
            embedded_url_regex: fields.embedded_url_regex,
            embedded_url_exclude_regex: fields.embedded_url_exclude_regex,
            connect_timeout_ms: fields.connect_timeout_ms,
            response_timeout_ms: fields.response_timeout_ms,
            concurrent_pool: fields.concurrent_pool,
            proxy: fields.proxy,
        },
    })
}

#[allow(
    clippy::field_reassign_with_default,
    reason = "the parser fills source-preserving optional fields in wire order"
)]
fn parse_request_fields(
    node_id: NodeId,
    path: &[NodeId],
    element: &TestElement,
    limits: NativeV3HttpCompileLimits,
    sampler: bool,
) -> Result<(RequestFields, BodyFields, Option<bool>), NativeV3HttpCompileError> {
    validate_properties(node_id, path, element)?;
    let allowed = [
        "HTTPSampler.domain",
        "HTTPSampler.port",
        "HTTPSampler.protocol",
        "HTTPSampler.contentEncoding",
        "HTTPSampler.path",
        "HTTPSampler.method",
        "HTTPSampler.implementation",
        "HTTPSampler.follow_redirects",
        "HTTPSampler.auto_redirects",
        "HTTPSampler.use_keepalive",
        "HTTPSampler.concurrentDwn",
        "HTTPSampler.image_parser",
        "HTTPSampler.embedded_url_re",
        "HTTPSampler.embedded_url_exclude_re",
        "HTTPSampler.connect_timeout",
        "HTTPSampler.response_timeout",
        "HTTPSampler.concurrentPool",
        "HTTPSampler.postBodyRaw",
        "HTTPSampler.DO_MULTIPART_POST",
        "HTTPSampler.files",
        "HTTPsampler.Arguments",
        "HTTPSampler.proxyScheme",
        "HTTPSampler.proxyHost",
        "HTTPSampler.proxyPort",
        "HTTPSampler.proxyUser",
        "HTTPSampler.proxyPass",
    ];
    for entry in element.properties.iter() {
        if !allowed.contains(&entry.name.as_str()) {
            return Err(NativeV3HttpCompileError::UnsupportedProperty {
                source: NativeV3ErrorSource::new(node_id, path, element),
                property: entry.name.clone(),
            });
        }
        reject_opaque_value(node_id, path, element, &entry.value, "property-opaque")?;
        if !sampler
            && matches!(
                entry.name.as_str(),
                "HTTPSampler.postBodyRaw" | "HTTPSampler.DO_MULTIPART_POST" | "HTTPSampler.files"
            )
        {
            if entry.name == "HTTPSampler.files" {
                let _ = parse_files(node_id, path, element, entry, limits)?;
            } else if entry.name == "HTTPSampler.postBodyRaw"
                || entry.name == "HTTPSampler.DO_MULTIPART_POST"
            {
                let _ = bool_entry(node_id, path, element, entry)?;
            }
        }
    }
    let mut fields = RequestFields::default();
    fields.domain = optional_text(
        node_id,
        path,
        element,
        &element.properties,
        "HTTPSampler.domain",
        limits,
    )?;
    fields.port = optional_text(
        node_id,
        path,
        element,
        &element.properties,
        "HTTPSampler.port",
        limits,
    )?;
    fields.protocol = optional_text(
        node_id,
        path,
        element,
        &element.properties,
        "HTTPSampler.protocol",
        limits,
    )?;
    fields.content_encoding = optional_text(
        node_id,
        path,
        element,
        &element.properties,
        "HTTPSampler.contentEncoding",
        limits,
    )?;
    fields.path = optional_text(
        node_id,
        path,
        element,
        &element.properties,
        "HTTPSampler.path",
        limits,
    )?;
    fields.method = optional_text(
        node_id,
        path,
        element,
        &element.properties,
        "HTTPSampler.method",
        limits,
    )?;
    fields.implementation = optional_text(
        node_id,
        path,
        element,
        &element.properties,
        "HTTPSampler.implementation",
        limits,
    )?;
    fields.follow_redirects = optional_bool(
        node_id,
        path,
        element,
        &element.properties,
        "HTTPSampler.follow_redirects",
    )?;
    fields.auto_redirects = optional_bool(
        node_id,
        path,
        element,
        &element.properties,
        "HTTPSampler.auto_redirects",
    )?;
    fields.use_keepalive = optional_bool(
        node_id,
        path,
        element,
        &element.properties,
        "HTTPSampler.use_keepalive",
    )?;
    fields.concurrent_downloads = optional_bool(
        node_id,
        path,
        element,
        &element.properties,
        "HTTPSampler.concurrentDwn",
    )?;
    let image_parser = optional_bool(
        node_id,
        path,
        element,
        &element.properties,
        "HTTPSampler.image_parser",
    )?;
    fields.embedded_url_regex = optional_text(
        node_id,
        path,
        element,
        &element.properties,
        "HTTPSampler.embedded_url_re",
        limits,
    )?;
    fields.embedded_url_exclude_regex = optional_text(
        node_id,
        path,
        element,
        &element.properties,
        "HTTPSampler.embedded_url_exclude_re",
        limits,
    )?;
    if let Some(entry) = element.properties.get_entry("HTTPSampler.connect_timeout") {
        fields.connect_timeout_explicit = true;
        fields.connect_timeout_ms = integer_entry(node_id, path, element, entry, limits, true)?;
    }
    if let Some(entry) = element.properties.get_entry("HTTPSampler.response_timeout") {
        fields.response_timeout_explicit = true;
        fields.response_timeout_ms = integer_entry(node_id, path, element, entry, limits, true)?;
    }
    if let Some(entry) = element.properties.get_entry("HTTPSampler.concurrentPool") {
        fields.concurrent_pool_explicit = true;
        fields.concurrent_pool = integer_entry(node_id, path, element, entry, limits, true)?
            .map(|value| {
                u16::try_from(value).map_err(|_| NativeV3HttpCompileError::ValueLimit {
                    source: NativeV3ErrorSource::new(node_id, path, element),
                    property: entry.name.clone(),
                    observed: value as usize,
                    maximum: u16::MAX as usize,
                })
            })
            .transpose()?;
    }
    let mut proxy = NativeV3ProxyTemplate::default();
    proxy.scheme = optional_text(
        node_id,
        path,
        element,
        &element.properties,
        "HTTPSampler.proxyScheme",
        limits,
    )?;
    proxy.host = optional_text(
        node_id,
        path,
        element,
        &element.properties,
        "HTTPSampler.proxyHost",
        limits,
    )?;
    proxy.port = optional_text(
        node_id,
        path,
        element,
        &element.properties,
        "HTTPSampler.proxyPort",
        limits,
    )?;
    proxy.username = optional_text(
        node_id,
        path,
        element,
        &element.properties,
        "HTTPSampler.proxyUser",
        limits,
    )?;
    proxy.password_present = element
        .properties
        .get_entry("HTTPSampler.proxyPass")
        .map(|entry| {
            text_entry(node_id, path, element, entry, limits).map(|value| !value.value().is_empty())
        })
        .transpose()?;
    proxy.non_proxy_hosts = None;
    fields.proxy = proxy;
    let mut body = BodyFields::default();
    if let Some(entry) = element.properties.get_entry("HTTPSampler.postBodyRaw") {
        body.present = true;
        body.post_body_raw = Some(bool_entry(node_id, path, element, entry)?);
    }
    if let Some(entry) = element
        .properties
        .get_entry("HTTPSampler.DO_MULTIPART_POST")
    {
        body.present = true;
        body.multipart = Some(bool_entry(node_id, path, element, entry)?);
    }
    if let Some(entry) = element.properties.get_entry("HTTPsampler.Arguments") {
        body.present = true;
        body.arguments = parse_arguments(node_id, path, element, entry, limits)?;
    }
    if let Some(entry) = element.properties.get_entry("HTTPSampler.files") {
        body.present = true;
        body.files = parse_files(node_id, path, element, entry, limits)?;
    }
    if !sampler {
        body.arguments.clear();
        body.files.clear();
    }
    Ok((fields, body, image_parser))
}

fn optional_bool(
    node_id: NodeId,
    path: &[NodeId],
    element: &TestElement,
    properties: &Properties,
    name: &'static str,
) -> Result<Option<bool>, NativeV3HttpCompileError> {
    properties
        .get_entry(name)
        .map(|entry| bool_entry(node_id, path, element, entry))
        .transpose()
}

fn fields_to_http_defaults(fields: &RequestFields) -> Result<HttpRequestDefaults, &'static str> {
    let mut defaults = HttpRequestDefaults::default();
    if let Some(value) = &fields.domain {
        defaults.domain =
            OptionalString::present(value.value()).map_err(|_| "http.defaults.domain")?;
    }
    if let Some(value) = &fields.port
        && let Ok(port) = value.value().parse::<u16>()
    {
        defaults.port = Some(port);
    }
    if let Some(value) = &fields.protocol {
        defaults.protocol =
            OptionalString::present(value.value()).map_err(|_| "http.defaults.protocol")?;
    }
    if let Some(value) = &fields.content_encoding {
        defaults.content_encoding =
            OptionalString::present(value.value()).map_err(|_| "http.defaults.content-encoding")?;
    }
    if let Some(value) = &fields.path {
        defaults.path = OptionalString::present(value.value()).map_err(|_| "http.defaults.path")?;
    }
    if let Some(value) = &fields.method {
        defaults.method =
            OptionalString::present(value.value()).map_err(|_| "http.defaults.method")?;
    }
    defaults.follow_redirects = fields
        .follow_redirects
        .map_or(OptionalBool::absent(), OptionalBool::present);
    defaults.auto_redirects = fields
        .auto_redirects
        .map_or(OptionalBool::absent(), OptionalBool::present);
    defaults.use_keepalive = fields
        .use_keepalive
        .map_or(OptionalBool::absent(), OptionalBool::present);
    defaults.concurrent_downloads = fields
        .concurrent_downloads
        .map_or(OptionalBool::absent(), OptionalBool::present);
    if let Some(value) = &fields.embedded_url_regex {
        defaults.embedded_url_regex =
            OptionalString::present(value.value()).map_err(|_| "http.defaults.embedded")?;
    }
    if let Some(value) = &fields.embedded_url_exclude_regex {
        defaults.embedded_url_exclude_regex =
            OptionalString::present(value.value()).map_err(|_| "http.defaults.embedded-exclude")?;
    }
    defaults.connect_timeout_ms = fields.connect_timeout_ms;
    defaults.response_timeout_ms = fields.response_timeout_ms;
    defaults.concurrent_pool = fields.concurrent_pool;
    defaults.proxy = proxy_to_core(&fields.proxy).map_err(|_| "http.defaults.proxy")?;
    if let Some(value) = &fields.implementation {
        defaults
            .set_implementation_wire(Some(value.value()))
            .map_err(|_| "http.defaults.implementation")?;
    }
    defaults.validate().map_err(|_| "http.defaults.validate")?;
    Ok(defaults)
}

fn merge_effective_fields(
    defaults: &[NativeV3Scoped<NativeV3RequestDefaults>],
    sampler: &RequestFields,
) -> Result<RequestFields, NativeV3HttpCompileError> {
    let mut result = RequestFields::default();
    for scoped in defaults {
        overlay_request_fields(&mut result, &request_fields_from_defaults(&scoped.value));
    }
    overlay_request_fields(&mut result, sampler);
    Ok(result)
}

fn request_fields_from_defaults(value: &NativeV3RequestDefaults) -> RequestFields {
    RequestFields {
        domain: value.domain.clone(),
        port: value.port.clone(),
        protocol: value.protocol.clone(),
        content_encoding: value.content_encoding.clone(),
        path: value.path.clone(),
        method: value.method.clone(),
        implementation: value
            .wire
            .implementation_wire
            .value()
            .map(|text| NativeV3Text::new(text.to_owned(), true)),
        follow_redirects: value.follow_redirects,
        auto_redirects: value.auto_redirects,
        use_keepalive: value.use_keepalive,
        concurrent_downloads: value.concurrent_downloads,
        embedded_url_regex: value.embedded_url_regex.clone(),
        embedded_url_exclude_regex: value.embedded_url_exclude_regex.clone(),
        connect_timeout_ms: value.connect_timeout_ms,
        connect_timeout_explicit: value.connect_timeout_ms.is_some(),
        response_timeout_ms: value.response_timeout_ms,
        response_timeout_explicit: value.response_timeout_ms.is_some(),
        concurrent_pool: value.concurrent_pool,
        concurrent_pool_explicit: value.concurrent_pool.is_some(),
        proxy: value.proxy.clone(),
    }
}

fn overlay_request_fields(target: &mut RequestFields, local: &RequestFields) {
    macro_rules! overlay {
        ($field:ident) => {
            if local.$field.is_some() {
                target.$field = local.$field.clone();
            }
        };
    }
    overlay!(domain);
    overlay!(port);
    overlay!(protocol);
    overlay!(content_encoding);
    overlay!(path);
    overlay!(method);
    overlay!(implementation);
    overlay!(follow_redirects);
    overlay!(auto_redirects);
    overlay!(use_keepalive);
    overlay!(concurrent_downloads);
    overlay!(embedded_url_regex);
    overlay!(embedded_url_exclude_regex);
    if local.connect_timeout_explicit {
        target.connect_timeout_explicit = true;
        target.connect_timeout_ms = local.connect_timeout_ms;
    }
    if local.response_timeout_explicit {
        target.response_timeout_explicit = true;
        target.response_timeout_ms = local.response_timeout_ms;
    }
    if local.concurrent_pool_explicit {
        target.concurrent_pool_explicit = true;
        target.concurrent_pool = local.concurrent_pool;
    }
    overlay_proxy(&mut target.proxy, &local.proxy);
}

fn overlay_proxy(target: &mut NativeV3ProxyTemplate, local: &NativeV3ProxyTemplate) {
    macro_rules! overlay {
        ($field:ident) => {
            if local.$field.is_some() {
                target.$field = local.$field.clone();
            }
        };
    }
    overlay!(scheme);
    overlay!(host);
    overlay!(port);
    overlay!(username);
    overlay!(password_present);
    overlay!(non_proxy_hosts);
}

fn parse_source_provider(
    node_id: NodeId,
    path: &[NodeId],
    implementation: &Option<NativeV3Text>,
    element: &TestElement,
) -> Result<NativeV3SourceProvider, NativeV3HttpCompileError> {
    let Some(value) = implementation else {
        return Ok(NativeV3SourceProvider::JmeterDefaultHttpClient4);
    };
    if is_expression(value.value()) {
        return Err(NativeV3HttpCompileError::UnsupportedProvider {
            source: NativeV3ErrorSource::new(node_id, path, element),
            capability: "http.provider.dynamic",
        });
    }
    match value.value() {
        "Java" => Ok(NativeV3SourceProvider::Java),
        "HttpClient4" => Ok(NativeV3SourceProvider::HttpClient4),
        _ => Err(NativeV3HttpCompileError::UnsupportedProvider {
            source: NativeV3ErrorSource::new(node_id, path, element),
            capability: "http.provider.unknown",
        }),
    }
}

fn parse_arguments(
    node_id: NodeId,
    path: &[NodeId],
    element: &TestElement,
    entry: &PropertyEntry,
    limits: NativeV3HttpCompileLimits,
) -> Result<Vec<NativeV3Argument>, NativeV3HttpCompileError> {
    let nested =
        entry
            .value
            .as_element()
            .map_err(|_| NativeV3HttpCompileError::InvalidProperty {
                source: NativeV3ErrorSource::new(node_id, path, element),
                property: entry.name.clone(),
                expected: "Arguments element",
            })?;
    if nested.name != "HTTPsampler.Arguments" {
        return Err(NativeV3HttpCompileError::InvalidProperty {
            source: NativeV3ErrorSource::new(node_id, path, element),
            property: entry.name.clone(),
            expected: "HTTPsampler.Arguments element",
        });
    }
    validate_nested_class(
        node_id,
        path,
        element,
        nested,
        &["Arguments", "org.apache.jmeter.config.Arguments"],
        "http.arguments-type",
    )?;
    if !nested.opaque_extensions.is_empty() {
        return Err(NativeV3HttpCompileError::OpaqueData {
            source: NativeV3ErrorSource::new(node_id, path, element),
            kind: "arguments-extension",
        });
    }
    for property in nested.properties.iter() {
        if property.name != "Arguments.arguments" {
            return Err(NativeV3HttpCompileError::UnsupportedProperty {
                source: NativeV3ErrorSource::new(node_id, path, element),
                property: property.name.clone(),
            });
        }
    }
    let Some(values) = nested.properties.get("Arguments.arguments") else {
        return Ok(Vec::new());
    };
    let values = collection_values(
        node_id,
        path,
        element,
        values,
        "Arguments.arguments",
        limits.max_arguments,
        "arguments",
    )?;
    if values.len() > limits.max_arguments {
        return Err(NativeV3HttpCompileError::Limit {
            dimension: "arguments",
            observed: values.len(),
            maximum: limits.max_arguments,
        });
    }
    let mut output = Vec::with_capacity(values.len());
    for value in values {
        output.push(parse_argument(node_id, path, element, value, limits)?);
    }
    Ok(output)
}

fn parse_argument(
    node_id: NodeId,
    path: &[NodeId],
    element: &TestElement,
    value: &PropertyValue,
    limits: NativeV3HttpCompileLimits,
) -> Result<NativeV3Argument, NativeV3HttpCompileError> {
    let nested = value
        .as_element()
        .map_err(|_| NativeV3HttpCompileError::InvalidProperty {
            source: NativeV3ErrorSource::new(node_id, path, element),
            property: "Arguments.arguments".to_owned(),
            expected: "HTTPArgument element",
        })?;
    if let Some(class) = nested.class_name()
        && !class.is_empty()
        && class != "HTTPArgument"
        && class != "org.apache.jmeter.protocol.http.util.HTTPArgument"
    {
        return Err(NativeV3HttpCompileError::UnsupportedCapability {
            source: NativeV3ErrorSource::new(node_id, path, element),
            capability: "http.argument-type",
        });
    }
    if !nested.opaque_extensions.is_empty() {
        return Err(NativeV3HttpCompileError::OpaqueData {
            source: NativeV3ErrorSource::new(node_id, path, element),
            kind: "argument-extension",
        });
    }
    let allowed = [
        "Argument.name",
        "Argument.value",
        "Argument.metadata",
        "HTTPArgument.always_encode",
        "Argument.always_encode",
        "HTTPArgument.use_equals",
        "Argument.use_equals",
        "HTTPArgument.content_type",
        "Argument.content_type",
    ];
    validate_nested_allowlist(node_id, path, element, &nested.properties, &allowed)?;
    let name = optional_nested_text(
        node_id,
        path,
        element,
        &nested.properties,
        "Argument.name",
        limits,
    )?;
    let value_entry = nested
        .properties
        .get_entry("Argument.value")
        .ok_or_else(|| NativeV3HttpCompileError::MissingProperty {
            source: NativeV3ErrorSource::new(node_id, path, element),
            property: "Argument.value".to_owned(),
        })?;
    let value_text = body_text_entry(node_id, path, element, value_entry, limits)?;
    let metadata = optional_nested_text(
        node_id,
        path,
        element,
        &nested.properties,
        "Argument.metadata",
        limits,
    )?
    .unwrap_or_else(|| NativeV3Text::new("=".to_owned(), false));
    let always_encode = optional_nested_bool_alias(
        node_id,
        path,
        element,
        &nested.properties,
        "HTTPArgument.always_encode",
        "Argument.always_encode",
    )?;
    let use_equals = optional_nested_bool_alias(
        node_id,
        path,
        element,
        &nested.properties,
        "HTTPArgument.use_equals",
        "Argument.use_equals",
    )?;
    let content_type = optional_nested_text_alias(
        node_id,
        path,
        element,
        &nested.properties,
        "HTTPArgument.content_type",
        "Argument.content_type",
        limits,
    )?;
    let always_encode_value = always_encode.is_none_or(|(_, value)| value);
    let use_equals_value = use_equals.is_none_or(|(_, value)| value);
    let http_name = name.as_ref().map_or("", NativeV3Text::value);
    let mut http = HttpArgument::with_options(
        http_name,
        value_text.value(),
        metadata.value(),
        use_equals_value,
        always_encode_value,
    );
    if let Some(content_type) = &content_type {
        http = http.with_content_type(content_type.value());
    }
    Ok(NativeV3Argument {
        name,
        value: value_text,
        metadata,
        always_encode: always_encode_value,
        always_encode_explicit: always_encode.is_some(),
        use_equals: use_equals_value,
        use_equals_explicit: use_equals.is_some(),
        http,
    })
}

/// Decodes both JMeter's unnamed collection form and SaveService's
/// insertion-preserving named collection form. The semantic model keeps the
/// distinction because names may be meaningful to an upstream converter, but
/// the V3 descriptors consume only the ordered element values.
fn collection_values<'a>(
    node_id: NodeId,
    path: &[NodeId],
    element: &TestElement,
    value: &'a PropertyValue,
    property: &'static str,
    maximum: usize,
    dimension: &'static str,
) -> Result<Vec<&'a PropertyValue>, NativeV3HttpCompileError> {
    let count = match value {
        PropertyValue::Collection(values) => values.len(),
        PropertyValue::NamedCollection(values) | PropertyValue::Map(values) => values.len(),
        _ => {
            return Err(NativeV3HttpCompileError::InvalidProperty {
                source: NativeV3ErrorSource::new(node_id, path, element),
                property: property.to_owned(),
                expected: "collection",
            });
        }
    };
    if count > maximum {
        return Err(NativeV3HttpCompileError::Limit {
            dimension,
            observed: count,
            maximum,
        });
    }
    match value {
        PropertyValue::Collection(values) => Ok(values.iter().collect()),
        PropertyValue::NamedCollection(values) | PropertyValue::Map(values) => {
            Ok(values.iter().map(|entry| &entry.value).collect())
        }
        _ => Err(NativeV3HttpCompileError::InvalidProperty {
            source: NativeV3ErrorSource::new(node_id, path, element),
            property: property.to_owned(),
            expected: "collection",
        }),
    }
}

fn parse_files(
    node_id: NodeId,
    path: &[NodeId],
    element: &TestElement,
    entry: &PropertyEntry,
    limits: NativeV3HttpCompileLimits,
) -> Result<Vec<NativeV3FilePart>, NativeV3HttpCompileError> {
    let nested =
        entry
            .value
            .as_element()
            .map_err(|_| NativeV3HttpCompileError::InvalidProperty {
                source: NativeV3ErrorSource::new(node_id, path, element),
                property: entry.name.clone(),
                expected: "HTTP files element",
            })?;
    if nested.name != "HTTPSampler.files" {
        return Err(NativeV3HttpCompileError::InvalidProperty {
            source: NativeV3ErrorSource::new(node_id, path, element),
            property: entry.name.clone(),
            expected: "HTTPSampler.files element",
        });
    }
    validate_nested_class(
        node_id,
        path,
        element,
        nested,
        &[
            "Files",
            "HTTPFileArgs",
            "org.apache.jmeter.protocol.http.util.HTTPFileArgs",
        ],
        "http.files-type",
    )?;
    validate_nested_allowlist(
        node_id,
        path,
        element,
        &nested.properties,
        &["HTTPsampler.files"],
    )?;
    let Some(values) = nested.properties.get("HTTPsampler.files") else {
        return Ok(Vec::new());
    };
    let values = collection_values(
        node_id,
        path,
        element,
        values,
        "HTTPsampler.files",
        limits.max_multipart_parts,
        "multipart-parts",
    )?;
    if values.len() > limits.max_multipart_parts {
        return Err(NativeV3HttpCompileError::Limit {
            dimension: "multipart-parts",
            observed: values.len(),
            maximum: limits.max_multipart_parts,
        });
    }
    let mut output = Vec::with_capacity(values.len());
    for value in values {
        let file = value
            .as_element()
            .map_err(|_| NativeV3HttpCompileError::InvalidProperty {
                source: NativeV3ErrorSource::new(node_id, path, element),
                property: "HTTPsampler.files".to_owned(),
                expected: "HTTPFileArg element",
            })?;
        if let Some(class) = file.class_name()
            && !class.is_empty()
            && class != "HTTPFileArg"
            && class != "org.apache.jmeter.protocol.http.util.HTTPFileArg"
        {
            return Err(NativeV3HttpCompileError::UnsupportedCapability {
                source: NativeV3ErrorSource::new(node_id, path, element),
                capability: "http.file-argument-type",
            });
        }
        validate_nested_allowlist(
            node_id,
            path,
            element,
            &file.properties,
            &["File.path", "File.paramname", "File.mimetype"],
        )?;
        let path_entry = file.properties.get_entry("File.path");
        let path_text = path_entry
            .map(|entry| text_entry(node_id, path, element, entry, limits))
            .transpose()?;
        let parameter = optional_nested_text(
            node_id,
            path,
            element,
            &file.properties,
            "File.paramname",
            limits,
        )?;
        let content_type = optional_nested_text(
            node_id,
            path,
            element,
            &file.properties,
            "File.mimetype",
            limits,
        )?;
        output.push(NativeV3FilePart {
            path_present: path_text.is_some(),
            path_bytes: path_text.as_ref().map_or(0, |value| value.value().len()),
            parameter,
            filename: None,
            content_type,
            replayability: RequestReplayability::Replayable,
            source: RequestBodySource::file(RequestReplayability::Replayable),
        });
    }
    Ok(output)
}

fn validate_nested_allowlist(
    node_id: NodeId,
    path: &[NodeId],
    element: &TestElement,
    properties: &Properties,
    allowed: &[&str],
) -> Result<(), NativeV3HttpCompileError> {
    let mut names = BTreeSet::new();
    for entry in properties.iter() {
        if !names.insert(entry.name.as_str()) {
            return Err(NativeV3HttpCompileError::DuplicateProperty {
                source: NativeV3ErrorSource::new(node_id, path, element),
                property: entry.name.clone(),
            });
        }
        if !allowed.contains(&entry.name.as_str()) {
            return Err(NativeV3HttpCompileError::UnsupportedProperty {
                source: NativeV3ErrorSource::new(node_id, path, element),
                property: entry.name.clone(),
            });
        }
        reject_opaque_value(node_id, path, element, &entry.value, "nested-opaque")?;
    }
    Ok(())
}

fn validate_nested_class(
    node_id: NodeId,
    path: &[NodeId],
    element: &TestElement,
    nested: &jmeter_rs_model::ElementProperty,
    allowed: &[&str],
    capability: &'static str,
) -> Result<(), NativeV3HttpCompileError> {
    if let Some(class) = nested.class_name()
        && !allowed.contains(&class)
    {
        return Err(NativeV3HttpCompileError::UnsupportedCapability {
            source: NativeV3ErrorSource::new(node_id, path, element),
            capability,
        });
    }
    Ok(())
}

fn optional_nested_text(
    node_id: NodeId,
    path: &[NodeId],
    element: &TestElement,
    properties: &Properties,
    name: &'static str,
    limits: NativeV3HttpCompileLimits,
) -> Result<Option<NativeV3Text>, NativeV3HttpCompileError> {
    properties
        .get_entry(name)
        .map(|entry| text_entry(node_id, path, element, entry, limits))
        .transpose()
}

fn optional_nested_text_alias(
    node_id: NodeId,
    path: &[NodeId],
    element: &TestElement,
    properties: &Properties,
    primary: &'static str,
    alias: &'static str,
    limits: NativeV3HttpCompileLimits,
) -> Result<Option<NativeV3Text>, NativeV3HttpCompileError> {
    if properties.get(primary).is_some() && properties.get(alias).is_some() {
        return Err(NativeV3HttpCompileError::DuplicateProperty {
            source: NativeV3ErrorSource::new(node_id, path, element),
            property: primary.to_owned(),
        });
    }
    properties
        .get_entry(primary)
        .or_else(|| properties.get_entry(alias))
        .map(|entry| text_entry(node_id, path, element, entry, limits))
        .transpose()
}

fn optional_nested_bool_alias(
    node_id: NodeId,
    path: &[NodeId],
    element: &TestElement,
    properties: &Properties,
    primary: &'static str,
    alias: &'static str,
) -> Result<Option<(&'static str, bool)>, NativeV3HttpCompileError> {
    if properties.get(primary).is_some() && properties.get(alias).is_some() {
        return Err(NativeV3HttpCompileError::DuplicateProperty {
            source: NativeV3ErrorSource::new(node_id, path, element),
            property: primary.to_owned(),
        });
    }
    if let Some(entry) = properties.get_entry(primary) {
        return Ok(Some((primary, bool_entry(node_id, path, element, entry)?)));
    }
    if let Some(entry) = properties.get_entry(alias) {
        return Ok(Some((alias, bool_entry(node_id, path, element, entry)?)));
    }
    Ok(None)
}

fn parse_header_manager(
    node_id: NodeId,
    path: &[NodeId],
    element: &TestElement,
    limits: NativeV3HttpCompileLimits,
) -> Result<ParsedDeclaration<HeaderManager>, NativeV3HttpCompileError> {
    validate_allowlist(node_id, path, element, &["HeaderManager.headers"])?;
    let mut manager = HeaderManager::new(limits.max_manager_entries)
        .map_err(|error| http_error(node_id, path, element, None, error.stable_code()))?;
    let Some(value) = element.property("HeaderManager.headers") else {
        return Ok(ParsedDeclaration {
            node_id,
            path: path.to_vec(),
            location: element_location(element),
            value: manager,
        });
    };
    let values = collection_values(
        node_id,
        path,
        element,
        value,
        "HeaderManager.headers",
        limits.max_manager_entries,
        "header-entries",
    )?;
    if values.len() > limits.max_manager_entries {
        return Err(NativeV3HttpCompileError::Limit {
            dimension: "header-entries",
            observed: values.len(),
            maximum: limits.max_manager_entries,
        });
    }
    for value in values {
        let nested = value
            .as_element()
            .map_err(|_| NativeV3HttpCompileError::InvalidProperty {
                source: NativeV3ErrorSource::new(node_id, path, element),
                property: "HeaderManager.headers".to_owned(),
                expected: "Header element",
            })?;
        validate_nested_class(
            node_id,
            path,
            element,
            nested,
            &["Header", "org.apache.jmeter.protocol.http.control.Header"],
            "http.header-type",
        )?;
        validate_nested_allowlist(
            node_id,
            path,
            element,
            &nested.properties,
            &["Header.name", "Header.value"],
        )?;
        let name = nested.properties.get_entry("Header.name").ok_or_else(|| {
            NativeV3HttpCompileError::MissingProperty {
                source: NativeV3ErrorSource::new(node_id, path, element),
                property: "Header.name".to_owned(),
            }
        })?;
        let header_name = text_entry(node_id, path, element, name, limits)?;
        let value = nested.properties.get_entry("Header.value").ok_or_else(|| {
            NativeV3HttpCompileError::MissingProperty {
                source: NativeV3ErrorSource::new(node_id, path, element),
                property: "Header.value".to_owned(),
            }
        })?;
        let header_value = text_entry(node_id, path, element, value, limits)?;
        manager
            .add(header_name.value(), header_value.value())
            .map_err(|error| {
                http_error(
                    node_id,
                    path,
                    element,
                    Some("HeaderManager.headers"),
                    error.stable_code(),
                )
            })?;
    }
    Ok(ParsedDeclaration {
        node_id,
        path: path.to_vec(),
        location: element_location(element),
        value: manager,
    })
}

#[allow(
    clippy::field_reassign_with_default,
    reason = "the parser fills exact CookieManager optional fields before entries"
)]
fn parse_cookie_manager(
    node_id: NodeId,
    path: &[NodeId],
    element: &TestElement,
    limits: NativeV3HttpCompileLimits,
) -> Result<ParsedDeclaration<CookieConfiguration>, NativeV3HttpCompileError> {
    validate_allowlist(
        node_id,
        path,
        element,
        &[
            "CookieManager.cookies",
            "CookieManager.clearEachIteration",
            "CookieManager.controlledByThreadGroup",
            "CookieManager.save.cookies",
            "CookieManager.check.cookies",
            "CookieManager.delete_null_cookies",
            "CookieManager.policy",
            "CookieManager.implementation",
        ],
    )?;
    let mut config = CookieConfiguration::default();
    config.clear_each_iteration = optional_core_bool(
        node_id,
        path,
        element,
        element.property("CookieManager.clearEachIteration"),
        "CookieManager.clearEachIteration",
    )?;
    config.controlled_by_thread_group = optional_core_bool(
        node_id,
        path,
        element,
        element.property("CookieManager.controlledByThreadGroup"),
        "CookieManager.controlledByThreadGroup",
    )?;
    config.save_cookies = optional_core_bool(
        node_id,
        path,
        element,
        element.property("CookieManager.save.cookies"),
        "CookieManager.save.cookies",
    )?;
    config.check_cookies = optional_core_bool(
        node_id,
        path,
        element,
        element.property("CookieManager.check.cookies"),
        "CookieManager.check.cookies",
    )?;
    config.delete_null_cookies = optional_core_bool(
        node_id,
        path,
        element,
        element.property("CookieManager.delete_null_cookies"),
        "CookieManager.delete_null_cookies",
    )?;
    config.policy = optional_core_string(
        node_id,
        path,
        element,
        element.property("CookieManager.policy"),
        "CookieManager.policy",
        limits,
    )?;
    config.implementation = optional_core_string(
        node_id,
        path,
        element,
        element.property("CookieManager.implementation"),
        "CookieManager.implementation",
        limits,
    )?;
    if config.policy.is_present() && config.effective_policy() != "standard" {
        return Err(NativeV3HttpCompileError::UnsupportedCapability {
            source: NativeV3ErrorSource::new(node_id, path, element),
            capability: "http.cookie.custom-policy",
        });
    }
    if config.implementation.is_present()
        && config.effective_implementation()
            != "org.apache.jmeter.protocol.http.control.HC4CookieHandler"
    {
        return Err(NativeV3HttpCompileError::UnsupportedCapability {
            source: NativeV3ErrorSource::new(node_id, path, element),
            capability: "http.cookie.custom-handler",
        });
    }
    if let Some(value) = element.property("CookieManager.cookies") {
        let values = collection_values(
            node_id,
            path,
            element,
            value,
            "CookieManager.cookies",
            limits.max_manager_entries,
            "cookie-entries",
        )?;
        if values.len() > limits.max_manager_entries {
            return Err(NativeV3HttpCompileError::Limit {
                dimension: "cookie-entries",
                observed: values.len(),
                maximum: limits.max_manager_entries,
            });
        }
        for value in values {
            let nested =
                value
                    .as_element()
                    .map_err(|_| NativeV3HttpCompileError::InvalidProperty {
                        source: NativeV3ErrorSource::new(node_id, path, element),
                        property: "CookieManager.cookies".to_owned(),
                        expected: "Cookie element",
                    })?;
            validate_nested_class(
                node_id,
                path,
                element,
                nested,
                &["Cookie", "org.apache.jmeter.protocol.http.control.Cookie"],
                "http.cookie-type",
            )?;
            validate_nested_allowlist(
                node_id,
                path,
                element,
                &nested.properties,
                &[
                    "Cookie.name",
                    "Cookie.value",
                    "Cookie.domain",
                    "Cookie.path",
                    "Cookie.secure",
                    "Cookie.hostOnly",
                    "Cookie.expires",
                ],
            )?;
            let name = required_nested_text(
                node_id,
                path,
                element,
                &nested.properties,
                "Cookie.name",
                limits,
            )?;
            let cookie_value = required_nested_text(
                node_id,
                path,
                element,
                &nested.properties,
                "Cookie.value",
                limits,
            )?;
            let domain = required_nested_text(
                node_id,
                path,
                element,
                &nested.properties,
                "Cookie.domain",
                limits,
            )?;
            let cookie_path = required_nested_text(
                node_id,
                path,
                element,
                &nested.properties,
                "Cookie.path",
                limits,
            )?;
            let secure =
                optional_nested_bool(node_id, path, element, &nested.properties, "Cookie.secure")?
                    .unwrap_or(false);
            let host_only = optional_nested_bool(
                node_id,
                path,
                element,
                &nested.properties,
                "Cookie.hostOnly",
            )?
            .unwrap_or(true);
            let mut cookie = jmeter_rs_http::Cookie::new(
                name.value(),
                cookie_value.value(),
                domain.value(),
                cookie_path.value(),
            )
            .map_err(|error| {
                http_error(
                    node_id,
                    path,
                    element,
                    Some("CookieManager.cookies"),
                    error.stable_code(),
                )
            })?;
            cookie = cookie.secure(secure).host_only(host_only);
            if let Some(expiry) = nested.properties.get_entry("Cookie.expires") {
                let expiry = integer_entry(node_id, path, element, expiry, limits, true)?;
                if expiry.is_some_and(|value| value != 0) {
                    return Err(NativeV3HttpCompileError::UnsupportedCapability {
                        source: NativeV3ErrorSource::new(node_id, path, element),
                        capability: "http.cookie.absolute-expiry",
                    });
                }
            }
            config.initial_cookies.push(cookie);
        }
    }
    config
        .validate()
        .map_err(|error| http_error(node_id, path, element, None, error.stable_code()))?;
    Ok(ParsedDeclaration {
        node_id,
        path: path.to_vec(),
        location: element_location(element),
        value: config,
    })
}

fn parse_cache_manager(
    node_id: NodeId,
    path: &[NodeId],
    element: &TestElement,
    limits: NativeV3HttpCompileLimits,
) -> Result<ParsedDeclaration<CacheConfiguration>, NativeV3HttpCompileError> {
    validate_allowlist(
        node_id,
        path,
        element,
        &[
            "CacheManager.urls",
            "CacheManager.maxSize",
            "maxSize",
            "CacheManager.clearEachIteration",
            "clearEachIteration",
            "CacheManager.controlledByThread",
            "controlledByThread",
            "CacheManager.useExpires",
            "useExpires",
        ],
    )?;
    let mut config = CacheConfiguration::default();
    for name in ["CacheManager.maxSize", "maxSize"] {
        if let Some(entry) = element.properties.get_entry(name) {
            if config.max_size.is_some() {
                return Err(NativeV3HttpCompileError::DuplicateProperty {
                    source: NativeV3ErrorSource::new(node_id, path, element),
                    property: name.to_owned(),
                });
            }
            config.max_size = integer_entry(node_id, path, element, entry, limits, false)?
                .map(|value| {
                    usize::try_from(value).map_err(|_| NativeV3HttpCompileError::ValueLimit {
                        source: NativeV3ErrorSource::new(node_id, path, element),
                        property: entry.name.clone(),
                        observed: usize::MAX,
                        maximum: usize::MAX,
                    })
                })
                .transpose()?;
        }
    }
    config.clear_each_iteration = optional_core_bool_alias(
        node_id,
        path,
        element,
        &element.properties,
        "CacheManager.clearEachIteration",
        "clearEachIteration",
    )?;
    config.controlled_by_thread = optional_core_bool_alias(
        node_id,
        path,
        element,
        &element.properties,
        "CacheManager.controlledByThread",
        "controlledByThread",
    )?;
    config.use_expires = optional_core_bool_alias(
        node_id,
        path,
        element,
        &element.properties,
        "CacheManager.useExpires",
        "useExpires",
    )?;
    if let Some(value) = element.property("CacheManager.urls") {
        let values = collection_values(
            node_id,
            path,
            element,
            value,
            "CacheManager.urls",
            limits.max_manager_entries,
            "cache-entries",
        )?;
        if !values.is_empty() {
            return Err(NativeV3HttpCompileError::UnsupportedCapability {
                source: NativeV3ErrorSource::new(node_id, path, element),
                capability: "http.cache.initial-entries",
            });
        }
    }
    config
        .validate()
        .map_err(|error| http_error(node_id, path, element, None, error.stable_code()))?;
    Ok(ParsedDeclaration {
        node_id,
        path: path.to_vec(),
        location: element_location(element),
        value: config,
    })
}

#[allow(
    clippy::field_reassign_with_default,
    reason = "the parser fills exact AuthManager reset fields before entries"
)]
fn parse_auth_manager(
    node_id: NodeId,
    path: &[NodeId],
    element: &TestElement,
    limits: NativeV3HttpCompileLimits,
) -> Result<ParsedDeclaration<AuthConfiguration>, NativeV3HttpCompileError> {
    validate_allowlist(
        node_id,
        path,
        element,
        &[
            "AuthManager.auth_list",
            "AuthManager.clearEachIteration",
            "AuthManager.controlledByThreadGroup",
        ],
    )?;
    let mut config = AuthConfiguration::default();
    config.clear_each_iteration = optional_core_bool(
        node_id,
        path,
        element,
        element.property("AuthManager.clearEachIteration"),
        "AuthManager.clearEachIteration",
    )?;
    config.controlled_by_thread_group = optional_core_bool(
        node_id,
        path,
        element,
        element.property("AuthManager.controlledByThreadGroup"),
        "AuthManager.controlledByThreadGroup",
    )?;
    let mut seen_urls = BTreeSet::new();
    if let Some(value) = element.property("AuthManager.auth_list") {
        let values = collection_values(
            node_id,
            path,
            element,
            value,
            "AuthManager.auth_list",
            limits.max_manager_entries,
            "auth-entries",
        )?;
        if values.len() > limits.max_manager_entries {
            return Err(NativeV3HttpCompileError::Limit {
                dimension: "auth-entries",
                observed: values.len(),
                maximum: limits.max_manager_entries,
            });
        }
        for value in values {
            let nested =
                value
                    .as_element()
                    .map_err(|_| NativeV3HttpCompileError::InvalidProperty {
                        source: NativeV3ErrorSource::new(node_id, path, element),
                        property: "AuthManager.auth_list".to_owned(),
                        expected: "Authorization element",
                    })?;
            validate_nested_class(
                node_id,
                path,
                element,
                nested,
                &[
                    "Authorization",
                    "org.apache.jmeter.protocol.http.control.Authorization",
                ],
                "http.authorization-type",
            )?;
            validate_nested_allowlist(
                node_id,
                path,
                element,
                &nested.properties,
                &[
                    "Authorization.url",
                    "Authorization.username",
                    "Authorization.password",
                    "Authorization.domain",
                    "Authorization.realm",
                    "Authorization.mechanism",
                ],
            )?;
            let url = required_nested_text(
                node_id,
                path,
                element,
                &nested.properties,
                "Authorization.url",
                limits,
            )?;
            if is_expression(url.value()) {
                return Err(NativeV3HttpCompileError::UnsupportedCapability {
                    source: NativeV3ErrorSource::new(node_id, path, element),
                    capability: "http.auth.dynamic-url",
                });
            }
            let username = required_nested_text(
                node_id,
                path,
                element,
                &nested.properties,
                "Authorization.username",
                limits,
            )?;
            let password = required_nested_text(
                node_id,
                path,
                element,
                &nested.properties,
                "Authorization.password",
                limits,
            )?;
            let domain = optional_nested_text(
                node_id,
                path,
                element,
                &nested.properties,
                "Authorization.domain",
                limits,
            )?;
            let realm = optional_nested_text(
                node_id,
                path,
                element,
                &nested.properties,
                "Authorization.realm",
                limits,
            )?;
            let mechanism = required_nested_text(
                node_id,
                path,
                element,
                &nested.properties,
                "Authorization.mechanism",
                limits,
            )?;
            let mechanism = match mechanism.value().to_ascii_uppercase().as_str() {
                "BASIC" => AuthMechanism::Basic,
                "BEARER" => AuthMechanism::Bearer,
                "DIGEST" => {
                    return Err(NativeV3HttpCompileError::UnsupportedCapability {
                        source: NativeV3ErrorSource::new(node_id, path, element),
                        capability: "http.auth.digest",
                    });
                }
                "NTLM" => {
                    return Err(NativeV3HttpCompileError::UnsupportedCapability {
                        source: NativeV3ErrorSource::new(node_id, path, element),
                        capability: "http.auth.ntlm",
                    });
                }
                "KERBEROS" | "SPNEGO" => {
                    return Err(NativeV3HttpCompileError::UnsupportedCapability {
                        source: NativeV3ErrorSource::new(node_id, path, element),
                        capability: "http.auth.kerberos",
                    });
                }
                _ => {
                    return Err(NativeV3HttpCompileError::UnsupportedCapability {
                        source: NativeV3ErrorSource::new(node_id, path, element),
                        capability: "http.auth.mechanism",
                    });
                }
            };
            let key = url.value().to_owned();
            if !seen_urls.insert(key) {
                return Err(NativeV3HttpCompileError::DuplicateProperty {
                    source: NativeV3ErrorSource::new(node_id, path, element),
                    property: "Authorization.url".to_owned(),
                });
            }
            let mut entry =
                AuthEntry::new(url.value(), username.value(), password.value(), mechanism)
                    .map_err(|error| {
                        http_error(
                            node_id,
                            path,
                            element,
                            Some("Authorization.url"),
                            error.stable_code(),
                        )
                    })?;
            if let Some(domain) = domain {
                entry = entry.domain(domain.value());
            }
            if let Some(realm) = realm {
                entry = entry.realm(realm.value());
            }
            config.entries.push(entry);
        }
    }
    config
        .validate()
        .map_err(|error| http_error(node_id, path, element, None, error.stable_code()))?;
    Ok(ParsedDeclaration {
        node_id,
        path: path.to_vec(),
        location: element_location(element),
        value: config,
    })
}

#[allow(
    clippy::field_reassign_with_default,
    reason = "the parser fills exact DNS manager options before static entries"
)]
fn parse_dns_manager(
    node_id: NodeId,
    path: &[NodeId],
    element: &TestElement,
    limits: NativeV3HttpCompileLimits,
) -> Result<ParsedDeclaration<DnsConfiguration>, NativeV3HttpCompileError> {
    validate_allowlist(
        node_id,
        path,
        element,
        &[
            "DNSCacheManager.hosts",
            "DNSCacheManager.clearEachIteration",
            "DNSCacheManager.isCustomResolver",
            "DNSCacheManager.servers",
        ],
    )?;
    let mut config = DnsConfiguration::default();
    config.clear_each_iteration = optional_core_bool(
        node_id,
        path,
        element,
        element.property("DNSCacheManager.clearEachIteration"),
        "DNSCacheManager.clearEachIteration",
    )?;
    config.custom_resolver = optional_core_bool(
        node_id,
        path,
        element,
        element.property("DNSCacheManager.isCustomResolver"),
        "DNSCacheManager.isCustomResolver",
    )?;
    if config.custom_resolver.value() == Some(false) {
        return Err(NativeV3HttpCompileError::UnsupportedCapability {
            source: NativeV3ErrorSource::new(node_id, path, element),
            capability: "http.dns.ambient",
        });
    }
    if let Some(entry) = element.properties.get_entry("DNSCacheManager.servers") {
        let value = text_entry(node_id, path, element, entry, limits)?;
        if !value.value().is_empty() {
            let mut servers = Vec::new();
            for part in value.value().split(',').map(str::trim) {
                if part.is_empty() {
                    continue;
                }
                if servers.len() >= limits.max_manager_entries {
                    return Err(NativeV3HttpCompileError::Limit {
                        dimension: "dns-servers",
                        observed: servers.len().saturating_add(1),
                        maximum: limits.max_manager_entries,
                    });
                }
                servers.push(part.to_owned());
            }
            config.servers = servers;
        }
    }
    if let Some(value) = element.property("DNSCacheManager.hosts") {
        let values = collection_values(
            node_id,
            path,
            element,
            value,
            "DNSCacheManager.hosts",
            limits.max_manager_entries,
            "dns-hosts",
        )?;
        if values.len() > limits.max_manager_entries {
            return Err(NativeV3HttpCompileError::Limit {
                dimension: "dns-hosts",
                observed: values.len(),
                maximum: limits.max_manager_entries,
            });
        }
        for value in values {
            let nested =
                value
                    .as_element()
                    .map_err(|_| NativeV3HttpCompileError::InvalidProperty {
                        source: NativeV3ErrorSource::new(node_id, path, element),
                        property: "DNSCacheManager.hosts".to_owned(),
                        expected: "StaticHost element",
                    })?;
            validate_nested_class(
                node_id,
                path,
                element,
                nested,
                &[
                    "StaticHost",
                    "org.apache.jmeter.protocol.http.control.StaticHost",
                ],
                "http.static-dns-type",
            )?;
            validate_nested_allowlist(
                node_id,
                path,
                element,
                &nested.properties,
                &["StaticHost.Name", "StaticHost.Address"],
            )?;
            let name = required_nested_text(
                node_id,
                path,
                element,
                &nested.properties,
                "StaticHost.Name",
                limits,
            )?;
            let address = required_nested_text(
                node_id,
                path,
                element,
                &nested.properties,
                "StaticHost.Address",
                limits,
            )?;
            let host = StaticDnsHost::new(name.value(), address.value()).map_err(|error| {
                http_error(
                    node_id,
                    path,
                    element,
                    Some("DNSCacheManager.hosts"),
                    error.stable_code(),
                )
            })?;
            config.static_hosts.push(host);
        }
    }
    config
        .validate()
        .map_err(|error| http_error(node_id, path, element, None, error.stable_code()))?;
    Ok(ParsedDeclaration {
        node_id,
        path: path.to_vec(),
        location: element_location(element),
        value: config,
    })
}

fn required_nested_text(
    node_id: NodeId,
    path: &[NodeId],
    element: &TestElement,
    properties: &Properties,
    name: &'static str,
    limits: NativeV3HttpCompileLimits,
) -> Result<NativeV3Text, NativeV3HttpCompileError> {
    properties
        .get_entry(name)
        .ok_or_else(|| NativeV3HttpCompileError::MissingProperty {
            source: NativeV3ErrorSource::new(node_id, path, element),
            property: name.to_owned(),
        })
        .and_then(|entry| text_entry(node_id, path, element, entry, limits))
}

fn optional_nested_bool(
    node_id: NodeId,
    path: &[NodeId],
    element: &TestElement,
    properties: &Properties,
    name: &'static str,
) -> Result<Option<bool>, NativeV3HttpCompileError> {
    properties
        .get_entry(name)
        .map(|entry| bool_entry(node_id, path, element, entry))
        .transpose()
}

fn optional_core_string(
    node_id: NodeId,
    path: &[NodeId],
    element: &TestElement,
    value: Option<&PropertyValue>,
    name: &'static str,
    limits: NativeV3HttpCompileLimits,
) -> Result<OptionalString, NativeV3HttpCompileError> {
    value
        .map(|value| {
            let entry = PropertyEntry::new(name, value.clone());
            let value = text_entry(node_id, path, element, &entry, limits)?;
            OptionalString::present(value.value()).map_err(|error| {
                http_error(node_id, path, element, Some(name), error.stable_code())
            })
        })
        .transpose()
        .map(|value| value.unwrap_or_else(OptionalString::absent))
}

fn optional_core_bool(
    node_id: NodeId,
    path: &[NodeId],
    element: &TestElement,
    value: Option<&PropertyValue>,
    name: &'static str,
) -> Result<OptionalBool, NativeV3HttpCompileError> {
    value
        .map(|value| {
            let entry = PropertyEntry::new(name, value.clone());
            bool_entry(node_id, path, element, &entry).map(OptionalBool::present)
        })
        .transpose()
        .map(|value| value.unwrap_or_else(OptionalBool::absent))
}

fn optional_core_bool_alias(
    node_id: NodeId,
    path: &[NodeId],
    element: &TestElement,
    properties: &Properties,
    primary: &'static str,
    alias: &'static str,
) -> Result<OptionalBool, NativeV3HttpCompileError> {
    if properties.get(primary).is_some() && properties.get(alias).is_some() {
        return Err(NativeV3HttpCompileError::DuplicateProperty {
            source: NativeV3ErrorSource::new(node_id, path, element),
            property: primary.to_owned(),
        });
    }
    optional_core_bool(
        node_id,
        path,
        element,
        properties.get(primary).or_else(|| properties.get(alias)),
        primary,
    )
}

fn proxy_to_core(proxy: &NativeV3ProxyTemplate) -> Result<ProxyConfiguration, &'static str> {
    let mut result = ProxyConfiguration::default();
    if let Some(value) = &proxy.scheme {
        result.scheme = OptionalString::present(value.value()).map_err(|_| "proxy.scheme")?;
    }
    if let Some(value) = &proxy.host {
        result.host = OptionalString::present(value.value()).map_err(|_| "proxy.host")?;
    }
    if let Some(value) = &proxy.port
        && let Ok(port) = value.value().parse::<u16>()
    {
        result.port = Some(port);
    }
    if let Some(value) = &proxy.username
        && !value.value().is_empty()
    {
        result.username = OptionalString::present(value.value()).map_err(|_| "proxy.username")?;
    }
    if let Some(value) = proxy.password_present {
        result.password_present = OptionalBool::present(value);
    }
    if let Some(value) = &proxy.non_proxy_hosts {
        result.non_proxy_hosts =
            OptionalString::present(value.value()).map_err(|_| "proxy.no-proxy")?;
    }
    Ok(result)
}

fn effective_proxy(
    node_id: NodeId,
    path: &[NodeId],
    element: &TestElement,
    proxy: &NativeV3ProxyTemplate,
) -> Result<NativeV3ProxyRequirement, NativeV3HttpCompileError> {
    let present = proxy.scheme.is_some()
        || proxy.host.is_some()
        || proxy.port.is_some()
        || proxy.username.is_some()
        || proxy.password_present.is_some()
        || proxy.non_proxy_hosts.is_some();
    if !present {
        return Ok(NativeV3ProxyRequirement {
            enabled: false,
            policy: jmeter_rs_http::ProxyPolicy::default(),
            capability: None,
        });
    }
    for value in [
        proxy.scheme.as_ref(),
        proxy.host.as_ref(),
        proxy.port.as_ref(),
        proxy.username.as_ref(),
        proxy.non_proxy_hosts.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        if is_expression(value.value()) {
            return Err(NativeV3HttpCompileError::UnsupportedCapability {
                source: NativeV3ErrorSource::new(node_id, path, element),
                capability: "http.proxy.dynamic",
            });
        }
    }
    if proxy
        .username
        .as_ref()
        .is_some_and(|value| !value.value().is_empty())
        || proxy.password_present == Some(true)
    {
        return Err(NativeV3HttpCompileError::UnsupportedCapability {
            source: NativeV3ErrorSource::new(node_id, path, element),
            capability: "http.proxy.credentials",
        });
    }
    let config =
        proxy_to_core(proxy).map_err(|property| NativeV3HttpCompileError::InvalidProperty {
            source: NativeV3ErrorSource::new(node_id, path, element),
            property: property.to_owned(),
            expected: "explicit proxy descriptor",
        })?;
    let policy = config.to_policy().map_err(|error| {
        http_error(
            node_id,
            path,
            element,
            Some("HTTPSampler.proxyHost"),
            error.stable_code(),
        )
    })?;
    let enabled = policy.http.is_some() || policy.https.is_some();
    Ok(NativeV3ProxyRequirement {
        enabled,
        policy,
        capability: enabled.then_some("http.proxy.explicit/1"),
    })
}

fn parse_port_template(value: NativeV3Text) -> Result<NativeV3PortTemplate, ()> {
    if value.value().is_empty() {
        return Ok(NativeV3PortTemplate::ExplicitEmpty);
    }
    if is_expression(value.value()) {
        return Ok(NativeV3PortTemplate::Template(value));
    }
    match value.value().parse::<u16>() {
        Ok(port) => Ok(NativeV3PortTemplate::Literal(port)),
        Err(_) => Err(()),
    }
}

fn materialize_request(
    template: &NativeV3RequestTemplate,
    headers: Option<&HeaderManager>,
    node_id: NodeId,
    path: &[NodeId],
    element: &TestElement,
) -> Result<Option<HttpSamplerRequest>, NativeV3HttpCompileError> {
    let (NativeV3PortTemplate::Implicit
    | NativeV3PortTemplate::ExplicitEmpty
    | NativeV3PortTemplate::Literal(_)) = &template.port
    else {
        return Ok(None);
    };
    if template.host.value().contains("${") || template.path.value().contains("${") {
        return Ok(None);
    }
    if matches!(
        template.body,
        NativeV3BodyPlan::Multipart { .. }
            | NativeV3BodyPlan::PresentEmpty {
                mode: NativeV3BodyMode::Multipart
            }
    ) {
        // JMeter chooses a provider boundary at execution time.  V3 records
        // multipart data but never invents a random/ambient boundary.
        return Ok(None);
    }
    let port = match template.port {
        NativeV3PortTemplate::Implicit | NativeV3PortTemplate::ExplicitEmpty => None,
        NativeV3PortTemplate::Literal(0) => None,
        NativeV3PortTemplate::Literal(port) => Some(port),
        NativeV3PortTemplate::Template(_) => return Ok(None),
    };
    let host = authority_host(template.host.value());
    let authority = port.map_or_else(|| host.clone(), |port| format!("{host}:{port}"));
    let url = format!(
        "{}://{}{}",
        template.protocol.value(),
        authority,
        template.path.value()
    );
    let url = jmeter_rs_http::Url::parse(url).map_err(|error| {
        http_error(
            node_id,
            path,
            element,
            Some("HTTPSampler.path"),
            error.stable_code(),
        )
    })?;
    let mut request = HttpSamplerRequest::new(template.method.clone(), url)
        .content_encoding(template.content_encoding.value())
        .post_body_raw(matches!(
            template.body,
            NativeV3BodyPlan::Raw { .. }
                | NativeV3BodyPlan::PresentEmpty {
                    mode: NativeV3BodyMode::Raw
                }
        ));
    match &template.body {
        NativeV3BodyPlan::Missing => {}
        NativeV3BodyPlan::PresentEmpty {
            mode: NativeV3BodyMode::Form | NativeV3BodyMode::Raw,
        } => {}
        NativeV3BodyPlan::Raw { arguments } | NativeV3BodyPlan::Form { arguments } => {
            request = request
                .try_arguments(arguments.iter().map(|argument| argument.http.clone()))
                .map_err(|error| {
                    http_error(
                        node_id,
                        path,
                        element,
                        Some("HTTPsampler.Arguments"),
                        error.stable_code(),
                    )
                })?;
        }
        NativeV3BodyPlan::PresentEmpty {
            mode: NativeV3BodyMode::Multipart,
        }
        | NativeV3BodyPlan::Multipart { .. } => return Ok(None),
    }
    if let Some(headers) = headers {
        for header in headers.headers() {
            request = request
                .header(header.name().as_str(), header.value().as_str())
                .map_err(|error| {
                    http_error(
                        node_id,
                        path,
                        element,
                        Some("HeaderManager.headers"),
                        error.stable_code(),
                    )
                })?;
        }
    }
    Ok(Some(request))
}

fn parse_body_plan(
    node_id: NodeId,
    path: &[NodeId],
    element: &TestElement,
    fields: BodyFields,
    limits: NativeV3HttpCompileLimits,
    accounting: &mut Accounting,
) -> Result<NativeV3BodyPlan, NativeV3HttpCompileError> {
    let raw = fields.post_body_raw.unwrap_or(false);
    let multipart = fields.multipart.unwrap_or(false) || !fields.files.is_empty();
    if fields.arguments.len() > limits.max_arguments {
        return Err(NativeV3HttpCompileError::Limit {
            dimension: "arguments",
            observed: fields.arguments.len(),
            maximum: limits.max_arguments,
        });
    }
    if fields.files.len() > limits.max_multipart_parts {
        return Err(NativeV3HttpCompileError::Limit {
            dimension: "multipart-parts",
            observed: fields.files.len(),
            maximum: limits.max_multipart_parts,
        });
    }
    for argument in &fields.arguments {
        accounting.charge(argument.value.value().len())?;
        accounting.charge(argument.metadata.value().len())?;
        if let Some(name) = &argument.name {
            accounting.charge(name.value().len())?;
        }
    }
    if multipart {
        if raw {
            return Err(NativeV3HttpCompileError::InvalidProperty {
                source: NativeV3ErrorSource::new(node_id, path, element),
                property: "HTTPSampler.postBodyRaw".to_owned(),
                expected: "false for multipart mode",
            });
        }
        if fields.arguments.is_empty() && fields.files.is_empty() && fields.present {
            return Ok(NativeV3BodyPlan::PresentEmpty {
                mode: NativeV3BodyMode::Multipart,
            });
        }
        return Ok(NativeV3BodyPlan::Multipart {
            arguments: fields.arguments,
            files: fields.files,
        });
    }
    if fields.arguments.is_empty() {
        if fields.present {
            let mode = if multipart {
                NativeV3BodyMode::Multipart
            } else if raw {
                NativeV3BodyMode::Raw
            } else {
                NativeV3BodyMode::Form
            };
            return Ok(NativeV3BodyPlan::PresentEmpty { mode });
        }
        return Ok(NativeV3BodyPlan::Missing);
    }
    if raw {
        Ok(NativeV3BodyPlan::Raw {
            arguments: fields.arguments,
        })
    } else {
        Ok(NativeV3BodyPlan::Form {
            arguments: fields.arguments,
        })
    }
}

fn accepts_compressed_response(manager: &HeaderManager) -> bool {
    manager.headers().iter().any(|header| {
        header
            .name()
            .as_str()
            .eq_ignore_ascii_case("accept-encoding")
            && header.value().as_str().split(',').any(|part| {
                matches!(
                    part.trim().to_ascii_lowercase().as_str(),
                    "gzip" | "deflate" | "br"
                )
            })
    })
}

fn is_expression(value: &str) -> bool {
    value.contains("${")
}

fn is_ip_literal(value: &str) -> bool {
    let value = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(value);
    value.parse::<IpAddr>().is_ok()
}

fn authority_host(value: &str) -> String {
    if value.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{value}]")
    } else {
        value.to_owned()
    }
}

fn http_error(
    node_id: NodeId,
    path: &[NodeId],
    element: &TestElement,
    property: Option<&str>,
    code: &'static str,
) -> NativeV3HttpCompileError {
    NativeV3HttpCompileError::Http {
        source: NativeV3ErrorSource::new(node_id, path, element),
        property: property.map(str::to_owned),
        code,
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::panic,
        clippy::unwrap_used,
        reason = "tests construct fixed semantic plans and assert explicit errors"
    )]

    use super::*;
    use jmeter_rs_jmx::{SemanticRootMetadata, Span};
    use jmeter_rs_model::{ElementProperty, ElementTree, TestElement};

    fn plan_with_sampler(sampler: TestElement) -> SemanticPlan {
        let root_meta =
            SemanticRootMetadata::new("jmeterTestPlan", Vec::new(), Span::new(0, 0).expect("span"));
        let mut tree = ElementTree::new();
        let root = tree
            .insert_root(TestElement::named("TestPlan", "TestPlanGui", "plan"))
            .expect("root");
        tree.insert(Some(root), sampler).expect("sampler");
        SemanticPlan::new(root_meta, tree)
    }

    fn sampler() -> TestElement {
        let mut sampler = TestElement::named("HTTPSamplerProxy", "HttpTestSampleGui", "sample");
        sampler.set_property("HTTPSampler.domain", PropertyValue::string("127.0.0.1"));
        sampler.set_property("HTTPSampler.path", PropertyValue::string("/ok"));
        sampler.set_property("HTTPSampler.method", PropertyValue::string("GET"));
        sampler
    }

    #[test]
    fn compiles_whole_plan_with_explicit_provider_identity() {
        let plan = plan_with_sampler(sampler());
        let compiled = compile_native_v3_http_plan(&plan).expect("compile");
        assert_eq!(compiled.provider, NATIVE_V3_HTTP_CAPABILITY);
        assert_eq!(
            compiled.resolver,
            NativeV3ResolverIdentity::ExplicitSelectorV1
        );
        assert_eq!(compiled.samplers.len(), 1);
        assert_eq!(compiled.samplers[0].request.method, Method::Get);
        assert_eq!(
            compiled.samplers[0].provider.executed,
            NATIVE_V3_HTTP_CAPABILITY
        );
        assert!(matches!(
            compiled.samplers[0].request.body,
            NativeV3BodyPlan::Missing
        ));
    }

    #[test]
    fn body_presence_distinguishes_missing_and_present_empty() {
        let mut raw = sampler();
        raw.set_property("HTTPSampler.method", PropertyValue::string("POST"));
        raw.set_property("HTTPSampler.postBodyRaw", PropertyValue::boolean(true));
        let plan = plan_with_sampler(raw);
        let compiled = compile_native_v3_http_plan(&plan).expect("compile");
        assert!(matches!(
            compiled.samplers[0].request.body,
            NativeV3BodyPlan::PresentEmpty {
                mode: NativeV3BodyMode::Raw
            }
        ));
        let mut no_body = sampler();
        no_body.set_property("HTTPSampler.method", PropertyValue::string("POST"));
        let compiled = compile_native_v3_http_plan(&plan_with_sampler(no_body)).expect("compile");
        assert!(matches!(
            compiled.samplers[0].request.body,
            NativeV3BodyPlan::Missing
        ));
    }

    #[test]
    fn disabled_unknown_branch_is_ignored() {
        let mut root = TestElement::named("TestPlan", "TestPlanGui", "plan");
        root.set_enabled(false);
        let meta =
            SemanticRootMetadata::new("jmeterTestPlan", Vec::new(), Span::new(0, 0).expect("span"));
        let mut tree = ElementTree::new();
        let root_id = tree.insert_root(root).expect("root");
        tree.insert(
            Some(root_id),
            TestElement::named("plugin.UnknownSampler", "", "disabled"),
        )
        .expect("child");
        let plan = SemanticPlan::new(meta, tree);
        let compiled = compile_native_v3_http_plan(&plan).expect("disabled branch");
        assert!(compiled.samplers.is_empty());
    }

    #[test]
    fn automatic_resolution_and_auto_redirects_fail_closed() {
        let plan = plan_with_sampler(sampler());
        let error = NativeV3HttpPlanCompiler::new()
            .with_resolver(NativeV3ResolverIdentity::AutoV1)
            .compile(&plan)
            .expect_err("auto resolution disabled");
        assert_eq!(error.code(), "native.v3.auto-resolution-disabled");
        let mut sampler = sampler();
        sampler.set_property("HTTPSampler.auto_redirects", PropertyValue::boolean(true));
        let error = compile_native_v3_http_plan(&plan_with_sampler(sampler))
            .expect_err("automatic redirects unsupported");
        assert!(matches!(
            error,
            NativeV3HttpCompileError::UnsupportedCapability {
                capability: "http.automatic-redirects",
                ..
            }
        ));
    }

    #[test]
    fn proxy_tls_and_dns_require_explicit_subordinate_capabilities() {
        let mut sampler = sampler();
        sampler.set_property("HTTPSampler.domain", PropertyValue::string("fixture.test"));
        sampler.set_property("HTTPSampler.protocol", PropertyValue::string("https"));
        let compiled = compile_native_v3_http_plan(&plan_with_sampler(sampler)).expect("compile");
        let requirements = &compiled.samplers[0].requirements;
        assert!(matches!(
            requirements.dns,
            NativeV3DnsRequirement::ExplicitResolverRequired { .. }
        ));
        assert!(requirements.tls.enabled);
        assert_eq!(
            requirements.tls.trust_capability,
            Some("http.tls.explicit-roots/1")
        );
        assert_eq!(requirements.http_version, HttpVersionPolicy::Http11Only);
    }

    #[test]
    fn debug_and_errors_do_not_expose_body_or_auth_values() {
        let mut sampler = sampler();
        sampler.set_property("HTTPSampler.method", PropertyValue::string("POST"));
        sampler.set_property("HTTPSampler.postBodyRaw", PropertyValue::boolean(true));
        let mut arguments =
            ElementProperty::new("HTTPsampler.Arguments").with_class_name("Arguments");
        let mut raw = ElementProperty::new("secret").with_class_name("HTTPArgument");
        raw.properties
            .insert("Argument.value", PropertyValue::string("secret-body"));
        raw.properties
            .insert("HTTPArgument.always_encode", PropertyValue::boolean(false));
        arguments.properties.insert(
            "Arguments.arguments",
            PropertyValue::collection(vec![PropertyValue::Element(raw)]),
        );
        sampler.set_property("HTTPsampler.Arguments", PropertyValue::Element(arguments));
        let plan = plan_with_sampler(sampler);
        let compiled = compile_native_v3_http_plan(&plan).expect("compile");
        let debug = format!("{compiled:?}");
        assert!(!debug.contains("secret-body"));
    }

    #[test]
    fn duplicate_special_manager_is_ambiguous() {
        let root_meta =
            SemanticRootMetadata::new("jmeterTestPlan", Vec::new(), Span::new(0, 0).expect("span"));
        let mut tree = ElementTree::new();
        let root = tree
            .insert_root(TestElement::named("TestPlan", "TestPlanGui", "plan"))
            .expect("root");
        tree.insert_child(
            root,
            TestElement::named("CookieManager", "CookiePanel", "one"),
        )
        .expect("cookie one");
        tree.insert_child(
            root,
            TestElement::named("CookieManager", "CookiePanel", "two"),
        )
        .expect("cookie two");
        tree.insert_child(root, sampler()).expect("sampler");
        let error = compile_native_v3_http_plan(&SemanticPlan::new(root_meta, tree))
            .expect_err("duplicate manager");
        assert!(matches!(
            error,
            NativeV3HttpCompileError::AmbiguousManager {
                manager: "http.cookie-manager",
                ..
            }
        ));
    }

    #[test]
    fn opaque_property_fails_atomically_and_redacts_value() {
        let mut sampler = sampler();
        sampler.set_property(
            "plugin.secret",
            PropertyValue::opaque_text("plugin.Secret", "token"),
        );
        let error =
            compile_native_v3_http_plan(&plan_with_sampler(sampler)).expect_err("opaque property");
        assert!(matches!(
            error,
            NativeV3HttpCompileError::UnsupportedProperty { .. }
        ));
        let debug = format!("{error:?}");
        assert!(!debug.contains("token"));
    }

    #[test]
    fn source_provider_expression_is_rejected_without_auto_resolution() {
        let mut sampler = sampler();
        sampler.set_property(
            "HTTPSampler.implementation",
            PropertyValue::string("${__P(provider,HttpClient4)}"),
        );
        let error =
            compile_native_v3_http_plan(&plan_with_sampler(sampler)).expect_err("dynamic provider");
        assert!(matches!(
            error,
            NativeV3HttpCompileError::UnsupportedProvider { .. }
        ));
    }

    #[test]
    fn scope_precedence_merges_headers_and_keeps_reset_provenance() {
        let root_meta =
            SemanticRootMetadata::new("jmeterTestPlan", Vec::new(), Span::new(0, 0).expect("span"));
        let mut tree = ElementTree::new();
        let root = tree
            .insert_root(TestElement::named("TestPlan", "TestPlanGui", "plan"))
            .expect("root");

        let mut defaults = TestElement::named("ConfigTestElement", "HttpDefaultsGui", "defaults");
        defaults.set_property("HTTPSampler.domain", PropertyValue::string("127.0.0.1"));
        defaults.set_property("HTTPSampler.method", PropertyValue::string("GET"));
        tree.insert_child(root, defaults).expect("defaults");

        let mut outer_headers = TestElement::named("HeaderManager", "HeaderPanel", "outer headers");
        let mut outer = ElementProperty::new("outer").with_class_name("Header");
        outer
            .properties
            .insert("Header.name", PropertyValue::string("X-Scope"));
        outer
            .properties
            .insert("Header.value", PropertyValue::string("outer"));
        outer_headers.set_property(
            "HeaderManager.headers",
            PropertyValue::collection(vec![PropertyValue::Element(outer)]),
        );
        tree.insert_child(root, outer_headers)
            .expect("outer headers");

        let group = tree
            .insert_child(
                root,
                TestElement::named("ThreadGroup", "ThreadGroupGui", "group"),
            )
            .expect("group");
        let mut inner_headers = TestElement::named("HeaderManager", "HeaderPanel", "inner headers");
        let mut inner = ElementProperty::new("inner").with_class_name("Header");
        inner
            .properties
            .insert("Header.name", PropertyValue::string("X-Scope"));
        inner
            .properties
            .insert("Header.value", PropertyValue::string("inner"));
        inner_headers.set_property(
            "HeaderManager.headers",
            PropertyValue::collection(vec![PropertyValue::Element(inner)]),
        );
        tree.insert_child(group, inner_headers)
            .expect("inner headers");

        let mut request = sampler();
        request.set_property("HTTPSampler.path", PropertyValue::string("/scoped"));
        tree.insert_child(group, request).expect("sampler");

        let compiled = compile_native_v3_http_plan(&SemanticPlan::new(root_meta, tree))
            .expect("scope compile");
        let sampler = &compiled.samplers[0];
        assert_eq!(sampler.scope.request_defaults.len(), 1);
        assert_eq!(sampler.scope.headers.len(), 2);
        let effective = sampler
            .scope
            .effective_headers
            .as_ref()
            .expect("effective headers");
        let field = effective.headers().iter().next().expect("header");
        assert_eq!(field.name().as_str(), "X-Scope");
        assert_eq!(field.value().as_str(), "inner");
        assert_eq!(
            sampler.scope.headers[1].origin.scope,
            NativeV3ScopeKind::ThreadGroup
        );
        assert!(sampler.scope.reset.cookie.is_none());
        assert_eq!(sampler.request.host.value(), "127.0.0.1");
    }

    #[test]
    fn body_modes_include_empty_form_and_file_capability_metadata() {
        let mut form = sampler();
        form.set_property("HTTPSampler.method", PropertyValue::string("POST"));
        let arguments = ElementProperty::new("HTTPsampler.Arguments").with_class_name("Arguments");
        form.set_property("HTTPsampler.Arguments", PropertyValue::Element(arguments));
        let compiled = compile_native_v3_http_plan(&plan_with_sampler(form)).expect("empty form");
        assert!(matches!(
            compiled.samplers[0].request.body,
            NativeV3BodyPlan::PresentEmpty {
                mode: NativeV3BodyMode::Form
            }
        ));

        let mut multipart = sampler();
        multipart.set_property("HTTPSampler.method", PropertyValue::string("POST"));
        multipart.set_property(
            "HTTPSampler.DO_MULTIPART_POST",
            PropertyValue::boolean(true),
        );
        let mut files = ElementProperty::new("HTTPSampler.files").with_class_name("Files");
        let mut file = ElementProperty::new("file").with_class_name("HTTPFileArg");
        file.properties
            .insert("File.path", PropertyValue::string("fixtures/upload.bin"));
        file.properties
            .insert("File.paramname", PropertyValue::string("upload"));
        file.properties.insert(
            "File.mimetype",
            PropertyValue::string("application/octet-stream"),
        );
        files.properties.insert(
            "HTTPsampler.files",
            PropertyValue::collection(vec![PropertyValue::Element(file)]),
        );
        multipart.set_property("HTTPSampler.files", PropertyValue::Element(files));
        let compiled =
            compile_native_v3_http_plan(&plan_with_sampler(multipart)).expect("multipart");
        let NativeV3BodyPlan::Multipart { files, .. } = &compiled.samplers[0].request.body else {
            panic!("multipart body expected");
        };
        assert_eq!(files.len(), 1);
        assert!(files[0].path_present);
        assert_eq!(files[0].path_bytes, "fixtures/upload.bin".len());
        assert!(matches!(
            files[0].source,
            RequestBodySource::File {
                replayability: RequestReplayability::Replayable
            }
        ));
    }

    #[test]
    fn explicit_java_identity_disabled_content_and_limits_are_fail_closed() {
        let mut java = sampler();
        java.set_property("HTTPSampler.implementation", PropertyValue::string("Java"));
        let compiled = compile_native_v3_http_plan(&plan_with_sampler(java)).expect("Java source");
        assert_eq!(
            compiled.samplers[0].provider.source,
            NativeV3SourceProvider::Java
        );

        let root_meta =
            SemanticRootMetadata::new("jmeterTestPlan", Vec::new(), Span::new(0, 0).expect("span"));
        let mut tree = ElementTree::new();
        let root = tree
            .insert_root(TestElement::named("TestPlan", "TestPlanGui", "plan"))
            .expect("root");
        let mut disabled = TestElement::named("plugin.UnknownSampler", "", "disabled");
        disabled.set_enabled(false);
        tree.insert_child(root, disabled).expect("disabled");
        tree.insert_child(root, sampler()).expect("enabled sampler");
        let compiled = compile_native_v3_http_plan(&SemanticPlan::new(root_meta, tree))
            .expect("disabled content");
        assert_eq!(compiled.samplers.len(), 1);
        assert!(!compiled.nodes.iter().any(|node| node.name == "disabled"));

        let limits = NativeV3HttpCompileLimits {
            max_text_bytes: 4,
            ..NativeV3HttpCompileLimits::default()
        };
        let error = NativeV3HttpPlanCompiler::with_limits(limits)
            .compile(&plan_with_sampler(sampler()))
            .expect_err("text limit");
        assert_eq!(error.code(), "native.v3.value-limit");
        let limits = NativeV3HttpCompileLimits {
            max_aggregate_bytes: 8,
            ..NativeV3HttpCompileLimits::default()
        };
        let error = NativeV3HttpPlanCompiler::with_limits(limits)
            .compile(&plan_with_sampler(sampler()))
            .expect_err("aggregate limit");
        assert_eq!(error.code(), "native.v3.limit");
    }

    #[test]
    fn strict_nested_classes_ports_and_disabled_pool_are_preserved() {
        let mut header_manager =
            TestElement::named("HeaderManager", "HeaderPanel", "bad nested class");
        let mut bad_header = ElementProperty::new("bad").with_class_name("PluginHeader");
        bad_header
            .properties
            .insert("Header.name", PropertyValue::string("X-Test"));
        bad_header
            .properties
            .insert("Header.value", PropertyValue::string("value"));
        header_manager.set_property(
            "HeaderManager.headers",
            PropertyValue::collection(vec![PropertyValue::Element(bad_header)]),
        );
        let root_meta =
            SemanticRootMetadata::new("jmeterTestPlan", Vec::new(), Span::new(0, 0).unwrap());
        let mut tree = ElementTree::new();
        let root = tree
            .insert_root(TestElement::named("TestPlan", "TestPlanGui", "plan"))
            .unwrap();
        tree.insert_child(root, header_manager).unwrap();
        tree.insert_child(root, sampler()).unwrap();
        let error = compile_native_v3_http_plan(&SemanticPlan::new(root_meta, tree))
            .expect_err("unknown nested manager class");
        assert!(matches!(
            error,
            NativeV3HttpCompileError::UnsupportedCapability {
                capability: "http.header-type",
                ..
            }
        ));

        let mut defaults =
            TestElement::named("ConfigTestElement", "HttpDefaultsGui", "invalid port");
        defaults.set_property("HTTPSampler.port", PropertyValue::string("not-a-port"));
        let mut invalid_tree = ElementTree::new();
        let invalid_root = invalid_tree
            .insert_root(TestElement::named("TestPlan", "TestPlanGui", "plan"))
            .unwrap();
        invalid_tree.insert_child(invalid_root, defaults).unwrap();
        invalid_tree.insert_child(invalid_root, sampler()).unwrap();
        let error = compile_native_v3_http_plan(&SemanticPlan::new(
            SemanticRootMetadata::new("jmeterTestPlan", Vec::new(), Span::new(0, 0).unwrap()),
            invalid_tree,
        ))
        .expect_err("invalid default port");
        assert!(matches!(
            error,
            NativeV3HttpCompileError::InvalidProperty {
                property,
                expected: "u16 or expression",
                ..
            } if property == "HTTPSampler.port"
        ));

        let mut no_pool = sampler();
        no_pool.set_property("HTTPSampler.use_keepalive", PropertyValue::boolean(false));
        let compiled = compile_native_v3_http_plan(&plan_with_sampler(no_pool)).unwrap();
        assert!(!compiled.requirements.has_pooling);
        assert!(
            !compiled
                .requirements
                .subordinate_capabilities
                .contains(&"http.pool/1")
        );
    }
}
