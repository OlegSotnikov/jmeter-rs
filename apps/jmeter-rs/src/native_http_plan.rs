// SPDX-License-Identifier: Apache-2.0
//! Pure NativeV2 HTTP plan compilation.
//!
//! This module is intentionally an application-local compiler rather than a
//! transport adapter.  It reads the already decoded semantic JMX tree, walks
//! its ordered tree, and returns an immutable request manifest.  NativeV2 is a
//! closed no-body path: active Request Defaults and manager elements are
//! rejected before a manifest is emitted.  The compiler never resolves an
//! expression, opens a file, performs DNS/TLS work, starts a thread, or
//! mutates the source plan.  The later run owner is responsible for resolving
//! direct NativeV2 DNS/CA properties after this admission pass.

#![forbid(unsafe_code)]
#![allow(
    clippy::module_name_repetitions,
    reason = "the application boundary uses explicit NativeV2 HTTP type names"
)]
use std::collections::BTreeSet;
use std::fmt;
use std::net::IpAddr;

use jmeter_rs_http::Method;
use jmeter_rs_jmx::SemanticPlan;
use jmeter_rs_model::{ElementProperty, NodeId, Properties, PropertyEntry, PropertyValue};

/// The independently named provider compiled by this module.
pub const NATIVE_V2_HTTP_CAPABILITY: &str = "http.native/2";

const MAX_TEXT_BYTES: usize = 128 * 1024;
const MAX_ARGUMENTS: usize = 65_536;
const MAX_TIMEOUT_MS: u64 = 86_400_000;

/// Limits used by the pure HTTP plan compiler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeV2HttpCompileLimits {
    /// Maximum source semantic nodes inspected.
    pub max_nodes: usize,
    /// Maximum enabled HTTP sampler packages emitted.
    pub max_samplers: usize,
    /// Maximum scope components attached to one sampler.
    pub max_scope_components: usize,
    /// Maximum bytes retained by one textual value.
    pub max_text_bytes: usize,
}

impl Default for NativeV2HttpCompileLimits {
    fn default() -> Self {
        Self {
            max_nodes: 100_000,
            max_samplers: 100_000,
            max_scope_components: 65_536,
            max_text_bytes: MAX_TEXT_BYTES,
        }
    }
}

impl NativeV2HttpCompileLimits {
    fn validate(self) -> Result<(), NativeV2HttpCompileError> {
        if self.max_nodes == 0
            || self.max_samplers == 0
            || self.max_scope_components == 0
            || self.max_text_bytes == 0
            || self.max_text_bytes > MAX_TEXT_BYTES
        {
            return Err(NativeV2HttpCompileError::Limit {
                dimension: "compiler-limits",
                observed: self.max_text_bytes,
                maximum: MAX_TEXT_BYTES,
            });
        }
        Ok(())
    }
}

/// Stable failure from the pure NativeV2 HTTP compiler.
///
/// Error variants carry node/property identity and bounded metadata only. In
/// particular, scalar property values, authorization passwords, cookie
/// values, URL query strings, and expression text never cross this boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeV2HttpCompileError {
    /// The source tree is malformed or a referenced node is absent.
    Tree {
        /// Node involved in the malformed topology.
        node_id: Option<NodeId>,
        /// Stable reason category.
        reason: &'static str,
    },
    /// An enabled element is outside the NativeV2 HTTP projection.
    UnsupportedElement {
        /// Source identity.
        node_id: NodeId,
        /// Number of bytes in the unrecognised test-class spelling.
        class_bytes: usize,
    },
    /// A property on a recognised HTTP element is not in the projection.
    UnsupportedProperty {
        /// Source identity.
        node_id: NodeId,
        /// Exact wire property name (property names are not secret values).
        property: String,
    },
    /// A property collection contained the same exact name twice.
    DuplicateProperty {
        /// Source identity.
        node_id: NodeId,
        /// Exact duplicated wire property name.
        property: String,
    },
    /// A required property was absent or explicitly empty.
    EmptyProperty {
        /// Source identity.
        node_id: NodeId,
        /// Exact wire property name.
        property: String,
    },
    /// A property had a different typed representation than its wire schema.
    InvalidProperty {
        /// Source identity.
        node_id: NodeId,
        /// Exact wire property name.
        property: String,
        /// Expected semantic kind, never the supplied value.
        expected: &'static str,
    },
    /// A scalar exceeded the finite compiler text bound.
    ValueLimit {
        /// Source identity.
        node_id: NodeId,
        /// Exact wire property name.
        property: String,
        /// Observed byte length.
        observed: usize,
        /// Maximum accepted bytes.
        maximum: usize,
    },
    /// A known JMeter provider spelling cannot be substituted by NativeV2.
    UnsupportedProvider {
        /// Source identity.
        node_id: NodeId,
        /// Number of bytes in the provider spelling.
        provider_bytes: usize,
    },
    /// A valid JMeter field requests a NativeV2 capability not implemented by
    /// this increment (redirects, proxy, embedded resources, and so on).
    UnsupportedCapability {
        /// Source identity.
        node_id: NodeId,
        /// Stable capability category.
        capability: &'static str,
    },
    /// A required HTTP origin component is not present on the sampler.
    MissingOrigin {
        /// Source sampler identity.
        node_id: NodeId,
        /// Missing origin component.
        component: &'static str,
    },
    /// A bounded HTTP-domain constructor rejected a typed descriptor.
    Http {
        /// Source identity.
        node_id: NodeId,
        /// Property, if one caused the lower-edge error.
        property: Option<String>,
        /// Stable lower-edge code, with all detail redacted.
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
}

impl NativeV2HttpCompileError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Tree { .. } => "app.native-http.plan.tree",
            Self::UnsupportedElement { .. } => "app.native-http.plan.unsupported-element",
            Self::UnsupportedProperty { .. } => "app.native-http.plan.unsupported-property",
            Self::DuplicateProperty { .. } => "app.native-http.plan.duplicate-property",
            Self::EmptyProperty { .. } => "app.native-http.plan.empty-property",
            Self::InvalidProperty { .. } => "app.native-http.plan.invalid-property",
            Self::ValueLimit { .. } => "app.native-http.plan.value-limit",
            Self::UnsupportedProvider { .. } => "app.native-http.plan.provider",
            Self::UnsupportedCapability { .. } => "app.native-http.plan.capability",
            Self::MissingOrigin { .. } => "app.native-http.plan.origin",
            Self::Http { .. } => "app.native-http.plan.http",
            Self::Limit { .. } => "app.native-http.plan.limit",
        }
    }

    /// Returns the source node, when the error is node-specific.
    #[must_use]
    pub const fn node_id(&self) -> Option<NodeId> {
        match self {
            Self::Tree { node_id, .. } => *node_id,
            Self::UnsupportedElement { node_id, .. }
            | Self::UnsupportedProperty { node_id, .. }
            | Self::DuplicateProperty { node_id, .. }
            | Self::EmptyProperty { node_id, .. }
            | Self::InvalidProperty { node_id, .. }
            | Self::ValueLimit { node_id, .. }
            | Self::UnsupportedProvider { node_id, .. }
            | Self::UnsupportedCapability { node_id, .. }
            | Self::MissingOrigin { node_id, .. }
            | Self::Http { node_id, .. } => Some(*node_id),
            Self::Limit { .. } => None,
        }
    }
}

impl fmt::Display for NativeV2HttpCompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())?;
        match self {
            Self::Tree { node_id, reason } => write!(formatter, ": node={node_id:?}, {reason}"),
            Self::UnsupportedElement {
                node_id,
                class_bytes,
            } => write!(formatter, ": node={node_id}, class-bytes={class_bytes}"),
            Self::UnsupportedProperty { node_id, property }
            | Self::DuplicateProperty { node_id, property }
            | Self::EmptyProperty { node_id, property }
            | Self::InvalidProperty {
                node_id, property, ..
            }
            | Self::ValueLimit {
                node_id, property, ..
            } => write!(formatter, ": node={node_id}, property={property}"),
            Self::UnsupportedProvider {
                node_id,
                provider_bytes,
            } => write!(
                formatter,
                ": node={node_id}, provider-bytes={provider_bytes}"
            ),
            Self::UnsupportedCapability {
                node_id,
                capability,
            } => write!(formatter, ": node={node_id}, capability={capability}"),
            Self::MissingOrigin { node_id, component } => {
                write!(formatter, ": node={node_id}, missing={component}")
            }
            Self::Http {
                node_id,
                property,
                code,
            } => write!(
                formatter,
                ": node={node_id}, property={property:?}, lower-edge={code}"
            ),
            Self::Limit {
                dimension,
                observed,
                maximum,
            } => write!(formatter, ": {dimension}={observed}, maximum={maximum}"),
        }
    }
}

impl std::error::Error for NativeV2HttpCompileError {}

/// The source-side provider spelling retained beside every native sampler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeV2SourceProvider {
    /// No implementation property was present; JMeter's 5.6.3 default is
    /// retained as provenance rather than silently erased.
    JmeterDefaultHttpClient4,
    /// Explicit JMeter Java URLConnection provider.
    Java,
    /// Explicit JMeter HttpClient4 provider.
    HttpClient4,
}

impl NativeV2SourceProvider {
    /// Returns the source wire spelling when it is static.
    #[must_use]
    pub const fn static_wire_name(&self) -> Option<&'static str> {
        match self {
            Self::JmeterDefaultHttpClient4 => None,
            Self::Java => Some("Java"),
            Self::HttpClient4 => Some("HttpClient4"),
        }
    }
}

/// A source provider and the independently selected execution provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeV2ProviderIdentity {
    /// Source/JMeter implementation provenance.
    pub source: NativeV2SourceProvider,
    /// Explicit native provider selected by this compiler.
    pub execution: &'static str,
}

/// A bounded source text retained with explicit-presence metadata.
#[derive(Clone, Eq, PartialEq)]
pub struct NativeV2TextTemplate {
    value: String,
    explicit: bool,
}

impl fmt::Debug for NativeV2TextTemplate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeV2TextTemplate")
            .field("value", &"<redacted>")
            .field("value_bytes", &self.value.len())
            .field("explicit", &self.explicit)
            .finish()
    }
}

impl NativeV2TextTemplate {
    fn new(value: String, explicit: bool) -> Self {
        Self { value, explicit }
    }

    /// Returns the source text exactly as retained by the semantic plan.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Returns whether the source carried this field explicitly.
    #[must_use]
    pub const fn explicit(&self) -> bool {
        self.explicit
    }
}

/// A port retained as either a validated literal or JMeter's unspecified port.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeV2PortTemplate {
    /// No port was supplied; the protocol's standard port is selected later.
    Implicit,
    /// An explicit numeric port, including zero as JMeter's unspecified value.
    Literal(u16),
}

/// One ordered HTTP argument from `HTTPsampler.Arguments`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeV2Argument {
    /// Argument name, which may be absent for raw-body mode.
    pub name: Option<NativeV2TextTemplate>,
    /// Argument value, including an explicit empty value.
    pub value: NativeV2TextTemplate,
    /// Wire metadata/separator spelling.
    pub metadata: NativeV2TextTemplate,
    /// Whether the argument is URL encoded.
    pub always_encode: bool,
    /// Whether URL encoding was explicitly authored.
    pub always_encode_explicit: bool,
    /// Whether the emitted field includes `=`.
    pub use_equals: bool,
    /// Whether separator emission was explicitly authored.
    pub use_equals_explicit: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct RequestFields {
    domain: Option<NativeV2TextTemplate>,
    port: Option<NativeV2TextTemplate>,
    protocol: Option<NativeV2TextTemplate>,
    content_encoding: Option<NativeV2TextTemplate>,
    path: Option<NativeV2TextTemplate>,
    method: Option<NativeV2TextTemplate>,
    follow_redirects: Option<bool>,
    auto_redirects: Option<bool>,
    use_keepalive: Option<bool>,
    concurrent_downloads: Option<bool>,
    image_parser: Option<bool>,
    embedded_url_regex: Option<NativeV2TextTemplate>,
    embedded_url_exclude_regex: Option<NativeV2TextTemplate>,
    proxy_present: bool,
    implementation: Option<NativeV2TextTemplate>,
    connect_timeout_ms: Option<u64>,
    connect_timeout_explicit: bool,
    response_timeout_ms: Option<u64>,
    response_timeout_explicit: bool,
    concurrent_pool: Option<u16>,
    concurrent_pool_explicit: bool,
    arguments: Option<Vec<NativeV2Argument>>,
    post_body_raw: Option<bool>,
    multipart: Option<bool>,
}

/// An immutable request template emitted for one sampler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeV2RequestTemplate {
    /// Effective HTTP method.
    pub method: Method,
    /// Whether the effective method was authored by the sampler.
    pub method_explicit: bool,
    /// Effective protocol, preserving source spelling/case.
    pub protocol: NativeV2TextTemplate,
    /// Effective host/domain, preserving expression text when present.
    pub host: NativeV2TextTemplate,
    /// Effective port template.
    pub port: NativeV2PortTemplate,
    /// Effective path, with JMeter's empty path represented as `/`.
    pub path: NativeV2TextTemplate,
    /// Effective request encoding.
    pub content_encoding: NativeV2TextTemplate,
    /// Whether the effective protocol/host/path/encoding fields were
    /// authored rather than compiler defaults.
    pub protocol_explicit: bool,
    /// Whether the effective host/domain was authored rather than missing.
    pub host_explicit: bool,
    /// Whether the effective path was authored rather than `/` fallback.
    pub path_explicit: bool,
    /// Whether the effective content encoding was authored rather than
    /// UTF-8 fallback.
    pub content_encoding_explicit: bool,
    /// Effective redirect policy.
    pub follow_redirects: bool,
    /// Whether the redirect policy was authored.
    pub follow_redirects_explicit: bool,
    /// Effective automatic redirect policy.
    pub auto_redirects: bool,
    /// Whether the automatic-redirect policy was authored.
    pub auto_redirects_explicit: bool,
    /// Effective connection reuse policy.
    pub use_keepalive: bool,
    /// Whether the connection-reuse policy was authored.
    pub use_keepalive_explicit: bool,
    /// Effective body arguments in source order.
    pub arguments: Vec<NativeV2Argument>,
    /// Effective raw body flag.
    pub post_body_raw: bool,
    /// Whether raw-body mode was authored.
    pub post_body_raw_explicit: bool,
    /// Effective multipart flag.
    pub multipart: bool,
    /// Whether multipart mode was authored.
    pub multipart_explicit: bool,
    /// Optional connect timeout in milliseconds.
    pub connect_timeout_ms: Option<u64>,
    /// Whether the connect-timeout field was authored, including empty.
    pub connect_timeout_explicit: bool,
    /// Optional response timeout in milliseconds.
    pub response_timeout_ms: Option<u64>,
    /// Whether the response-timeout field was authored, including empty.
    pub response_timeout_explicit: bool,
    /// Optional embedded-resource pool size.
    pub concurrent_pool: Option<u16>,
    /// Whether the embedded-resource pool field was authored, including
    /// empty.
    pub concurrent_pool_explicit: bool,
}

/// One immutable NativeV2 sampler package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeV2SamplerPlan {
    /// Sampler identity.
    pub node_id: NodeId,
    /// Root-to-sampler source path.
    pub path: Vec<NodeId>,
    /// Source element name.
    pub name: String,
    /// JMeter source provider and selected native provider identity.
    pub provider: NativeV2ProviderIdentity,
    /// Resource requirements for this sampler's effective origin.
    pub requirements: NativeV2SamplerRequirements,
    /// Effective request template.
    pub request: NativeV2RequestTemplate,
}

/// Resource requirements for one immutable NativeV2 sampler package.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeV2SamplerRequirements {
    /// Whether the effective host may require hostname resolution.
    pub has_hostname: bool,
    /// Whether the effective protocol may require TLS.
    pub has_https: bool,
    /// Explicit execution capability selected for this sampler.
    pub capability: &'static str,
}

/// Whole-plan facts consumed by the application-owned NativeV2 resource edge.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NativeV2PlanRequirements {
    /// Whether at least one enabled native HTTP sampler exists.
    pub has_http: bool,
    /// Whether any effective origin requires hostname resolution.
    pub has_hostname: bool,
    /// Whether any effective origin uses HTTPS.
    pub has_https: bool,
    /// Enabled sampler count.
    pub sampler_count: usize,
}

impl NativeV2PlanRequirements {
    /// Returns the exact native capability identity.
    #[must_use]
    pub const fn capability_id(self) -> &'static str {
        NATIVE_V2_HTTP_CAPABILITY
    }
}

/// An immutable compiled NativeV2 HTTP plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledNativeV2HttpPlan {
    /// Explicit execution provider identity.
    pub provider: &'static str,
    /// Whole-plan HTTP resource requirements.
    pub requirements: NativeV2PlanRequirements,
    /// Sampler packages in semantic preorder/source order.
    pub samplers: Vec<NativeV2SamplerPlan>,
}

impl CompiledNativeV2HttpPlan {
    /// Returns a sampler package by source identity.
    #[must_use]
    pub fn sampler(&self, node_id: NodeId) -> Option<&NativeV2SamplerPlan> {
        self.samplers
            .iter()
            .find(|sampler| sampler.node_id == node_id)
    }

    /// Returns immutable packages in source order.
    #[must_use]
    pub fn samplers(&self) -> &[NativeV2SamplerPlan] {
        &self.samplers
    }

    /// Returns whole-plan resource requirements.
    #[must_use]
    pub const fn requirements(&self) -> NativeV2PlanRequirements {
        self.requirements
    }
}

/// The standalone NativeV2 HTTP JMX compiler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeV2HttpPlanCompiler {
    limits: NativeV2HttpCompileLimits,
}

impl Default for NativeV2HttpPlanCompiler {
    fn default() -> Self {
        Self::new()
    }
}

impl NativeV2HttpPlanCompiler {
    /// Creates a compiler with the finite default limits.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            limits: NativeV2HttpCompileLimits {
                max_nodes: 100_000,
                max_samplers: 100_000,
                max_scope_components: 65_536,
                max_text_bytes: MAX_TEXT_BYTES,
            },
        }
    }

    /// Creates a compiler with explicit finite limits.
    #[must_use]
    pub const fn with_limits(limits: NativeV2HttpCompileLimits) -> Self {
        Self { limits }
    }

    /// Returns the compiler limits.
    #[must_use]
    pub const fn limits(self) -> NativeV2HttpCompileLimits {
        self.limits
    }

    /// Compiles a preserved semantic JMX plan atomically.
    ///
    /// Disabled nodes and their complete descendants are omitted from the
    /// executable projection, matching JMeter's disabled-element preparation.
    /// Any enabled unsupported element/property aborts the complete compile;
    /// no partial package list is returned.
    pub fn compile(
        self,
        plan: &SemanticPlan,
    ) -> Result<CompiledNativeV2HttpPlan, NativeV2HttpCompileError> {
        self.limits.validate()?;
        let tree = plan.tree();
        if tree.len() > self.limits.max_nodes {
            return Err(NativeV2HttpCompileError::Limit {
                dimension: "source-nodes",
                observed: tree.len(),
                maximum: self.limits.max_nodes,
            });
        }
        let mut output = Vec::new();
        let mut requirements = NativeV2PlanRequirements::default();
        self.walk_branch(tree, tree.root_ids(), &[], &mut output, &mut requirements)?;
        if output.len() > self.limits.max_samplers {
            return Err(NativeV2HttpCompileError::Limit {
                dimension: "samplers",
                observed: output.len(),
                maximum: self.limits.max_samplers,
            });
        }
        requirements.has_http = !output.is_empty();
        requirements.sampler_count = output.len();
        Ok(CompiledNativeV2HttpPlan {
            provider: NATIVE_V2_HTTP_CAPABILITY,
            requirements,
            samplers: output,
        })
    }

    fn walk_branch(
        self,
        tree: &jmeter_rs_model::ElementTree,
        children: &[NodeId],
        parent_path: &[NodeId],
        output: &mut Vec<NativeV2SamplerPlan>,
        requirements: &mut NativeV2PlanRequirements,
    ) -> Result<(), NativeV2HttpCompileError> {
        let mut parsed_children = Vec::with_capacity(children.len());
        for id in children {
            let node = tree.get(*id).ok_or(NativeV2HttpCompileError::Tree {
                node_id: Some(*id),
                reason: "child-node-missing",
            })?;
            let path = path_with(parent_path, *id);
            if !node.value().is_enabled() {
                // Disabled ancestry is deliberately not decoded: it remains
                // preserved in the source SemanticPlan but contributes no
                // executable fields or unsupported errors.
                parsed_children.push(ParsedChild::Disabled);
                continue;
            }
            let parsed = self.parse_component(*id, &path, node.value())?;
            parsed_children.push(parsed);
        }

        for (id, parsed) in children.iter().copied().zip(parsed_children) {
            let node = tree.get(id).ok_or(NativeV2HttpCompileError::Tree {
                node_id: Some(id),
                reason: "child-node-missing",
            })?;
            if !node.value().is_enabled() {
                continue;
            }
            let path = path_with(parent_path, id);
            match parsed {
                ParsedChild::Sampler(fields) => {
                    if output.len() >= self.limits.max_samplers {
                        return Err(NativeV2HttpCompileError::Limit {
                            dimension: "samplers",
                            observed: output.len().saturating_add(1),
                            maximum: self.limits.max_samplers,
                        });
                    }
                    self.validate_attached_children(tree, id, &path)?;
                    let sampler = self.compile_sampler(id, path, *fields, requirements)?;
                    output.push(sampler);
                }
                ParsedChild::Structural => {
                    self.walk_branch(tree, node.children(), &path, output, requirements)?;
                }
                ParsedChild::PreservationOnly => {
                    // WorkBench/TestFragment source containers are not part of
                    // the executable tree unless a separate replacement pass
                    // has materialized them. This compiler has no replacement
                    // edge and therefore intentionally does not descend.
                }
                ParsedChild::Disabled => {}
            }
        }
        Ok(())
    }

    fn validate_attached_children(
        self,
        tree: &jmeter_rs_model::ElementTree,
        sampler_id: NodeId,
        sampler_path: &[NodeId],
    ) -> Result<(), NativeV2HttpCompileError> {
        let node = tree.get(sampler_id).ok_or(NativeV2HttpCompileError::Tree {
            node_id: Some(sampler_id),
            reason: "sampler-node-missing",
        })?;
        for child_id in node.children() {
            let path = path_with(sampler_path, *child_id);
            self.validate_attached_node(tree, *child_id, &path)?;
        }
        Ok(())
    }

    fn validate_attached_node(
        self,
        tree: &jmeter_rs_model::ElementTree,
        node_id: NodeId,
        path: &[NodeId],
    ) -> Result<(), NativeV2HttpCompileError> {
        let node = tree.get(node_id).ok_or(NativeV2HttpCompileError::Tree {
            node_id: Some(node_id),
            reason: "attached-node-missing",
        })?;
        if !node.value().is_enabled() {
            return Ok(());
        }
        let _ = self.parse_component(node_id, path, node.value())?;
        Err(NativeV2HttpCompileError::UnsupportedElement {
            node_id,
            class_bytes: node.value().test_class().len(),
        })
    }

    fn parse_component(
        self,
        node_id: NodeId,
        _path: &[NodeId],
        element: &jmeter_rs_model::TestElement,
    ) -> Result<ParsedChild, NativeV2HttpCompileError> {
        let class = element.test_class();
        if class.len() > self.limits.max_text_bytes {
            return Err(NativeV2HttpCompileError::ValueLimit {
                node_id,
                property: "testclass".to_owned(),
                observed: class.len(),
                maximum: self.limits.max_text_bytes,
            });
        }
        match classify_native_v2_class(class) {
            Some(NativeV2ClassKind::HttpSampler) => Ok(ParsedChild::Sampler(Box::new(
                parse_sampler_fields(node_id, element, self.limits.max_text_bytes)?,
            ))),
            Some(NativeV2ClassKind::UnsupportedCapability { capability }) => {
                Err(NativeV2HttpCompileError::UnsupportedCapability {
                    node_id,
                    capability,
                })
            }
            Some(NativeV2ClassKind::PreservationOnly) => Ok(ParsedChild::PreservationOnly),
            Some(NativeV2ClassKind::Structural) => Ok(ParsedChild::Structural),
            None => Err(NativeV2HttpCompileError::UnsupportedElement {
                node_id,
                class_bytes: class.len(),
            }),
        }
    }

    fn compile_sampler(
        self,
        node_id: NodeId,
        path: Vec<NodeId>,
        fields: SamplerFields,
        requirements: &mut NativeV2PlanRequirements,
    ) -> Result<NativeV2SamplerPlan, NativeV2HttpCompileError> {
        let effective = fields.request;
        reject_dynamic_request_fields(node_id, &effective)?;
        let source_provider = effective
            .implementation
            .as_ref()
            .map(|value| parse_source_provider(value.value(), node_id))
            .transpose()?
            .unwrap_or(NativeV2SourceProvider::JmeterDefaultHttpClient4);
        let protocol = effective_text(
            effective.protocol.as_ref(),
            "http",
            false,
            node_id,
            "HTTPSampler.protocol",
        )?;
        let protocol_explicit = effective.protocol.is_some();
        if !protocol.value().eq_ignore_ascii_case("http")
            && !protocol.value().eq_ignore_ascii_case("https")
        {
            return Err(NativeV2HttpCompileError::UnsupportedCapability {
                node_id,
                capability: "http.protocol",
            });
        }
        let host = effective
            .domain
            .as_ref()
            .filter(|value| !value.value().is_empty())
            .cloned()
            .ok_or(NativeV2HttpCompileError::MissingOrigin {
                node_id,
                component: "HTTPSampler.domain",
            })?;
        if host.value().chars().any(char::is_whitespace) {
            return Err(NativeV2HttpCompileError::InvalidProperty {
                node_id,
                property: "HTTPSampler.domain".to_owned(),
                expected: "HTTP host without whitespace",
            });
        }
        let host_explicit = effective.domain.is_some();
        let port = effective
            .port
            .as_ref()
            .map(|value| parse_port_template(value.clone(), node_id))
            .transpose()?
            .unwrap_or(NativeV2PortTemplate::Implicit);
        let method_text = effective_text(
            effective.method.as_ref(),
            "GET",
            false,
            node_id,
            "HTTPSampler.method",
        )?;
        let method_explicit = effective.method.is_some();
        let method = Method::parse(method_text.value()).map_err(|error| {
            http_error(node_id, Some("HTTPSampler.method"), error.stable_code())
        })?;
        if !matches!(
            method,
            Method::Get | Method::Head | Method::Delete | Method::Options
        ) {
            return Err(NativeV2HttpCompileError::UnsupportedCapability {
                node_id,
                capability: "http.method",
            });
        }
        let path_explicit = effective.path.is_some();
        let path_template = match effective.path.as_ref() {
            Some(value) if value.value().is_empty() => {
                NativeV2TextTemplate::new("/".to_owned(), value.explicit())
            }
            Some(value) => value.clone(),
            None => NativeV2TextTemplate::new("/".to_owned(), false),
        };
        if path_template.value().contains('#')
            || (!path_template.value().is_empty() && !path_template.value().starts_with('/'))
        {
            return Err(NativeV2HttpCompileError::InvalidProperty {
                node_id,
                property: "HTTPSampler.path".to_owned(),
                expected: "origin-form path",
            });
        }
        let content_encoding = effective_text(
            effective.content_encoding.as_ref(),
            "UTF-8",
            true,
            node_id,
            "HTTPSampler.contentEncoding",
        )?;
        let content_encoding_explicit = effective.content_encoding.is_some();
        if !content_encoding.value().is_empty()
            && !content_encoding.value().eq_ignore_ascii_case("UTF-8")
        {
            return Err(NativeV2HttpCompileError::UnsupportedCapability {
                node_id,
                capability: "http.request-encoding",
            });
        }
        reject_unsupported_request_features(node_id, &effective)?;
        let arguments = effective.arguments.unwrap_or_default();
        if arguments.len() > MAX_ARGUMENTS {
            return Err(NativeV2HttpCompileError::Limit {
                dimension: "arguments",
                observed: arguments.len(),
                maximum: MAX_ARGUMENTS,
            });
        }
        let request = NativeV2RequestTemplate {
            method,
            method_explicit,
            protocol: protocol.clone(),
            host: host.clone(),
            port,
            path: path_template,
            content_encoding,
            protocol_explicit,
            host_explicit,
            path_explicit,
            content_encoding_explicit,
            follow_redirects: effective.follow_redirects.unwrap_or(true),
            follow_redirects_explicit: effective.follow_redirects.is_some(),
            auto_redirects: effective.auto_redirects.unwrap_or(false),
            auto_redirects_explicit: effective.auto_redirects.is_some(),
            use_keepalive: effective.use_keepalive.unwrap_or(true),
            use_keepalive_explicit: effective.use_keepalive.is_some(),
            arguments,
            post_body_raw: effective.post_body_raw.unwrap_or(false),
            post_body_raw_explicit: effective.post_body_raw.is_some(),
            multipart: effective.multipart.unwrap_or(false),
            multipart_explicit: effective.multipart.is_some(),
            connect_timeout_ms: effective.connect_timeout_ms,
            connect_timeout_explicit: effective.connect_timeout_explicit,
            response_timeout_ms: effective.response_timeout_ms,
            response_timeout_explicit: effective.response_timeout_explicit,
            concurrent_pool: effective.concurrent_pool,
            concurrent_pool_explicit: effective.concurrent_pool_explicit,
        };
        let has_hostname = !parse_ip_literal(host.value());
        let has_https = protocol.value().eq_ignore_ascii_case("https");
        requirements.has_hostname |= has_hostname;
        requirements.has_https |= has_https;
        Ok(NativeV2SamplerPlan {
            node_id,
            path,
            name: fields.name,
            provider: NativeV2ProviderIdentity {
                source: source_provider,
                execution: NATIVE_V2_HTTP_CAPABILITY,
            },
            requirements: NativeV2SamplerRequirements {
                has_hostname,
                has_https,
                capability: NATIVE_V2_HTTP_CAPABILITY,
            },
            request,
        })
    }
}

/// Compiles an HTTP projection using the explicit NativeV2 provider.
pub fn compile_native_v2_http_plan(
    plan: &SemanticPlan,
) -> Result<CompiledNativeV2HttpPlan, NativeV2HttpCompileError> {
    NativeV2HttpPlanCompiler::default().compile(plan)
}

#[derive(Clone, Debug)]
enum ParsedChild {
    Sampler(Box<SamplerFields>),
    Structural,
    PreservationOnly,
    Disabled,
}

#[derive(Clone, Debug)]
struct SamplerFields {
    name: String,
    request: RequestFields,
}

fn path_with(parent: &[NodeId], id: NodeId) -> Vec<NodeId> {
    let mut result = parent.to_vec();
    result.push(id);
    result
}

fn http_error(
    node_id: NodeId,
    property: Option<&str>,
    code: &'static str,
) -> NativeV2HttpCompileError {
    NativeV2HttpCompileError::Http {
        node_id,
        property: property.map(str::to_owned),
        code,
    }
}

fn is_expression(value: &str) -> bool {
    value.contains("${")
}

fn parse_ip_literal(value: &str) -> bool {
    let candidate = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(value);
    candidate.parse::<IpAddr>().is_ok()
}

fn parse_source_provider(
    value: &str,
    node_id: NodeId,
) -> Result<NativeV2SourceProvider, NativeV2HttpCompileError> {
    if value == "Java" {
        return Ok(NativeV2SourceProvider::Java);
    }
    if value == "HttpClient4" {
        return Ok(NativeV2SourceProvider::HttpClient4);
    }
    Err(NativeV2HttpCompileError::UnsupportedProvider {
        node_id,
        provider_bytes: value.len(),
    })
}

fn effective_text(
    value: Option<&NativeV2TextTemplate>,
    default: &'static str,
    empty_is_default: bool,
    node_id: NodeId,
    property: &'static str,
) -> Result<NativeV2TextTemplate, NativeV2HttpCompileError> {
    let Some(value) = value else {
        return Ok(NativeV2TextTemplate::new(default.to_owned(), false));
    };
    if value.value().is_empty() && empty_is_default {
        return Ok(NativeV2TextTemplate::new(
            default.to_owned(),
            value.explicit(),
        ));
    }
    if value.value().is_empty() && !empty_is_default {
        return Err(NativeV2HttpCompileError::EmptyProperty {
            node_id,
            property: property.to_owned(),
        });
    }
    Ok(value.clone())
}

fn reject_unsupported_request_features(
    node_id: NodeId,
    fields: &RequestFields,
) -> Result<(), NativeV2HttpCompileError> {
    if fields.follow_redirects.unwrap_or(true) {
        return Err(NativeV2HttpCompileError::UnsupportedCapability {
            node_id,
            capability: "http.redirects",
        });
    }
    if fields.auto_redirects.unwrap_or(false) {
        return Err(NativeV2HttpCompileError::UnsupportedCapability {
            node_id,
            capability: "http.automatic-redirects",
        });
    }
    if fields.concurrent_downloads.unwrap_or(false)
        || fields.image_parser.unwrap_or(false)
        || fields
            .embedded_url_regex
            .as_ref()
            .is_some_and(|value| !value.value().is_empty())
        || fields
            .embedded_url_exclude_regex
            .as_ref()
            .is_some_and(|value| !value.value().is_empty())
    {
        return Err(NativeV2HttpCompileError::UnsupportedCapability {
            node_id,
            capability: "http.embedded-resources",
        });
    }
    if fields.proxy_present {
        return Err(NativeV2HttpCompileError::UnsupportedCapability {
            node_id,
            capability: "http.proxy",
        });
    }
    if !fields.use_keepalive.unwrap_or(true) {
        return Err(NativeV2HttpCompileError::UnsupportedCapability {
            node_id,
            capability: "http.keepalive",
        });
    }
    if fields.post_body_raw.unwrap_or(false) {
        return Err(NativeV2HttpCompileError::UnsupportedCapability {
            node_id,
            capability: "http.request-body",
        });
    }
    if fields.multipart.unwrap_or(false) {
        return Err(NativeV2HttpCompileError::UnsupportedCapability {
            node_id,
            capability: "http.multipart",
        });
    }
    if fields.concurrent_pool_explicit || fields.concurrent_pool.is_some() {
        return Err(NativeV2HttpCompileError::UnsupportedCapability {
            node_id,
            capability: "http.embedded-resources",
        });
    }
    if fields
        .arguments
        .as_ref()
        .is_some_and(|arguments| !arguments.is_empty())
    {
        return Err(NativeV2HttpCompileError::UnsupportedCapability {
            node_id,
            capability: "http.request-body",
        });
    }
    for timeout in [fields.connect_timeout_ms, fields.response_timeout_ms]
        .into_iter()
        .flatten()
    {
        if timeout > MAX_TIMEOUT_MS {
            return Err(NativeV2HttpCompileError::Limit {
                dimension: "http-timeout-ms",
                observed: usize::try_from(timeout).unwrap_or(usize::MAX),
                maximum: usize::try_from(MAX_TIMEOUT_MS).unwrap_or(usize::MAX),
            });
        }
    }
    Ok(())
}

fn reject_dynamic_request_fields(
    node_id: NodeId,
    fields: &RequestFields,
) -> Result<(), NativeV2HttpCompileError> {
    for value in [
        fields.domain.as_ref(),
        fields.port.as_ref(),
        fields.protocol.as_ref(),
        fields.content_encoding.as_ref(),
        fields.path.as_ref(),
        fields.method.as_ref(),
        fields.implementation.as_ref(),
    ] {
        if value.is_some_and(|value| is_expression(value.value())) {
            return Err(NativeV2HttpCompileError::UnsupportedCapability {
                node_id,
                capability: "http.dynamic-field",
            });
        }
    }
    Ok(())
}

fn parse_sampler_fields(
    node_id: NodeId,
    element: &jmeter_rs_model::TestElement,
    max_text_bytes: usize,
) -> Result<SamplerFields, NativeV2HttpCompileError> {
    let request = parse_request_fields(node_id, element, max_text_bytes)?;
    let name = bounded_text(node_id, "testname", element.name(), max_text_bytes)?;
    Ok(SamplerFields { name, request })
}

fn parse_request_fields(
    node_id: NodeId,
    element: &jmeter_rs_model::TestElement,
    max_text_bytes: usize,
) -> Result<RequestFields, NativeV2HttpCompileError> {
    validate_properties(node_id, &element.properties)?;
    if !element.opaque_extensions.is_empty() {
        return Err(NativeV2HttpCompileError::UnsupportedCapability {
            node_id,
            capability: "http.opaque-extension",
        });
    }
    let mut result = RequestFields::default();
    for entry in element.properties.iter() {
        let key = entry.name.as_str();
        match key {
            "HTTPSampler.domain" => {
                result.domain = Some(text_field(node_id, entry, max_text_bytes)?)
            }
            "HTTPSampler.port" => result.port = Some(text_field(node_id, entry, max_text_bytes)?),
            "HTTPSampler.protocol" => {
                result.protocol = Some(text_field(node_id, entry, max_text_bytes)?)
            }
            "HTTPSampler.contentEncoding" => {
                result.content_encoding = Some(text_field(node_id, entry, max_text_bytes)?)
            }
            "HTTPSampler.path" => result.path = Some(text_field(node_id, entry, max_text_bytes)?),
            "HTTPSampler.method" => {
                result.method = Some(text_field(node_id, entry, max_text_bytes)?)
            }
            "HTTPSampler.implementation" => {
                result.implementation = Some(text_field(node_id, entry, max_text_bytes)?)
            }
            "HTTPSampler.follow_redirects" => {
                result.follow_redirects = Some(bool_field(node_id, entry)?)
            }
            "HTTPSampler.auto_redirects" => {
                result.auto_redirects = Some(bool_field(node_id, entry)?)
            }
            "HTTPSampler.use_keepalive" => result.use_keepalive = Some(bool_field(node_id, entry)?),
            "HTTPSampler.concurrentDwn" => {
                result.concurrent_downloads = Some(bool_field(node_id, entry)?)
            }
            "HTTPSampler.image_parser" => result.image_parser = Some(bool_field(node_id, entry)?),
            "HTTPSampler.embedded_url_re" => {
                result.embedded_url_regex = Some(text_field(node_id, entry, max_text_bytes)?)
            }
            "HTTPSampler.embedded_url_exclude_re" => {
                result.embedded_url_exclude_regex =
                    Some(text_field(node_id, entry, max_text_bytes)?)
            }
            "HTTPSampler.connect_timeout" => {
                result.connect_timeout_explicit = true;
                result.connect_timeout_ms = optional_integer_field(node_id, entry, max_text_bytes)?;
            }
            "HTTPSampler.response_timeout" => {
                result.response_timeout_explicit = true;
                result.response_timeout_ms =
                    optional_integer_field(node_id, entry, max_text_bytes)?;
            }
            "HTTPSampler.concurrentPool" => {
                result.concurrent_pool_explicit = true;
                result.concurrent_pool = optional_u16_field(node_id, entry, max_text_bytes)?;
            }
            "HTTPSampler.postBodyRaw" => result.post_body_raw = Some(bool_field(node_id, entry)?),
            "HTTPSampler.DO_MULTIPART_POST" => result.multipart = Some(bool_field(node_id, entry)?),
            "HTTPSampler.proxyScheme"
            | "HTTPSampler.proxyHost"
            | "HTTPSampler.proxyPort"
            | "HTTPSampler.proxyUser"
            | "HTTPSampler.proxyPass" => {
                // Keep presence explicit and reject the capability after the
                // full atomic decode, without retaining secret values.
                result.proxy_present = true;
                let _ = text_field(node_id, entry, max_text_bytes)?;
            }
            "HTTPSampler.files" => {
                return Err(NativeV2HttpCompileError::UnsupportedCapability {
                    node_id,
                    capability: "http.files",
                });
            }
            "HTTPsampler.Arguments" => {
                result.arguments = Some(parse_arguments(node_id, entry, max_text_bytes)?)
            }
            _ => {
                return Err(NativeV2HttpCompileError::UnsupportedProperty {
                    node_id,
                    property: key.to_owned(),
                });
            }
        }
    }
    Ok(result)
}

fn parse_arguments(
    node_id: NodeId,
    entry: &PropertyEntry,
    max_text_bytes: usize,
) -> Result<Vec<NativeV2Argument>, NativeV2HttpCompileError> {
    let element = as_element(node_id, entry, "HTTPsampler.Arguments")?;
    if element.name != "HTTPsampler.Arguments" {
        return Err(NativeV2HttpCompileError::InvalidProperty {
            node_id,
            property: entry.name.clone(),
            expected: "Arguments element",
        });
    }
    validate_properties_allowlist(node_id, &element.properties, &["Arguments.arguments"])?;
    if !element.opaque_extensions.is_empty() {
        return Err(NativeV2HttpCompileError::UnsupportedCapability {
            node_id,
            capability: "http.arguments-opaque-extension",
        });
    }
    let Some(arguments) = element.properties.get("Arguments.arguments") else {
        return Ok(Vec::new());
    };
    let values =
        arguments
            .as_collection()
            .map_err(|_| NativeV2HttpCompileError::InvalidProperty {
                node_id,
                property: "Arguments.arguments".to_owned(),
                expected: "collection",
            })?;
    if values.len() > MAX_ARGUMENTS {
        return Err(NativeV2HttpCompileError::Limit {
            dimension: "arguments",
            observed: values.len(),
            maximum: MAX_ARGUMENTS,
        });
    }
    values
        .iter()
        .map(|value| parse_argument(node_id, value, max_text_bytes))
        .collect()
}

fn parse_argument(
    node_id: NodeId,
    value: &PropertyValue,
    max_text_bytes: usize,
) -> Result<NativeV2Argument, NativeV2HttpCompileError> {
    let element = value
        .as_element()
        .map_err(|_| NativeV2HttpCompileError::InvalidProperty {
            node_id,
            property: "Arguments.arguments".to_owned(),
            expected: "HTTPArgument element",
        })?;
    if let Some(class) = element.class_name()
        && !class.is_empty()
        && class != "HTTPArgument"
        && class != "org.apache.jmeter.protocol.http.util.HTTPArgument"
    {
        return Err(NativeV2HttpCompileError::UnsupportedCapability {
            node_id,
            capability: "http.argument-type",
        });
    }
    validate_properties_allowlist(
        node_id,
        &element.properties,
        &[
            "Argument.name",
            "Argument.value",
            "Argument.metadata",
            "HTTPArgument.always_encode",
            "Argument.always_encode",
            "HTTPArgument.use_equals",
            "Argument.use_equals",
        ],
    )?;
    if !element.opaque_extensions.is_empty() {
        return Err(NativeV2HttpCompileError::UnsupportedCapability {
            node_id,
            capability: "http.argument-opaque-extension",
        });
    }
    let name = optional_text_property(
        node_id,
        &element.properties,
        "Argument.name",
        max_text_bytes,
    )?;
    let value = present_text_property(
        node_id,
        &element.properties,
        "Argument.value",
        max_text_bytes,
    )?;
    let metadata = optional_text_property(
        node_id,
        &element.properties,
        "Argument.metadata",
        max_text_bytes,
    )?
    .unwrap_or_else(|| NativeV2TextTemplate::new("=".to_owned(), false));
    let always_encode = optional_bool_alias(
        node_id,
        &element.properties,
        "HTTPArgument.always_encode",
        "Argument.always_encode",
    )?;
    let use_equals = optional_bool_alias(
        node_id,
        &element.properties,
        "HTTPArgument.use_equals",
        "Argument.use_equals",
    )?;
    Ok(NativeV2Argument {
        name,
        value,
        metadata,
        always_encode: always_encode.unwrap_or(true),
        always_encode_explicit: always_encode.is_some(),
        use_equals: use_equals.unwrap_or(true),
        use_equals_explicit: use_equals.is_some(),
    })
}

fn validate_properties(
    node_id: NodeId,
    properties: &Properties,
) -> Result<(), NativeV2HttpCompileError> {
    let mut names = BTreeSet::new();
    for entry in properties.iter() {
        if !names.insert(entry.name.as_str()) {
            return Err(NativeV2HttpCompileError::DuplicateProperty {
                node_id,
                property: entry.name.clone(),
            });
        }
    }
    Ok(())
}

fn validate_properties_allowlist(
    node_id: NodeId,
    properties: &Properties,
    allowed: &[&str],
) -> Result<(), NativeV2HttpCompileError> {
    validate_properties(node_id, properties)?;
    for entry in properties.iter() {
        if !allowed.contains(&entry.name.as_str()) {
            return Err(NativeV2HttpCompileError::UnsupportedProperty {
                node_id,
                property: entry.name.clone(),
            });
        }
    }
    Ok(())
}

fn bounded_text(
    node_id: NodeId,
    property: &str,
    value: &str,
    maximum: usize,
) -> Result<String, NativeV2HttpCompileError> {
    if value.len() > maximum {
        return Err(NativeV2HttpCompileError::ValueLimit {
            node_id,
            property: property.to_owned(),
            observed: value.len(),
            maximum,
        });
    }
    if value.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return Err(NativeV2HttpCompileError::InvalidProperty {
            node_id,
            property: property.to_owned(),
            expected: "UTF-8 text without control bytes",
        });
    }
    Ok(value.to_owned())
}

fn text_field(
    node_id: NodeId,
    entry: &PropertyEntry,
    maximum: usize,
) -> Result<NativeV2TextTemplate, NativeV2HttpCompileError> {
    let value = entry
        .value
        .as_string()
        .map_err(|_| NativeV2HttpCompileError::InvalidProperty {
            node_id,
            property: entry.name.clone(),
            expected: "string",
        })?;
    Ok(NativeV2TextTemplate::new(
        bounded_text(node_id, &entry.name, value, maximum)?,
        true,
    ))
}

fn bool_field(node_id: NodeId, entry: &PropertyEntry) -> Result<bool, NativeV2HttpCompileError> {
    entry
        .value
        .as_boolean()
        .map_err(|_| NativeV2HttpCompileError::InvalidProperty {
            node_id,
            property: entry.name.clone(),
            expected: "boolean",
        })
}

fn optional_integer_field(
    node_id: NodeId,
    entry: &PropertyEntry,
    maximum: usize,
) -> Result<Option<u64>, NativeV2HttpCompileError> {
    if let Ok(value) = entry.value.as_integer() {
        return u64::try_from(i64::from(value)).map(Some).map_err(|_| {
            NativeV2HttpCompileError::InvalidProperty {
                node_id,
                property: entry.name.clone(),
                expected: "non-negative integer",
            }
        });
    }
    if let Ok(value) = entry.value.as_long() {
        return u64::try_from(value).map(Some).map_err(|_| {
            NativeV2HttpCompileError::InvalidProperty {
                node_id,
                property: entry.name.clone(),
                expected: "non-negative integer",
            }
        });
    }
    let value = entry
        .value
        .as_string()
        .map_err(|_| NativeV2HttpCompileError::InvalidProperty {
            node_id,
            property: entry.name.clone(),
            expected: "integer or empty string",
        })?;
    let value = bounded_text(node_id, &entry.name, value, maximum)?;
    if value.is_empty() {
        return Ok(None);
    }
    if value.starts_with("${") && value.ends_with('}') {
        return Err(NativeV2HttpCompileError::UnsupportedCapability {
            node_id,
            capability: "http.dynamic-timeout",
        });
    }
    value
        .parse::<u64>()
        .map(Some)
        .map_err(|_| NativeV2HttpCompileError::InvalidProperty {
            node_id,
            property: entry.name.clone(),
            expected: "non-negative integer",
        })
}

fn optional_u16_field(
    node_id: NodeId,
    entry: &PropertyEntry,
    maximum: usize,
) -> Result<Option<u16>, NativeV2HttpCompileError> {
    optional_integer_field(node_id, entry, maximum)?.map_or(Ok(None), |value| {
        u16::try_from(value)
            .map(Some)
            .map_err(|_| NativeV2HttpCompileError::InvalidProperty {
                node_id,
                property: entry.name.clone(),
                expected: "u16",
            })
    })
}

fn parse_port_template(
    value: NativeV2TextTemplate,
    node_id: NodeId,
) -> Result<NativeV2PortTemplate, NativeV2HttpCompileError> {
    if value.value().is_empty() {
        return Ok(NativeV2PortTemplate::Literal(0));
    }
    let port =
        value
            .value()
            .parse::<u16>()
            .map_err(|_| NativeV2HttpCompileError::InvalidProperty {
                node_id,
                property: "HTTPSampler.port".to_owned(),
                expected: "u16",
            })?;
    Ok(NativeV2PortTemplate::Literal(port))
}

fn as_element<'a>(
    node_id: NodeId,
    entry: &'a PropertyEntry,
    property: &'static str,
) -> Result<&'a ElementProperty, NativeV2HttpCompileError> {
    entry
        .value
        .as_element()
        .map_err(|_| NativeV2HttpCompileError::InvalidProperty {
            node_id,
            property: property.to_owned(),
            expected: "element property",
        })
}

fn present_text_property(
    node_id: NodeId,
    properties: &Properties,
    property: &'static str,
    maximum: usize,
) -> Result<NativeV2TextTemplate, NativeV2HttpCompileError> {
    let Some(value) = properties.get(property) else {
        return Err(NativeV2HttpCompileError::EmptyProperty {
            node_id,
            property: property.to_owned(),
        });
    };
    text_field(
        node_id,
        &PropertyEntry::new(property, value.clone()),
        maximum,
    )
}

fn optional_text_property(
    node_id: NodeId,
    properties: &Properties,
    property: &'static str,
    maximum: usize,
) -> Result<Option<NativeV2TextTemplate>, NativeV2HttpCompileError> {
    properties
        .get(property)
        .map(|value| {
            text_field(
                node_id,
                &PropertyEntry::new(property, value.clone()),
                maximum,
            )
        })
        .transpose()
}

fn optional_bool_alias(
    node_id: NodeId,
    properties: &Properties,
    primary: &'static str,
    alias: &'static str,
) -> Result<Option<bool>, NativeV2HttpCompileError> {
    if properties.get(primary).is_some() && properties.get(alias).is_some() {
        return Err(NativeV2HttpCompileError::DuplicateProperty {
            node_id,
            property: primary.to_owned(),
        });
    }
    if let Some(value) = properties.get(primary) {
        return bool_field(node_id, &PropertyEntry::new(primary, value.clone())).map(Some);
    }
    if let Some(value) = properties.get(alias) {
        return bool_field(node_id, &PropertyEntry::new(alias, value.clone())).map(Some);
    }
    Ok(None)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeV2ClassKind {
    HttpSampler,
    PreservationOnly,
    Structural,
    UnsupportedCapability { capability: &'static str },
}

// This is the only class vocabulary used by the NativeV2 compiler. Every
// spelling is an exact pinned JMeter/runtime alias; class-package suffixes,
// case variants, and plugin-provided lookalikes are intentionally absent.
const NATIVE_V2_CLASS_ALLOWLIST: &[(&str, NativeV2ClassKind)] = &[
    // NativeV2 admits the canonical HTTP sampler and its exact Apache class
    // spelling. HTTPHC4Impl is a separate legacy runtime alias and is not a
    // NativeV2 sampler class.
    ("HTTPSamplerProxy", NativeV2ClassKind::HttpSampler),
    (
        "org.apache.jmeter.protocol.http.sampler.HTTPSamplerProxy",
        NativeV2ClassKind::HttpSampler,
    ),
    // Source containers are preserved but never traversed as executable
    // branches by this compiler.
    ("WorkBench", NativeV2ClassKind::PreservationOnly),
    (
        "org.apache.jmeter.testelement.WorkBench",
        NativeV2ClassKind::PreservationOnly,
    ),
    (
        "TestFragmentController",
        NativeV2ClassKind::PreservationOnly,
    ),
    (
        "org.apache.jmeter.control.TestFragmentController",
        NativeV2ClassKind::PreservationOnly,
    ),
    // Active manager/default classes are deliberately classified only to
    // return their stable unsupported capability; none are compiled.
    (
        "ConfigTestElement",
        NativeV2ClassKind::UnsupportedCapability {
            capability: "http.request-defaults",
        },
    ),
    (
        "org.apache.jmeter.config.ConfigTestElement",
        NativeV2ClassKind::UnsupportedCapability {
            capability: "http.request-defaults",
        },
    ),
    (
        "HeaderManager",
        NativeV2ClassKind::UnsupportedCapability {
            capability: "http.header-manager",
        },
    ),
    (
        "HTTPHeaderManager",
        NativeV2ClassKind::UnsupportedCapability {
            capability: "http.header-manager",
        },
    ),
    (
        "org.apache.jmeter.protocol.http.control.HeaderManager",
        NativeV2ClassKind::UnsupportedCapability {
            capability: "http.header-manager",
        },
    ),
    (
        "CookieManager",
        NativeV2ClassKind::UnsupportedCapability {
            capability: "http.cookie-manager",
        },
    ),
    (
        "org.apache.jmeter.protocol.http.control.CookieManager",
        NativeV2ClassKind::UnsupportedCapability {
            capability: "http.cookie-manager",
        },
    ),
    (
        "CacheManager",
        NativeV2ClassKind::UnsupportedCapability {
            capability: "http.cache-manager",
        },
    ),
    (
        "org.apache.jmeter.protocol.http.control.CacheManager",
        NativeV2ClassKind::UnsupportedCapability {
            capability: "http.cache-manager",
        },
    ),
    (
        "AuthManager",
        NativeV2ClassKind::UnsupportedCapability {
            capability: "http.auth-manager",
        },
    ),
    (
        "org.apache.jmeter.protocol.http.control.AuthManager",
        NativeV2ClassKind::UnsupportedCapability {
            capability: "http.auth-manager",
        },
    ),
    (
        "DNSCacheManager",
        NativeV2ClassKind::UnsupportedCapability {
            capability: "http.dns-manager",
        },
    ),
    (
        "org.apache.jmeter.protocol.http.control.DNSCacheManager",
        NativeV2ClassKind::UnsupportedCapability {
            capability: "http.dns-manager",
        },
    ),
    (
        "SSLManager",
        NativeV2ClassKind::UnsupportedCapability {
            capability: "http.tls-store",
        },
    ),
    (
        "org.apache.jmeter.protocol.http.util.SSLManager",
        NativeV2ClassKind::UnsupportedCapability {
            capability: "http.tls-store",
        },
    ),
    (
        "KeystoreConfig",
        NativeV2ClassKind::UnsupportedCapability {
            capability: "http.tls-store",
        },
    ),
    (
        "org.apache.jmeter.config.KeystoreConfig",
        NativeV2ClassKind::UnsupportedCapability {
            capability: "http.tls-store",
        },
    ),
    (
        "KeystoreConfiguration",
        NativeV2ClassKind::UnsupportedCapability {
            capability: "http.tls-store",
        },
    ),
    (
        "KeyStoreConfig",
        NativeV2ClassKind::UnsupportedCapability {
            capability: "http.tls-store",
        },
    ),
    // Executable structural aliases are exact and intentionally limited to
    // the no-side-effect traversal vocabulary of this NativeV2 compiler.
    ("TestPlan", NativeV2ClassKind::Structural),
    (
        "org.apache.jmeter.testelement.TestPlan",
        NativeV2ClassKind::Structural,
    ),
    ("ThreadGroup", NativeV2ClassKind::Structural),
    (
        "org.apache.jmeter.threads.ThreadGroup",
        NativeV2ClassKind::Structural,
    ),
    ("SetupThreadGroup", NativeV2ClassKind::Structural),
    (
        "org.apache.jmeter.threads.SetupThreadGroup",
        NativeV2ClassKind::Structural,
    ),
    ("PostThreadGroup", NativeV2ClassKind::Structural),
    (
        "org.apache.jmeter.threads.PostThreadGroup",
        NativeV2ClassKind::Structural,
    ),
    ("LoopController", NativeV2ClassKind::Structural),
    (
        "org.apache.jmeter.control.LoopController",
        NativeV2ClassKind::Structural,
    ),
    ("GenericController", NativeV2ClassKind::Structural),
    (
        "org.apache.jmeter.control.GenericController",
        NativeV2ClassKind::Structural,
    ),
    ("IfController", NativeV2ClassKind::Structural),
    (
        "org.apache.jmeter.control.IfController",
        NativeV2ClassKind::Structural,
    ),
    ("WhileController", NativeV2ClassKind::Structural),
    (
        "org.apache.jmeter.control.WhileController",
        NativeV2ClassKind::Structural,
    ),
    ("OnceOnlyController", NativeV2ClassKind::Structural),
    (
        "org.apache.jmeter.control.OnceOnlyController",
        NativeV2ClassKind::Structural,
    ),
    ("InterleaveControl", NativeV2ClassKind::Structural),
    (
        "org.apache.jmeter.control.InterleaveControl",
        NativeV2ClassKind::Structural,
    ),
    ("RandomController", NativeV2ClassKind::Structural),
    (
        "org.apache.jmeter.control.RandomController",
        NativeV2ClassKind::Structural,
    ),
    ("RandomOrderController", NativeV2ClassKind::Structural),
    (
        "org.apache.jmeter.control.RandomOrderController",
        NativeV2ClassKind::Structural,
    ),
    ("ThroughputController", NativeV2ClassKind::Structural),
    (
        "org.apache.jmeter.control.ThroughputController",
        NativeV2ClassKind::Structural,
    ),
    ("TransactionController", NativeV2ClassKind::Structural),
    (
        "org.apache.jmeter.control.TransactionController",
        NativeV2ClassKind::Structural,
    ),
    ("ModuleController", NativeV2ClassKind::Structural),
    (
        "org.apache.jmeter.control.ModuleController",
        NativeV2ClassKind::Structural,
    ),
    ("IncludeController", NativeV2ClassKind::Structural),
    (
        "org.apache.jmeter.control.IncludeController",
        NativeV2ClassKind::Structural,
    ),
];

fn classify_native_v2_class(class: &str) -> Option<NativeV2ClassKind> {
    NATIVE_V2_CLASS_ALLOWLIST
        .iter()
        .find(|(alias, _)| *alias == class)
        .map(|(_, kind)| *kind)
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
    use jmeter_rs_model::{ElementTree, TestElement};

    fn plan_with_sampler(sampler: TestElement) -> SemanticPlan {
        let root =
            SemanticRootMetadata::new("jmeterTestPlan", Vec::new(), Span::new(0, 0).expect("span"));
        let mut tree = ElementTree::new();
        let test_plan = tree
            .insert_root(TestElement::named("TestPlan", "TestPlanGui", "plan"))
            .expect("root");
        tree.insert(Some(test_plan), sampler).expect("sampler");
        SemanticPlan::new(root, tree)
    }

    fn sampler() -> TestElement {
        let mut sampler = TestElement::named("HTTPSamplerProxy", "HttpTestSampleGui", "sample");
        sampler.set_property("HTTPSampler.domain", PropertyValue::string("127.0.0.1"));
        sampler.set_property("HTTPSampler.path", PropertyValue::string("/ok"));
        sampler.set_property("HTTPSampler.method", PropertyValue::string("GET"));
        sampler.set_property(
            "HTTPSampler.follow_redirects",
            PropertyValue::boolean(false),
        );
        sampler
    }

    #[test]
    fn compiles_immutable_native_v2_template_without_io() {
        let plan = plan_with_sampler(sampler());
        let compiled = compile_native_v2_http_plan(&plan).expect("compile");
        assert_eq!(compiled.provider, NATIVE_V2_HTTP_CAPABILITY);
        assert_eq!(compiled.samplers.len(), 1);
        assert_eq!(compiled.requirements.has_http, true);
        assert_eq!(compiled.requirements.has_hostname, false);
        assert_eq!(compiled.samplers[0].request.method, Method::Get);
        assert_eq!(compiled.samplers[0].request.path.value(), "/ok");
        assert_eq!(
            compiled.samplers[0].provider.source,
            NativeV2SourceProvider::JmeterDefaultHttpClient4
        );
    }

    #[test]
    fn accepted_methods_and_defaults_keep_presence_explicit() {
        for method in ["GET", "HEAD", "DELETE", "OPTIONS"] {
            let mut candidate = sampler();
            candidate.set_property("HTTPSampler.method", PropertyValue::string(method));
            let compiled = compile_native_v2_http_plan(&plan_with_sampler(candidate))
                .expect("closed method compiles");
            let request = &compiled.samplers[0].request;
            assert_eq!(request.method.to_string(), method);
            assert!(!request.protocol_explicit);
            assert!(request.host_explicit);
            assert!(request.path_explicit);
            assert!(!request.content_encoding_explicit);
            assert!(request.follow_redirects_explicit);
            assert!(!request.auto_redirects);
            assert!(request.use_keepalive);
            assert!(!request.use_keepalive_explicit);
        }
    }

    #[test]
    fn nested_scope_preserves_source_order_and_paths() {
        let root_meta =
            SemanticRootMetadata::new("jmeterTestPlan", Vec::new(), Span::new(0, 0).expect("span"));
        let mut tree = ElementTree::new();
        let root = tree
            .insert_root(TestElement::named("TestPlan", "TestPlanGui", "plan"))
            .expect("root");
        let group = tree
            .insert(
                Some(root),
                TestElement::named("ThreadGroup", "ThreadGroupGui", "group"),
            )
            .expect("thread group");
        let controller = tree
            .insert(
                Some(group),
                TestElement::named("LoopController", "LoopControlPanel", "loop"),
            )
            .expect("controller");
        let nested = tree
            .insert(Some(controller), sampler())
            .expect("nested sampler");
        let sibling = tree
            .insert(Some(group), sampler())
            .expect("sibling sampler");
        let plan = SemanticPlan::new(root_meta, tree);
        let compiled = compile_native_v2_http_plan(&plan).expect("nested scope compiles");
        assert_eq!(
            compiled
                .samplers
                .iter()
                .map(|item| item.node_id)
                .collect::<Vec<_>>(),
            [nested, sibling]
        );
        assert_eq!(
            compiled.samplers[0].path,
            vec![root, group, controller, nested]
        );
        assert_eq!(compiled.samplers[1].path, vec![root, group, sibling]);
    }

    #[test]
    fn duplicate_wire_property_is_rejected_without_partial_output() {
        let source = br#"<jmeterTestPlan version="1.2"><hashTree><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="plan" enabled="true"/><hashTree><HTTPSamplerProxy guiclass="HttpTestSampleGui" testclass="HTTPSamplerProxy" testname="sample" enabled="true"><stringProp name="HTTPSampler.domain">127.0.0.1</stringProp><stringProp name="HTTPSampler.domain">127.0.0.2</stringProp><boolProp name="HTTPSampler.follow_redirects">false</boolProp></HTTPSamplerProxy><hashTree/></hashTree></hashTree></jmeterTestPlan>"#;
        let plan = jmeter_rs_jmx::parse_semantic(source).expect("duplicate JMX decodes");
        let error = compile_native_v2_http_plan(&plan).expect_err("duplicate property rejects");
        assert!(matches!(
            error,
            NativeV2HttpCompileError::UnsupportedCapability {
                capability: "http.opaque-extension",
                ..
            }
        ));
    }

    #[test]
    fn disabled_ancestry_is_not_executable() {
        let mut root = TestElement::named("TestPlan", "TestPlanGui", "plan");
        root.set_enabled(false);
        let root_meta =
            SemanticRootMetadata::new("jmeterTestPlan", Vec::new(), Span::new(0, 0).expect("span"));
        let mut tree = ElementTree::new();
        let root_id = tree.insert_root(root).expect("root");
        let disabled_sampler = tree.insert(Some(root_id), sampler()).expect("sampler");
        tree.insert(
            Some(disabled_sampler),
            TestElement::named("evil.HTTPSamplerProxy", "HttpTestSampleGui", "unknown"),
        )
        .expect("disabled descendant");
        let plan = SemanticPlan::new(root_meta, tree);
        let compiled = compile_native_v2_http_plan(&plan).expect("compile");
        assert!(compiled.samplers.is_empty());
    }

    #[test]
    fn disabled_manager_is_not_admitted_or_decoded() {
        let root_meta =
            SemanticRootMetadata::new("jmeterTestPlan", Vec::new(), Span::new(0, 0).expect("span"));
        let mut tree = ElementTree::new();
        let root = tree
            .insert_root(TestElement::named("TestPlan", "TestPlanGui", "plan"))
            .expect("root");
        tree.insert(Some(root), sampler()).expect("sampler");
        let mut manager = TestElement::named("HeaderManager", "HeaderGui", "disabled");
        manager.set_enabled(false);
        tree.insert(Some(root), manager).expect("disabled manager");
        let plan = SemanticPlan::new(root_meta, tree);
        let compiled = compile_native_v2_http_plan(&plan).expect("disabled manager ignored");
        assert_eq!(compiled.samplers.len(), 1);
    }

    #[test]
    fn unsupported_property_fails_atomically_and_redacts_value() {
        let mut sampler = sampler();
        sampler.set_property(
            "HTTPSampler.proxyPass",
            PropertyValue::string("super-secret-password"),
        );
        let plan = plan_with_sampler(sampler);
        let error = compile_native_v2_http_plan(&plan).expect_err("proxy unsupported");
        assert_eq!(error.code(), "app.native-http.plan.capability");
        assert!(!error.to_string().contains("super-secret-password"));
    }

    #[test]
    fn unresolved_dynamic_origin_fails_before_native_execution() {
        let mut candidate = sampler();
        candidate.set_property(
            "HTTPSampler.domain",
            PropertyValue::string("${__P(host,fixture.example)}"),
        );
        let error = compile_native_v2_http_plan(&plan_with_sampler(candidate))
            .expect_err("V2 cannot execute unresolved expressions");
        assert!(matches!(
            error,
            NativeV2HttpCompileError::UnsupportedCapability {
                capability: "http.dynamic-field",
                ..
            }
        ));
    }

    #[test]
    fn empty_origin_and_negative_numeric_values_fail_closed() {
        let mut empty = sampler();
        empty.set_property("HTTPSampler.domain", PropertyValue::string(""));
        let error =
            compile_native_v2_http_plan(&plan_with_sampler(empty)).expect_err("empty domain");
        assert_eq!(error.code(), "app.native-http.plan.origin");

        let mut negative = sampler();
        negative.set_property("HTTPSampler.connect_timeout", PropertyValue::string("-1"));
        let error = compile_native_v2_http_plan(&plan_with_sampler(negative))
            .expect_err("negative timeout");
        assert_eq!(error.code(), "app.native-http.plan.invalid-property");
        assert!(!error.to_string().contains("-1"));
    }

    #[test]
    fn limits_are_enforced_before_unbounded_sampler_accumulation() {
        let compiler = NativeV2HttpPlanCompiler::with_limits(NativeV2HttpCompileLimits {
            max_nodes: 1,
            max_samplers: 1,
            max_scope_components: 1,
            max_text_bytes: 8,
        });
        let error = compiler
            .compile(&plan_with_sampler(sampler()))
            .expect_err("source exceeds node or text bound");
        assert_eq!(error.code(), "app.native-http.plan.limit");
    }

    fn assert_active_element_rejected(class: &str, capability: &'static str) {
        let root_meta =
            SemanticRootMetadata::new("jmeterTestPlan", Vec::new(), Span::new(0, 0).expect("span"));
        let mut tree = ElementTree::new();
        let root = tree
            .insert_root(TestElement::named("TestPlan", "TestPlanGui", "plan"))
            .expect("root");
        let first_sampler = tree.insert(Some(root), sampler()).expect("first sampler");
        let manager = tree
            .insert(
                Some(root),
                TestElement::named(class, "ManagerGui", "unsupported"),
            )
            .expect("manager");
        tree.insert(Some(root), sampler()).expect("second sampler");
        let plan = SemanticPlan::new(root_meta, tree);
        let error =
            compile_native_v2_http_plan(&plan).expect_err("closed V2 rejects active element");
        assert_eq!(error.code(), "app.native-http.plan.capability");
        assert!(matches!(
            &error,
            NativeV2HttpCompileError::UnsupportedCapability {
                node_id,
                capability: actual,
            } if *node_id == manager && *actual == capability
        ));
        assert_ne!(first_sampler, manager);
    }

    #[test]
    fn active_defaults_and_http_managers_are_rejected_atomically() {
        for (class, capability) in [
            ("ConfigTestElement", "http.request-defaults"),
            ("HeaderManager", "http.header-manager"),
            ("CookieManager", "http.cookie-manager"),
            ("CacheManager", "http.cache-manager"),
            ("AuthManager", "http.auth-manager"),
        ] {
            assert_active_element_rejected(class, capability);
        }
    }

    #[test]
    fn active_dns_tls_and_unknown_managers_are_not_structural() {
        for (class, capability) in [
            ("DNSCacheManager", "http.dns-manager"),
            ("SSLManager", "http.tls-store"),
            ("KeystoreConfig", "http.tls-store"),
        ] {
            assert_active_element_rejected(class, capability);
        }
    }

    #[test]
    fn unknown_manager_suffix_is_not_a_pinned_manager_alias() {
        let root_meta =
            SemanticRootMetadata::new("jmeterTestPlan", Vec::new(), Span::new(0, 0).expect("span"));
        let mut tree = ElementTree::new();
        let root = tree
            .insert_root(TestElement::named("TestPlan", "TestPlanGui", "plan"))
            .expect("root");
        tree.insert(Some(root), sampler()).expect("sampler");
        let manager = tree
            .insert(
                Some(root),
                TestElement::named("evil.CustomManager", "ManagerGui", "unknown"),
            )
            .expect("unknown manager");
        let plan = SemanticPlan::new(root_meta, tree);
        let error = compile_native_v2_http_plan(&plan).expect_err("unknown manager rejects");
        assert!(matches!(
            error,
            NativeV2HttpCompileError::UnsupportedElement {
                node_id,
                class_bytes,
            } if node_id == manager && class_bytes == "evil.CustomManager".len()
        ));
        assert!(!error.to_string().contains("evil.CustomManager"));
    }

    #[test]
    fn only_pinned_http_sampler_aliases_are_admitted() {
        let mut apache_alias = sampler();
        apache_alias.metadata.test_class =
            "org.apache.jmeter.protocol.http.sampler.HTTPSamplerProxy".to_owned();
        let accepted = compile_native_v2_http_plan(&plan_with_sampler(apache_alias))
            .expect("exact Apache sampler alias compiles");
        assert_eq!(accepted.samplers.len(), 1);

        for class in [
            "evil.HTTPSamplerProxy",
            "httpsamplerproxy",
            "HTTPHC4Impl",
            "evil.HTTPHC4Impl",
        ] {
            let candidate = TestElement::named(class, "HttpTestSampleGui", "not-a-sampler");
            let error = compile_native_v2_http_plan(&plan_with_sampler(candidate))
                .expect_err("unlisted HTTP class must reject");
            assert!(matches!(
                error,
                NativeV2HttpCompileError::UnsupportedElement {
                    class_bytes,
                    ..
                } if class_bytes == class.len()
            ));
            assert!(!error.to_string().contains(class));
        }
    }

    #[test]
    fn unsupported_class_metadata_is_stable_and_bounded() {
        let class = format!("evil.{}", "x".repeat(MAX_TEXT_BYTES + 1));
        let candidate = TestElement::named(&class, "HttpTestSampleGui", "oversized");
        let plan = plan_with_sampler(candidate);
        let error = compile_native_v2_http_plan(&plan).expect_err("class bound rejects");
        assert!(matches!(
            error,
            NativeV2HttpCompileError::ValueLimit {
                node_id: _,
                ref property,
                observed,
                maximum,
            } if property == "testclass" && observed == class.len() && maximum == MAX_TEXT_BYTES
        ));
        let display = error.to_string();
        assert!(display.len() < 256);
        assert!(!display.contains(&class));
    }

    #[test]
    fn closed_native_v2_accepts_numeric_hostname_http_and_https() {
        let numeric = compile_native_v2_http_plan(&plan_with_sampler(sampler())).expect("numeric");
        assert!(!numeric.requirements.has_hostname);
        assert!(!numeric.requirements.has_https);

        let mut hostname_sampler = sampler();
        hostname_sampler.set_property(
            "HTTPSampler.domain",
            PropertyValue::string("fixture.example"),
        );
        let hostname =
            compile_native_v2_http_plan(&plan_with_sampler(hostname_sampler)).expect("hostname");
        assert!(hostname.requirements.has_hostname);
        assert!(!hostname.requirements.has_https);

        let mut https_sampler = sampler();
        https_sampler.set_property(
            "HTTPSampler.domain",
            PropertyValue::string("fixture.example"),
        );
        https_sampler.set_property("HTTPSampler.protocol", PropertyValue::string("https"));
        let https = compile_native_v2_http_plan(&plan_with_sampler(https_sampler)).expect("https");
        assert!(https.requirements.has_hostname);
        assert!(https.requirements.has_https);
    }

    #[test]
    fn closed_native_v2_rejects_body_redirect_and_keepalive_features() {
        for (property, value, capability) in [
            (
                "HTTPSampler.method",
                PropertyValue::string("POST"),
                "http.method",
            ),
            (
                "HTTPSampler.postBodyRaw",
                PropertyValue::boolean(true),
                "http.request-body",
            ),
            (
                "HTTPSampler.DO_MULTIPART_POST",
                PropertyValue::boolean(true),
                "http.multipart",
            ),
            (
                "HTTPSampler.files",
                PropertyValue::string("secret-file-reference"),
                "http.files",
            ),
            (
                "HTTPSampler.follow_redirects",
                PropertyValue::boolean(true),
                "http.redirects",
            ),
            (
                "HTTPSampler.auto_redirects",
                PropertyValue::boolean(true),
                "http.automatic-redirects",
            ),
            (
                "HTTPSampler.use_keepalive",
                PropertyValue::boolean(false),
                "http.keepalive",
            ),
            (
                "HTTPSampler.concurrentPool",
                PropertyValue::string("6"),
                "http.embedded-resources",
            ),
        ] {
            let mut candidate = sampler();
            candidate.set_property(property, value);
            let error = compile_native_v2_http_plan(&plan_with_sampler(candidate))
                .expect_err("closed V2 feature must reject");
            assert!(matches!(
                error,
                NativeV2HttpCompileError::UnsupportedCapability {
                    capability: actual,
                    ..
                } if actual == capability
            ));
        }
    }
}
