// SPDX-License-Identifier: Apache-2.0
//! Pure preparation of the NativeV2 HTTP request boundary.
//!
//! [`crate::native_http_plan`] owns the closed JMX projection.  This module
//! is the next, still-pure, boundary: it turns those already validated
//! templates into typed [`jmeter_rs_http::Request`] values and explicit
//! client policy.  It deliberately does not own a transport or any run
//! resource.  In particular, this module never resolves a name, reads a
//! file, starts a worker, consults process state, or selects a provider from
//! a request's URL.

#![forbid(unsafe_code)]
#![allow(
    clippy::module_name_repetitions,
    reason = "the application boundary uses explicit NativeV2 request types"
)]

use std::collections::BTreeSet;
use std::fmt;
use std::net::{IpAddr, Ipv6Addr};
use std::time::Duration;

use jmeter_rs_http::{
    ClientConfig, ClientLimits, DecompressionPolicy, HARD_MAX_REDIRECT_RETAINED_BYTES,
    HARD_MAX_TIMEOUT, HttpVersionPolicy, MAX_ERROR_DIAGNOSTIC_BYTES, MAX_PATH_QUERY_BYTES,
    MAX_URL_BYTES, Method, NoProxy, ProxyPolicy, RedirectPolicy, Request, RetryPolicy,
    SessionLimits, TimeoutConfig, TlsConfig, TlsTrustSource, TlsVerification, TlsVersion, Url,
};
use jmeter_rs_http_native::NativeTransportLimits;
use jmeter_rs_model::NodeId;

use crate::native_http_plan::{
    CompiledNativeV2HttpPlan, NATIVE_V2_HTTP_CAPABILITY, NativeV2PlanRequirements,
    NativeV2PortTemplate, NativeV2ProviderIdentity, NativeV2SamplerPlan, NativeV2SourceProvider,
};

/// The independently named NativeV2 execution provider.
pub const NATIVE_V2_REQUEST_CAPABILITY: &str = NATIVE_V2_HTTP_CAPABILITY;

/// Maximum timeout accepted by the NativeV2 preparation boundary.
pub const MAX_NATIVE_V2_TIMEOUT: Duration = HARD_MAX_TIMEOUT;

/// Provider-safety timeout recipe used for absent and zero JMeter timeout
/// spellings.  These values are an explicit NativeV2 safety policy selected by
/// this mapper; they are not a claim about an upstream JMeter equivalence.
pub const NATIVE_V2_PROVIDER_SAFETY_OVERALL_TIMEOUT: Duration = Duration::from_secs(120);

/// Provider-safety phase cap used for absent and zero JMeter timeout
/// spellings.  The later run transaction turns the resulting finite recipe
/// into its one local deadline; this module never reads a clock.
pub const NATIVE_V2_PROVIDER_SAFETY_PHASE_TIMEOUT: Duration = Duration::from_secs(30);

/// Explicit finite timeout recipe selected at the NativeV2 application edge.
///
/// JMeter's absent/empty/zero timeout spellings do not establish a portable
/// finite deadline for this provider.  The default recipe is therefore named
/// provider-safety policy rather than presented as an upstream compatibility
/// default.  A central factory may inject a different bounded recipe before
/// mapping; no clock or absolute deadline is stored here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeV2TimeoutPolicy {
    /// Overall operation duration recipe before longer explicit phases extend
    /// it to preserve the phase-within-overall invariant.
    pub overall: Duration,
    /// Phase duration recipe for absent and zero JMeter timeout spellings.
    pub phase: Duration,
}

impl Default for NativeV2TimeoutPolicy {
    fn default() -> Self {
        Self {
            overall: NATIVE_V2_PROVIDER_SAFETY_OVERALL_TIMEOUT,
            phase: NATIVE_V2_PROVIDER_SAFETY_PHASE_TIMEOUT,
        }
    }
}

impl NativeV2TimeoutPolicy {
    fn validate(self) -> Result<(), NativeV2RequestPrepareError> {
        for (dimension, duration) in [
            ("overall-timeout-policy", self.overall),
            ("phase-timeout-policy", self.phase),
        ] {
            if duration.is_zero() || duration > MAX_NATIVE_V2_TIMEOUT {
                return Err(NativeV2RequestPrepareError::limit(
                    None,
                    &[],
                    dimension,
                    duration.as_millis().try_into().unwrap_or(usize::MAX),
                    MAX_NATIVE_V2_TIMEOUT
                        .as_millis()
                        .try_into()
                        .unwrap_or(usize::MAX),
                ));
            }
        }
        Ok(())
    }
}

const DEFAULT_MAX_SAMPLERS: usize = 100_000;
const DEFAULT_MAX_RETAINED_BYTES: usize = 512 * 1024 * 1024;
const DEFAULT_MAX_SOURCE_PATH_NODES: usize = 128;
const DEFAULT_MAX_SAMPLER_NAME_BYTES: usize = 128 * 1024;
const PREPARED_REQUEST_OVERHEAD_BYTES: usize = 128;
const MAX_MAPPER_DIAGNOSTIC_CODE_BYTES: usize =
    "app.native-http.request.requirements-mismatch".len();

/// Bounds for the immutable prepared request map.
///
/// These limits cover retained preparation data, not the run-owned worker
/// queue.  Every field is checked before allocation and values are never
/// silently clamped.  The URL/path/diagnostic ceilings mirror the lower HTTP
/// boundary; source paths additionally follow the error-context cap in
/// Decision 0006.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeV2RequestMapLimits {
    /// Maximum number of samplers in one prepared map.
    pub max_samplers: usize,
    /// Maximum aggregate bytes retained by all prepared samplers.
    pub max_aggregate_retained_bytes: usize,
    /// Maximum bytes in one absolute URL passed to the HTTP core.
    pub max_url_bytes: usize,
    /// Maximum bytes in one origin-form path and query.
    pub max_path_query_bytes: usize,
    /// Maximum bytes in one bounded diagnostic category/message budget.
    pub max_diagnostic_bytes: usize,
    /// Maximum NodeIds retained in one source path.
    pub max_source_path_nodes: usize,
    /// Maximum bytes retained for one sampler name.
    pub max_sampler_name_bytes: usize,
}

impl Default for NativeV2RequestMapLimits {
    fn default() -> Self {
        Self {
            max_samplers: DEFAULT_MAX_SAMPLERS,
            max_aggregate_retained_bytes: DEFAULT_MAX_RETAINED_BYTES,
            max_url_bytes: MAX_URL_BYTES,
            max_path_query_bytes: MAX_PATH_QUERY_BYTES,
            max_diagnostic_bytes: MAX_ERROR_DIAGNOSTIC_BYTES,
            max_source_path_nodes: DEFAULT_MAX_SOURCE_PATH_NODES,
            max_sampler_name_bytes: DEFAULT_MAX_SAMPLER_NAME_BYTES,
        }
    }
}

impl NativeV2RequestMapLimits {
    fn validate(self) -> Result<(), NativeV2RequestPrepareError> {
        let invalid = [
            ("samplers", self.max_samplers, DEFAULT_MAX_SAMPLERS),
            (
                "aggregate-retained-bytes",
                self.max_aggregate_retained_bytes,
                DEFAULT_MAX_RETAINED_BYTES,
            ),
            ("url-bytes", self.max_url_bytes, MAX_URL_BYTES),
            (
                "path-query-bytes",
                self.max_path_query_bytes,
                MAX_PATH_QUERY_BYTES,
            ),
            (
                "diagnostic-bytes",
                self.max_diagnostic_bytes,
                MAX_ERROR_DIAGNOSTIC_BYTES.max(MAX_MAPPER_DIAGNOSTIC_CODE_BYTES),
            ),
            (
                "source-path-nodes",
                self.max_source_path_nodes,
                DEFAULT_MAX_SOURCE_PATH_NODES,
            ),
            (
                "sampler-name-bytes",
                self.max_sampler_name_bytes,
                DEFAULT_MAX_SAMPLER_NAME_BYTES,
            ),
        ];
        for (dimension, value, maximum) in invalid {
            if value == 0 || value > maximum {
                return Err(NativeV2RequestPrepareError::limit(
                    None,
                    &[],
                    dimension,
                    value,
                    maximum,
                ));
            }
        }
        if self.max_diagnostic_bytes < MAX_MAPPER_DIAGNOSTIC_CODE_BYTES {
            return Err(NativeV2RequestPrepareError::limit(
                None,
                &[],
                "diagnostic-bytes",
                self.max_diagnostic_bytes,
                MAX_MAPPER_DIAGNOSTIC_CODE_BYTES,
            ));
        }
        Ok(())
    }
}

/// Typed, redacted error returned while preparing a NativeV2 request map.
///
/// Source paths contain only bounded document-local NodeIds.  Request URLs,
/// names, query strings, property values, and lower-edge diagnostic text are
/// intentionally absent from this type and its formatting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeV2RequestPrepareError {
    /// A plan-level identity or invariant did not match the NativeV2 map.
    Plan {
        /// Stable redacted category.
        code: &'static str,
    },
    /// A node-level identity, request, or policy invariant failed.
    Node {
        /// Source document-local identity.
        node_id: NodeId,
        /// Bounded root-to-node source path.
        source_path: Vec<NodeId>,
        /// Stable redacted category.
        code: &'static str,
    },
    /// A finite map or source boundary was exceeded.
    Limit {
        /// Node involved, when the bound is node-specific.
        node_id: Option<NodeId>,
        /// Bounded source path, when available.
        source_path: Vec<NodeId>,
        /// Stable bounded dimension.
        dimension: &'static str,
        /// Checked observed count/bytes.
        observed: usize,
        /// Configured maximum.
        maximum: usize,
    },
}

impl NativeV2RequestPrepareError {
    fn node(node_id: NodeId, source_path: &[NodeId], code: &'static str) -> Self {
        Self::Node {
            node_id,
            source_path: bounded_path(source_path),
            code,
        }
    }

    fn limit(
        node_id: Option<NodeId>,
        source_path: &[NodeId],
        dimension: &'static str,
        observed: usize,
        maximum: usize,
    ) -> Self {
        Self::Limit {
            node_id,
            source_path: bounded_path(source_path),
            dimension,
            observed,
            maximum,
        }
    }

    /// Stable machine-readable preparation code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Plan { code } => code,
            Self::Node { code, .. } => code,
            Self::Limit { .. } => "app.native-http.request.limit",
        }
    }

    /// Returns the source node involved in the error, when available.
    #[must_use]
    pub const fn node_id(&self) -> Option<NodeId> {
        match self {
            Self::Plan { .. } => None,
            Self::Node { node_id, .. } => Some(*node_id),
            Self::Limit { node_id, .. } => *node_id,
        }
    }

    /// Returns the bounded source path attached to this error.
    #[must_use]
    pub fn source_path(&self) -> &[NodeId] {
        match self {
            Self::Plan { .. } => &[],
            Self::Node { source_path, .. } | Self::Limit { source_path, .. } => source_path,
        }
    }
}

impl fmt::Display for NativeV2RequestPrepareError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())?;
        match self {
            Self::Plan { .. } => Ok(()),
            Self::Node {
                node_id,
                source_path,
                ..
            } => write!(
                formatter,
                ": node={node_id}, source-depth={}",
                source_path.len()
            ),
            Self::Limit {
                node_id,
                source_path,
                dimension,
                observed,
                maximum,
            } => write!(
                formatter,
                ": node={node_id:?}, source-depth={}, {dimension}={observed}, maximum={maximum}",
                source_path.len()
            ),
        }
    }
}

impl std::error::Error for NativeV2RequestPrepareError {}

/// One immutable, source-identity-preserving NativeV2 sampler prepared for a
/// later central factory.
#[derive(Clone, Eq, PartialEq)]
pub struct PreparedNativeV2Sampler {
    node_id: NodeId,
    source_path: Vec<NodeId>,
    name: String,
    provider: NativeV2ProviderIdentity,
    request: Request,
    client_config: ClientConfig,
    transport_limits: NativeTransportLimits,
    operation_duration: Duration,
}

impl fmt::Debug for PreparedNativeV2Sampler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedNativeV2Sampler")
            .field("node_id", &self.node_id)
            .field("source_path", &self.source_path)
            .field("name_bytes", &self.name.len())
            .field("provider", &self.provider)
            .field("request_method", &self.request.method())
            .field("request_url_bytes", &self.request.url().as_str().len())
            .field(
                "request_authority_bytes",
                &self.request.url().authority().len(),
            )
            .field(
                "request_path_query_bytes",
                &self.request.url().path_and_query().len(),
            )
            .field("request_body_present", &self.request.body().is_present())
            .field("client_config", &self.client_config)
            .field("transport_limits", &self.transport_limits)
            .field("overall_operation_duration", &self.operation_duration)
            .finish()
    }
}

impl PreparedNativeV2Sampler {
    /// Returns the exact source NodeId.
    #[must_use]
    pub const fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Returns the exact bounded root-to-sampler source path.
    #[must_use]
    pub fn source_path(&self) -> &[NodeId] {
        &self.source_path
    }

    /// Returns the source element name exactly as compiled.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the source/executed provider pair.
    #[must_use]
    pub const fn provider(&self) -> &NativeV2ProviderIdentity {
        &self.provider
    }

    /// Returns the preserved JMeter source provider.
    #[must_use]
    pub const fn source_provider(&self) -> &NativeV2SourceProvider {
        &self.provider.source
    }

    /// Returns the independently selected executed provider identity.
    #[must_use]
    pub const fn executed_provider(&self) -> &'static str {
        self.provider.execution
    }

    /// Returns the typed request passed to the later semantic client.
    #[must_use]
    pub const fn request(&self) -> &Request {
        &self.request
    }

    /// Returns the explicit client policy passed to the later semantic
    /// client.  No transport/client owner is constructed here.
    #[must_use]
    pub const fn client_config(&self) -> &ClientConfig {
        &self.client_config
    }

    /// Returns the bounded native transport/parser limits.
    #[must_use]
    pub const fn transport_limits(&self) -> &NativeTransportLimits {
        &self.transport_limits
    }

    /// Returns the finite relative overall-operation duration recipe.
    ///
    /// The value is not an absolute deadline and was selected without reading
    /// a clock.  The later run transaction creates its one local deadline.
    #[must_use]
    pub const fn overall_operation_duration(&self) -> Duration {
        self.operation_duration
    }
}

/// Complete immutable NativeV2 request map, retained in source order.
#[derive(Clone, Eq, PartialEq)]
pub struct PreparedNativeV2RequestMap {
    provider: &'static str,
    requirements: NativeV2PlanRequirements,
    samplers: Vec<PreparedNativeV2Sampler>,
    transport_limits: NativeTransportLimits,
    overall_operation_duration: Duration,
    retained_bytes: usize,
}

impl fmt::Debug for PreparedNativeV2RequestMap {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedNativeV2RequestMap")
            .field("provider", &self.provider)
            .field("requirements", &self.requirements)
            .field("sampler_count", &self.samplers.len())
            .field("transport_limits", &self.transport_limits)
            .field(
                "overall_operation_duration",
                &self.overall_operation_duration,
            )
            .field("retained_bytes", &self.retained_bytes)
            .finish()
    }
}

impl PreparedNativeV2RequestMap {
    /// Returns the executed provider identity.
    #[must_use]
    pub const fn provider(&self) -> &'static str {
        self.provider
    }

    /// Returns whole-plan facts copied from the closed compiler.
    #[must_use]
    pub const fn requirements(&self) -> NativeV2PlanRequirements {
        self.requirements
    }

    /// Returns samplers in the exact source order supplied by the compiler.
    #[must_use]
    pub fn samplers(&self) -> &[PreparedNativeV2Sampler] {
        &self.samplers
    }

    /// Returns the prepared sampler for one exact source NodeId.
    #[must_use]
    pub fn sampler(&self, node_id: NodeId) -> Option<&PreparedNativeV2Sampler> {
        self.samplers
            .iter()
            .find(|sampler| sampler.node_id == node_id)
    }

    /// Returns the bounded limits used by every prepared sampler.
    #[must_use]
    pub const fn transport_limits(&self) -> &NativeTransportLimits {
        &self.transport_limits
    }

    /// Returns the largest finite operation-duration recipe in the map.
    #[must_use]
    pub const fn overall_operation_duration(&self) -> Duration {
        self.overall_operation_duration
    }

    /// Returns the checked aggregate bytes retained by this map's preparation
    /// records.
    #[must_use]
    pub const fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }
}

/// Pure NativeV2 request mapper with explicit finite bounds and transport
/// limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeV2RequestMapper {
    limits: NativeV2RequestMapLimits,
    transport_limits: NativeTransportLimits,
    timeout_policy: NativeV2TimeoutPolicy,
}

impl Default for NativeV2RequestMapper {
    fn default() -> Self {
        Self::new()
    }
}

impl NativeV2RequestMapper {
    /// Creates a mapper using the repository's bounded NativeV2 defaults.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            limits: NativeV2RequestMapLimits {
                max_samplers: DEFAULT_MAX_SAMPLERS,
                max_aggregate_retained_bytes: DEFAULT_MAX_RETAINED_BYTES,
                max_url_bytes: MAX_URL_BYTES,
                max_path_query_bytes: MAX_PATH_QUERY_BYTES,
                max_diagnostic_bytes: MAX_ERROR_DIAGNOSTIC_BYTES,
                max_source_path_nodes: DEFAULT_MAX_SOURCE_PATH_NODES,
                max_sampler_name_bytes: DEFAULT_MAX_SAMPLER_NAME_BYTES,
            },
            transport_limits: NativeTransportLimits {
                max_dns_addresses: 16,
                max_request_head_bytes: 256 * 1024,
                max_request_body_bytes: 16 * 1024 * 1024,
                max_request_total_bytes: 32 * 1024 * 1024,
                max_response_head_bytes: 256 * 1024,
                max_response_body_bytes: 32 * 1024 * 1024,
                max_response_total_bytes: 64 * 1024 * 1024,
                max_header_count: 128,
                max_header_name_bytes: 1024,
                max_header_value_bytes: 16 * 1024,
                max_header_aggregate_bytes: 256 * 1024,
                max_status_line_bytes: 4 * 1024,
                max_reason_bytes: 1024,
                max_line_bytes: jmeter_rs_http_native::DEFAULT_MAX_LINE_BYTES,
                max_informational_count: 8,
                max_informational_bytes: 64 * 1024,
                max_chunk_line_bytes: 2 * 1024,
                max_chunk_count: 1_000_000,
                max_chunk_extension_count: 32,
                max_chunk_extension_bytes_per_chunk: 2 * 1024,
                max_chunk_extension_aggregate_bytes: 16 * 1024,
                max_trailer_count: 64,
                max_trailer_name_bytes: 1024,
                max_trailer_value_bytes: 16 * 1024,
                max_trailer_aggregate_bytes: 64 * 1024,
                max_io_buffer_bytes: 16 * 1024,
            },
            timeout_policy: NativeV2TimeoutPolicy {
                overall: NATIVE_V2_PROVIDER_SAFETY_OVERALL_TIMEOUT,
                phase: NATIVE_V2_PROVIDER_SAFETY_PHASE_TIMEOUT,
            },
        }
    }

    /// Creates a mapper with explicit preparation limits and the native
    /// transport's checked defaults.
    #[must_use]
    pub const fn with_limits(limits: NativeV2RequestMapLimits) -> Self {
        Self {
            limits,
            ..Self::new()
        }
    }

    /// Creates a mapper with explicit preparation and transport limits.
    #[must_use]
    pub const fn with_transport_limits(
        limits: NativeV2RequestMapLimits,
        transport_limits: NativeTransportLimits,
    ) -> Self {
        Self {
            limits,
            transport_limits,
            timeout_policy: NativeV2TimeoutPolicy {
                overall: NATIVE_V2_PROVIDER_SAFETY_OVERALL_TIMEOUT,
                phase: NATIVE_V2_PROVIDER_SAFETY_PHASE_TIMEOUT,
            },
        }
    }

    /// Creates a mapper with an explicit bounded timeout recipe.
    #[must_use]
    pub const fn with_timeout_policy(timeout_policy: NativeV2TimeoutPolicy) -> Self {
        Self {
            timeout_policy,
            ..Self::new()
        }
    }

    /// Returns the preparation limits.
    #[must_use]
    pub const fn limits(self) -> NativeV2RequestMapLimits {
        self.limits
    }

    /// Returns the selected native transport limits.
    #[must_use]
    pub const fn native_transport_limits(self) -> NativeTransportLimits {
        self.transport_limits
    }

    /// Returns the explicit relative timeout recipe used by this mapper.
    #[must_use]
    pub const fn timeout_policy(self) -> NativeV2TimeoutPolicy {
        self.timeout_policy
    }

    /// Maps every compiled sampler atomically into a complete immutable map.
    pub fn prepare(
        self,
        plan: &CompiledNativeV2HttpPlan,
    ) -> Result<PreparedNativeV2RequestMap, NativeV2RequestPrepareError> {
        self.limits.validate()?;
        self.timeout_policy.validate()?;
        self.transport_limits
            .validate()
            .map_err(|_| NativeV2RequestPrepareError::Plan {
                code: "app.native-http.request.transport-limits",
            })?;
        validate_plan_identity(plan, self.limits.max_samplers)?;

        let mut seen = BTreeSet::new();
        let mut prepared = Vec::with_capacity(plan.samplers.len());
        let mut retained_bytes = 0usize;
        let mut maximum_operation_duration = self.timeout_policy.overall;
        let mut has_hostname = false;
        let mut has_https = false;

        for sampler in &plan.samplers {
            validate_node_identity(sampler, self.limits)?;
            if !seen.insert(sampler.node_id) {
                return Err(NativeV2RequestPrepareError::node(
                    sampler.node_id,
                    &sampler.path,
                    "app.native-http.request.duplicate-node",
                ));
            }
            let mapped = self.prepare_sampler(sampler)?;
            let node_retained = retained_bytes_for(&mapped)?;
            retained_bytes = retained_bytes.checked_add(node_retained).ok_or_else(|| {
                NativeV2RequestPrepareError::limit(
                    Some(mapped.node_id),
                    mapped.source_path(),
                    "aggregate-retained-bytes",
                    usize::MAX,
                    self.limits.max_aggregate_retained_bytes,
                )
            })?;
            if retained_bytes > self.limits.max_aggregate_retained_bytes {
                return Err(NativeV2RequestPrepareError::limit(
                    Some(mapped.node_id),
                    mapped.source_path(),
                    "aggregate-retained-bytes",
                    retained_bytes,
                    self.limits.max_aggregate_retained_bytes,
                ));
            }
            has_hostname |= !is_ip_literal(mapped.request.url().host());
            has_https |= mapped.request.url().scheme() == "https";
            maximum_operation_duration = maximum_operation_duration.max(mapped.operation_duration);
            prepared.push(mapped);
        }

        validate_plan_requirements(plan.requirements, prepared.len(), has_hostname, has_https)?;

        Ok(PreparedNativeV2RequestMap {
            provider: NATIVE_V2_REQUEST_CAPABILITY,
            requirements: plan.requirements,
            samplers: prepared,
            transport_limits: self.transport_limits,
            overall_operation_duration: maximum_operation_duration,
            retained_bytes,
        })
    }

    fn prepare_sampler(
        self,
        sampler: &NativeV2SamplerPlan,
    ) -> Result<PreparedNativeV2Sampler, NativeV2RequestPrepareError> {
        let node_id = sampler.node_id;
        let path = sampler.path.as_slice();
        let request_template = &sampler.request;

        if sampler.provider.execution != NATIVE_V2_REQUEST_CAPABILITY
            || sampler.requirements.capability != NATIVE_V2_REQUEST_CAPABILITY
        {
            return Err(NativeV2RequestPrepareError::node(
                node_id,
                path,
                "app.native-http.request.provider-mismatch",
            ));
        }
        if sampler.name.len() > self.limits.max_sampler_name_bytes
            || sampler.name.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
        {
            return Err(NativeV2RequestPrepareError::node(
                node_id,
                path,
                "app.native-http.request.name",
            ));
        }
        if request_template.protocol.value().contains("${")
            || request_template.host.value().contains("${")
            || request_template.path.value().contains("${")
        {
            return Err(NativeV2RequestPrepareError::node(
                node_id,
                path,
                "app.native-http.request.dynamic-field",
            ));
        }
        if !request_template
            .protocol
            .value()
            .eq_ignore_ascii_case("http")
            && !request_template
                .protocol
                .value()
                .eq_ignore_ascii_case("https")
        {
            return Err(NativeV2RequestPrepareError::node(
                node_id,
                path,
                "app.native-http.request.protocol",
            ));
        }
        if !matches!(
            request_template.method,
            Method::Get | Method::Head | Method::Delete | Method::Options
        ) {
            return Err(NativeV2RequestPrepareError::node(
                node_id,
                path,
                "app.native-http.request.method",
            ));
        }
        if request_template.content_encoding.value().is_empty()
            || !request_template
                .content_encoding
                .value()
                .eq_ignore_ascii_case("UTF-8")
        {
            return Err(NativeV2RequestPrepareError::node(
                node_id,
                path,
                "app.native-http.request.encoding",
            ));
        }
        if request_template.follow_redirects
            || request_template.auto_redirects
            || !request_template.use_keepalive
            || request_template.post_body_raw
            || request_template.multipart
            || request_template.concurrent_pool_explicit
            || request_template.concurrent_pool.is_some()
            || !request_template.arguments.is_empty()
        {
            return Err(NativeV2RequestPrepareError::node(
                node_id,
                path,
                "app.native-http.request.policy",
            ));
        }
        let url = build_url(request_template, self.limits)
            .map_err(|code| NativeV2RequestPrepareError::node(node_id, path, code))?;
        let (connect_timeout, response_timeout, operation_duration) =
            timeout_recipe(request_template, node_id, path, self.timeout_policy)?;
        let client_config = build_client_config(
            connect_timeout,
            response_timeout,
            operation_duration,
            self.transport_limits,
        )
        .map_err(|code| NativeV2RequestPrepareError::node(node_id, path, code))?;

        let request = Request::new(request_template.method.clone(), url);
        request
            .validate(
                self.transport_limits.max_request_body_bytes,
                self.transport_limits.max_header_count,
            )
            .map_err(|error| {
                NativeV2RequestPrepareError::node(
                    node_id,
                    path,
                    map_http_error_code(error.stable_code()),
                )
            })?;

        let actual_hostname = !is_ip_literal(request.url().host());
        let actual_https = request.url().scheme() == "https";
        if sampler.requirements.has_hostname != actual_hostname
            || sampler.requirements.has_https != actual_https
        {
            return Err(NativeV2RequestPrepareError::node(
                node_id,
                path,
                "app.native-http.request.requirements-mismatch",
            ));
        }

        Ok(PreparedNativeV2Sampler {
            node_id,
            source_path: path.to_vec(),
            name: sampler.name.clone(),
            provider: sampler.provider.clone(),
            request,
            client_config,
            transport_limits: self.transport_limits,
            operation_duration,
        })
    }
}

fn validate_plan_identity(
    plan: &CompiledNativeV2HttpPlan,
    maximum_samplers: usize,
) -> Result<(), NativeV2RequestPrepareError> {
    if plan.provider != NATIVE_V2_REQUEST_CAPABILITY {
        return Err(NativeV2RequestPrepareError::Plan {
            code: "app.native-http.request.plan-provider",
        });
    }
    if plan.samplers.len() > maximum_samplers {
        return Err(NativeV2RequestPrepareError::limit(
            None,
            &[],
            "samplers",
            plan.samplers.len(),
            maximum_samplers,
        ));
    }
    if plan.requirements.sampler_count != plan.samplers.len() {
        return Err(NativeV2RequestPrepareError::Plan {
            code: "app.native-http.request.sampler-count",
        });
    }
    if plan.requirements.has_http != !plan.samplers.is_empty() {
        return Err(NativeV2RequestPrepareError::Plan {
            code: "app.native-http.request.plan-requirements",
        });
    }
    Ok(())
}

fn validate_node_identity(
    sampler: &NativeV2SamplerPlan,
    limits: NativeV2RequestMapLimits,
) -> Result<(), NativeV2RequestPrepareError> {
    if !sampler.node_id.is_valid() || sampler.path.is_empty() {
        return Err(NativeV2RequestPrepareError::node(
            sampler.node_id,
            &sampler.path,
            "app.native-http.request.path",
        ));
    }
    if sampler.path.len() > limits.max_source_path_nodes {
        return Err(NativeV2RequestPrepareError::limit(
            Some(sampler.node_id),
            &sampler.path,
            "source-path-nodes",
            sampler.path.len(),
            limits.max_source_path_nodes,
        ));
    }
    if sampler.path.last().copied() != Some(sampler.node_id)
        || sampler.path.iter().any(|id| !id.is_valid())
        || sampler
            .path
            .iter()
            .enumerate()
            .any(|(index, id)| sampler.path[..index].contains(id))
    {
        return Err(NativeV2RequestPrepareError::node(
            sampler.node_id,
            &sampler.path,
            "app.native-http.request.path",
        ));
    }
    Ok(())
}

fn validate_plan_requirements(
    requirements: NativeV2PlanRequirements,
    sampler_count: usize,
    has_hostname: bool,
    has_https: bool,
) -> Result<(), NativeV2RequestPrepareError> {
    if requirements.sampler_count != sampler_count
        || requirements.has_http != (sampler_count != 0)
        || requirements.has_hostname != has_hostname
        || requirements.has_https != has_https
    {
        return Err(NativeV2RequestPrepareError::Plan {
            code: "app.native-http.request.plan-requirements",
        });
    }
    Ok(())
}

fn build_url(
    template: &crate::native_http_plan::NativeV2RequestTemplate,
    limits: NativeV2RequestMapLimits,
) -> Result<Url, &'static str> {
    let host = template.host.value();
    let path = template.path.value();
    if host.is_empty() {
        return Err("app.native-http.request.authority");
    }
    if path.is_empty() || path.len() > limits.max_path_query_bytes {
        return Err("app.native-http.request.path-limit");
    }
    if !path.starts_with('/') || path.contains('#') {
        return Err("app.native-http.request.path");
    }
    if path.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return Err("app.native-http.request.path");
    }
    if template.host.value().len() > limits.max_url_bytes
        || template.protocol.value().len() > limits.max_url_bytes
    {
        return Err("app.native-http.request.url-limit");
    }

    let authority_host = if host.starts_with('[') {
        host.to_owned()
    } else if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else if host.contains(':') {
        // A non-literal colon is not a DNS host.  Do not pass it to a
        // resolver or reinterpret it as a port.
        return Err("app.native-http.request.authority");
    } else {
        host.to_owned()
    };
    let authority = match template.port {
        NativeV2PortTemplate::Implicit | NativeV2PortTemplate::Literal(0) => authority_host,
        NativeV2PortTemplate::Literal(port) => format!("{authority_host}:{port}"),
    };
    let url_text = format!("{}://{}{}", template.protocol.value(), authority, path);
    if url_text.len() > limits.max_url_bytes {
        return Err("app.native-http.request.url-limit");
    }
    Url::parse(url_text).map_err(|_| "app.native-http.request.url")
}

fn timeout_recipe(
    template: &crate::native_http_plan::NativeV2RequestTemplate,
    node_id: NodeId,
    path: &[NodeId],
    timeout_policy: NativeV2TimeoutPolicy,
) -> Result<(Duration, Duration, Duration), NativeV2RequestPrepareError> {
    let connect = timeout_or_default(template.connect_timeout_ms, timeout_policy.phase);
    let response = timeout_or_default(template.response_timeout_ms, timeout_policy.phase);
    for duration in [connect, response] {
        if duration > MAX_NATIVE_V2_TIMEOUT {
            return Err(NativeV2RequestPrepareError::limit(
                Some(node_id),
                path,
                "timeout",
                duration.as_millis().try_into().unwrap_or(usize::MAX),
                MAX_NATIVE_V2_TIMEOUT
                    .as_millis()
                    .try_into()
                    .unwrap_or(usize::MAX),
            ));
        }
    }
    let operation = timeout_policy.overall.max(connect).max(response);
    if operation > MAX_NATIVE_V2_TIMEOUT {
        return Err(NativeV2RequestPrepareError::limit(
            Some(node_id),
            path,
            "overall-timeout",
            operation.as_millis().try_into().unwrap_or(usize::MAX),
            MAX_NATIVE_V2_TIMEOUT
                .as_millis()
                .try_into()
                .unwrap_or(usize::MAX),
        ));
    }
    Ok((connect, response, operation))
}

fn timeout_or_default(value: Option<u64>, default_phase: Duration) -> Duration {
    match value {
        Some(0) | None => default_phase,
        Some(value) => Duration::from_millis(value),
    }
}

fn build_client_config(
    connect: Duration,
    response: Duration,
    operation: Duration,
    limits: NativeTransportLimits,
) -> Result<ClientConfig, &'static str> {
    let config = ClientConfig {
        redirects: RedirectPolicy {
            follow: false,
            maximum: 0,
            allow_cross_origin: false,
            forward_authorization: false,
            maximum_retained_bytes: HARD_MAX_REDIRECT_RETAINED_BYTES,
        },
        proxy: ProxyPolicy {
            http: None,
            https: None,
            no_proxy: NoProxy::none(),
        },
        tls: TlsConfig {
            verification: TlsVerification::Verify,
            trust_source: TlsTrustSource::Explicit,
            minimum_version: TlsVersion::Tls1_2,
            maximum_version: TlsVersion::Tls1_3,
            extra_roots: Vec::new(),
            client_identity: None,
            use_sni: true,
        },
        http_version: HttpVersionPolicy::Http11Only,
        decompression: DecompressionPolicy::Disabled,
        retries: RetryPolicy {
            maximum_transparent_retries: 0,
            maximum_auth_challenges: 0,
        },
        timeouts: TimeoutConfig {
            overall: Some(operation),
            connect: Some(connect),
            write: Some(response),
            read: Some(response),
            tls: Some(connect),
        },
        limits: ClientLimits {
            max_request_body_bytes: limits.max_request_body_bytes,
            max_response_body_bytes: limits.max_response_body_bytes,
            max_header_fields: limits.max_header_count,
            max_header_bytes: limits.max_header_aggregate_bytes,
            session: SessionLimits {
                max_dns_entries: 256,
                max_cookies: 512,
                max_cache_entries: 5_000,
                max_cache_bytes: 64 * 1024 * 1024,
                max_auth_entries: 128,
                max_headers: 128,
            },
        },
        cookies_enabled: false,
        cache_enabled: false,
        auth_enabled: false,
        headers_enabled: false,
        retry_basic_challenge: false,
    };
    if connect > operation || response > operation {
        return Err("app.native-http.request.timeout-budget");
    }
    config
        .validate()
        .map_err(|_| "app.native-http.request.client-config")?;
    Ok(config)
}

fn retained_bytes_for(
    sampler: &PreparedNativeV2Sampler,
) -> Result<usize, NativeV2RequestPrepareError> {
    let path_bytes = sampler
        .source_path
        .len()
        .checked_mul(std::mem::size_of::<NodeId>())
        .ok_or_else(|| {
            NativeV2RequestPrepareError::limit(
                Some(sampler.node_id),
                sampler.source_path(),
                "retained-bytes",
                usize::MAX,
                usize::MAX,
            )
        })?;
    let request_bytes = sampler
        .request
        .url()
        .as_str()
        .len()
        .checked_add(sampler.name.len())
        .and_then(|value| value.checked_add(path_bytes))
        .and_then(|value| value.checked_add(PREPARED_REQUEST_OVERHEAD_BYTES))
        .and_then(|value| value.checked_add(std::mem::size_of::<Request>()))
        .and_then(|value| value.checked_add(std::mem::size_of::<ClientConfig>()))
        .and_then(|value| value.checked_add(std::mem::size_of::<NativeTransportLimits>()))
        .ok_or_else(|| {
            NativeV2RequestPrepareError::limit(
                Some(sampler.node_id),
                sampler.source_path(),
                "retained-bytes",
                usize::MAX,
                usize::MAX,
            )
        })?;
    Ok(request_bytes)
}

fn bounded_path(path: &[NodeId]) -> Vec<NodeId> {
    path.iter()
        .copied()
        .take(DEFAULT_MAX_SOURCE_PATH_NODES)
        .collect()
}

fn is_ip_literal(host: &str) -> bool {
    let candidate = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    candidate.parse::<IpAddr>().is_ok()
}

fn map_http_error_code(code: &'static str) -> &'static str {
    match code {
        "http.invalid-url" => "app.native-http.request.url",
        "http.invalid-method" => "app.native-http.request.method",
        "http.resource-limit"
        | "http.request-body-limit"
        | "http.response-body-limit"
        | "http.invalid-timeout" => "app.native-http.request.limit",
        _ => "app.native-http.request.http",
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::panic,
        clippy::unwrap_used,
        reason = "tests construct fixed semantic plans and assert explicit mapper outcomes"
    )]

    use super::*;
    use jmeter_rs_jmx::{SemanticPlan, SemanticRootMetadata, Span};
    use jmeter_rs_model::{ElementTree, PropertyValue, TestElement};

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

    fn sampler(domain: &str, protocol: &str, path: &str, method: &str) -> TestElement {
        sampler_named(domain, protocol, path, method, "sample")
    }

    fn sampler_named(
        domain: &str,
        protocol: &str,
        path: &str,
        method: &str,
        name: &str,
    ) -> TestElement {
        let mut sampler = TestElement::named("HTTPSamplerProxy", "HttpTestSampleGui", name);
        sampler.set_property("HTTPSampler.domain", PropertyValue::string(domain));
        sampler.set_property("HTTPSampler.protocol", PropertyValue::string(protocol));
        sampler.set_property("HTTPSampler.path", PropertyValue::string(path));
        sampler.set_property("HTTPSampler.method", PropertyValue::string(method));
        sampler.set_property(
            "HTTPSampler.follow_redirects",
            PropertyValue::boolean(false),
        );
        sampler
    }

    fn compile(sampler: TestElement) -> CompiledNativeV2HttpPlan {
        crate::native_http_plan::compile_native_v2_http_plan(&plan_with_sampler(sampler))
            .expect("closed NativeV2 plan")
    }

    fn prepare_native_v2_requests(
        plan: &CompiledNativeV2HttpPlan,
    ) -> Result<PreparedNativeV2RequestMap, NativeV2RequestPrepareError> {
        NativeV2RequestMapper::new().prepare(plan)
    }

    #[test]
    fn authority_preserves_hostname_ipv4_ipv6_and_default_or_explicit_ports() {
        let cases = [
            ("http", "example.test", None, "example.test", 80),
            ("https", "example.test", None, "example.test", 443),
            ("http", "127.0.0.1", Some("8080"), "127.0.0.1:8080", 8080),
            (
                "https",
                "2001:db8::1",
                Some("8443"),
                "[2001:db8::1]:8443",
                8443,
            ),
            ("http", "[2001:db8::2]", Some("0"), "[2001:db8::2]", 80),
        ];
        for (protocol, host, port, authority, expected_port) in cases {
            let mut source = sampler(host, protocol, "/a%20b?q=x%2Fy", "GET");
            if let Some(port) = port {
                source.set_property("HTTPSampler.port", PropertyValue::string(port));
            }
            let mapped = prepare_native_v2_requests(&compile(source)).expect("prepare");
            let request = mapped.samplers()[0].request();
            assert_eq!(request.url().authority(), authority);
            assert_eq!(request.url().port(), expected_port);
            assert_eq!(request.url().wire_target(), "/a%20b?q=x%2Fy");
            assert_eq!(
                request.url().host(),
                host.trim_start_matches('[').trim_end_matches(']')
            );
        }
    }

    #[test]
    fn all_closed_methods_have_an_absent_body() {
        for method in ["GET", "HEAD", "DELETE", "OPTIONS"] {
            let mapped =
                prepare_native_v2_requests(&compile(sampler("127.0.0.1", "http", "/", method)))
                    .expect("method prepare");
            let request = mapped.samplers()[0].request();
            assert_eq!(request.method().as_str(), method);
            assert!(!request.body().is_present());
        }
    }

    #[test]
    fn absent_zero_and_explicit_timeouts_are_finite_and_budgeted() {
        let absent = compile(sampler("127.0.0.1", "http", "/", "GET"));
        let absent = prepare_native_v2_requests(&absent).expect("absent timeout");
        assert_eq!(
            absent.samplers()[0].client_config().timeouts.connect,
            Some(NATIVE_V2_PROVIDER_SAFETY_PHASE_TIMEOUT)
        );
        assert_eq!(
            absent.samplers()[0].client_config().timeouts.overall,
            Some(NATIVE_V2_PROVIDER_SAFETY_OVERALL_TIMEOUT)
        );

        let mut zero_source = sampler("127.0.0.1", "http", "/", "GET");
        zero_source.set_property("HTTPSampler.connect_timeout", PropertyValue::string("0"));
        zero_source.set_property("HTTPSampler.response_timeout", PropertyValue::string("0"));
        let zero = prepare_native_v2_requests(&compile(zero_source)).expect("zero timeout");
        assert_eq!(
            zero.samplers()[0].client_config().timeouts.read,
            Some(NATIVE_V2_PROVIDER_SAFETY_PHASE_TIMEOUT)
        );

        let mut explicit_source = sampler("127.0.0.1", "http", "/", "GET");
        explicit_source.set_property("HTTPSampler.connect_timeout", PropertyValue::string("5000"));
        explicit_source.set_property(
            "HTTPSampler.response_timeout",
            PropertyValue::string("7000"),
        );
        let explicit = prepare_native_v2_requests(&compile(explicit_source)).expect("timeout");
        let config = explicit.samplers()[0].client_config();
        assert_eq!(config.timeouts.connect, Some(Duration::from_secs(5)));
        assert_eq!(config.timeouts.tls, Some(Duration::from_secs(5)));
        assert_eq!(config.timeouts.write, Some(Duration::from_secs(7)));
        assert_eq!(config.timeouts.read, Some(Duration::from_secs(7)));
        assert!(config.timeouts.connect <= config.timeouts.overall);
        assert!(config.timeouts.read <= config.timeouts.overall);
    }

    #[test]
    fn client_policy_disables_ambient_behaviors_explicitly() {
        let mapped =
            prepare_native_v2_requests(&compile(sampler("127.0.0.1", "https", "/", "GET")))
                .expect("policy prepare");
        let config = mapped.samplers()[0].client_config();
        assert!(!config.redirects.follow);
        assert_eq!(config.redirects.maximum, 0);
        assert!(config.proxy.http.is_none());
        assert!(config.proxy.https.is_none());
        assert!(matches!(
            config.decompression,
            DecompressionPolicy::Disabled
        ));
        assert_eq!(config.http_version, HttpVersionPolicy::Http11Only);
        assert_eq!(config.retries.maximum_transparent_retries, 0);
        assert_eq!(config.retries.maximum_auth_challenges, 0);
        assert!(!config.cookies_enabled);
        assert!(!config.cache_enabled);
        assert!(!config.auth_enabled);
        assert!(!config.headers_enabled);
        assert!(!config.retry_basic_challenge);
        assert_eq!(
            config.tls.trust_source,
            jmeter_rs_http::TlsTrustSource::Explicit
        );
        assert!(config.tls.extra_roots.is_empty());
        assert!(config.tls.use_sni);
    }

    #[test]
    fn source_and_executed_provider_identity_is_preserved() {
        let mut source = sampler("127.0.0.1", "http", "/", "GET");
        source.set_property("HTTPSampler.implementation", PropertyValue::string("Java"));
        let compiled = compile(source);
        let node_id = compiled.samplers[0].node_id;
        let source_path = compiled.samplers[0].path.clone();
        let mapped = prepare_native_v2_requests(&compiled).expect("identity prepare");
        assert_eq!(mapped.samplers()[0].node_id(), node_id);
        assert_eq!(mapped.samplers()[0].source_path(), source_path.as_slice());
        assert_eq!(mapped.samplers()[0].name(), "sample");
        assert_eq!(
            *mapped.samplers()[0].source_provider(),
            NativeV2SourceProvider::Java
        );
        assert_eq!(
            mapped.samplers()[0].executed_provider(),
            NATIVE_V2_REQUEST_CAPABILITY
        );
    }

    #[test]
    fn duplicate_identity_limit_and_invalid_node_are_atomic_and_redacted() {
        let plan = {
            let root = SemanticRootMetadata::new(
                "jmeterTestPlan",
                Vec::new(),
                Span::new(0, 0).expect("span"),
            );
            let mut tree = ElementTree::new();
            let root_id = tree
                .insert_root(TestElement::named("TestPlan", "TestPlanGui", "plan"))
                .expect("root");
            tree.insert(Some(root_id), sampler("127.0.0.1", "http", "/one", "GET"))
                .expect("first");
            tree.insert(Some(root_id), sampler("127.0.0.1", "http", "/two", "GET"))
                .expect("second");
            SemanticPlan::new(root, tree)
        };
        let mut compiled =
            crate::native_http_plan::compile_native_v2_http_plan(&plan).expect("two samplers");
        compiled.samplers[1].node_id = compiled.samplers[0].node_id;
        compiled.samplers[1].path = compiled.samplers[0].path.clone();
        let duplicate = prepare_native_v2_requests(&compiled).expect_err("duplicate");
        assert_eq!(duplicate.code(), "app.native-http.request.duplicate-node");

        let too_many = NativeV2RequestMapper::with_limits(NativeV2RequestMapLimits {
            max_samplers: 1,
            ..NativeV2RequestMapLimits::default()
        })
        .prepare(
            &crate::native_http_plan::compile_native_v2_http_plan(&plan).expect("two samplers"),
        )
        .expect_err("sampler limit");
        assert_eq!(too_many.code(), "app.native-http.request.limit");

        let mut invalid =
            crate::native_http_plan::compile_native_v2_http_plan(&plan).expect("two samplers");
        invalid.samplers[1].request.method = Method::Post;
        invalid.samplers[1].name = "secret-password".to_owned();
        let error = prepare_native_v2_requests(&invalid).expect_err("invalid second sampler");
        assert_eq!(error.node_id(), Some(invalid.samplers[1].node_id));
        assert!(!error.to_string().contains("secret-password"));
        assert!(!format!("{error:?}").contains("secret-password"));

        // Keep the source plan alive until all malformed compiled variants
        // have been checked; no mapper operation mutates it.
        let _ = plan.tree();
    }

    #[test]
    fn bounds_and_provider_or_path_identity_fail_before_a_public_map_exists() {
        let source = sampler("127.0.0.1", "http", "/bounded", "GET");
        let compiled = compile(source);
        let aggregate = NativeV2RequestMapper::with_limits(NativeV2RequestMapLimits {
            max_aggregate_retained_bytes: 1,
            ..NativeV2RequestMapLimits::default()
        })
        .prepare(&compiled)
        .expect_err("aggregate bound");
        assert_eq!(aggregate.code(), "app.native-http.request.limit");

        let path = NativeV2RequestMapper::with_limits(NativeV2RequestMapLimits {
            max_path_query_bytes: 2,
            ..NativeV2RequestMapLimits::default()
        })
        .prepare(&compiled)
        .expect_err("path bound");
        assert_eq!(path.code(), "app.native-http.request.path-limit");

        let url = NativeV2RequestMapper::with_limits(NativeV2RequestMapLimits {
            max_url_bytes: 8,
            ..NativeV2RequestMapLimits::default()
        })
        .prepare(&compiled)
        .expect_err("URL bound");
        assert_eq!(url.code(), "app.native-http.request.url-limit");

        let diagnostic = NativeV2RequestMapper::with_limits(NativeV2RequestMapLimits {
            max_diagnostic_bytes: 1,
            ..NativeV2RequestMapLimits::default()
        })
        .prepare(&compiled)
        .expect_err("diagnostic bound");
        assert_eq!(diagnostic.code(), "app.native-http.request.limit");

        let mut timeout = compiled.clone();
        timeout.samplers[0].request.connect_timeout_ms = Some(86_400_001);
        let timeout_error = NativeV2RequestMapper::new()
            .prepare(&timeout)
            .expect_err("timeout cap");
        assert_eq!(timeout_error.code(), "app.native-http.request.limit");

        let mut provider = compiled.clone();
        provider.samplers[0].provider.execution = "http.native/wrong";
        let provider_error = prepare_native_v2_requests(&provider).expect_err("provider");
        assert_eq!(
            provider_error.code(),
            "app.native-http.request.provider-mismatch"
        );

        let mut path_identity = compiled;
        path_identity.samplers[0].path.pop();
        let path_error = prepare_native_v2_requests(&path_identity).expect_err("path identity");
        assert_eq!(path_error.code(), "app.native-http.request.path");
    }

    #[test]
    fn timeout_policy_is_explicit_and_debug_is_metadata_only() {
        let policy = NativeV2TimeoutPolicy {
            overall: Duration::from_secs(9),
            phase: Duration::from_secs(2),
        };
        let mapper = NativeV2RequestMapper::with_timeout_policy(policy);
        assert_eq!(mapper.timeout_policy(), policy);
        let source = sampler_named(
            "example.test",
            "https",
            "/?secret=sentinel-query",
            "GET",
            "sentinel-name",
        );
        let mapped = mapper.prepare(&compile(source)).expect("explicit policy");
        assert_eq!(
            mapped.samplers()[0].client_config().timeouts.overall,
            Some(Duration::from_secs(9))
        );
        assert_eq!(
            mapped.samplers()[0].client_config().timeouts.connect,
            Some(Duration::from_secs(2))
        );
        let debug = format!("{:?}", mapped.samplers()[0]);
        assert!(!debug.contains("secret=sentinel-query"));
        assert!(!debug.contains("sentinel-name"));
        assert!(debug.contains("request_url_bytes"));
    }

    #[test]
    fn empty_compiled_projection_still_has_a_finite_recipe() {
        let root =
            SemanticRootMetadata::new("jmeterTestPlan", Vec::new(), Span::new(0, 0).expect("span"));
        let mut tree = ElementTree::new();
        tree.insert_root(TestElement::named("TestPlan", "TestPlanGui", "plan"))
            .expect("root");
        let plan = SemanticPlan::new(root, tree);
        let compiled =
            crate::native_http_plan::compile_native_v2_http_plan(&plan).expect("empty projection");
        let mapped = NativeV2RequestMapper::new()
            .prepare(&compiled)
            .expect("empty map");
        assert!(mapped.samplers().is_empty());
        assert_eq!(
            mapped.overall_operation_duration(),
            NATIVE_V2_PROVIDER_SAFETY_OVERALL_TIMEOUT
        );
    }
}
