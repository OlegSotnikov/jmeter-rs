// SPDX-License-Identifier: Apache-2.0
//! Bounded semantic-plan to native-controller compilation.
//!
//! This module is deliberately independent of the JMX crate.  A caller at the
//! application boundary can expose a [`SemanticSource`] over a JMX semantic
//! document, while the runtime only consumes the lossless model tree and an
//! opaque-element predicate.  The compiler builds one identity/path index and
//! uses that index for both lifecycle discovery and controller traversal.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

use jmeter_rs_model::{
    ElementProperty, ElementTree, ModelError, NodeId, PropertyValue, TestElement, ValidationLimits,
};

use crate::scope::capability_requires_external;
use crate::{
    ComponentCategory, ComponentRegistry, Digest32, GroupKind, GroupSchedule, ImplementationPath,
    ImplementationPathFamily, ImplementationPathIdentity, ImplementationPathManifest,
    InitialVariables, InitialVariablesError, LogicCondition, LogicControllerError, LogicLimits,
    LogicNode, LogicProgram, LoopCount, MAX_INITIAL_VARIABLES, PlanAdmission, PlanAdmissionError,
    ProfileIdentity, ProviderIdentity, RuntimeCapabilitySet, SampleErrorPolicy, SourceIdentity,
    SwitchSelection, ThroughputMode, UnavailableReason, UnavailableReasonCode, VersionedCapability,
};

const DEFAULT_MAX_NODES: usize = 100_000;
const DEFAULT_MAX_DEPTH: usize = 256;
const DEFAULT_MAX_PROPERTIES: usize = 500_000;
const DEFAULT_MAX_OPAQUE_BYTES: usize = 8 * 1024 * 1024;
const DEFAULT_MAX_STRING_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_MAX_GROUPS: usize = 1_024;
const DEFAULT_MAX_CHILDREN: usize = 65_536;
const DEFAULT_MAX_LOGIC_NODES: usize = 65_536;
const DEFAULT_MAX_TRANSITIONS: usize = 65_536;
const DEFAULT_MAX_THREADS: usize = 1_000_000;
// JMeter's Arguments map deduplicates only after reading the source list, so
// this source-entry guard must be greater than the canonical 64-entry seed
// bound.  It is independent of that canonical bound: duplicate source
// entries are valid input, but an unbounded source list must not drive parser
// allocations even when a caller supplies unusually wide model limits.
const MAX_INITIAL_VARIABLE_SOURCE_ENTRIES: usize = 65_536;
const MAX_DIAGNOSTIC_BYTES: usize = 4_096;

/// A source view supplied by a syntax/semantic boundary.
///
/// The runtime does not depend on JMX and therefore cannot name
/// `SemanticDocument` here.  The default opaque predicate is conservative for
/// directly constructed model trees; a JMX adapter should return `true` for
/// every retained opaque element.
pub trait PlanSourceView {
    /// Returns the ordered, identity-based semantic tree.
    fn tree(&self) -> &ElementTree;

    /// Returns whether a node is retained as an opaque/unknown source value.
    fn is_opaque(&self, _id: NodeId) -> bool {
        false
    }
}

impl PlanSourceView for ElementTree {
    fn tree(&self) -> &ElementTree {
        self
    }
}

/// A convenient source adapter for callers that already have an opaque-node
/// set but do not need a JMX-specific implementation.
#[derive(Clone, Copy, Debug)]
pub struct SemanticSource<'a> {
    tree: &'a ElementTree,
    opaque: Option<&'a BTreeSet<NodeId>>,
}

impl<'a> SemanticSource<'a> {
    /// Creates a source view with no opaque nodes.
    #[must_use]
    pub const fn new(tree: &'a ElementTree) -> Self {
        Self { tree, opaque: None }
    }

    /// Attaches a caller-owned set of opaque source identities.
    #[must_use]
    pub const fn with_opaque(mut self, opaque: &'a BTreeSet<NodeId>) -> Self {
        self.opaque = Some(opaque);
        self
    }
}

impl PlanSourceView for SemanticSource<'_> {
    fn tree(&self) -> &ElementTree {
        self.tree
    }

    fn is_opaque(&self, id: NodeId) -> bool {
        self.opaque.is_some_and(|opaque| opaque.contains(&id))
    }
}

/// A domain-qualified source identity.
///
/// Tree nodes retain their complete root-to-node identity path.  Embedded
/// properties, notably `ThreadGroup.main_controller`, retain the owning tree
/// path and their exact property path.  Names are never used as identity.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum SourceRef {
    /// An element in the ordered semantic tree.
    Tree {
        /// Root-to-node document-local identity path.
        path: Vec<NodeId>,
    },
    /// An embedded element property owned by a tree node.
    Embedded {
        /// Root-to-owner identity path.
        owner_path: Vec<NodeId>,
        /// Exact ordered property path inside the owner.
        property_path: Vec<String>,
    },
}

impl SourceRef {
    fn tree(path: Vec<NodeId>) -> Self {
        Self::Tree { path }
    }

    fn embedded(owner_path: Vec<NodeId>, property_path: Vec<String>) -> Self {
        Self::Embedded {
            owner_path,
            property_path,
        }
    }

    /// Returns the owning tree identity, when one exists.
    #[must_use]
    pub fn node_id(&self) -> Option<NodeId> {
        match self {
            Self::Tree { path }
            | Self::Embedded {
                owner_path: path, ..
            } => path.last().copied(),
        }
    }

    /// Returns the root-to-owner tree path.
    #[must_use]
    pub fn tree_path(&self) -> &[NodeId] {
        match self {
            Self::Tree { path }
            | Self::Embedded {
                owner_path: path, ..
            } => path,
        }
    }

    /// Returns the exact embedded property path, if this is an embedded
    /// source.
    #[must_use]
    pub fn property_path(&self) -> Option<&[String]> {
        match self {
            Self::Tree { .. } => None,
            Self::Embedded { property_path, .. } => Some(property_path),
        }
    }
}

/// Resource limits applied by the plan compiler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlanCompileLimits {
    /// Maximum number of semantic tree nodes indexed.
    pub max_nodes: usize,
    /// Maximum zero-based tree depth.
    pub max_depth: usize,
    /// Maximum persistent property values validated in the model.
    pub max_properties: usize,
    /// Maximum opaque/object payload bytes validated in the model.
    pub max_opaque_bytes: usize,
    /// Maximum aggregate model string bytes validated in the model.
    pub max_string_bytes: usize,
    /// Maximum enabled lifecycle groups.
    pub max_groups: usize,
    /// Maximum direct children in one source node.
    pub max_children: usize,
    /// Maximum nodes accepted by one native logic program.
    pub max_logic_nodes: usize,
    /// Maximum logic-program depth.
    pub max_logic_depth: usize,
    /// Maximum transitions allowed by one logic runner step budget.
    pub max_transitions: usize,
    /// Maximum virtual users in one group.
    pub max_threads: usize,
}

impl Default for PlanCompileLimits {
    fn default() -> Self {
        Self {
            max_nodes: DEFAULT_MAX_NODES,
            max_depth: DEFAULT_MAX_DEPTH,
            max_properties: DEFAULT_MAX_PROPERTIES,
            max_opaque_bytes: DEFAULT_MAX_OPAQUE_BYTES,
            max_string_bytes: DEFAULT_MAX_STRING_BYTES,
            max_groups: DEFAULT_MAX_GROUPS,
            max_children: DEFAULT_MAX_CHILDREN,
            max_logic_nodes: DEFAULT_MAX_LOGIC_NODES,
            max_logic_depth: DEFAULT_MAX_DEPTH,
            max_transitions: DEFAULT_MAX_TRANSITIONS,
            max_threads: DEFAULT_MAX_THREADS,
        }
    }
}

impl PlanCompileLimits {
    /// A small bounded policy suitable for deterministic unit tests.
    #[must_use]
    pub const fn small() -> Self {
        Self {
            max_nodes: 128,
            max_depth: 16,
            max_properties: 512,
            max_opaque_bytes: 64 * 1024,
            max_string_bytes: 256 * 1024,
            max_groups: 8,
            max_children: 64,
            max_logic_nodes: 128,
            max_logic_depth: 16,
            max_transitions: 256,
            max_threads: 32,
        }
    }

    fn model_limits(self) -> ValidationLimits {
        ValidationLimits {
            max_nodes: self.max_nodes,
            max_tree_depth: self.max_depth,
            max_properties: self.max_properties,
            max_property_depth: self.max_depth,
            max_opaque_bytes: self.max_opaque_bytes,
            max_string_bytes: self.max_string_bytes,
        }
    }

    fn logic_limits(self) -> LogicLimits {
        LogicLimits {
            max_nodes: self.max_logic_nodes,
            max_depth: self.max_logic_depth,
            max_transitions: self.max_transitions,
        }
    }
}

/// The resource dimension rejected by a plan compiler.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PlanLimitKind {
    /// Semantic tree nodes.
    Nodes,
    /// Tree depth.
    Depth,
    /// Direct children.
    Children,
    /// Lifecycle groups.
    Groups,
    /// Logic nodes.
    LogicNodes,
    /// Virtual users.
    Threads,
    /// TestPlan initial-variable seed entries or bytes.
    InitialVariables,
}

impl PlanLimitKind {
    /// Returns a stable diagnostic code suffix.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Nodes => "nodes",
            Self::Depth => "depth",
            Self::Children => "children",
            Self::Groups => "groups",
            Self::LogicNodes => "logic-nodes",
            Self::Threads => "threads",
            Self::InitialVariables => "initial-variables",
        }
    }
}

/// A typed plan compilation failure.
#[derive(Clone, Debug, PartialEq)]
pub enum PlanCompileError {
    /// The model tree is malformed or violates model resource limits.
    Tree {
        /// Bounded model detail.
        detail: String,
    },
    /// A compiler resource limit was exceeded.
    Limit {
        /// Rejected dimension.
        kind: PlanLimitKind,
        /// Observed bounded count.
        actual: usize,
        /// Configured limit.
        limit: usize,
        /// Source location, when available.
        source: Option<SourceRef>,
    },
    /// A required plan topology invariant is not satisfied.
    InvalidTopology {
        /// Source location, when available.
        source: Option<SourceRef>,
        /// Bounded explanation.
        detail: String,
    },
    /// An enabled opaque element cannot execute natively.
    UnsupportedOpaque {
        /// Opaque source identity.
        source: SourceRef,
        /// Exact source class.
        test_class: String,
    },
    /// An enabled class is not in the active exact-class registry.
    UnsupportedClass {
        /// Source identity.
        source: SourceRef,
        /// Exact source class.
        test_class: String,
    },
    /// A known class has a property whose behavior is not represented.
    UnsupportedProperty {
        /// Source identity.
        source: SourceRef,
        /// Exact source class.
        test_class: String,
        /// Exact persistent property name.
        property: String,
    },
    /// A known class/property value cannot be decoded safely.
    InvalidProperty {
        /// Source identity.
        source: SourceRef,
        /// Exact source class.
        test_class: String,
        /// Exact persistent property name.
        property: String,
        /// Bounded type/value detail.
        detail: String,
    },
    /// A recognized feature crosses an unsupported capability boundary.
    UnsupportedFeature {
        /// Source identity.
        source: SourceRef,
        /// Stable capability identifier.
        capability_id: String,
        /// Bounded explanation.
        detail: String,
    },
    /// A source ID cannot be converted into a unique runtime identity.
    IdentityExhausted {
        /// Source identity that required allocation.
        source: SourceRef,
    },
    /// The pinned path-manifest identity or context is invalid.
    PathManifest {
        /// Bounded identity/manifest detail.
        detail: String,
    },
    /// Existing native logic compilation rejected the generated AST.
    Logic {
        /// Native logic error.
        source: LogicControllerError,
    },
}

impl PlanCompileError {
    /// Returns a stable machine-readable diagnostic code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Tree { .. } => "runtime.plan.invalid-tree",
            Self::Limit { kind, .. } => match kind {
                PlanLimitKind::Nodes => "runtime.plan.limit-nodes",
                PlanLimitKind::Depth => "runtime.plan.limit-depth",
                PlanLimitKind::Children => "runtime.plan.limit-children",
                PlanLimitKind::Groups => "runtime.plan.limit-groups",
                PlanLimitKind::LogicNodes => "runtime.plan.limit-logic-nodes",
                PlanLimitKind::Threads => "runtime.plan.limit-threads",
                PlanLimitKind::InitialVariables => "runtime.plan.limit-initial-variables",
            },
            Self::InvalidTopology { .. } => "runtime.plan.invalid-topology",
            Self::UnsupportedOpaque { .. } => "runtime.plan.unsupported-opaque",
            Self::UnsupportedClass { .. } => "runtime.plan.unsupported-class",
            Self::UnsupportedProperty { .. } => "runtime.plan.unsupported-property",
            Self::InvalidProperty { .. } => "runtime.plan.invalid-property",
            Self::UnsupportedFeature { .. } => "runtime.plan.unsupported-feature",
            Self::IdentityExhausted { .. } => "runtime.plan.identity-exhausted",
            Self::PathManifest { .. } => "runtime.plan.invalid-path-manifest",
            Self::Logic { source } => source.code(),
        }
    }
}

impl fmt::Display for PlanCompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tree { detail } => write!(formatter, "{}: {detail}", self.code()),
            Self::Limit {
                kind,
                actual,
                limit,
                source,
            } => write!(
                formatter,
                "{} ({}: {} actual, {} limit, source {:?})",
                self.code(),
                kind.code(),
                actual,
                limit,
                source
            ),
            Self::InvalidTopology { source, detail } => {
                write!(formatter, "{} at {source:?}: {detail}", self.code())
            }
            Self::UnsupportedOpaque { source, test_class } => write!(
                formatter,
                "{} at {source:?}: opaque class {test_class:?}",
                self.code()
            ),
            Self::UnsupportedClass { source, test_class } => write!(
                formatter,
                "{} at {source:?}: class {test_class:?}",
                self.code()
            ),
            Self::UnsupportedProperty {
                source,
                test_class,
                property,
            } => write!(
                formatter,
                "{} at {source:?}: {test_class:?}.{property}",
                self.code()
            ),
            Self::InvalidProperty {
                source,
                test_class,
                property,
                detail,
            } => write!(
                formatter,
                "{} at {source:?}: {test_class:?}.{property}: {detail}",
                self.code()
            ),
            Self::UnsupportedFeature {
                source,
                capability_id,
                detail,
            } => write!(
                formatter,
                "{} at {source:?}: {capability_id}: {detail}",
                self.code()
            ),
            Self::IdentityExhausted { source } => {
                write!(formatter, "{} at {source:?}", self.code())
            }
            Self::PathManifest { detail } => write!(formatter, "{}: {detail}", self.code()),
            Self::Logic { source } => write!(formatter, "{}: {source}", self.code()),
        }
    }
}

impl std::error::Error for PlanCompileError {}

/// A source-node classification in the shared bounded index.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum IndexedCategory {
    /// Test Plan root.
    TestPlan,
    /// Setup, main, or teardown thread group.
    ThreadGroup(GroupKind),
    /// Native logic controller.
    Controller,
    /// Module or Include replacement controller.
    Replaceable,
    /// A sampler recognized by the component registry.
    Sampler,
    /// A scope component recognized by the component registry.
    Scope(ComponentCategory),
    /// A known non-executable source element such as WorkBench.
    Ignored,
    /// Explicitly recognized but unavailable open-model lifecycle group.
    OpenModel,
    /// No exact active registry entry exists.
    Unknown,
}

/// One indexed source node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexedNode {
    /// Document-local identity.
    pub id: NodeId,
    /// Domain-qualified source identity.
    pub source: SourceRef,
    /// Parent identity.
    pub parent: Option<NodeId>,
    /// Children in source order.
    pub children: Vec<NodeId>,
    /// Zero-based source depth.
    pub depth: usize,
    /// Exact source class.
    pub test_class: String,
    /// Exact source display name.
    pub name: String,
    /// Whether the source node itself was enabled.
    pub source_enabled: bool,
    /// Whether the node remains executable after disabled-ancestor removal.
    pub effective_enabled: bool,
    /// Whether the node remains an executable path after preservation-only
    /// ancestor removal.
    pub executable: bool,
    /// Group owner, including the group itself.
    pub group_id: Option<NodeId>,
    /// Exact registry classification.
    pub category: IndexedCategory,
}

/// The single bounded identity/path index used by compilation phases.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanIndex {
    roots: Vec<NodeId>,
    preorder: Vec<NodeId>,
    executable_preorder: Vec<NodeId>,
    nodes: BTreeMap<NodeId, IndexedNode>,
    disabled: BTreeSet<NodeId>,
}

impl PlanIndex {
    /// Returns root identities in source order.
    #[must_use]
    pub fn roots(&self) -> &[NodeId] {
        &self.roots
    }

    /// Returns all identities in bounded source preorder.
    #[must_use]
    pub fn preorder(&self) -> &[NodeId] {
        &self.preorder
    }

    /// Returns executable identities in source preorder.
    #[must_use]
    pub fn executable_preorder(&self) -> &[NodeId] {
        &self.executable_preorder
    }

    /// Returns the number of executable source identities accounted for by
    /// this index.
    #[must_use]
    pub fn executable_len(&self) -> usize {
        self.executable_preorder.len()
    }

    /// Returns an executable source node by identity.
    #[must_use]
    pub fn executable_node(&self, id: NodeId) -> Option<&IndexedNode> {
        self.node(id).filter(|node| node.executable)
    }

    /// Returns an indexed source node.
    #[must_use]
    pub fn node(&self, id: NodeId) -> Option<&IndexedNode> {
        self.nodes.get(&id)
    }

    /// Returns source IDs removed from the executable tree by disabled state.
    #[must_use]
    pub fn disabled_ids(&self) -> &BTreeSet<NodeId> {
        &self.disabled
    }

    /// Returns the number of indexed nodes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Returns whether the index has no nodes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

/// Pinned identity inputs for standalone whole-plan path preflight.
///
/// The compiler deliberately does not derive or hash these values. They are
/// supplied by the application/profile owner from canonical manifests and
/// copied into every path identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanPathContext {
    /// Exact compatibility profile identity.
    pub profile: ProfileIdentity,
    /// Digest of the complete executable plan.
    pub plan_digest: Digest32,
    /// Provider/driver/built-in implementation identity.
    pub provider: ProviderIdentity,
    /// Digest of the negotiated runtime capability set.
    pub capability_set_digest: Digest32,
}

impl PlanPathContext {
    /// Creates and validates pinned path identity inputs.
    pub fn new(
        profile: ProfileIdentity,
        plan_digest: Digest32,
        provider: ProviderIdentity,
        capability_set_digest: Digest32,
    ) -> Result<Self, PlanCompileError> {
        profile.validate().map_err(path_identity_error)?;
        provider.validate().map_err(path_identity_error)?;
        if plan_digest.is_zero() {
            return Err(PlanCompileError::PathManifest {
                detail: "plan digest must be present and non-zero".to_owned(),
            });
        }
        if capability_set_digest.is_zero() {
            return Err(PlanCompileError::PathManifest {
                detail: "capability-set digest must be present and non-zero".to_owned(),
            });
        }
        Ok(Self {
            profile,
            plan_digest,
            provider,
            capability_set_digest,
        })
    }
}

impl Digest32 {
    /// Hashes one bounded in-memory canonical value with SHA-256.
    ///
    /// The implementation is kept in this pure runtime crate so profile and
    /// plan identity construction does not acquire filesystem, process,
    /// network, or executor dependencies. It is the FIPS 180-4 SHA-256
    /// construction, not a routing hash or an approximation.
    #[must_use]
    pub fn sha256(value: &[u8]) -> Self {
        Self::from_bytes(sha256_bytes(value))
    }
}

/// Deterministic whole-plan implementation-path output.
///
/// Entries are sorted by [`SourceIdentity`] by the capability manifest
/// constructor. Disabled and preservation-only branches are absent. Enabled
/// opaque nodes are retained in [`Self::opaque_sources`] but intentionally do
/// not receive an executable path, as required by Decision 0009.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanPathManifest {
    context: PlanPathContext,
    paths: ImplementationPathManifest,
    opaque_sources: Vec<SourceRef>,
}

impl PlanPathManifest {
    /// Returns the complete pinned identity context used for every path.
    #[must_use]
    pub const fn context(&self) -> &PlanPathContext {
        &self.context
    }

    /// Returns the pinned profile identity copied into every path.
    #[must_use]
    pub fn profile(&self) -> &ProfileIdentity {
        &self.context.profile
    }

    /// Returns the executable-plan digest copied into every path.
    #[must_use]
    pub const fn plan_digest(&self) -> Digest32 {
        self.context.plan_digest
    }

    /// Returns the capability-set digest copied into every path.
    #[must_use]
    pub const fn capability_set_digest(&self) -> Digest32 {
        self.context.capability_set_digest
    }

    /// Returns the deterministic ordered implementation-path manifest.
    #[must_use]
    pub const fn paths(&self) -> &ImplementationPathManifest {
        &self.paths
    }

    /// Returns ordered path identities, as a convenience for admission APIs.
    #[must_use]
    pub fn entries(&self) -> &[ImplementationPathIdentity] {
        self.paths.entries()
    }

    /// Returns enabled opaque source identities that were deliberately not
    /// assigned an executable path.
    #[must_use]
    pub fn opaque_sources(&self) -> &[SourceRef] {
        &self.opaque_sources
    }

    /// Returns the number of executable path identities.
    #[must_use]
    pub fn len(&self) -> usize {
        self.paths.len()
    }

    /// Returns whether no executable path identities were emitted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    /// Performs atomic admission against one explicitly selected capability
    /// set. No setup, I/O, process, JVM, or listener operation is reachable
    /// from this pure method.
    pub fn admit(
        &self,
        capabilities: &RuntimeCapabilitySet,
    ) -> Result<PlanAdmission, PlanAdmissionError> {
        capabilities.classify(self.entries().iter().cloned())
    }
}

/// One immutable lifecycle/controller compilation result.
#[derive(Clone, Debug)]
pub struct CompiledPlanDraft {
    /// Shared source index used by all groups and scope consumers.
    pub index: PlanIndex,
    /// Enabled setup/main/teardown groups in source order.
    pub groups: Vec<CompiledThreadGroupDraft>,
    /// Deterministic TestPlan user-defined variables copied into each virtual
    /// user before configuration and preprocessor phases.
    pub initial_variables: BTreeMap<String, String>,
    /// Test Plan serialization policy.
    pub serialize_thread_groups: bool,
    /// Test Plan teardown-on-shutdown policy.
    pub teardown_on_shutdown: bool,
}

impl CompiledPlanDraft {
    /// Returns the deterministic TestPlan variable seed for each virtual user.
    #[must_use]
    pub fn initial_variables(&self) -> &BTreeMap<String, String> {
        &self.initial_variables
    }

    /// Validates and returns the immutable runtime seed used by
    /// [`crate::EnginePlan`].  The draft retains its historical ordered map
    /// field for source compatibility; this typed seam applies the explicit
    /// JMeter `Arguments` projection policy before execution.
    pub fn initial_variables_typed(&self) -> Result<InitialVariables, InitialVariablesError> {
        InitialVariables::try_from_jmeter_arguments(
            self.initial_variables
                .iter()
                .map(|(name, value)| (name.clone(), value.clone())),
        )
    }

    /// Applies this draft's validated initial-variable seed to an executable
    /// engine plan before admission.  The complete JMeter projection is
    /// validated before mutating its existing seed.
    pub fn apply_initial_variables(
        &self,
        plan: &mut crate::EnginePlan,
    ) -> Result<(), InitialVariablesError> {
        let initial = self.initial_variables_typed()?;
        plan.set_initial_variables(initial);
        Ok(())
    }
}

/// A lifecycle group draft awaiting package assembly and lifecycle API wiring.
#[derive(Clone, Debug)]
pub struct CompiledThreadGroupDraft {
    /// Group identity.
    pub id: NodeId,
    /// Exact group name.
    pub name: String,
    /// Setup/main/teardown phase.
    pub kind: GroupKind,
    /// Number of virtual users.
    pub threads: usize,
    /// Representable delay/ramp/duration schedule.
    pub schedule: GroupSchedule,
    /// Error policy after a failed sample.
    pub on_sample_error: SampleErrorPolicy,
    /// Whether user context is retained between root iterations.
    pub same_user_on_next_iteration: bool,
    /// Root controller program.  The embedded `main_controller` is the root
    /// node, so its identity and loop count remain in the AST.
    pub controller: LogicProgram,
    /// Domain-qualified identity of the embedded root controller.
    pub root_controller: SourceRef,
    /// Checked synthetic runtime ID assigned to the embedded root controller.
    pub root_runtime_id: u64,
    /// Source group path.
    pub source_path: Vec<NodeId>,
}

/// The bounded JMX-independent controller/lifecycle compiler.
#[derive(Clone, Debug)]
pub struct PlanCompiler {
    registry: ComponentRegistry,
    limits: PlanCompileLimits,
}

impl PlanCompiler {
    /// Creates a compiler with an exact-class registry and explicit bounds.
    #[must_use]
    pub fn new(registry: ComponentRegistry, limits: PlanCompileLimits) -> Self {
        Self { registry, limits }
    }

    /// Creates a compiler using the built-in profile vocabulary.
    #[must_use]
    pub fn builtins() -> Self {
        Self::new(ComponentRegistry::builtins(), PlanCompileLimits::default())
    }

    /// Returns the exact-class registry.
    #[must_use]
    pub fn registry(&self) -> &ComponentRegistry {
        &self.registry
    }

    /// Returns compiler bounds.
    #[must_use]
    pub const fn limits(&self) -> PlanCompileLimits {
        self.limits
    }

    /// Compiles a model tree with no opaque source identities.
    pub fn compile_tree(&self, tree: &ElementTree) -> Result<CompiledPlanDraft, PlanCompileError> {
        self.compile(tree)
    }

    /// Performs pure, whole-plan implementation-path preflight.
    ///
    /// This operation builds the same bounded identity index as native
    /// compilation, but does not reject external, unknown, or unresolved
    /// executable nodes. Instead it assigns each such node one explicit JVM,
    /// RMI, or unavailable path so the application can perform atomic
    /// capability admission before any setup or observable side effect.
    pub fn preflight_paths(
        &self,
        source: &dyn PlanSourceView,
        context: &PlanPathContext,
    ) -> Result<PlanPathManifest, PlanCompileError> {
        validate_path_context(context)?;
        let index = self.build_index(source)?;
        self.validate_path_topology(source, &index)?;
        let mut identities = Vec::new();
        let mut opaque_sources = Vec::new();

        for id in index.preorder() {
            let node = index.node(*id).ok_or_else(|| PlanCompileError::Tree {
                detail: format!("index lost source node {id}"),
            })?;
            if !node.effective_enabled {
                continue;
            }
            let element = source.tree().value(node.id).map_err(model_tree_error)?;
            if !is_preservation_only(&index, node)
                && (source.is_opaque(node.id) || !element.opaque_extensions.is_empty())
            {
                opaque_sources.push(node.source.clone());
            }
        }

        for id in index.executable_preorder() {
            let node = index.node(*id).ok_or_else(|| PlanCompileError::Tree {
                detail: format!("index lost executable source node {id}"),
            })?;
            let path = self.path_for_node(node)?;
            identities.push(self.path_identity(context, SourceIdentity::node(node.id), path)?);
        }

        let mut callback_ordinal = 0_u32;
        for id in index.executable_preorder() {
            let group = index.node(*id).ok_or_else(|| PlanCompileError::Tree {
                detail: format!("index lost executable source node {id}"),
            })?;
            let IndexedCategory::ThreadGroup(kind) = group.category else {
                continue;
            };
            let element = source.tree().value(group.id).map_err(model_tree_error)?;
            let root_value = element
                .property("ThreadGroup.main_controller")
                .ok_or_else(|| PlanCompileError::InvalidTopology {
                    source: Some(group.source.clone()),
                    detail: "ThreadGroup.main_controller is required".to_owned(),
                })?;
            let root_element = root_value.as_element().map_err(|error| {
                invalid_property(
                    &group.source,
                    &group.test_class,
                    "ThreadGroup.main_controller",
                    error.to_string(),
                )
            })?;
            let root_source = embedded_source(group, "ThreadGroup.main_controller");
            let root_class = root_element.class_name.as_deref().ok_or_else(|| {
                PlanCompileError::InvalidProperty {
                    source: root_source.clone(),
                    test_class: bounded(&group.test_class),
                    property: "ThreadGroup.main_controller".to_owned(),
                    detail: "embedded controller has no elementType/testclass".to_owned(),
                }
            })?;
            let path = if root_element.opaque_extensions.is_empty() {
                self.path_for_class(&root_source, root_class, IndexedCategory::Controller)?
            } else {
                opaque_sources.push(root_source);
                continue;
            };
            let callback = match kind {
                GroupKind::Setup => "setup",
                GroupKind::Main => "main",
                GroupKind::Teardown => "teardown",
            };
            let source_identity = SourceIdentity::run_level(callback_ordinal, callback)
                .map_err(path_identity_error)?;
            identities.push(self.path_identity(context, source_identity, path)?);
            callback_ordinal = callback_ordinal.checked_add(1).ok_or_else(|| {
                PlanCompileError::IdentityExhausted {
                    source: group.source.clone(),
                }
            })?;
        }

        let paths = ImplementationPathManifest::new(identities).map_err(path_manifest_error)?;
        Ok(PlanPathManifest {
            context: context.clone(),
            paths,
            opaque_sources,
        })
    }

    fn validate_path_topology(
        &self,
        source: &dyn PlanSourceView,
        index: &PlanIndex,
    ) -> Result<(), PlanCompileError> {
        let enabled_test_plans = index
            .roots()
            .iter()
            .filter_map(|id| index.node(*id))
            .filter(|node| {
                node.effective_enabled && matches!(node.category, IndexedCategory::TestPlan)
            })
            .collect::<Vec<_>>();
        if enabled_test_plans.is_empty() {
            if index
                .roots()
                .iter()
                .all(|id| index.node(*id).is_some_and(|node| !node.effective_enabled))
            {
                return Ok(());
            }
            return Err(PlanCompileError::InvalidTopology {
                source: None,
                detail: "an enabled plan must have one TestPlan root".to_owned(),
            });
        }
        if enabled_test_plans.len() != 1 {
            return Err(PlanCompileError::InvalidTopology {
                source: Some(enabled_test_plans[0].source.clone()),
                detail: "multiple enabled TestPlan roots are not executable".to_owned(),
            });
        }
        let test_plan = enabled_test_plans[0];
        let test_plan_element = source
            .tree()
            .value(test_plan.id)
            .map_err(model_tree_error)?;
        validate_test_plan_properties(&test_plan.source, test_plan_element)?;
        let _ = parse_initial_variables(&test_plan.source, test_plan_element)?;
        for child_id in &test_plan.children {
            let child = index
                .node(*child_id)
                .ok_or_else(|| PlanCompileError::Tree {
                    detail: format!("index lost TestPlan child {child_id}"),
                })?;
            if !child.effective_enabled {
                continue;
            }
            let child_element = source.tree().value(child.id).map_err(model_tree_error)?;
            if source.is_opaque(child.id) || !child_element.opaque_extensions.is_empty() {
                continue;
            }
            match child.category {
                IndexedCategory::Ignored => {}
                IndexedCategory::Scope(_) => {
                    if has_executable_child(index, child) {
                        return Err(PlanCompileError::InvalidTopology {
                            source: Some(child.source.clone()),
                            detail: "scope components must not own executable descendants"
                                .to_owned(),
                        });
                    }
                }
                IndexedCategory::ThreadGroup(_) => {
                    let group_element = source.tree().value(child.id).map_err(model_tree_error)?;
                    self.validate_path_group_properties(child, group_element)?;
                    self.validate_path_branch(index, &child.children)?;
                }
                IndexedCategory::OpenModel
                | IndexedCategory::Unknown
                | IndexedCategory::Replaceable => {
                    // Path preflight retains an explicit unavailable path for
                    // unresolved/open-model sources. Native compilation still
                    // rejects these classes before producing a draft.
                }
                _ => {
                    return Err(PlanCompileError::InvalidTopology {
                        source: Some(child.source.clone()),
                        detail: "only lifecycle groups may be direct executable TestPlan children"
                            .to_owned(),
                    });
                }
            }
        }
        Ok(())
    }

    fn validate_path_group_properties(
        &self,
        group: &IndexedNode,
        element: &TestElement,
    ) -> Result<(), PlanCompileError> {
        ensure_allowed_properties(
            &group.source,
            element,
            &group.test_class,
            &[
                "ThreadGroup.on_sample_error",
                "ThreadGroup.main_controller",
                "ThreadGroup.num_threads",
                "ThreadGroup.ramp_time",
                "ThreadGroup.delayedStart",
                "ThreadGroup.start_time",
                "ThreadGroup.end_time",
                "ThreadGroup.scheduler",
                "ThreadGroup.duration",
                "ThreadGroup.delay",
                "ThreadGroup.same_user_on_next_iteration",
            ],
        )?;
        let threads = usize_property(
            &group.source,
            &group.test_class,
            element,
            "ThreadGroup.num_threads",
            0,
        )?;
        if threads > i32::MAX as usize {
            return Err(invalid_property(
                &group.source,
                &group.test_class,
                "ThreadGroup.num_threads",
                "value exceeds JMeter's signed 32-bit property range",
            ));
        }
        if threads > self.limits.max_threads {
            return Err(PlanCompileError::Limit {
                kind: PlanLimitKind::Threads,
                actual: threads,
                limit: self.limits.max_threads,
                source: Some(group.source.clone()),
            });
        }
        let _ = self.group_schedule(&group.source, &group.test_class, element)?;
        let _ = sample_error_policy(
            &group.source,
            &group.test_class,
            element,
            "ThreadGroup.on_sample_error",
        )?;
        let _ = bool_property(
            &group.source,
            &group.test_class,
            element,
            "ThreadGroup.same_user_on_next_iteration",
            true,
        )?;
        let root_value = element
            .property("ThreadGroup.main_controller")
            .ok_or_else(|| PlanCompileError::InvalidTopology {
                source: Some(group.source.clone()),
                detail: "ThreadGroup.main_controller is required".to_owned(),
            })?;
        let root_element = root_value.as_element().map_err(|error| {
            invalid_property(
                &group.source,
                &group.test_class,
                "ThreadGroup.main_controller",
                error.to_string(),
            )
        })?;
        if root_element.opaque_extensions.is_empty() && root_element.class_name.as_deref().is_none()
        {
            return Err(PlanCompileError::InvalidProperty {
                source: embedded_source(group, "ThreadGroup.main_controller"),
                test_class: bounded(&group.test_class),
                property: "ThreadGroup.main_controller".to_owned(),
                detail: "embedded controller has no elementType/testclass".to_owned(),
            });
        }
        Ok(())
    }

    fn validate_path_branch(
        &self,
        index: &PlanIndex,
        child_ids: &[NodeId],
    ) -> Result<(), PlanCompileError> {
        let mut stack = child_ids.to_vec();
        while let Some(id) = stack.pop() {
            let child = index.node(id).ok_or_else(|| PlanCompileError::Tree {
                detail: format!("index lost executable branch node {id}"),
            })?;
            if !child.effective_enabled || !child.executable {
                continue;
            }
            match child.category {
                IndexedCategory::Controller => stack.extend(child.children.iter().copied()),
                IndexedCategory::Sampler => self.validate_sampler_children(index, child)?,
                IndexedCategory::Scope(_) => {
                    if has_executable_child(index, child) {
                        return Err(PlanCompileError::InvalidTopology {
                            source: Some(child.source.clone()),
                            detail: "scope components must not own executable descendants"
                                .to_owned(),
                        });
                    }
                }
                IndexedCategory::Ignored => {}
                IndexedCategory::Replaceable
                | IndexedCategory::Unknown
                | IndexedCategory::OpenModel => {}
                IndexedCategory::ThreadGroup(_) | IndexedCategory::TestPlan => {
                    return Err(PlanCompileError::InvalidTopology {
                        source: Some(child.source.clone()),
                        detail: "nested lifecycle/TestPlan elements are not controller children"
                            .to_owned(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Alias for callers that name path compilation rather than preflight.
    pub fn compile_path_manifest(
        &self,
        source: &dyn PlanSourceView,
        context: &PlanPathContext,
    ) -> Result<PlanPathManifest, PlanCompileError> {
        self.preflight_paths(source, context)
    }

    fn path_identity(
        &self,
        context: &PlanPathContext,
        source: SourceIdentity,
        path: ImplementationPath,
    ) -> Result<ImplementationPathIdentity, PlanCompileError> {
        ImplementationPathIdentity::new(
            context.profile.clone(),
            context.plan_digest,
            source,
            context.provider.clone(),
            context.capability_set_digest,
            path,
        )
        .map_err(path_identity_error)
    }

    fn path_for_node(&self, node: &IndexedNode) -> Result<ImplementationPath, PlanCompileError> {
        self.path_for_class(&node.source, &node.test_class, node.category)
    }

    fn path_for_class(
        &self,
        _source: &SourceRef,
        class: &str,
        category: IndexedCategory,
    ) -> Result<ImplementationPath, PlanCompileError> {
        if matches!(category, IndexedCategory::Unknown) {
            return unavailable_path(
                UnavailableReasonCode::UnsupportedCapability,
                "no active capability binding for the enabled source class",
            );
        }
        if matches!(category, IndexedCategory::OpenModel) {
            return unavailable_path(
                UnavailableReasonCode::RequiresCompatibilityPack,
                "open-model scheduling is not represented by the standalone native runtime",
            );
        }
        if matches!(category, IndexedCategory::Replaceable) {
            return unavailable_path(
                UnavailableReasonCode::InvalidConfiguration,
                "replacement resolution is required before execution",
            );
        }
        if self.registry.get(class).is_none() && builtin_lifecycle_capability(class).is_some() {
            return Ok(ImplementationPath::native(
                VersionedCapability::new("runtime.local-plan", 1).map_err(path_identity_error)?,
            ));
        }
        if matches!(category, IndexedCategory::Controller)
            && self.registry.get(class).is_none()
            && builtin_controller_capability(class).is_some()
        {
            return Ok(ImplementationPath::native(
                VersionedCapability::new("runtime.local-plan", 1).map_err(path_identity_error)?,
            ));
        }
        let Some(binding) = self.registry.get(class) else {
            return unavailable_path(
                UnavailableReasonCode::UnsupportedCapability,
                "no active capability binding for the enabled source class",
            );
        };
        if binding.is_unavailable() {
            let reason_code = if binding.capability_id == "runtime.controller.recording" {
                UnavailableReasonCode::RequiresCompatibilityPack
            } else {
                UnavailableReasonCode::UnsupportedCapability
            };
            return unavailable_path(
                reason_code,
                format!(
                    "component capability {} is recognized but has no executable adapter",
                    bounded(&binding.capability_id)
                ),
            );
        }
        let capability_id =
            if binding.is_external() || capability_requires_external(&binding.capability_id) {
                match external_path_family(&binding.capability_id) {
                    ImplementationPathFamily::CompatRmi => "jmeter.rmi",
                    ImplementationPathFamily::CompatJvm
                        if binding.capability_id.starts_with("runtime.assertion.jvm.")
                            || binding.capability_id.starts_with("jvm.scripting")
                            || matches!(
                                binding.capability_id.as_str(),
                                "assertion.json" | "assertion.jmespath"
                            ) =>
                    {
                        "jvm.scripting"
                    }
                    _ => "jvm.external-elements",
                }
            } else {
                "runtime.local-plan"
            };
        let capability = VersionedCapability::new(capability_id, 1).map_err(path_identity_error)?;
        if binding.is_external() || capability_requires_external(&binding.capability_id) {
            return Ok(match external_path_family(&binding.capability_id) {
                ImplementationPathFamily::CompatRmi => ImplementationPath::compat_rmi(capability),
                _ => ImplementationPath::compat_jvm(capability),
            });
        }
        Ok(ImplementationPath::native(capability))
    }

    /// Builds the bounded index and compiles lifecycle/controller semantics.
    pub fn compile(
        &self,
        source: &dyn PlanSourceView,
    ) -> Result<CompiledPlanDraft, PlanCompileError> {
        let index = self.build_index(source)?;
        self.reject_enabled_unrepresentable(source, &index)?;

        let enabled_test_plans = index
            .roots()
            .iter()
            .filter_map(|id| index.node(*id))
            .filter(|node| {
                node.effective_enabled && matches!(node.category, IndexedCategory::TestPlan)
            })
            .collect::<Vec<_>>();

        if enabled_test_plans.is_empty() {
            if index
                .roots()
                .iter()
                .all(|id| index.node(*id).is_some_and(|node| !node.effective_enabled))
            {
                return Ok(CompiledPlanDraft {
                    index,
                    groups: Vec::new(),
                    initial_variables: BTreeMap::new(),
                    serialize_thread_groups: false,
                    teardown_on_shutdown: false,
                });
            }
            return Err(PlanCompileError::InvalidTopology {
                source: None,
                detail: "an enabled plan must have one TestPlan root".to_owned(),
            });
        }
        if enabled_test_plans.len() != 1 {
            return Err(PlanCompileError::InvalidTopology {
                source: Some(enabled_test_plans[0].source.clone()),
                detail: "multiple enabled TestPlan roots are not executable".to_owned(),
            });
        }

        let test_plan = enabled_test_plans[0];
        let test_plan_element = source
            .tree()
            .value(test_plan.id)
            .map_err(model_tree_error)?;
        validate_test_plan_properties(&test_plan.source, test_plan_element)?;
        let serialize_thread_groups = bool_property(
            &test_plan.source,
            "TestPlan",
            test_plan_element,
            "TestPlan.serialize_threadgroups",
            false,
        )?;
        let teardown_on_shutdown = bool_property(
            &test_plan.source,
            "TestPlan",
            test_plan_element,
            "TestPlan.tearDown_on_shutdown",
            false,
        )?;
        let initial_variables = parse_initial_variables(&test_plan.source, test_plan_element)?;

        let max_id = index
            .preorder()
            .iter()
            .filter_map(|id| index.node(*id))
            .map(|node| node.id.get())
            .max()
            .unwrap_or(0);
        let mut ids = RuntimeIdAllocator::new(max_id);
        let mut groups = Vec::new();
        for child_id in &test_plan.children {
            let child = index
                .node(*child_id)
                .ok_or_else(|| PlanCompileError::InvalidTopology {
                    source: Some(test_plan.source.clone()),
                    detail: format!("missing indexed TestPlan child {child_id}"),
                })?;
            if !child.effective_enabled {
                continue;
            }
            let IndexedCategory::ThreadGroup(kind) = child.category else {
                if matches!(child.category, IndexedCategory::Ignored) {
                    continue;
                }
                if matches!(child.category, IndexedCategory::Scope(_)) {
                    if has_executable_child(&index, child) {
                        return Err(PlanCompileError::InvalidTopology {
                            source: Some(child.source.clone()),
                            detail: "scope components must not own executable descendants"
                                .to_owned(),
                        });
                    }
                    continue;
                }
                return Err(PlanCompileError::InvalidTopology {
                    source: Some(child.source.clone()),
                    detail: "only lifecycle groups may be direct executable TestPlan children"
                        .to_owned(),
                });
            };
            if groups.len() >= self.limits.max_groups {
                let actual = groups
                    .len()
                    .checked_add(1)
                    .ok_or_else(|| PlanCompileError::Tree {
                        detail: "group count overflow".to_owned(),
                    })?;
                return Err(PlanCompileError::Limit {
                    kind: PlanLimitKind::Groups,
                    actual,
                    limit: self.limits.max_groups,
                    source: Some(child.source.clone()),
                });
            }
            groups.push(self.compile_group(source, &index, child, kind, &mut ids)?);
        }

        Ok(CompiledPlanDraft {
            index,
            groups,
            initial_variables,
            serialize_thread_groups,
            teardown_on_shutdown,
        })
    }

    fn build_index(&self, source: &dyn PlanSourceView) -> Result<PlanIndex, PlanCompileError> {
        let tree = source.tree();
        tree.validate_with_limits(&self.limits.model_limits())
            .map_err(model_error)?;
        let roots = tree
            .get_array_bounded(self.limits.max_nodes)
            .map_err(|error| PlanCompileError::Tree {
                detail: bounded(error.to_string()),
            })?;

        let mut nodes = BTreeMap::new();
        let mut preorder = Vec::new();
        let mut executable_preorder = Vec::new();
        let mut disabled = BTreeSet::new();
        let mut stack = Vec::with_capacity(roots.len());
        for id in roots.iter().rev().copied() {
            stack.push(IndexFrame {
                id,
                parent: None,
                path: vec![id],
                group_id: None,
                ancestor_enabled: true,
                ignored_ancestor: false,
                opaque_ancestor: false,
            });
        }
        while let Some(frame) = stack.pop() {
            if nodes.len() >= self.limits.max_nodes {
                let actual = nodes
                    .len()
                    .checked_add(1)
                    .ok_or_else(|| PlanCompileError::Tree {
                        detail: "node count overflow".to_owned(),
                    })?;
                return Err(PlanCompileError::Limit {
                    kind: PlanLimitKind::Nodes,
                    actual,
                    limit: self.limits.max_nodes,
                    source: Some(SourceRef::tree(frame.path)),
                });
            }
            let tree_node = tree.node(frame.id).map_err(model_tree_error)?;
            let element = tree_node.value();
            let depth = frame
                .path
                .len()
                .checked_sub(1)
                .ok_or_else(|| PlanCompileError::Tree {
                    detail: "index frame path is empty".to_owned(),
                })?;
            if depth > self.limits.max_depth {
                return Err(PlanCompileError::Limit {
                    kind: PlanLimitKind::Depth,
                    actual: depth,
                    limit: self.limits.max_depth,
                    source: Some(SourceRef::tree(frame.path)),
                });
            }
            let source_enabled = element.is_enabled();
            let effective_enabled = frame.ancestor_enabled && source_enabled;
            if !effective_enabled {
                disabled.insert(frame.id);
            }
            let category = classify(&self.registry, element.test_class());
            let executable = effective_enabled
                && !frame.ignored_ancestor
                && !frame.opaque_ancestor
                && !matches!(category, IndexedCategory::Ignored)
                && !source.is_opaque(frame.id)
                && element.opaque_extensions.is_empty();
            let group_id = match category {
                IndexedCategory::ThreadGroup(_) => Some(frame.id),
                _ => frame.group_id,
            };
            let children = tree_node.children();
            if children.len() > self.limits.max_children {
                return Err(PlanCompileError::Limit {
                    kind: PlanLimitKind::Children,
                    actual: children.len(),
                    limit: self.limits.max_children,
                    source: Some(SourceRef::tree(frame.path)),
                });
            }
            let source_ref = SourceRef::tree(frame.path.clone());
            nodes.insert(
                frame.id,
                IndexedNode {
                    id: frame.id,
                    source: source_ref,
                    parent: frame.parent,
                    children: children.to_vec(),
                    depth,
                    test_class: element.test_class().to_owned(),
                    name: element.name().to_owned(),
                    source_enabled,
                    effective_enabled,
                    executable,
                    group_id,
                    category,
                },
            );
            preorder.push(frame.id);
            if executable {
                executable_preorder.push(frame.id);
            }

            for child_id in children.iter().rev().copied() {
                let mut path = frame.path.clone();
                path.push(child_id);
                stack.push(IndexFrame {
                    id: child_id,
                    parent: Some(frame.id),
                    path,
                    group_id,
                    ancestor_enabled: effective_enabled,
                    ignored_ancestor: frame.ignored_ancestor
                        || matches!(category, IndexedCategory::Ignored),
                    opaque_ancestor: frame.opaque_ancestor
                        || source.is_opaque(frame.id)
                        || !element.opaque_extensions.is_empty(),
                });
            }
        }

        Ok(PlanIndex {
            roots,
            preorder,
            executable_preorder,
            nodes,
            disabled,
        })
    }

    fn reject_enabled_unrepresentable(
        &self,
        source: &dyn PlanSourceView,
        index: &PlanIndex,
    ) -> Result<(), PlanCompileError> {
        for id in index.preorder() {
            let node = index.node(*id).ok_or_else(|| PlanCompileError::Tree {
                detail: format!("index lost source node {id}"),
            })?;
            if !node.effective_enabled {
                continue;
            }
            if is_preservation_only(index, node) {
                continue;
            }
            if source.is_opaque(*id) {
                return Err(PlanCompileError::UnsupportedOpaque {
                    source: node.source.clone(),
                    test_class: bounded(&node.test_class),
                });
            }
            let element = source.tree().value(node.id).map_err(model_tree_error)?;
            if !element.opaque_extensions.is_empty() {
                return Err(PlanCompileError::UnsupportedFeature {
                    source: node.source.clone(),
                    capability_id: "runtime.plan.opaque-element-extension".to_owned(),
                    detail: "opaque element extensions cannot execute in the native compiler"
                        .to_owned(),
                });
            }
            if !node.executable {
                continue;
            }
            match node.category {
                IndexedCategory::Unknown => {
                    return Err(PlanCompileError::UnsupportedClass {
                        source: node.source.clone(),
                        test_class: bounded(&node.test_class),
                    });
                }
                IndexedCategory::OpenModel => {
                    return Err(PlanCompileError::UnsupportedFeature {
                        source: node.source.clone(),
                        capability_id: "runtime.lifecycle.open-model-thread-group".to_owned(),
                        detail: "arrival-rate/open-model scheduling is not represented by the native lifecycle plan".to_owned(),
                    });
                }
                _ => {}
            }
            if let Some(binding) = self.registry.get(&node.test_class) {
                if binding.is_unavailable() {
                    return Err(PlanCompileError::UnsupportedFeature {
                        source: node.source.clone(),
                        capability_id: bounded(&binding.capability_id),
                        detail: "the recognized component has no executable adapter".to_owned(),
                    });
                }
                if binding.is_external() || capability_requires_external(&binding.capability_id) {
                    return Err(PlanCompileError::UnsupportedFeature {
                        source: node.source.clone(),
                        capability_id: bounded(&binding.capability_id),
                        detail: "the selected component requires an explicit external compatibility capability".to_owned(),
                    });
                }
            }
        }
        Ok(())
    }

    fn compile_group(
        &self,
        source: &dyn PlanSourceView,
        index: &PlanIndex,
        group: &IndexedNode,
        kind: GroupKind,
        ids: &mut RuntimeIdAllocator,
    ) -> Result<CompiledThreadGroupDraft, PlanCompileError> {
        let element = source.tree().value(group.id).map_err(model_tree_error)?;
        ensure_allowed_properties(
            &group.source,
            element,
            group.test_class.as_str(),
            &[
                "ThreadGroup.on_sample_error",
                "ThreadGroup.main_controller",
                "ThreadGroup.num_threads",
                "ThreadGroup.ramp_time",
                "ThreadGroup.delayedStart",
                "ThreadGroup.start_time",
                "ThreadGroup.end_time",
                "ThreadGroup.scheduler",
                "ThreadGroup.duration",
                "ThreadGroup.delay",
                "ThreadGroup.same_user_on_next_iteration",
            ],
        )?;
        let threads = usize_property(
            &group.source,
            &group.test_class,
            element,
            "ThreadGroup.num_threads",
            0,
        )?;
        if threads > i32::MAX as usize {
            return Err(invalid_property(
                &group.source,
                &group.test_class,
                "ThreadGroup.num_threads",
                "value exceeds JMeter's signed 32-bit property range",
            ));
        }
        if threads > self.limits.max_threads {
            return Err(PlanCompileError::Limit {
                kind: PlanLimitKind::Threads,
                actual: threads,
                limit: self.limits.max_threads,
                source: Some(group.source.clone()),
            });
        }
        let schedule = self.group_schedule(&group.source, &group.test_class, element)?;
        let on_sample_error = sample_error_policy(
            &group.source,
            &group.test_class,
            element,
            "ThreadGroup.on_sample_error",
        )?;
        let same_user_on_next_iteration = bool_property(
            &group.source,
            &group.test_class,
            element,
            "ThreadGroup.same_user_on_next_iteration",
            true,
        )?;
        let root_value = element
            .property("ThreadGroup.main_controller")
            .ok_or_else(|| PlanCompileError::InvalidTopology {
                source: Some(group.source.clone()),
                detail: "ThreadGroup.main_controller is required".to_owned(),
            })?;
        let root_element = root_value.as_element().map_err(|error| {
            invalid_property(
                &group.source,
                &group.test_class,
                "ThreadGroup.main_controller",
                error.to_string(),
            )
        })?;
        if !root_element.opaque_extensions.is_empty() {
            return Err(PlanCompileError::UnsupportedFeature {
                source: embedded_source(group, "ThreadGroup.main_controller"),
                capability_id: "runtime.plan.opaque-embedded-controller".to_owned(),
                detail: "opaque embedded controller properties cannot execute natively".to_owned(),
            });
        }
        let root_source = embedded_source(group, "ThreadGroup.main_controller");
        let root_class = root_element.class_name.as_deref().ok_or_else(|| {
            PlanCompileError::InvalidProperty {
                source: root_source.clone(),
                test_class: bounded(&group.test_class),
                property: "ThreadGroup.main_controller".to_owned(),
                detail: "embedded controller has no elementType/testclass".to_owned(),
            }
        })?;
        let root_runtime_id = ids.allocate(&root_source)?;
        let children = self.compile_branch(source, index, &group.children, ids)?;
        let root_node = self.compile_controller_element(
            ControllerCompileContext {
                source: &root_source,
                class: root_class,
                element: root_element,
                runtime_id: root_runtime_id,
                root_controller: true,
            },
            children,
            ids,
        )?;
        let controller = LogicProgram::compile_with_limits(root_node, self.limits.logic_limits())
            .map_err(|source| PlanCompileError::Logic { source })?;

        Ok(CompiledThreadGroupDraft {
            id: group.id,
            name: group.name.clone(),
            kind,
            threads,
            schedule,
            on_sample_error,
            same_user_on_next_iteration,
            controller,
            root_controller: root_source,
            root_runtime_id,
            source_path: group.source.tree_path().to_vec(),
        })
    }

    fn group_schedule(
        &self,
        source: &SourceRef,
        class: &str,
        element: &TestElement,
    ) -> Result<GroupSchedule, PlanCompileError> {
        let scheduler = bool_property(source, class, element, "ThreadGroup.scheduler", false)?;
        let delayed_start =
            bool_property(source, class, element, "ThreadGroup.delayedStart", false)?;
        if delayed_start {
            return unsupported_feature(
                source,
                "runtime.lifecycle.delayed-start",
                "ThreadGroup.delayedStart requires lifecycle startup coordination outside the plan draft",
            );
        }
        let start_time = i64_property(source, class, element, "ThreadGroup.start_time", 0)?;
        let end_time = i64_property(source, class, element, "ThreadGroup.end_time", 0)?;
        if start_time != 0 || end_time != 0 {
            let properties = if start_time != 0 {
                if end_time != 0 {
                    "ThreadGroup.start_time and ThreadGroup.end_time"
                } else {
                    "ThreadGroup.start_time"
                }
            } else {
                "ThreadGroup.end_time"
            };
            return Err(PlanCompileError::UnsupportedFeature {
                source: source.clone(),
                capability_id: "runtime.lifecycle.scheduler-boundary".to_owned(),
                detail: format!(
                    "non-zero {properties} use absolute wall-clock boundaries not represented by the native lifecycle schedule"
                ),
            });
        }
        let delay = seconds_property(source, class, element, "ThreadGroup.delay", Duration::ZERO)?;
        let ramp_up = seconds_property(
            source,
            class,
            element,
            "ThreadGroup.ramp_time",
            Duration::ZERO,
        )?;
        if ramp_up.as_secs() > i32::MAX as u64 {
            return Err(invalid_property(
                source,
                class,
                "ThreadGroup.ramp_time",
                "value exceeds JMeter's signed 32-bit property range",
            ));
        }
        let duration = optional_seconds_property(source, class, element, "ThreadGroup.duration")?;
        // JMeter's ThreadGroup only applies delay and duration from
        // scheduleThread when the scheduler flag is enabled.  Ramp-up is
        // configured and applied independently of that flag.  Decode the
        // disabled fields above as well so malformed values remain a typed
        // plan error instead of being silently accepted by the compiler.
        if !scheduler {
            return Ok(GroupSchedule {
                delay: Duration::ZERO,
                ramp_up,
                duration: None,
            });
        }
        let Some(duration) = duration else {
            return Err(invalid_property(
                source,
                class,
                "ThreadGroup.duration",
                "scheduler requires a positive duration",
            ));
        };
        if duration.is_zero() {
            return Err(invalid_property(
                source,
                class,
                "ThreadGroup.duration",
                "scheduler requires a positive duration",
            ));
        }
        Ok(GroupSchedule {
            delay,
            ramp_up,
            duration: Some(duration),
        })
    }

    fn compile_branch(
        &self,
        source: &dyn PlanSourceView,
        index: &PlanIndex,
        child_ids: &[NodeId],
        ids: &mut RuntimeIdAllocator,
    ) -> Result<Vec<CompiledChild>, PlanCompileError> {
        let mut stack = vec![BranchCompileFrame::new(
            child_ids,
            None,
            self.limits.max_children,
            index,
        )?];
        loop {
            let Some(frame) = stack.last_mut() else {
                return Err(PlanCompileError::Tree {
                    detail: "controller compilation stack underflow".to_owned(),
                });
            };
            if frame.next >= frame.child_ids.len() {
                let finished = stack.pop().ok_or_else(|| PlanCompileError::Tree {
                    detail: "controller compilation stack underflow".to_owned(),
                })?;
                if let Some(controller) = finished.controller {
                    let node = self.compile_controller_element(
                        ControllerCompileContext {
                            source: &controller.source,
                            class: &controller.class,
                            element: &controller.element,
                            runtime_id: controller.runtime_id,
                            root_controller: false,
                        },
                        finished.result,
                        ids,
                    )?;
                    let parent = stack.last_mut().ok_or_else(|| PlanCompileError::Tree {
                        detail: "controller compilation parent frame missing".to_owned(),
                    })?;
                    parent.result.push(CompiledChild {
                        name: controller.name,
                        node,
                    });
                    continue;
                }
                return Ok(finished.result);
            }

            let child_id = frame.child_ids[frame.next];
            frame.next += 1;
            let child = index.node(child_id).ok_or_else(|| PlanCompileError::Tree {
                detail: format!("index lost child node {child_id}"),
            })?;
            if !child.effective_enabled || !child.executable {
                continue;
            }
            match child.category {
                IndexedCategory::Controller => {
                    let element = source.tree().value(child.id).map_err(model_tree_error)?;
                    if !element.opaque_extensions.is_empty() {
                        return unsupported_feature(
                            &child.source,
                            "runtime.plan.opaque-controller-extension",
                            "opaque controller properties cannot execute natively",
                        );
                    }
                    let properties = ElementProperty {
                        name: child.name.clone(),
                        class_name: Some(child.test_class.clone()),
                        properties: element.properties.clone(),
                        opaque_extensions: Vec::new(),
                    };
                    let controller = ControllerCompileFinish {
                        source: child.source.clone(),
                        class: child.test_class.clone(),
                        element: properties,
                        runtime_id: child.id.get(),
                        name: child.name.clone(),
                    };
                    let children = child.children.clone();
                    let max_children = self.limits.max_children;
                    stack.push(BranchCompileFrame::new(
                        &children,
                        Some(controller),
                        max_children,
                        index,
                    )?);
                }
                IndexedCategory::Replaceable => {
                    let capability_id = self
                        .registry
                        .get(&child.test_class)
                        .map(|binding| binding.capability_id.clone())
                        .unwrap_or_else(|| format!("runtime.controller.{}", child.test_class));
                    return Err(PlanCompileError::UnsupportedFeature {
                        source: child.source.clone(),
                        capability_id,
                        detail:
                            "Module/Include replacement must be resolved before native compilation"
                                .to_owned(),
                    });
                }
                IndexedCategory::Sampler => {
                    self.validate_sampler_children(index, child)?;
                    frame.result.push(CompiledChild {
                        name: child.name.clone(),
                        node: LogicNode::Sample { id: child.id.get() },
                    });
                }
                IndexedCategory::Scope(_) => {
                    if has_executable_child(index, child) {
                        return Err(PlanCompileError::InvalidTopology {
                            source: Some(child.source.clone()),
                            detail: "scope components must not own executable descendants"
                                .to_owned(),
                        });
                    }
                }
                IndexedCategory::Ignored => {}
                IndexedCategory::ThreadGroup(_) | IndexedCategory::TestPlan => {
                    return Err(PlanCompileError::InvalidTopology {
                        source: Some(child.source.clone()),
                        detail: "nested lifecycle/TestPlan elements are not controller children"
                            .to_owned(),
                    });
                }
                IndexedCategory::OpenModel | IndexedCategory::Unknown => {
                    return Err(PlanCompileError::UnsupportedClass {
                        source: child.source.clone(),
                        test_class: bounded(&child.test_class),
                    });
                }
            }
        }
    }

    fn validate_sampler_children(
        &self,
        index: &PlanIndex,
        sampler: &IndexedNode,
    ) -> Result<(), PlanCompileError> {
        for child_id in &sampler.children {
            let child = index
                .node(*child_id)
                .ok_or_else(|| PlanCompileError::Tree {
                    detail: format!("index lost sampler child {child_id}"),
                })?;
            if !child.effective_enabled {
                continue;
            }
            if !matches!(
                child.category,
                IndexedCategory::Scope(_) | IndexedCategory::Ignored
            ) {
                return Err(PlanCompileError::InvalidTopology {
                    source: Some(child.source.clone()),
                    detail: "sampler descendants must be scope components".to_owned(),
                });
            }
            if child.executable && has_executable_child(index, child) {
                return Err(PlanCompileError::InvalidTopology {
                    source: Some(child.source.clone()),
                    detail: "sampler scope components must be leaves".to_owned(),
                });
            }
        }
        Ok(())
    }

    fn compile_controller_element(
        &self,
        context: ControllerCompileContext<'_>,
        children: Vec<CompiledChild>,
        ids: &mut RuntimeIdAllocator,
    ) -> Result<LogicNode, PlanCompileError> {
        let ControllerCompileContext {
            source,
            class,
            element,
            runtime_id,
            root_controller,
        } = context;
        let child_names = children
            .iter()
            .map(|child| child.name.clone())
            .collect::<Vec<_>>();
        let nodes = children
            .into_iter()
            .map(|child| child.node)
            .collect::<Vec<_>>();
        match class {
            "GenericController"
            | "SimpleController"
            | "org.apache.jmeter.control.GenericController" => {
                ensure_allowed_embedded(source, element, class, &[])?;
                Ok(LogicNode::Sequence {
                    id: runtime_id,
                    children: nodes,
                })
            }
            "LoopController" | "org.apache.jmeter.control.LoopController" => {
                ensure_allowed_embedded(
                    source,
                    element,
                    class,
                    &["LoopController.continue_forever", "LoopController.loops"],
                )?;
                let (count, continue_forever) =
                    loop_count(source, class, element, root_controller)?;
                let loop_node = LogicNode::Loop {
                    id: runtime_id,
                    count,
                    children: nodes,
                };
                if !root_controller && !continue_forever {
                    let once_id = ids.allocate(source)?;
                    Ok(LogicNode::OnceOnly {
                        id: once_id,
                        children: vec![loop_node],
                    })
                } else {
                    Ok(loop_node)
                }
            }
            "OnceOnlyController" | "org.apache.jmeter.control.OnceOnlyController" => {
                ensure_allowed_embedded(source, element, class, &[])?;
                Ok(LogicNode::OnceOnly {
                    id: runtime_id,
                    children: nodes,
                })
            }
            "InterleaveControl" | "org.apache.jmeter.control.InterleaveControl" => {
                ensure_allowed_embedded(
                    source,
                    element,
                    class,
                    &[
                        "InterleaveControl.style",
                        "InterleaveControl.accrossThreads",
                    ],
                )?;
                let style = embedded_i32(source, class, element, "InterleaveControl.style", 0)?;
                if style != 0 {
                    return unsupported_feature(
                        source,
                        "runtime.controller.interleave-style",
                        "non-default InterleaveControl.style is not represented",
                    );
                }
                if embedded_bool(
                    source,
                    class,
                    element,
                    "InterleaveControl.accrossThreads",
                    false,
                )? {
                    return unsupported_feature(
                        source,
                        "runtime.controller.interleave-across-threads",
                        "InterleaveControl.accrossThreads requires cross-thread controller state",
                    );
                }
                Ok(LogicNode::Interleave {
                    id: runtime_id,
                    children: nodes,
                })
            }
            "RandomController" | "org.apache.jmeter.control.RandomController" => {
                ensure_allowed_embedded(source, element, class, &[])?;
                Ok(LogicNode::Random {
                    id: runtime_id,
                    children: nodes,
                })
            }
            "RandomOrderController" | "org.apache.jmeter.control.RandomOrderController" => {
                ensure_allowed_embedded(source, element, class, &[])?;
                Ok(LogicNode::RandomOrder {
                    id: runtime_id,
                    children: nodes,
                })
            }
            "ThroughputController" | "org.apache.jmeter.control.ThroughputController" => {
                ensure_allowed_embedded(
                    source,
                    element,
                    class,
                    &[
                        "ThroughputController.style",
                        "ThroughputController.perThread",
                        "ThroughputController.maxThroughput",
                        "ThroughputController.percentThroughput",
                    ],
                )?;
                let style = embedded_i32(source, class, element, "ThroughputController.style", 0)?;
                let mode = match style {
                    0 => ThroughputMode::Total,
                    1 => ThroughputMode::Percentage,
                    _ => {
                        return unsupported_feature(
                            source,
                            "runtime.controller.throughput-style",
                            "unknown ThroughputController.style",
                        );
                    }
                };
                let per_user = embedded_bool(
                    source,
                    class,
                    element,
                    "ThroughputController.perThread",
                    true,
                )?;
                let max = embedded_i32(
                    source,
                    class,
                    element,
                    "ThroughputController.maxThroughput",
                    1,
                )?;
                if max < 0 {
                    return invalid_embedded(
                        source,
                        class,
                        "ThroughputController.maxThroughput",
                        "value must be non-negative",
                    );
                }
                let percent = embedded_f64(
                    source,
                    class,
                    element,
                    "ThroughputController.percentThroughput",
                    100.0,
                )?;
                Ok(LogicNode::Throughput {
                    id: runtime_id,
                    mode,
                    limit: max as u64,
                    percent,
                    per_user,
                    children: nodes,
                })
            }
            "RunTime" | "RuntimeController" | "org.apache.jmeter.control.RunTime" => {
                ensure_allowed_embedded(source, element, class, &["RunTime.seconds"])?;
                let seconds = embedded_i64(source, class, element, "RunTime.seconds", 0)?;
                // JMeter treats a negative RunTime value as an already-expired
                // deadline.  A zero duration has the same bounded native
                // behavior: the runner observes the deadline before selecting
                // the first child, so no sampler is visited.
                let duration = if seconds < 0 {
                    Duration::ZERO
                } else {
                    checked_duration_secs(seconds as u64)
                };
                Ok(LogicNode::Runtime {
                    id: runtime_id,
                    duration,
                    children: nodes,
                })
            }
            "IfController" | "org.apache.jmeter.control.IfController" => {
                ensure_allowed_embedded(
                    source,
                    element,
                    class,
                    &[
                        "IfController.condition",
                        "IfController.evaluateAll",
                        "IfController.useExpression",
                    ],
                )?;
                let use_expression =
                    embedded_bool(source, class, element, "IfController.useExpression", false)?;
                let condition =
                    condition_from_embedded(source, class, element, false, use_expression)?;
                let evaluate_each_iteration =
                    embedded_bool(source, class, element, "IfController.evaluateAll", false)?;
                Ok(LogicNode::If {
                    id: runtime_id,
                    condition,
                    evaluate_each_iteration,
                    children: nodes,
                })
            }
            "WhileController" | "org.apache.jmeter.control.WhileController" => {
                ensure_allowed_embedded(source, element, class, &["WhileController.condition"])?;
                let condition = condition_from_embedded(source, class, element, true, true)?;
                Ok(LogicNode::While {
                    id: runtime_id,
                    condition,
                    max_iterations: None,
                    children: nodes,
                })
            }
            "ForEachController"
            | "ForeachController"
            | "org.apache.jmeter.control.ForeachController" => {
                ensure_allowed_embedded(
                    source,
                    element,
                    class,
                    &[
                        "ForeachController.inputVal",
                        "ForeachController.returnVal",
                        "ForeachController.useSeparator",
                        "ForeachController.startIndex",
                        "ForeachController.endIndex",
                    ],
                )?;
                let use_separator = embedded_bool(
                    source,
                    class,
                    element,
                    "ForeachController.useSeparator",
                    true,
                )?;
                if !use_separator {
                    return unsupported_feature(
                        source,
                        "runtime.controller.foreach-separator",
                        "ForEach without underscore-separated variables is not represented",
                    );
                }
                for property in ["ForeachController.startIndex", "ForeachController.endIndex"] {
                    let value = embedded_string(source, class, element, property, "")?;
                    if !value.trim().is_empty() && value != "0" {
                        return unsupported_feature(
                            source,
                            "runtime.controller.foreach-range",
                            "explicit ForEach start/end ranges are not represented",
                        );
                    }
                }
                let input_prefix =
                    embedded_string(source, class, element, "ForeachController.inputVal", "")?;
                let output_variable =
                    embedded_string(source, class, element, "ForeachController.returnVal", "")?;
                Ok(LogicNode::ForEach {
                    id: runtime_id,
                    input_prefix,
                    output_variable,
                    children: nodes,
                })
            }
            "SwitchController" | "org.apache.jmeter.control.SwitchController" => {
                ensure_allowed_embedded(source, element, class, &["SwitchController.value"])?;
                let variable =
                    embedded_string(source, class, element, "SwitchController.value", "")?;
                Ok(LogicNode::Switch {
                    id: runtime_id,
                    selection: SwitchSelection::VariableWithNames {
                        variable,
                        child_names,
                    },
                    children: nodes,
                })
            }
            "TransactionController" | "org.apache.jmeter.control.TransactionController" => {
                ensure_allowed_embedded(
                    source,
                    element,
                    class,
                    &[
                        "TransactionController.parent",
                        "TransactionController.includeTimers",
                    ],
                )?;
                Ok(LogicNode::Transaction {
                    id: runtime_id,
                    parent: embedded_bool(
                        source,
                        class,
                        element,
                        "TransactionController.parent",
                        false,
                    )?,
                    include_timers: embedded_bool(
                        source,
                        class,
                        element,
                        "TransactionController.includeTimers",
                        true,
                    )?,
                    children: nodes,
                })
            }
            "CriticalSectionController" | "org.apache.jmeter.control.CriticalSectionController" => {
                ensure_allowed_embedded(
                    source,
                    element,
                    class,
                    &["CriticalSectionController.lockName"],
                )?;
                let lock_name = embedded_string(
                    source,
                    class,
                    element,
                    "CriticalSectionController.lockName",
                    "",
                )?;
                Ok(LogicNode::CriticalSection {
                    id: runtime_id,
                    lock_name,
                    children: nodes,
                })
            }
            "RecordingController" => unsupported_feature(
                source,
                "runtime.controller.recording",
                "recording requires the external proxy/GUI capability",
            ),
            "ModuleController" | "IncludeController" => unsupported_feature(
                source,
                "runtime.controller.replacement",
                "replacement resolution is an explicit pre-compilation capability",
            ),
            _ => Err(PlanCompileError::UnsupportedClass {
                source: source.clone(),
                test_class: bounded(class),
            }),
        }
    }
}

#[derive(Clone, Debug)]
struct IndexFrame {
    id: NodeId,
    parent: Option<NodeId>,
    path: Vec<NodeId>,
    group_id: Option<NodeId>,
    ancestor_enabled: bool,
    ignored_ancestor: bool,
    opaque_ancestor: bool,
}

#[derive(Clone, Debug)]
struct CompiledChild {
    name: String,
    node: LogicNode,
}

#[derive(Clone, Debug)]
struct ControllerCompileFinish {
    source: SourceRef,
    class: String,
    element: ElementProperty,
    runtime_id: u64,
    name: String,
}

struct ControllerCompileContext<'a> {
    source: &'a SourceRef,
    class: &'a str,
    element: &'a ElementProperty,
    runtime_id: u64,
    root_controller: bool,
}

#[derive(Clone, Debug)]
struct BranchCompileFrame {
    child_ids: Vec<NodeId>,
    next: usize,
    result: Vec<CompiledChild>,
    controller: Option<ControllerCompileFinish>,
}

impl BranchCompileFrame {
    fn new(
        child_ids: &[NodeId],
        controller: Option<ControllerCompileFinish>,
        max_children: usize,
        index: &PlanIndex,
    ) -> Result<Self, PlanCompileError> {
        if child_ids.len() > max_children {
            return Err(PlanCompileError::Limit {
                kind: PlanLimitKind::Children,
                actual: child_ids.len(),
                limit: max_children,
                source: child_ids
                    .first()
                    .and_then(|id| index.node(*id))
                    .map(|node| node.source.clone()),
            });
        }
        Ok(Self {
            child_ids: child_ids.to_vec(),
            next: 0,
            result: Vec::with_capacity(child_ids.len()),
            controller,
        })
    }
}

#[derive(Clone, Debug)]
struct RuntimeIdAllocator {
    next: Option<u64>,
    used: BTreeSet<u64>,
}

impl RuntimeIdAllocator {
    fn new(max_source_id: u64) -> Self {
        Self {
            next: max_source_id.checked_add(1),
            used: BTreeSet::new(),
        }
    }

    fn allocate(&mut self, source: &SourceRef) -> Result<u64, PlanCompileError> {
        let Some(id) = self.next else {
            return Err(PlanCompileError::IdentityExhausted {
                source: source.clone(),
            });
        };
        if id == 0 || self.used.contains(&id) {
            return Err(PlanCompileError::IdentityExhausted {
                source: source.clone(),
            });
        }
        self.used.insert(id);
        self.next = id.checked_add(1);
        Ok(id)
    }
}

fn classify(registry: &ComponentRegistry, class: &str) -> IndexedCategory {
    if matches!(class, "TestPlan" | "org.apache.jmeter.testelement.TestPlan") {
        return IndexedCategory::TestPlan;
    }
    if matches!(
        class,
        "OpenModelThreadGroup" | "org.apache.jmeter.threads.openmodel.OpenModelThreadGroup"
    ) {
        return IndexedCategory::OpenModel;
    }
    if class == "WorkBench" {
        return IndexedCategory::Ignored;
    }
    if let Some(kind) = group_kind(class) {
        return IndexedCategory::ThreadGroup(kind);
    }
    let Some(binding) = registry.get(class) else {
        if builtin_controller_capability(class).is_some() {
            return IndexedCategory::Controller;
        }
        return IndexedCategory::Unknown;
    };
    match binding.category {
        ComponentCategory::Controller => IndexedCategory::Controller,
        ComponentCategory::Replaceable => IndexedCategory::Replaceable,
        ComponentCategory::Sampler => IndexedCategory::Sampler,
        category @ (ComponentCategory::Configuration
        | ComponentCategory::Preprocessor
        | ComponentCategory::Timer
        | ComponentCategory::Postprocessor
        | ComponentCategory::Assertion
        | ComponentCategory::Listener) => IndexedCategory::Scope(category),
        ComponentCategory::Lifecycle => IndexedCategory::Ignored,
    }
}

fn builtin_controller_capability(class: &str) -> Option<&'static str> {
    match class {
        "org.apache.jmeter.control.GenericController"
        | "org.apache.jmeter.control.LoopController"
        | "org.apache.jmeter.control.IfController"
        | "org.apache.jmeter.control.WhileController"
        | "org.apache.jmeter.control.ForeachController"
        | "org.apache.jmeter.control.SwitchController"
        | "org.apache.jmeter.control.InterleaveControl"
        | "org.apache.jmeter.control.RandomController"
        | "org.apache.jmeter.control.RandomOrderController"
        | "org.apache.jmeter.control.OnceOnlyController"
        | "org.apache.jmeter.control.ThroughputController"
        | "org.apache.jmeter.control.RunTime"
        | "org.apache.jmeter.control.TransactionController"
        | "org.apache.jmeter.control.CriticalSectionController" => Some("runtime.local-plan"),
        _ => None,
    }
}

fn builtin_lifecycle_capability(class: &str) -> Option<&'static str> {
    match class {
        "TestPlan"
        | "org.apache.jmeter.testelement.TestPlan"
        | "ThreadGroup"
        | "org.apache.jmeter.threads.ThreadGroup"
        | "SetupThreadGroup"
        | "org.apache.jmeter.threads.SetupThreadGroup"
        | "PostThreadGroup"
        | "TearDownThreadGroup"
        | "org.apache.jmeter.threads.PostThreadGroup"
        | "org.apache.jmeter.threads.TearDownThreadGroup" => Some("runtime.local-plan"),
        _ => None,
    }
}

/// Returns whether a recognized capability is intentionally outside the
/// standalone Rust execution boundary.
///
/// The registry normalizes these IDs into the explicit external availability
/// state, while this check remains a defensive boundary for custom bindings.
/// Keeping it at admission prevents a provider marker from becoming a late,
/// post-setup failure or an accidental native fallback.
fn external_path_family(capability_id: &str) -> ImplementationPathFamily {
    if capability_id.starts_with("runtime.rmi.")
        || capability_id.starts_with("runtime.external.rmi.")
        || capability_id.starts_with("jmeter.rmi")
        || capability_id.contains(".rmi.")
    {
        ImplementationPathFamily::CompatRmi
    } else {
        ImplementationPathFamily::CompatJvm
    }
}

fn unavailable_path(
    code: UnavailableReasonCode,
    detail: impl Into<String>,
) -> Result<ImplementationPath, PlanCompileError> {
    UnavailableReason::new(code, bounded(detail))
        .map(ImplementationPath::unavailable)
        .map_err(path_identity_error)
}

fn validate_path_context(context: &PlanPathContext) -> Result<(), PlanCompileError> {
    context.profile.validate().map_err(path_identity_error)?;
    context.provider.validate().map_err(path_identity_error)?;
    if context.plan_digest.is_zero() {
        return Err(PlanCompileError::PathManifest {
            detail: "plan digest must be present and non-zero".to_owned(),
        });
    }
    if context.capability_set_digest.is_zero() {
        return Err(PlanCompileError::PathManifest {
            detail: "capability-set digest must be present and non-zero".to_owned(),
        });
    }
    Ok(())
}

fn path_identity_error(error: crate::CapabilityIdentityError) -> PlanCompileError {
    PlanCompileError::PathManifest {
        detail: bounded(error.to_string()),
    }
}

fn path_manifest_error(error: crate::ManifestError) -> PlanCompileError {
    PlanCompileError::PathManifest {
        detail: bounded(error.to_string()),
    }
}

fn has_executable_child(index: &PlanIndex, node: &IndexedNode) -> bool {
    node.children
        .iter()
        .any(|child_id| index.node(*child_id).is_some_and(|child| child.executable))
}

fn is_preservation_only(index: &PlanIndex, node: &IndexedNode) -> bool {
    if matches!(node.category, IndexedCategory::Ignored) {
        return true;
    }
    let mut parent = node.parent;
    while let Some(parent_id) = parent {
        let Some(ancestor) = index.node(parent_id) else {
            return false;
        };
        if matches!(ancestor.category, IndexedCategory::Ignored) {
            return true;
        }
        parent = ancestor.parent;
    }
    false
}

fn group_kind(class: &str) -> Option<GroupKind> {
    match class {
        "SetupThreadGroup" | "org.apache.jmeter.threads.SetupThreadGroup" => Some(GroupKind::Setup),
        "ThreadGroup" | "org.apache.jmeter.threads.ThreadGroup" => Some(GroupKind::Main),
        "PostThreadGroup"
        | "TearDownThreadGroup"
        | "org.apache.jmeter.threads.PostThreadGroup"
        | "org.apache.jmeter.threads.TearDownThreadGroup" => Some(GroupKind::Teardown),
        _ => None,
    }
}

fn embedded_source(group: &IndexedNode, property: &str) -> SourceRef {
    SourceRef::embedded(group.source.tree_path().to_vec(), vec![property.to_owned()])
}

fn parse_initial_variables(
    source: &SourceRef,
    test_plan: &TestElement,
) -> Result<BTreeMap<String, String>, PlanCompileError> {
    let Some(value) = test_plan.property("TestPlan.user_defined_variables") else {
        return Ok(BTreeMap::new());
    };
    let variables_source = SourceRef::embedded(
        source.tree_path().to_vec(),
        vec!["TestPlan.user_defined_variables".to_owned()],
    );
    let variables = value.as_element().map_err(|error| {
        invalid_property(
            &variables_source,
            "TestPlan",
            "TestPlan.user_defined_variables",
            error.to_string(),
        )
    })?;
    if !variables.opaque_extensions.is_empty() {
        return unsupported_feature(
            &variables_source,
            "runtime.plan.opaque-user-variables",
            "opaque user-variable properties cannot be initialized natively",
        );
    }
    if variables
        .class_name()
        .is_some_and(|class| !matches!(class, "Arguments" | "org.apache.jmeter.config.Arguments"))
    {
        return unsupported_feature(
            &variables_source,
            "runtime.plan.user-variable-type",
            "TestPlan.user_defined_variables must use the JMeter Arguments element type",
        );
    }
    ensure_allowed_embedded(
        &variables_source,
        variables,
        "Arguments",
        &["Arguments.arguments"],
    )?;
    let arguments_value = variables
        .properties
        .get("Arguments.arguments")
        .ok_or_else(|| PlanCompileError::InvalidProperty {
            source: variables_source.clone(),
            test_class: "TestPlan".to_owned(),
            property: "TestPlan.user_defined_variables".to_owned(),
            detail: "Arguments.arguments is required".to_owned(),
        })?;
    let argument_count = match arguments_value {
        PropertyValue::Collection(values) => values.len(),
        PropertyValue::NamedCollection(entries) | PropertyValue::Map(entries) => entries.len(),
        other => {
            return Err(PlanCompileError::InvalidProperty {
                source: variables_source,
                test_class: "TestPlan".to_owned(),
                property: "TestPlan.user_defined_variables".to_owned(),
                detail: format!(
                    "Arguments.arguments must be a collection, found {}",
                    other.kind()
                ),
            });
        }
    };
    if argument_count > MAX_INITIAL_VARIABLE_SOURCE_ENTRIES {
        return Err(PlanCompileError::Limit {
            kind: PlanLimitKind::InitialVariables,
            actual: argument_count,
            limit: MAX_INITIAL_VARIABLE_SOURCE_ENTRIES,
            source: Some(variables_source),
        });
    }

    // Only canonical winners are retained for the typed constructor.  This
    // keeps temporary allocation bounded by MAX_INITIAL_VARIABLES even when
    // a source list contains many duplicate names.  The source collection is
    // still traversed in order so first-wins selection remains exact.
    let mut seen_names = BTreeSet::new();
    let mut argument_entries = Vec::with_capacity(argument_count.min(MAX_INITIAL_VARIABLES));
    let mut push_argument =
        |index: usize, argument_value: &PropertyValue| -> Result<(), PlanCompileError> {
            let (name, value) = parse_initial_variable_argument(source, index, argument_value)?;
            if !seen_names.insert(name.clone()) {
                return Ok(());
            }
            let actual =
                argument_entries
                    .len()
                    .checked_add(1)
                    .ok_or_else(|| PlanCompileError::Limit {
                        kind: PlanLimitKind::InitialVariables,
                        actual: usize::MAX,
                        limit: MAX_INITIAL_VARIABLES,
                        source: Some(SourceRef::embedded(
                            source.tree_path().to_vec(),
                            vec!["TestPlan.user_defined_variables".to_owned()],
                        )),
                    })?;
            if actual > MAX_INITIAL_VARIABLES {
                return Err(PlanCompileError::Limit {
                    kind: PlanLimitKind::InitialVariables,
                    actual,
                    limit: MAX_INITIAL_VARIABLES,
                    source: Some(SourceRef::embedded(
                        source.tree_path().to_vec(),
                        vec!["TestPlan.user_defined_variables".to_owned()],
                    )),
                });
            }
            argument_entries.push((name, value));
            Ok(())
        };
    match arguments_value {
        PropertyValue::Collection(values) => {
            for (index, argument_value) in values.iter().enumerate() {
                push_argument(index, argument_value)?;
            }
        }
        PropertyValue::NamedCollection(entries) | PropertyValue::Map(entries) => {
            for (index, entry) in entries.iter().enumerate() {
                push_argument(index, &entry.value)?;
            }
        }
        other => {
            return Err(PlanCompileError::InvalidProperty {
                source: variables_source.clone(),
                test_class: "TestPlan".to_owned(),
                property: "TestPlan.user_defined_variables".to_owned(),
                detail: format!(
                    "Arguments.arguments must be a collection, found {}",
                    other.kind()
                ),
            });
        }
    }
    let initial = InitialVariables::try_from_jmeter_arguments(argument_entries)
        .map_err(|error| initial_variables_error(&variables_source, error))?;
    Ok(initial
        .iter()
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect())
}

fn parse_initial_variable_argument(
    source: &SourceRef,
    index: usize,
    argument_value: &PropertyValue,
) -> Result<(String, String), PlanCompileError> {
    let argument_source = SourceRef::embedded(
        source.tree_path().to_vec(),
        vec![
            "TestPlan.user_defined_variables".to_owned(),
            "Arguments.arguments".to_owned(),
            index.to_string(),
        ],
    );
    let argument = argument_value.as_element().map_err(|error| {
        invalid_property(
            &argument_source,
            "Argument",
            "Arguments.arguments",
            error.to_string(),
        )
    })?;
    if !argument.opaque_extensions.is_empty() {
        return unsupported_feature(
            &argument_source,
            "runtime.plan.opaque-user-variable",
            "opaque user-variable entries cannot be initialized natively",
        );
    }
    if argument
        .class_name()
        .is_some_and(|class| !matches!(class, "Argument" | "org.apache.jmeter.config.Argument"))
    {
        return unsupported_feature(
            &argument_source,
            "runtime.plan.user-variable-type",
            "TestPlan.user_defined_variables entries must use the JMeter Argument element type",
        );
    }
    ensure_allowed_embedded(
        &argument_source,
        argument,
        "Argument",
        &["Argument.name", "Argument.value", "Argument.metadata"],
    )?;
    let metadata = embedded_string(
        &argument_source,
        "Argument",
        argument,
        "Argument.metadata",
        "=",
    )?;
    if metadata != "=" {
        return unsupported_feature(
            &argument_source,
            "runtime.plan.user-variable-metadata",
            "non-default Argument.metadata is not represented by the initial-variable seed",
        );
    }
    let name = argument
        .properties
        .get("Argument.name")
        .map(|value| scalar_string(&argument_source, "Argument", "Argument.name", value))
        .unwrap_or_else(|| Ok(argument.name.clone()))?;
    let value = argument
        .properties
        .get("Argument.value")
        .map(|value| scalar_string(&argument_source, "Argument", "Argument.value", value))
        .unwrap_or_else(|| Ok(String::new()))?;
    Ok((name, value))
}

fn initial_variables_error(source: &SourceRef, error: InitialVariablesError) -> PlanCompileError {
    match error {
        InitialVariablesError::CountLimit { actual, limit }
        | InitialVariablesError::NameLimit { actual, limit }
        | InitialVariablesError::ValueLimit { actual, limit }
        | InitialVariablesError::TotalBytesLimit { actual, limit } => PlanCompileError::Limit {
            kind: PlanLimitKind::InitialVariables,
            actual,
            limit,
            source: Some(source.clone()),
        },
        // The JMeter projection accepts empty names and discards duplicate
        // entries before construction.  These branches are defensive in
        // case the policy constructor changes; keep their diagnostics free
        // of source values.
        InitialVariablesError::EmptyName => PlanCompileError::InvalidProperty {
            source: source.clone(),
            test_class: "TestPlan".to_owned(),
            property: "TestPlan.user_defined_variables".to_owned(),
            detail: "initial-variable name rejected by JMeter policy".to_owned(),
        },
        InitialVariablesError::DuplicateName { .. } => PlanCompileError::InvalidProperty {
            source: source.clone(),
            test_class: "TestPlan".to_owned(),
            property: "TestPlan.user_defined_variables".to_owned(),
            detail: "duplicate initial-variable name rejected by JMeter policy".to_owned(),
        },
    }
}

fn validate_test_plan_properties(
    source: &SourceRef,
    element: &TestElement,
) -> Result<(), PlanCompileError> {
    ensure_allowed_properties(
        source,
        element,
        "TestPlan",
        &[
            "TestPlan.functional_mode",
            "TestPlan.serialize_threadgroups",
            "TestPlan.user_defined_variables",
            "TestPlan.thread_groups",
            "TestPlan.comments",
            "TestPlan.user_define_classpath",
            "TestPlan.tearDown_on_shutdown",
        ],
    )?;
    let functional_mode = bool_property(
        source,
        "TestPlan",
        element,
        "TestPlan.functional_mode",
        false,
    )?;
    if functional_mode {
        return unsupported_feature(
            source,
            "runtime.plan.functional-mode",
            "TestPlan.functional_mode changes result-data behavior outside the engine draft",
        );
    }
    let _ = bool_property(
        source,
        "TestPlan",
        element,
        "TestPlan.serialize_threadgroups",
        false,
    )?;
    let _ = bool_property(
        source,
        "TestPlan",
        element,
        "TestPlan.tearDown_on_shutdown",
        false,
    )?;
    if let Some(value) = element.property("TestPlan.comments") {
        let _ = scalar_string(source, "TestPlan", "TestPlan.comments", value)?;
    }
    if let Some(value) = element.property("TestPlan.user_define_classpath") {
        let classpath = scalar_string(source, "TestPlan", "TestPlan.user_define_classpath", value)?;
        if !classpath.is_empty() {
            return unsupported_feature(
                source,
                "runtime.plan.user-classpath",
                "TestPlan.user_define_classpath requires external classpath setup",
            );
        }
    }
    if let Some(value) = element.property("TestPlan.thread_groups") {
        match value {
            PropertyValue::Collection(values) if values.is_empty() => {}
            PropertyValue::NamedCollection(values) if values.is_empty() => {}
            PropertyValue::Map(values) if values.is_empty() => {}
            PropertyValue::Collection(_)
            | PropertyValue::NamedCollection(_)
            | PropertyValue::Map(_) => {
                return unsupported_feature(
                    source,
                    "runtime.plan.thread-groups-property",
                    "TestPlan.thread_groups is a legacy serialized property and must be empty",
                );
            }
            other => {
                return Err(invalid_property(
                    source,
                    "TestPlan",
                    "TestPlan.thread_groups",
                    format!("expected collection, found {}", other.kind()),
                ));
            }
        }
    }
    Ok(())
}

fn ensure_allowed_properties(
    source: &SourceRef,
    element: &TestElement,
    class: &str,
    allowed: &[&str],
) -> Result<(), PlanCompileError> {
    for property in element.properties.keys() {
        if !allowed.contains(&property) {
            return Err(PlanCompileError::UnsupportedProperty {
                source: source.clone(),
                test_class: bounded(class),
                property: bounded(property),
            });
        }
    }
    Ok(())
}

fn ensure_allowed_embedded(
    source: &SourceRef,
    element: &ElementProperty,
    class: &str,
    allowed: &[&str],
) -> Result<(), PlanCompileError> {
    for property in element.properties.keys() {
        if !allowed.contains(&property) {
            return Err(PlanCompileError::UnsupportedProperty {
                source: source.clone(),
                test_class: bounded(class),
                property: bounded(property),
            });
        }
    }
    Ok(())
}

fn loop_count(
    source: &SourceRef,
    class: &str,
    element: &ElementProperty,
    root_controller: bool,
) -> Result<(LoopCount, bool), PlanCompileError> {
    let continue_forever = embedded_bool(
        source,
        class,
        element,
        "LoopController.continue_forever",
        !root_controller,
    )?;
    let loops = embedded_i32(source, class, element, "LoopController.loops", 0)?;
    if loops < -1 {
        return invalid_embedded(
            source,
            class,
            "LoopController.loops",
            "value must be -1 or non-negative",
        );
    }
    let count = if loops == -1 {
        LoopCount::Forever
    } else {
        LoopCount::Finite(loops as u64)
    };
    Ok((count, continue_forever))
}

fn condition_from_embedded(
    source: &SourceRef,
    class: &str,
    element: &ElementProperty,
    while_controller: bool,
    use_expression: bool,
) -> Result<LogicCondition, PlanCompileError> {
    let property = if while_controller {
        "WhileController.condition"
    } else {
        "IfController.condition"
    };
    let value = embedded_string(source, class, element, property, "")?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        if while_controller {
            return unsupported_feature(
                source,
                "runtime.logic.while-condition-state",
                "an empty WhileController condition depends on last-sample initialization",
            );
        }
        return Ok(LogicCondition::Never);
    }
    if while_controller && trimmed == "LAST" {
        return unsupported_feature(
            source,
            "runtime.logic.while-condition-state",
            "WhileController LAST requires first-visit and last-sample state not represented by this draft",
        );
    }
    if matches!(
        trimmed.to_ascii_lowercase().as_str(),
        "true" | "false" | "1" | "0" | "yes" | "no" | "on" | "off"
    ) {
        return Ok(LogicCondition::Literal(trimmed.to_owned()));
    }
    if let Some(name) = simple_variable(trimmed) {
        return Ok(LogicCondition::VariableBoolean { name });
    }
    let capability_id = if use_expression {
        "runtime.logic.if-expression"
    } else {
        "runtime.logic.if-javascript"
    };
    Err(PlanCompileError::UnsupportedFeature {
        source: source.clone(),
        capability_id: capability_id.to_owned(),
        detail: "condition requires an expression evaluator outside the native compiler".to_owned(),
    })
}

fn simple_variable(value: &str) -> Option<String> {
    let name = value.strip_prefix("${")?.strip_suffix('}')?;
    if name.is_empty()
        || !name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '.'))
    {
        return None;
    }
    Some(name.to_owned())
}

fn sample_error_policy(
    source: &SourceRef,
    class: &str,
    element: &TestElement,
    property: &str,
) -> Result<SampleErrorPolicy, PlanCompileError> {
    let value = string_property(source, class, element, property, "continue")?;
    match value.trim().to_ascii_lowercase().as_str() {
        "continue" => Ok(SampleErrorPolicy::Continue),
        "startnextloop" => Ok(SampleErrorPolicy::StartNextLoop),
        "stopthread" => Ok(SampleErrorPolicy::StopThread),
        "stoptest" => Ok(SampleErrorPolicy::StopTestGraceful),
        "stoptestnow" => Ok(SampleErrorPolicy::StopTestImmediate),
        _ => Err(PlanCompileError::InvalidProperty {
            source: source.clone(),
            test_class: bounded(class),
            property: property.to_owned(),
            detail: "unknown sample error policy".to_owned(),
        }),
    }
}

fn string_property(
    source: &SourceRef,
    class: &str,
    element: &TestElement,
    property: &str,
    default: &str,
) -> Result<String, PlanCompileError> {
    element
        .property(property)
        .map(|value| scalar_string(source, class, property, value))
        .unwrap_or_else(|| Ok(default.to_owned()))
}

fn usize_property(
    source: &SourceRef,
    class: &str,
    element: &TestElement,
    property: &str,
    default: usize,
) -> Result<usize, PlanCompileError> {
    let value = i64_property(source, class, element, property, default as i64)?;
    if value < 0 {
        return Err(PlanCompileError::InvalidProperty {
            source: source.clone(),
            test_class: bounded(class),
            property: property.to_owned(),
            detail: "value must be non-negative".to_owned(),
        });
    }
    if value > i64::from(i32::MAX) {
        return Err(PlanCompileError::InvalidProperty {
            source: source.clone(),
            test_class: bounded(class),
            property: property.to_owned(),
            detail: "value exceeds JMeter's signed 32-bit property range".to_owned(),
        });
    }
    usize::try_from(value).map_err(|_| PlanCompileError::InvalidProperty {
        source: source.clone(),
        test_class: bounded(class),
        property: property.to_owned(),
        detail: "value exceeds the host usize bound".to_owned(),
    })
}

fn i64_property(
    source: &SourceRef,
    class: &str,
    element: &TestElement,
    property: &str,
    default: i64,
) -> Result<i64, PlanCompileError> {
    element
        .property(property)
        .map(|value| scalar_i64(source, class, property, value))
        .unwrap_or(Ok(default))
}

fn bool_property(
    source: &SourceRef,
    class: &str,
    element: &TestElement,
    property: &str,
    default: bool,
) -> Result<bool, PlanCompileError> {
    element
        .property(property)
        .map(|value| scalar_bool(source, class, property, value))
        .unwrap_or(Ok(default))
}

fn seconds_property(
    source: &SourceRef,
    class: &str,
    element: &TestElement,
    property: &str,
    default: Duration,
) -> Result<Duration, PlanCompileError> {
    let Some(value) = element.property(property) else {
        return Ok(default);
    };
    match value {
        PropertyValue::String(value) if value.trim().is_empty() => Ok(default),
        _ => duration_value(source, class, property, value),
    }
}

fn optional_seconds_property(
    source: &SourceRef,
    class: &str,
    element: &TestElement,
    property: &str,
) -> Result<Option<Duration>, PlanCompileError> {
    let Some(value) = element.property(property) else {
        return Ok(None);
    };
    if matches!(value, PropertyValue::String(value) if value.trim().is_empty()) {
        return Ok(None);
    }
    duration_value(source, class, property, value).map(Some)
}

fn duration_value(
    source: &SourceRef,
    class: &str,
    property: &str,
    value: &PropertyValue,
) -> Result<Duration, PlanCompileError> {
    match value {
        PropertyValue::String(value) => duration_seconds(source, class, property, value),
        PropertyValue::Integer(value) => {
            duration_integer(source, class, property, i64::from(*value))
        }
        PropertyValue::Long(value) => duration_integer(source, class, property, *value),
        _ => Err(invalid_property(
            source,
            class,
            property,
            format!("expected seconds value, found {:?}", value.kind()),
        )),
    }
}

fn duration_integer(
    source: &SourceRef,
    class: &str,
    property: &str,
    value: i64,
) -> Result<Duration, PlanCompileError> {
    let seconds = u64::try_from(value).map_err(|_| PlanCompileError::InvalidProperty {
        source: source.clone(),
        test_class: bounded(class),
        property: property.to_owned(),
        detail: "duration must be an unsigned number of seconds".to_owned(),
    })?;
    Ok(checked_duration_secs(seconds))
}

fn checked_duration_secs(seconds: u64) -> Duration {
    // `std::time::Duration` stores seconds as an unsigned 64-bit field, so
    // every JMeter long value accepted above has a direct, non-saturating
    // representation here.
    Duration::from_secs(seconds)
}

fn duration_seconds(
    source: &SourceRef,
    class: &str,
    property: &str,
    value: &str,
) -> Result<Duration, PlanCompileError> {
    let seconds = value
        .parse::<i64>()
        .map_err(|_| PlanCompileError::InvalidProperty {
            source: source.clone(),
            test_class: bounded(class),
            property: property.to_owned(),
            detail: "duration must be a signed 64-bit number of seconds".to_owned(),
        })?;
    duration_integer(source, class, property, seconds)
}

fn scalar_string(
    source: &SourceRef,
    class: &str,
    property: &str,
    value: &PropertyValue,
) -> Result<String, PlanCompileError> {
    match value {
        PropertyValue::String(value) => Ok(value.clone()),
        _ => Err(invalid_property(
            source,
            class,
            property,
            format!("expected string, found {:?}", value.kind()),
        )),
    }
}

fn scalar_i64(
    source: &SourceRef,
    class: &str,
    property: &str,
    value: &PropertyValue,
) -> Result<i64, PlanCompileError> {
    match value {
        PropertyValue::Integer(value) => Ok(i64::from(*value)),
        PropertyValue::Long(value) => Ok(*value),
        PropertyValue::String(value) => value.parse::<i64>().map_err(|_| {
            invalid_property(source, class, property, "invalid signed integer".to_owned())
        }),
        _ => Err(invalid_property(
            source,
            class,
            property,
            format!("expected integer, found {:?}", value.kind()),
        )),
    }
}

fn scalar_bool(
    source: &SourceRef,
    class: &str,
    property: &str,
    value: &PropertyValue,
) -> Result<bool, PlanCompileError> {
    match value {
        PropertyValue::Boolean(value) => Ok(*value),
        _ => Err(invalid_property(
            source,
            class,
            property,
            format!("expected boolean, found {:?}", value.kind()),
        )),
    }
}

fn scalar_f64(
    source: &SourceRef,
    class: &str,
    property: &str,
    value: &PropertyValue,
) -> Result<f64, PlanCompileError> {
    let value = match value {
        PropertyValue::Float(value) => f64::from(*value),
        PropertyValue::Double(value) => *value,
        PropertyValue::Integer(value) => f64::from(*value),
        PropertyValue::Long(value) => *value as f64,
        PropertyValue::String(value) => value.parse::<f64>().map_err(|_| {
            invalid_property(
                source,
                class,
                property,
                "invalid floating-point value".to_owned(),
            )
        })?,
        value => {
            return Err(invalid_property(
                source,
                class,
                property,
                format!("expected number, found {:?}", value.kind()),
            ));
        }
    };
    if !value.is_finite() {
        return Err(invalid_property(
            source,
            class,
            property,
            "value must be finite".to_owned(),
        ));
    }
    Ok(value)
}

fn embedded_string(
    source: &SourceRef,
    class: &str,
    element: &ElementProperty,
    property: &str,
    default: &str,
) -> Result<String, PlanCompileError> {
    element
        .properties
        .get(property)
        .map(|value| scalar_string(source, class, property, value))
        .unwrap_or_else(|| Ok(default.to_owned()))
}

fn embedded_i64(
    source: &SourceRef,
    class: &str,
    element: &ElementProperty,
    property: &str,
    default: i64,
) -> Result<i64, PlanCompileError> {
    element
        .properties
        .get(property)
        .map(|value| scalar_i64(source, class, property, value))
        .unwrap_or(Ok(default))
}

fn embedded_i32(
    source: &SourceRef,
    class: &str,
    element: &ElementProperty,
    property: &str,
    default: i32,
) -> Result<i32, PlanCompileError> {
    let value = embedded_i64(source, class, element, property, i64::from(default))?;
    i32::try_from(value).map_err(|_| {
        invalid_property(
            source,
            class,
            property,
            "value exceeds JMeter's signed 32-bit property range",
        )
    })
}

fn embedded_bool(
    source: &SourceRef,
    class: &str,
    element: &ElementProperty,
    property: &str,
    default: bool,
) -> Result<bool, PlanCompileError> {
    element
        .properties
        .get(property)
        .map(|value| scalar_bool(source, class, property, value))
        .unwrap_or(Ok(default))
}

fn embedded_f64(
    source: &SourceRef,
    class: &str,
    element: &ElementProperty,
    property: &str,
    default: f64,
) -> Result<f64, PlanCompileError> {
    element
        .properties
        .get(property)
        .map(|value| scalar_f64(source, class, property, value))
        .unwrap_or(Ok(default))
}

fn invalid_property(
    source: &SourceRef,
    class: &str,
    property: &str,
    detail: impl Into<String>,
) -> PlanCompileError {
    PlanCompileError::InvalidProperty {
        source: source.clone(),
        test_class: bounded(class),
        property: property.to_owned(),
        detail: bounded(detail),
    }
}

fn invalid_embedded<T>(
    source: &SourceRef,
    class: &str,
    property: &str,
    detail: impl Into<String>,
) -> Result<T, PlanCompileError> {
    Err(invalid_property(source, class, property, detail))
}

fn unsupported_feature<T>(
    source: &SourceRef,
    capability_id: &str,
    detail: impl Into<String>,
) -> Result<T, PlanCompileError> {
    Err(PlanCompileError::UnsupportedFeature {
        source: source.clone(),
        capability_id: bounded(capability_id),
        detail: bounded(detail),
    })
}

fn model_tree_error(error: jmeter_rs_model::TreeError) -> PlanCompileError {
    PlanCompileError::Tree {
        detail: bounded(error.to_string()),
    }
}

fn model_error(error: ModelError) -> PlanCompileError {
    PlanCompileError::Tree {
        detail: bounded(error.to_string()),
    }
}

fn bounded(value: impl Into<String>) -> String {
    let mut value = value.into();
    if value.len() > MAX_DIAGNOSTIC_BYTES {
        let mut end = MAX_DIAGNOSTIC_BYTES;
        while end > 0 && !value.is_char_boundary(end) {
            end -= 1;
        }
        value.truncate(end);
    }
    value
}

fn sha256_bytes(input: &[u8]) -> [u8; 32] {
    const INITIAL: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    const ROUND: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];
    let mut state = INITIAL;
    let mut block = [0_u8; 64];
    let mut used = 0_usize;
    for byte in input {
        block[used] = *byte;
        used += 1;
        if used == block.len() {
            sha256_compress(&mut state, &block, &ROUND);
            used = 0;
        }
    }
    block[used] = 0x80;
    used += 1;
    if used > 56 {
        block[used..].fill(0);
        sha256_compress(&mut state, &block, &ROUND);
        block.fill(0);
    } else {
        block[used..56].fill(0);
    }
    let bit_len = (input.len() as u64).wrapping_mul(8);
    block[56..].copy_from_slice(&bit_len.to_be_bytes());
    sha256_compress(&mut state, &block, &ROUND);

    let mut digest = [0_u8; 32];
    for (index, word) in state.into_iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

fn sha256_compress(state: &mut [u32; 8], block: &[u8; 64], round: &[u32; 64]) {
    let mut schedule = [0_u32; 64];
    for (index, chunk) in block.chunks_exact(4).enumerate() {
        schedule[index] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    for index in 16..64 {
        let s0 = schedule[index - 15].rotate_right(7)
            ^ schedule[index - 15].rotate_right(18)
            ^ (schedule[index - 15] >> 3);
        let s1 = schedule[index - 2].rotate_right(17)
            ^ schedule[index - 2].rotate_right(19)
            ^ (schedule[index - 2] >> 10);
        schedule[index] = schedule[index - 16]
            .wrapping_add(s0)
            .wrapping_add(schedule[index - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for index in 0..64 {
        let sigma1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let choose = (e & f) ^ ((!e) & g);
        let temp1 = h
            .wrapping_add(sigma1)
            .wrapping_add(choose)
            .wrapping_add(round[index])
            .wrapping_add(schedule[index]);
        let sigma0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = sigma0.wrapping_add(majority);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "deterministic compiler fixtures")]
mod tests {
    use super::*;
    use crate::MAX_INITIAL_VARIABLE_VALUE_BYTES;

    fn root_controller(loops: i64) -> PropertyValue {
        let mut root =
            ElementProperty::new("ThreadGroup.main_controller").with_class_name("LoopController");
        root.properties.insert(
            "LoopController.continue_forever",
            PropertyValue::boolean(false),
        );
        root.properties.insert(
            "LoopController.loops",
            PropertyValue::string(loops.to_string()),
        );
        PropertyValue::Element(root)
    }

    fn plan_with_children(children: Vec<TestElement>) -> ElementTree {
        let mut tree = ElementTree::new();
        let mut plan = TestElement::named("TestPlan", "TestPlanGui", "plan");
        plan.set_property(
            "TestPlan.serialize_threadgroups",
            PropertyValue::boolean(false),
        );
        let plan_id = tree.insert_root(plan).expect("plan");
        let mut group = TestElement::named("ThreadGroup", "ThreadGroupGui", "main");
        group.set_property("ThreadGroup.main_controller", root_controller(2));
        group.set_property("ThreadGroup.num_threads", PropertyValue::string("1"));
        group.set_property("ThreadGroup.scheduler", PropertyValue::boolean(false));
        group.set_property("ThreadGroup.ramp_time", PropertyValue::string("0"));
        group.set_property("ThreadGroup.delay", PropertyValue::string(""));
        group.set_property("ThreadGroup.duration", PropertyValue::string(""));
        group.set_property("ThreadGroup.start_time", PropertyValue::long(0));
        group.set_property("ThreadGroup.end_time", PropertyValue::long(0));
        let group_id = tree.insert_child(plan_id, group).expect("group");
        for child in children {
            tree.insert_child(group_id, child).expect("child");
        }
        tree
    }

    #[test]
    fn index_preserves_order_paths_and_disabled_subtrees() {
        let mut disabled = TestElement::named("DebugSampler", "TestBeanGUI", "disabled");
        disabled.set_enabled(false);
        let tree = plan_with_children(vec![
            TestElement::named("DebugSampler", "TestBeanGUI", "first"),
            disabled,
            TestElement::named("DebugSampler", "TestBeanGUI", "last"),
        ]);
        let compiler = PlanCompiler::new(ComponentRegistry::builtins(), PlanCompileLimits::small());
        let plan = compiler.compile_tree(&tree).expect("compile");
        assert_eq!(plan.index.preorder().len(), 5);
        assert_eq!(plan.index.disabled_ids().len(), 1);
        assert_eq!(
            plan.index.executable_preorder(),
            &[
                NodeId::new(1),
                NodeId::new(2),
                NodeId::new(3),
                NodeId::new(5)
            ]
        );
        let first = plan.index.node(NodeId::new(3)).expect("first");
        assert_eq!(
            first.source.tree_path(),
            &[NodeId::new(1), NodeId::new(2), NodeId::new(3)]
        );
        assert_eq!(plan.groups.len(), 1);
        assert_eq!(plan.groups[0].kind, GroupKind::Main);
    }

    #[test]
    fn embedded_root_identity_and_loop_are_retained() {
        let tree = plan_with_children(vec![TestElement::named(
            "DebugSampler",
            "TestBeanGUI",
            "sample",
        )]);
        let plan = PlanCompiler::new(ComponentRegistry::builtins(), PlanCompileLimits::small())
            .compile_tree(&tree)
            .expect("compile");
        let group = &plan.groups[0];
        assert_eq!(group.root_controller.node_id(), Some(NodeId::new(2)));
        assert_eq!(
            group
                .root_controller
                .property_path()
                .map(<[String]>::to_vec),
            Some(vec!["ThreadGroup.main_controller".to_owned()])
        );
        assert_eq!(sample_count(&group.controller), 2);
    }

    #[test]
    fn nested_controller_mappings_are_bounded_and_ordered() {
        let mut loop_controller =
            TestElement::named("LoopController", "LoopControlPanel", "nested");
        loop_controller.set_property("LoopController.loops", PropertyValue::string("2"));
        loop_controller.set_property(
            "LoopController.continue_forever",
            PropertyValue::boolean(false),
        );
        let tree = plan_with_children(vec![loop_controller]);
        let mut tree = tree;
        let nested = NodeId::new(3);
        tree.insert_child(
            nested,
            TestElement::named("DebugSampler", "TestBeanGUI", "nested-sample"),
        )
        .expect("nested sample");
        let plan = PlanCompiler::new(ComponentRegistry::builtins(), PlanCompileLimits::small())
            .compile_tree(&tree)
            .expect("compile");
        let nested = plan.index.node(nested).expect("nested controller");
        assert_eq!(nested.category, IndexedCategory::Controller);
        assert_eq!(nested.parent, Some(NodeId::new(2)));
        assert_eq!(
            nested.source.tree_path(),
            &[NodeId::new(1), NodeId::new(2), NodeId::new(3)]
        );
    }

    #[test]
    fn fully_qualified_builtin_controller_aliases_keep_native_classification() {
        let mut tree = plan_with_children(Vec::new());
        let mut controller = TestElement::named(
            "org.apache.jmeter.control.LoopController",
            "LoopControlPanel",
            "qualified",
        );
        controller.set_property("LoopController.loops", PropertyValue::string("1"));
        controller.set_property(
            "LoopController.continue_forever",
            PropertyValue::boolean(false),
        );
        tree.insert_child(NodeId::new(2), controller)
            .expect("qualified controller");
        tree.insert_child(
            NodeId::new(3),
            TestElement::named("DebugSampler", "TestBeanGUI", "sample"),
        )
        .expect("qualified sampler");
        let compiler = PlanCompiler::builtins();
        let plan = compiler
            .compile_tree(&tree)
            .expect("qualified built-in controller");
        assert_eq!(
            plan.index.node(NodeId::new(3)).map(|node| node.category),
            Some(IndexedCategory::Controller)
        );
        let manifest = compiler
            .preflight_paths(&tree, &path_context())
            .expect("qualified path");
        assert_eq!(
            manifest
                .entries()
                .iter()
                .find(|entry| entry.source == SourceIdentity::node(NodeId::new(3)))
                .map(ImplementationPathIdentity::family),
            Some(ImplementationPathFamily::Native)
        );
    }

    #[test]
    fn registry_external_override_cannot_fall_back_to_native_fq_controller() {
        let mut tree = plan_with_children(Vec::new());
        let mut controller = TestElement::named(
            "org.apache.jmeter.control.LoopController",
            "LoopControlPanel",
            "external override",
        );
        controller.set_property("LoopController.loops", PropertyValue::string("1"));
        controller.set_property(
            "LoopController.continue_forever",
            PropertyValue::boolean(false),
        );
        tree.insert_child(NodeId::new(2), controller)
            .expect("external override controller");
        let mut registry = ComponentRegistry::new();
        registry.register(
            crate::ComponentBinding::native(
                "org.apache.jmeter.control.LoopController",
                ComponentCategory::Controller,
                "runtime.external.loop-controller",
            )
            .external(),
        );
        let compiler = PlanCompiler::new(registry, PlanCompileLimits::small());
        let manifest = compiler
            .preflight_paths(&tree, &path_context())
            .expect("external path preflight");
        assert_eq!(
            manifest
                .entries()
                .iter()
                .find(|entry| entry.source == SourceIdentity::node(NodeId::new(3)))
                .map(ImplementationPathIdentity::family),
            Some(ImplementationPathFamily::CompatJvm)
        );
    }

    #[test]
    fn fully_qualified_lifecycle_aliases_keep_native_plan_classification() {
        let mut tree = plan_with_children(Vec::new());
        tree.get_mut(NodeId::new(1))
            .expect("plan")
            .value_mut()
            .metadata
            .test_class = "org.apache.jmeter.testelement.TestPlan".to_owned();
        tree.get_mut(NodeId::new(2))
            .expect("group")
            .value_mut()
            .metadata
            .test_class = "org.apache.jmeter.threads.ThreadGroup".to_owned();
        let compiler = PlanCompiler::builtins();
        let draft = compiler
            .compile_tree(&tree)
            .expect("fully qualified lifecycle aliases compile");
        assert_eq!(
            draft.index.node(NodeId::new(1)).map(|node| node.category),
            Some(IndexedCategory::TestPlan)
        );
        assert_eq!(
            draft.index.node(NodeId::new(2)).map(|node| node.category),
            Some(IndexedCategory::ThreadGroup(GroupKind::Main))
        );
        let manifest = compiler
            .preflight_paths(&tree, &path_context())
            .expect("fully qualified lifecycle path preflight");
        assert!(manifest.entries().iter().any(|entry| {
            entry.source == SourceIdentity::node(NodeId::new(1))
                && entry.family() == ImplementationPathFamily::Native
        }));
        assert!(manifest.entries().iter().any(|entry| {
            entry.source == SourceIdentity::node(NodeId::new(2))
                && entry.family() == ImplementationPathFamily::Native
        }));
    }

    #[test]
    fn fully_qualified_open_model_group_is_unavailable_in_path_manifest() {
        let mut tree = plan_with_children(Vec::new());
        tree.get_mut(NodeId::new(2))
            .expect("group")
            .value_mut()
            .metadata
            .test_class = "org.apache.jmeter.threads.openmodel.OpenModelThreadGroup".to_owned();
        let compiler = PlanCompiler::builtins();
        assert_eq!(
            compiler
                .compile_tree(&tree)
                .expect_err("open-model lifecycle cannot compile")
                .code(),
            "runtime.plan.unsupported-feature"
        );
        let manifest = compiler
            .preflight_paths(&tree, &path_context())
            .expect("open-model path preflight");
        let path = manifest
            .entries()
            .iter()
            .find(|entry| entry.source == SourceIdentity::node(NodeId::new(2)))
            .expect("open-model path entry");
        assert_eq!(path.family(), ImplementationPathFamily::Unavailable);
        assert_eq!(
            path.path.unavailable_reason().map(|reason| reason.code),
            Some(UnavailableReasonCode::RequiresCompatibilityPack)
        );
    }

    #[test]
    fn opaque_and_unknown_enabled_nodes_fail_closed() {
        let tree = plan_with_children(vec![TestElement::named(
            "PluginController",
            "PluginGui",
            "unknown",
        )]);
        let mut opaque = BTreeSet::new();
        opaque.insert(NodeId::new(3));
        let source = SemanticSource::new(&tree).with_opaque(&opaque);
        let error = PlanCompiler::new(ComponentRegistry::builtins(), PlanCompileLimits::small())
            .compile(&source)
            .expect_err("opaque element must fail");
        assert_eq!(error.code(), "runtime.plan.unsupported-opaque");

        let error = PlanCompiler::builtins()
            .compile_tree(&tree)
            .expect_err("unknown element must fail");
        assert_eq!(error.code(), "runtime.plan.unsupported-class");
    }

    #[test]
    fn disabled_unknown_nodes_and_preservation_subtrees_do_not_block_compile() {
        let mut disabled_unknown = TestElement::named("MissingPlugin", "PluginGui", "disabled");
        disabled_unknown.set_enabled(false);
        let workbench_child = TestElement::named("MissingPlugin", "PluginGui", "saved");
        let tree = plan_with_children(vec![
            disabled_unknown,
            TestElement::named("WorkBench", "WorkBenchGui", "workbench"),
        ]);
        let mut tree = tree;
        tree.insert_child(NodeId::new(4), workbench_child)
            .expect("workbench child");

        let draft = PlanCompiler::builtins()
            .compile_tree(&tree)
            .expect("disabled/preservation-only nodes must not become executable");
        assert!(
            draft
                .index
                .node(NodeId::new(3))
                .is_some_and(|node| { !node.effective_enabled && !node.executable })
        );
        assert!(
            draft
                .index
                .node(NodeId::new(4))
                .is_some_and(|node| { node.effective_enabled && !node.executable })
        );
        assert!(
            draft
                .index
                .node(NodeId::new(5))
                .is_some_and(|node| { node.effective_enabled && !node.executable })
        );
        assert!(!draft.index.executable_preorder().contains(&NodeId::new(4)));
        assert!(!draft.index.executable_preorder().contains(&NodeId::new(5)));
        assert_eq!(draft.index.executable_len(), 2);
    }

    #[test]
    fn scheduler_decodes_delay_duration_and_ramp() {
        let mut tree = plan_with_children(vec![TestElement::named(
            "DebugSampler",
            "TestBeanGUI",
            "sample",
        )]);
        let group = tree.get_mut(NodeId::new(2)).expect("group").value_mut();
        group.set_property("ThreadGroup.scheduler", PropertyValue::boolean(true));
        group.set_property("ThreadGroup.ramp_time", PropertyValue::string("4"));
        group.set_property("ThreadGroup.delay", PropertyValue::string("2"));
        group.set_property("ThreadGroup.duration", PropertyValue::string("3"));
        let draft = PlanCompiler::builtins()
            .compile_tree(&tree)
            .expect("scheduler fields are representable");
        assert_eq!(
            draft.groups[0].schedule,
            GroupSchedule {
                delay: Duration::from_secs(2),
                ramp_up: Duration::from_secs(4),
                duration: Some(Duration::from_secs(3)),
            }
        );
    }

    #[test]
    fn scheduler_decodes_numeric_property_forms() {
        let mut tree = plan_with_children(vec![TestElement::named(
            "DebugSampler",
            "TestBeanGUI",
            "sample",
        )]);
        let group = tree.get_mut(NodeId::new(2)).expect("group").value_mut();
        group.set_property("ThreadGroup.scheduler", PropertyValue::boolean(true));
        group.set_property("ThreadGroup.ramp_time", PropertyValue::long(4));
        group.set_property("ThreadGroup.delay", PropertyValue::integer(2));
        group.set_property("ThreadGroup.duration", PropertyValue::long(3));
        let draft = PlanCompiler::builtins()
            .compile_tree(&tree)
            .expect("numeric scheduler fields are representable");
        assert_eq!(
            draft.groups[0].schedule,
            GroupSchedule {
                delay: Duration::from_secs(2),
                ramp_up: Duration::from_secs(4),
                duration: Some(Duration::from_secs(3)),
            }
        );
    }

    #[test]
    fn disabled_scheduler_ignores_delay_and_duration_but_keeps_ramp() {
        let mut tree = plan_with_children(vec![TestElement::named(
            "DebugSampler",
            "TestBeanGUI",
            "sample",
        )]);
        let group = tree.get_mut(NodeId::new(2)).expect("group").value_mut();
        group.set_property("ThreadGroup.scheduler", PropertyValue::boolean(false));
        group.set_property("ThreadGroup.ramp_time", PropertyValue::string("4"));
        group.set_property("ThreadGroup.delay", PropertyValue::string("2"));
        group.set_property("ThreadGroup.duration", PropertyValue::string("3"));
        let draft = PlanCompiler::builtins()
            .compile_tree(&tree)
            .expect("disabled scheduler fields are ignored");
        assert_eq!(
            draft.groups[0].schedule,
            GroupSchedule {
                delay: Duration::ZERO,
                ramp_up: Duration::from_secs(4),
                duration: None,
            }
        );
    }

    #[test]
    fn zero_legacy_scheduler_times_are_accepted_as_placeholders() {
        let mut tree = plan_with_children(vec![TestElement::named(
            "DebugSampler",
            "TestBeanGUI",
            "sample",
        )]);
        let group = tree.get_mut(NodeId::new(2)).expect("group").value_mut();
        group.set_property("ThreadGroup.scheduler", PropertyValue::boolean(true));
        group.set_property("ThreadGroup.start_time", PropertyValue::long(0));
        group.set_property("ThreadGroup.end_time", PropertyValue::long(0));
        group.set_property("ThreadGroup.duration", PropertyValue::string("1"));
        let draft = PlanCompiler::builtins()
            .compile_tree(&tree)
            .expect("zero legacy values are placeholders");
        assert_eq!(
            draft.groups[0].schedule,
            GroupSchedule {
                duration: Some(Duration::from_secs(1)),
                ..GroupSchedule::default()
            }
        );
    }

    #[test]
    fn nonzero_legacy_scheduler_times_fail_with_boundary_capability() {
        for property in ["ThreadGroup.start_time", "ThreadGroup.end_time"] {
            let mut tree = plan_with_children(vec![TestElement::named(
                "DebugSampler",
                "TestBeanGUI",
                "sample",
            )]);
            tree.get_mut(NodeId::new(2))
                .expect("group")
                .value_mut()
                .set_property(property, PropertyValue::long(1));
            let error = PlanCompiler::builtins()
                .compile_tree(&tree)
                .expect_err("absolute legacy boundary must fail closed");
            match error {
                PlanCompileError::UnsupportedFeature {
                    capability_id,
                    detail,
                    ..
                } => {
                    assert_eq!(capability_id, "runtime.lifecycle.scheduler-boundary");
                    assert!(detail.contains(property));
                }
                other => panic!("unexpected legacy boundary error: {other:?}"),
            }
        }
    }

    #[test]
    fn invalid_scheduler_values_fail_as_typed_properties() {
        for (property, value) in [
            ("ThreadGroup.delay", "-1"),
            ("ThreadGroup.ramp_time", "-1"),
            ("ThreadGroup.duration", "18446744073709551616"),
        ] {
            let mut tree = plan_with_children(vec![TestElement::named(
                "DebugSampler",
                "TestBeanGUI",
                "sample",
            )]);
            tree.get_mut(NodeId::new(2))
                .expect("group")
                .value_mut()
                .set_property("ThreadGroup.scheduler", PropertyValue::boolean(true));
            tree.get_mut(NodeId::new(2))
                .expect("group")
                .value_mut()
                .set_property(property, PropertyValue::string(value));
            let error = PlanCompiler::builtins()
                .compile_tree(&tree)
                .expect_err("invalid schedule value must fail");
            match error {
                PlanCompileError::InvalidProperty {
                    property: actual, ..
                } => assert_eq!(actual, property),
                other => panic!("unexpected invalid schedule error: {other:?}"),
            }
        }
    }

    #[test]
    fn scheduler_missing_or_empty_duration_is_invalid() {
        for empty in [false, true] {
            let mut tree = plan_with_children(vec![TestElement::named(
                "DebugSampler",
                "TestBeanGUI",
                "sample",
            )]);
            let group = tree.get_mut(NodeId::new(2)).expect("group").value_mut();
            group.set_property("ThreadGroup.scheduler", PropertyValue::boolean(true));
            if empty {
                group.set_property("ThreadGroup.duration", PropertyValue::string(""));
            } else {
                group.remove_property("ThreadGroup.duration");
            }
            let error = PlanCompiler::builtins()
                .compile_tree(&tree)
                .expect_err("JMeter rejects a scheduler without positive duration");
            assert!(matches!(
                error,
                PlanCompileError::InvalidProperty { property, .. }
                    if property == "ThreadGroup.duration"
            ));
        }
    }

    #[test]
    fn scheduler_and_replacements_are_not_approximated() {
        let mut tree = plan_with_children(vec![TestElement::named(
            "ModuleController",
            "ModuleControllerGui",
            "module",
        )]);
        tree.get_mut(NodeId::new(2))
            .expect("group")
            .value_mut()
            .set_property("ThreadGroup.scheduler", PropertyValue::boolean(false));
        let error = PlanCompiler::builtins()
            .compile_tree(&tree)
            .expect_err("replacement must fail closed");
        match error {
            PlanCompileError::UnsupportedFeature { capability_id, .. } => {
                assert_eq!(capability_id, "runtime.controller.ModuleController");
            }
            other => panic!("unexpected replacement error: {other:?}"),
        }
    }

    #[test]
    fn enabled_external_component_is_rejected_during_preflight() {
        let tree = plan_with_children(vec![TestElement::named(
            "JSR223PostProcessor",
            "JSR223PostProcessorGui",
            "external processor",
        )]);
        let error = PlanCompiler::builtins()
            .compile_tree(&tree)
            .expect_err("external processor must be rejected before assembly");
        match error {
            PlanCompileError::UnsupportedFeature {
                source,
                capability_id,
                ..
            } => {
                assert_eq!(
                    source.tree_path(),
                    &[NodeId::new(1), NodeId::new(2), NodeId::new(3)]
                );
                assert_eq!(capability_id, "runtime.external.JSR223PostProcessor");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn setup_main_teardown_are_source_ordered() {
        let mut tree = ElementTree::new();
        let plan_id = tree
            .insert_root(TestElement::named("TestPlan", "TestPlanGui", "plan"))
            .expect("plan");
        for (class, name) in [
            ("SetupThreadGroup", "setup"),
            ("ThreadGroup", "main"),
            ("PostThreadGroup", "teardown"),
        ] {
            let mut group = TestElement::named(class, "ThreadGroupGui", name);
            group.set_property("ThreadGroup.main_controller", root_controller(1));
            group.set_property("ThreadGroup.scheduler", PropertyValue::boolean(false));
            group.set_property("ThreadGroup.start_time", PropertyValue::long(0));
            group.set_property("ThreadGroup.end_time", PropertyValue::long(0));
            tree.insert_child(plan_id, group).expect("group");
        }
        let draft = PlanCompiler::new(ComponentRegistry::builtins(), PlanCompileLimits::small())
            .compile_tree(&tree)
            .expect("compile");
        assert_eq!(
            draft
                .groups
                .iter()
                .map(|group| group.kind)
                .collect::<Vec<_>>(),
            vec![GroupKind::Setup, GroupKind::Main, GroupKind::Teardown]
        );
    }

    #[test]
    fn plan_properties_are_validated_without_mutating_source() {
        let mut tree = plan_with_children(Vec::new());
        tree.get_mut(NodeId::new(1))
            .expect("plan")
            .value_mut()
            .set_property("TestPlan.unknown", PropertyValue::string("x"));
        let before = tree.clone();
        let error = PlanCompiler::builtins()
            .compile_tree(&tree)
            .expect_err("unknown plan property");
        assert_eq!(error.code(), "runtime.plan.unsupported-property");
        assert_eq!(tree, before);
    }

    #[test]
    fn test_plan_wire_defaults_and_shutdown_property_are_exact() {
        let mut tree = plan_with_children(Vec::new());
        let default = PlanCompiler::builtins()
            .compile_tree(&tree)
            .expect("default TestPlan");
        assert!(!default.teardown_on_shutdown);

        tree.get_mut(NodeId::new(1))
            .expect("plan")
            .value_mut()
            .set_property(
                "TestPlan.tearDown_on_shutdown",
                PropertyValue::boolean(true),
            );
        let enabled = PlanCompiler::builtins()
            .compile_tree(&tree)
            .expect("canonical shutdown property");
        assert!(enabled.teardown_on_shutdown);

        tree.get_mut(NodeId::new(1))
            .expect("plan")
            .value_mut()
            .remove_property("TestPlan.tearDown_on_shutdown");
        tree.get_mut(NodeId::new(1))
            .expect("plan")
            .value_mut()
            .set_property("TestPlan.tearDownOnShutdown", PropertyValue::boolean(true));
        let error = PlanCompiler::builtins()
            .compile_tree(&tree)
            .expect_err("legacy non-wire spelling must not be accepted");
        assert!(matches!(
            error,
            PlanCompileError::UnsupportedProperty { property, .. }
                if property == "TestPlan.tearDownOnShutdown"
        ));
    }

    #[test]
    fn unsupported_test_plan_execution_properties_fail_closed() {
        for (property, value) in [
            ("TestPlan.functional_mode", PropertyValue::boolean(true)),
            (
                "TestPlan.user_define_classpath",
                PropertyValue::string("external/classes"),
            ),
        ] {
            let mut tree = plan_with_children(Vec::new());
            tree.get_mut(NodeId::new(1))
                .expect("plan")
                .value_mut()
                .set_property(property, value);
            let error = PlanCompiler::builtins()
                .compile_tree(&tree)
                .expect_err("unsupported TestPlan execution property");
            assert!(matches!(error, PlanCompileError::UnsupportedFeature { .. }));
        }
    }

    #[test]
    fn delayed_thread_start_is_explicitly_unsupported() {
        let mut tree = plan_with_children(Vec::new());
        tree.get_mut(NodeId::new(2))
            .expect("group")
            .value_mut()
            .set_property("ThreadGroup.delayedStart", PropertyValue::boolean(true));
        let error = PlanCompiler::builtins()
            .compile_tree(&tree)
            .expect_err("delayed startup requires lifecycle coordination");
        assert!(matches!(
            error,
            PlanCompileError::UnsupportedFeature { capability_id, .. }
                if capability_id == "runtime.lifecycle.delayed-start"
        ));
    }

    #[test]
    fn thread_group_num_threads_uses_jmeter_zero_default() {
        let mut tree = plan_with_children(Vec::new());
        tree.get_mut(NodeId::new(2))
            .expect("group")
            .value_mut()
            .remove_property("ThreadGroup.num_threads");
        let draft = PlanCompiler::builtins()
            .compile_tree(&tree)
            .expect("missing num_threads is a valid zero-user group");
        assert_eq!(draft.groups[0].threads, 0);
    }

    #[test]
    fn deeply_nested_controller_tree_hits_checked_depth_limit() {
        let mut tree = plan_with_children(Vec::new());
        let mut parent = NodeId::new(2);
        for index in 0..(PlanCompileLimits::small().max_depth + 2) {
            let id = tree
                .insert_child(
                    parent,
                    TestElement::named(
                        "GenericController",
                        "LogicControllerGui",
                        &index.to_string(),
                    ),
                )
                .expect("nested controller");
            parent = id;
        }
        let error = PlanCompiler::new(ComponentRegistry::builtins(), PlanCompileLimits::small())
            .compile_tree(&tree)
            .expect_err("deep controller tree must be bounded");
        assert!(matches!(
            error,
            PlanCompileError::Tree { .. }
                | PlanCompileError::Limit {
                    kind: PlanLimitKind::Depth,
                    ..
                }
        ));
    }

    fn path_context() -> PlanPathContext {
        PlanPathContext::new(
            ProfileIdentity::new("jmeter-5.6.3", 2, Digest32::from_bytes([0x11; 32]))
                .expect("profile"),
            Digest32::from_bytes([0x22; 32]),
            ProviderIdentity::new("standalone-native", "0.1").expect("provider"),
            Digest32::from_bytes([0x33; 32]),
        )
        .expect("path context")
    }

    #[test]
    fn digest32_sha256_matches_known_vector() {
        assert_eq!(
            Digest32::sha256(b"abc").as_bytes(),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
    }

    #[test]
    fn path_preflight_is_deterministic_and_accounts_for_closed_families() {
        let mut registry = ComponentRegistry::builtins();
        registry.register(
            crate::ComponentBinding::native(
                "RmiSampler",
                ComponentCategory::Sampler,
                "runtime.external.rmi.RmiSampler",
            )
            .external(),
        );
        let tree = plan_with_children(vec![
            TestElement::named("DebugSampler", "TestBeanGUI", "native"),
            TestElement::named("JSR223PostProcessor", "JSR223PostProcessorGui", "jvm"),
            TestElement::named("RmiSampler", "RmiSamplerGui", "rmi"),
            TestElement::named("MissingPlugin", "PluginGui", "unavailable"),
        ]);
        let compiler = PlanCompiler::new(registry, PlanCompileLimits::small());
        let context = path_context();
        let first = compiler
            .preflight_paths(&tree, &context)
            .expect("path preflight");
        let second = compiler
            .compile_path_manifest(&tree, &context)
            .expect("path preflight alias");
        assert_eq!(first, second);
        assert_eq!(first.plan_digest(), context.plan_digest);
        assert_eq!(first.capability_set_digest(), context.capability_set_digest);
        assert!(
            first
                .entries()
                .iter()
                .any(|entry| entry.source == SourceIdentity::node(NodeId::new(3))
                    && entry.family() == ImplementationPathFamily::Native)
        );
        assert!(
            first
                .entries()
                .iter()
                .any(|entry| entry.source == SourceIdentity::node(NodeId::new(4))
                    && entry.family() == ImplementationPathFamily::CompatJvm)
        );
        assert!(
            first
                .entries()
                .iter()
                .any(|entry| entry.source == SourceIdentity::node(NodeId::new(5))
                    && entry.family() == ImplementationPathFamily::CompatRmi)
        );
        let unavailable = first
            .entries()
            .iter()
            .find(|entry| entry.source == SourceIdentity::node(NodeId::new(6)))
            .expect("unavailable entry");
        assert_eq!(unavailable.family(), ImplementationPathFamily::Unavailable);
        assert!(
            first
                .entries()
                .iter()
                .any(|entry| { matches!(&entry.source, SourceIdentity::RunLevel { .. }) })
        );
    }

    #[test]
    fn every_builtin_binding_has_one_preflight_and_compile_classification() {
        let registry = ComponentRegistry::builtins();
        let compiler = PlanCompiler::new(registry.clone(), PlanCompileLimits::small());
        let context = path_context();

        for binding in registry.iter() {
            let category = classify(&registry, &binding.test_class);
            assert!(
                !matches!(category, IndexedCategory::Unknown),
                "{}",
                binding.test_class
            );

            // Lifecycle and preservation-only nodes are accounted for by the
            // index but do not become per-branch executable entries. Their
            // dedicated topology tests cover those paths separately.
            if matches!(
                category,
                IndexedCategory::TestPlan
                    | IndexedCategory::ThreadGroup(_)
                    | IndexedCategory::Ignored
                    | IndexedCategory::OpenModel
            ) {
                continue;
            }

            // Replacement nodes are registry-known, but their executable
            // path is unavailable until a resolved target is supplied.
            let effective_availability = if matches!(category, IndexedCategory::Replaceable) {
                crate::ComponentAvailability::Unavailable
            } else {
                binding.availability()
            };
            let expected_family = match effective_availability {
                crate::ComponentAvailability::Native => ImplementationPathFamily::Native,
                crate::ComponentAvailability::External => {
                    if binding.capability_id.contains(".rmi.") {
                        ImplementationPathFamily::CompatRmi
                    } else {
                        ImplementationPathFamily::CompatJvm
                    }
                }
                crate::ComponentAvailability::Unavailable => ImplementationPathFamily::Unavailable,
            };
            let direct_path = compiler
                .path_for_class(
                    &SourceRef::tree(vec![NodeId::new(3)]),
                    &binding.test_class,
                    category,
                )
                .expect("binding path classification");
            assert_eq!(
                direct_path.family(),
                expected_family,
                "{}",
                binding.test_class
            );

            let tree = plan_with_children(vec![TestElement::named(
                &binding.test_class,
                "TestBeanGUI",
                "binding",
            )]);
            let manifest = compiler
                .preflight_paths(&tree, &context)
                .expect("preflight binding tree");
            let entry = manifest
                .entries()
                .iter()
                .find(|entry| entry.source == SourceIdentity::node(NodeId::new(3)))
                .expect("preflight node entry");
            assert_eq!(
                entry.path.family(),
                expected_family,
                "{}",
                binding.test_class
            );

            let compiled = compiler.compile_tree(&tree);
            match effective_availability {
                crate::ComponentAvailability::Native => {
                    if binding.test_class == "WhileController" {
                        let error = compiled.expect_err(
                            "an empty WhileController condition must remain explicitly unsupported",
                        );
                        assert!(matches!(
                            error,
                            PlanCompileError::UnsupportedFeature { capability_id, .. }
                                if capability_id == "runtime.logic.while-condition-state"
                        ));
                    } else {
                        compiled.expect("native binding must compile");
                    }
                }
                crate::ComponentAvailability::External
                | crate::ComponentAvailability::Unavailable => {
                    let error = compiled.expect_err("non-native binding must fail closed");
                    assert!(
                        matches!(error, PlanCompileError::UnsupportedFeature { .. }),
                        "{}: {error:?}",
                        binding.test_class
                    );
                }
            }
        }
    }

    #[test]
    fn path_preflight_omits_disabled_opaque_and_preservation_only_nodes() {
        let mut disabled = TestElement::named("MissingPlugin", "PluginGui", "disabled");
        disabled.set_enabled(false);
        let mut tree = plan_with_children(vec![
            disabled,
            TestElement::named("WorkBench", "WorkBenchGui", "workbench"),
        ]);
        tree.insert_child(
            NodeId::new(4),
            TestElement::named("MissingPlugin", "PluginGui", "saved"),
        )
        .expect("preserved WorkBench child");
        tree.insert_child(
            NodeId::new(2),
            TestElement::named("MissingPlugin", "PluginGui", "opaque executable"),
        )
        .expect("opaque executable");
        let mut opaque = BTreeSet::new();
        opaque.insert(NodeId::new(6));
        let source = SemanticSource::new(&tree).with_opaque(&opaque);
        let manifest = PlanCompiler::builtins()
            .preflight_paths(&source, &path_context())
            .expect("path preflight");
        assert!(!manifest
            .entries()
            .iter()
            .any(|entry| matches!(&entry.source, SourceIdentity::Node { node_id } if *node_id == NodeId::new(3))));
        assert!(!manifest
            .entries()
            .iter()
            .any(|entry| matches!(&entry.source, SourceIdentity::Node { node_id } if *node_id == NodeId::new(4) || *node_id == NodeId::new(5))));
        assert!(!manifest
            .entries()
            .iter()
            .any(|entry| matches!(&entry.source, SourceIdentity::Node { node_id } if *node_id == NodeId::new(6))));
        assert_eq!(manifest.opaque_sources().len(), 1);
        assert_eq!(manifest.opaque_sources()[0].node_id(), Some(NodeId::new(6)));
    }

    #[test]
    fn native_path_manifest_can_be_admitted_atomically() {
        let tree = plan_with_children(vec![TestElement::named(
            "DebugSampler",
            "TestBeanGUI",
            "native",
        )]);
        let context = path_context();
        let manifest = PlanCompiler::builtins()
            .preflight_paths(&tree, &context)
            .expect("native path preflight");
        let capabilities = manifest
            .entries()
            .iter()
            .filter_map(|entry| entry.path.capability().cloned())
            .collect::<BTreeSet<_>>();
        let set = RuntimeCapabilitySet::standalone_native(
            context.profile.clone(),
            context.plan_digest,
            context.capability_set_digest,
            capabilities,
        )
        .expect("native capability set");
        let admission = manifest.admit(&set).expect("whole native plan admission");
        assert_eq!(admission.manifest().len(), manifest.len());
    }

    #[test]
    fn test_plan_user_variables_are_retained_in_deterministic_initial_state() {
        let mut tree = plan_with_children(Vec::new());
        let mut variables =
            ElementProperty::new("TestPlan.user_defined_variables").with_class_name("Arguments");
        let mut first = ElementProperty::new("first").with_class_name("Argument");
        first
            .properties
            .insert("Argument.name", PropertyValue::string("ZED"));
        first
            .properties
            .insert("Argument.value", PropertyValue::string("last"));
        first
            .properties
            .insert("Argument.metadata", PropertyValue::string("="));
        let mut second = ElementProperty::new("second").with_class_name("Argument");
        second
            .properties
            .insert("Argument.name", PropertyValue::string("ALPHA"));
        second
            .properties
            .insert("Argument.value", PropertyValue::string("first"));
        second
            .properties
            .insert("Argument.metadata", PropertyValue::string("="));
        variables.properties.insert(
            "Arguments.arguments",
            PropertyValue::collection(vec![
                PropertyValue::Element(first),
                PropertyValue::Element(second),
            ]),
        );
        tree.get_mut(NodeId::new(1))
            .expect("plan")
            .value_mut()
            .set_property(
                "TestPlan.user_defined_variables",
                PropertyValue::Element(variables),
            );
        let draft = PlanCompiler::builtins()
            .compile_tree(&tree)
            .expect("variables compile");
        assert_eq!(
            draft.initial_variables,
            BTreeMap::from([
                ("ALPHA".to_owned(), "first".to_owned()),
                ("ZED".to_owned(), "last".to_owned()),
            ])
        );
        let typed = draft.initial_variables_typed().expect("typed seed");
        assert_eq!(typed.get("ALPHA"), Some("first"));
        assert_eq!(typed.get("ZED"), Some("last"));
        let mut engine_plan = crate::EnginePlan::new();
        draft
            .apply_initial_variables(&mut engine_plan)
            .expect("engine seed");
        assert_eq!(engine_plan.initial_variables().get("ALPHA"), Some("first"));
    }

    #[test]
    fn first_duplicate_initial_variable_wins_in_source_order() {
        let mut tree = plan_with_children(Vec::new());
        let mut variables =
            ElementProperty::new("TestPlan.user_defined_variables").with_class_name("Arguments");
        let mut first = ElementProperty::new("first").with_class_name("Argument");
        first
            .properties
            .insert("Argument.name", PropertyValue::string("same"));
        first
            .properties
            .insert("Argument.value", PropertyValue::string("first"));
        let mut second = ElementProperty::new("second").with_class_name("Argument");
        second
            .properties
            .insert("Argument.name", PropertyValue::string("same"));
        second
            .properties
            .insert("Argument.value", PropertyValue::string("second"));
        variables.properties.insert(
            "Arguments.arguments",
            PropertyValue::collection(vec![
                PropertyValue::Element(first),
                PropertyValue::Element(second),
            ]),
        );
        tree.get_mut(NodeId::new(1))
            .expect("plan")
            .value_mut()
            .set_property(
                "TestPlan.user_defined_variables",
                PropertyValue::Element(variables),
            );
        let draft = PlanCompiler::builtins()
            .compile_tree(&tree)
            .expect("JMeter Arguments uses first duplicate");
        assert_eq!(
            draft.initial_variables,
            BTreeMap::from([(String::from("same"), String::from("first"))])
        );
    }

    #[test]
    fn empty_initial_variable_name_is_preserved_by_jmeter_projection() {
        let mut tree = plan_with_children(Vec::new());
        let mut variables =
            ElementProperty::new("TestPlan.user_defined_variables").with_class_name("Arguments");
        let mut empty = ElementProperty::new("empty").with_class_name("Argument");
        empty
            .properties
            .insert("Argument.name", PropertyValue::string(""));
        empty
            .properties
            .insert("Argument.value", PropertyValue::string("empty-key"));
        let mut duplicate = ElementProperty::new("duplicate").with_class_name("Argument");
        duplicate
            .properties
            .insert("Argument.name", PropertyValue::string(""));
        duplicate
            .properties
            .insert("Argument.value", PropertyValue::string("discarded"));
        variables.properties.insert(
            "Arguments.arguments",
            PropertyValue::collection(vec![
                PropertyValue::Element(empty),
                PropertyValue::Element(duplicate),
            ]),
        );
        tree.get_mut(NodeId::new(1))
            .expect("plan")
            .value_mut()
            .set_property(
                "TestPlan.user_defined_variables",
                PropertyValue::Element(variables),
            );

        let draft = PlanCompiler::builtins()
            .compile_tree(&tree)
            .expect("empty JMeter variable names are accepted");
        assert_eq!(
            draft.initial_variables,
            BTreeMap::from([(String::new(), String::from("empty-key"))])
        );
        let typed = draft.initial_variables_typed().expect("typed seed");
        assert_eq!(typed.get(""), Some("empty-key"));
    }

    #[test]
    fn duplicate_initial_variable_values_do_not_consume_canonical_bounds() {
        let mut tree = plan_with_children(Vec::new());
        let mut variables =
            ElementProperty::new("TestPlan.user_defined_variables").with_class_name("Arguments");
        let mut first = ElementProperty::new("first").with_class_name("Argument");
        first
            .properties
            .insert("Argument.name", PropertyValue::string("same"));
        first
            .properties
            .insert("Argument.value", PropertyValue::string("kept"));
        let mut duplicate = ElementProperty::new("duplicate").with_class_name("Argument");
        duplicate
            .properties
            .insert("Argument.name", PropertyValue::string("same"));
        duplicate.properties.insert(
            "Argument.value",
            PropertyValue::string(
                "secret-value-that-is-not-selected"
                    .repeat(MAX_INITIAL_VARIABLE_VALUE_BYTES / 32 + 1),
            ),
        );
        variables.properties.insert(
            "Arguments.arguments",
            PropertyValue::collection(vec![
                PropertyValue::Element(first),
                PropertyValue::Element(duplicate),
            ]),
        );
        tree.get_mut(NodeId::new(1))
            .expect("plan")
            .value_mut()
            .set_property(
                "TestPlan.user_defined_variables",
                PropertyValue::Element(variables),
            );

        let draft = PlanCompiler::builtins()
            .compile_tree(&tree)
            .expect("discarded duplicate is outside canonical bounds");
        assert_eq!(
            draft.initial_variables().get("same").map(String::as_str),
            Some("kept")
        );
    }

    #[test]
    fn initial_variable_source_collection_has_a_separate_finite_bound() {
        let mut tree = plan_with_children(Vec::new());
        let mut variables =
            ElementProperty::new("TestPlan.user_defined_variables").with_class_name("Arguments");
        let entries = (0..=MAX_INITIAL_VARIABLE_SOURCE_ENTRIES)
            .map(|index| {
                let mut argument =
                    ElementProperty::new(format!("source-{index}")).with_class_name("Argument");
                argument
                    .properties
                    .insert("Argument.name", PropertyValue::string("same"));
                PropertyValue::Element(argument)
            })
            .collect();
        variables
            .properties
            .insert("Arguments.arguments", PropertyValue::collection(entries));
        tree.get_mut(NodeId::new(1))
            .expect("plan")
            .value_mut()
            .set_property(
                "TestPlan.user_defined_variables",
                PropertyValue::Element(variables),
            );

        let error = PlanCompiler::builtins()
            .compile_tree(&tree)
            .expect_err("source collection bound");
        assert!(matches!(
            error,
            PlanCompileError::Limit {
                kind: PlanLimitKind::InitialVariables,
                actual,
                limit,
                ..
            } if actual == MAX_INITIAL_VARIABLE_SOURCE_ENTRIES + 1
                && limit == MAX_INITIAL_VARIABLE_SOURCE_ENTRIES
        ));
    }

    #[test]
    fn draft_initial_variable_failure_does_not_mutate_existing_plan_seed() {
        let tree = plan_with_children(Vec::new());
        let mut draft = PlanCompiler::builtins()
            .compile_tree(&tree)
            .expect("empty plan draft");
        draft.initial_variables.insert(
            String::from("invalid"),
            "secret-oversized-value".repeat(MAX_INITIAL_VARIABLE_VALUE_BYTES / 22 + 1),
        );
        let existing =
            InitialVariables::try_from_iter([(String::from("existing"), String::from("keep"))])
                .expect("existing seed");
        let mut plan = crate::EnginePlan::new().with_initial_variables(existing);

        let error = draft
            .apply_initial_variables(&mut plan)
            .expect_err("oversized draft seed");
        assert_eq!(error.code(), "runtime.initial-variables.value-limit");
        assert_eq!(plan.initial_variables().get("existing"), Some("keep"));
        assert_eq!(plan.initial_variables().get("invalid"), None);
    }

    #[test]
    fn oversized_initial_variable_fails_before_compilation_output() {
        let mut tree = plan_with_children(Vec::new());
        let mut variables =
            ElementProperty::new("TestPlan.user_defined_variables").with_class_name("Arguments");
        let mut argument = ElementProperty::new("large").with_class_name("Argument");
        argument
            .properties
            .insert("Argument.name", PropertyValue::string("large"));
        argument.properties.insert(
            "Argument.value",
            PropertyValue::string("x".repeat(MAX_INITIAL_VARIABLE_VALUE_BYTES + 1)),
        );
        variables.properties.insert(
            "Arguments.arguments",
            PropertyValue::collection(vec![PropertyValue::Element(argument)]),
        );
        tree.get_mut(NodeId::new(1))
            .expect("plan")
            .value_mut()
            .set_property(
                "TestPlan.user_defined_variables",
                PropertyValue::Element(variables),
            );
        let error = PlanCompiler::builtins()
            .compile_tree(&tree)
            .expect_err("oversized value is bounded");
        match error {
            PlanCompileError::Limit {
                kind: PlanLimitKind::InitialVariables,
                ..
            } => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn non_default_initial_variable_metadata_is_explicitly_unsupported() {
        let mut tree = plan_with_children(Vec::new());
        let mut variables =
            ElementProperty::new("TestPlan.user_defined_variables").with_class_name("Arguments");
        let mut argument = ElementProperty::new("argument").with_class_name("Argument");
        argument
            .properties
            .insert("Argument.name", PropertyValue::string("name"));
        argument
            .properties
            .insert("Argument.value", PropertyValue::string("value"));
        argument
            .properties
            .insert("Argument.metadata", PropertyValue::string(":"));
        variables.properties.insert(
            "Arguments.arguments",
            PropertyValue::collection(vec![PropertyValue::Element(argument)]),
        );
        tree.get_mut(NodeId::new(1))
            .expect("plan")
            .value_mut()
            .set_property(
                "TestPlan.user_defined_variables",
                PropertyValue::Element(variables),
            );
        let error = PlanCompiler::builtins()
            .compile_tree(&tree)
            .expect_err("non-default metadata must not be discarded");
        assert!(matches!(
            error,
            PlanCompileError::UnsupportedFeature { capability_id, .. }
                if capability_id == "runtime.plan.user-variable-metadata"
        ));
    }

    #[test]
    fn unknown_initial_variable_field_is_not_silently_dropped() {
        let mut tree = plan_with_children(Vec::new());
        let mut variables =
            ElementProperty::new("TestPlan.user_defined_variables").with_class_name("Arguments");
        let mut argument = ElementProperty::new("argument").with_class_name("Argument");
        argument
            .properties
            .insert("Argument.name", PropertyValue::string("name"));
        argument
            .properties
            .insert("Argument.value", PropertyValue::string("value"));
        argument
            .properties
            .insert("Argument.unknown", PropertyValue::string("opaque"));
        variables.properties.insert(
            "Arguments.arguments",
            PropertyValue::collection(vec![PropertyValue::Element(argument)]),
        );
        tree.get_mut(NodeId::new(1))
            .expect("plan")
            .value_mut()
            .set_property(
                "TestPlan.user_defined_variables",
                PropertyValue::Element(variables),
            );
        let error = PlanCompiler::builtins()
            .compile_tree(&tree)
            .expect_err("unknown nested fields must remain fail-closed");
        assert!(matches!(
            error,
            PlanCompileError::UnsupportedProperty { property, .. }
                if property == "Argument.unknown"
        ));
    }

    #[test]
    fn scope_component_with_enabled_descendant_is_not_silently_dropped() {
        let mut tree = plan_with_children(vec![TestElement::named(
            "ScopePreprocessor",
            "ScopePreprocessorGui",
            "scope",
        )]);
        tree.insert_child(
            NodeId::new(3),
            TestElement::named("DebugSampler", "TestBeanGUI", "invalid descendant"),
        )
        .expect("invalid scope descendant");
        let mut registry = ComponentRegistry::builtins();
        registry.register_native(
            "ScopePreprocessor",
            ComponentCategory::Preprocessor,
            "runtime.test.preprocessor",
        );
        let error = PlanCompiler::new(registry, PlanCompileLimits::small())
            .compile_tree(&tree)
            .expect_err("scope descendant must be diagnosed");
        match error {
            PlanCompileError::InvalidTopology { source, detail } => {
                assert_eq!(
                    source.and_then(|value| value.node_id()),
                    Some(NodeId::new(3))
                );
                assert!(detail.contains("scope components"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    fn sample_count(program: &LogicProgram) -> usize {
        let mut runner = program.runner();
        let mut count = 0;
        for _ in 0..128 {
            match runner
                .step(crate::LogicInput::default())
                .expect("logic step")
            {
                crate::LogicStep::Sample(_) => count += 1,
                crate::LogicStep::Complete => break,
                crate::LogicStep::NeedsRandom => continue,
                crate::LogicStep::Stopped(signal) => panic!("unexpected stop: {signal:?}"),
            }
        }
        count
    }
}
