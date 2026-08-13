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

use crate::{
    ComponentCategory, ComponentRegistry, GroupKind, GroupSchedule, LogicCondition,
    LogicControllerError, LogicLimits, LogicNode, LogicProgram, LoopCount, SampleErrorPolicy,
    SwitchSelection, ThroughputMode,
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
            },
            Self::InvalidTopology { .. } => "runtime.plan.invalid-topology",
            Self::UnsupportedOpaque { .. } => "runtime.plan.unsupported-opaque",
            Self::UnsupportedClass { .. } => "runtime.plan.unsupported-class",
            Self::UnsupportedProperty { .. } => "runtime.plan.unsupported-property",
            Self::InvalidProperty { .. } => "runtime.plan.invalid-property",
            Self::UnsupportedFeature { .. } => "runtime.plan.unsupported-feature",
            Self::IdentityExhausted { .. } => "runtime.plan.identity-exhausted",
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

/// One immutable lifecycle/controller compilation result.
#[derive(Clone, Debug)]
pub struct CompiledPlanDraft {
    /// Shared source index used by all groups and scope consumers.
    pub index: PlanIndex,
    /// Enabled setup/main/teardown groups in source order.
    pub groups: Vec<CompiledThreadGroupDraft>,
    /// Test Plan serialization policy.
    pub serialize_thread_groups: bool,
    /// Test Plan teardown-on-shutdown policy.
    pub teardown_on_shutdown: bool,
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
                    serialize_thread_groups: false,
                    teardown_on_shutdown: true,
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
        ensure_allowed_properties(
            &test_plan.source,
            test_plan_element,
            "TestPlan",
            &[
                "TestPlan.functional_mode",
                "TestPlan.serialize_threadgroups",
                "TestPlan.user_defined_variables",
                "TestPlan.thread_groups",
                "TestPlan.comments",
                "TestPlan.user_define_classpath",
                "TestPlan.tearDownOnShutdown",
            ],
        )?;
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
            "TestPlan.tearDownOnShutdown",
            true,
        )?;

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
                if matches!(
                    child.category,
                    IndexedCategory::Scope(_) | IndexedCategory::Ignored
                ) {
                    continue;
                }
                return Err(PlanCompileError::InvalidTopology {
                    source: Some(child.source.clone()),
                    detail: "only lifecycle groups may be direct executable TestPlan children"
                        .to_owned(),
                });
            };
            if groups.len() >= self.limits.max_groups {
                return Err(PlanCompileError::Limit {
                    kind: PlanLimitKind::Groups,
                    actual: groups.len().saturating_add(1),
                    limit: self.limits.max_groups,
                    source: Some(child.source.clone()),
                });
            }
            groups.push(self.compile_group(source, &index, child, kind, &mut ids)?);
        }

        Ok(CompiledPlanDraft {
            index,
            groups,
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
        let mut disabled = BTreeSet::new();
        let mut stack = Vec::with_capacity(roots.len());
        for id in roots.iter().rev().copied() {
            stack.push(IndexFrame {
                id,
                parent: None,
                path: vec![id],
                group_id: None,
                ancestor_enabled: true,
            });
        }
        while let Some(frame) = stack.pop() {
            if nodes.len() >= self.limits.max_nodes {
                return Err(PlanCompileError::Limit {
                    kind: PlanLimitKind::Nodes,
                    actual: nodes.len().saturating_add(1),
                    limit: self.limits.max_nodes,
                    source: Some(SourceRef::tree(frame.path)),
                });
            }
            let tree_node = tree.node(frame.id).map_err(model_tree_error)?;
            let element = tree_node.value();
            let depth = frame.path.len().saturating_sub(1);
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
                    group_id,
                    category,
                },
            );
            preorder.push(frame.id);

            for child_id in children.iter().rev().copied() {
                let mut path = frame.path.clone();
                path.push(child_id);
                stack.push(IndexFrame {
                    id: child_id,
                    parent: Some(frame.id),
                    path,
                    group_id,
                    ancestor_enabled: effective_enabled,
                });
            }
        }

        Ok(PlanIndex {
            roots,
            preorder,
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
            if source.is_opaque(*id) {
                return Err(PlanCompileError::UnsupportedOpaque {
                    source: node.source.clone(),
                    test_class: node.test_class.clone(),
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
            match node.category {
                IndexedCategory::Unknown => {
                    return Err(PlanCompileError::UnsupportedClass {
                        source: node.source.clone(),
                        test_class: node.test_class.clone(),
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
            1,
        )?;
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
                test_class: group.test_class.clone(),
                property: "ThreadGroup.main_controller".to_owned(),
                detail: "embedded controller has no elementType/testclass".to_owned(),
            }
        })?;
        let root_runtime_id = ids.allocate(&root_source)?;
        let children = self.compile_branch(source, index, &group.children, ids)?;
        let root_node = self.compile_controller_element(
            &root_source,
            root_class,
            root_element,
            children,
            root_runtime_id,
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
        let start_time = i64_property(source, class, element, "ThreadGroup.start_time", 0)?;
        let end_time = i64_property(source, class, element, "ThreadGroup.end_time", 0)?;
        if scheduler || start_time != 0 || end_time != 0 {
            return Err(PlanCompileError::UnsupportedFeature {
                source: source.clone(),
                capability_id: "runtime.lifecycle.scheduler-boundary".to_owned(),
                detail: "scheduler/start_time/end_time require the lifecycle scheduler extension"
                    .to_owned(),
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
        let duration = optional_seconds_property(source, class, element, "ThreadGroup.duration")?;
        Ok(GroupSchedule {
            delay,
            ramp_up,
            duration,
        })
    }

    fn compile_branch(
        &self,
        source: &dyn PlanSourceView,
        index: &PlanIndex,
        child_ids: &[NodeId],
        ids: &mut RuntimeIdAllocator,
    ) -> Result<Vec<CompiledChild>, PlanCompileError> {
        if child_ids.len() > self.limits.max_children {
            return Err(PlanCompileError::Limit {
                kind: PlanLimitKind::Children,
                actual: child_ids.len(),
                limit: self.limits.max_children,
                source: child_ids
                    .first()
                    .and_then(|id| index.node(*id))
                    .map(|node| node.source.clone()),
            });
        }
        let mut result = Vec::new();
        for child_id in child_ids {
            let child = index
                .node(*child_id)
                .ok_or_else(|| PlanCompileError::Tree {
                    detail: format!("index lost child node {child_id}"),
                })?;
            if !child.effective_enabled {
                continue;
            }
            match child.category {
                IndexedCategory::Controller => {
                    let node = self.compile_controller_node(source, index, child, ids)?;
                    result.push(CompiledChild {
                        name: child.name.clone(),
                        node,
                    });
                }
                IndexedCategory::Replaceable => {
                    return Err(PlanCompileError::UnsupportedFeature {
                        source: child.source.clone(),
                        capability_id: format!("runtime.controller.{}", child.test_class),
                        detail:
                            "Module/Include replacement must be resolved before native compilation"
                                .to_owned(),
                    });
                }
                IndexedCategory::Sampler => {
                    self.validate_sampler_children(index, child)?;
                    result.push(CompiledChild {
                        name: child.name.clone(),
                        node: LogicNode::Sample { id: child.id.get() },
                    });
                }
                IndexedCategory::Scope(_) | IndexedCategory::Ignored => {}
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
                        test_class: child.test_class.clone(),
                    });
                }
            }
        }
        Ok(result)
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
        }
        Ok(())
    }

    fn compile_controller_node(
        &self,
        source: &dyn PlanSourceView,
        index: &PlanIndex,
        node: &IndexedNode,
        ids: &mut RuntimeIdAllocator,
    ) -> Result<LogicNode, PlanCompileError> {
        let element = source.tree().value(node.id).map_err(model_tree_error)?;
        if !element.opaque_extensions.is_empty() {
            return unsupported_feature(
                &node.source,
                "runtime.plan.opaque-controller-extension",
                "opaque controller properties cannot execute natively",
            );
        }
        let mut properties =
            ElementProperty::new(node.name.clone()).with_class_name(node.test_class.clone());
        properties.properties = element.properties.clone();
        let children = self.compile_branch(source, index, &node.children, ids)?;
        let runtime_id = node.id.get();
        self.compile_controller_element(
            &node.source,
            node.test_class.as_str(),
            &properties,
            children,
            runtime_id,
        )
    }

    fn compile_controller_element(
        &self,
        source: &SourceRef,
        class: &str,
        element: &ElementProperty,
        children: Vec<CompiledChild>,
        runtime_id: u64,
    ) -> Result<LogicNode, PlanCompileError> {
        let child_names = children
            .iter()
            .map(|child| child.name.clone())
            .collect::<Vec<_>>();
        let nodes = children
            .into_iter()
            .map(|child| child.node)
            .collect::<Vec<_>>();
        match class {
            "GenericController" => {
                ensure_allowed_embedded(source, element, class, &[])?;
                Ok(LogicNode::Sequence {
                    id: runtime_id,
                    children: nodes,
                })
            }
            "LoopController" => {
                ensure_allowed_embedded(
                    source,
                    element,
                    class,
                    &["LoopController.continue_forever", "LoopController.loops"],
                )?;
                let count = loop_count(source, class, element)?;
                Ok(LogicNode::Loop {
                    id: runtime_id,
                    count,
                    children: nodes,
                })
            }
            "OnceOnlyController" => {
                ensure_allowed_embedded(source, element, class, &[])?;
                Ok(LogicNode::OnceOnly {
                    id: runtime_id,
                    children: nodes,
                })
            }
            "InterleaveControl" => {
                ensure_allowed_embedded(source, element, class, &["InterleaveControl.style"])?;
                let style = embedded_i64(source, class, element, "InterleaveControl.style", 0)?;
                if style != 0 {
                    return unsupported_feature(
                        source,
                        "runtime.controller.interleave-style",
                        "non-default InterleaveControl.style is not represented",
                    );
                }
                Ok(LogicNode::Interleave {
                    id: runtime_id,
                    children: nodes,
                })
            }
            "RandomController" => {
                ensure_allowed_embedded(source, element, class, &[])?;
                Ok(LogicNode::Random {
                    id: runtime_id,
                    children: nodes,
                })
            }
            "RandomOrderController" => {
                ensure_allowed_embedded(source, element, class, &[])?;
                Ok(LogicNode::RandomOrder {
                    id: runtime_id,
                    children: nodes,
                })
            }
            "ThroughputController" => {
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
                let style = embedded_i64(source, class, element, "ThroughputController.style", 0)?;
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
                let max = embedded_i64(
                    source,
                    class,
                    element,
                    "ThroughputController.maxThroughput",
                    0,
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
            "RunTime" | "RuntimeController" => {
                ensure_allowed_embedded(source, element, class, &["RunTime.seconds"])?;
                let seconds = embedded_i64(source, class, element, "RunTime.seconds", 0)?;
                // JMeter treats a negative RunTime value as an already-expired
                // deadline.  A zero duration has the same bounded native
                // behavior: the runner observes the deadline before selecting
                // the first child, so no sampler is visited.
                let duration = if seconds < 0 {
                    Duration::ZERO
                } else {
                    Duration::from_secs(seconds as u64)
                };
                Ok(LogicNode::Runtime {
                    id: runtime_id,
                    duration,
                    children: nodes,
                })
            }
            "IfController" => {
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
                let use_expression = embedded_bool(
                    source,
                    class,
                    element,
                    "IfController.useExpression",
                    true,
                )?;
                if !use_expression {
                    return unsupported_feature(
                        source,
                        "runtime.logic.if-variable-mode",
                        "IfController.useExpression=false requires JMeter variable-mode evaluation",
                    );
                }
                let condition = condition_from_embedded(source, class, element, false)?;
                let evaluate_each_iteration =
                    embedded_bool(source, class, element, "IfController.evaluateAll", false)?;
                Ok(LogicNode::If {
                    id: runtime_id,
                    condition,
                    evaluate_each_iteration,
                    children: nodes,
                })
            }
            "WhileController" => {
                ensure_allowed_embedded(source, element, class, &["WhileController.condition"])?;
                let condition = condition_from_embedded(source, class, element, true)?;
                Ok(LogicNode::While {
                    id: runtime_id,
                    condition,
                    max_iterations: None,
                    children: nodes,
                })
            }
            "ForEachController" | "ForeachController" => {
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
            "SwitchController" => {
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
            "TransactionController" => {
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
                        false,
                    )?,
                    children: nodes,
                })
            }
            "CriticalSectionController" => {
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
                test_class: class.to_owned(),
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
}

#[derive(Clone, Debug)]
struct CompiledChild {
    name: String,
    node: LogicNode,
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
    if class == "TestPlan" {
        return IndexedCategory::TestPlan;
    }
    if class == "OpenModelThreadGroup" {
        return IndexedCategory::OpenModel;
    }
    if class == "WorkBench" {
        return IndexedCategory::Ignored;
    }
    if let Some(kind) = group_kind(class) {
        return IndexedCategory::ThreadGroup(kind);
    }
    let Some(binding) = registry.get(class) else {
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

fn group_kind(class: &str) -> Option<GroupKind> {
    match class {
        "SetupThreadGroup" => Some(GroupKind::Setup),
        "ThreadGroup" => Some(GroupKind::Main),
        "PostThreadGroup" | "TearDownThreadGroup" => Some(GroupKind::Teardown),
        _ => None,
    }
}

fn embedded_source(group: &IndexedNode, property: &str) -> SourceRef {
    SourceRef::embedded(group.source.tree_path().to_vec(), vec![property.to_owned()])
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
                test_class: class.to_owned(),
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
                test_class: class.to_owned(),
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
) -> Result<LoopCount, PlanCompileError> {
    let continue_forever = embedded_bool(
        source,
        class,
        element,
        "LoopController.continue_forever",
        false,
    )?;
    let loops = embedded_i64(source, class, element, "LoopController.loops", 1)?;
    if continue_forever || loops == -1 {
        return Ok(LoopCount::Forever);
    }
    if loops < 0 {
        return invalid_embedded(
            source,
            class,
            "LoopController.loops",
            "value must be -1 or non-negative",
        );
    }
    Ok(LoopCount::Finite(loops as u64))
}

fn condition_from_embedded(
    source: &SourceRef,
    class: &str,
    element: &ElementProperty,
    while_controller: bool,
) -> Result<LogicCondition, PlanCompileError> {
    let property = if while_controller {
        "WhileController.condition"
    } else {
        "IfController.condition"
    };
    let value = embedded_string(source, class, element, property, "")?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(LogicCondition::Never);
    }
    if while_controller && trimmed == "LAST" {
        return Ok(LogicCondition::LastSampleSuccess { expected: true });
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
    Err(PlanCompileError::UnsupportedFeature {
        source: source.clone(),
        capability_id: "runtime.logic.condition-expression".to_owned(),
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
        "startnextloop" | "start_next_loop" => Ok(SampleErrorPolicy::StartNextLoop),
        "stopthread" | "stop_thread" => Ok(SampleErrorPolicy::StopThread),
        "stoptest" | "stop_test" => Ok(SampleErrorPolicy::StopTestGraceful),
        "stoptestnow" | "stop_test_now" => Ok(SampleErrorPolicy::StopTestImmediate),
        _ => Err(PlanCompileError::InvalidProperty {
            source: source.clone(),
            test_class: class.to_owned(),
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
            test_class: class.to_owned(),
            property: property.to_owned(),
            detail: "value must be non-negative".to_owned(),
        });
    }
    usize::try_from(value).map_err(|_| PlanCompileError::InvalidProperty {
        source: source.clone(),
        test_class: class.to_owned(),
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
    let value = string_property(source, class, element, property, "")?;
    if value.trim().is_empty() {
        return Ok(default);
    }
    duration_seconds(source, class, property, &value)
}

fn optional_seconds_property(
    source: &SourceRef,
    class: &str,
    element: &TestElement,
    property: &str,
) -> Result<Option<Duration>, PlanCompileError> {
    let value = string_property(source, class, element, property, "")?;
    if value.trim().is_empty() {
        return Ok(None);
    }
    duration_seconds(source, class, property, &value).map(Some)
}

fn duration_seconds(
    source: &SourceRef,
    class: &str,
    property: &str,
    value: &str,
) -> Result<Duration, PlanCompileError> {
    let seconds = value
        .parse::<u64>()
        .map_err(|_| PlanCompileError::InvalidProperty {
            source: source.clone(),
            test_class: class.to_owned(),
            property: property.to_owned(),
            detail: "duration must be an unsigned number of seconds".to_owned(),
        })?;
    Ok(Duration::from_secs(seconds))
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
        test_class: class.to_owned(),
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
        capability_id: capability_id.to_owned(),
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

#[cfg(test)]
#[allow(clippy::expect_used, reason = "deterministic compiler fixtures")]
mod tests {
    use super::*;

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
    fn scheduler_and_replacements_are_not_approximated() {
        let mut tree = plan_with_children(vec![TestElement::named(
            "ModuleController",
            "ModuleControllerGui",
            "module",
        )]);
        tree.get_mut(NodeId::new(2))
            .expect("group")
            .value_mut()
            .set_property("ThreadGroup.scheduler", PropertyValue::boolean(true));
        let error = PlanCompiler::builtins()
            .compile_tree(&tree)
            .expect_err("scheduler must fail closed");
        match error {
            PlanCompileError::UnsupportedFeature { capability_id, .. } => {
                assert_eq!(capability_id, "runtime.lifecycle.scheduler-boundary");
            }
            other => panic!("unexpected scheduler error: {other:?}"),
        }

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
