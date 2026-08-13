// SPDX-License-Identifier: Apache-2.0
//! Identity-keyed executable scope compilation.
//!
//! JMeter's compiler walks an ordered tree for every sampler and accumulates
//! the applicable component categories from its ancestors.  This module keeps
//! that relationship explicit: packages are keyed by [`NodeId`], disabled
//! branches disappear only from the executable plan, and source elements are
//! never mutated or silently dropped.  Unknown executable classes produce a
//! typed capability error.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use jmeter_rs_model::{ElementTree, NodeId, TestElement, TreeError};

use crate::{CompiledPackages, PackageCompileError, SamplePackage};

/// JMeter 5.6.3 assertion aliases and their stable runtime capabilities.
///
/// The semantic JMX layer normally canonicalizes fully-qualified class names
/// to the short SaveService alias.  Keeping both spellings here is deliberate
/// nevertheless: callers can compile a model constructed directly, and an
/// unsupported/plugin class must never be made executable merely by changing
/// the XML tag.  The source [`TestElement`] remains the lossless wire record
/// either way.
pub(crate) const JMETER_ASSERTION_BINDINGS: &[(&str, &str)] = &[
    ("BeanShellAssertion", "runtime.assertion.jvm.beanshell"),
    (
        "org.apache.jmeter.assertions.BeanShellAssertion",
        "runtime.assertion.jvm.beanshell",
    ),
    ("BSFAssertion", "runtime.assertion.jvm.bsf"),
    (
        "org.apache.jmeter.assertions.BSFAssertion",
        "runtime.assertion.jvm.bsf",
    ),
    ("CompareAssertion", "runtime.assertion.jvm.compare"),
    (
        "org.apache.jmeter.assertions.CompareAssertion",
        "runtime.assertion.jvm.compare",
    ),
    ("DurationAssertion", "runtime.assertion.duration"),
    (
        "org.apache.jmeter.assertions.DurationAssertion",
        "runtime.assertion.duration",
    ),
    ("HTMLAssertion", "runtime.assertion.jvm.html"),
    (
        "org.apache.jmeter.assertions.HTMLAssertion",
        "runtime.assertion.jvm.html",
    ),
    ("JMESPathAssertion", "assertion.jmespath"),
    (
        "org.apache.jmeter.assertions.jmespath.JMESPathAssertion",
        "assertion.jmespath",
    ),
    ("JSONPathAssertion", "assertion.json"),
    (
        "org.apache.jmeter.assertions.JSONPathAssertion",
        "assertion.json",
    ),
    ("JSR223Assertion", "runtime.assertion.jvm.jsr223"),
    (
        "org.apache.jmeter.assertions.JSR223Assertion",
        "runtime.assertion.jvm.jsr223",
    ),
    ("MD5HexAssertion", "runtime.assertion.md5hex"),
    (
        "org.apache.jmeter.assertions.MD5HexAssertion",
        "runtime.assertion.md5hex",
    ),
    ("ResponseAssertion", "runtime.assertion.response"),
    (
        "org.apache.jmeter.assertions.ResponseAssertion",
        "runtime.assertion.response",
    ),
    ("SizeAssertion", "runtime.assertion.size"),
    (
        "org.apache.jmeter.assertions.SizeAssertion",
        "runtime.assertion.size",
    ),
    ("SMIMEAssertion", "runtime.assertion.jvm.smime"),
    (
        "org.apache.jmeter.assertions.SMIMEAssertionTestElement",
        "runtime.assertion.jvm.smime",
    ),
    ("XMLAssertion", "runtime.assertion.xml"),
    (
        "org.apache.jmeter.assertions.XMLAssertion",
        "runtime.assertion.xml",
    ),
    ("XMLSchemaAssertion", "runtime.assertion.jvm.xml-schema"),
    (
        "org.apache.jmeter.assertions.XMLSchemaAssertion",
        "runtime.assertion.jvm.xml-schema",
    ),
    ("XPathAssertion", "runtime.assertion.xpath"),
    (
        "org.apache.jmeter.assertions.XPathAssertion",
        "runtime.assertion.xpath",
    ),
    ("XPath2Assertion", "runtime.assertion.jvm.xpath2"),
    (
        "org.apache.jmeter.assertions.XPath2Assertion",
        "runtime.assertion.jvm.xpath2",
    ),
];

const DEFAULT_MAX_COMPONENTS: usize = 65_536;
const DEFAULT_MAX_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_MAX_DEPTH: usize = 256;
const DEFAULT_MAX_NODES: usize = 100_000;
const DEFAULT_MAX_PACKAGES: usize = 16_384;

/// Runtime component categories recognized by scope compilation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ComponentCategory {
    /// Configuration element merged before preprocessors.
    Configuration,
    /// Preprocessor running before timers.
    Preprocessor,
    /// Additive timer.
    Timer,
    /// Sampler leaf.
    Sampler,
    /// Postprocessor running after a non-null result.
    Postprocessor,
    /// Assertion running after postprocessors.
    Assertion,
    /// Listener observing a result event.
    Listener,
    /// Logic/controller node handled by controller compilation.
    Controller,
    /// Test-plan/thread-group lifecycle node.
    Lifecycle,
    /// A replaceable Module/Include node.
    Replaceable,
}

/// A registry entry preserving the exact upstream class name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComponentBinding {
    /// Exact upstream `testclass` or accepted alias.
    pub test_class: String,
    /// Runtime category.
    pub category: ComponentCategory,
    /// Stable capability ID used in diagnostics and profile mapping.
    pub capability_id: String,
    /// Whether the class requires an external adapter.
    pub external: bool,
}

/// The native or external timer family associated with an exact JMeter
/// `testclass` alias.
///
/// This is deliberately separate from [`ComponentBinding`].  A binding is
/// also used by callers that only classify scope; the timer decoder needs the
/// additional, property-schema identity without making every component
/// binding carry a decoder function or an executor-specific value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimerBinding {
    /// JMeter's `ConstantTimer`.
    Constant,
    /// JMeter's `UniformRandomTimer`.
    UniformRandom,
    /// JMeter's `GaussianRandomTimer`.
    GaussianRandom,
    /// JMeter's `PoissonRandomTimer`.
    PoissonRandom,
    /// JMeter's `ConstantThroughputTimer`.
    ConstantThroughput,
    /// JMeter's `PreciseThroughputTimer`.
    PreciseThroughput,
    /// JMeter's `SyncTimer`.
    Synchronizing,
    /// A script-backed timer that requires the external JVM/plugin boundary.
    ExternalScript,
}

/// One exact timer alias and its decoder metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimerAlias {
    /// The exact JMeter `testclass`/SaveService alias.
    pub alias: &'static str,
    /// The property decoder family for this alias.
    pub binding: TimerBinding,
    /// Stable capability identifier used by scope diagnostics.
    pub capability_id: &'static str,
    /// Whether this alias requires an external runtime boundary.
    pub external: bool,
}

/// Exact timer aliases from the pinned JMeter 5.6.3 SaveService vocabulary.
///
/// The order follows the repository's pinned alias source.  Callers that
/// need to emit or inspect aliases must not infer a different primary alias
/// from a hash-map iteration order.
pub const fn builtin_timer_aliases() -> &'static [TimerAlias] {
    &[
        TimerAlias {
            alias: "BeanShellTimer",
            binding: TimerBinding::ExternalScript,
            capability_id: "runtime.external.BeanShellTimer",
            external: true,
        },
        TimerAlias {
            alias: "BSFTimer",
            binding: TimerBinding::ExternalScript,
            capability_id: "runtime.external.BSFTimer",
            external: true,
        },
        TimerAlias {
            alias: "ConstantThroughputTimer",
            binding: TimerBinding::ConstantThroughput,
            capability_id: "runtime.ConstantThroughputTimer",
            external: false,
        },
        TimerAlias {
            alias: "ConstantTimer",
            binding: TimerBinding::Constant,
            capability_id: "runtime.ConstantTimer",
            external: false,
        },
        TimerAlias {
            alias: "PreciseThroughputTimer",
            binding: TimerBinding::PreciseThroughput,
            capability_id: "runtime.PreciseThroughputTimer",
            external: false,
        },
        TimerAlias {
            alias: "GaussianRandomTimer",
            binding: TimerBinding::GaussianRandom,
            capability_id: "runtime.GaussianRandomTimer",
            external: false,
        },
        TimerAlias {
            alias: "JSR223Timer",
            binding: TimerBinding::ExternalScript,
            capability_id: "runtime.external.JSR223Timer",
            external: true,
        },
        TimerAlias {
            alias: "PoissonRandomTimer",
            binding: TimerBinding::PoissonRandom,
            capability_id: "runtime.PoissonRandomTimer",
            external: false,
        },
        TimerAlias {
            alias: "SyncTimer",
            binding: TimerBinding::Synchronizing,
            capability_id: "runtime.SyncTimer",
            external: false,
        },
        TimerAlias {
            alias: "UniformRandomTimer",
            binding: TimerBinding::UniformRandom,
            capability_id: "runtime.UniformRandomTimer",
            external: false,
        },
    ]
}

impl ComponentBinding {
    /// Creates a native component binding.
    #[must_use]
    pub fn native(
        test_class: impl Into<String>,
        category: ComponentCategory,
        capability_id: impl Into<String>,
    ) -> Self {
        Self {
            test_class: test_class.into(),
            category,
            capability_id: capability_id.into(),
            external: false,
        }
    }

    /// Marks a binding as requiring an external/JVM/plugin capability.
    #[must_use]
    pub fn external(mut self) -> Self {
        self.external = true;
        self
    }
}

/// A class registry used by the scope compiler.
#[derive(Clone, Debug, Default)]
pub struct ComponentRegistry {
    bindings: BTreeMap<String, ComponentBinding>,
    timer_bindings: BTreeMap<String, TimerBinding>,
}

impl ComponentRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a class or alias, retaining insertion-independent lookup.
    pub fn register(&mut self, binding: ComponentBinding) {
        self.timer_bindings.remove(&binding.test_class);
        self.bindings.insert(binding.test_class.clone(), binding);
    }

    /// Registers an exact timer alias and its property-decoder family.
    pub fn register_timer(
        &mut self,
        alias: impl Into<String>,
        binding: TimerBinding,
        capability_id: impl Into<String>,
    ) {
        let alias = alias.into();
        self.bindings.insert(
            alias.clone(),
            ComponentBinding::native(alias.clone(), ComponentCategory::Timer, capability_id),
        );
        self.timer_bindings.insert(alias, binding);
    }

    /// Registers an exact external timer alias.  Script-backed timers use
    /// this path so scope compilation returns an explicit capability error
    /// before an executor ever attempts to instantiate them.
    pub fn register_external_timer(
        &mut self,
        alias: impl Into<String>,
        capability_id: impl Into<String>,
    ) {
        let alias = alias.into();
        self.bindings.insert(
            alias.clone(),
            ComponentBinding::native(alias.clone(), ComponentCategory::Timer, capability_id)
                .external(),
        );
        self.timer_bindings
            .insert(alias, TimerBinding::ExternalScript);
    }

    /// Registers a native class in one call.
    pub fn register_native(
        &mut self,
        test_class: impl Into<String>,
        category: ComponentCategory,
        capability_id: impl Into<String>,
    ) {
        self.register(ComponentBinding::native(
            test_class,
            category,
            capability_id,
        ));
    }

    /// Looks up an exact class or alias.
    #[must_use]
    pub fn get(&self, test_class: &str) -> Option<&ComponentBinding> {
        self.bindings.get(test_class)
    }

    /// Returns the timer decoder family for an exact registered alias.
    #[must_use]
    pub fn timer_binding(&self, test_class: &str) -> Option<TimerBinding> {
        self.timer_bindings.get(test_class).copied()
    }

    /// Returns all registered bindings in stable class order.
    pub fn iter(&self) -> impl Iterator<Item = &ComponentBinding> {
        self.bindings.values()
    }

    /// Creates the built-in structural and timer registry. Concrete sampler
    /// factories remain an application concern; timer aliases additionally
    /// retain the property-decoder family needed by the runtime factory seam.
    #[must_use]
    pub fn builtins() -> Self {
        let mut registry = Self::new();
        for (name, category) in [
            ("TestPlan", ComponentCategory::Lifecycle),
            ("Arguments", ComponentCategory::Configuration),
            ("ConfigTestElement", ComponentCategory::Configuration),
            ("UserDefinedVariables", ComponentCategory::Configuration),
            ("ThreadGroup", ComponentCategory::Lifecycle),
            ("SetupThreadGroup", ComponentCategory::Lifecycle),
            ("PostThreadGroup", ComponentCategory::Lifecycle),
            ("GenericController", ComponentCategory::Controller),
            ("LoopController", ComponentCategory::Controller),
            ("IfController", ComponentCategory::Controller),
            ("WhileController", ComponentCategory::Controller),
            ("ForEachController", ComponentCategory::Controller),
            ("ForeachController", ComponentCategory::Controller),
            ("SwitchController", ComponentCategory::Controller),
            ("InterleaveControl", ComponentCategory::Controller),
            ("RandomController", ComponentCategory::Controller),
            ("RandomOrderController", ComponentCategory::Controller),
            ("OnceOnlyController", ComponentCategory::Controller),
            ("ThroughputController", ComponentCategory::Controller),
            ("RunTime", ComponentCategory::Controller),
            ("RuntimeController", ComponentCategory::Controller),
            ("TransactionController", ComponentCategory::Controller),
            ("ModuleController", ComponentCategory::Replaceable),
            ("IncludeController", ComponentCategory::Replaceable),
            ("RecordingController", ComponentCategory::Controller),
            ("CriticalSectionController", ComponentCategory::Controller),
            ("ResponseAssertion", ComponentCategory::Assertion),
            ("JSONPostProcessor", ComponentCategory::Postprocessor),
            ("RegexExtractor", ComponentCategory::Postprocessor),
            ("XPathExtractor", ComponentCategory::Postprocessor),
            ("JSR223PostProcessor", ComponentCategory::Postprocessor),
            ("DebugPostProcessor", ComponentCategory::Postprocessor),
            (
                "UserParametersPreProcessor",
                ComponentCategory::Preprocessor,
            ),
            ("JSR223PreProcessor", ComponentCategory::Preprocessor),
            ("BeanShellPreProcessor", ComponentCategory::Preprocessor),
            ("DebugSampler", ComponentCategory::Sampler),
            ("HTTPHC4Impl", ComponentCategory::Sampler),
            ("HTTPSamplerProxy", ComponentCategory::Sampler),
            ("ResultCollector", ComponentCategory::Listener),
        ] {
            registry.register_native(name, category, format!("runtime.{name}"));
        }
        for alias in builtin_timer_aliases() {
            if alias.external {
                registry.register_external_timer(alias.alias, alias.capability_id);
            } else {
                registry.register_timer(alias.alias, alias.binding, alias.capability_id);
            }
        }
        for (name, category) in [
            ("JSR223PostProcessor", ComponentCategory::Postprocessor),
            ("BeanShellPostProcessor", ComponentCategory::Postprocessor),
            ("JSR223PreProcessor", ComponentCategory::Preprocessor),
            ("BeanShellPreProcessor", ComponentCategory::Preprocessor),
            ("RegexExtractor", ComponentCategory::Postprocessor),
            ("XPathExtractor", ComponentCategory::Postprocessor),
            ("JSONPostProcessor", ComponentCategory::Postprocessor),
            ("HTTPHC4Impl", ComponentCategory::Sampler),
            ("HTTPSamplerProxy", ComponentCategory::Sampler),
        ] {
            registry.register(
                ComponentBinding::native(name, category, format!("runtime.external.{name}"))
                    .external(),
            );
        }
        for (name, capability_id) in JMETER_ASSERTION_BINDINGS {
            // The class is known to the pinned profile, but not every
            // assertion family has a native evaluator.  The compiler's
            // assertion factory supplies a typed unsupported component for
            // those families; marking the binding as a generic unknown here
            // would lose its profile-specific capability identity.
            registry.register_native(*name, ComponentCategory::Assertion, *capability_id);
        }
        registry
    }
}

/// Bounded resource policy applied independently to each package compilation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScopeLimits {
    /// Maximum source-tree nodes inspected during compilation.
    pub max_nodes: usize,
    /// Maximum executable/package nodes.
    pub max_components: usize,
    /// Maximum sampler packages retained in the immutable plan.
    pub max_packages: usize,
    /// Maximum total UTF-8 bytes in retained class/capability metadata.
    pub max_bytes: usize,
    /// Maximum source-tree depth.
    pub max_depth: usize,
}

impl Default for ScopeLimits {
    fn default() -> Self {
        Self {
            max_nodes: DEFAULT_MAX_NODES,
            max_components: DEFAULT_MAX_COMPONENTS,
            max_packages: DEFAULT_MAX_PACKAGES,
            max_bytes: DEFAULT_MAX_BYTES,
            max_depth: DEFAULT_MAX_DEPTH,
        }
    }
}

impl ScopeLimits {
    /// Creates an explicit package policy. Zero values are valid and reject
    /// the first matching component deterministically.
    #[must_use]
    pub const fn new(max_components: usize, max_bytes: usize, max_depth: usize) -> Self {
        Self {
            max_nodes: DEFAULT_MAX_NODES,
            max_components,
            max_packages: DEFAULT_MAX_PACKAGES,
            max_bytes,
            max_depth,
        }
    }

    /// Returns a copy with explicit source-node and package bounds.
    #[must_use]
    pub const fn with_topology_limits(mut self, max_nodes: usize, max_packages: usize) -> Self {
        self.max_nodes = max_nodes;
        self.max_packages = max_packages;
        self
    }
}

/// A source node accepted by [`ScopeCompiler::compile_scope`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeNode {
    /// Document-local identity.
    pub id: NodeId,
    /// Exact upstream test class.
    pub test_class: String,
    /// Exact source name.
    pub name: String,
    /// Source enabled state.
    pub enabled: bool,
    /// Ordered children.
    pub children: Vec<Self>,
    /// Optional replacement subtree for a Module/Include node.
    pub replacement: Option<Box<Self>>,
}

impl ScopeNode {
    /// Creates a source node.
    #[must_use]
    pub fn new(id: NodeId, test_class: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id,
            test_class: test_class.into(),
            name: name.into(),
            enabled: true,
            children: Vec::new(),
            replacement: None,
        }
    }

    /// Adds a child in source order.
    pub fn push_child(&mut self, child: Self) {
        self.children.push(child);
    }

    /// Marks a node disabled while retaining it in the source representation.
    #[must_use]
    pub const fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }

    /// Supplies a resolved replacement subtree.
    #[must_use]
    pub fn with_replacement(mut self, replacement: Self) -> Self {
        self.replacement = Some(Box::new(replacement));
        self
    }
}

/// One compiled component reference in a sampler package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsupportedComponent {
    /// Element identity.
    pub node_id: NodeId,
    /// Exact upstream class.
    pub test_class: String,
    /// Component category.
    pub category: ComponentCategory,
    /// Stable capability ID, if the registry supplied one.
    pub capability_id: Option<String>,
    /// Whether the component is explicitly external.
    pub external: bool,
    /// Root-to-node identity path, in source order.
    pub path: Vec<NodeId>,
}

/// One component retained in a compiled sampler scope.
///
/// [`ComponentBinding`] is class-oriented for compatibility with callers that
/// only need the registry vocabulary. Factory-backed compilation needs the
/// source identity and exact properties as well, so this node-oriented record
/// is retained alongside the legacy binding vectors.
#[derive(Clone, Debug, PartialEq)]
pub struct ScopeComponent {
    /// Source element identity.
    pub node_id: NodeId,
    /// Root-to-component identity path, including this node.
    pub path: Vec<NodeId>,
    /// Exact source element retained for a decoder/factory hook.
    pub element: TestElement,
    /// Registry binding for the source class.
    pub binding: ComponentBinding,
}

/// GUI-backed result collector kinds understood by the run-sink routing seam.
///
/// This is metadata only: runtime does not construct a file, JTL codec, or
/// report implementation while compiling a plan.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ResultCollectorKind {
    /// A JTL/file writer (`SimpleDataWriter`).
    SimpleDataWriter,
    /// Aggregate report listener (`StatVisualizer`).
    StatVisualizer,
    /// Summary report listener (`SummaryReport`).
    SummaryReport,
    /// Graph report listener (`GraphVisualizer`).
    GraphVisualizer,
    /// A visualizer not supported by the active profile.
    Unsupported,
}

impl ScopeComponent {
    pub(crate) fn new(
        node_id: NodeId,
        path: &[NodeId],
        element: &TestElement,
        binding: &ComponentBinding,
    ) -> Self {
        Self {
            node_id,
            path: path.to_vec(),
            element: element.clone(),
            binding: binding.clone(),
        }
    }

    /// Classifies a `ResultCollector` by its exact GUI class, if applicable.
    #[must_use]
    pub fn result_collector_kind(&self) -> Option<ResultCollectorKind> {
        if self.binding.category != ComponentCategory::Listener
            || self.binding.test_class != "ResultCollector"
        {
            return None;
        }
        Some(match self.element.gui_class() {
            "SimpleDataWriter" => ResultCollectorKind::SimpleDataWriter,
            "StatVisualizer" => ResultCollectorKind::StatVisualizer,
            "SummaryReport" => ResultCollectorKind::SummaryReport,
            "GraphVisualizer" => ResultCollectorKind::GraphVisualizer,
            _ => ResultCollectorKind::Unsupported,
        })
    }
}

/// One category entry retained in the package's verified scope order.
#[derive(Clone, Debug, PartialEq)]
pub struct ScopePlan {
    /// Sampler identity.
    pub sampler_id: NodeId,
    /// Configuration from outermost to innermost scope.
    pub configurations: Vec<ComponentBinding>,
    /// Preprocessors from outermost to innermost scope.
    pub preprocessors: Vec<ComponentBinding>,
    /// Timers from outermost to innermost scope.
    pub timers: Vec<ComponentBinding>,
    /// The sampler binding.
    pub sampler: ComponentBinding,
    /// Postprocessors from outermost to innermost scope.
    pub postprocessors: Vec<ComponentBinding>,
    /// Assertions from outermost to innermost scope.
    pub assertions: Vec<ComponentBinding>,
    /// Listeners in scope/tree order.
    pub listeners: Vec<ComponentBinding>,
    /// Controller/transaction path, outermost to innermost.
    pub controller_path: Vec<NodeId>,
    /// Node-oriented configuration records for factory hooks.
    pub configuration_components: Vec<ScopeComponent>,
    /// Node-oriented preprocessor records for factory hooks.
    pub preprocessor_components: Vec<ScopeComponent>,
    /// Node-oriented timer records for factory hooks.
    pub timer_components: Vec<ScopeComponent>,
    /// Node-oriented sampler record for factory hooks.
    pub sampler_component: ScopeComponent,
    /// Node-oriented postprocessor records for factory hooks.
    pub postprocessor_components: Vec<ScopeComponent>,
    /// Node-oriented assertion records for factory hooks.
    pub assertion_components: Vec<ScopeComponent>,
    /// Node-oriented listener records for factory hooks.
    pub listener_components: Vec<ScopeComponent>,
}

impl ScopePlan {
    /// Returns all configuration records in lexical scope order.
    #[must_use]
    pub fn configuration_nodes(&self) -> &[ScopeComponent] {
        &self.configuration_components
    }

    /// Returns all preprocessor records in lexical scope order.
    #[must_use]
    pub fn preprocessor_nodes(&self) -> &[ScopeComponent] {
        &self.preprocessor_components
    }

    /// Returns all timer records in lexical scope order.
    #[must_use]
    pub fn timer_nodes(&self) -> &[ScopeComponent] {
        &self.timer_components
    }

    /// Returns the sampler source record.
    #[must_use]
    pub fn sampler_node(&self) -> &ScopeComponent {
        &self.sampler_component
    }

    /// Returns all postprocessor records in lexical scope order.
    #[must_use]
    pub fn postprocessor_nodes(&self) -> &[ScopeComponent] {
        &self.postprocessor_components
    }

    /// Returns all assertion records in lexical scope order.
    #[must_use]
    pub fn assertion_nodes(&self) -> &[ScopeComponent] {
        &self.assertion_components
    }

    /// Returns all listener records in lexical scope order.
    #[must_use]
    pub fn listener_nodes(&self) -> &[ScopeComponent] {
        &self.listener_components
    }
}

/// The complete executable scope result.
#[derive(Clone, Debug, PartialEq)]
pub struct CompiledScopePlan {
    pub(crate) packages: BTreeMap<NodeId, ScopePlan>,
    pub(crate) disabled: BTreeSet<NodeId>,
    pub(crate) replacements: BTreeMap<NodeId, NodeId>,
    pub(crate) run_collectors: Vec<ScopeComponent>,
}

impl CompiledScopePlan {
    /// Returns a sampler package by identity.
    #[must_use]
    pub fn get(&self, sampler_id: NodeId) -> Option<&ScopePlan> {
        self.packages.get(&sampler_id)
    }

    /// Returns all package plans in stable identity order.
    pub fn iter(&self) -> impl Iterator<Item = (NodeId, &ScopePlan)> {
        self.packages.iter().map(|(id, package)| (*id, package))
    }

    /// Returns whether the executable plan has no samplers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.packages.is_empty()
    }

    /// Returns the number of executable samplers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.packages.len()
    }

    /// Returns source IDs retained as disabled branches.
    #[must_use]
    pub fn disabled_ids(&self) -> &BTreeSet<NodeId> {
        &self.disabled
    }

    /// Returns replacement source-to-target mappings.
    #[must_use]
    pub fn replacements(&self) -> &BTreeMap<NodeId, NodeId> {
        &self.replacements
    }

    /// Returns enabled root-level result collectors in lexical source order.
    ///
    /// These records describe run-owned sink configuration only. Runtime does
    /// not instantiate a concrete writer or report adapter here.
    #[must_use]
    pub fn run_collectors(&self) -> &[ScopeComponent] {
        &self.run_collectors
    }
}

/// Errors raised while decoding one ordered scope component through a
/// bounded factory registry.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(
    missing_docs,
    reason = "error payload fields are documented by variant semantics"
)]
pub enum ScopeFactoryError {
    /// The registry could not admit another class hook.
    RegistryLimit { limit: usize },
    /// A factory was not registered for a recognized executable class.
    MissingFactory {
        node_id: NodeId,
        path: Vec<NodeId>,
        test_class: String,
        category: ComponentCategory,
    },
    /// A registered factory rejected the exact source properties.
    Decode {
        node_id: NodeId,
        path: Vec<NodeId>,
        test_class: String,
        category: ComponentCategory,
        detail: String,
    },
    /// A hook returned a domain component different from its registry class.
    CategoryMismatch {
        node_id: NodeId,
        path: Vec<NodeId>,
        expected: ComponentCategory,
        actual: ComponentCategory,
    },
    /// A factory registration itself is invalid.
    InvalidRegistration { test_class: String, detail: String },
}

impl ScopeFactoryError {
    /// Returns the stable diagnostic code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::RegistryLimit { .. } => "runtime.scope.factory-registry-limit",
            Self::MissingFactory { .. } => "runtime.scope.missing-factory",
            Self::Decode { .. } => "runtime.scope.factory-decode",
            Self::CategoryMismatch { .. } => "runtime.scope.factory-category-mismatch",
            Self::InvalidRegistration { .. } => "runtime.scope.invalid-factory-registration",
        }
    }
}

impl fmt::Display for ScopeFactoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RegistryLimit { limit } => write!(formatter, "{}: {limit}", self.code()),
            Self::MissingFactory {
                node_id,
                path,
                test_class,
                category,
            } => write!(
                formatter,
                "{}: node {node_id} class {test_class:?} category {category:?} path {path:?}",
                self.code()
            ),
            Self::Decode {
                node_id,
                path,
                test_class,
                category,
                detail,
            } => write!(
                formatter,
                "{}: node {node_id} class {test_class:?} category {category:?} path {path:?}: {detail}",
                self.code()
            ),
            Self::CategoryMismatch {
                node_id,
                path,
                expected,
                actual,
            } => write!(
                formatter,
                "{}: node {node_id} path {path:?}: expected {expected:?}, got {actual:?}",
                self.code()
            ),
            Self::InvalidRegistration { test_class, detail } => {
                write!(formatter, "{}: class {test_class:?}: {detail}", self.code())
            }
        }
    }
}

impl std::error::Error for ScopeFactoryError {}

/// Stable scope compilation failures.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(
    missing_docs,
    reason = "error payload fields are documented by variant semantics"
)]
pub enum ScopeCompileError {
    /// The source tree itself is malformed.
    Tree(String),
    /// The source tree contains more nodes than the compiler is allowed to inspect.
    NodeLimit { count: usize, limit: usize },
    /// The executable plan contains more sampler packages than allowed.
    PackageLimit { count: usize, limit: usize },
    /// Too many executable components were encountered.
    ComponentLimit { count: usize, limit: usize },
    /// Retained class/capability metadata exceeded the byte policy.
    ByteLimit { bytes: usize, limit: usize },
    /// Source depth exceeded the package policy.
    DepthLimit { depth: usize, limit: usize },
    /// An executable class has no native or external binding.
    Unsupported(UnsupportedComponent),
    /// A class name is present but contains invalid control characters.
    InvalidTestClass {
        node_id: NodeId,
        path: Vec<NodeId>,
        reason: String,
    },
    /// An executable source node did not declare a test class.
    EmptyTestClass { node_id: NodeId, path: Vec<NodeId> },
    /// A replaceable node requested a replacement but none was resolved.
    UnresolvedReplacement {
        node_id: NodeId,
        test_class: String,
        path: Vec<NodeId>,
    },
    /// A replacement cycle was detected.
    ReplacementCycle { node_id: NodeId, path: Vec<NodeId> },
    /// A replacement target or include/module reference is absent.
    OrphanReference {
        node_id: NodeId,
        target: NodeId,
        path: Vec<NodeId>,
    },
    /// A tree topology or hashTree wrapper is invalid at this boundary.
    Topology {
        node_id: Option<NodeId>,
        path: Vec<NodeId>,
        detail: String,
    },
    /// A component appears in a parent category that cannot own it.
    CategoryMisuse {
        node_id: NodeId,
        category: ComponentCategory,
        parent_id: Option<NodeId>,
        path: Vec<NodeId>,
    },
    /// Two executable scope paths produced one sampler identity.
    DuplicateSampler {
        sampler_id: NodeId,
        path: Vec<NodeId>,
    },
    /// A concrete package assembler rejected a verified scope plan.
    PackageAssembly { source: PackageCompileError },
    /// A component factory rejected or could not decode an executable node.
    Factory { source: ScopeFactoryError },
}

impl ScopeCompileError {
    /// Returns the stable diagnostic code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Tree(_) => "runtime.scope.tree",
            Self::NodeLimit { .. } => "runtime.scope.node-limit",
            Self::PackageLimit { .. } => "runtime.scope.package-limit",
            Self::ComponentLimit { .. } => "runtime.scope.component-limit",
            Self::ByteLimit { .. } => "runtime.scope.byte-limit",
            Self::DepthLimit { .. } => "runtime.scope.depth-limit",
            Self::Unsupported(_) => "runtime.scope.unsupported",
            Self::InvalidTestClass { .. } => "runtime.scope.invalid-test-class",
            Self::EmptyTestClass { .. } => "runtime.scope.empty-test-class",
            Self::UnresolvedReplacement { .. } => "runtime.scope.unresolved-replacement",
            Self::ReplacementCycle { .. } => "runtime.scope.replacement-cycle",
            Self::OrphanReference { .. } => "runtime.scope.orphan-reference",
            Self::Topology { .. } => "runtime.scope.topology",
            Self::CategoryMisuse { .. } => "runtime.scope.category-misuse",
            Self::DuplicateSampler { .. } => "runtime.scope.duplicate-sampler",
            Self::PackageAssembly { .. } => "runtime.scope.package-assembly",
            Self::Factory { .. } => "runtime.scope.factory",
        }
    }
}

impl fmt::Display for ScopeCompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tree(message) => write!(formatter, "{}: {message}", self.code()),
            Self::NodeLimit { count, limit } => {
                write!(formatter, "{}: {count}/{limit}", self.code())
            }
            Self::PackageLimit { count, limit } => {
                write!(formatter, "{}: {count}/{limit}", self.code())
            }
            Self::ComponentLimit { count, limit } => {
                write!(formatter, "{}: {count}/{limit}", self.code())
            }
            Self::ByteLimit { bytes, limit } => {
                write!(formatter, "{}: {bytes}/{limit}", self.code())
            }
            Self::DepthLimit { depth, limit } => {
                write!(formatter, "{}: {depth}/{limit}", self.code())
            }
            Self::Unsupported(component) => write!(formatter, "{}: {component:?}", self.code()),
            Self::InvalidTestClass {
                node_id,
                path,
                reason,
            } => write!(
                formatter,
                "{}: node {node_id} path {path:?}: {reason}",
                self.code()
            ),
            Self::EmptyTestClass { node_id, path } => {
                write!(formatter, "{}: node {node_id} path {path:?}", self.code())
            }
            Self::UnresolvedReplacement {
                node_id,
                test_class,
                path,
            } => {
                write!(
                    formatter,
                    "{}: node {node_id} class {test_class:?} path {path:?}",
                    self.code()
                )
            }
            Self::ReplacementCycle { node_id, path } => {
                write!(formatter, "{}: node {node_id} path {path:?}", self.code())
            }
            Self::OrphanReference {
                node_id,
                target,
                path,
            } => {
                write!(
                    formatter,
                    "{}: node {node_id} target {target} path {path:?}",
                    self.code()
                )
            }
            Self::Topology {
                node_id,
                path,
                detail,
            } => write!(
                formatter,
                "{}: node {node_id:?} path {path:?}: {detail}",
                self.code()
            ),
            Self::CategoryMisuse {
                node_id,
                category,
                parent_id,
                path,
            } => write!(
                formatter,
                "{}: node {node_id} category {category:?} parent {parent_id:?} path {path:?}",
                self.code()
            ),
            Self::DuplicateSampler { sampler_id, path } => {
                write!(
                    formatter,
                    "{}: sampler {sampler_id} path {path:?}",
                    self.code()
                )
            }
            Self::PackageAssembly { source } => write!(formatter, "{}: {source}", self.code()),
            Self::Factory { source } => write!(formatter, "{}: {source}", self.code()),
        }
    }
}

impl std::error::Error for ScopeCompileError {}

/// Converts a verified scope plan into a concrete package. Implementations
/// are expected to resolve native adapters or return an explicit unsupported
/// capability error for JVM/plugin-only components.
pub trait ScopePackageAssembler: Send + Sync {
    /// Builds one isolated package template from a scope plan.
    fn assemble(&self, plan: &ScopePlan) -> Result<SamplePackage, ScopeCompileError>;
}

/// An immutable compiler for source model trees.
#[derive(Clone, Debug)]
pub struct ScopeCompiler {
    registry: ComponentRegistry,
    limits: ScopeLimits,
}

impl ScopeCompiler {
    /// Creates a compiler with explicit registry and limits.
    #[must_use]
    pub fn new(registry: ComponentRegistry, limits: ScopeLimits) -> Self {
        Self { registry, limits }
    }

    /// Creates a compiler for the built-in class vocabulary.
    #[must_use]
    pub fn builtins() -> Self {
        Self::new(ComponentRegistry::builtins(), ScopeLimits::default())
    }

    /// Returns the registry.
    #[must_use]
    pub fn registry(&self) -> &ComponentRegistry {
        &self.registry
    }

    /// Returns resource limits.
    #[must_use]
    pub const fn limits(&self) -> ScopeLimits {
        self.limits
    }

    /// Compiles a model tree without changing its source nodes.
    pub fn compile(&self, tree: &ElementTree) -> Result<CompiledScopePlan, ScopeCompileError> {
        crate::compiler::compile_scope(self, tree)
    }

    /// Compiles an owned scope tree, including replacement nodes.
    pub fn compile_scope(&self, root: &ScopeNode) -> Result<CompiledScopePlan, ScopeCompileError> {
        let mut model = ElementTree::new();
        let mut stack = vec![(None, root)];
        while let Some((parent, node)) = stack.pop() {
            let mut element = TestElement::named(&node.test_class, "Runtime", &node.name);
            element.set_enabled(node.enabled);
            if let Some(replacement) = &node.replacement {
                if replacement.id.as_u64() > i64::MAX as u64 {
                    return Err(ScopeCompileError::InvalidTestClass {
                        node_id: node.id,
                        path: vec![node.id],
                        reason: "replacement identity exceeds the model property range".to_owned(),
                    });
                }
                element.set_temporary_property(
                    "runtime.replacement-node",
                    jmeter_rs_model::PropertyValue::long(replacement.id.as_u64() as i64),
                );
            }
            let id = model
                .insert_with_id(parent, node.id, element)
                .map_err(|error| ScopeCompileError::Tree(error.to_string()))?;
            for child in node.children.iter().rev() {
                stack.push((Some(id), child));
            }
            if let Some(replacement) = node.replacement.as_deref() {
                stack.push((Some(id), replacement));
            }
        }
        self.compile(&model)
    }

    /// Compiles model scope and delegates concrete package construction to an
    /// explicit adapter. No sampler is silently discarded when the adapter
    /// lacks a JVM/plugin implementation.
    pub fn compile_packages(
        &self,
        tree: &ElementTree,
        assembler: &dyn ScopePackageAssembler,
    ) -> Result<CompiledPackages, ScopeCompileError> {
        let plan = self.compile(tree)?;
        let packages = plan
            .iter()
            .map(|(expected_id, scope)| {
                let package = assembler.assemble(scope)?;
                let actual_id = package.sampler_id();
                if actual_id != expected_id {
                    return Err(ScopeCompileError::PackageAssembly {
                        source: PackageCompileError::SamplerIdentityMismatch {
                            expected: expected_id,
                            actual: actual_id,
                        },
                    });
                }
                Ok(package)
            })
            .collect::<Result<Vec<_>, _>>()?;
        CompiledPackages::from_packages(packages)
            .map_err(|source| ScopeCompileError::PackageAssembly { source })
    }

    /// Compiles and decodes native component hooks from a bounded registry.
    ///
    /// The registry is deliberately separate from the class vocabulary above:
    /// adding HTTP, extractor, listener, or assertion support therefore adds a
    /// factory entry and does not grow a central class match statement.
    pub fn compile_with_factories(
        &self,
        tree: &ElementTree,
        factories: &crate::ComponentFactoryRegistry,
    ) -> Result<CompiledPackages, ScopeCompileError> {
        crate::compiler::compile_packages(self, tree, factories)
    }
}

impl From<TreeError> for ScopeCompileError {
    fn from(error: TreeError) -> Self {
        Self::Tree(error.to_string())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "deterministic scope setup")]
mod tests {
    use super::*;
    use crate::UnsupportedSampler;
    use jmeter_rs_model::PropertyValue;
    use std::sync::Arc;

    struct WrongIdentityAssembler;

    impl ScopePackageAssembler for WrongIdentityAssembler {
        fn assemble(&self, _plan: &ScopePlan) -> Result<SamplePackage, ScopeCompileError> {
            Ok(SamplePackage::new(
                NodeId::new(999),
                Arc::new(UnsupportedSampler::new("scope test")),
            ))
        }
    }

    fn tree() -> ElementTree {
        let mut tree = ElementTree::new();
        let root = tree
            .insert_root(TestElement::named("TestPlan", "TestPlanGui", "plan"))
            .expect("root");
        let config = tree
            .insert_child(
                root,
                TestElement::named("Arguments", "ArgumentsPanel", "config"),
            )
            .expect("config");
        let sampler = tree
            .insert_child(
                config,
                TestElement::named("DebugSampler", "TestBeanGUI", "sample"),
            )
            .expect("sampler");
        let disabled = tree
            .insert_child(
                root,
                TestElement::named("DebugSampler", "TestBeanGUI", "disabled"),
            )
            .expect("disabled");
        tree.get_mut(disabled)
            .expect("disabled node")
            .value_mut()
            .set_enabled(false);
        let _ = sampler;
        tree
    }

    #[test]
    fn pinned_assertion_aliases_are_registered_as_assertions() {
        let registry = ComponentRegistry::builtins();
        for (alias, capability_id) in JMETER_ASSERTION_BINDINGS {
            let binding = registry.get(alias).expect("pinned assertion alias");
            assert_eq!(binding.test_class, *alias);
            assert_eq!(binding.category, ComponentCategory::Assertion);
            assert_eq!(binding.capability_id, *capability_id);
            assert!(!binding.external);
        }
    }

    #[test]
    fn disabled_branches_are_retained_but_not_compiled() {
        let mut registry = ComponentRegistry::builtins();
        registry.register_native(
            "Arguments",
            ComponentCategory::Configuration,
            "runtime.config",
        );
        let plan = ScopeCompiler::new(registry, ScopeLimits::default())
            .compile(&tree())
            .expect("compile");
        assert_eq!(plan.len(), 1);
        assert_eq!(plan.disabled_ids().len(), 1);
        let package = plan.iter().next().expect("package").1;
        assert_eq!(package.configurations.len(), 1);
        assert_eq!(package.sampler.test_class, "DebugSampler");
    }

    #[test]
    fn unknown_executable_class_is_not_silently_skipped() {
        let mut tree = ElementTree::new();
        tree.insert_root(TestElement::named("UnknownSampler", "Gui", "x"))
            .expect("root");
        let error = ScopeCompiler::builtins()
            .compile(&tree)
            .expect_err("unsupported");
        assert!(matches!(error, ScopeCompileError::Unsupported(_)));
    }

    #[test]
    fn empty_test_class_is_a_typed_scope_error() {
        let mut tree = ElementTree::new();
        tree.insert_root(TestElement::named("", "Gui", "empty"))
            .expect("root");
        let error = ScopeCompiler::builtins()
            .compile(&tree)
            .expect_err("empty testclass");
        assert!(matches!(error, ScopeCompileError::EmptyTestClass { .. }));
    }

    #[test]
    fn disabled_empty_test_class_is_retained_without_compilation() {
        let mut tree = ElementTree::new();
        let id = tree
            .insert_root(TestElement::named("", "Gui", "disabled-empty"))
            .expect("root");
        tree.get_mut(id)
            .expect("disabled node")
            .value_mut()
            .set_enabled(false);
        let plan = ScopeCompiler::builtins().compile(&tree).expect("compile");
        assert!(plan.is_empty());
        assert!(plan.disabled_ids().contains(&id));
    }

    #[test]
    fn package_assembler_identity_mismatch_is_rejected() {
        let error = ScopeCompiler::builtins()
            .compile_packages(&tree(), &WrongIdentityAssembler)
            .expect_err("identity mismatch");
        assert!(matches!(
            error,
            ScopeCompileError::PackageAssembly {
                source: PackageCompileError::SamplerIdentityMismatch { .. }
            }
        ));
    }

    #[test]
    fn replacement_requires_explicit_resolution() {
        let node = ScopeNode::new(NodeId::new(1), "ModuleController", "module");
        let error = ScopeCompiler::builtins()
            .compile_scope(&node)
            .expect_err("unresolved module");
        assert!(matches!(
            error,
            ScopeCompileError::UnresolvedReplacement { .. }
        ));
        let mut replacement = ScopeNode::new(NodeId::new(2), "DebugSampler", "target");
        replacement
            .children
            .push(ScopeNode::new(NodeId::new(3), "UnknownSampler", "opaque"));
        let resolved = ScopeNode::new(NodeId::new(1), "ModuleController", "module")
            .with_replacement(replacement);
        let error = ScopeCompiler::builtins()
            .compile_scope(&resolved)
            .expect_err("replacement remains a source diagnostic");
        assert!(matches!(error, ScopeCompileError::Unsupported(_)));
        let _ = PropertyValue::long(1);
    }

    #[test]
    fn package_limits_apply_independently_to_each_sampler() {
        let mut tree = ElementTree::new();
        let root = tree
            .insert_root(TestElement::named("TestPlan", "Gui", "plan"))
            .expect("root");
        let config = tree
            .insert_child(root, TestElement::named("Arguments", "Gui", "config"))
            .expect("config");
        tree.insert_child(config, TestElement::named("DebugSampler", "Gui", "one"))
            .expect("one");
        tree.insert_child(config, TestElement::named("DebugSampler", "Gui", "two"))
            .expect("two");
        let mut registry = ComponentRegistry::builtins();
        registry.register_native(
            "Arguments",
            ComponentCategory::Configuration,
            "runtime.config",
        );
        let compiler = ScopeCompiler::new(registry, ScopeLimits::new(2, 4096, 16));
        let plan = compiler
            .compile(&tree)
            .expect("both packages fit independently");
        assert_eq!(plan.len(), 2);
    }

    #[test]
    fn builtin_timer_aliases_match_pinned_save_service_order() {
        let aliases = builtin_timer_aliases();
        let names = aliases.iter().map(|alias| alias.alias).collect::<Vec<_>>();
        assert_eq!(
            names,
            vec![
                "BeanShellTimer",
                "BSFTimer",
                "ConstantThroughputTimer",
                "ConstantTimer",
                "PreciseThroughputTimer",
                "GaussianRandomTimer",
                "JSR223Timer",
                "PoissonRandomTimer",
                "SyncTimer",
                "UniformRandomTimer",
            ]
        );

        let registry = ComponentRegistry::builtins();
        for alias in aliases {
            let binding = registry.get(alias.alias).expect("timer alias registered");
            assert_eq!(binding.category, ComponentCategory::Timer);
            assert_eq!(registry.timer_binding(alias.alias), Some(alias.binding));
            assert_eq!(binding.capability_id, alias.capability_id);
            assert_eq!(binding.external, alias.external);
        }
        assert!(registry.get("SynchronizingTimer").is_none());
    }

    #[test]
    fn script_timer_aliases_fail_with_external_capabilities() {
        for (test_class, capability_id) in [
            ("JSR223Timer", "runtime.external.JSR223Timer"),
            ("BeanShellTimer", "runtime.external.BeanShellTimer"),
            ("BSFTimer", "runtime.external.BSFTimer"),
        ] {
            let mut tree = ElementTree::new();
            let id = tree
                .insert_root(TestElement::named(
                    test_class,
                    "TestBeanGUI",
                    "script timer",
                ))
                .expect("timer");
            let error = ScopeCompiler::builtins()
                .compile(&tree)
                .expect_err("script timer must remain external");
            assert!(matches!(
                error,
                ScopeCompileError::Unsupported(UnsupportedComponent {
                    node_id,
                    category: ComponentCategory::Timer,
                    capability_id: Some(actual),
                    external: true,
                    ..
                }) if node_id == id && actual == capability_id
            ));
        }
    }
}
