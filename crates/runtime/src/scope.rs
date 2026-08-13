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

/// Execution support declared for one exact component binding.
///
/// A source class can be known without being executable by the standalone
/// runtime.  Keeping that state separate from the component category prevents
/// a decoder skeleton (or a preserved JMX alias) from becoming an accidental
/// native implementation path.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ComponentAvailability {
    /// A bounded native implementation is available in the active runtime.
    Native,
    /// Exact behavior requires the optional JVM/plugin/service boundary.
    External,
    /// The class is recognized and retained, but no executable adapter is
    /// currently declared.
    Unavailable,
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
    /// Closed support state used by scope and plan classification.
    pub availability: ComponentAvailability,
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

/// One exact built-in class and its category/support metadata.
///
/// This table is the single source of truth shared by `ComponentRegistry` and
/// the scope/plan compilers.  Aliases are intentionally case-sensitive and
/// are never inferred from class-name substrings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BuiltinComponentSpec {
    /// Exact upstream alias or class name.
    pub alias: &'static str,
    /// Runtime component category.
    pub category: ComponentCategory,
    /// Stable capability identity.
    pub capability_id: &'static str,
    /// Declared execution support.
    pub availability: ComponentAvailability,
}

/// Built-in non-timer/non-assertion vocabulary for the pinned profile.
///
/// The entries include the aliases needed by the runtime model and the
/// fully-qualified spellings accepted by callers that construct a semantic
/// tree without the JMX SaveService canonicalization pass.  A fully-qualified
/// spelling is a distinct exact alias; no case folding is performed.
pub(crate) const BUILTIN_COMPONENT_SPECS: &[BuiltinComponentSpec] = &[
    BuiltinComponentSpec {
        alias: "TestPlan",
        category: ComponentCategory::Lifecycle,
        capability_id: "runtime.TestPlan",
        availability: ComponentAvailability::Native,
    },
    BuiltinComponentSpec {
        alias: "Arguments",
        category: ComponentCategory::Configuration,
        capability_id: "runtime.Arguments",
        availability: ComponentAvailability::Native,
    },
    BuiltinComponentSpec {
        alias: "ConfigTestElement",
        category: ComponentCategory::Configuration,
        capability_id: "runtime.ConfigTestElement",
        availability: ComponentAvailability::Native,
    },
    BuiltinComponentSpec {
        alias: "UserDefinedVariables",
        category: ComponentCategory::Configuration,
        capability_id: "runtime.UserDefinedVariables",
        availability: ComponentAvailability::Native,
    },
    BuiltinComponentSpec {
        alias: "ThreadGroup",
        category: ComponentCategory::Lifecycle,
        capability_id: "runtime.ThreadGroup",
        availability: ComponentAvailability::Native,
    },
    BuiltinComponentSpec {
        alias: "SetupThreadGroup",
        category: ComponentCategory::Lifecycle,
        capability_id: "runtime.SetupThreadGroup",
        availability: ComponentAvailability::Native,
    },
    BuiltinComponentSpec {
        alias: "PostThreadGroup",
        category: ComponentCategory::Lifecycle,
        capability_id: "runtime.PostThreadGroup",
        availability: ComponentAvailability::Native,
    },
    BuiltinComponentSpec {
        alias: "TearDownThreadGroup",
        category: ComponentCategory::Lifecycle,
        capability_id: "runtime.TearDownThreadGroup",
        availability: ComponentAvailability::Native,
    },
    BuiltinComponentSpec {
        alias: "OpenModelThreadGroup",
        category: ComponentCategory::Lifecycle,
        capability_id: "runtime.lifecycle.open-model-thread-group",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "OpenModelThreadGroupController",
        category: ComponentCategory::Controller,
        capability_id: "runtime.lifecycle.open-model-thread-group",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.threads.openmodel.OpenModelThreadGroupController",
        category: ComponentCategory::Controller,
        capability_id: "runtime.lifecycle.open-model-thread-group",
        availability: ComponentAvailability::Unavailable,
    },
    // Reflection groups are a recognized JMeter lifecycle family, but the
    // standalone runtime has no lifecycle adapter.  They are represented as
    // unavailable controller entries here so PlanCompiler cannot treat them
    // as preservation-only lifecycle nodes and silently drop an enabled one.
    BuiltinComponentSpec {
        alias: "ReflectionThreadGroup",
        category: ComponentCategory::Controller,
        capability_id: "runtime.lifecycle.reflection-thread-group",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.threads.ReflectionThreadGroup",
        category: ComponentCategory::Controller,
        capability_id: "runtime.lifecycle.reflection-thread-group",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "TestFragmentController",
        category: ComponentCategory::Lifecycle,
        capability_id: "runtime.TestFragmentController",
        availability: ComponentAvailability::Native,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.control.TestFragmentController",
        category: ComponentCategory::Lifecycle,
        capability_id: "runtime.TestFragmentController",
        availability: ComponentAvailability::Native,
    },
    BuiltinComponentSpec {
        alias: "WorkBench",
        category: ComponentCategory::Lifecycle,
        capability_id: "runtime.WorkBench",
        availability: ComponentAvailability::Native,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.testelement.WorkBench",
        category: ComponentCategory::Lifecycle,
        capability_id: "runtime.WorkBench",
        availability: ComponentAvailability::Native,
    },
    BuiltinComponentSpec {
        alias: "GenericController",
        category: ComponentCategory::Controller,
        capability_id: "runtime.GenericController",
        availability: ComponentAvailability::Native,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.control.GenericController",
        category: ComponentCategory::Controller,
        capability_id: "runtime.GenericController",
        availability: ComponentAvailability::Native,
    },
    BuiltinComponentSpec {
        alias: "SimpleController",
        category: ComponentCategory::Controller,
        capability_id: "runtime.SimpleController",
        availability: ComponentAvailability::Native,
    },
    BuiltinComponentSpec {
        alias: "LoopController",
        category: ComponentCategory::Controller,
        capability_id: "runtime.LoopController",
        availability: ComponentAvailability::Native,
    },
    BuiltinComponentSpec {
        alias: "IfController",
        category: ComponentCategory::Controller,
        capability_id: "runtime.IfController",
        availability: ComponentAvailability::Native,
    },
    BuiltinComponentSpec {
        alias: "WhileController",
        category: ComponentCategory::Controller,
        capability_id: "runtime.WhileController",
        availability: ComponentAvailability::Native,
    },
    BuiltinComponentSpec {
        alias: "ForEachController",
        category: ComponentCategory::Controller,
        capability_id: "runtime.ForEachController",
        availability: ComponentAvailability::Native,
    },
    BuiltinComponentSpec {
        alias: "ForeachController",
        category: ComponentCategory::Controller,
        capability_id: "runtime.ForeachController",
        availability: ComponentAvailability::Native,
    },
    BuiltinComponentSpec {
        alias: "SwitchController",
        category: ComponentCategory::Controller,
        capability_id: "runtime.SwitchController",
        availability: ComponentAvailability::Native,
    },
    BuiltinComponentSpec {
        alias: "InterleaveControl",
        category: ComponentCategory::Controller,
        capability_id: "runtime.InterleaveControl",
        availability: ComponentAvailability::Native,
    },
    BuiltinComponentSpec {
        alias: "RandomController",
        category: ComponentCategory::Controller,
        capability_id: "runtime.RandomController",
        availability: ComponentAvailability::Native,
    },
    BuiltinComponentSpec {
        alias: "RandomOrderController",
        category: ComponentCategory::Controller,
        capability_id: "runtime.RandomOrderController",
        availability: ComponentAvailability::Native,
    },
    BuiltinComponentSpec {
        alias: "OnceOnlyController",
        category: ComponentCategory::Controller,
        capability_id: "runtime.OnceOnlyController",
        availability: ComponentAvailability::Native,
    },
    BuiltinComponentSpec {
        alias: "ThroughputController",
        category: ComponentCategory::Controller,
        capability_id: "runtime.ThroughputController",
        availability: ComponentAvailability::Native,
    },
    BuiltinComponentSpec {
        alias: "RunTime",
        category: ComponentCategory::Controller,
        capability_id: "runtime.RunTime",
        availability: ComponentAvailability::Native,
    },
    BuiltinComponentSpec {
        alias: "RuntimeController",
        category: ComponentCategory::Controller,
        capability_id: "runtime.RuntimeController",
        availability: ComponentAvailability::Native,
    },
    BuiltinComponentSpec {
        alias: "TransactionController",
        category: ComponentCategory::Controller,
        capability_id: "runtime.TransactionController",
        availability: ComponentAvailability::Native,
    },
    BuiltinComponentSpec {
        alias: "CriticalSectionController",
        category: ComponentCategory::Controller,
        capability_id: "runtime.CriticalSectionController",
        availability: ComponentAvailability::Native,
    },
    BuiltinComponentSpec {
        alias: "ModuleController",
        category: ComponentCategory::Replaceable,
        capability_id: "runtime.controller.ModuleController",
        availability: ComponentAvailability::Native,
    },
    BuiltinComponentSpec {
        alias: "IncludeController",
        category: ComponentCategory::Replaceable,
        capability_id: "runtime.controller.IncludeController",
        availability: ComponentAvailability::Native,
    },
    BuiltinComponentSpec {
        alias: "RecordingController",
        category: ComponentCategory::Controller,
        capability_id: "runtime.controller.recording",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.protocol.http.control.RecordingController",
        category: ComponentCategory::Controller,
        capability_id: "runtime.controller.recording",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "DebugSampler",
        category: ComponentCategory::Sampler,
        capability_id: "runtime.DebugSampler",
        availability: ComponentAvailability::Native,
    },
    BuiltinComponentSpec {
        alias: "HTTPHC4Impl",
        category: ComponentCategory::Sampler,
        capability_id: "runtime.HTTPHC4Impl",
        availability: ComponentAvailability::Native,
    },
    BuiltinComponentSpec {
        alias: "HTTPSamplerProxy",
        category: ComponentCategory::Sampler,
        capability_id: "runtime.HTTPSamplerProxy",
        availability: ComponentAvailability::Native,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.protocol.http.sampler.HTTPSamplerProxy",
        category: ComponentCategory::Sampler,
        capability_id: "runtime.HTTPSamplerProxy",
        availability: ComponentAvailability::Native,
    },
    BuiltinComponentSpec {
        alias: "ResultCollector",
        category: ComponentCategory::Listener,
        capability_id: "runtime.ResultCollector",
        availability: ComponentAvailability::Native,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.reporters.ResultCollector",
        category: ComponentCategory::Listener,
        capability_id: "runtime.ResultCollector",
        availability: ComponentAvailability::Native,
    },
    BuiltinComponentSpec {
        alias: "UserParameters",
        category: ComponentCategory::Preprocessor,
        capability_id: "runtime.UserParameters",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.modifiers.UserParameters",
        category: ComponentCategory::Preprocessor,
        capability_id: "runtime.UserParameters",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "RegExUserParameters",
        category: ComponentCategory::Preprocessor,
        capability_id: "runtime.RegExUserParameters",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.protocol.http.modifier.RegExUserParameters",
        category: ComponentCategory::Preprocessor,
        capability_id: "runtime.RegExUserParameters",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "SampleTimeout",
        category: ComponentCategory::Preprocessor,
        capability_id: "runtime.SampleTimeout",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.modifiers.SampleTimeout",
        category: ComponentCategory::Preprocessor,
        capability_id: "runtime.SampleTimeout",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "URLRewritingModifier",
        category: ComponentCategory::Preprocessor,
        capability_id: "runtime.URLRewritingModifier",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.protocol.http.modifier.URLRewritingModifier",
        category: ComponentCategory::Preprocessor,
        capability_id: "runtime.URLRewritingModifier",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "UserParameterModifier",
        category: ComponentCategory::Preprocessor,
        capability_id: "runtime.UserParameterModifier",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.protocol.http.modifier.UserParameterModifier",
        category: ComponentCategory::Preprocessor,
        capability_id: "runtime.UserParameterModifier",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "ParamMask",
        category: ComponentCategory::Preprocessor,
        capability_id: "runtime.external.ParamMask",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.protocol.http.modifier.ParamMask",
        category: ComponentCategory::Preprocessor,
        capability_id: "runtime.external.ParamMask",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "ParamModifier",
        category: ComponentCategory::Preprocessor,
        capability_id: "runtime.external.ParamModifier",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.protocol.http.modifier.ParamModifier",
        category: ComponentCategory::Preprocessor,
        capability_id: "runtime.external.ParamModifier",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "AnchorModifier",
        category: ComponentCategory::Preprocessor,
        capability_id: "runtime.external.AnchorModifier",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.protocol.http.modifier.AnchorModifier",
        category: ComponentCategory::Preprocessor,
        capability_id: "runtime.external.AnchorModifier",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "RegexExtractor",
        category: ComponentCategory::Postprocessor,
        capability_id: "runtime.RegexExtractor",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.extractor.RegexExtractor",
        category: ComponentCategory::Postprocessor,
        capability_id: "runtime.RegexExtractor",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "BoundaryExtractor",
        category: ComponentCategory::Postprocessor,
        capability_id: "runtime.BoundaryExtractor",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.extractor.BoundaryExtractor",
        category: ComponentCategory::Postprocessor,
        capability_id: "runtime.BoundaryExtractor",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "DebugPostProcessor",
        category: ComponentCategory::Postprocessor,
        capability_id: "runtime.DebugPostProcessor",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.extractor.DebugPostProcessor",
        category: ComponentCategory::Postprocessor,
        capability_id: "runtime.DebugPostProcessor",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "ResultAction",
        category: ComponentCategory::Postprocessor,
        capability_id: "runtime.ResultAction",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.reporters.ResultAction",
        category: ComponentCategory::Postprocessor,
        capability_id: "runtime.ResultAction",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "JSONPostProcessor",
        category: ComponentCategory::Postprocessor,
        capability_id: "runtime.external.JSONPostProcessor",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.extractor.json.jsonpath.JSONPostProcessor",
        category: ComponentCategory::Postprocessor,
        capability_id: "runtime.external.JSONPostProcessor",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "JMESPathExtractor",
        category: ComponentCategory::Postprocessor,
        capability_id: "runtime.external.JMESPathExtractor",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.extractor.json.jmespath.JMESPathExtractor",
        category: ComponentCategory::Postprocessor,
        capability_id: "runtime.external.JMESPathExtractor",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "HtmlExtractor",
        category: ComponentCategory::Postprocessor,
        capability_id: "runtime.external.HtmlExtractor",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.extractor.HtmlExtractor",
        category: ComponentCategory::Postprocessor,
        capability_id: "runtime.external.HtmlExtractor",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "XPathExtractor",
        category: ComponentCategory::Postprocessor,
        capability_id: "runtime.external.XPathExtractor",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.extractor.XPathExtractor",
        category: ComponentCategory::Postprocessor,
        capability_id: "runtime.external.XPathExtractor",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "XPath2Extractor",
        category: ComponentCategory::Postprocessor,
        capability_id: "runtime.external.XPath2Extractor",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.extractor.XPath2Extractor",
        category: ComponentCategory::Postprocessor,
        capability_id: "runtime.external.XPath2Extractor",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "JSR223PostProcessor",
        category: ComponentCategory::Postprocessor,
        capability_id: "runtime.external.JSR223PostProcessor",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.extractor.JSR223PostProcessor",
        category: ComponentCategory::Postprocessor,
        capability_id: "runtime.external.JSR223PostProcessor",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "BeanShellPostProcessor",
        category: ComponentCategory::Postprocessor,
        capability_id: "runtime.external.BeanShellPostProcessor",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.extractor.BeanShellPostProcessor",
        category: ComponentCategory::Postprocessor,
        capability_id: "runtime.external.BeanShellPostProcessor",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "BSFPostProcessor",
        category: ComponentCategory::Postprocessor,
        capability_id: "runtime.external.BSFPostProcessor",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.extractor.BSFPostProcessor",
        category: ComponentCategory::Postprocessor,
        capability_id: "runtime.external.BSFPostProcessor",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "JDBCPostProcessor",
        category: ComponentCategory::Postprocessor,
        capability_id: "runtime.external.JDBCPostProcessor",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.protocol.jdbc.processor.JDBCPostProcessor",
        category: ComponentCategory::Postprocessor,
        capability_id: "runtime.external.JDBCPostProcessor",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "JSR223PreProcessor",
        category: ComponentCategory::Preprocessor,
        capability_id: "runtime.external.JSR223PreProcessor",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.modifiers.JSR223PreProcessor",
        category: ComponentCategory::Preprocessor,
        capability_id: "runtime.external.JSR223PreProcessor",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "BeanShellPreProcessor",
        category: ComponentCategory::Preprocessor,
        capability_id: "runtime.external.BeanShellPreProcessor",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.modifiers.BeanShellPreProcessor",
        category: ComponentCategory::Preprocessor,
        capability_id: "runtime.external.BeanShellPreProcessor",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "BSFPreProcessor",
        category: ComponentCategory::Preprocessor,
        capability_id: "runtime.external.BSFPreProcessor",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.modifiers.BSFPreProcessor",
        category: ComponentCategory::Preprocessor,
        capability_id: "runtime.external.BSFPreProcessor",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "JDBCPreProcessor",
        category: ComponentCategory::Preprocessor,
        capability_id: "runtime.external.JDBCPreProcessor",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.protocol.jdbc.processor.JDBCPreProcessor",
        category: ComponentCategory::Preprocessor,
        capability_id: "runtime.external.JDBCPreProcessor",
        availability: ComponentAvailability::External,
    },
    // Configuration elements.  These aliases are deliberately registered
    // even when the standalone executable has no corresponding decoder: a
    // recognized element must produce a stable unavailable/external result,
    // not be mistaken for an unknown plugin or silently ignored.
    BuiltinComponentSpec {
        alias: "CSVDataSet",
        category: ComponentCategory::Configuration,
        capability_id: "runtime.CSVDataSet",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.config.CSVDataSet",
        category: ComponentCategory::Configuration,
        capability_id: "runtime.CSVDataSet",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "AuthManager",
        category: ComponentCategory::Configuration,
        capability_id: "runtime.AuthManager",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.protocol.http.control.AuthManager",
        category: ComponentCategory::Configuration,
        capability_id: "runtime.AuthManager",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "CacheManager",
        category: ComponentCategory::Configuration,
        capability_id: "runtime.CacheManager",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.protocol.http.control.CacheManager",
        category: ComponentCategory::Configuration,
        capability_id: "runtime.CacheManager",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "CookieManager",
        category: ComponentCategory::Configuration,
        capability_id: "runtime.CookieManager",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.protocol.http.control.CookieManager",
        category: ComponentCategory::Configuration,
        capability_id: "runtime.CookieManager",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "DNSCacheManager",
        category: ComponentCategory::Configuration,
        capability_id: "runtime.DNSCacheManager",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.protocol.http.control.DNSCacheManager",
        category: ComponentCategory::Configuration,
        capability_id: "runtime.DNSCacheManager",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "HeaderManager",
        category: ComponentCategory::Configuration,
        capability_id: "runtime.HeaderManager",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.protocol.http.control.HeaderManager",
        category: ComponentCategory::Configuration,
        capability_id: "runtime.HeaderManager",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "JDBCDataSource",
        category: ComponentCategory::Configuration,
        capability_id: "runtime.external.JDBCDataSource",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.protocol.jdbc.config.DataSourceElement",
        category: ComponentCategory::Configuration,
        capability_id: "runtime.external.JDBCDataSource",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "JavaConfig",
        category: ComponentCategory::Configuration,
        capability_id: "runtime.external.JavaConfig",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.protocol.java.config.JavaConfig",
        category: ComponentCategory::Configuration,
        capability_id: "runtime.external.JavaConfig",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "KeystoreConfig",
        category: ComponentCategory::Configuration,
        capability_id: "runtime.external.KeystoreConfig",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.config.KeystoreConfig",
        category: ComponentCategory::Configuration,
        capability_id: "runtime.external.KeystoreConfig",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "LoginConfig",
        category: ComponentCategory::Configuration,
        capability_id: "runtime.LoginConfig",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.config.LoginConfig",
        category: ComponentCategory::Configuration,
        capability_id: "runtime.LoginConfig",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "LDAPArguments",
        category: ComponentCategory::Configuration,
        capability_id: "runtime.external.LDAPArguments",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "RandomVariableConfig",
        category: ComponentCategory::Configuration,
        capability_id: "runtime.RandomVariableConfig",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.config.RandomVariableConfig",
        category: ComponentCategory::Configuration,
        capability_id: "runtime.RandomVariableConfig",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "CounterConfig",
        category: ComponentCategory::Configuration,
        capability_id: "runtime.CounterConfig",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.modifiers.CounterConfig",
        category: ComponentCategory::Configuration,
        capability_id: "runtime.CounterConfig",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "MongoSourceElement",
        category: ComponentCategory::Configuration,
        capability_id: "runtime.external.MongoSourceElement",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.protocol.mongodb.config.MongoSourceElement",
        category: ComponentCategory::Configuration,
        capability_id: "runtime.external.MongoSourceElement",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "BoltConnectionElement",
        category: ComponentCategory::Configuration,
        capability_id: "runtime.external.BoltConnectionElement",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.protocol.bolt.config.BoltConnectionElement",
        category: ComponentCategory::Configuration,
        capability_id: "runtime.external.BoltConnectionElement",
        availability: ComponentAvailability::External,
    },
    // External and deprecated samplers.  The class identity is retained so
    // admission can name the exact required service/JVM boundary.
    BuiltinComponentSpec {
        alias: "AccessLogSampler",
        category: ComponentCategory::Sampler,
        capability_id: "runtime.external.AccessLogSampler",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.protocol.http.sampler.AccessLogSampler",
        category: ComponentCategory::Sampler,
        capability_id: "runtime.external.AccessLogSampler",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "AjpSampler",
        category: ComponentCategory::Sampler,
        capability_id: "runtime.external.AjpSampler",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "BeanShellSampler",
        category: ComponentCategory::Sampler,
        capability_id: "runtime.external.BeanShellSampler",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "BSFSampler",
        category: ComponentCategory::Sampler,
        capability_id: "runtime.external.BSFSampler",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "FTPSampler",
        category: ComponentCategory::Sampler,
        capability_id: "runtime.external.FTPSampler",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.protocol.ftp.sampler.FTPSampler",
        category: ComponentCategory::Sampler,
        capability_id: "runtime.external.FTPSampler",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "JavaSampler",
        category: ComponentCategory::Sampler,
        capability_id: "runtime.external.JavaSampler",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "JDBCSampler",
        category: ComponentCategory::Sampler,
        capability_id: "runtime.external.JDBCSampler",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.protocol.jdbc.sampler.JDBCSampler",
        category: ComponentCategory::Sampler,
        capability_id: "runtime.external.JDBCSampler",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "JMSSampler",
        category: ComponentCategory::Sampler,
        capability_id: "runtime.external.JMSSampler",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "JSR223Sampler",
        category: ComponentCategory::Sampler,
        capability_id: "runtime.external.JSR223Sampler",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "JUnitSampler",
        category: ComponentCategory::Sampler,
        capability_id: "runtime.external.JUnitSampler",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "LDAPSampler",
        category: ComponentCategory::Sampler,
        capability_id: "runtime.external.LDAPSampler",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "LDAPExtSampler",
        category: ComponentCategory::Sampler,
        capability_id: "runtime.external.LDAPExtSampler",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "MailReaderSampler",
        category: ComponentCategory::Sampler,
        capability_id: "runtime.external.MailReaderSampler",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "MongoScriptSampler",
        category: ComponentCategory::Sampler,
        capability_id: "runtime.external.MongoScriptSampler",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "BoltSampler",
        category: ComponentCategory::Sampler,
        capability_id: "runtime.external.BoltSampler",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "PublisherSampler",
        category: ComponentCategory::Sampler,
        capability_id: "runtime.external.PublisherSampler",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "SubscriberSampler",
        category: ComponentCategory::Sampler,
        capability_id: "runtime.external.SubscriberSampler",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "SmtpSampler",
        category: ComponentCategory::Sampler,
        capability_id: "runtime.external.SmtpSampler",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "SoapSampler",
        category: ComponentCategory::Sampler,
        capability_id: "runtime.external.SoapSampler",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "SystemSampler",
        category: ComponentCategory::Sampler,
        capability_id: "runtime.external.SystemSampler",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "TCPSampler",
        category: ComponentCategory::Sampler,
        capability_id: "runtime.external.TCPSampler",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "WebServiceSampler",
        category: ComponentCategory::Sampler,
        capability_id: "runtime.external.WebServiceSampler",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "TestAction",
        category: ComponentCategory::Sampler,
        capability_id: "runtime.TestAction",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "HTTPSampler2",
        category: ComponentCategory::Sampler,
        capability_id: "runtime.external.HTTPSampler2",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "org.apache.jmeter.protocol.http.sampler.HTTPSamplerFull",
        category: ComponentCategory::Sampler,
        capability_id: "runtime.HTTPSamplerProxy",
        availability: ComponentAvailability::Native,
    },
    // Listener/result-consumer vocabulary.  ResultCollector is the only
    // native scope listener in this runtime wave; all other known listeners
    // remain explicitly unavailable or external.
    BuiltinComponentSpec {
        alias: "BackendListener",
        category: ComponentCategory::Listener,
        capability_id: "runtime.external.BackendListener",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "BeanShellListener",
        category: ComponentCategory::Listener,
        capability_id: "runtime.external.BeanShellListener",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "BSFListener",
        category: ComponentCategory::Listener,
        capability_id: "runtime.external.BSFListener",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "JSR223Listener",
        category: ComponentCategory::Listener,
        capability_id: "runtime.external.JSR223Listener",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "MailerResultCollector",
        category: ComponentCategory::Listener,
        capability_id: "runtime.external.MailerResultCollector",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "ResultSaver",
        category: ComponentCategory::Listener,
        capability_id: "runtime.ResultSaver",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "SimpleDataWriter",
        category: ComponentCategory::Listener,
        capability_id: "runtime.SimpleDataWriter",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "StatVisualizer",
        category: ComponentCategory::Listener,
        capability_id: "runtime.StatVisualizer",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "SummaryReport",
        category: ComponentCategory::Listener,
        capability_id: "runtime.SummaryReport",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "GraphVisualizer",
        category: ComponentCategory::Listener,
        capability_id: "runtime.GraphVisualizer",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "GraphAccumVisualizer",
        category: ComponentCategory::Listener,
        capability_id: "runtime.GraphAccumVisualizer",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "RespTimeGraphVisualizer",
        category: ComponentCategory::Listener,
        capability_id: "runtime.RespTimeGraphVisualizer",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "TableVisualizer",
        category: ComponentCategory::Listener,
        capability_id: "runtime.TableVisualizer",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "ViewResultsFullVisualizer",
        category: ComponentCategory::Listener,
        capability_id: "runtime.ViewResultsFullVisualizer",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "AssertionVisualizer",
        category: ComponentCategory::Listener,
        capability_id: "runtime.AssertionVisualizer",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "ComparisonVisualizer",
        category: ComponentCategory::Listener,
        capability_id: "runtime.ComparisonVisualizer",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "DistributionGraphVisualizer",
        category: ComponentCategory::Listener,
        capability_id: "runtime.DistributionGraphVisualizer",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "MonitorHealthVisualizer",
        category: ComponentCategory::Listener,
        capability_id: "runtime.MonitorHealthVisualizer",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "MailerVisualizer",
        category: ComponentCategory::Listener,
        capability_id: "runtime.MailerVisualizer",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "SplineVisualizer",
        category: ComponentCategory::Listener,
        capability_id: "runtime.SplineVisualizer",
        availability: ComponentAvailability::Unavailable,
    },
    BuiltinComponentSpec {
        alias: "StatGraphVisualizer",
        category: ComponentCategory::Listener,
        capability_id: "runtime.StatGraphVisualizer",
        availability: ComponentAvailability::Unavailable,
    },
    // Legacy report aliases remain loadable and diagnosable, but are not
    // transparent native listeners.
    BuiltinComponentSpec {
        alias: "ReportPlan",
        // PlanCompiler treats generic lifecycle entries as preservation-only;
        // use an unavailable controller-shaped owner here so an enabled
        // legacy report root cannot disappear silently before its external
        // capability is diagnosed.
        category: ComponentCategory::Controller,
        capability_id: "runtime.external.ReportPlan",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "ReportPage",
        category: ComponentCategory::Listener,
        capability_id: "runtime.external.ReportPage",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "ReportTable",
        category: ComponentCategory::Listener,
        capability_id: "runtime.external.ReportTable",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "LineGraph",
        category: ComponentCategory::Listener,
        capability_id: "runtime.external.LineGraph",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "BarChart",
        category: ComponentCategory::Listener,
        capability_id: "runtime.external.BarChart",
        availability: ComponentAvailability::External,
    },
    BuiltinComponentSpec {
        alias: "HTMLReportWriter",
        category: ComponentCategory::Listener,
        capability_id: "runtime.external.HTMLReportWriter",
        availability: ComponentAvailability::External,
    },
];

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
    /// Creates a component binding from a capability ID.
    ///
    /// IDs in an explicitly external namespace are normalized to
    /// [`ComponentAvailability::External`] even when this constructor is
    /// used, so a caller cannot accidentally advertise a JVM/plugin class as
    /// native.
    #[must_use]
    pub fn native(
        test_class: impl Into<String>,
        category: ComponentCategory,
        capability_id: impl Into<String>,
    ) -> Self {
        let capability_id = capability_id.into();
        let external = capability_requires_external(&capability_id);
        Self {
            test_class: test_class.into(),
            category,
            capability_id,
            external,
            availability: if external {
                ComponentAvailability::External
            } else {
                ComponentAvailability::Native
            },
        }
    }

    /// Marks a binding as requiring an external/JVM/plugin capability.
    #[must_use]
    pub fn external(mut self) -> Self {
        self.external = true;
        self.availability = ComponentAvailability::External;
        self
    }

    /// Marks a recognized class as unavailable without claiming a JVM path.
    #[must_use]
    pub fn unavailable(mut self) -> Self {
        self.external = false;
        self.availability = ComponentAvailability::Unavailable;
        self
    }

    /// Returns the closed execution-support state.
    #[must_use]
    pub const fn availability(&self) -> ComponentAvailability {
        self.availability
    }

    /// Returns whether the binding is a native implementation path.
    #[must_use]
    pub const fn is_native(&self) -> bool {
        matches!(self.availability, ComponentAvailability::Native)
    }

    /// Returns whether the binding requires an explicit external boundary.
    #[must_use]
    pub const fn is_external(&self) -> bool {
        matches!(self.availability, ComponentAvailability::External)
    }

    /// Returns whether the class is recognized but currently unavailable.
    #[must_use]
    pub const fn is_unavailable(&self) -> bool {
        matches!(self.availability, ComponentAvailability::Unavailable)
    }
}

/// Returns whether a capability ID crosses the explicit JVM/service/RMI
/// boundary.  Class aliases and capability IDs are both checked by the
/// registry so a caller cannot accidentally reclassify an external adapter as
/// native by constructing a binding through the generic constructor.
pub(crate) fn capability_requires_external(capability_id: &str) -> bool {
    capability_id.starts_with("runtime.external.")
        || capability_id.starts_with("runtime.assertion.jvm.")
        || capability_id.starts_with("jmeter.rmi")
        || matches!(capability_id, "assertion.json" | "assertion.jmespath")
}

fn normalize_binding(mut binding: ComponentBinding) -> ComponentBinding {
    match binding.availability {
        ComponentAvailability::External => binding.external = true,
        ComponentAvailability::Unavailable => binding.external = false,
        ComponentAvailability::Native => {
            if binding.external || capability_requires_external(&binding.capability_id) {
                binding.external = true;
                binding.availability = ComponentAvailability::External;
            }
        }
    }
    binding
}

/// A class registry used by the scope compiler.
#[derive(Clone, Debug, Default)]
pub struct ComponentRegistry {
    bindings: BTreeMap<String, ComponentBinding>,
    timer_bindings: BTreeMap<String, TimerBinding>,
}

fn binding_from_spec(spec: BuiltinComponentSpec) -> ComponentBinding {
    let binding = ComponentBinding::native(spec.alias, spec.category, spec.capability_id);
    match spec.availability {
        ComponentAvailability::Native => binding,
        ComponentAvailability::External => binding.external(),
        ComponentAvailability::Unavailable => binding.unavailable(),
    }
}

/// Returns the canonical built-in binding for one exact alias.
///
/// This helper intentionally includes the timer and assertion tables as well
/// as [`BUILTIN_COMPONENT_SPECS`], so a caller never needs a second class-name
/// match statement to answer the same registry question.
pub(crate) fn builtin_component_binding(class: &str) -> Option<ComponentBinding> {
    if let Some(alias) = builtin_timer_aliases()
        .iter()
        .find(|alias| alias.alias == class)
    {
        let binding =
            ComponentBinding::native(alias.alias, ComponentCategory::Timer, alias.capability_id);
        return Some(if alias.external {
            binding.external()
        } else {
            binding
        });
    }
    if let Some(spec) = BUILTIN_COMPONENT_SPECS
        .iter()
        .find(|spec| spec.alias == class)
        .copied()
    {
        return Some(binding_from_spec(spec));
    }
    JMETER_ASSERTION_BINDINGS
        .iter()
        .find(|(alias, _)| *alias == class)
        .map(|(alias, capability_id)| {
            let binding =
                ComponentBinding::native(*alias, ComponentCategory::Assertion, *capability_id);
            if capability_requires_external(capability_id) {
                binding.external()
            } else {
                binding
            }
        })
}

impl ComponentRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a class or alias, retaining insertion-independent lookup.
    pub fn register(&mut self, binding: ComponentBinding) {
        let binding = normalize_binding(binding);
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
        self.register(ComponentBinding::native(
            alias.clone(),
            ComponentCategory::Timer,
            capability_id,
        ));
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
        self.register(
            ComponentBinding::native(alias.clone(), ComponentCategory::Timer, capability_id)
                .external(),
        );
        self.timer_bindings
            .insert(alias, TimerBinding::ExternalScript);
    }

    /// Registers a class in one call, preserving explicit capability-boundary
    /// normalization performed by [`ComponentBinding::native`].
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
        for spec in BUILTIN_COMPONENT_SPECS {
            registry.register(binding_from_spec(*spec));
        }
        for alias in builtin_timer_aliases() {
            if alias.external {
                registry.register_external_timer(alias.alias, alias.capability_id);
            } else {
                registry.register_timer(alias.alias, alias.binding, alias.capability_id);
            }
        }
        for (name, _) in JMETER_ASSERTION_BINDINGS {
            if let Some(binding) = builtin_component_binding(name) {
                registry.register(binding);
            }
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
            || !matches!(
                self.binding.test_class.as_str(),
                "ResultCollector" | "org.apache.jmeter.reporters.ResultCollector"
            )
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
    /// Configuration from the sampler's nearest scope outward.
    pub configurations: Vec<ComponentBinding>,
    /// Preprocessors from outermost to innermost scope.
    pub preprocessors: Vec<ComponentBinding>,
    /// Timers from the sampler's nearest scope outward.
    pub timers: Vec<ComponentBinding>,
    /// The sampler binding.
    pub sampler: ComponentBinding,
    /// Postprocessors from outermost to innermost scope.
    pub postprocessors: Vec<ComponentBinding>,
    /// Assertions from outermost to innermost scope.
    pub assertions: Vec<ComponentBinding>,
    /// Listeners from the sampler's nearest scope outward, preserving sibling
    /// order within each scope.
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
    /// Returns configuration records from the nearest scope outward.
    #[must_use]
    pub fn configuration_nodes(&self) -> &[ScopeComponent] {
        &self.configuration_components
    }

    /// Returns all preprocessor records in lexical scope order.
    #[must_use]
    pub fn preprocessor_nodes(&self) -> &[ScopeComponent] {
        &self.preprocessor_components
    }

    /// Returns timer records from the nearest scope outward.
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

    /// Returns listener records from the nearest scope outward.
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
    /// A factory declared an exact class identity different from the source
    /// alias under which it was selected.
    IdentityMismatch {
        node_id: NodeId,
        path: Vec<NodeId>,
        expected: String,
        actual: String,
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
            Self::IdentityMismatch { .. } => "runtime.scope.factory-identity-mismatch",
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
            Self::IdentityMismatch {
                node_id,
                path,
                expected,
                actual,
            } => write!(
                formatter,
                "{}: node {node_id} path {path:?}: expected factory for {expected:?}, got {actual:?}",
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
    /// A bounded count or metadata-size calculation overflowed before a
    /// configured limit could be applied.
    ArithmeticOverflow { path: Vec<NodeId>, detail: String },
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
            Self::ArithmeticOverflow { .. } => "runtime.scope.arithmetic-overflow",
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
            Self::ArithmeticOverflow { path, detail } => {
                write!(formatter, "{}: path {path:?}: {detail}", self.code())
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
    use crate::{
        ComponentFactoryRegistry, FactoryComponent, ScopeComponentFactory, UnsupportedSampler,
    };
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
            assert_eq!(
                binding.external,
                capability_requires_external(capability_id)
            );
        }
    }

    #[test]
    fn native_http_sampler_aliases_are_not_marked_external() {
        let registry = ComponentRegistry::builtins();
        for test_class in ["HTTPHC4Impl", "HTTPSamplerProxy"] {
            let binding = registry.get(test_class).expect("native HTTP sampler alias");
            assert_eq!(binding.category, ComponentCategory::Sampler);
            assert_eq!(binding.test_class, test_class);
            assert_eq!(binding.capability_id, format!("runtime.{test_class}"));
            assert!(!binding.external);
        }
    }

    #[test]
    fn processor_aliases_are_exact_and_do_not_promote_decoder_skeletons() {
        let registry = ComponentRegistry::builtins();
        for (class, category, capability_id, availability) in [
            (
                "SimpleController",
                ComponentCategory::Controller,
                "runtime.SimpleController",
                ComponentAvailability::Native,
            ),
            (
                "UserParameters",
                ComponentCategory::Preprocessor,
                "runtime.UserParameters",
                ComponentAvailability::Unavailable,
            ),
            (
                "SampleTimeout",
                ComponentCategory::Preprocessor,
                "runtime.SampleTimeout",
                ComponentAvailability::Unavailable,
            ),
            (
                "BoundaryExtractor",
                ComponentCategory::Postprocessor,
                "runtime.BoundaryExtractor",
                ComponentAvailability::Unavailable,
            ),
            (
                "URLRewritingModifier",
                ComponentCategory::Preprocessor,
                "runtime.URLRewritingModifier",
                ComponentAvailability::Unavailable,
            ),
            (
                "AnchorModifier",
                ComponentCategory::Preprocessor,
                "runtime.external.AnchorModifier",
                ComponentAvailability::External,
            ),
            (
                "ResultAction",
                ComponentCategory::Postprocessor,
                "runtime.ResultAction",
                ComponentAvailability::Unavailable,
            ),
            (
                "RecordingController",
                ComponentCategory::Controller,
                "runtime.controller.recording",
                ComponentAvailability::Unavailable,
            ),
        ] {
            let binding = registry.get(class).expect("exact built-in alias");
            assert_eq!(binding.category, category);
            assert_eq!(binding.capability_id, capability_id);
            assert_eq!(binding.availability(), availability);
        }
        assert!(registry.get("userparameters").is_none());
        assert!(registry.get("UserParametersPreProcessor").is_none());
        for (alias, fqcn) in [
            (
                "UserParameters",
                "org.apache.jmeter.modifiers.UserParameters",
            ),
            ("SampleTimeout", "org.apache.jmeter.modifiers.SampleTimeout"),
            (
                "URLRewritingModifier",
                "org.apache.jmeter.protocol.http.modifier.URLRewritingModifier",
            ),
            (
                "AnchorModifier",
                "org.apache.jmeter.protocol.http.modifier.AnchorModifier",
            ),
            (
                "BoundaryExtractor",
                "org.apache.jmeter.extractor.BoundaryExtractor",
            ),
            ("ResultAction", "org.apache.jmeter.reporters.ResultAction"),
            (
                "JDBCPostProcessor",
                "org.apache.jmeter.protocol.jdbc.processor.JDBCPostProcessor",
            ),
            (
                "JDBCPreProcessor",
                "org.apache.jmeter.protocol.jdbc.processor.JDBCPreProcessor",
            ),
        ] {
            let short = registry.get(alias).expect("short alias");
            let qualified = registry.get(fqcn).expect("fully-qualified alias");
            assert_eq!(qualified.category, short.category);
            assert_eq!(qualified.capability_id, short.capability_id);
            assert_eq!(qualified.availability(), short.availability());
            assert_eq!(qualified.test_class, fqcn);
        }
    }

    #[test]
    fn scope_registry_has_one_exact_vocabulary_for_fixture_component_families() {
        let registry = ComponentRegistry::builtins();
        for (class, category, availability, capability_id) in [
            (
                "CSVDataSet",
                ComponentCategory::Configuration,
                ComponentAvailability::Unavailable,
                "runtime.CSVDataSet",
            ),
            (
                "HeaderManager",
                ComponentCategory::Configuration,
                ComponentAvailability::Unavailable,
                "runtime.HeaderManager",
            ),
            (
                "JDBCPreProcessor",
                ComponentCategory::Preprocessor,
                ComponentAvailability::External,
                "runtime.external.JDBCPreProcessor",
            ),
            (
                "JSONPostProcessor",
                ComponentCategory::Postprocessor,
                ComponentAvailability::External,
                "runtime.external.JSONPostProcessor",
            ),
            (
                "ConstantTimer",
                ComponentCategory::Timer,
                ComponentAvailability::Native,
                "runtime.ConstantTimer",
            ),
            (
                "ResultCollector",
                ComponentCategory::Listener,
                ComponentAvailability::Native,
                "runtime.ResultCollector",
            ),
            (
                "HTTPSampler2",
                ComponentCategory::Sampler,
                ComponentAvailability::External,
                "runtime.external.HTTPSampler2",
            ),
            (
                "TransactionController",
                ComponentCategory::Controller,
                ComponentAvailability::Native,
                "runtime.TransactionController",
            ),
            (
                "ReflectionThreadGroup",
                ComponentCategory::Controller,
                ComponentAvailability::Unavailable,
                "runtime.lifecycle.reflection-thread-group",
            ),
        ] {
            let binding = registry.get(class).expect("fixture class binding");
            assert_eq!(binding.category, category, "{class}");
            assert_eq!(binding.availability(), availability, "{class}");
            assert_eq!(binding.capability_id, capability_id, "{class}");
        }

        for (short, qualified) in [
            (
                "JDBCDataSource",
                "org.apache.jmeter.protocol.jdbc.config.DataSourceElement",
            ),
            (
                "TestFragmentController",
                "org.apache.jmeter.control.TestFragmentController",
            ),
            ("WorkBench", "org.apache.jmeter.testelement.WorkBench"),
            (
                "ResultCollector",
                "org.apache.jmeter.reporters.ResultCollector",
            ),
        ] {
            let short_binding = registry.get(short).expect("short alias");
            let qualified_binding = registry.get(qualified).expect("qualified alias");
            assert_eq!(qualified_binding.category, short_binding.category);
            assert_eq!(
                qualified_binding.availability(),
                short_binding.availability()
            );
            assert_eq!(qualified_binding.capability_id, short_binding.capability_id);
        }

        // Embedded JMX property classes and application/plugin classes are
        // source data, not transparent executable scope elements.
        for class in [
            "FloatProperty",
            "JMSProperties",
            "JMSProperty",
            "com.example.plugin.PluginSampler",
        ] {
            assert!(registry.get(class).is_none(), "{class} must stay unknown");
        }
    }

    #[test]
    fn unavailable_lifecycle_bindings_fail_closed_instead_of_being_ignored() {
        for class in ["ReflectionThreadGroup", "OpenModelThreadGroupController"] {
            let mut tree = ElementTree::new();
            tree.insert_root(TestElement::named(class, "Gui", class))
                .expect("unavailable lifecycle node");
            let error = ScopeCompiler::builtins()
                .compile(&tree)
                .expect_err("unsupported lifecycle must be explicit");
            assert!(matches!(
                error,
                ScopeCompileError::Unsupported(UnsupportedComponent {
                    capability_id: Some(capability_id),
                    external: false,
                    ..
                }) if capability_id.starts_with("runtime.lifecycle.")
            ));
        }
    }

    #[test]
    fn simple_controller_is_a_native_scope_owner() {
        let mut tree = ElementTree::new();
        let plan = tree
            .insert_root(TestElement::named("TestPlan", "Gui", "plan"))
            .expect("plan");
        let group = tree
            .insert_child(plan, TestElement::named("ThreadGroup", "Gui", "group"))
            .expect("group");
        let controller = tree
            .insert_child(
                group,
                TestElement::named("SimpleController", "Gui", "sequence"),
            )
            .expect("controller");
        tree.insert_child(
            controller,
            TestElement::named("DebugSampler", "Gui", "sample"),
        )
        .expect("sampler");

        let plan = ScopeCompiler::builtins().compile(&tree).expect("scope");
        assert_eq!(plan.len(), 1);
    }

    #[test]
    fn provider_assertions_keep_their_external_jvm_boundary() {
        let registry = ComponentRegistry::builtins();
        for class in [
            "BeanShellAssertion",
            "BSFAssertion",
            "HTMLAssertion",
            "JSONPathAssertion",
            "JMESPathAssertion",
            "JSR223Assertion",
            "SMIMEAssertion",
            "XMLSchemaAssertion",
            "XPath2Assertion",
        ] {
            let binding = registry.get(class).expect("assertion alias");
            assert_eq!(binding.availability(), ComponentAvailability::External);
            assert!(binding.external);
        }
        for class in [
            "ResponseAssertion",
            "DurationAssertion",
            "SizeAssertion",
            "MD5HexAssertion",
            "XMLAssertion",
            "XPathAssertion",
        ] {
            let binding = registry.get(class).expect("native assertion alias");
            assert_eq!(binding.availability(), ComponentAvailability::Native);
            assert!(!binding.external);
        }
    }

    #[test]
    fn external_capability_ids_cannot_be_registered_as_native() {
        let mut registry = ComponentRegistry::new();
        registry.register(ComponentBinding::native(
            "ProviderProcessor",
            ComponentCategory::Postprocessor,
            "runtime.external.ProviderProcessor",
        ));
        let binding = registry.get("ProviderProcessor").expect("binding");
        assert_eq!(binding.availability(), ComponentAvailability::External);
        assert!(binding.external);
    }

    struct NativeHttpSamplerFactory;

    impl ScopeComponentFactory for NativeHttpSamplerFactory {
        fn create(
            &self,
            _component: &ScopeComponent,
        ) -> Result<FactoryComponent, ScopeFactoryError> {
            // The transport adapter belongs to the application edge. This
            // deterministic hook only proves that runtime can select an
            // exact native sampler registration without performing I/O.
            Ok(FactoryComponent::Sampler(Arc::new(
                UnsupportedSampler::new("native HTTP test hook"),
            )))
        }
    }

    #[test]
    fn native_http_sampler_aliases_accept_caller_owned_factories() {
        for test_class in ["HTTPHC4Impl", "HTTPSamplerProxy"] {
            let mut tree = ElementTree::new();
            tree.insert_root(TestElement::named(test_class, "HttpSamplerGui", "sample"))
                .expect("sampler");
            let mut factories = ComponentFactoryRegistry::with_capacity(1);
            factories
                .register(test_class, Arc::new(NativeHttpSamplerFactory))
                .expect("HTTP sampler factory");

            let packages = ScopeCompiler::builtins()
                .compile_with_factories(&tree, &factories)
                .expect("native HTTP sampler factory package");
            assert_eq!(packages.len(), 1);
        }
    }

    #[test]
    fn native_http_sampler_without_factory_is_typed_and_fail_closed() {
        let mut tree = ElementTree::new();
        tree.insert_root(TestElement::named(
            "HTTPSamplerProxy",
            "HttpSamplerGui",
            "sample",
        ))
        .expect("sampler");

        let error = ScopeCompiler::builtins()
            .compile_with_factories(&tree, &ComponentFactoryRegistry::default())
            .expect_err("HTTP transport must be supplied by the application edge");
        assert_eq!(error.code(), "runtime.scope.factory");
        assert!(matches!(
            error,
            ScopeCompileError::Factory {
                source: ScopeFactoryError::MissingFactory { test_class, .. }
            } if test_class == "HTTPSamplerProxy"
        ));
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
