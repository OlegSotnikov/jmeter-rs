// SPDX-License-Identifier: Apache-2.0
//! Application-owned admission for standalone built-in scope factories.
//!
//! The runtime owns the exact timer and assertion decoders.  This module only
//! composes that registry and keeps class classification separate from
//! executable-factory admission.  In particular, a class being known to the
//! runtime registry does not make it executable by the standalone application:
//! configuration elements still need a faithful
//! [`jmeter_rs_runtime::Configuration`] implementation, and external or
//! unavailable classes must fail closed.
//!
//! This module deliberately has no filesystem, environment, network, clock,
//! process, or expression-registry dependency.  Each builder call constructs
//! a fresh registry, so an application run cannot share mutable factory state
//! with another run or virtual user.

use std::fmt;
use std::sync::Arc;

use jmeter_rs_runtime::{
    ComponentAvailability, ComponentCategory, ComponentFactoryRegistry, ComponentRegistry,
    ScopeComponentFactory,
};

/// Maximum bytes retained for a validated class alias in diagnostics and
/// classification metadata.
pub const MAX_BUILTIN_CLASS_DIAGNOSTIC_BYTES: usize = 256;

/// Maximum bytes retained for a validated capability identifier in diagnostics
/// and classification metadata.
pub const MAX_BUILTIN_CAPABILITY_DIAGNOSTIC_BYTES: usize = 256;

/// Exact aliases which the application must classify but cannot execute as a
/// generic standalone scope configuration.
///
/// `Arguments` and `UserDefinedVariables` are retained here for scope
/// admission only.  Test-plan initial variables are decoded once by
/// `PlanCompiler` and installed into `EnginePlan`; registering a per-sampler
/// configuration factory would duplicate those variables and change scope.
/// `ConfigTestElement` is likewise deliberately not treated as a no-op: its
/// scope-correct HTTP Request Defaults behavior belongs to the versioned HTTP
/// compiler.
const APPLICATION_CLASSIFIED_ALIASES: &[(&str, ComponentCategory, &str, ComponentAvailability)] = &[
    (
        "org.apache.jmeter.config.Arguments",
        ComponentCategory::Configuration,
        "runtime.Arguments",
        ComponentAvailability::Native,
    ),
    (
        "org.apache.jmeter.config.UserDefinedVariables",
        ComponentCategory::Configuration,
        "runtime.UserDefinedVariables",
        ComponentAvailability::Native,
    ),
    (
        "org.apache.jmeter.config.ConfigTestElement",
        ComponentCategory::Configuration,
        "runtime.ConfigTestElement",
        ComponentAvailability::Native,
    ),
    // HTTP manager aliases are admission-visible but owned by the
    // versioned HTTP compiler, never by this generic scope registry.
    (
        "HTTPHeaderManager",
        ComponentCategory::Configuration,
        "runtime.HeaderManager",
        ComponentAvailability::Unavailable,
    ),
    (
        "org.apache.jmeter.protocol.http.control.HTTPHeaderManager",
        ComponentCategory::Configuration,
        "runtime.HeaderManager",
        ComponentAvailability::Unavailable,
    ),
];

/// A class alias copied only from the bounded built-in vocabulary.
///
/// The field is private so callers cannot construct an error or
/// classification containing an arbitrary unbounded source string.  Exact
/// spelling remains available through [`Self::as_str`].
#[derive(Clone, Eq, PartialEq)]
pub struct BuiltinClassAlias(String);

impl BuiltinClassAlias {
    fn from_known(value: String) -> Option<Self> {
        (value.len() <= MAX_BUILTIN_CLASS_DIAGNOSTIC_BYTES).then_some(Self(value))
    }

    /// Returns the exact validated class alias.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for BuiltinClassAlias {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("BuiltinClassAlias")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for BuiltinClassAlias {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A capability identifier copied only from the bounded built-in vocabulary.
#[derive(Clone, Eq, PartialEq)]
pub struct BuiltinCapabilityId(String);

impl BuiltinCapabilityId {
    fn from_known(value: String) -> Option<Self> {
        (value.len() <= MAX_BUILTIN_CAPABILITY_DIAGNOSTIC_BYTES).then_some(Self(value))
    }
}

impl fmt::Debug for BuiltinCapabilityId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("BuiltinCapabilityId")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for BuiltinCapabilityId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// The reason a classified class cannot be admitted as a standalone native
/// executable factory.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum BuiltinUnsupportedReason {
    /// Exact behavior crosses a JVM, plugin, service, or other external
    /// capability boundary.
    ExternalCapability,
    /// The class is known, but this build has no executable adapter for it.
    UnavailableCapability,
}

impl fmt::Display for BuiltinUnsupportedReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ExternalCapability => "external capability is not selected",
            Self::UnavailableCapability => "no standalone executable adapter is registered",
        })
    }
}

/// Classification metadata for one exact class alias.
///
/// Classification is intentionally independent from executable admission.
/// A native classification with `factory_registered == false` is a visible
/// capability gap, not an invitation to construct a placeholder component.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuiltinScopeClassification {
    /// The exact class alias supplied by the caller or retained by the
    /// runtime registry.  Matching is case-sensitive and never canonicalizes
    /// this value.
    pub test_class: BuiltinClassAlias,
    /// Runtime component category.
    pub category: ComponentCategory,
    /// Stable capability identity associated with the class.
    pub capability_id: BuiltinCapabilityId,
    /// Runtime-declared availability of the class.
    pub availability: ComponentAvailability,
    /// Whether the underlying runtime factory registry contains a hook for
    /// this exact alias.  This is not sufficient for admission when the
    /// class is external or unavailable.
    pub factory_registered: bool,
}

impl BuiltinScopeClassification {
    /// Returns whether this classification has a usable standalone factory.
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        matches!(self.availability, ComponentAvailability::Native) && self.factory_registered
    }
}

/// A typed failure from standalone built-in scope-factory admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuiltinFactoryError {
    /// The exact alias is not in the active built-in classification vocabulary.
    UnknownClass {
        /// Byte length of the unclassified alias. The alias itself is not
        /// retained because it is untrusted input.
        input_bytes: usize,
        /// Category the caller attempted to admit.
        expected: ComponentCategory,
    },
    /// The caller supplied an alias larger than the finite diagnostic bound.
    OversizeClass {
        /// Byte length of the rejected alias.
        input_bytes: usize,
        /// Maximum class-alias bytes accepted by this seam.
        limit: usize,
        /// Category the caller attempted to admit.
        expected: ComponentCategory,
    },
    /// The class is known, but the caller supplied the wrong category.
    WrongCategory {
        /// Exact class alias.
        test_class: BuiltinClassAlias,
        /// Category requested by the caller.
        expected: ComponentCategory,
        /// Category declared by the built-in registry.
        actual: ComponentCategory,
    },
    /// A native class is classified but has no faithful executable factory.
    MissingFactory {
        /// Exact class alias.
        test_class: BuiltinClassAlias,
        /// Declared category.
        category: ComponentCategory,
        /// Stable capability identity.
        capability_id: BuiltinCapabilityId,
    },
    /// A known class is intentionally outside the standalone native path.
    Unsupported {
        /// Exact class alias.
        test_class: BuiltinClassAlias,
        /// Declared category.
        category: ComponentCategory,
        /// Stable capability identity.
        capability_id: BuiltinCapabilityId,
        /// Why admission is rejected.
        reason: BuiltinUnsupportedReason,
    },
    /// A known alias had a capability identifier beyond the finite diagnostic
    /// bound. The identifier itself is not retained.
    OversizeCapability {
        /// Exact validated class alias.
        test_class: BuiltinClassAlias,
        /// Declared category.
        category: ComponentCategory,
        /// Byte length of the rejected capability identifier.
        capability_bytes: usize,
        /// Maximum capability bytes accepted by this seam.
        limit: usize,
    },
}

impl BuiltinFactoryError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnknownClass { .. } => "app.builtin-factory.unknown-class",
            Self::OversizeClass { .. } => "app.builtin-factory.class-too-long",
            Self::WrongCategory { .. } => "app.builtin-factory.category-mismatch",
            Self::MissingFactory { .. } => "app.builtin-factory.missing-factory",
            Self::Unsupported { .. } => "app.builtin-factory.unsupported",
            Self::OversizeCapability { .. } => "app.builtin-factory.capability-too-long",
        }
    }
}

impl fmt::Display for BuiltinFactoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownClass {
                input_bytes,
                expected,
            } => write!(
                formatter,
                "{}: unclassified class input is {input_bytes} bytes for {expected:?}",
                self.code()
            ),
            Self::OversizeClass {
                input_bytes,
                limit,
                expected,
            } => write!(
                formatter,
                "{}: class input is {input_bytes} bytes (limit {limit}) for {expected:?}",
                self.code()
            ),
            Self::WrongCategory {
                test_class,
                expected,
                actual,
            } => write!(
                formatter,
                "{}: class {test_class} is {actual:?}, not {expected:?}",
                self.code()
            ),
            Self::MissingFactory {
                test_class,
                category,
                capability_id,
            } => write!(
                formatter,
                "{}: class {test_class} category {category:?} capability {capability_id} has no faithful factory",
                self.code()
            ),
            Self::Unsupported {
                test_class,
                category,
                capability_id,
                reason,
            } => write!(
                formatter,
                "{}: class {test_class} category {category:?} capability {capability_id}: {reason}",
                self.code()
            ),
            Self::OversizeCapability {
                test_class,
                category,
                capability_bytes,
                limit,
            } => write!(
                formatter,
                "{}: class {test_class} category {category:?} capability is {capability_bytes} bytes (limit {limit})",
                self.code()
            ),
        }
    }
}

impl std::error::Error for BuiltinFactoryError {}

/// Fresh application-side registry for standalone built-in scope components.
///
/// The runtime registry contains only its exact timer/assertion vocabulary.
/// No sampler, processor, listener, or configuration hook is added here.
/// Configuration aliases remain available through [`Self::classify`] so the
/// caller can produce a precise admission error rather than silently dropping
/// them.
#[derive(Debug)]
pub struct BuiltinScopeFactoryRegistry {
    runtime: ComponentFactoryRegistry,
    classes: ComponentRegistry,
}

impl BuiltinScopeFactoryRegistry {
    fn new() -> Self {
        Self {
            runtime: ComponentFactoryRegistry::builtins(),
            classes: ComponentRegistry::builtins(),
        }
    }

    /// Consumes this wrapper and returns the exact runtime registry.
    #[must_use]
    pub fn into_runtime_registry(self) -> ComponentFactoryRegistry {
        self.runtime
    }

    /// Classifies one exact class alias without admitting it for execution.
    ///
    /// The returned alias is preserved byte-for-byte.  In particular,
    /// lower-case or otherwise similar names are not accepted as aliases.
    #[must_use]
    pub fn classify(&self, test_class: &str) -> Option<BuiltinScopeClassification> {
        let binding = self.binding_for(test_class)?;
        self.classification_from_binding(binding, test_class).ok()
    }

    fn binding_for(&self, test_class: &str) -> Option<jmeter_rs_runtime::ComponentBinding> {
        self.classes.get(test_class).cloned().or_else(|| {
            APPLICATION_CLASSIFIED_ALIASES
                .iter()
                .find(|(alias, _, _, _)| *alias == test_class)
                .map(|(alias, category, capability_id, availability)| {
                    let mut binding = jmeter_rs_runtime::ComponentBinding::native(
                        *alias,
                        *category,
                        *capability_id,
                    );
                    binding = match availability {
                        ComponentAvailability::Native => binding,
                        ComponentAvailability::External => binding.external(),
                        ComponentAvailability::Unavailable => binding.unavailable(),
                    };
                    binding
                })
        })
    }

    fn classification_from_binding(
        &self,
        binding: jmeter_rs_runtime::ComponentBinding,
        test_class: &str,
    ) -> Result<BuiltinScopeClassification, BuiltinFactoryError> {
        let category = binding.category;
        let class_bytes = binding.test_class.len();
        let test_class = BuiltinClassAlias::from_known(binding.test_class).ok_or(
            BuiltinFactoryError::OversizeClass {
                input_bytes: class_bytes.max(test_class.len()),
                limit: MAX_BUILTIN_CLASS_DIAGNOSTIC_BYTES,
                expected: category,
            },
        )?;
        let capability_bytes = binding.capability_id.len();
        let capability_id =
            BuiltinCapabilityId::from_known(binding.capability_id).ok_or_else(|| {
                BuiltinFactoryError::OversizeCapability {
                    test_class: test_class.clone(),
                    category,
                    capability_bytes,
                    limit: MAX_BUILTIN_CAPABILITY_DIAGNOSTIC_BYTES,
                }
            })?;
        let factory_registered = self.runtime.get(test_class.as_str()).is_some();
        Ok(BuiltinScopeClassification {
            test_class,
            category,
            capability_id,
            availability: binding.availability,
            factory_registered,
        })
    }

    /// Admits one exact class alias as a native executable factory.
    ///
    /// This method checks category, runtime availability, and actual factory
    /// registration independently.  Callers that only need classification
    /// should use [`Self::classify`].
    pub fn factory_for(
        &self,
        test_class: &str,
        expected: ComponentCategory,
    ) -> Result<&Arc<dyn ScopeComponentFactory>, BuiltinFactoryError> {
        if test_class.len() > MAX_BUILTIN_CLASS_DIAGNOSTIC_BYTES {
            return Err(BuiltinFactoryError::OversizeClass {
                input_bytes: test_class.len(),
                limit: MAX_BUILTIN_CLASS_DIAGNOSTIC_BYTES,
                expected,
            });
        }
        let Some(binding) = self.binding_for(test_class) else {
            return Err(BuiltinFactoryError::UnknownClass {
                input_bytes: test_class.len(),
                expected,
            });
        };
        let classification = self.classification_from_binding(binding, test_class)?;
        if classification.category != expected {
            return Err(BuiltinFactoryError::WrongCategory {
                test_class: classification.test_class,
                expected,
                actual: classification.category,
            });
        }
        match classification.availability {
            ComponentAvailability::External => {
                return Err(BuiltinFactoryError::Unsupported {
                    test_class: classification.test_class,
                    category: classification.category,
                    capability_id: classification.capability_id,
                    reason: BuiltinUnsupportedReason::ExternalCapability,
                });
            }
            ComponentAvailability::Unavailable => {
                return Err(BuiltinFactoryError::Unsupported {
                    test_class: classification.test_class,
                    category: classification.category,
                    capability_id: classification.capability_id,
                    reason: BuiltinUnsupportedReason::UnavailableCapability,
                });
            }
            ComponentAvailability::Native => {}
        }
        self.runtime.get(classification.test_class.as_str()).ok_or(
            BuiltinFactoryError::MissingFactory {
                test_class: classification.test_class,
                category: classification.category,
                capability_id: classification.capability_id,
            },
        )
    }
}

/// Builds a fresh standalone built-in scope-factory registry.
#[must_use]
pub fn build_builtin_scope_factories() -> BuiltinScopeFactoryRegistry {
    BuiltinScopeFactoryRegistry::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use jmeter_rs_runtime::{ComponentBinding, builtin_timer_aliases};

    fn error_code(
        result: Result<&Arc<dyn ScopeComponentFactory>, BuiltinFactoryError>,
    ) -> &'static str {
        match result {
            Ok(_) => "app.builtin-factory.accepted",
            Err(error) => error.code(),
        }
    }

    #[test]
    fn exact_timer_and_assertion_vocabulary_comes_from_runtime() {
        let registry = build_builtin_scope_factories();
        for alias in builtin_timer_aliases() {
            let classification = registry.classify(alias.alias);
            assert!(
                classification.is_some(),
                "timer alias missing: {}",
                alias.alias
            );
            if let Some(classification) = classification {
                assert_eq!(classification.category, ComponentCategory::Timer);
                assert_eq!(classification.factory_registered, !alias.external);
                assert_eq!(classification.is_executable(), !alias.external);
                if alias.external {
                    assert!(
                        registry
                            .factory_for(alias.alias, ComponentCategory::Timer)
                            .is_err()
                    );
                } else {
                    assert!(
                        registry
                            .factory_for(alias.alias, ComponentCategory::Timer)
                            .is_ok()
                    );
                }
            }
        }

        let classes = ComponentRegistry::builtins();
        let mut assertions = 0usize;
        for binding in classes
            .iter()
            .filter(|binding| binding.category == ComponentCategory::Assertion)
        {
            assertions += 1;
            let classification = registry.classify(&binding.test_class);
            assert!(
                classification.is_some(),
                "assertion alias missing: {}",
                binding.test_class
            );
            if let Some(classification) = classification {
                assert_eq!(classification.test_class.as_str(), binding.test_class);
                assert_eq!(
                    classification.factory_registered,
                    registry.runtime.get(&binding.test_class).is_some()
                );
                let admission = registry.factory_for(&binding.test_class, binding.category);
                if binding.availability == ComponentAvailability::Native {
                    assert!(admission.is_ok());
                } else {
                    assert!(admission.is_err());
                }
            }
        }
        assert!(assertions > 0);
    }

    #[test]
    fn aliases_are_exact_and_case_sensitive() {
        let registry = build_builtin_scope_factories();
        assert!(registry.classify("ConstantTimer").is_some());
        assert!(registry.classify("constanttimer").is_none());
        assert!(
            registry
                .classify("org.apache.jmeter.timers.ConstantTimer")
                .is_none()
        );
        assert!(
            registry
                .classify("org.apache.jmeter.assertions.ResponseAssertion")
                .is_some()
        );
        let error = registry.factory_for("constanttimer", ComponentCategory::Timer);
        assert_eq!(error_code(error), "app.builtin-factory.unknown-class");
    }

    #[test]
    fn oversized_unknown_alias_is_length_only_and_redacted() {
        let registry = build_builtin_scope_factories();
        let sentinel =
            "SECRET-CLASS-".to_owned() + &"x".repeat(MAX_BUILTIN_CLASS_DIAGNOSTIC_BYTES + 17);
        let error = match registry.factory_for(&sentinel, ComponentCategory::Configuration) {
            Ok(_) => panic!("oversized alias must fail before lookup"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            BuiltinFactoryError::OversizeClass {
                input_bytes,
                limit: MAX_BUILTIN_CLASS_DIAGNOSTIC_BYTES,
                expected: ComponentCategory::Configuration,
            } if input_bytes == sentinel.len()
        ));
        assert!(!error.to_string().contains("SECRET-CLASS-"));
        assert!(!format!("{error:?}").contains("SECRET-CLASS-"));

        let unknown = "SECRET-UNKNOWN";
        let error = match registry.factory_for(unknown, ComponentCategory::Configuration) {
            Ok(_) => panic!("unknown alias must fail before lookup"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            BuiltinFactoryError::UnknownClass {
                input_bytes,
                expected: ComponentCategory::Configuration,
            } if input_bytes == unknown.len()
        ));
        assert!(!error.to_string().contains(unknown));
        assert!(!format!("{error:?}").contains(unknown));
    }

    #[test]
    fn oversized_capability_is_length_only_and_redacted() {
        let registry = build_builtin_scope_factories();
        let sentinel = "SECRET-CAPABILITY-".to_owned()
            + &"x".repeat(MAX_BUILTIN_CAPABILITY_DIAGNOSTIC_BYTES + 17);
        let sentinel_bytes = sentinel.len();
        let binding = ComponentBinding::native(
            "BoundedTestClass",
            ComponentCategory::Configuration,
            sentinel,
        );
        let error = match registry.classification_from_binding(binding, "BoundedTestClass") {
            Ok(_) => panic!("oversized capability must fail before admission"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            BuiltinFactoryError::OversizeCapability {
                capability_bytes,
                limit: MAX_BUILTIN_CAPABILITY_DIAGNOSTIC_BYTES,
                ..
            } if capability_bytes == sentinel_bytes
        ));
        assert!(!error.to_string().contains("SECRET-CAPABILITY-"));
        assert!(!format!("{error:?}").contains("SECRET-CAPABILITY-"));
    }

    #[test]
    fn wrong_category_is_rejected_before_factory_lookup() {
        let registry = build_builtin_scope_factories();
        let error = registry.factory_for("ConstantTimer", ComponentCategory::Assertion);
        assert!(matches!(
            error,
            Err(BuiltinFactoryError::WrongCategory {
                test_class,
                expected: ComponentCategory::Assertion,
                actual: ComponentCategory::Timer,
            }) if test_class.as_str() == "ConstantTimer"
        ));
    }

    #[test]
    fn arguments_user_variables_and_generic_config_are_typed_gaps() {
        let registry = build_builtin_scope_factories();
        for alias in [
            "Arguments",
            "org.apache.jmeter.config.Arguments",
            "UserDefinedVariables",
            "org.apache.jmeter.config.UserDefinedVariables",
            "ConfigTestElement",
            "org.apache.jmeter.config.ConfigTestElement",
        ] {
            let classification = registry.classify(alias);
            assert!(classification.is_some(), "config alias missing: {alias}");
            if let Some(classification) = classification {
                assert_eq!(classification.category, ComponentCategory::Configuration);
                assert!(!classification.factory_registered);
                assert!(matches!(
                    registry.factory_for(alias, ComponentCategory::Configuration),
                    Err(BuiltinFactoryError::MissingFactory { .. })
                ));
            }
        }
    }

    #[test]
    fn http_defaults_and_managers_are_not_accepted_by_generic_registry() {
        let registry = build_builtin_scope_factories();
        for alias in [
            "ConfigTestElement",
            "org.apache.jmeter.config.ConfigTestElement",
            "HeaderManager",
            "HTTPHeaderManager",
            "org.apache.jmeter.protocol.http.control.HeaderManager",
            "org.apache.jmeter.protocol.http.control.HTTPHeaderManager",
            "CookieManager",
            "CacheManager",
            "AuthManager",
            "DNSCacheManager",
        ] {
            let classification = registry.classify(alias);
            assert!(classification.is_some(), "HTTP alias missing: {alias}");
            let error = registry.factory_for(alias, ComponentCategory::Configuration);
            assert!(error.is_err(), "HTTP alias admitted: {alias}");
            if !matches!(
                alias,
                "ConfigTestElement" | "org.apache.jmeter.config.ConfigTestElement"
            ) {
                assert!(matches!(
                    error,
                    Err(BuiltinFactoryError::Unsupported { .. })
                ));
            }
        }
    }

    #[test]
    fn script_plugin_file_database_and_security_config_fail_closed() {
        let registry = build_builtin_scope_factories();
        for (alias, category) in [
            ("JSR223Timer", ComponentCategory::Timer),
            ("BeanShellTimer", ComponentCategory::Timer),
            ("BeanShellAssertion", ComponentCategory::Assertion),
            ("CSVDataSet", ComponentCategory::Configuration),
            ("JDBCDataSource", ComponentCategory::Configuration),
            ("KeystoreConfig", ComponentCategory::Configuration),
        ] {
            assert!(matches!(
                registry.factory_for(alias, category),
                Err(BuiltinFactoryError::Unsupported { .. })
            ));
        }
        assert!(matches!(
            registry.factory_for("com.example.PluginConfig", ComponentCategory::Configuration),
            Err(BuiltinFactoryError::UnknownClass { .. })
        ));
    }

    #[test]
    fn registry_is_bounded_and_does_not_add_non_scope_factories() {
        let registry = build_builtin_scope_factories();
        assert!(!registry.runtime.is_empty());
        assert!(registry.runtime.len() <= registry.runtime.max_entries());
        for (alias, category) in [
            ("DebugSampler", ComponentCategory::Sampler),
            ("HTTPSamplerProxy", ComponentCategory::Sampler),
            ("JSR223PreProcessor", ComponentCategory::Preprocessor),
            ("ResultCollector", ComponentCategory::Listener),
        ] {
            assert!(registry.runtime.get(alias).is_none());
            assert!(registry.factory_for(alias, category).is_err());
        }
    }

    #[test]
    fn each_builder_call_has_independent_factory_storage() {
        let first = build_builtin_scope_factories().into_runtime_registry();
        let second = build_builtin_scope_factories();
        assert_eq!(first.len(), second.runtime.len());
        assert!(first.get("application-only-test-hook").is_none());
        assert!(second.runtime.get("application-only-test-hook").is_none());
    }
}
