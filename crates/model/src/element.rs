// SPDX-License-Identifier: Apache-2.0
//! Semantic test-element metadata and state.

use core::fmt;

use crate::limits::ValidationState;
use crate::{
    MetadataField, ModelValidationError, OpaqueExtension, Properties, PropertyValue,
    SourceLocation, ValidationLimits,
};

/// Exact JMX metadata carried by one element.
///
/// These values are not Rust type names.  They are the exact upstream wire
/// values and must therefore be retained even for classes unknown to the
/// current capability profile.
#[derive(Clone, Default, Eq, Hash, PartialEq)]
pub struct ElementMetadata {
    /// Exact upstream `testclass` value.
    pub test_class: String,
    /// Exact upstream `guiclass` value.
    pub gui_class: String,
    /// Exact upstream `testname`/element name value.
    pub name: String,
}

impl fmt::Debug for ElementMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ElementMetadata")
            .field("test_class", &"<redacted>")
            .field("test_class_len", &self.test_class.len())
            .field("gui_class", &"<redacted>")
            .field("gui_class_len", &self.gui_class.len())
            .field("name", &"<redacted>")
            .field("name_len", &self.name.len())
            .finish()
    }
}

impl ElementMetadata {
    /// Creates metadata from exact upstream values.
    #[must_use]
    pub fn new(
        test_class: impl Into<String>,
        gui_class: impl Into<String>,
        name: impl Into<String>,
    ) -> Self {
        Self {
            test_class: test_class.into(),
            gui_class: gui_class.into(),
            name: name.into(),
        }
    }

    /// Returns the exact `testclass` wire value.
    #[must_use]
    pub fn testclass(&self) -> &str {
        &self.test_class
    }

    /// Returns the exact `guiclass` wire value.
    #[must_use]
    pub fn guiclass(&self) -> &str {
        &self.gui_class
    }

    /// Returns the exact element name.
    #[must_use]
    pub fn testname(&self) -> &str {
        &self.name
    }

    /// Validates required metadata and aggregate string usage.
    pub fn validate_with_limits(
        &self,
        limits: &ValidationLimits,
    ) -> Result<(), ModelValidationError> {
        let mut state = ValidationState::new(limits);
        self.validate_into(&mut state)
    }

    pub(crate) fn validate_into(
        &self,
        state: &mut ValidationState<'_>,
    ) -> Result<(), ModelValidationError> {
        for (field, value) in [
            (MetadataField::TestClass, &self.test_class),
            (MetadataField::GuiClass, &self.gui_class),
            (MetadataField::Name, &self.name),
        ] {
            if value.is_empty() {
                return Err(ModelValidationError::EmptyMetadata { field });
            }
            state.add_string_bytes(value.len())?;
        }
        Ok(())
    }
}

/// A JMeter test element in the semantic model.
///
/// Unknown classes and plugin extension payloads remain representable: the
/// model does not require a Rust component registry in order to hold an
/// element.  `enabled == false` is retained here even when a later execution
/// preparation pass chooses to remove the branch from an executable tree.
#[derive(Clone, PartialEq)]
pub struct TestElement {
    /// Exact test/gui/name metadata.
    pub metadata: ElementMetadata,
    /// Whether the element is enabled in the source plan.
    pub enabled: bool,
    /// Persistent, insertion-ordered properties.
    pub properties: Properties,
    /// Runtime-only properties that must not be serialized as persistent plan
    /// properties.
    pub temporary_properties: Properties,
    /// Source location retained for diagnostics.
    pub source_location: SourceLocation,
    /// Unknown/plugin extension payloads retained without interpretation.
    pub opaque_extensions: Vec<OpaqueExtension>,
    running_version: Option<RunningVersion>,
}

impl fmt::Debug for TestElement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TestElement")
            .field("metadata", &self.metadata)
            .field("enabled", &self.enabled)
            .field("properties_len", &self.properties.len())
            .field("temporary_properties_len", &self.temporary_properties.len())
            .field("source_location", &self.source_location)
            .field("opaque_extensions_len", &self.opaque_extensions.len())
            .field("running_version_present", &self.running_version.is_some())
            .finish()
    }
}

impl Default for TestElement {
    fn default() -> Self {
        Self::new(ElementMetadata::default())
    }
}

#[derive(Clone, PartialEq)]
struct RunningVersion {
    metadata: ElementMetadata,
    enabled: bool,
    properties: Properties,
    temporary_properties: Properties,
    source_location: SourceLocation,
    opaque_extensions: Vec<OpaqueExtension>,
}

impl TestElement {
    /// Creates an enabled element with the supplied exact metadata.
    #[must_use]
    pub fn new(metadata: ElementMetadata) -> Self {
        Self {
            metadata,
            enabled: true,
            properties: Properties::new(),
            temporary_properties: Properties::new(),
            source_location: SourceLocation::unknown(),
            opaque_extensions: Vec::new(),
            running_version: None,
        }
    }

    /// Creates an enabled element directly from exact class and name values.
    #[must_use]
    pub fn named(
        test_class: impl Into<String>,
        gui_class: impl Into<String>,
        name: impl Into<String>,
    ) -> Self {
        Self::new(ElementMetadata::new(test_class, gui_class, name))
    }

    /// Returns the exact test class value.
    #[must_use]
    pub fn test_class(&self) -> &str {
        self.metadata.testclass()
    }

    /// Returns the exact GUI class value.
    #[must_use]
    pub fn gui_class(&self) -> &str {
        self.metadata.guiclass()
    }

    /// Returns the exact element name.
    #[must_use]
    pub fn name(&self) -> &str {
        self.metadata.testname()
    }

    /// Returns whether this source element is enabled.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Sets the source enabled state.
    pub const fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Looks up a persistent property by exact name.
    #[must_use]
    pub fn property(&self, name: &str) -> Option<&PropertyValue> {
        self.properties.get(name)
    }

    /// Inserts or replaces a persistent property while retaining order.
    pub fn set_property(
        &mut self,
        name: impl Into<String>,
        value: PropertyValue,
    ) -> Option<PropertyValue> {
        self.properties.insert(name, value)
    }

    /// Removes a persistent property by exact name.
    pub fn remove_property(&mut self, name: &str) -> Option<PropertyValue> {
        self.properties.remove(name)
    }

    /// Looks up a temporary property by exact name.
    #[must_use]
    pub fn temporary_property(&self, name: &str) -> Option<&PropertyValue> {
        self.temporary_properties.get(name)
    }

    /// Inserts or replaces a temporary runtime property.
    pub fn set_temporary_property(
        &mut self,
        name: impl Into<String>,
        value: PropertyValue,
    ) -> Option<PropertyValue> {
        self.temporary_properties.insert(name, value)
    }

    /// Adds an opaque/plugin extension payload.
    pub fn push_opaque_extension(&mut self, extension: OpaqueExtension) {
        self.opaque_extensions.push(extension);
    }

    /// Returns the source location.
    #[must_use]
    pub fn source(&self) -> &SourceLocation {
        &self.source_location
    }

    /// Replaces the source location.
    pub fn set_source_location(&mut self, source_location: SourceLocation) {
        self.source_location = source_location;
    }

    /// Snapshots the source state for a later [`Self::recover_running_version`]
    /// call.
    pub fn set_running_version(&mut self) {
        self.running_version = Some(RunningVersion {
            metadata: self.metadata.clone(),
            enabled: self.enabled,
            properties: self.properties.clone(),
            temporary_properties: self.temporary_properties.clone(),
            source_location: self.source_location.clone(),
            opaque_extensions: self.opaque_extensions.clone(),
        });
    }

    /// Restores the state captured by [`Self::set_running_version`].
    ///
    /// Returns `true` when a snapshot existed and was restored, or `false` when
    /// no snapshot had been recorded.
    pub fn recover_running_version(&mut self) -> bool {
        let Some(snapshot) = self.running_version.clone() else {
            return false;
        };
        self.metadata = snapshot.metadata;
        self.enabled = snapshot.enabled;
        self.properties = snapshot.properties;
        self.temporary_properties = snapshot.temporary_properties;
        self.source_location = snapshot.source_location;
        self.opaque_extensions = snapshot.opaque_extensions;
        true
    }

    /// Compares persistent semantic element state while excluding temporary
    /// properties, source diagnostics, and the private running-version
    /// snapshot.
    #[must_use]
    pub fn semantic_eq(&self, other: &Self) -> bool {
        self.metadata == other.metadata
            && self.enabled == other.enabled
            && self.properties.semantic_eq(&other.properties)
            && self.opaque_extensions == other.opaque_extensions
    }

    /// Compares every in-memory field, including runtime and diagnostic state.
    /// This is the explicit form of the structural [`PartialEq`] contract.
    #[must_use]
    pub fn structural_eq(&self, other: &Self) -> bool {
        self == other
    }

    /// Validates this directly constructed element with caller-provided
    /// resource limits.
    pub fn validate_with_limits(
        &self,
        limits: &ValidationLimits,
    ) -> Result<(), ModelValidationError> {
        let mut state = ValidationState::new(limits);
        self.validate_into(&mut state)
    }

    pub(crate) fn validate_into(
        &self,
        state: &mut ValidationState<'_>,
    ) -> Result<(), ModelValidationError> {
        self.metadata.validate_into(state)?;
        self.source_location
            .validate()
            .map_err(|error| ModelValidationError::InvalidSourceLocation { error })?;
        if let Some(source) = self.source_location.source_name() {
            state.add_string_bytes(source.len())?;
        }
        self.properties.validate_into(state, 0)?;
        self.temporary_properties.validate_into(state, 0)?;
        for extension in &self.opaque_extensions {
            state.add_string_bytes(extension.type_name.len())?;
            state.add_opaque_bytes(extension.raw.len())?;
        }
        Ok(())
    }
}
