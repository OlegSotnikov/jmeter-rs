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
    /// The exact XML attribute carrying the test-element class.
    pub const TEST_CLASS_ATTRIBUTE: &'static str = "testclass";
    /// The exact XML attribute carrying the GUI class.
    pub const GUI_CLASS_ATTRIBUTE: &'static str = "guiclass";
    /// The exact XML attribute carrying the element name.
    pub const NAME_ATTRIBUTE: &'static str = "testname";

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

    /// Creates metadata and rejects a missing required wire attribute.
    ///
    /// [`Self::new`] remains available for callers that need to assemble a
    /// value before a profile-specific validation pass.  JMX input-facing
    /// code should prefer this constructor when an incomplete element cannot
    /// be represented meaningfully.
    pub fn try_new(
        test_class: impl Into<String>,
        gui_class: impl Into<String>,
        name: impl Into<String>,
    ) -> Result<Self, ModelValidationError> {
        let metadata = Self::new(test_class, gui_class, name);
        metadata.validate_nonempty()?;
        Ok(metadata)
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

    fn validate_nonempty(&self) -> Result<(), ModelValidationError> {
        for (field, value) in [
            (MetadataField::TestClass, &self.test_class),
            (MetadataField::GuiClass, &self.gui_class),
            (MetadataField::Name, &self.name),
        ] {
            if value.is_empty() {
                return Err(ModelValidationError::EmptyMetadata { field });
            }
        }
        Ok(())
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
        self.validate_nonempty()?;
        for value in [&self.test_class, &self.gui_class, &self.name] {
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

    /// Creates an element and rejects missing required wire metadata.
    pub fn try_new(metadata: ElementMetadata) -> Result<Self, ModelValidationError> {
        metadata.validate_nonempty()?;
        Ok(Self::new(metadata))
    }

    /// Creates an element from exact class, GUI class, and name values.
    pub fn try_named(
        test_class: impl Into<String>,
        gui_class: impl Into<String>,
        name: impl Into<String>,
    ) -> Result<Self, ModelValidationError> {
        Self::try_new(ElementMetadata::new(test_class, gui_class, name))
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

    /// Inserts or replaces a persistent property only when the resulting
    /// element stays within `limits`.
    ///
    /// The mutation is transactional: a failed validation restores the
    /// original value and insertion position.  This keeps a bounded caller
    /// from observing a partially accepted plan edit.
    pub fn try_set_property(
        &mut self,
        name: impl Into<String>,
        value: PropertyValue,
        limits: &ValidationLimits,
    ) -> Result<Option<PropertyValue>, ModelValidationError> {
        let name = name.into();
        let previous = self.set_property(name.clone(), value);
        if let Err(error) = self.validate_with_limits(limits) {
            match previous {
                Some(previous) => {
                    let _ = self.set_property(name, previous);
                }
                None => {
                    let _ = self.remove_property(&name);
                }
            }
            return Err(error);
        }
        Ok(previous)
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

    /// Inserts or replaces a temporary property only when the resulting
    /// element stays within `limits`.
    pub fn try_set_temporary_property(
        &mut self,
        name: impl Into<String>,
        value: PropertyValue,
        limits: &ValidationLimits,
    ) -> Result<Option<PropertyValue>, ModelValidationError> {
        let name = name.into();
        let previous = self.set_temporary_property(name.clone(), value);
        if let Err(error) = self.validate_with_limits(limits) {
            match previous {
                Some(previous) => {
                    let _ = self.set_temporary_property(name, previous);
                }
                None => {
                    let _ = self.temporary_properties.remove(&name);
                }
            }
            return Err(error);
        }
        Ok(previous)
    }

    /// Adds an opaque/plugin extension payload.
    pub fn push_opaque_extension(&mut self, extension: OpaqueExtension) {
        self.opaque_extensions.push(extension);
    }

    /// Appends an opaque/plugin payload only when the resulting element stays
    /// within `limits`.
    pub fn try_push_opaque_extension(
        &mut self,
        extension: OpaqueExtension,
        limits: &ValidationLimits,
    ) -> Result<(), ModelValidationError> {
        self.opaque_extensions.push(extension);
        if let Err(error) = self.validate_with_limits(limits) {
            let _ = self.opaque_extensions.pop();
            return Err(error);
        }
        Ok(())
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
        Self::validate_state_into(
            state,
            &self.metadata,
            &self.properties,
            &self.temporary_properties,
            &self.source_location,
            &self.opaque_extensions,
        )?;
        if let Some(snapshot) = &self.running_version {
            Self::validate_state_into(
                state,
                &snapshot.metadata,
                &snapshot.properties,
                &snapshot.temporary_properties,
                &snapshot.source_location,
                &snapshot.opaque_extensions,
            )?;
        }
        Ok(())
    }

    fn validate_state_into(
        state: &mut ValidationState<'_>,
        metadata: &ElementMetadata,
        properties: &Properties,
        temporary_properties: &Properties,
        source_location: &SourceLocation,
        opaque_extensions: &[OpaqueExtension],
    ) -> Result<(), ModelValidationError> {
        metadata.validate_into(state)?;
        source_location
            .validate()
            .map_err(|error| ModelValidationError::InvalidSourceLocation { error })?;
        if let Some(source) = source_location.source_name() {
            state.add_string_bytes(source.len())?;
        }
        properties.validate_into(state, 0)?;
        temporary_properties.validate_into(state, 0)?;
        for extension in opaque_extensions {
            state.add_string_bytes(extension.type_name.len())?;
            state.add_opaque_bytes(extension.raw.len())?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "deterministic element tests assert setup before inspecting values"
)]
mod tests {
    use super::*;
    use crate::{OpaqueValue, ValidationLimitKind};

    fn element() -> TestElement {
        TestElement::try_named("plugin.TestElement", "plugin.Gui", " exact ☃ name ")
            .expect("non-empty exact metadata")
    }

    #[test]
    fn exact_wire_metadata_and_enabled_state_are_preserved() {
        let mut item = element();
        assert_eq!(ElementMetadata::TEST_CLASS_ATTRIBUTE, "testclass");
        assert_eq!(ElementMetadata::GUI_CLASS_ATTRIBUTE, "guiclass");
        assert_eq!(ElementMetadata::NAME_ATTRIBUTE, "testname");
        assert_eq!(item.test_class(), "plugin.TestElement");
        assert_eq!(item.gui_class(), "plugin.Gui");
        assert_eq!(item.name(), " exact ☃ name ");
        assert!(item.is_enabled());
        item.set_enabled(false);
        assert!(!item.is_enabled());
        assert!(
            item.validate_with_limits(&ValidationLimits::default())
                .is_ok()
        );
    }

    #[test]
    fn fallible_constructors_report_each_missing_wire_attribute() {
        for (field, test_class, gui_class, name) in [
            (MetadataField::TestClass, "", "Gui", "name"),
            (MetadataField::GuiClass, "Test", "", "name"),
            (MetadataField::Name, "Test", "Gui", ""),
        ] {
            let error = ElementMetadata::try_new(test_class, gui_class, name)
                .expect_err("empty required metadata must be rejected");
            assert_eq!(error, ModelValidationError::EmptyMetadata { field });
            assert_eq!(error.code(), "model.validation.empty-metadata");
        }
        assert_eq!(
            TestElement::try_named("", "Gui", "name").expect_err("empty class"),
            ModelValidationError::EmptyMetadata {
                field: MetadataField::TestClass
            }
        );
    }

    #[test]
    fn ordered_properties_replace_in_place_and_keep_wire_states_distinct() {
        let mut item = element();
        for index in 0..32 {
            item.set_property(
                format!("plugin.property.{index}"),
                PropertyValue::Integer(index),
            );
        }
        item.set_property("plugin.property.7", PropertyValue::String(String::new()));
        item.set_property("plugin.null", PropertyValue::Null);
        assert_eq!(item.properties.position("plugin.property.7"), Some(7));
        let keys = item.properties.keys().collect::<Vec<_>>();
        assert!(
            keys.iter()
                .take(8)
                .enumerate()
                .all(|(index, key)| *key == format!("plugin.property.{index}"))
        );
        assert_eq!(
            item.property("plugin.property.7"),
            Some(&PropertyValue::String(String::new()))
        );
        assert_eq!(item.property("plugin.null"), Some(&PropertyValue::Null));
        assert!(item.property("plugin.absent").is_none());
    }

    #[test]
    fn unknown_payload_order_and_disabled_source_state_survive_clone_and_recovery() {
        let mut item = element();
        item.set_enabled(false);
        item.push_opaque_extension(OpaqueValue::new("plugin.first", vec![0, 1, 2]));
        item.push_opaque_extension(OpaqueValue::new("plugin.second", b"<raw>".to_vec()));
        item.set_running_version();
        item.set_enabled(true);
        item.opaque_extensions[0].raw[0] = 9;
        assert!(item.recover_running_version());
        assert!(!item.is_enabled());
        assert_eq!(item.opaque_extensions[0].raw, vec![0, 1, 2]);
        assert_eq!(item.opaque_extensions[1].raw, b"<raw>".to_vec());
        let mut clone = item.clone();
        clone.opaque_extensions[1].raw.push(b'!');
        assert_ne!(clone.opaque_extensions, item.opaque_extensions);
        assert!(!item.semantic_eq(&clone));
    }

    #[test]
    fn duplicate_element_values_keep_distinct_document_local_identities() {
        let mut tree = crate::ElementTree::new();
        let first = tree
            .insert_root(element())
            .expect("first source element identity");
        let second = tree
            .insert_root(element())
            .expect("second source element identity");
        assert_ne!(first, second);
        assert_eq!(
            tree.element(first).expect("first element"),
            tree.element(second).expect("second element")
        );
        assert_eq!(tree.root_ids(), &[first, second]);
    }

    #[test]
    fn bounded_mutations_are_transactional_and_return_typed_limits() {
        let mut item = element();
        let limits = ValidationLimits {
            max_properties: 0,
            ..ValidationLimits::default()
        };
        let error = item
            .try_set_property(
                "too-many",
                PropertyValue::String("value".to_owned()),
                &limits,
            )
            .expect_err("bounded property insertion must fail");
        assert_eq!(
            error,
            ModelValidationError::LimitExceeded {
                kind: ValidationLimitKind::Properties,
                limit: 0,
                actual: 1,
            }
        );
        assert!(item.property("too-many").is_none());

        let opaque_limits = ValidationLimits {
            max_opaque_bytes: 2,
            ..ValidationLimits::default()
        };
        let error = item
            .try_push_opaque_extension(OpaqueValue::new("plugin", vec![1, 2, 3]), &opaque_limits)
            .expect_err("bounded opaque insertion must fail");
        assert_eq!(error.code(), "model.validation.limit-opaque-bytes");
        assert!(item.opaque_extensions.is_empty());

        let mut replacement = element();
        replacement.set_property("stable", PropertyValue::String("before".to_owned()));
        replacement.set_property("later", PropertyValue::Null);
        let stable_position = replacement.properties.position("stable");
        let replacement_limits = ValidationLimits {
            max_string_bytes: replacement
                .metadata
                .test_class
                .len()
                .saturating_add(replacement.metadata.gui_class.len())
                .saturating_add(replacement.metadata.name.len())
                .saturating_add("stable".len())
                .saturating_add("later".len())
                .saturating_add("before".len()),
            ..ValidationLimits::default()
        };
        let error = replacement
            .try_set_property(
                "stable",
                PropertyValue::String("replacement-that-is-too-long".to_owned()),
                &replacement_limits,
            )
            .expect_err("replacement over the string bound must fail");
        assert_eq!(error.code(), "model.validation.limit-string-bytes");
        assert_eq!(replacement.properties.position("stable"), stable_position);
        assert_eq!(
            replacement.property("stable"),
            Some(&PropertyValue::String("before".to_owned()))
        );

        let temporary_limits = ValidationLimits {
            max_properties: 0,
            ..ValidationLimits::default()
        };
        let error = replacement
            .try_set_temporary_property("runtime", PropertyValue::Null, &temporary_limits)
            .expect_err("temporary properties are bounded too");
        assert_eq!(error.code(), "model.validation.limit-properties");
        assert!(replacement.temporary_property("runtime").is_none());
    }

    #[test]
    fn retained_running_version_is_included_in_bounds() {
        let mut item = element();
        item.set_running_version();
        let limits = ValidationLimits {
            max_string_bytes: item.metadata.test_class.len()
                + item.metadata.gui_class.len()
                + item.metadata.name.len(),
            ..ValidationLimits::default()
        };
        let error = item
            .validate_with_limits(&limits)
            .expect_err("retained snapshot must consume bounded string budget");
        assert_eq!(error.code(), "model.validation.limit-string-bytes");
    }
}
