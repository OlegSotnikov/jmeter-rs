// SPDX-License-Identifier: Apache-2.0
//! Insertion-ordered, typed JMeter property values.

use core::fmt;
use std::collections::BTreeSet;

use crate::limits::ValidationState;
use crate::{
    ModelValidationError, OpaqueValue, PropertyError, PropertyTypeError, ValidationLimits,
};

/// The value kinds used by JMeter's structural property converters.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PropertyKind {
    /// An explicit null value.
    Null,
    /// A UTF-8 string, including an intentionally empty string.
    String,
    /// A boolean value.
    Boolean,
    /// A 32-bit integer value.
    Integer,
    /// A 64-bit integer value.
    Long,
    /// A 32-bit floating-point value.
    Float,
    /// A 64-bit floating-point value.
    Double,
    /// An unnamed ordered collection.
    Collection,
    /// A named ordered collection.
    NamedCollection,
    /// An ordered map represented by named entries.
    Map,
    /// A serialized object value.
    Object,
    /// A nested element property.
    Element,
    /// An unknown or profile-specific value retained without interpretation.
    Opaque,
}

impl fmt::Display for PropertyKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Null => "null",
            Self::String => "string",
            Self::Boolean => "boolean",
            Self::Integer => "integer",
            Self::Long => "long",
            Self::Float => "float",
            Self::Double => "double",
            Self::Collection => "collection",
            Self::NamedCollection => "named-collection",
            Self::Map => "map",
            Self::Object => "object",
            Self::Element => "element",
            Self::Opaque => "opaque",
        };
        formatter.write_str(name)
    }
}

/// A named property entry.
///
/// The name is kept exactly as supplied by upstream, including case and
/// whitespace.  `Properties` replaces an existing entry in place when using
/// [`Properties::insert`], so changing a value never changes property order.
#[derive(Clone, PartialEq)]
pub struct PropertyEntry {
    /// Exact upstream property name.
    pub name: String,
    /// Typed property value.
    pub value: PropertyValue,
}

impl fmt::Debug for PropertyEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PropertyEntry")
            .field("name", &"<redacted>")
            .field("name_len", &self.name.len())
            .field("value_kind", &self.value.kind())
            .finish()
    }
}

impl PropertyEntry {
    /// Creates a named property entry.
    #[must_use]
    pub fn new(name: impl Into<String>, value: PropertyValue) -> Self {
        Self {
            name: name.into(),
            value,
        }
    }
}

/// Alias for map entries in nested property values.
pub type MapEntry = PropertyEntry;

/// The encoding of the bytes retained by an [`ObjectProperty`].
///
/// The model deliberately does not parse or validate an opaque payload.  The
/// distinction is nevertheless important at a serialization boundary:
/// textual object data may be emitted as text, while an opaque nested XML
/// subtree must be emitted as the original bytes and metadata.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ObjectPayloadKind {
    /// The bytes are a textual object representation.
    Text,
    /// The bytes are an opaque nested XML payload.
    OpaqueXml,
}

/// An attribute retained from an opaque nested object payload.
///
/// Attribute order and spelling are intentionally preserved.  Keeping this
/// as a model type avoids coupling the runtime-independent model to an XML
/// parser or to the JMX crate.  Debug output reports lengths and redacts the
/// value; the public fields remain available to a trusted serializer.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ObjectPropertyAttribute {
    /// Exact upstream attribute name.
    pub name: String,
    /// Exact upstream attribute value.
    pub value: String,
}

impl fmt::Debug for ObjectPropertyAttribute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObjectPropertyAttribute")
            .field("name", &"<redacted>")
            .field("name_len", &self.name.len())
            .field("value_len", &self.value.len())
            .field("value", &"<redacted>")
            .finish()
    }
}

impl ObjectPropertyAttribute {
    /// Creates a retained object-payload attribute.
    #[must_use]
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

/// A serialized object property retained at the model boundary.
///
/// Debug output reports payload and metadata lengths without printing the
/// serialized bytes.  The public [`ObjectProperty::raw`] field remains the
/// explicit lossless access path for a trusted boundary serializer.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ObjectProperty {
    /// Upstream class/type name, when known.
    ///
    /// `None` means the source object had no `class` attribute.  `Some("")`
    /// means that the attribute was present with an explicitly empty value;
    /// those two wire states must remain distinct for a lossless JMX
    /// round-trip.
    pub class_name: Option<String>,
    /// Serialized object bytes.  The model does not deserialize them.
    pub raw: Vec<u8>,
    /// How the retained bytes should be interpreted by a boundary serializer.
    pub payload_kind: ObjectPayloadKind,
    /// Ordered source metadata for opaque nested object payloads.
    pub attributes: Vec<ObjectPropertyAttribute>,
}

impl fmt::Debug for ObjectProperty {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObjectProperty")
            .field("class_name_present", &self.class_name.is_some())
            .field(
                "class_name",
                &self.class_name.as_ref().map(|_| "<redacted>"),
            )
            .field("class_name_len", &self.class_name.as_ref().map(String::len))
            .field("raw_len", &self.raw.len())
            .field("raw", &"<redacted>")
            .field("payload_kind", &self.payload_kind)
            .field("attributes_len", &self.attributes.len())
            .finish()
    }
}

impl ObjectProperty {
    /// Creates a serialized object property with the default text payload
    /// marker.  Use [`ObjectProperty::opaque_xml`] when the bytes represent a
    /// nested XML subtree and source metadata must be retained.
    #[must_use]
    pub fn new(class_name: impl Into<String>, raw: impl Into<Vec<u8>>) -> Self {
        Self {
            class_name: Some(class_name.into()),
            raw: raw.into(),
            payload_kind: ObjectPayloadKind::Text,
            attributes: Vec::new(),
        }
    }

    /// Creates an object property while retaining whether its class
    /// attribute was absent or explicitly empty.
    #[must_use]
    pub fn from_optional_class_name(class_name: Option<String>, raw: impl Into<Vec<u8>>) -> Self {
        Self {
            class_name,
            raw: raw.into(),
            payload_kind: ObjectPayloadKind::Text,
            attributes: Vec::new(),
        }
    }

    /// Creates an object property with no source `class` attribute.
    #[must_use]
    pub fn without_class_name(raw: impl Into<Vec<u8>>) -> Self {
        Self::from_optional_class_name(None, raw)
    }

    /// Returns the optional source `class` attribute.
    #[must_use]
    pub fn class_name(&self) -> Option<&str> {
        self.class_name.as_deref()
    }

    /// Replaces the optional source `class` attribute.
    #[must_use]
    pub fn with_optional_class_name(mut self, class_name: Option<String>) -> Self {
        self.class_name = class_name;
        self
    }

    /// Sets the source `class` attribute to a present value.
    #[must_use]
    pub fn with_class_name(mut self, class_name: impl Into<String>) -> Self {
        self.class_name = Some(class_name.into());
        self
    }

    /// Removes the source `class` attribute while retaining the payload.
    #[must_use]
    pub fn without_class_attribute(mut self) -> Self {
        self.class_name = None;
        self
    }

    /// Returns the retained serialized bytes for an explicitly trusted
    /// boundary.  Ordinary diagnostics use metadata-only [`Debug`](fmt::Debug)
    /// output instead.
    #[must_use]
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// Alias for [`Self::raw_bytes`].
    #[must_use]
    pub fn raw(&self) -> &[u8] {
        self.raw_bytes()
    }

    /// Returns the retained serialized bytes by value for an explicitly
    /// trusted boundary.
    #[must_use]
    pub fn into_raw(self) -> Vec<u8> {
        self.raw
    }

    /// Creates an object property from textual bytes.
    #[must_use]
    pub fn text(class_name: impl Into<String>, text: impl Into<String>) -> Self {
        Self::new(class_name, text.into().into_bytes())
    }

    /// Creates a textual object property while retaining an optional source
    /// `class` attribute.
    #[must_use]
    pub fn text_with_optional_class_name(
        class_name: Option<String>,
        text: impl Into<String>,
    ) -> Self {
        Self::from_optional_class_name(class_name, text.into().into_bytes())
    }

    /// Creates an object property whose bytes and source metadata must be
    /// retained as an opaque nested XML payload.
    #[must_use]
    pub fn opaque_xml(
        class_name: impl Into<String>,
        raw: impl Into<Vec<u8>>,
        attributes: impl Into<Vec<ObjectPropertyAttribute>>,
    ) -> Self {
        Self {
            class_name: Some(class_name.into()),
            raw: raw.into(),
            payload_kind: ObjectPayloadKind::OpaqueXml,
            attributes: attributes.into(),
        }
    }

    /// Creates an opaque XML object property while retaining an optional
    /// source `class` attribute.
    #[must_use]
    pub fn opaque_xml_with_optional_class_name(
        class_name: Option<String>,
        raw: impl Into<Vec<u8>>,
        attributes: impl Into<Vec<ObjectPropertyAttribute>>,
    ) -> Self {
        Self {
            class_name,
            raw: raw.into(),
            payload_kind: ObjectPayloadKind::OpaqueXml,
            attributes: attributes.into(),
        }
    }

    /// Sets the payload encoding marker while retaining the object bytes.
    #[must_use]
    pub fn with_payload_kind(mut self, payload_kind: ObjectPayloadKind) -> Self {
        self.payload_kind = payload_kind;
        self
    }

    /// Sets the ordered source metadata retained with the object payload.
    #[must_use]
    pub fn with_attributes(mut self, attributes: impl Into<Vec<ObjectPropertyAttribute>>) -> Self {
        self.attributes = attributes.into();
        self
    }

    /// Returns whether this object contains an opaque nested XML payload.
    #[must_use]
    pub const fn is_opaque_xml(&self) -> bool {
        matches!(self.payload_kind, ObjectPayloadKind::OpaqueXml)
    }
}

/// A nested JMeter `elementProp` value.
#[derive(Clone, PartialEq)]
pub struct ElementProperty {
    /// Exact nested property name.
    pub name: String,
    /// Optional upstream class name.  `None` preserves an absent attribute,
    /// while `Some(String::new())` preserves an explicitly empty one.
    pub class_name: Option<String>,
    /// Ordered nested properties.
    pub properties: Properties,
    /// Unknown nested extension values retained without interpretation.
    pub opaque_extensions: Vec<OpaqueValue>,
}

impl fmt::Debug for ElementProperty {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ElementProperty")
            .field("name", &"<redacted>")
            .field("name_len", &self.name.len())
            .field("class_name_present", &self.class_name.is_some())
            .field(
                "class_name",
                &self.class_name.as_ref().map(|_| "<redacted>"),
            )
            .field("class_name_len", &self.class_name.as_ref().map(String::len))
            .field("properties_len", &self.properties.len())
            .field("opaque_extensions_len", &self.opaque_extensions.len())
            .finish()
    }
}

impl ElementProperty {
    /// Creates a nested element property with no class attribute.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            class_name: None,
            properties: Properties::new(),
            opaque_extensions: Vec::new(),
        }
    }

    /// Sets the nested upstream class name, retaining an explicit empty value.
    #[must_use]
    pub fn with_class_name(mut self, class_name: impl Into<String>) -> Self {
        self.class_name = Some(class_name.into());
        self
    }

    /// Adds an opaque nested extension.
    pub fn push_opaque(&mut self, value: OpaqueValue) {
        self.opaque_extensions.push(value);
    }

    /// Compares persistent nested-element state while ignoring no runtime
    /// fields (nested properties have none).
    #[must_use]
    pub fn semantic_eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.class_name == other.class_name
            && self.properties.semantic_eq(&other.properties)
            && self.opaque_extensions == other.opaque_extensions
    }
}

/// A typed JMeter property value.
///
/// `String(String::new())` is intentionally distinct from [`PropertyValue::Null`]
/// and from an absent entry in [`Properties`].  Unknown values use
/// [`PropertyValue::Opaque`] and retain their type name and raw payload.
#[derive(Clone, PartialEq)]
pub enum PropertyValue {
    /// An explicit null value.
    Null,
    /// A UTF-8 string, including an empty string.
    String(String),
    /// A boolean value.
    Boolean(bool),
    /// A 32-bit integer value.
    Integer(i32),
    /// A 64-bit integer value.
    Long(i64),
    /// A 32-bit floating-point value.
    Float(f32),
    /// A 64-bit floating-point value.
    Double(f64),
    /// An ordered collection without names on its entries.
    Collection(Vec<PropertyValue>),
    /// An ordered collection whose entries retain exact names.
    NamedCollection(Vec<PropertyEntry>),
    /// An ordered map whose entries retain exact names.
    Map(Vec<MapEntry>),
    /// A serialized object property.
    Object(ObjectProperty),
    /// A nested element property.
    Element(ElementProperty),
    /// An unknown/plugin property retained without interpretation.
    Opaque(OpaqueValue),
}

impl fmt::Debug for PropertyValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("PropertyValue");
        debug.field("kind", &self.kind());
        match self {
            Self::Null => {}
            Self::String(value) => {
                debug.field("value", &"<redacted>");
                debug.field("string_len", &value.len());
            }
            Self::Boolean(_)
            | Self::Integer(_)
            | Self::Long(_)
            | Self::Float(_)
            | Self::Double(_) => {
                // Scalar values can still carry user data (for example a
                // token represented as an integer).  Keep diagnostics to the
                // value kind rather than exposing the scalar itself.
                debug.field("scalar", &"<redacted>");
            }
            Self::Collection(values) => {
                debug.field("entries_len", &values.len());
            }
            Self::NamedCollection(entries) | Self::Map(entries) => {
                debug.field("entries_len", &entries.len());
            }
            Self::Object(value) => {
                debug.field("class_name_present", &value.class_name.is_some());
                debug.field(
                    "class_name",
                    &value.class_name.as_ref().map(|_| "<redacted>"),
                );
                debug.field("raw_len", &value.raw.len());
                debug.field("raw", &"<redacted>");
                debug.field("attributes_len", &value.attributes.len());
            }
            Self::Element(value) => {
                debug.field("name", &"<redacted>");
                debug.field("name_len", &value.name.len());
                debug.field("class_name_present", &value.class_name.is_some());
                debug.field(
                    "class_name",
                    &value.class_name.as_ref().map(|_| "<redacted>"),
                );
                debug.field("properties_len", &value.properties.len());
                debug.field("opaque_extensions_len", &value.opaque_extensions.len());
            }
            Self::Opaque(value) => {
                debug.field("type_name", &"<redacted>");
                debug.field("raw_len", &value.raw.len());
                debug.field("raw", &"<redacted>");
            }
        }
        debug.finish()
    }
}

impl PropertyValue {
    /// Creates a string value.
    #[must_use]
    pub fn string(value: impl Into<String>) -> Self {
        Self::String(value.into())
    }

    /// Creates a boolean value.
    #[must_use]
    pub const fn boolean(value: bool) -> Self {
        Self::Boolean(value)
    }

    /// Creates a 32-bit integer value.
    #[must_use]
    pub const fn integer(value: i32) -> Self {
        Self::Integer(value)
    }

    /// Creates a 64-bit integer value.
    #[must_use]
    pub const fn long(value: i64) -> Self {
        Self::Long(value)
    }

    /// Creates a 32-bit floating-point value.
    #[must_use]
    pub const fn float(value: f32) -> Self {
        Self::Float(value)
    }

    /// Creates a 64-bit floating-point value.
    #[must_use]
    pub const fn double(value: f64) -> Self {
        Self::Double(value)
    }

    /// Creates an unnamed ordered collection.
    ///
    /// Collection entries have no names.  A serializer must not manufacture
    /// names for them; use [`PropertyValue::named_collection`] when entry
    /// names are part of the source contract.
    #[must_use]
    pub fn collection(values: Vec<PropertyValue>) -> Self {
        Self::Collection(values)
    }

    /// Creates a named ordered collection.
    ///
    /// Names and order are retained exactly, including duplicate names.  This
    /// is intentionally distinct from [`PropertyValue::collection`].
    #[must_use]
    pub fn named_collection(entries: Vec<PropertyEntry>) -> Self {
        Self::NamedCollection(entries)
    }

    /// Creates an ordered map with named entries.
    #[must_use]
    pub fn map(entries: Vec<MapEntry>) -> Self {
        Self::Map(entries)
    }

    /// Creates an explicit null value.
    #[must_use]
    pub const fn null() -> Self {
        Self::Null
    }

    /// Returns the typed kind of this value.
    #[must_use]
    pub const fn kind(&self) -> PropertyKind {
        match self {
            Self::Null => PropertyKind::Null,
            Self::String(_) => PropertyKind::String,
            Self::Boolean(_) => PropertyKind::Boolean,
            Self::Integer(_) => PropertyKind::Integer,
            Self::Long(_) => PropertyKind::Long,
            Self::Float(_) => PropertyKind::Float,
            Self::Double(_) => PropertyKind::Double,
            Self::Collection(_) => PropertyKind::Collection,
            Self::NamedCollection(_) => PropertyKind::NamedCollection,
            Self::Map(_) => PropertyKind::Map,
            Self::Object(_) => PropertyKind::Object,
            Self::Element(_) => PropertyKind::Element,
            Self::Opaque(_) => PropertyKind::Opaque,
        }
    }

    /// Creates an opaque unknown value.
    #[must_use]
    pub fn opaque(type_name: impl Into<String>, raw: impl Into<Vec<u8>>) -> Self {
        Self::Opaque(OpaqueValue::new(type_name, raw))
    }

    /// Creates an opaque unknown value from textual bytes.
    #[must_use]
    pub fn opaque_text(type_name: impl Into<String>, text: impl Into<String>) -> Self {
        Self::Opaque(OpaqueValue::text(type_name, text))
    }

    /// Returns a string value or a typed mismatch error.
    pub fn as_string(&self) -> Result<&str, PropertyTypeError> {
        match self {
            Self::String(value) => Ok(value),
            _ => Err(self.type_error(PropertyKind::String)),
        }
    }

    /// Alias for the string accessor.
    pub fn as_str(&self) -> Result<&str, PropertyTypeError> {
        self.as_string()
    }

    /// Returns a boolean value or a typed mismatch error.
    pub fn as_boolean(&self) -> Result<bool, PropertyTypeError> {
        match self {
            Self::Boolean(value) => Ok(*value),
            _ => Err(self.type_error(PropertyKind::Boolean)),
        }
    }

    /// Alias for the boolean accessor.
    pub fn as_bool(&self) -> Result<bool, PropertyTypeError> {
        self.as_boolean()
    }

    /// Returns a 32-bit integer or a typed mismatch error.
    pub fn as_integer(&self) -> Result<i32, PropertyTypeError> {
        match self {
            Self::Integer(value) => Ok(*value),
            _ => Err(self.type_error(PropertyKind::Integer)),
        }
    }

    /// Alias for the 32-bit integer accessor.
    pub fn as_i32(&self) -> Result<i32, PropertyTypeError> {
        self.as_integer()
    }

    /// Returns a 64-bit integer or a typed mismatch error.
    pub fn as_long(&self) -> Result<i64, PropertyTypeError> {
        match self {
            Self::Long(value) => Ok(*value),
            _ => Err(self.type_error(PropertyKind::Long)),
        }
    }

    /// Alias for the 64-bit integer accessor.
    pub fn as_i64(&self) -> Result<i64, PropertyTypeError> {
        self.as_long()
    }

    /// Returns a 32-bit floating-point value or a typed mismatch error.
    pub fn as_float(&self) -> Result<f32, PropertyTypeError> {
        match self {
            Self::Float(value) => Ok(*value),
            _ => Err(self.type_error(PropertyKind::Float)),
        }
    }

    /// Alias for the 32-bit floating-point accessor.
    pub fn as_f32(&self) -> Result<f32, PropertyTypeError> {
        self.as_float()
    }

    /// Returns a 64-bit floating-point value or a typed mismatch error.
    pub fn as_double(&self) -> Result<f64, PropertyTypeError> {
        match self {
            Self::Double(value) => Ok(*value),
            _ => Err(self.type_error(PropertyKind::Double)),
        }
    }

    /// Alias for the floating-point accessor.
    pub fn as_f64(&self) -> Result<f64, PropertyTypeError> {
        self.as_double()
    }

    /// Returns success for an explicit null or a typed mismatch error.
    pub fn as_null(&self) -> Result<(), PropertyTypeError> {
        match self {
            Self::Null => Ok(()),
            _ => Err(self.type_error(PropertyKind::Null)),
        }
    }

    /// Returns unnamed collection entries or a typed mismatch error.
    pub fn as_collection(&self) -> Result<&[PropertyValue], PropertyTypeError> {
        match self {
            Self::Collection(values) => Ok(values),
            _ => Err(self.type_error(PropertyKind::Collection)),
        }
    }

    /// Returns named collection entries or a typed mismatch error.
    pub fn as_named_collection(&self) -> Result<&[PropertyEntry], PropertyTypeError> {
        match self {
            Self::NamedCollection(entries) => Ok(entries),
            _ => Err(self.type_error(PropertyKind::NamedCollection)),
        }
    }

    /// Returns map entries or a typed mismatch error.
    pub fn as_map(&self) -> Result<&[MapEntry], PropertyTypeError> {
        match self {
            Self::Map(entries) => Ok(entries),
            _ => Err(self.type_error(PropertyKind::Map)),
        }
    }

    /// Returns a serialized object property or a typed mismatch error.
    pub fn as_object(&self) -> Result<&ObjectProperty, PropertyTypeError> {
        match self {
            Self::Object(value) => Ok(value),
            _ => Err(self.type_error(PropertyKind::Object)),
        }
    }

    /// Returns a nested element property or a typed mismatch error.
    pub fn as_element(&self) -> Result<&ElementProperty, PropertyTypeError> {
        match self {
            Self::Element(value) => Ok(value),
            _ => Err(self.type_error(PropertyKind::Element)),
        }
    }

    /// Returns an opaque value or a typed mismatch error.
    pub fn as_opaque(&self) -> Result<&OpaqueValue, PropertyTypeError> {
        match self {
            Self::Opaque(value) => Ok(value),
            _ => Err(self.type_error(PropertyKind::Opaque)),
        }
    }

    fn type_error(&self, expected: PropertyKind) -> PropertyTypeError {
        PropertyTypeError {
            expected,
            actual: self.kind(),
        }
    }

    /// Compares property meaning while treating all NaN payloads as the same
    /// semantic value and preserving signed-zero distinctions.
    #[must_use]
    pub fn semantic_eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Null, Self::Null)
            | (Self::Boolean(_), Self::Boolean(_))
            | (Self::Integer(_), Self::Integer(_))
            | (Self::Long(_), Self::Long(_))
            | (Self::String(_), Self::String(_))
            | (Self::Opaque(_), Self::Opaque(_)) => self == other,
            (Self::Float(left), Self::Float(right)) => {
                (left.is_nan() && right.is_nan()) || left.to_bits() == right.to_bits()
            }
            (Self::Double(left), Self::Double(right)) => {
                (left.is_nan() && right.is_nan()) || left.to_bits() == right.to_bits()
            }
            (Self::Collection(left), Self::Collection(right)) => {
                left.len() == right.len()
                    && left
                        .iter()
                        .zip(right)
                        .all(|(left, right)| left.semantic_eq(right))
            }
            (Self::NamedCollection(left), Self::NamedCollection(right))
            | (Self::Map(left), Self::Map(right)) => {
                left.len() == right.len()
                    && left.iter().zip(right).all(|(left, right)| {
                        left.name == right.name && left.value.semantic_eq(&right.value)
                    })
            }
            (Self::Object(left), Self::Object(right)) => left == right,
            (Self::Element(left), Self::Element(right)) => left.semantic_eq(right),
            _ => false,
        }
    }
}

/// Explicit validation work item.  Keeping nested values as references in a
/// heap-backed stack avoids using the Rust call stack for attacker-controlled
/// property depth.
enum ValidationTask<'a> {
    Value {
        value: &'a PropertyValue,
        depth: usize,
    },
    Properties {
        properties: &'a Properties,
        depth: usize,
        index: usize,
        names: BTreeSet<&'a str>,
    },
    Values {
        values: &'a [PropertyValue],
        depth: usize,
        index: usize,
    },
    Entries {
        entries: &'a [PropertyEntry],
        depth: usize,
        index: usize,
    },
    ElementExtensions {
        extensions: &'a [OpaqueValue],
        index: usize,
    },
}

fn validate_properties_iterative(
    properties: &Properties,
    state: &mut ValidationState<'_>,
    depth: usize,
) -> Result<(), ModelValidationError> {
    let mut tasks = vec![ValidationTask::Properties {
        properties,
        depth,
        index: 0,
        names: BTreeSet::new(),
    }];
    validate_property_tasks(&mut tasks, state)
}

fn validate_property_tasks(
    tasks: &mut Vec<ValidationTask<'_>>,
    state: &mut ValidationState<'_>,
) -> Result<(), ModelValidationError> {
    while let Some(task) = tasks.pop() {
        match task {
            ValidationTask::Value { value, depth } => {
                if depth > state.limits().max_property_depth {
                    return Err(ModelValidationError::LimitExceeded {
                        kind: crate::ValidationLimitKind::PropertyDepth,
                        limit: state.limits().max_property_depth,
                        actual: depth,
                    });
                }
                match value {
                    PropertyValue::Null
                    | PropertyValue::Boolean(_)
                    | PropertyValue::Integer(_)
                    | PropertyValue::Long(_)
                    | PropertyValue::Float(_)
                    | PropertyValue::Double(_) => {}
                    PropertyValue::String(value) => state.add_string_bytes(value.len())?,
                    PropertyValue::Collection(values) => {
                        if !values.is_empty() {
                            tasks.push(ValidationTask::Values {
                                values,
                                depth: depth.saturating_add(1),
                                index: 0,
                            });
                        }
                    }
                    PropertyValue::NamedCollection(entries) | PropertyValue::Map(entries) => {
                        if !entries.is_empty() {
                            tasks.push(ValidationTask::Entries {
                                entries,
                                depth: depth.saturating_add(1),
                                index: 0,
                            });
                        }
                    }
                    PropertyValue::Object(object) => {
                        if let Some(class_name) = &object.class_name {
                            state.add_string_bytes(class_name.len())?;
                        }
                        state.add_opaque_bytes(object.raw.len())?;
                        for attribute in &object.attributes {
                            state.add_string_bytes(attribute.name.len())?;
                            state.add_string_bytes(attribute.value.len())?;
                        }
                    }
                    PropertyValue::Element(element) => {
                        state.add_string_bytes(element.name.len())?;
                        if let Some(class_name) = &element.class_name {
                            state.add_string_bytes(class_name.len())?;
                        }
                        // Extensions follow nested properties on the source
                        // wire.  Push them first so the property task runs
                        // before the extension task (LIFO stack order).
                        if !element.opaque_extensions.is_empty() {
                            tasks.push(ValidationTask::ElementExtensions {
                                extensions: &element.opaque_extensions,
                                index: 0,
                            });
                        }
                        tasks.push(ValidationTask::Properties {
                            properties: &element.properties,
                            depth: depth.saturating_add(1),
                            index: 0,
                            names: BTreeSet::new(),
                        });
                    }
                    PropertyValue::Opaque(value) => {
                        state.add_string_bytes(value.type_name.len())?;
                        state.add_opaque_bytes(value.raw.len())?;
                    }
                }
            }
            ValidationTask::Properties {
                properties,
                depth,
                mut index,
                mut names,
            } => {
                if index < properties.entries.len() {
                    let entry = &properties.entries[index];
                    if !names.insert(entry.name.as_str()) {
                        return Err(ModelValidationError::DuplicatePropertyName {
                            name: entry.name.clone(),
                        });
                    }
                    index = index.saturating_add(1);
                    state.add_property()?;
                    state.add_string_bytes(entry.name.len())?;
                    tasks.push(ValidationTask::Properties {
                        properties,
                        depth,
                        index,
                        names,
                    });
                    tasks.push(ValidationTask::Value {
                        value: &entry.value,
                        depth,
                    });
                }
            }
            ValidationTask::Values {
                values,
                depth,
                index,
            } => {
                if index < values.len() {
                    let value = &values[index];
                    state.add_property()?;
                    tasks.push(ValidationTask::Values {
                        values,
                        depth,
                        index: index.saturating_add(1),
                    });
                    tasks.push(ValidationTask::Value { value, depth });
                }
            }
            ValidationTask::Entries {
                entries,
                depth,
                index,
            } => {
                if index < entries.len() {
                    let entry = &entries[index];
                    state.add_property()?;
                    state.add_string_bytes(entry.name.len())?;
                    tasks.push(ValidationTask::Entries {
                        entries,
                        depth,
                        index: index.saturating_add(1),
                    });
                    tasks.push(ValidationTask::Value {
                        value: &entry.value,
                        depth,
                    });
                }
            }
            ValidationTask::ElementExtensions { extensions, index } => {
                if index < extensions.len() {
                    let extension = &extensions[index];
                    state.add_string_bytes(extension.type_name.len())?;
                    state.add_opaque_bytes(extension.raw.len())?;
                    tasks.push(ValidationTask::ElementExtensions {
                        extensions,
                        index: index.saturating_add(1),
                    });
                }
            }
        }
    }
    Ok(())
}

/// An insertion-ordered property collection.
///
/// This is intentionally backed by a `Vec`, not a hash map.  JMeter converters
/// and plugins can observe property order, and exact property names are part of
/// the wire contract.  [`Properties::insert`] replaces a matching name in
/// place; [`Properties::try_insert`] is available when duplicate input should
/// be rejected explicitly.
#[derive(Clone, Default, PartialEq)]
pub struct Properties {
    entries: Vec<PropertyEntry>,
}

impl fmt::Debug for Properties {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Properties")
            .field("entries", &"<redacted>")
            .field("entries_len", &self.entries.len())
            .finish()
    }
}

impl Properties {
    /// Creates an empty ordered property collection.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Creates properties from entries, rejecting duplicate names.
    pub fn from_entries<I>(entries: I) -> Result<Self, PropertyError>
    where
        I: IntoIterator<Item = PropertyEntry>,
    {
        let mut properties = Self::new();
        for entry in entries {
            properties.try_insert_entry(entry)?;
        }
        Ok(properties)
    }

    /// Returns the number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether there are no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the entries in insertion order.
    #[must_use]
    pub fn as_slice(&self) -> &[PropertyEntry] {
        &self.entries
    }

    /// Returns the entries in insertion order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &PropertyEntry> {
        self.entries.iter()
    }

    /// Edits entries transactionally while preserving the unique-name
    /// invariant.
    ///
    /// The closure receives a private candidate slice.  If it introduces a
    /// duplicate name, the original collection is left untouched and the
    /// duplicate error is returned.  Names are intentionally not exposed by a
    /// mutable iterator; callers that only need to change values can use
    /// [`Self::values_mut`].
    pub fn edit<F>(&mut self, edit: F) -> Result<(), PropertyError>
    where
        F: FnOnce(&mut [PropertyEntry]),
    {
        let mut candidate = self.entries.clone();
        edit(&mut candidate);
        let mut names = BTreeSet::new();
        for entry in &candidate {
            if !names.insert(entry.name.as_str()) {
                return Err(PropertyError::DuplicateName {
                    name: entry.name.clone(),
                });
            }
        }
        self.entries = candidate;
        Ok(())
    }

    /// Returns mutable access to values without permitting property names to
    /// become duplicated.
    pub fn values_mut(&mut self) -> impl ExactSizeIterator<Item = &mut PropertyValue> {
        self.entries.iter_mut().map(|entry| &mut entry.value)
    }

    /// Returns property names in insertion order.
    pub fn keys(&self) -> impl ExactSizeIterator<Item = &str> {
        self.entries.iter().map(|entry| entry.name.as_str())
    }

    /// Returns values in insertion order.
    pub fn values(&self) -> impl ExactSizeIterator<Item = &PropertyValue> {
        self.entries.iter().map(|entry| &entry.value)
    }

    /// Looks up a property by its exact name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&PropertyValue> {
        self.get_entry(name).map(|entry| &entry.value)
    }

    /// Looks up a property entry by its exact name.
    #[must_use]
    pub fn get_entry(&self, name: &str) -> Option<&PropertyEntry> {
        self.entries.iter().find(|entry| entry.name == name)
    }

    /// Looks up a mutable property value by its exact name.
    pub fn get_mut(&mut self, name: &str) -> Option<&mut PropertyValue> {
        self.entries
            .iter_mut()
            .find(|entry| entry.name == name)
            .map(|entry| &mut entry.value)
    }

    /// Returns the insertion position of a property name.
    #[must_use]
    pub fn position(&self, name: &str) -> Option<usize> {
        self.entries.iter().position(|entry| entry.name == name)
    }

    /// Returns whether a property with this exact name is present.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.position(name).is_some()
    }

    /// Inserts or replaces a value while retaining the original position.
    ///
    /// The previous value is returned when a name was already present.
    pub fn insert(
        &mut self,
        name: impl Into<String>,
        value: PropertyValue,
    ) -> Option<PropertyValue> {
        let name = name.into();
        if let Some(entry) = self.entries.iter_mut().find(|entry| entry.name == name) {
            return Some(std::mem::replace(&mut entry.value, value));
        }
        self.entries.push(PropertyEntry::new(name, value));
        None
    }

    /// Alias for [`Properties::insert`].
    pub fn set(&mut self, name: impl Into<String>, value: PropertyValue) -> Option<PropertyValue> {
        self.insert(name, value)
    }

    /// Inserts an entry and rejects a duplicate exact name.
    pub fn try_insert(
        &mut self,
        name: impl Into<String>,
        value: PropertyValue,
    ) -> Result<(), PropertyError> {
        self.try_insert_entry(PropertyEntry::new(name, value))
    }

    /// Inserts an entry and rejects a duplicate exact name.
    pub fn try_insert_entry(&mut self, entry: PropertyEntry) -> Result<(), PropertyError> {
        if self.contains(&entry.name) {
            return Err(PropertyError::DuplicateName { name: entry.name });
        }
        self.entries.push(entry);
        Ok(())
    }

    /// Removes a property by exact name and returns its value.
    pub fn remove(&mut self, name: &str) -> Option<PropertyValue> {
        let position = self.position(name)?;
        Some(self.entries.remove(position).value)
    }

    /// Removes a property by exact name and returns a typed missing-name error
    /// when it is absent.
    pub fn try_remove(&mut self, name: &str) -> Result<PropertyValue, PropertyError> {
        self.remove(name)
            .ok_or_else(|| PropertyError::NameNotFound {
                name: name.to_owned(),
            })
    }

    /// Consumes the collection and yields entries in insertion order.
    #[must_use]
    pub fn into_entries(self) -> Vec<PropertyEntry> {
        self.entries
    }

    /// Validates names, nested values, and resource usage with caller bounds.
    pub fn validate_with_limits(
        &self,
        limits: &ValidationLimits,
    ) -> Result<(), ModelValidationError> {
        let mut state = ValidationState::new(limits);
        self.validate_into(&mut state, 0)
    }

    pub(crate) fn validate_into(
        &self,
        state: &mut ValidationState<'_>,
        depth: usize,
    ) -> Result<(), ModelValidationError> {
        validate_properties_iterative(self, state, depth)
    }

    /// Compares ordered persistent properties and nested values while using
    /// semantic floating-point equality.
    #[must_use]
    pub fn semantic_eq(&self, other: &Self) -> bool {
        self.len() == other.len()
            && self.iter().zip(other).all(|(left, right)| {
                left.name == right.name && left.value.semantic_eq(&right.value)
            })
    }
}

impl IntoIterator for Properties {
    type Item = PropertyEntry;
    type IntoIter = std::vec::IntoIter<PropertyEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}

impl<'a> IntoIterator for &'a Properties {
    type Item = &'a PropertyEntry;
    type IntoIter = std::slice::Iter<'a, PropertyEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}

/// Alias emphasizing that the collection is ordered.
pub type OrderedProperties = Properties;

/// Alias matching JMeter's property-map terminology.
pub type PropertyMap = Properties;

/// Alias used by model consumers that mirror JMeter's run-scoped naming.
pub type JMeterProperties = Properties;
