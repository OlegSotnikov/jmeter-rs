// SPDX-License-Identifier: Apache-2.0
//! Explicit JMX syntax-to-semantic mapping and canonical encoding.
//!
//! This layer deliberately sits above the lossless XML event parser.  It
//! validates JMeter's alternating element/hashTree grammar, decodes the
//! structural SaveService property vocabulary into `jmeter-rs-model`, and
//! keeps wire-only information (tags, extra attributes, unknown payloads and
//! property node kinds) beside the model.  No class name is ever loaded or
//! executed.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

use jmeter_rs_model::{
    ElementMetadata, ElementProperty, ElementTree, NodeId, ObjectPropertyAttribute, OpaqueValue,
    Properties, PropertyEntry, PropertyValue, SourceLocation, TestElement,
};

use crate::{
    Document, Error, EventKind, JmxRegistry, Position, SemanticErrorKind, Span, is_xml_char,
};

/// Options controlling syntax-to-semantic decoding.
#[derive(Clone, Debug)]
pub struct DecodeOptions {
    /// Bounded semantic allocation limits.
    pub limits: DecodeLimits,
    /// Optional source label copied into model source locations.
    pub source_name: Option<String>,
    /// Alias and upgrade vocabulary used for this document.
    pub registry: JmxRegistry,
    /// Apply the pinned historical class/property/value upgrades.
    pub apply_upgrades: bool,
}

impl Default for DecodeOptions {
    fn default() -> Self {
        Self {
            limits: DecodeLimits::default(),
            source_name: None,
            registry: JmxRegistry::default(),
            apply_upgrades: true,
        }
    }
}

impl DecodeOptions {
    /// Sets a caller-visible source label for diagnostics and locations.
    #[must_use]
    pub fn with_source_name(mut self, source_name: impl Into<String>) -> Self {
        self.source_name = Some(source_name.into());
        self
    }

    /// Uses a caller-supplied pinned registry pair.
    #[must_use]
    pub fn with_registry(mut self, registry: JmxRegistry) -> Self {
        self.registry = registry;
        self
    }

    /// Disables historical upgrade rewrites while retaining alias lookup.
    #[must_use]
    pub const fn without_upgrades(mut self) -> Self {
        self.apply_upgrades = false;
        self
    }
}

/// Resource limits applied while mapping syntax events to semantic values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodeLimits {
    /// Maximum number of semantic test-element nodes.
    pub max_elements: usize,
    /// Maximum number of persistent properties across the document.
    pub max_properties: usize,
    /// Maximum nested property depth.
    pub max_property_depth: usize,
    /// Maximum alternating semantic hashTree depth.  This is separate from
    /// the XML parser's nesting bound because a caller may construct or pass
    /// a syntax document with a much larger structural tree.
    pub max_tree_depth: usize,
    /// Maximum aggregate bytes retained in opaque/lexical semantic storage.
    ///
    /// This is a conservative semantic-storage budget, not a unique-source
    /// interval budget.  Each distinct opaque payload slot owned by the
    /// semantic document is charged once: unknown elements/properties,
    /// comments and processing instructions, retained non-whitespace CDATA
    /// spans, and object-value payloads all participate.  If an opaque parent
    /// and a child extension retain overlapping source bytes, they are still
    /// separate owned payloads and are charged separately.  Auxiliary index
    /// bookkeeping is not charged a second time for the same payload slot.
    pub max_opaque_bytes: usize,
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self {
            max_elements: 100_000,
            max_properties: 500_000,
            max_property_depth: 256,
            max_tree_depth: 256,
            max_opaque_bytes: 8 * 1024 * 1024,
        }
    }
}

impl DecodeLimits {
    /// A conservative limit set for unit tests and small plans.
    pub const fn small() -> Self {
        Self {
            max_elements: 1_000,
            max_properties: 10_000,
            max_property_depth: 64,
            max_tree_depth: 64,
            max_opaque_bytes: 512 * 1024,
        }
    }
}

/// Severity of a non-fatal semantic diagnostic.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DiagnosticSeverity {
    /// Informational fact, such as an unknown element retained opaquely.
    Info,
    /// A compatibility concern that did not prevent a lossless mapping.
    Warning,
}

/// A bounded, stable diagnostic attached to a semantic document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Diagnostic {
    /// Stable machine-readable code.
    pub code: String,
    /// Severity of the diagnostic.
    pub severity: DiagnosticSeverity,
    /// Human-readable bounded context.
    pub message: String,
    /// Source position, when the syntax parser supplied one.
    pub position: Option<Position>,
    /// Semantic node identity, when one has already been allocated.
    pub node_id: Option<NodeId>,
}

/// An exact XML attribute retained in source order.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SemanticAttribute {
    /// Lexical attribute name.
    pub name: String,
    /// Decoded attribute value.
    pub value: String,
}

impl SemanticAttribute {
    /// Creates an exact attribute pair.
    #[must_use]
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

/// Root metadata and source span of a semantic JMX document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticRootMetadata {
    /// Root XML element name (normally `jmeterTestPlan`).
    pub name: String,
    /// Root attributes in source order, including profile-specific extras.
    pub attributes: Vec<SemanticAttribute>,
    /// Complete root subtree span in the source document.
    pub span: Span,
}

impl SemanticRootMetadata {
    /// Creates root metadata from an element name and ordered attributes.
    #[must_use]
    pub fn new(name: impl Into<String>, attributes: Vec<SemanticAttribute>, span: Span) -> Self {
        Self {
            name: name.into(),
            attributes,
            span,
        }
    }

    /// Returns an exact root attribute value.
    #[must_use]
    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|attribute| attribute.name == name)
            .map(|attribute| attribute.value.as_str())
    }

    /// Returns the JMX wrapper conversion version.
    #[must_use]
    pub fn version(&self) -> Option<&str> {
        self.attribute("version")
    }

    /// Returns the SaveService properties version.
    #[must_use]
    pub fn properties_version(&self) -> Option<&str> {
        self.attribute("properties")
    }

    /// Returns the JMeter producer version.
    #[must_use]
    pub fn jmeter_version(&self) -> Option<&str> {
        self.attribute("jmeter")
    }
}

/// Wire metadata for one semantic element before/after alias upgrades.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticElementInfo {
    /// Exact source XML tag.
    pub tag: String,
    /// Source-order non-special attributes.
    pub extra_attributes: Vec<SemanticAttribute>,
    /// Original special-attribute values before upgrades.
    pub original_testclass: String,
    /// Original GUI class value before upgrades.
    pub original_guiclass: String,
    /// Original element name before legacy decoding.
    pub original_testname: String,
    /// Whether the element was recognized by the pinned alias table.
    pub opaque: bool,
    /// Source start-to-end subtree span.
    pub span: Span,
}

impl SemanticElementInfo {
    /// Returns the exact source XML tag.
    #[must_use]
    pub fn wire_tag(&self) -> &str {
        &self.tag
    }

    /// Returns whether this node is retained as an unknown extension.
    #[must_use]
    pub const fn is_opaque(&self) -> bool {
        self.opaque
    }
}

/// Wire kind retained for one property path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireProperty {
    /// XML property node name (`stringProp`, `elementProp`, or an unknown tag).
    pub tag: String,
    /// Extra attributes in source order (excluding `name`).
    pub extra_attributes: Vec<SemanticAttribute>,
    /// Original complete XML bytes for an unknown property, when available.
    pub raw_xml: Option<Vec<u8>>,
}

/// A name-free inventory entry for a source property removed by an explicit
/// upgrade rule.
///
/// Only the document-local element identity and bounded source size are
/// exposed.  The property name and raw bytes remain private to the semantic
/// writer so diagnostics and fuzz invariants cannot accidentally disclose
/// user-controlled property data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DroppedProperty {
    /// Document-local identity of the element that owned the property.
    pub node_id: NodeId,
    /// Number of source bytes retained for diagnostics.
    pub source_bytes: usize,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct PropertyPath {
    node_id: NodeId,
    names: Vec<String>,
    /// The occurrence of each name among its siblings in the source wire
    /// representation.  A name is not an identity: JMeter permits duplicate
    /// map/named-collection keys, and positional collections have no names at
    /// all.  Keeping the occurrence beside the name prevents source metadata
    /// from being overwritten or reused for a different entry after an edit.
    occurrences: Vec<usize>,
}

impl PropertyPath {
    fn new(node_id: NodeId) -> Self {
        Self {
            node_id,
            names: Vec::new(),
            occurrences: Vec::new(),
        }
    }

    fn child(&self, name: &str) -> Self {
        self.child_occurrence(name, 0)
    }

    fn child_occurrence(&self, name: &str, occurrence: usize) -> Self {
        let mut child = self.clone();
        child.names.push(name.to_owned());
        child.occurrences.push(occurrence);
        child
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ElementItem {
    Property(String),
    Opaque {
        raw: Vec<u8>,
        type_name: String,
        occurrence: usize,
    },
}

/// An ordered event in the JMX wrapper or a `hashTree` container.
///
/// The semantic model owns element identity and child ordering, while this
/// JMX-side stream owns the wire-visible placement of non-element XML events.
/// A `HashTree` event identifies the companion tree belonging to the
/// preceding `Element` event.  `RootHashTree` is used only in the wrapper
/// event stream.  Whitespace-only text/CDATA is formatting and is not kept in
/// this stream; comments, processing instructions, and non-whitespace CDATA
/// are retained as opaque raw XML.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SemanticEvent {
    /// An element in the ordered semantic tree.
    Element(NodeId),
    /// The child `hashTree` companion for an element event with this ID.
    HashTree(NodeId),
    /// The single root `hashTree` child of the JMX wrapper.
    RootHashTree,
    /// A retained comment, processing instruction, or CDATA event.
    Extension(OpaqueValue),
}

type DecodedProperty = (
    String,
    PropertyValue,
    WireProperty,
    Option<(Vec<u8>, String)>,
);

#[derive(Clone, Debug, Eq, PartialEq)]
enum NestedItem {
    Property(String),
    Opaque {
        raw: Vec<u8>,
        type_name: String,
        occurrence: usize,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NestedMetadata {
    extra_attributes: Vec<SemanticAttribute>,
    items: Vec<NestedItem>,
}

/// The source-side semantic state needed to decide whether an opaque element
/// can be emitted from its original XML span.  Source locations are excluded:
/// changing a diagnostic label must not turn a lossless element into a rebuilt
/// one.
#[derive(Clone, Debug)]
struct ElementSnapshot {
    metadata: ElementMetadata,
    enabled: bool,
    properties: Properties,
    opaque_extensions: Vec<OpaqueValue>,
}

impl ElementSnapshot {
    fn from_element(element: &TestElement) -> Self {
        Self {
            metadata: element.metadata.clone(),
            enabled: element.enabled,
            properties: element.properties.clone(),
            opaque_extensions: element.opaque_extensions.clone(),
        }
    }

    fn matches(&self, element: &TestElement) -> crate::Result<bool> {
        if self.metadata != element.metadata || self.enabled != element.enabled {
            return Ok(false);
        }
        if !properties_equal_bounded(&self.properties, &element.properties)? {
            return Ok(false);
        }
        compare_opaque_extensions(&self.opaque_extensions, &element.opaque_extensions)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObjectValueMetadata {
    attributes: Vec<SemanticAttribute>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ObjectPropertyChild {
    Name,
    Value,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObjectPropertyShape {
    children: Vec<ObjectPropertyChild>,
    name_attributes: Vec<SemanticAttribute>,
}

/// A semantic JMX document backed by the stable model crate.
#[derive(Clone, Debug)]
pub struct SemanticDocument {
    /// Root metadata retained from the source document.
    pub root: SemanticRootMetadata,
    /// Ordered identity tree of test elements.
    pub tree: ElementTree,
    /// Pinned alias/upgrade registry used to decode this document.
    registry: JmxRegistry,
    /// Wire element details keyed by document-local node identity.
    element_info: BTreeMap<NodeId, SemanticElementInfo>,
    /// Attributes on the document's root hashTree.
    root_hash_tree_attributes: Vec<SemanticAttribute>,
    /// Non-element XML events retained from the root wrapper. The exact
    /// source placement is carried by `root_events`; this extension-only view
    /// remains for compatibility with earlier callers.
    root_extensions: Vec<OpaqueValue>,
    /// Non-element XML events retained directly inside the root hashTree.
    root_hash_tree_extensions: Vec<OpaqueValue>,
    /// Attributes on each element's child hashTree.
    hash_tree_attributes: BTreeMap<NodeId, Vec<SemanticAttribute>>,
    /// Non-element XML events retained from each hashTree. The exact source
    /// placement is carried by `hash_tree_events`; this extension-only view
    /// remains for compatibility with earlier callers.
    hash_tree_extensions: BTreeMap<NodeId, Vec<OpaqueValue>>,
    /// Ordered wrapper events. Parsed documents contain one
    /// [`SemanticEvent::RootHashTree`] and all retained non-element events;
    /// programmatically constructed documents leave this empty and use the
    /// canonical fallback ordering.
    root_events: Vec<SemanticEvent>,
    /// Comments and processing instructions before the JMX root element.
    leading_extensions: Vec<OpaqueValue>,
    /// Comments and processing instructions after the JMX root element.
    trailing_extensions: Vec<OpaqueValue>,
    /// Ordered events for each child `hashTree`. `None` is the root
    /// `hashTree`; `Some(id)` is the child tree belonging to that element.
    hash_tree_events: BTreeMap<Option<NodeId>, Vec<SemanticEvent>>,
    /// Property/opaque child order keyed by document-local node identity.
    element_items: BTreeMap<NodeId, Vec<ElementItem>>,
    /// Wire property tags and attributes keyed by semantic property path.
    wire_properties: BTreeMap<PropertyPath, WireProperty>,
    /// Decoded source values keyed by semantic property path.  This guards
    /// raw XML reuse after a caller edits an opaque property value.
    original_property_values: BTreeMap<PropertyPath, PropertyValue>,
    /// Source spans keyed by semantic property path.
    property_spans: BTreeMap<PropertyPath, Span>,
    /// Nested element-property metadata keyed by semantic property path.
    nested_metadata: BTreeMap<PropertyPath, NestedMetadata>,
    /// Attributes on serialized `objProp` value children.
    object_value_metadata: BTreeMap<PropertyPath, ObjectValueMetadata>,
    /// Wire shape for object properties whose name is a child element, as
    /// emitted by standard JMeter SaveService (`<name>...</name>`).
    object_property_shapes: BTreeMap<PropertyPath, ObjectPropertyShape>,
    /// Source bytes for unknown element subtrees.
    opaque_element_bytes: BTreeMap<NodeId, Vec<u8>>,
    /// Raw bytes for properties explicitly removed by a pinned upgrade rule.
    /// These are retained for diagnostics but intentionally omitted by the
    /// canonical writer, matching `upgrade.properties` deletion semantics.
    dropped_property_bytes: BTreeMap<PropertyPath, Vec<u8>>,
    /// Source-side state for deciding when an unknown element can be emitted
    /// from its original raw XML span.
    element_snapshots: BTreeMap<NodeId, ElementSnapshot>,
    /// Non-fatal compatibility diagnostics.
    diagnostics: Vec<Diagnostic>,
    /// Source label copied into model locations.
    source_name: Option<String>,
}

impl SemanticDocument {
    /// Creates a semantic document for programmatically constructed model data.
    ///
    /// Wire details are inferred from the model during canonical encoding;
    /// documents loaded from syntax retain the richer source-side metadata.
    #[must_use]
    pub fn new(root: SemanticRootMetadata, tree: ElementTree) -> Self {
        Self {
            root,
            tree,
            registry: JmxRegistry::default(),
            element_info: BTreeMap::new(),
            root_hash_tree_attributes: Vec::new(),
            root_extensions: Vec::new(),
            root_hash_tree_extensions: Vec::new(),
            hash_tree_attributes: BTreeMap::new(),
            hash_tree_extensions: BTreeMap::new(),
            root_events: Vec::new(),
            leading_extensions: Vec::new(),
            trailing_extensions: Vec::new(),
            hash_tree_events: BTreeMap::new(),
            element_items: BTreeMap::new(),
            wire_properties: BTreeMap::new(),
            original_property_values: BTreeMap::new(),
            property_spans: BTreeMap::new(),
            nested_metadata: BTreeMap::new(),
            object_value_metadata: BTreeMap::new(),
            object_property_shapes: BTreeMap::new(),
            opaque_element_bytes: BTreeMap::new(),
            dropped_property_bytes: BTreeMap::new(),
            element_snapshots: BTreeMap::new(),
            diagnostics: Vec::new(),
            source_name: None,
        }
    }

    /// Decodes a parsed syntax document with default pinned options.
    pub fn decode(document: &Document) -> crate::Result<Self> {
        Self::decode_with_options(document, DecodeOptions::default())
    }

    /// Decodes syntax with explicit limits, source label, and registry.
    pub fn decode_with_options(document: &Document, options: DecodeOptions) -> crate::Result<Self> {
        Decoder::new(document, options).decode()
    }

    /// Parses and decodes a complete JMX byte slice.
    pub fn from_bytes(source: &[u8]) -> crate::Result<Self> {
        let document = crate::Parser::new().parse(source)?;
        Self::decode(&document)
    }

    /// Parses and decodes a complete JMX byte slice with options.
    pub fn from_bytes_with_options(source: &[u8], options: DecodeOptions) -> crate::Result<Self> {
        let document = crate::Parser::new().parse(source)?;
        Self::decode_with_options(&document, options)
    }

    /// Returns root metadata.
    #[must_use]
    pub fn root(&self) -> &SemanticRootMetadata {
        &self.root
    }

    /// Returns retained non-element XML events directly inside the wrapper.
    ///
    /// This compatibility accessor preserves the historical extension-only
    /// view. Use [`Self::root_events`] when the exact placement relative to
    /// the root `hashTree` is needed.
    #[must_use]
    pub fn root_extensions(&self) -> &[OpaqueValue] {
        &self.root_extensions
    }

    /// Returns the ordered wrapper event stream, including the root
    /// `hashTree` slot. Empty means that this document was constructed without
    /// a source wire stream and canonical encoding will use model order.
    #[must_use]
    pub fn root_events(&self) -> &[SemanticEvent] {
        &self.root_events
    }

    /// Returns comments and processing instructions before the JMX root.
    #[must_use]
    pub fn leading_extensions(&self) -> &[OpaqueValue] {
        &self.leading_extensions
    }

    /// Returns comments and processing instructions after the JMX root.
    #[must_use]
    pub fn trailing_extensions(&self) -> &[OpaqueValue] {
        &self.trailing_extensions
    }

    /// Returns comments and processing instructions retained directly inside
    /// the root `hashTree`.  This accessor is useful to no-drop and fuzz
    /// invariants because these events are not model test-element children.
    #[must_use]
    pub fn root_hash_tree_extensions(&self) -> &[OpaqueValue] {
        &self.root_hash_tree_extensions
    }

    /// Returns the ordered event stream for the root `hashTree`, including
    /// element/companion-tree slots and retained non-element XML events.
    #[must_use]
    pub fn root_hash_tree_events(&self) -> &[SemanticEvent] {
        self.hash_tree_events.get(&None).map_or(&[], Vec::as_slice)
    }

    /// Returns comments and processing instructions retained directly inside
    /// a child `hashTree`, if the node has one.
    #[must_use]
    pub fn hash_tree_extensions(&self, id: NodeId) -> Option<&[OpaqueValue]> {
        self.hash_tree_extensions.get(&id).map(Vec::as_slice)
    }

    /// Returns the ordered event stream for an element's child `hashTree`.
    #[must_use]
    pub fn hash_tree_events(&self, id: NodeId) -> Option<&[SemanticEvent]> {
        self.hash_tree_events.get(&Some(id)).map(Vec::as_slice)
    }

    /// Returns the ordered identity tree.
    #[must_use]
    pub fn tree(&self) -> &ElementTree {
        &self.tree
    }

    /// Returns mutable access to the ordered identity tree.
    pub fn tree_mut(&mut self) -> &mut ElementTree {
        &mut self.tree
    }

    /// Returns the document-local IDs in deterministic preorder.
    ///
    /// The legacy infallible accessor returns an empty vector when a
    /// programmatically constructed tree exceeds the semantic encoder's node
    /// budget.  Call [`Self::try_node_ids`] when the limit must be observed by
    /// the caller rather than treated as an unavailable inventory.
    #[must_use]
    pub fn node_ids(&self) -> Vec<NodeId> {
        self.try_node_ids().unwrap_or_default()
    }

    /// Returns document-local IDs in deterministic preorder with an explicit
    /// allocation/limit error for oversized programmatic trees.
    pub fn try_node_ids(&self) -> crate::Result<Vec<NodeId>> {
        bounded_preorder_ids(&self.tree, MAX_ENCODER_NODES)
    }

    /// Returns the source tag for a semantic node.
    #[must_use]
    pub fn element_tag(&self, id: NodeId) -> Option<&str> {
        self.element_info.get(&id).map(|info| info.tag.as_str())
    }

    /// Returns whether a node may be considered executable by a later runtime
    /// compiler. Unknown/plugin nodes are preservation-only.
    #[must_use]
    pub fn is_executable(&self, id: NodeId) -> bool {
        self.tree
            .lookup(id)
            .ok()
            .is_some_and(|node| node.value().is_enabled() && !self.is_opaque(id))
    }

    /// Returns the registry provenance used by this document.
    #[must_use]
    pub fn registry(&self) -> &JmxRegistry {
        &self.registry
    }

    /// Returns all non-fatal diagnostics in source order.
    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    /// Returns wire details for a semantic node.
    #[must_use]
    pub fn element_info(&self, id: NodeId) -> Option<&SemanticElementInfo> {
        self.element_info.get(&id)
    }

    /// Returns whether a semantic node is an unknown/opaque test element.
    #[must_use]
    pub fn is_opaque(&self, id: NodeId) -> bool {
        self.element_info.get(&id).is_some_and(|info| info.opaque)
    }

    /// Returns the exact source bytes for an opaque element, if retained.
    #[must_use]
    pub fn opaque_element_bytes(&self, id: NodeId) -> Option<&[u8]> {
        self.opaque_element_bytes.get(&id).map(Vec::as_slice)
    }

    /// Returns source bytes for a property removed by an explicit upgrade rule.
    /// The canonical writer omits these bytes by design; callers can inspect
    /// them to distinguish intentional migration from silent data loss.
    #[must_use]
    pub fn dropped_property_bytes(&self, id: NodeId, name: &str) -> Option<&[u8]> {
        self.dropped_property_bytes
            .get(&PropertyPath {
                node_id: id,
                names: vec![name.to_owned()],
                occurrences: vec![0],
            })
            .map(Vec::as_slice)
    }

    /// Returns a bounded, deterministic inventory of source properties
    /// removed by explicit upgrade rules.
    ///
    /// Names and raw bytes are intentionally omitted.  The entries are
    /// ordered by the document's internal property paths, and the retained
    /// source bytes are bounded by the decoder's opaque-storage limit.
    #[must_use]
    pub fn dropped_property_inventory(&self) -> Vec<DroppedProperty> {
        self.dropped_property_bytes
            .iter()
            .map(|(path, raw)| DroppedProperty {
                node_id: path.node_id,
                source_bytes: raw.len(),
            })
            .collect()
    }

    /// Returns the source label used for model locations.
    #[must_use]
    pub fn source_name(&self) -> Option<&str> {
        self.source_name.as_deref()
    }

    /// Returns the wire property tag for a top-level property.
    #[must_use]
    pub fn property_wire(&self, id: NodeId, name: &str) -> Option<&WireProperty> {
        self.wire_properties.get(&PropertyPath {
            node_id: id,
            names: vec![name.to_owned()],
            occurrences: vec![0],
        })
    }

    /// Returns the source span for a property path. The path starts with the
    /// top-level property name and continues through nested collection or
    /// element-property names.
    #[must_use]
    pub fn property_span(&self, id: NodeId, names: &[&str]) -> Option<Span> {
        self.property_spans
            .get(&PropertyPath {
                node_id: id,
                names: names.iter().map(|name| (*name).to_owned()).collect(),
                occurrences: vec![0; names.len()],
            })
            .copied()
    }

    /// Canonically writes this semantic document as UTF-8 JMX XML.
    pub fn write_canonical<W: Write>(&self, mut writer: W) -> crate::Result<()> {
        let mut encoder = Encoder::new(self, &mut writer);
        encoder.write_document()
    }

    /// Returns canonical UTF-8 JMX bytes.
    pub fn to_canonical_bytes(&self) -> crate::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        self.write_canonical(&mut bytes)?;
        Ok(bytes)
    }

    /// Alias for [`Self::to_canonical_bytes`].
    pub fn encode(&self) -> crate::Result<Vec<u8>> {
        self.to_canonical_bytes()
    }

    /// Alias for [`Self::to_canonical_bytes`].
    pub fn canonical_xml(&self) -> crate::Result<Vec<u8>> {
        self.to_canonical_bytes()
    }

    /// Alias for [`Self::write_canonical`].
    pub fn write<W: Write>(&self, writer: W) -> crate::Result<()> {
        self.write_canonical(writer)
    }

    /// Compares the existing semantic-document policy used by [`PartialEq`].
    ///
    /// Semantic equality keeps ordered model topology, typed values, retained
    /// extension events, and registry meaning. Alias spellings and pinned
    /// upgrade spellings that resolve to the same component are intentionally
    /// equivalent. It is not a byte or lexical wire comparison.
    #[must_use]
    pub fn semantic_eq(&self, other: &Self) -> bool {
        self.try_semantic_eq(other).is_ok_and(|equal| equal)
    }

    /// Compares semantic document state while reporting a bounded-model
    /// failure instead of collapsing it into ordinary inequality.
    pub fn try_semantic_eq(&self, other: &Self) -> crate::Result<bool> {
        self.semantic_equal_checked(other)
    }

    /// Compares the retained wire metadata in addition to semantic meaning.
    ///
    /// This stricter relation distinguishes historical aliases and original
    /// special-attribute spellings even when [`Self::semantic_eq`] considers
    /// their decoded plans equal. Source byte offsets are diagnostics and are
    /// deliberately excluded.
    #[must_use]
    pub fn wire_eq(&self, other: &Self) -> bool {
        self.try_wire_eq(other).is_ok_and(|equal| equal)
    }

    /// Compares semantic and retained wire state with typed limit errors.
    pub fn try_wire_eq(&self, other: &Self) -> crate::Result<bool> {
        if !self.try_semantic_eq(other)? {
            return Ok(false);
        }
        Ok(self.element_info.len() == other.element_info.len()
            && self.element_info.iter().all(|(id, info)| {
                other.element_info.get(id).is_some_and(|rhs| {
                    info.tag == rhs.tag
                        && info.extra_attributes == rhs.extra_attributes
                        && info.original_testclass == rhs.original_testclass
                        && info.original_guiclass == rhs.original_guiclass
                        && info.original_testname == rhs.original_testname
                        && info.opaque == rhs.opaque
                })
            }))
    }
}

/// Compatibility alias for callers that name the semantic JMX document a
/// semantic plan.
pub type SemanticPlan = SemanticDocument;

/// Compatibility alias for callers that name the semantic document a JMX
/// document.
pub type JmxSemanticDocument = SemanticDocument;

// `PropertyValue` derives `PartialEq` in the model, which intentionally keeps
// Rust's IEEE NaN inequality.  A JMX round trip canonicalizes every NaN to the
// Java spelling `NaN`, however, so semantic document equality must compare NaN
// values by meaning (all NaN payloads are equivalent) while retaining the
// sign bit distinction of finite zero values.
fn float32_semantic_eq(left: f32, right: f32) -> bool {
    (left.is_nan() && right.is_nan()) || left.to_bits() == right.to_bits()
}

fn float64_semantic_eq(left: f64, right: f64) -> bool {
    (left.is_nan() && right.is_nan()) || left.to_bits() == right.to_bits()
}

enum PropertyCompareTask<'a> {
    Value {
        left: &'a PropertyValue,
        right: &'a PropertyValue,
        depth: usize,
    },
    Properties {
        left: &'a Properties,
        right: &'a Properties,
        depth: usize,
    },
    Maps {
        left: &'a BTreeMap<PropertyPath, PropertyValue>,
        right: &'a BTreeMap<PropertyPath, PropertyValue>,
        depth: usize,
    },
}

fn property_compare_limit(what: &str, limit: usize) -> Error {
    Error::semantic(
        SemanticErrorKind::Limit,
        None,
        format!("semantic property comparison exceeded {what} limit {limit}"),
    )
}

fn account_compare_entries(observed: &mut usize, count: usize) -> crate::Result<()> {
    let next = observed.saturating_add(count);
    if next > MAX_ENCODER_ENTRIES {
        return Err(property_compare_limit(
            "property entry count",
            MAX_ENCODER_ENTRIES,
        ));
    }
    *observed = next;
    Ok(())
}

fn account_compare_opaque_bytes(observed: &mut usize, count: usize) -> crate::Result<()> {
    let next = observed.saturating_add(count);
    if next > MAX_ENCODER_OPAQUE_BYTES {
        return Err(property_compare_limit(
            "opaque payload bytes",
            MAX_ENCODER_OPAQUE_BYTES,
        ));
    }
    *observed = next;
    Ok(())
}

fn compare_opaque_extensions(left: &[OpaqueValue], right: &[OpaqueValue]) -> crate::Result<bool> {
    if left.len() != right.len() {
        return Ok(false);
    }
    let mut entries = 0;
    let mut opaque_bytes = 0;
    account_compare_entries(&mut entries, left.len())?;
    for (left, right) in left.iter().zip(right) {
        account_compare_opaque_bytes(&mut opaque_bytes, left.raw.len().max(right.raw.len()))?;
        if left != right {
            return Ok(false);
        }
    }
    Ok(true)
}

fn compare_property_tasks(tasks: &mut Vec<PropertyCompareTask<'_>>) -> crate::Result<bool> {
    let mut entries = 0;
    let mut opaque_bytes = 0;
    while let Some(task) = tasks.pop() {
        match task {
            PropertyCompareTask::Value { left, right, depth } => {
                if depth > MAX_ENCODER_DEPTH {
                    return Err(property_compare_limit("property depth", MAX_ENCODER_DEPTH));
                }
                match (left, right) {
                    (PropertyValue::Null, PropertyValue::Null)
                    | (PropertyValue::Boolean(_), PropertyValue::Boolean(_))
                    | (PropertyValue::Integer(_), PropertyValue::Integer(_))
                    | (PropertyValue::Long(_), PropertyValue::Long(_))
                    | (PropertyValue::String(_), PropertyValue::String(_)) => {
                        if left != right {
                            return Ok(false);
                        }
                    }
                    (PropertyValue::Float(left), PropertyValue::Float(right)) => {
                        if !float32_semantic_eq(*left, *right) {
                            return Ok(false);
                        }
                    }
                    (PropertyValue::Double(left), PropertyValue::Double(right)) => {
                        if !float64_semantic_eq(*left, *right) {
                            return Ok(false);
                        }
                    }
                    (PropertyValue::Opaque(left), PropertyValue::Opaque(right)) => {
                        account_compare_opaque_bytes(
                            &mut opaque_bytes,
                            left.raw.len().max(right.raw.len()),
                        )?;
                        if left != right {
                            return Ok(false);
                        }
                    }
                    (PropertyValue::Collection(left), PropertyValue::Collection(right)) => {
                        if left.len() != right.len() {
                            return Ok(false);
                        }
                        account_compare_entries(&mut entries, left.len())?;
                        for (left, right) in left.iter().zip(right).rev() {
                            tasks.push(PropertyCompareTask::Value {
                                left,
                                right,
                                depth: depth.saturating_add(1),
                            });
                        }
                    }
                    (
                        PropertyValue::NamedCollection(left),
                        PropertyValue::NamedCollection(right),
                    )
                    | (PropertyValue::Map(left), PropertyValue::Map(right)) => {
                        if left.len() != right.len() {
                            return Ok(false);
                        }
                        if left
                            .iter()
                            .zip(right)
                            .any(|(left, right)| left.name != right.name)
                        {
                            return Ok(false);
                        }
                        account_compare_entries(&mut entries, left.len())?;
                        for (left, right) in left.iter().zip(right).rev() {
                            tasks.push(PropertyCompareTask::Value {
                                left: &left.value,
                                right: &right.value,
                                depth: depth.saturating_add(1),
                            });
                        }
                    }
                    (PropertyValue::Object(left), PropertyValue::Object(right)) => {
                        account_compare_opaque_bytes(
                            &mut opaque_bytes,
                            left.raw.len().max(right.raw.len()),
                        )?;
                        if left != right {
                            return Ok(false);
                        }
                    }
                    (PropertyValue::Element(left), PropertyValue::Element(right)) => {
                        if left.name != right.name || left.class_name != right.class_name {
                            return Ok(false);
                        }
                        if left.opaque_extensions.len() != right.opaque_extensions.len() {
                            return Ok(false);
                        }
                        account_compare_entries(&mut entries, left.opaque_extensions.len())?;
                        for (left, right) in
                            left.opaque_extensions.iter().zip(&right.opaque_extensions)
                        {
                            account_compare_opaque_bytes(
                                &mut opaque_bytes,
                                left.raw.len().max(right.raw.len()),
                            )?;
                            if left != right {
                                return Ok(false);
                            }
                        }
                        tasks.push(PropertyCompareTask::Properties {
                            left: &left.properties,
                            right: &right.properties,
                            depth: depth.saturating_add(1),
                        });
                    }
                    _ => return Ok(false),
                }
            }
            PropertyCompareTask::Properties { left, right, depth } => {
                if depth > MAX_ENCODER_DEPTH {
                    return Err(property_compare_limit("property depth", MAX_ENCODER_DEPTH));
                }
                if left.len() != right.len() {
                    return Ok(false);
                }
                if left
                    .iter()
                    .zip(right)
                    .any(|(left, right)| left.name != right.name)
                {
                    return Ok(false);
                }
                account_compare_entries(&mut entries, left.len())?;
                for (left, right) in left.as_slice().iter().zip(right.as_slice()).rev() {
                    tasks.push(PropertyCompareTask::Value {
                        left: &left.value,
                        right: &right.value,
                        depth,
                    });
                }
            }
            PropertyCompareTask::Maps { left, right, depth } => {
                if left.len() != right.len() {
                    return Ok(false);
                }
                account_compare_entries(&mut entries, left.len())?;
                for (path, value) in left {
                    let Some(other) = right.get(path) else {
                        return Ok(false);
                    };
                    tasks.push(PropertyCompareTask::Value {
                        left: value,
                        right: other,
                        depth,
                    });
                }
            }
        }
    }
    Ok(true)
}

fn property_values_equal_bounded(
    left: &PropertyValue,
    right: &PropertyValue,
) -> crate::Result<bool> {
    compare_property_tasks(&mut vec![PropertyCompareTask::Value {
        left,
        right,
        depth: 0,
    }])
}

fn properties_equal_bounded(left: &Properties, right: &Properties) -> crate::Result<bool> {
    compare_property_tasks(&mut vec![PropertyCompareTask::Properties {
        left,
        right,
        depth: 0,
    }])
}

fn property_maps_equal_bounded(
    left: &BTreeMap<PropertyPath, PropertyValue>,
    right: &BTreeMap<PropertyPath, PropertyValue>,
) -> crate::Result<bool> {
    compare_property_tasks(&mut vec![PropertyCompareTask::Maps {
        left,
        right,
        depth: 0,
    }])
}

fn property_values_equal(left: &PropertyValue, right: &PropertyValue) -> bool {
    property_values_equal_bounded(left, right).is_ok_and(|equal| equal)
}

fn alias_tags_equal(
    registry: &JmxRegistry,
    left: &SemanticElementInfo,
    right: &SemanticElementInfo,
) -> bool {
    fn upgraded_class(
        registry: &JmxRegistry,
        tag: &str,
        original: &str,
        original_gui: &str,
    ) -> Option<String> {
        let gui = registry
            .aliases
            .resolve(original_gui)
            .class_name
            .unwrap_or_else(|| original_gui.to_owned());
        registry
            .aliases
            .resolve(tag)
            .class_name
            .or_else(|| registry.aliases.resolve(original).class_name)
            .map(|class| registry.upgrades.upgrade_element(&class, &gui).test_class)
    }
    let left_class = upgraded_class(
        registry,
        &left.tag,
        &left.original_testclass,
        &left.original_guiclass,
    );
    let right_class = upgraded_class(
        registry,
        &right.tag,
        &right.original_testclass,
        &right.original_guiclass,
    );
    match (left_class, right_class) {
        (Some(left), Some(right)) => left == right,
        _ => left.tag == right.tag,
    }
}

impl PartialEq for SemanticDocument {
    fn eq(&self, other: &Self) -> bool {
        self.semantic_eq(other)
    }
}

impl SemanticDocument {
    fn semantic_equal_checked(&self, other: &Self) -> crate::Result<bool> {
        if self.root.name != other.root.name || self.root.attributes != other.root.attributes {
            return Ok(false);
        }
        let left_ids = bounded_preorder_ids(&self.tree, MAX_ENCODER_NODES)?;
        let right_ids = bounded_preorder_ids(&other.tree, MAX_ENCODER_NODES)?;
        if self.tree.root_ids() != other.tree.root_ids() || left_ids != right_ids {
            return Ok(false);
        }
        for id in left_ids {
            let Ok(left) = self.tree.lookup(id) else {
                return Ok(false);
            };
            let Ok(right) = other.tree.lookup(id) else {
                return Ok(false);
            };
            if left.parent() != right.parent()
                || left.children() != right.children()
                || left.value().metadata != right.value().metadata
                || left.value().enabled != right.value().enabled
                || left.value().opaque_extensions != right.value().opaque_extensions
            {
                return Ok(false);
            }
            if !properties_equal_bounded(&left.value().properties, &right.value().properties)? {
                return Ok(false);
            }
        }
        if self.registry != other.registry
            || self.element_info.len() != other.element_info.len()
            || !self.element_info.iter().all(|(id, info)| {
                other.element_info.get(id).is_some_and(|rhs| {
                    info.extra_attributes == rhs.extra_attributes
                        && info.opaque == rhs.opaque
                        && if info.opaque || rhs.opaque {
                            info.tag == rhs.tag
                        } else {
                            alias_tags_equal(&self.registry, info, rhs)
                        }
                })
            })
            || self.root_hash_tree_attributes != other.root_hash_tree_attributes
            || self.root_extensions != other.root_extensions
            || self.leading_extensions != other.leading_extensions
            || self.trailing_extensions != other.trailing_extensions
            || self.root_hash_tree_extensions != other.root_hash_tree_extensions
            || self.hash_tree_attributes != other.hash_tree_attributes
            || self.hash_tree_extensions != other.hash_tree_extensions
            || self.root_events != other.root_events
            || self.hash_tree_events != other.hash_tree_events
            || self.element_items != other.element_items
            || self.wire_properties != other.wire_properties
        {
            return Ok(false);
        }
        if !property_maps_equal_bounded(
            &self.original_property_values,
            &other.original_property_values,
        )? {
            return Ok(false);
        }
        Ok(self.nested_metadata == other.nested_metadata
            && self.object_value_metadata == other.object_value_metadata
            && self.object_property_shapes == other.object_property_shapes
            && self.opaque_element_bytes == other.opaque_element_bytes)
    }
}

/// Decodes syntax into the semantic model with default options.
pub fn decode(document: &Document) -> crate::Result<SemanticDocument> {
    SemanticDocument::decode(document)
}

/// Alias for [`decode`].
pub fn decode_document(document: &Document) -> crate::Result<SemanticDocument> {
    decode(document)
}

/// Parses and decodes JMX bytes with default options.
pub fn parse_semantic(source: &[u8]) -> crate::Result<SemanticDocument> {
    SemanticDocument::from_bytes(source)
}

/// Canonically encodes a semantic JMX document.
pub fn encode_semantic(document: &SemanticDocument) -> crate::Result<Vec<u8>> {
    document.to_canonical_bytes()
}

/// Alias for [`encode_semantic`].
pub fn encode_document(document: &SemanticDocument) -> crate::Result<Vec<u8>> {
    encode_semantic(document)
}

#[derive(Clone)]
struct XmlNode {
    name: String,
    attributes: Vec<SemanticAttribute>,
    children: Vec<XmlChild>,
    span: Span,
}

#[derive(Clone)]
enum XmlChild {
    Element(usize),
    Text { value: String, event_index: usize },
    CData { value: String, event_index: usize },
    Other { event_index: usize },
}

struct XmlArena {
    nodes: Vec<XmlNode>,
    root: usize,
    leading_extensions: Vec<usize>,
    trailing_extensions: Vec<usize>,
}

impl XmlArena {
    fn build(document: &Document) -> crate::Result<Self> {
        let mut nodes = Vec::<XmlNode>::new();
        let mut stack = Vec::<usize>::new();
        let mut root = None;
        let mut leading_extensions = Vec::new();
        let mut trailing_extensions = Vec::new();
        for (event_index, event) in document.events().iter().enumerate() {
            match &event.kind {
                EventKind::StartElement(start) => {
                    let index = nodes.len();
                    nodes.push(XmlNode {
                        name: start.name.raw().to_owned(),
                        attributes: attributes(&start.attributes),
                        children: Vec::new(),
                        span: event.subtree_span().unwrap_or(event.span),
                    });
                    if let Some(parent) = stack.last().copied() {
                        nodes[parent].children.push(XmlChild::Element(index));
                    } else if root.replace(index).is_some() {
                        return Err(Error::semantic(
                            SemanticErrorKind::InvalidRoot,
                            Some(position(document, event.span.start)),
                            "semantic input contains more than one root element",
                        ));
                    }
                    stack.push(index);
                }
                EventKind::EmptyElement(empty) => {
                    let index = nodes.len();
                    nodes.push(XmlNode {
                        name: empty.name.raw().to_owned(),
                        attributes: attributes(&empty.attributes),
                        children: Vec::new(),
                        span: event.span,
                    });
                    if let Some(parent) = stack.last().copied() {
                        nodes[parent].children.push(XmlChild::Element(index));
                    } else if root.replace(index).is_some() {
                        return Err(Error::semantic(
                            SemanticErrorKind::InvalidRoot,
                            Some(position(document, event.span.start)),
                            "semantic input contains more than one root element",
                        ));
                    }
                }
                EventKind::EndElement(_) => {
                    let Some(index) = stack.pop() else {
                        return Err(Error::semantic(
                            SemanticErrorKind::Topology,
                            Some(position(document, event.span.start)),
                            "end element has no semantic start node",
                        ));
                    };
                    nodes[index].span = Span {
                        start: nodes[index].span.start,
                        end: event.span.end,
                    };
                }
                EventKind::Text(text) => {
                    if let Some(parent) = stack.last().copied() {
                        nodes[parent].children.push(XmlChild::Text {
                            value: text.value.clone(),
                            event_index,
                        });
                    }
                }
                EventKind::CData(cdata) => {
                    if let Some(parent) = stack.last().copied() {
                        nodes[parent].children.push(XmlChild::CData {
                            value: cdata.value.clone(),
                            event_index,
                        });
                    }
                }
                EventKind::Comment(_) | EventKind::ProcessingInstruction(_) => {
                    if let Some(parent) = stack.last().copied() {
                        nodes[parent].children.push(XmlChild::Other { event_index });
                    } else if root.is_some() {
                        trailing_extensions.push(event_index);
                    } else {
                        leading_extensions.push(event_index);
                    }
                }
                EventKind::XmlDeclaration(_) => {}
            }
        }
        if !stack.is_empty() {
            return Err(Error::semantic(
                SemanticErrorKind::Topology,
                None,
                "semantic event arena contains unclosed elements",
            ));
        }
        let Some(root) = root else {
            return Err(Error::semantic(
                SemanticErrorKind::InvalidRoot,
                None,
                "semantic input has no root element",
            ));
        };
        Ok(Self {
            nodes,
            root,
            leading_extensions,
            trailing_extensions,
        })
    }
}

fn attributes(source: &[crate::Attribute]) -> Vec<SemanticAttribute> {
    source
        .iter()
        .map(|attribute| SemanticAttribute::new(attribute.name().raw(), attribute.value()))
        .collect()
}

fn position(document: &Document, offset: usize) -> Position {
    document.position(offset).unwrap_or(Position {
        offset,
        line: 1,
        column: 1,
    })
}

fn attr<'a>(attributes: &'a [SemanticAttribute], name: &str) -> Option<&'a str> {
    attributes
        .iter()
        .find(|attribute| attribute.name == name)
        .map(|attribute| attribute.value.as_str())
}

fn has_attr(attributes: &[SemanticAttribute], name: &str) -> bool {
    attributes.iter().any(|attribute| attribute.name == name)
}

fn non_special_attributes(
    attributes: &[SemanticAttribute],
    specials: &[&str],
) -> Vec<SemanticAttribute> {
    attributes
        .iter()
        .filter(|attribute| !specials.iter().any(|special| *special == attribute.name))
        .cloned()
        .collect()
}

struct Decoder<'a> {
    document: &'a Document,
    options: DecodeOptions,
    arena: XmlArena,
    tree: ElementTree,
    root: SemanticRootMetadata,
    source_name: Option<String>,
    registry: JmxRegistry,
    element_info: BTreeMap<NodeId, SemanticElementInfo>,
    root_hash_tree_attributes: Vec<SemanticAttribute>,
    root_extensions: Vec<OpaqueValue>,
    leading_extensions: Vec<OpaqueValue>,
    trailing_extensions: Vec<OpaqueValue>,
    root_hash_tree_extensions: Vec<OpaqueValue>,
    hash_tree_attributes: BTreeMap<NodeId, Vec<SemanticAttribute>>,
    hash_tree_extensions: BTreeMap<NodeId, Vec<OpaqueValue>>,
    root_events: Vec<SemanticEvent>,
    hash_tree_events: BTreeMap<Option<NodeId>, Vec<SemanticEvent>>,
    element_items: BTreeMap<NodeId, Vec<ElementItem>>,
    wire_properties: BTreeMap<PropertyPath, WireProperty>,
    original_property_values: BTreeMap<PropertyPath, PropertyValue>,
    property_spans: BTreeMap<PropertyPath, Span>,
    nested_metadata: BTreeMap<PropertyPath, NestedMetadata>,
    object_value_metadata: BTreeMap<PropertyPath, ObjectValueMetadata>,
    object_property_shapes: BTreeMap<PropertyPath, ObjectPropertyShape>,
    opaque_element_bytes: BTreeMap<NodeId, Vec<u8>>,
    dropped_property_bytes: BTreeMap<PropertyPath, Vec<u8>>,
    /// Next source occurrence for each duplicate upgrade-deleted property.
    /// Keeping this counter separate avoids rescanning the retained-byte map
    /// for every duplicate input while preserving deterministic paths.
    dropped_property_occurrences: BTreeMap<(NodeId, String), usize>,
    element_snapshots: BTreeMap<NodeId, ElementSnapshot>,
    diagnostics: Vec<Diagnostic>,
    property_count: usize,
    opaque_storage_bytes: usize,
}

impl<'a> Decoder<'a> {
    fn new(document: &'a Document, options: DecodeOptions) -> Self {
        // XmlArena::build is intentionally delayed until decode so syntax
        // errors and semantic errors share one public result type.
        let arena = XmlArena {
            nodes: Vec::new(),
            root: 0,
            leading_extensions: Vec::new(),
            trailing_extensions: Vec::new(),
        };
        let root = SemanticRootMetadata {
            name: String::new(),
            attributes: Vec::new(),
            span: Span { start: 0, end: 0 },
        };
        Self {
            document,
            source_name: options.source_name.clone(),
            registry: options.registry.clone(),
            options,
            arena,
            tree: ElementTree::new(),
            root,
            element_info: BTreeMap::new(),
            root_hash_tree_attributes: Vec::new(),
            root_extensions: Vec::new(),
            leading_extensions: Vec::new(),
            trailing_extensions: Vec::new(),
            root_hash_tree_extensions: Vec::new(),
            hash_tree_attributes: BTreeMap::new(),
            hash_tree_extensions: BTreeMap::new(),
            root_events: Vec::new(),
            hash_tree_events: BTreeMap::new(),
            element_items: BTreeMap::new(),
            wire_properties: BTreeMap::new(),
            original_property_values: BTreeMap::new(),
            property_spans: BTreeMap::new(),
            nested_metadata: BTreeMap::new(),
            object_value_metadata: BTreeMap::new(),
            object_property_shapes: BTreeMap::new(),
            opaque_element_bytes: BTreeMap::new(),
            dropped_property_bytes: BTreeMap::new(),
            dropped_property_occurrences: BTreeMap::new(),
            element_snapshots: BTreeMap::new(),
            diagnostics: Vec::new(),
            property_count: 0,
            opaque_storage_bytes: 0,
        }
    }

    fn decode(mut self) -> crate::Result<SemanticDocument> {
        if let Err(_error) = self.registry.validate() {
            return Err(Error::semantic(
                SemanticErrorKind::Registry,
                None,
                "semantic registry failed validation",
            ));
        }
        self.arena = XmlArena::build(self.document)?;
        self.leading_extensions =
            self.decode_external_extensions(&self.arena.leading_extensions.clone())?;
        self.trailing_extensions =
            self.decode_external_extensions(&self.arena.trailing_extensions.clone())?;
        let root_node = self.arena.nodes[self.arena.root].clone();
        if root_node.name != "jmeterTestPlan" {
            return Err(self.semantic_error(
                SemanticErrorKind::InvalidRoot,
                self.arena.root,
                "expected jmeterTestPlan root",
            ));
        }
        if !has_attr(&root_node.attributes, "version") {
            return Err(self.semantic_error(
                SemanticErrorKind::RootMetadata,
                self.arena.root,
                "jmeterTestPlan is missing required version metadata",
            ));
        }
        if !matches!(attr(&root_node.attributes, "version"), Some("1.0" | "1.2")) {
            return Err(self.semantic_error(
                SemanticErrorKind::RootMetadata,
                self.arena.root,
                "unsupported JMX wrapper version",
            ));
        }
        let (root_events, root_hash_tree) = self.decode_wrapper_events(self.arena.root)?;
        self.root_extensions = extensions_from_events(&root_events);
        self.root_events = root_events;
        let Some(hash_tree_index) = root_hash_tree else {
            return Err(self.semantic_error(
                SemanticErrorKind::Topology,
                self.arena.root,
                "jmeterTestPlan must contain exactly one root hashTree",
            ));
        };
        self.root = SemanticRootMetadata {
            name: root_node.name.clone(),
            attributes: root_node.attributes.clone(),
            span: root_node.span,
        };
        self.decode_hash_tree(hash_tree_index, None, 0)?;
        self.tree.validate().map_err(|error| {
            Error::semantic(
                SemanticErrorKind::Topology,
                None,
                format!("decoded identity tree is invalid: {error}"),
            )
        })?;
        Ok(SemanticDocument {
            root: self.root,
            tree: self.tree,
            registry: self.registry,
            element_info: self.element_info,
            root_hash_tree_attributes: self.root_hash_tree_attributes,
            root_extensions: self.root_extensions,
            leading_extensions: self.leading_extensions,
            trailing_extensions: self.trailing_extensions,
            root_hash_tree_extensions: self.root_hash_tree_extensions,
            hash_tree_attributes: self.hash_tree_attributes,
            hash_tree_extensions: self.hash_tree_extensions,
            root_events: self.root_events,
            hash_tree_events: self.hash_tree_events,
            element_items: self.element_items,
            wire_properties: self.wire_properties,
            original_property_values: self.original_property_values,
            property_spans: self.property_spans,
            nested_metadata: self.nested_metadata,
            object_value_metadata: self.object_value_metadata,
            object_property_shapes: self.object_property_shapes,
            opaque_element_bytes: self.opaque_element_bytes,
            dropped_property_bytes: self.dropped_property_bytes,
            element_snapshots: self.element_snapshots,
            diagnostics: self.diagnostics,
            source_name: self.source_name,
        })
    }

    fn decode_external_extensions(
        &mut self,
        event_indices: &[usize],
    ) -> crate::Result<Vec<OpaqueValue>> {
        let mut extensions = Vec::with_capacity(event_indices.len());
        for event_index in event_indices {
            let event = self.document.events().get(*event_index).ok_or_else(|| {
                Error::semantic(
                    SemanticErrorKind::InvalidRoot,
                    None,
                    "top-level XML extension event is outside the source document",
                )
            })?;
            let type_name = match &event.kind {
                EventKind::Comment(_) => "xml:comment",
                EventKind::ProcessingInstruction(_) => "xml:processing-instruction",
                _ => {
                    return Err(Error::semantic(
                        SemanticErrorKind::Unsupported,
                        Some(position(self.document, event.span.start)),
                        "unsupported top-level XML event",
                    ));
                }
            };
            let raw = self.raw_span(event.span, 0)?;
            self.retain_opaque(raw.len(), 0)?;
            extensions.push(OpaqueValue::new(type_name, raw));
        }
        Ok(extensions)
    }

    fn decode_hash_tree(
        &mut self,
        hash_tree_index: usize,
        parent: Option<NodeId>,
        depth: usize,
    ) -> crate::Result<()> {
        if depth > self.options.limits.max_tree_depth {
            return Err(self.semantic_limit(
                hash_tree_index,
                "semantic tree depth",
                self.options.limits.max_tree_depth,
            ));
        }
        let attributes = self.arena.nodes[hash_tree_index].attributes.clone();
        if let Some(parent) = parent {
            self.hash_tree_attributes.insert(parent, attributes);
        } else {
            self.root_hash_tree_attributes = attributes;
        }
        let mut events = Vec::new();
        let mut pending_element = None;
        let children = self.arena.nodes[hash_tree_index].children.clone();
        for child in children {
            let XmlChild::Element(element_index) = child.clone() else {
                if let Some(event) = self.decode_topology_extension(hash_tree_index, child)? {
                    events.push(event);
                }
                continue;
            };
            if self.arena.nodes[element_index].name == "hashTree" {
                let Some(element_id) = pending_element.take() else {
                    return Err(self.semantic_error(
                        SemanticErrorKind::UnexpectedHashTree,
                        element_index,
                        "hashTree appeared where a test element was required",
                    ));
                };
                events.push(SemanticEvent::HashTree(element_id));
                self.decode_hash_tree(element_index, Some(element_id), depth.saturating_add(1))?;
                continue;
            }
            if pending_element.is_some() {
                return Err(self.semantic_error(
                    SemanticErrorKind::Topology,
                    element_index,
                    "test element must alternate with hashTree",
                ));
            }
            let id = self.decode_element(element_index, parent)?;
            events.push(SemanticEvent::Element(id));
            pending_element = Some(id);
        }
        if let Some(pending_element) = pending_element {
            return Err(self.semantic_error(
                SemanticErrorKind::MissingHashTree,
                hash_tree_index,
                format!("test element {pending_element} is not followed by its hashTree companion"),
            ));
        }
        let extensions = extensions_from_events(&events);
        if let Some(parent) = parent {
            self.hash_tree_extensions.insert(parent, extensions);
        } else {
            self.root_hash_tree_extensions = extensions;
        }
        self.hash_tree_events.insert(parent, events);
        Ok(())
    }

    fn decode_element(&mut self, index: usize, parent: Option<NodeId>) -> crate::Result<NodeId> {
        if self.tree.len() >= self.options.limits.max_elements {
            return Err(self.semantic_limit(
                index,
                "element count",
                self.options.limits.max_elements,
            ));
        }
        let node = self.arena.nodes[index].clone();
        let Some(raw_gui) = attr(&node.attributes, "guiclass") else {
            return Err(self.semantic_error(
                SemanticErrorKind::MissingMetadata,
                index,
                "test element is missing guiclass metadata",
            ));
        };
        if raw_gui.is_empty() {
            return Err(self.semantic_error(
                SemanticErrorKind::MissingMetadata,
                index,
                "test element guiclass metadata must not be empty",
            ));
        }
        let Some(raw_testclass) = attr(&node.attributes, "testclass") else {
            return Err(self.semantic_error(
                SemanticErrorKind::MissingMetadata,
                index,
                "test element is missing testclass metadata",
            ));
        };
        if raw_testclass.is_empty() {
            return Err(self.semantic_error(
                SemanticErrorKind::MissingMetadata,
                index,
                "test element testclass metadata must not be empty",
            ));
        }
        let Some(raw_name) = attr(&node.attributes, "testname") else {
            return Err(self.semantic_error(
                SemanticErrorKind::MissingMetadata,
                index,
                "test element is missing testname metadata",
            ));
        };
        if raw_name.is_empty() {
            return Err(self.semantic_error(
                SemanticErrorKind::MissingMetadata,
                index,
                "test element testname metadata must not be empty",
            ));
        }
        let Some(raw_enabled) = attr(&node.attributes, "enabled") else {
            return Err(self.semantic_error(
                SemanticErrorKind::MissingMetadata,
                index,
                "test element is missing enabled metadata",
            ));
        };
        let enabled = match raw_enabled {
            "true" => true,
            "false" => false,
            _ => {
                return Err(self.semantic_error(
                    SemanticErrorKind::InvalidPropertyValue,
                    index,
                    "enabled metadata must be true or false",
                ));
            }
        };

        let original_name = self.decode_legacy(raw_name, index)?;
        if original_name.is_empty() {
            return Err(self.semantic_error(
                SemanticErrorKind::MissingMetadata,
                index,
                "test element testname metadata decodes to an empty value",
            ));
        }
        let (test_class, gui_class) = self.resolve_special_classes(raw_testclass, raw_gui);
        // The serialized element tag is a wire alias, but `testclass` is the
        // authoritative component identity.  A plugin or malformed document
        // must not become executable merely by borrowing a built-in tag.
        let test_class_identity = self.upgraded_class_identity(raw_testclass, raw_gui);
        let tag_class_identity = self.upgraded_class_identity(&node.name, raw_gui);
        let known_test_class = self.registry.aliases.resolve(raw_testclass).is_known()
            || self.registry.aliases.resolve(&test_class).is_known();
        // The testclass attribute is authoritative.  A profile-known class
        // under an unknown/non-matching wire tag is still retained, but must
        // remain opaque: canonicalizing the tag to a built-in alias would
        // silently reinterpret plugin or malformed input.
        let known = known_test_class
            && tag_class_identity
                .as_deref()
                .is_some_and(|tag| Some(tag) == test_class_identity.as_deref());
        let metadata = jmeter_rs_model::ElementMetadata::new(test_class, gui_class, original_name);
        let mut element = TestElement::new(metadata);
        element.set_enabled(enabled);
        let mut source_location = SourceLocation::from_byte_offset(node.span.start as u64)
            .with_line_column(
                position(self.document, node.span.start).line as u32,
                position(self.document, node.span.start).column as u32,
            )
            .map_err(|error| {
                self.semantic_error(
                    SemanticErrorKind::Topology,
                    index,
                    format!("invalid one-based source location: {error}"),
                )
            })?;
        if let Some(source_name) = self.source_name.clone() {
            source_location = source_location.with_source(source_name);
        }
        element.set_source_location(source_location);
        let id = self.tree.insert(parent, element).map_err(|error| {
            Error::semantic(
                SemanticErrorKind::Topology,
                Some(position(self.document, node.span.start)),
                format!("could not allocate semantic node: {error}"),
            )
        })?;
        let info = SemanticElementInfo {
            tag: node.name.clone(),
            extra_attributes: non_special_attributes(
                &node.attributes,
                &["guiclass", "testclass", "testname", "enabled"],
            ),
            original_testclass: raw_testclass.to_owned(),
            original_guiclass: raw_gui.to_owned(),
            original_testname: raw_name.to_owned(),
            opaque: !known,
            span: node.span,
        };
        if !known {
            let raw = self.raw_span(node.span, index)?;
            self.retain_opaque(raw.len(), index)?;
            self.opaque_element_bytes.insert(id, raw);
            self.diagnostics.push(Diagnostic {
                code: "jmx.semantic.unknown_element".to_owned(),
                severity: DiagnosticSeverity::Warning,
                message: "test element is not a profile-matching alias and was retained opaquely"
                    .to_owned(),
                position: Some(position(self.document, node.span.start)),
                node_id: Some(id),
            });
        }
        self.element_info.insert(id, info);
        self.element_items.insert(id, Vec::new());
        let child_indices = self.arena.nodes[index].children.clone();
        for child in child_indices {
            let XmlChild::Element(property_index) = child else {
                self.retain_non_element_child(id, index, child)?;
                continue;
            };
            let tag = self.arena.nodes[property_index].name.clone();
            if tag == "hashTree" {
                return Err(self.semantic_error(
                    SemanticErrorKind::Topology,
                    property_index,
                    "hashTree cannot be nested directly inside a test element",
                ));
            }
            let path = PropertyPath::new(id);
            let decoded = self.decode_property(property_index, id, path)?;
            if let Some((name, value, wire, raw_opaque)) = decoded {
                if let Some((raw, type_name)) = raw_opaque {
                    self.push_element_item(
                        id,
                        ElementItem::Opaque {
                            raw,
                            type_name,
                            occurrence: self.element_items.get(&id).map_or(0, |items| {
                                items
                                    .iter()
                                    .filter(|item| matches!(item, ElementItem::Opaque { .. }))
                                    .count()
                            }),
                        },
                        property_index,
                    )?;
                    continue;
                }
                self.reserve_property(property_index)?;
                let element = self.tree.lookup_mut(id).map_err(|error| {
                    Error::semantic(
                        SemanticErrorKind::Topology,
                        Some(position(self.document, self.arena.nodes[index].span.start)),
                        error.to_string(),
                    )
                })?;
                if element.value().properties.contains(&name) {
                    return Err(self.semantic_error(
                        SemanticErrorKind::DuplicateProperty,
                        property_index,
                        "duplicate property metadata",
                    ));
                }
                element
                    .value_mut()
                    .properties
                    .try_insert(name.clone(), value.clone())
                    .map_err(|error| {
                        Error::semantic(
                            SemanticErrorKind::DuplicateProperty,
                            Some(position(
                                self.document,
                                self.arena.nodes[property_index].span.start,
                            )),
                            error.to_string(),
                        )
                    })?;
                self.property_count = self.property_count.saturating_add(1);
                self.wire_properties
                    .insert(PropertyPath::new(id).child(&name), wire);
                self.original_property_values
                    .insert(PropertyPath::new(id).child(&name), value.clone());
                self.property_spans.insert(
                    PropertyPath::new(id).child(&name),
                    self.arena.nodes[property_index].span,
                );
                self.push_element_item(id, ElementItem::Property(name), property_index)?;
            }
        }
        self.element_snapshots.insert(
            id,
            ElementSnapshot::from_element(self.tree.element(id).map_err(|error| {
                Error::semantic(
                    SemanticErrorKind::Topology,
                    Some(position(self.document, node.span.start)),
                    error.to_string(),
                )
            })?),
        );
        Ok(id)
    }

    /// Decodes the wrapper's ordered children while identifying its one root
    /// `hashTree`.  Element children are rejected here rather than being
    /// silently treated as extensions.
    fn decode_wrapper_events(
        &mut self,
        index: usize,
    ) -> crate::Result<(Vec<SemanticEvent>, Option<usize>)> {
        let mut events = Vec::new();
        let mut root_hash_tree = None;
        for child in self.arena.nodes[index].children.clone() {
            let XmlChild::Element(child_index) = child.clone() else {
                if let Some(event) = self.decode_topology_extension(index, child)? {
                    events.push(event);
                }
                continue;
            };
            if self.arena.nodes[child_index].name != "hashTree" {
                return Err(self.semantic_error(
                    SemanticErrorKind::Topology,
                    child_index,
                    "jmeterTestPlan may contain only one root hashTree child",
                ));
            }
            if root_hash_tree.replace(child_index).is_some() {
                return Err(self.semantic_error(
                    SemanticErrorKind::Topology,
                    child_index,
                    "jmeterTestPlan must contain exactly one root hashTree",
                ));
            }
            events.push(SemanticEvent::RootHashTree);
        }
        Ok((events, root_hash_tree))
    }

    /// Decodes a non-element event in wrapper/hashTree topology. Whitespace
    /// text and CDATA remain formatting. Comments, PIs, and non-whitespace
    /// CDATA retain their exact source bytes in an ordered extension event;
    /// direct text is not part of the JMX topology and is rejected.
    fn decode_topology_extension(
        &mut self,
        parent_index: usize,
        child: XmlChild,
    ) -> crate::Result<Option<SemanticEvent>> {
        match child {
            XmlChild::Text { value, event_index } => {
                if value.chars().all(char::is_whitespace) {
                    Ok(None)
                } else {
                    Err(self.semantic_error(
                        SemanticErrorKind::Topology,
                        parent_index,
                        format!(
                            "non-whitespace text event {event_index} is not valid in wrapper/hashTree topology"
                        ),
                    ))
                }
            }
            XmlChild::CData { value, event_index } => {
                if value.chars().all(char::is_whitespace) {
                    return Ok(None);
                }
                let event = &self.document.events()[event_index];
                let raw = self.raw_span(event.span, parent_index)?;
                self.retain_opaque(raw.len(), parent_index)?;
                Ok(Some(SemanticEvent::Extension(OpaqueValue::new(
                    "xml:cdata",
                    raw,
                ))))
            }
            XmlChild::Other { event_index } => {
                let event = &self.document.events()[event_index];
                let type_name = match &event.kind {
                    EventKind::Comment(_) => "xml:comment",
                    EventKind::ProcessingInstruction(_) => "xml:processing-instruction",
                    _ => "xml:unknown",
                };
                let raw = self.raw_span(event.span, parent_index)?;
                self.retain_opaque(raw.len(), parent_index)?;
                Ok(Some(SemanticEvent::Extension(OpaqueValue::new(
                    type_name, raw,
                ))))
            }
            XmlChild::Element(_) => Ok(None),
        }
    }

    fn resolve_special_classes(&self, raw_testclass: &str, raw_gui: &str) -> (String, String) {
        let test_class_name = self
            .registry
            .aliases
            .resolve(raw_testclass)
            .class_name
            .unwrap_or_else(|| raw_testclass.to_owned());
        let gui_class_name = self
            .registry
            .aliases
            .resolve(raw_gui)
            .class_name
            .unwrap_or_else(|| raw_gui.to_owned());
        let upgraded = if self.options.apply_upgrades {
            self.registry
                .upgrades
                .upgrade_element(&test_class_name, &gui_class_name)
        } else {
            crate::UpgradedElement {
                test_class: test_class_name,
                gui_class: gui_class_name,
                changed: false,
            }
        };
        let test_wire = self
            .registry
            .aliases
            .primary_alias_for_class(&upgraded.test_class)
            .map(str::to_owned)
            .unwrap_or_else(|| {
                if upgraded.changed || raw_testclass.starts_with("org.") {
                    upgraded.test_class.clone()
                } else {
                    raw_testclass.to_owned()
                }
            });
        let gui_wire = self
            .registry
            .aliases
            .primary_alias_for_class(&upgraded.gui_class)
            .map(str::to_owned)
            .unwrap_or_else(|| {
                if upgraded.changed || raw_gui.starts_with("org.") {
                    upgraded.gui_class.clone()
                } else {
                    raw_gui.to_owned()
                }
            });
        (test_wire, gui_wire)
    }

    fn upgraded_class_identity(&self, value: &str, raw_gui: &str) -> Option<String> {
        let class_name = self.registry.aliases.resolve(value).class_name?;
        let gui_name = self
            .registry
            .aliases
            .resolve(raw_gui)
            .class_name
            .unwrap_or_else(|| raw_gui.to_owned());
        if self.options.apply_upgrades {
            Some(
                self.registry
                    .upgrades
                    .upgrade_element(&class_name, &gui_name)
                    .test_class,
            )
        } else {
            Some(class_name)
        }
    }

    fn decode_property(
        &mut self,
        index: usize,
        owner: NodeId,
        base_path: PropertyPath,
    ) -> crate::Result<Option<DecodedProperty>> {
        if base_path.names.len() > self.options.limits.max_property_depth {
            return Err(self.semantic_limit(
                index,
                "nested property depth",
                self.options.limits.max_property_depth,
            ));
        }
        let node = self.arena.nodes[index].clone();
        let tag = node.name.clone();
        let Some(raw_name) = attr(&node.attributes, "name") else {
            if tag == "objProp" {
                let (name, value_child, shape) = self.decode_object_property_shape(index)?;
                let path = base_path.child_occurrence(&name, 0);
                let value = self.decode_object_property(index, path.clone(), Some(value_child))?;
                self.object_property_shapes.insert(path, shape);
                return Ok(Some((
                    name,
                    value,
                    WireProperty {
                        tag,
                        extra_attributes: non_special_attributes(&node.attributes, &[]),
                        raw_xml: None,
                    },
                    None,
                )));
            }
            if is_property_tag(&tag) {
                return Err(self.semantic_error(
                    SemanticErrorKind::InvalidProperty,
                    index,
                    "property node is missing required name metadata",
                ));
            }
            let raw = self.raw_span(node.span, index)?;
            self.retain_opaque(raw.len(), index)?;
            let type_name = format!("xml:{tag}");
            let tree_node = match self.tree.lookup_mut(owner) {
                Ok(node) => node,
                Err(error) => {
                    return Err(self.semantic_error(
                        SemanticErrorKind::Topology,
                        index,
                        error.to_string(),
                    ));
                }
            };
            tree_node
                .value_mut()
                .push_opaque_extension(OpaqueValue::new(type_name.clone(), raw.clone()));
            return Ok(Some((
                String::new(),
                PropertyValue::Null,
                WireProperty {
                    tag,
                    extra_attributes: Vec::new(),
                    raw_xml: Some(raw.clone()),
                },
                Some((raw, type_name)),
            )));
        };
        let decoded_name = self.decode_legacy(raw_name, index)?;
        let class_name = self
            .tree
            .element(owner)
            .ok()
            .and_then(|element| {
                self.registry
                    .aliases
                    .resolve(element.test_class())
                    .class_name
            })
            .unwrap_or_else(|| {
                self.tree
                    .element(owner)
                    .map_or_else(|_| String::new(), |element| element.test_class().to_owned())
            });
        let upgraded_name = if self.options.apply_upgrades {
            self.registry
                .upgrades
                .upgrade_property_name(&class_name, &decoded_name)
        } else {
            Some(decoded_name.clone())
        };
        let Some(name) = upgraded_name else {
            let raw = self.raw_span(node.span, index)?;
            self.retain_opaque(raw.len(), index)?;
            let occurrence_key = (owner, decoded_name.clone());
            let occurrence = self
                .dropped_property_occurrences
                .get(&occurrence_key)
                .copied()
                .unwrap_or(0);
            let next_occurrence = occurrence.checked_add(1).ok_or_else(|| {
                self.semantic_limit(index, "dropped property occurrence count", usize::MAX)
            })?;
            self.dropped_property_occurrences
                .insert(occurrence_key, next_occurrence);
            self.dropped_property_bytes.insert(
                PropertyPath::new(owner).child_occurrence(&decoded_name, occurrence),
                raw,
            );
            self.diagnostics.push(Diagnostic {
                code: "jmx.semantic.upgraded_property_dropped".to_owned(),
                severity: DiagnosticSeverity::Info,
                message: "a source property was removed by the pinned upgrade table".to_owned(),
                position: Some(position(self.document, node.span.start)),
                node_id: Some(owner),
            });
            return Ok(None);
        };
        let path = base_path.child_occurrence(&name, 0);
        let mut wire = WireProperty {
            tag: tag.clone(),
            extra_attributes: non_special_attributes(&node.attributes, &["name"]),
            raw_xml: None,
        };
        if !is_property_tag(&tag) {
            let raw = self.raw_span(node.span, index)?;
            self.retain_opaque(raw.len(), index)?;
            let payload = self
                .text_content_bytes(index)
                .unwrap_or_else(|_| raw.clone());
            let value = PropertyValue::Opaque(OpaqueValue::new(tag.clone(), payload));
            let wire = WireProperty {
                tag,
                extra_attributes: non_special_attributes(&node.attributes, &["name"]),
                raw_xml: Some(raw),
            };
            return Ok(Some((name, value, wire, None)));
        }
        let value = self.decode_property_value(index, owner, path, &tag)?;
        let value = self.apply_value_upgrade(&class_name, &name, value);
        if self.has_lexical_extension(index) {
            let raw = self.raw_span(node.span, index)?;
            self.retain_opaque(raw.len(), index)?;
            wire.raw_xml = Some(raw);
        }
        Ok(Some((name, value, wire, None)))
    }

    fn apply_value_upgrade(
        &self,
        class_name: &str,
        property: &str,
        value: PropertyValue,
    ) -> PropertyValue {
        if !self.options.apply_upgrades {
            return value;
        }
        match value {
            PropertyValue::String(text) => PropertyValue::String(
                self.registry
                    .upgrades
                    .upgrade_property_value(class_name, property, &text),
            ),
            other => other,
        }
    }

    fn decode_property_value(
        &mut self,
        index: usize,
        owner: NodeId,
        path: PropertyPath,
        tag: &str,
    ) -> crate::Result<PropertyValue> {
        let nested_depth = path.names.len().saturating_sub(1);
        if nested_depth > self.options.limits.max_property_depth {
            return Err(self.semantic_limit(
                index,
                "nested property depth",
                self.options.limits.max_property_depth,
            ));
        }
        match tag {
            "stringProp" => Ok(PropertyValue::String(
                self.decode_legacy(&self.text_content(index)?, index)?,
            )),
            "boolProp" => {
                let text = self.text_content(index)?;
                match text.as_str() {
                    "true" => Ok(PropertyValue::Boolean(true)),
                    "false" => Ok(PropertyValue::Boolean(false)),
                    _ => Err(self.semantic_error(
                        SemanticErrorKind::InvalidPropertyValue,
                        index,
                        "boolProp value must be true or false",
                    )),
                }
            }
            "intProp" => {
                let text = self.text_content(index)?;
                let value = text.trim().parse::<i32>().map_err(|_| {
                    self.semantic_error(
                        SemanticErrorKind::InvalidPropertyValue,
                        index,
                        "intProp value is not a signed 32-bit integer",
                    )
                })?;
                Ok(PropertyValue::Integer(value))
            }
            "longProp" => {
                let text = self.text_content(index)?;
                let value = text.trim().parse::<i64>().map_err(|_| {
                    self.semantic_error(
                        SemanticErrorKind::InvalidPropertyValue,
                        index,
                        "longProp value is not a signed 64-bit integer",
                    )
                })?;
                Ok(PropertyValue::Long(value))
            }
            "floatProp" => {
                let text = self.text_content(index)?;
                let value = parse_java_f32(text.trim()).ok_or_else(|| {
                    self.semantic_error(
                        SemanticErrorKind::InvalidPropertyValue,
                        index,
                        "floatProp value is not a 32-bit floating-point number",
                    )
                })?;
                Ok(PropertyValue::Float(value))
            }
            "doubleProp" => {
                let text = self.text_content(index)?;
                let value = parse_java_f64(text.trim()).ok_or_else(|| {
                    self.semantic_error(
                        SemanticErrorKind::InvalidPropertyValue,
                        index,
                        "doubleProp value is not a floating-point number",
                    )
                })?;
                Ok(PropertyValue::Double(value))
            }
            "collectionProp" => self.decode_multi_property(index, owner, path, false),
            "mapProp" => self.decode_multi_property(index, owner, path, true),
            "elementProp" => self.decode_element_property(index, owner, path),
            "objProp" => self.decode_object_property(index, path, None),
            _ => Err(self.semantic_error(
                SemanticErrorKind::InvalidProperty,
                index,
                "unsupported property node",
            )),
        }
    }

    fn decode_multi_property(
        &mut self,
        index: usize,
        owner: NodeId,
        path: PropertyPath,
        is_map: bool,
    ) -> crate::Result<PropertyValue> {
        let mut entries: Vec<PropertyEntry> = Vec::new();
        let mut positional_values = Vec::new();
        let mut saw_named = false;
        let mut saw_positional = false;
        let children = self.arena.nodes[index].children.clone();
        let mut child_position = 0;
        for child in children {
            let XmlChild::Element(child_index) = child else {
                self.require_whitespace_child(index, child)?;
                continue;
            };
            let position = child_position;
            child_position += 1;
            let raw_child_name = attr(&self.arena.nodes[child_index].attributes, "name");
            let child_name = if let Some(raw_child_name) = raw_child_name {
                if saw_positional && !is_map {
                    return Err(self.semantic_error(
                        SemanticErrorKind::InvalidProperty,
                        child_index,
                        "collectionProp cannot mix named and positional children",
                    ));
                }
                saw_named = true;
                self.decode_legacy(raw_child_name, child_index)?
            } else {
                if is_map {
                    return Err(self.semantic_error(
                        SemanticErrorKind::InvalidProperty,
                        child_index,
                        "mapProp child is missing name",
                    ));
                }
                if saw_named {
                    return Err(self.semantic_error(
                        SemanticErrorKind::InvalidProperty,
                        child_index,
                        "collectionProp cannot mix named and positional children",
                    ));
                }
                saw_positional = true;
                position.to_string()
            };
            let occurrence = if saw_positional {
                position
            } else {
                entries
                    .iter()
                    .filter(|entry| entry.name == child_name)
                    .count()
            };
            let child_path = path.child_occurrence(&child_name, occurrence);
            let child_tag = self.arena.nodes[child_index].name.clone();
            self.reserve_property(child_index)?;
            if !is_property_tag(&child_tag) {
                let raw = self.raw_span(self.arena.nodes[child_index].span, child_index)?;
                self.retain_opaque(raw.len(), child_index)?;
                self.wire_properties.insert(
                    child_path.clone(),
                    WireProperty {
                        tag: child_tag.clone(),
                        extra_attributes: non_special_attributes(
                            &self.arena.nodes[child_index].attributes,
                            &["name"],
                        ),
                        raw_xml: Some(raw.clone()),
                    },
                );
                self.property_spans
                    .insert(child_path.clone(), self.arena.nodes[child_index].span);
                let value = PropertyValue::Opaque(OpaqueValue::new(child_tag, raw));
                self.original_property_values
                    .insert(child_path, value.clone());
                if saw_positional {
                    positional_values.push(value.clone());
                }
                entries.push(PropertyEntry::new(child_name, value));
                self.property_count = self.property_count.saturating_add(1);
                continue;
            }
            let mut wire = WireProperty {
                tag: child_tag.clone(),
                extra_attributes: non_special_attributes(
                    &self.arena.nodes[child_index].attributes,
                    &["name"],
                ),
                raw_xml: None,
            };
            let value = if child_tag == "elementProp" && raw_child_name.is_none() {
                self.decode_element_property_named(
                    child_index,
                    owner,
                    child_path.clone(),
                    Some(child_name.clone()),
                )?
            } else {
                self.decode_property_value(child_index, owner, child_path.clone(), &child_tag)?
            };
            if self.has_lexical_extension(child_index) {
                let raw = self.raw_span(self.arena.nodes[child_index].span, child_index)?;
                self.retain_opaque(raw.len(), child_index)?;
                wire.raw_xml = Some(raw);
            }
            self.wire_properties.insert(child_path.clone(), wire);
            self.original_property_values
                .insert(child_path.clone(), value.clone());
            self.property_spans
                .insert(child_path, self.arena.nodes[child_index].span);
            if saw_positional {
                positional_values.push(value.clone());
            }
            entries.push(PropertyEntry::new(child_name, value));
            self.property_count = self.property_count.saturating_add(1);
        }
        if is_map {
            Ok(PropertyValue::Map(entries))
        } else if saw_positional || entries.is_empty() {
            Ok(PropertyValue::Collection(positional_values))
        } else {
            Ok(PropertyValue::NamedCollection(entries))
        }
    }

    fn decode_element_property(
        &mut self,
        index: usize,
        owner: NodeId,
        path: PropertyPath,
    ) -> crate::Result<PropertyValue> {
        self.decode_element_property_named(index, owner, path, None)
    }

    fn decode_element_property_named(
        &mut self,
        index: usize,
        owner: NodeId,
        path: PropertyPath,
        positional_name: Option<String>,
    ) -> crate::Result<PropertyValue> {
        let node = self.arena.nodes[index].clone();
        let name = if let Some(name) = attr(&node.attributes, "name") {
            self.decode_legacy(name, index)?
        } else if let Some(name) = positional_name {
            name
        } else {
            return Err(self.semantic_error(
                SemanticErrorKind::InvalidProperty,
                index,
                "elementProp is missing name",
            ));
        };
        let class_name = attr(&node.attributes, "elementType").map(str::to_owned);
        let mut nested = ElementProperty::new(name.clone());
        if let Some(class_name) = class_name {
            nested = nested.with_class_name(class_name);
        }
        let nested_meta = NestedMetadata {
            extra_attributes: non_special_attributes(&node.attributes, &["name", "elementType"]),
            items: Vec::new(),
        };
        self.nested_metadata.insert(path.clone(), nested_meta);
        let children = node.children.clone();
        for child in children {
            let XmlChild::Element(child_index) = child else {
                self.require_whitespace_child(index, child)?;
                continue;
            };
            let child_tag = self.arena.nodes[child_index].name.clone();
            if !is_property_tag(&child_tag) {
                let raw = self.raw_span(self.arena.nodes[child_index].span, child_index)?;
                self.retain_opaque(raw.len(), child_index)?;
                nested.push_opaque(OpaqueValue::new(child_tag.clone(), raw.clone()));
                if let Some(meta) = self.nested_metadata.get_mut(&path) {
                    meta.items.push(NestedItem::Opaque {
                        raw,
                        type_name: child_tag,
                        occurrence: meta
                            .items
                            .iter()
                            .filter(|item| matches!(item, NestedItem::Opaque { .. }))
                            .count(),
                    });
                }
                continue;
            }
            let Some(raw_child_name) = attr(&self.arena.nodes[child_index].attributes, "name")
            else {
                return Err(self.semantic_error(
                    SemanticErrorKind::InvalidProperty,
                    child_index,
                    "nested property is missing name",
                ));
            };
            let child_name = self.decode_legacy(raw_child_name, child_index)?;
            let child_path = path.child_occurrence(&child_name, 0);
            self.reserve_property(child_index)?;
            let value =
                self.decode_property_value(child_index, owner, child_path.clone(), &child_tag)?;
            let mut wire = WireProperty {
                tag: child_tag,
                extra_attributes: non_special_attributes(
                    &self.arena.nodes[child_index].attributes,
                    &["name"],
                ),
                raw_xml: None,
            };
            if self.has_lexical_extension(child_index) {
                let raw = self.raw_span(self.arena.nodes[child_index].span, child_index)?;
                self.retain_opaque(raw.len(), child_index)?;
                wire.raw_xml = Some(raw);
            }
            if nested.properties.contains(&child_name) {
                return Err(self.semantic_error(
                    SemanticErrorKind::DuplicateProperty,
                    child_index,
                    "duplicate nested property metadata",
                ));
            }
            nested
                .properties
                .try_insert(child_name.clone(), value.clone())
                .map_err(|error| {
                    self.semantic_error(
                        SemanticErrorKind::DuplicateProperty,
                        child_index,
                        error.to_string(),
                    )
                })?;
            if let Some(meta) = self.nested_metadata.get_mut(&path) {
                meta.items.push(NestedItem::Property(child_name.clone()));
            }
            self.wire_properties.insert(child_path.clone(), wire);
            self.original_property_values
                .insert(child_path.clone(), value.clone());
            self.property_spans
                .insert(child_path, self.arena.nodes[child_index].span);
            self.property_count = self.property_count.saturating_add(1);
        }
        Ok(PropertyValue::Element(nested))
    }

    fn decode_object_property_shape(
        &self,
        index: usize,
    ) -> crate::Result<(String, usize, ObjectPropertyShape)> {
        let mut name = None;
        let mut value = None;
        let mut children = Vec::new();
        for child in &self.arena.nodes[index].children {
            let XmlChild::Element(child_index) = child else {
                self.require_whitespace_child(index, clone_xml_child(child))?;
                continue;
            };
            match self.arena.nodes[*child_index].name.as_str() {
                "name" => {
                    if name.replace(*child_index).is_some() {
                        return Err(self.semantic_error(
                            SemanticErrorKind::DuplicateProperty,
                            *child_index,
                            "objProp contains more than one name child",
                        ));
                    }
                    children.push(ObjectPropertyChild::Name);
                }
                "value" => {
                    if value.replace(*child_index).is_some() {
                        return Err(self.semantic_error(
                            SemanticErrorKind::DuplicateProperty,
                            *child_index,
                            "objProp contains more than one value child",
                        ));
                    }
                    children.push(ObjectPropertyChild::Value);
                }
                _ => {
                    return Err(self.semantic_error(
                        SemanticErrorKind::InvalidProperty,
                        *child_index,
                        "objProp child must be name or value",
                    ));
                }
            }
        }
        let Some(name_index) = name else {
            return Err(self.semantic_error(
                SemanticErrorKind::InvalidProperty,
                index,
                "objProp is missing required name child",
            ));
        };
        let Some(value_index) = value else {
            return Err(self.semantic_error(
                SemanticErrorKind::InvalidProperty,
                index,
                "objProp is missing required value child",
            ));
        };
        let name_node = &self.arena.nodes[name_index];
        for child in &name_node.children {
            match child {
                XmlChild::Text { .. } => {}
                XmlChild::CData { .. } => {
                    return Err(self.semantic_error(
                        SemanticErrorKind::Unsupported,
                        name_index,
                        "CDATA is not representable in an objProp name",
                    ));
                }
                XmlChild::Other { .. } => {
                    return Err(self.semantic_error(
                        SemanticErrorKind::Unsupported,
                        name_index,
                        "comment/processing-instruction is not representable in an objProp name",
                    ));
                }
                XmlChild::Element(_) => {
                    return Err(self.semantic_error(
                        SemanticErrorKind::InvalidProperty,
                        name_index,
                        "objProp name child must contain text only",
                    ));
                }
            }
        }
        let name = self.decode_legacy(&self.text_content(name_index)?, name_index)?;
        Ok((
            name,
            value_index,
            ObjectPropertyShape {
                children,
                name_attributes: name_node.attributes.clone(),
            },
        ))
    }

    fn decode_object_property(
        &mut self,
        index: usize,
        path: PropertyPath,
        value_child: Option<usize>,
    ) -> crate::Result<PropertyValue> {
        // Only whitespace text/CDATA is formatting around the structural
        // value child.  Comments, processing instructions, and direct
        // non-whitespace text have no objProp slot, so reject them rather
        // than silently dropping them or inventing an xml:text extension.
        let node_children = self.arena.nodes[index].children.clone();
        for child in &node_children {
            if value_child.is_some_and(
                |child_index| matches!(child, XmlChild::Element(index) if *index == child_index),
            ) {
                continue;
            }
            self.require_whitespace_child(index, clone_xml_child(child))?;
        }
        let children = node_children
            .iter()
            .filter_map(|child| match child {
                XmlChild::Element(child_index)
                    if value_child.is_none_or(|value| value == *child_index) =>
                {
                    Some(*child_index)
                }
                XmlChild::Text { .. } | XmlChild::CData { .. } | XmlChild::Other { .. } => None,
                XmlChild::Element(_) => None,
            })
            .collect::<Vec<_>>();
        if children.is_empty() {
            return Ok(PropertyValue::Null);
        }
        if children.len() != 1 || self.arena.nodes[children[0]].name != "value" {
            return Err(self.semantic_error(
                SemanticErrorKind::InvalidProperty,
                index,
                "objProp must contain at most one value child",
            ));
        }
        let value_index = children[0];
        let value_node = self.arena.nodes[value_index].clone();
        let value_attributes = value_node.attributes.clone();
        // Keep class/type absence distinct from an explicitly empty value in
        // the model and wire metadata. `object_value_metadata` below retains
        // the exact attribute list for unchanged source values.
        let class_name = attr(&value_node.attributes, "class")
            .or_else(|| attr(&value_node.attributes, "type"))
            .map(str::to_owned);
        let attributes = value_attributes
            .iter()
            .map(|attribute| ObjectPropertyAttribute::new(&attribute.name, &attribute.value))
            .collect::<Vec<_>>();
        let has_nested_payload = value_node
            .children
            .iter()
            .any(|child| matches!(child, XmlChild::Element(_)));
        let object = if has_nested_payload {
            let raw = self.raw_children_bytes(value_index)?;
            self.retain_opaque(raw.len(), value_index)?;
            jmeter_rs_model::ObjectProperty::opaque_xml_with_optional_class_name(
                class_name, raw, attributes,
            )
        } else {
            for child in &value_node.children {
                match child {
                    XmlChild::Text { .. } => {}
                    XmlChild::CData { .. } => {
                        return Err(self.semantic_error(
                            SemanticErrorKind::Unsupported,
                            value_index,
                            "CDATA is not representable inside a text-valued objProp value",
                        ));
                    }
                    XmlChild::Other { .. } => {
                        return Err(self.semantic_error(
                            SemanticErrorKind::Unsupported,
                            value_index,
                            "comment/processing-instruction is not representable inside a text-valued objProp value",
                        ));
                    }
                    XmlChild::Element(_) => {
                        return Err(self.semantic_error(
                            SemanticErrorKind::InvalidProperty,
                            value_index,
                            "object property value unexpectedly contains a nested element",
                        ));
                    }
                }
            }
            let payload = self.text_content_bytes(value_index)?;
            self.retain_opaque(payload.len(), value_index)?;
            jmeter_rs_model::ObjectProperty::from_optional_class_name(class_name, payload)
                .with_attributes(attributes)
        };
        self.object_value_metadata.insert(
            path,
            ObjectValueMetadata {
                attributes: value_attributes,
            },
        );
        Ok(PropertyValue::Object(object))
    }

    fn retain_non_element_child(
        &mut self,
        owner: NodeId,
        parent_index: usize,
        child: XmlChild,
    ) -> crate::Result<()> {
        match child {
            XmlChild::Text { value, .. } | XmlChild::CData { value, .. }
                if value.chars().all(char::is_whitespace) =>
            {
                Ok(())
            }
            XmlChild::Text { .. } | XmlChild::CData { .. } => Err(self.semantic_error(
                SemanticErrorKind::Unsupported,
                parent_index,
                "direct non-whitespace text is not representable in a test element",
            )),
            XmlChild::Other { event_index } => {
                let span = self.document.events()[event_index].span;
                let raw = self.raw_span(span, parent_index)?;
                self.retain_opaque(raw.len(), parent_index)?;
                let type_name = match &self.document.events()[event_index].kind {
                    EventKind::Comment(_) => "xml:comment",
                    EventKind::ProcessingInstruction(_) => "xml:processing-instruction",
                    _ => "xml:unknown",
                };
                let tree_node = match self.tree.lookup_mut(owner) {
                    Ok(node) => node,
                    Err(error) => {
                        return Err(self.semantic_error(
                            SemanticErrorKind::Topology,
                            parent_index,
                            error.to_string(),
                        ));
                    }
                };
                tree_node
                    .value_mut()
                    .push_opaque_extension(OpaqueValue::new(type_name, raw.clone()));
                let occurrence = self.element_items.get(&owner).map_or(0, |items| {
                    items
                        .iter()
                        .filter(|item| matches!(item, ElementItem::Opaque { .. }))
                        .count()
                });
                self.push_element_item(
                    owner,
                    ElementItem::Opaque {
                        raw,
                        type_name: type_name.to_owned(),
                        occurrence,
                    },
                    parent_index,
                )?;
                Ok(())
            }
            XmlChild::Element(_) => Ok(()),
        }
    }

    /// Validates a non-element child in a structural property container.
    ///
    /// Whitespace-only text and CDATA are formatting and are intentionally
    /// normalized away by semantic canonical encoding for known structural
    /// and property containers.  Non-whitespace text and CDATA, comments,
    /// and processing instructions are never discarded: callers either
    /// retain them in an explicit opaque slot or receive a typed
    /// unsupported/invalid-property error.  Text-valued `objProp` payloads
    /// apply the stricter rule in `decode_object_property`, where
    /// CDATA/comments/PIs are rejected instead of being normalized.
    fn require_whitespace_child(&self, parent: usize, child: XmlChild) -> crate::Result<()> {
        match child {
            XmlChild::Text { value, .. } | XmlChild::CData { value, .. }
                if value.chars().all(char::is_whitespace) =>
            {
                Ok(())
            }
            XmlChild::Text { .. } | XmlChild::CData { .. } => Err(self.semantic_error(
                SemanticErrorKind::InvalidProperty,
                parent,
                "non-whitespace text is not valid in a structural property",
            )),
            XmlChild::Other { .. } => Err(self.semantic_error(
                SemanticErrorKind::Unsupported,
                parent,
                "comment/processing-instruction is not representable inside a structural property",
            )),
            XmlChild::Element(_) => Ok(()),
        }
    }

    fn text_content(&self, index: usize) -> crate::Result<String> {
        let mut value = String::new();
        for child in &self.arena.nodes[index].children {
            match child {
                XmlChild::Text { value: text, .. } | XmlChild::CData { value: text, .. } => {
                    value.push_str(text);
                }
                XmlChild::Other { .. } => {}
                XmlChild::Element(_) => {
                    return Err(self.semantic_error(
                        SemanticErrorKind::InvalidProperty,
                        index,
                        "scalar property contains a nested element",
                    ));
                }
            }
        }
        Ok(value)
    }

    fn text_content_bytes(&self, index: usize) -> crate::Result<Vec<u8>> {
        let mut value = Vec::new();
        for child in &self.arena.nodes[index].children {
            match child {
                XmlChild::Text { value: text, .. } | XmlChild::CData { value: text, .. } => {
                    value.extend_from_slice(text.as_bytes());
                }
                XmlChild::Other { .. } => {}
                XmlChild::Element(_) => {
                    return Err(self.semantic_error(
                        SemanticErrorKind::InvalidProperty,
                        index,
                        "object property value contains a nested element",
                    ));
                }
            }
        }
        Ok(value)
    }

    fn raw_children_bytes(&self, index: usize) -> crate::Result<Vec<u8>> {
        let mut value = Vec::new();
        for child in &self.arena.nodes[index].children {
            let span = match child {
                XmlChild::Element(child_index) => self.arena.nodes[*child_index].span,
                XmlChild::Text { event_index, .. }
                | XmlChild::CData { event_index, .. }
                | XmlChild::Other { event_index } => self.document.events()[*event_index].span,
            };
            let bytes = self.raw_span(span, index)?;
            value.extend_from_slice(&bytes);
        }
        Ok(value)
    }

    fn has_lexical_extension(&self, index: usize) -> bool {
        self.arena.nodes[index]
            .children
            .iter()
            .any(|child| match child {
                // Whitespace-only CDATA in a known structural/property
                // container is formatting and is normalized by the
                // canonical writer.  Non-whitespace CDATA is retained as a
                // lexical span; comments/PIs are always retained as opaque
                // raw XML.  Unknown elements/properties use their full raw
                // spans regardless of content.
                XmlChild::CData { value, .. } => !value.chars().all(char::is_whitespace),
                XmlChild::Other { .. } => true,
                XmlChild::Element(_) | XmlChild::Text { .. } => false,
            })
    }

    fn raw_span(&self, span: Span, index: usize) -> crate::Result<Vec<u8>> {
        self.document
            .span_bytes(span)
            .map(ToOwned::to_owned)
            .ok_or_else(|| {
                self.semantic_error(
                    SemanticErrorKind::InvalidRoot,
                    index,
                    "semantic span is outside the source document",
                )
            })
    }

    /// Charges one distinct opaque payload slot owned by the semantic
    /// document.  Callers invoke this exactly once before storing that slot;
    /// overlapping source spans are intentionally allowed when the parent and
    /// child are independently retained, while auxiliary copies/indexes for
    /// one slot are not charged again.
    fn retain_opaque(&mut self, bytes: usize, index: usize) -> crate::Result<()> {
        let observed = self.opaque_storage_bytes.saturating_add(bytes);
        if observed > self.options.limits.max_opaque_bytes {
            return Err(self.semantic_limit(
                index,
                "opaque extension bytes",
                self.options.limits.max_opaque_bytes,
            ));
        }
        self.opaque_storage_bytes = observed;
        Ok(())
    }

    fn decode_legacy(&self, value: &str, index: usize) -> crate::Result<String> {
        if self.root.version() != Some("1.0") {
            return Ok(value.to_owned());
        }
        percent_decode(value).map_err(|_message| {
            self.semantic_error(
                SemanticErrorKind::InvalidPropertyValue,
                index,
                "legacy version-1.0 URL value is invalid",
            )
        })
    }

    fn semantic_error(
        &self,
        kind: SemanticErrorKind,
        index: usize,
        message: impl Into<String>,
    ) -> Error {
        let position = self
            .arena
            .nodes
            .get(index)
            .map(|node| position(self.document, node.span.start));
        Error::semantic(kind, position, message)
    }

    fn semantic_limit(&self, index: usize, what: &str, limit: usize) -> Error {
        self.semantic_error(
            SemanticErrorKind::Limit,
            index,
            format!("{what} exceeded configured limit {limit}"),
        )
    }

    fn reserve_property(&self, index: usize) -> crate::Result<()> {
        if self.property_count >= self.options.limits.max_properties {
            return Err(self.semantic_limit(
                index,
                "property count",
                self.options.limits.max_properties,
            ));
        }
        Ok(())
    }

    fn push_element_item(
        &mut self,
        id: NodeId,
        item: ElementItem,
        index: usize,
    ) -> crate::Result<()> {
        let Some(items) = self.element_items.get_mut(&id) else {
            return Err(self.semantic_error(
                SemanticErrorKind::Topology,
                index,
                format!("element {id} has no wire item list"),
            ));
        };
        items.push(item);
        Ok(())
    }
}

fn clone_xml_child(child: &XmlChild) -> XmlChild {
    match child {
        XmlChild::Element(index) => XmlChild::Element(*index),
        XmlChild::Text { value, event_index } => XmlChild::Text {
            value: value.clone(),
            event_index: *event_index,
        },
        XmlChild::CData { value, event_index } => XmlChild::CData {
            value: value.clone(),
            event_index: *event_index,
        },
        XmlChild::Other { event_index } => XmlChild::Other {
            event_index: *event_index,
        },
    }
}

fn extensions_from_events(events: &[SemanticEvent]) -> Vec<OpaqueValue> {
    events
        .iter()
        .filter_map(|event| match event {
            SemanticEvent::Extension(extension) => Some(extension.clone()),
            SemanticEvent::Element(_)
            | SemanticEvent::HashTree(_)
            | SemanticEvent::RootHashTree => None,
        })
        .collect()
}

fn is_property_tag(tag: &str) -> bool {
    matches!(
        tag,
        "stringProp"
            | "boolProp"
            | "intProp"
            | "longProp"
            | "floatProp"
            | "doubleProp"
            | "collectionProp"
            | "mapProp"
            | "elementProp"
            | "objProp"
    )
}

fn percent_decode(value: &str) -> std::result::Result<String, &'static str> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => output.push(b' '),
            b'%' if index + 2 < bytes.len() => {
                let high = hex_digit(bytes[index + 1]).ok_or("invalid percent escape")?;
                let low = hex_digit(bytes[index + 2]).ok_or("invalid percent escape")?;
                output.push((high << 4) | low);
                index += 2;
            }
            b'%' => return Err("truncated percent escape"),
            byte => output.push(byte),
        }
        index += 1;
    }
    String::from_utf8(output).map_err(|_| "decoded value is not UTF-8")
}

/// Encodes the UTF-8 application/x-www-form-urlencoded representation used by
/// JMeter's legacy SaveService 1.0 values.  This intentionally mirrors the
/// decoder above: spaces become `+`, while all other bytes outside the Java
/// URL-encoder safe set use uppercase percent escapes.
fn percent_encode(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'*' => {
                output.push(char::from(*byte))
            }
            b' ' => output.push('+'),
            byte => {
                output.push('%');
                output.push(char::from(HEX[usize::from(*byte >> 4)]));
                output.push(char::from(HEX[usize::from(*byte & 0x0F)]));
            }
        }
    }
    output
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Java's `Float.toString`/`Double.toString` spell non-finite values as
/// `NaN`, `Infinity`, and `-Infinity`.  Rust's parser accepts different
/// spellings on some toolchains, so decode the Java forms explicitly and do
/// not broaden the wire vocabulary accidentally.
fn parse_java_f32(value: &str) -> Option<f32> {
    match value {
        "NaN" => Some(f32::NAN),
        "Infinity" | "+Infinity" => Some(f32::INFINITY),
        "-Infinity" => Some(f32::NEG_INFINITY),
        _ => value.parse().ok().filter(|parsed: &f32| parsed.is_finite()),
    }
}

fn parse_java_f64(value: &str) -> Option<f64> {
    match value {
        "NaN" => Some(f64::NAN),
        "Infinity" | "+Infinity" => Some(f64::INFINITY),
        "-Infinity" => Some(f64::NEG_INFINITY),
        _ => value.parse().ok().filter(|parsed: &f64| parsed.is_finite()),
    }
}

struct Encoder<'a, W: Write> {
    document: &'a SemanticDocument,
    writer: &'a mut W,
    nodes_written: usize,
    entries_written: usize,
    metadata_written: usize,
    metadata_bytes: usize,
    opaque_bytes_written: usize,
    output_bytes: usize,
}

// Keep recursive model traversal bounded even when a caller constructs a
// document without going through the parser's matching limits.  The semantic
// tree and nested property values share this conservative structural ceiling.
const MAX_ENCODER_DEPTH: usize = 64;
const MAX_ENCODER_NODES: usize = 100_000;
const MAX_ENCODER_OPAQUE_BYTES: usize = 8 * 1024 * 1024;
const MAX_ENCODER_ENTRIES: usize = 500_000;
const MAX_ENCODER_METADATA: usize = 1_000_000;
const MAX_ENCODER_METADATA_BYTES: usize = 16 * 1024 * 1024;
// Keep successful canonical output within the parser's default retained-source
// bound. A source edit whose escaping would exceed this bound fails with a
// typed encoder limit instead of producing output the default decoder cannot
// accept.
const MAX_ENCODER_OUTPUT_BYTES: usize = 8 * 1024 * 1024;

fn encoder_validation_limits() -> jmeter_rs_model::ValidationLimits {
    jmeter_rs_model::ValidationLimits {
        max_nodes: MAX_ENCODER_NODES,
        max_tree_depth: MAX_ENCODER_DEPTH,
        max_properties: MAX_ENCODER_ENTRIES,
        max_property_depth: MAX_ENCODER_DEPTH,
        max_opaque_bytes: MAX_ENCODER_OPAQUE_BYTES,
        max_string_bytes: MAX_ENCODER_METADATA_BYTES,
    }
}

fn map_encoder_validation_error(error: jmeter_rs_model::ModelError) -> Error {
    match error {
        jmeter_rs_model::ModelError::Validation(
            jmeter_rs_model::ModelValidationError::LimitExceeded { kind, .. },
        ) => Error::semantic(
            SemanticErrorKind::Limit,
            None,
            format!("semantic encoder validation exceeded {}", kind.code()),
        ),
        jmeter_rs_model::ModelError::Validation(
            jmeter_rs_model::ModelValidationError::EmptyMetadata { .. },
        ) => Error::semantic(
            SemanticErrorKind::MissingMetadata,
            None,
            "element metadata is incomplete during canonical encoding",
        ),
        _ => Error::semantic(
            SemanticErrorKind::Topology,
            None,
            "cannot encode invalid semantic model",
        ),
    }
}

fn bounded_preorder_ids(tree: &ElementTree, max_nodes: usize) -> crate::Result<Vec<NodeId>> {
    tree.preorder_ids_bounded(max_nodes).map_err(|error| {
        Error::semantic(
            SemanticErrorKind::Limit,
            None,
            format!("semantic tree traversal exceeded node limit {max_nodes}: {error}"),
        )
    })
}

impl<'a, W: Write> Encoder<'a, W> {
    fn new(document: &'a SemanticDocument, writer: &'a mut W) -> Self {
        Self {
            document,
            writer,
            nodes_written: 0,
            entries_written: 0,
            metadata_written: 0,
            metadata_bytes: 0,
            opaque_bytes_written: 0,
            output_bytes: 0,
        }
    }

    fn write_document(&mut self) -> crate::Result<()> {
        self.validate_document()?;
        self.write_raw(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")?;
        self.write_extensions(0, &self.document.leading_extensions)?;
        self.write_indent(0)?;
        self.write_raw(b"<")?;
        self.write_name(&self.document.root.name)?;
        if self.document.root.attributes.is_empty() {
            self.write_attribute("version", "1.2")?;
            self.write_attribute("properties", "5.0")?;
            self.write_attribute("jmeter", "5.6.3")?;
        } else {
            self.write_attributes(&self.document.root.attributes, &[])?;
        }
        self.write_raw(b">\n")?;
        if self.document.root_events.is_empty() {
            self.write_extensions(1, &self.document.root_extensions)?;
            self.write_root_hash_tree(1)?;
        } else {
            let mut root_hash_tree_seen = false;
            for event in self.document.root_events.clone() {
                match event {
                    SemanticEvent::Extension(extension) => {
                        self.write_extensions(1, std::slice::from_ref(&extension))?;
                    }
                    SemanticEvent::RootHashTree => {
                        if root_hash_tree_seen {
                            return Err(Error::semantic(
                                SemanticErrorKind::Topology,
                                None,
                                "ordered wrapper event stream contains duplicate root hashTree",
                            ));
                        }
                        root_hash_tree_seen = true;
                        self.write_root_hash_tree(1)?;
                    }
                    SemanticEvent::Element(_) | SemanticEvent::HashTree(_) => {
                        return Err(Error::semantic(
                            SemanticErrorKind::Topology,
                            None,
                            "ordered wrapper event stream contains a non-root tree event",
                        ));
                    }
                }
            }
            if !root_hash_tree_seen {
                return Err(Error::semantic(
                    SemanticErrorKind::Topology,
                    None,
                    "ordered wrapper event stream is missing its root hashTree",
                ));
            }
        }
        self.write_indent(0)?;
        self.write_raw(b"</")?;
        self.write_name(&self.document.root.name)?;
        self.write_raw(b">\n")?;
        self.write_extensions(0, &self.document.trailing_extensions)
    }

    fn write_root_hash_tree(&mut self, indent: usize) -> crate::Result<()> {
        let attributes = self.document.root_hash_tree_attributes.clone();
        let events = self.document.hash_tree_events.get(&None).cloned();
        self.write_hash_tree_container(None, &attributes, events.as_deref(), indent)
    }

    fn write_element(&mut self, id: NodeId, indent: usize) -> crate::Result<()> {
        self.write_element_body(id, indent)?;
        self.write_hash_tree(id, indent)
    }

    fn write_element_body(&mut self, id: NodeId, indent: usize) -> crate::Result<()> {
        self.check_depth(indent, "element encoding depth")?;
        if self.nodes_written >= MAX_ENCODER_NODES {
            return Err(self.encoding_limit("element count", MAX_ENCODER_NODES));
        }
        self.nodes_written = self.nodes_written.saturating_add(1);
        let node =
            self.document.tree.lookup(id).map_err(|error| {
                Error::semantic(SemanticErrorKind::Encode, None, error.to_string())
            })?;
        let element = node.value();
        let info = self.document.element_info.get(&id);
        let snapshot_matches = if info.is_some_and(|item| item.opaque) {
            self.document
                .element_snapshots
                .get(&id)
                .map_or(Ok(false), |snapshot| snapshot.matches(element))?
        } else {
            false
        };
        let emit_opaque_raw =
            snapshot_matches && self.document.opaque_element_bytes.contains_key(&id);
        if emit_opaque_raw {
            self.write_indent(indent)?;
            if let Some(raw) = self.document.opaque_element_bytes.get(&id) {
                self.validate_opaque_raw(raw)?;
                self.account_opaque_bytes(raw.len())?;
                self.write_raw(raw)?;
            }
            self.write_raw(b"\n")?;
            return Ok(());
        }
        let tag = info.map_or_else(
            || {
                self.document
                    .registry
                    .aliases
                    .canonical_alias(element.test_class(), element.test_class())
            },
            |item| {
                if item.opaque {
                    item.tag.clone()
                } else {
                    self.document
                        .registry
                        .aliases
                        .canonical_alias(&item.tag, element.test_class())
                }
            },
        );
        self.write_indent(indent)?;
        self.write_raw(b"<")?;
        self.write_name(&tag)?;
        let gui = element.gui_class().to_owned();
        let test_class = element.test_class().to_owned();
        self.write_attribute("guiclass", &gui)?;
        self.write_attribute("testclass", &test_class)?;
        self.write_legacy_attribute("testname", element.name())?;
        self.write_attribute(
            "enabled",
            if element.is_enabled() {
                "true"
            } else {
                "false"
            },
        )?;
        if let Some(info) = info {
            self.write_attributes(
                &info.extra_attributes,
                &["guiclass", "testclass", "testname", "enabled"],
            )?;
        }
        self.write_raw(b">\n")?;

        // Property nodes are source-ordered in `element_items`, but the model
        // is the authority after an edit.  Consume the current insertion-
        // ordered model properties sequentially at the old property slots;
        // this preserves opaque-child placement without allowing stale source
        // property names to control edited property order.
        let current_properties = element.properties.iter().cloned().collect::<Vec<_>>();
        let mut next_property = 0;
        let items = self
            .document
            .element_items
            .get(&id)
            .cloned()
            .unwrap_or_default();
        let source_extension_count = items
            .iter()
            .filter(|item| matches!(item, ElementItem::Opaque { .. }))
            .count();
        let occurrence_stable = source_extension_count == element.opaque_extensions.len();
        let mut emitted_extensions = vec![false; element.opaque_extensions.len()];
        for item in &items {
            match item {
                ElementItem::Property(_) => {
                    if let Some(entry) = current_properties.get(next_property) {
                        self.write_property(id, &[], &entry.name, &entry.value, indent + 1)?;
                        next_property += 1;
                    }
                }
                ElementItem::Opaque {
                    raw,
                    type_name,
                    occurrence,
                } => {
                    let extension_index = if occurrence_stable {
                        (*occurrence < element.opaque_extensions.len()).then_some(*occurrence)
                    } else {
                        element
                            .opaque_extensions
                            .iter()
                            .enumerate()
                            .find(|(index, extension)| {
                                !emitted_extensions[*index]
                                    && extension.type_name == *type_name
                                    && extension.raw == *raw
                            })
                            .map(|(index, _)| index)
                    };
                    let Some(extension_index) = extension_index else {
                        continue;
                    };
                    if emitted_extensions[extension_index] {
                        continue;
                    }
                    emitted_extensions[extension_index] = true;
                    self.write_indent(indent + 1)?;
                    let extension = &element.opaque_extensions[extension_index];
                    self.write_opaque_xml(&extension.type_name, &extension.raw)?;
                    self.write_raw(b"\n")?;
                }
            }
        }
        for entry in current_properties.iter().skip(next_property) {
            self.write_property(id, &[], &entry.name, &entry.value, indent + 1)?;
        }
        for (extension_index, extension) in element.opaque_extensions.iter().enumerate() {
            if !emitted_extensions[extension_index] {
                self.write_indent(indent + 1)?;
                self.write_opaque_xml(&extension.type_name, &extension.raw)?;
                self.write_raw(b"\n")?;
            }
        }
        self.write_indent(indent)?;
        self.write_raw(b"</")?;
        self.write_name(&tag)?;
        self.write_raw(b">\n")
    }

    fn write_hash_tree(&mut self, id: NodeId, indent: usize) -> crate::Result<()> {
        let attributes = self
            .document
            .hash_tree_attributes
            .get(&id)
            .cloned()
            .unwrap_or_default();
        let events = self.document.hash_tree_events.get(&Some(id)).cloned();
        self.write_hash_tree_container(Some(id), &attributes, events.as_deref(), indent)
    }

    fn write_hash_tree_container(
        &mut self,
        tree_owner: Option<NodeId>,
        attributes: &[SemanticAttribute],
        events: Option<&[SemanticEvent]>,
        indent: usize,
    ) -> crate::Result<()> {
        self.write_indent(indent)?;
        self.write_raw(b"<hashTree")?;
        self.write_attributes(attributes, &[])?;

        let fallback_extensions = match tree_owner {
            Some(id) => self
                .document
                .hash_tree_extensions
                .get(&id)
                .cloned()
                .unwrap_or_default(),
            None => self.document.root_hash_tree_extensions.clone(),
        };
        let fallback_children = match tree_owner {
            Some(id) => self
                .document
                .tree
                .lookup(id)
                .map_err(|error| {
                    Error::semantic(SemanticErrorKind::Encode, None, error.to_string())
                })?
                .children()
                .to_vec(),
            None => self.document.tree.root_ids().to_vec(),
        };
        let has_events = events.is_some();
        let has_content = events.is_some_and(|items| !items.is_empty())
            || (!has_events && (!fallback_extensions.is_empty() || !fallback_children.is_empty()));
        if !has_content {
            self.write_raw(b"/>\n")?;
            return Ok(());
        }
        self.write_raw(b">\n")?;

        if let Some(events) = events {
            let mut pending_element = None;
            for event in events {
                match event {
                    SemanticEvent::Extension(extension) => {
                        self.write_extensions(indent + 1, std::slice::from_ref(extension))?;
                    }
                    SemanticEvent::Element(id) => {
                        if pending_element.replace(*id).is_some() {
                            return Err(Error::semantic(
                                SemanticErrorKind::Topology,
                                None,
                                "ordered hashTree event stream contains adjacent elements",
                            ));
                        }
                        self.write_element_body(*id, indent + 1)?;
                    }
                    SemanticEvent::HashTree(id) => {
                        if pending_element.take() != Some(*id) {
                            return Err(Error::semantic(
                                SemanticErrorKind::Topology,
                                None,
                                "ordered hashTree event stream has an unmatched companion tree",
                            ));
                        }
                        self.write_hash_tree(*id, indent + 1)?;
                    }
                    SemanticEvent::RootHashTree => {
                        return Err(Error::semantic(
                            SemanticErrorKind::Topology,
                            None,
                            "ordered hashTree event stream contains root hashTree",
                        ));
                    }
                }
            }
            if pending_element.is_some() {
                return Err(Error::semantic(
                    SemanticErrorKind::MissingHashTree,
                    None,
                    "ordered hashTree event stream is missing a companion tree",
                ));
            }
        } else {
            self.write_extensions(indent + 1, &fallback_extensions)?;
            for id in fallback_children {
                self.write_element(id, indent + 1)?;
            }
        }
        self.write_indent(indent)?;
        self.write_raw(b"</hashTree>\n")
    }

    fn write_extensions(&mut self, indent: usize, extensions: &[OpaqueValue]) -> crate::Result<()> {
        for extension in extensions {
            if indent != 0 {
                self.write_indent(indent)?;
            }
            self.write_opaque_xml(&extension.type_name, &extension.raw)?;
            self.write_raw(b"\n")?;
        }
        Ok(())
    }

    fn write_property(
        &mut self,
        owner: NodeId,
        prefix: &[String],
        name: &str,
        value: &PropertyValue,
        indent: usize,
    ) -> crate::Result<()> {
        let prefix_path = PropertyPath {
            node_id: owner,
            names: prefix.to_vec(),
            occurrences: vec![0; prefix.len()],
        };
        self.write_property_path(owner, &prefix_path, name, 0, value, indent, true)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "owner, wire path, occurrence, value, and output placement are independent"
    )]
    fn write_property_path(
        &mut self,
        owner: NodeId,
        prefix: &PropertyPath,
        name: &str,
        occurrence: usize,
        value: &PropertyValue,
        indent: usize,
        include_name: bool,
    ) -> crate::Result<()> {
        self.write_property_inner(owner, prefix, name, occurrence, value, indent, include_name)
    }

    fn write_unnamed_property(
        &mut self,
        owner: NodeId,
        prefix: &PropertyPath,
        position: usize,
        value: &PropertyValue,
        indent: usize,
    ) -> crate::Result<()> {
        let name = position.to_string();
        self.write_property_inner(owner, prefix, &name, position, value, indent, false)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "owner, wire path, occurrence, value, and output placement are independent"
    )]
    fn write_property_inner(
        &mut self,
        owner: NodeId,
        prefix: &PropertyPath,
        name: &str,
        occurrence: usize,
        value: &PropertyValue,
        indent: usize,
        include_name: bool,
    ) -> crate::Result<()> {
        self.check_depth(indent, "property encoding depth")?;
        self.account_entries(1)?;
        let path = prefix.child_occurrence(name, occurrence);
        let metadata_path = self.source_property_path(&path, value)?;
        let wire = self.document.wire_properties.get(&metadata_path);
        let unchanged = self
            .document
            .original_property_values
            .get(&metadata_path)
            .is_some_and(|original| property_values_equal(original, value));
        if unchanged && let Some(raw) = wire.and_then(|item| item.raw_xml.as_deref()) {
            self.account_opaque_bytes(raw.len())?;
            self.write_indent(indent)?;
            self.write_raw(raw)?;
            self.write_raw(b"\n")?;
            return Ok(());
        }
        if !unchanged && wire.and_then(|item| item.raw_xml.as_deref()).is_some() {
            return Err(Error::semantic(
                SemanticErrorKind::Unsupported,
                None,
                "edited property contains lexical XML extensions that cannot be normalized without data loss",
            ));
        }
        let requested_tag =
            wire.map_or_else(|| default_property_tag(value), |item| item.tag.as_str());
        let tag = if wire_tag_compatible(requested_tag, value) {
            requested_tag
        } else {
            default_property_tag(value)
        };
        self.write_value_node(
            owner,
            name,
            &metadata_path,
            value,
            tag,
            wire,
            indent,
            include_name,
        )
    }

    /// Selects source metadata by stable path first, then by the semantic
    /// value of an entry at the same parent/name.  The fallback is what makes
    /// duplicate named map/collection entries safe across removal and reorder:
    /// a surviving entry keeps the metadata belonging to its source
    /// occurrence instead of inheriting the removed/reordered sibling's wire
    /// tag or raw extension.
    fn source_property_path(
        &self,
        path: &PropertyPath,
        value: &PropertyValue,
    ) -> crate::Result<PropertyPath> {
        let parent_unchanged = self.parent_value_unchanged(path);
        if parent_unchanged
            && self
                .document
                .original_property_values
                .get(path)
                .is_some_and(|original| property_values_equal(original, value))
        {
            return Ok(path.clone());
        }
        let candidates = self
            .document
            .original_property_values
            .iter()
            .filter(|(candidate, original)| {
                candidate.node_id == path.node_id
                    && candidate.names.len() == path.names.len()
                    && Self::same_parent_names(candidate, path)
                    && (candidate.names.last() == path.names.last()
                        || path
                            .names
                            .last()
                            .is_some_and(|name| name.parse::<usize>().is_ok()))
                    && property_values_equal(original, value)
            })
            .map(|(candidate, _)| candidate)
            .collect::<Vec<_>>();
        let Some(first) = candidates.first().copied() else {
            return Ok(path.clone());
        };
        let equivalent_metadata = candidates.iter().all(|candidate| {
            self.document.wire_properties.get(*candidate)
                == self.document.wire_properties.get(first)
                && self.document.nested_metadata.get(*candidate)
                    == self.document.nested_metadata.get(first)
                && self.document.object_value_metadata.get(*candidate)
                    == self.document.object_value_metadata.get(first)
        });
        if !equivalent_metadata {
            return Err(Error::semantic(
                SemanticErrorKind::Unsupported,
                None,
                "duplicate property value has ambiguous source occurrence metadata",
            ));
        }
        Ok(first.clone())
    }

    fn same_parent_names(left: &PropertyPath, right: &PropertyPath) -> bool {
        left.names[..left.names.len().saturating_sub(1)]
            .iter()
            .zip(right.names[..right.names.len().saturating_sub(1)].iter())
            .all(|(left, right)| {
                left == right || left.parse::<usize>().is_ok() || right.parse::<usize>().is_ok()
            })
    }

    fn parent_value_unchanged(&self, path: &PropertyPath) -> bool {
        if path.names.len() <= 1 {
            return true;
        }
        let parent_names = &path.names[..path.names.len() - 1];
        let parent_occurrences = &path.occurrences[..path.occurrences.len() - 1];
        let parent_path = PropertyPath {
            node_id: path.node_id,
            names: parent_names.to_vec(),
            occurrences: parent_occurrences.to_vec(),
        };
        let Some(original) = self.document.original_property_values.get(&parent_path) else {
            return false;
        };
        let Some(current) =
            self.current_property_value(path.node_id, parent_names, parent_occurrences)
        else {
            return false;
        };
        property_values_equal(original, current)
    }

    fn current_property_value(
        &self,
        owner: NodeId,
        names: &[String],
        occurrences: &[usize],
    ) -> Option<&PropertyValue> {
        let element = self.document.tree.element(owner).ok()?;
        let mut value = element.properties.get(names.first()?)?;
        for (depth, name) in names.iter().enumerate().skip(1) {
            let occurrence = occurrences.get(depth).copied().unwrap_or(0);
            value = match value {
                PropertyValue::Element(element) => element.properties.get(name)?,
                PropertyValue::Collection(values) => values.get(occurrence)?,
                PropertyValue::NamedCollection(entries) | PropertyValue::Map(entries) => entries
                    .iter()
                    .filter(|entry| entry.name == *name)
                    .nth(occurrence)
                    .map(|entry| &entry.value)?,
                _ => return None,
            };
        }
        Some(value)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "wire path, property kind, and indentation are independent encoder inputs"
    )]
    fn write_value_node(
        &mut self,
        owner: NodeId,
        name: &str,
        source_path: &PropertyPath,
        value: &PropertyValue,
        tag: &str,
        wire: Option<&WireProperty>,
        indent: usize,
        include_name: bool,
    ) -> crate::Result<()> {
        self.check_depth(indent, "property value encoding depth")?;
        let path = source_path.clone();
        let extras = wire.map_or(&[][..], |item| item.extra_attributes.as_slice());
        match value {
            PropertyValue::Element(element) => {
                self.write_indent(indent)?;
                self.write_raw(b"<")?;
                self.write_name(if is_xml_name(tag) { tag } else { "elementProp" })?;
                if include_name {
                    self.write_legacy_attribute("name", name)?;
                }
                if let Some(class_name) = &element.class_name {
                    self.write_attribute("elementType", class_name)?;
                }
                if let Some(meta) = self.document.nested_metadata.get(&path) {
                    self.write_attributes(&meta.extra_attributes, &["name", "elementType"])?;
                } else {
                    self.write_attributes(extras, &["name", "elementType"])?;
                }
                self.write_raw(b">\n")?;
                let current_properties = element.properties.iter().cloned().collect::<Vec<_>>();
                let mut next_property = 0;
                let source_extension_count = self
                    .document
                    .nested_metadata
                    .get(&path)
                    .map(|metadata| {
                        metadata
                            .items
                            .iter()
                            .filter(|item| matches!(item, NestedItem::Opaque { .. }))
                            .count()
                    })
                    .unwrap_or(0);
                let occurrence_stable = source_extension_count == element.opaque_extensions.len();
                let mut emitted_extensions = vec![false; element.opaque_extensions.len()];
                if let Some(meta) = self.document.nested_metadata.get(&path) {
                    let items = meta.items.clone();
                    for item in &items {
                        match item {
                            NestedItem::Property(_) => {
                                if let Some(child) = current_properties.get(next_property) {
                                    self.write_property_path(
                                        owner,
                                        &path,
                                        &child.name,
                                        0,
                                        &child.value,
                                        indent + 1,
                                        true,
                                    )?;
                                    next_property += 1;
                                }
                            }
                            NestedItem::Opaque {
                                raw,
                                type_name,
                                occurrence,
                            } => {
                                let extension_index = if occurrence_stable {
                                    (*occurrence < element.opaque_extensions.len())
                                        .then_some(*occurrence)
                                } else {
                                    element
                                        .opaque_extensions
                                        .iter()
                                        .enumerate()
                                        .find(|(index, extension)| {
                                            !emitted_extensions[*index]
                                                && extension.type_name == *type_name
                                                && extension.raw == *raw
                                        })
                                        .map(|(index, _)| index)
                                };
                                let Some(extension_index) = extension_index else {
                                    continue;
                                };
                                if emitted_extensions[extension_index] {
                                    continue;
                                }
                                emitted_extensions[extension_index] = true;
                                self.write_indent(indent + 1)?;
                                let extension = &element.opaque_extensions[extension_index];
                                self.write_opaque_xml(&extension.type_name, &extension.raw)?;
                                self.write_raw(b"\n")?;
                            }
                        }
                    }
                }
                for child in current_properties.iter().skip(next_property) {
                    self.write_property_path(
                        owner,
                        &path,
                        &child.name,
                        0,
                        &child.value,
                        indent + 1,
                        true,
                    )?;
                }
                for (extension_index, extension) in element.opaque_extensions.iter().enumerate() {
                    if !emitted_extensions[extension_index] {
                        self.write_indent(indent + 1)?;
                        self.write_opaque_xml(&extension.type_name, &extension.raw)?;
                        self.write_raw(b"\n")?;
                    }
                }
                self.write_indent(indent)?;
                self.write_raw(b"</")?;
                self.write_name(if is_xml_name(tag) { tag } else { "elementProp" })?;
                self.write_raw(b">\n")?;
            }
            PropertyValue::NamedCollection(entries) | PropertyValue::Map(entries) => {
                self.write_indent(indent)?;
                self.write_raw(b"<")?;
                self.write_name(if is_xml_name(tag) {
                    tag
                } else {
                    default_property_tag(value)
                })?;
                if include_name {
                    self.write_legacy_attribute("name", name)?;
                }
                self.write_attributes(extras, &["name"])?;
                if entries.is_empty() {
                    self.write_raw(b"/>\n")?;
                } else {
                    self.write_raw(b">\n")?;
                    for (entry_index, entry) in entries.iter().enumerate() {
                        let occurrence = entries[..entry_index]
                            .iter()
                            .filter(|previous| previous.name == entry.name)
                            .count();
                        self.write_property_path(
                            owner,
                            &path,
                            &entry.name,
                            occurrence,
                            &entry.value,
                            indent + 1,
                            true,
                        )?;
                    }
                    self.write_indent(indent)?;
                    self.write_raw(b"</")?;
                    self.write_name(if is_xml_name(tag) {
                        tag
                    } else {
                        default_property_tag(value)
                    })?;
                    self.write_raw(b">\n")?;
                }
            }
            PropertyValue::Collection(values) => {
                self.write_indent(indent)?;
                self.write_raw(b"<")?;
                self.write_name(if is_xml_name(tag) {
                    tag
                } else {
                    "collectionProp"
                })?;
                if include_name {
                    self.write_legacy_attribute("name", name)?;
                }
                self.write_attributes(extras, &["name"])?;
                if values.is_empty() {
                    self.write_raw(b"/>\n")?;
                } else {
                    self.write_raw(b">\n")?;
                    for (position, child) in values.iter().enumerate() {
                        self.write_unnamed_property(owner, &path, position, child, indent + 1)?;
                    }
                    self.write_indent(indent)?;
                    self.write_raw(b"</")?;
                    self.write_name(if is_xml_name(tag) {
                        tag
                    } else {
                        "collectionProp"
                    })?;
                    self.write_raw(b">\n")?;
                }
            }
            PropertyValue::Object(object) => {
                if include_name
                    && let Some(shape) = self.document.object_property_shapes.get(&path).cloned()
                {
                    self.write_indent(indent)?;
                    self.write_raw(b"<")?;
                    self.write_name(if is_xml_name(tag) { tag } else { "objProp" })?;
                    self.write_attributes(extras, &["name"])?;
                    self.write_raw(b">\n")?;
                    for child in shape.children {
                        match child {
                            ObjectPropertyChild::Name => {
                                self.write_indent(indent + 1)?;
                                self.write_raw(b"<name")?;
                                self.write_attributes(&shape.name_attributes, &[])?;
                                self.write_raw(b">")?;
                                let encoded_name = self.legacy_value(name);
                                self.write_escaped(&encoded_name)?;
                                self.write_raw(b"</name>\n")?;
                            }
                            ObjectPropertyChild::Value => {
                                self.write_object_value(object, &path, indent + 1)?;
                            }
                        }
                    }
                    self.write_indent(indent)?;
                    self.write_raw(b"</")?;
                    self.write_name(if is_xml_name(tag) { tag } else { "objProp" })?;
                    self.write_raw(b">\n")?;
                    return Ok(());
                }
                self.write_indent(indent)?;
                self.write_raw(b"<")?;
                self.write_name(if is_xml_name(tag) { tag } else { "objProp" })?;
                if include_name {
                    self.write_legacy_attribute("name", name)?;
                }
                self.write_attributes(extras, &["name"])?;
                self.write_raw(b">\n")?;
                self.write_object_value(object, &path, indent + 1)?;
                self.write_indent(indent)?;
                self.write_raw(b"</")?;
                self.write_name(if is_xml_name(tag) { tag } else { "objProp" })?;
                self.write_raw(b">\n")?;
            }
            PropertyValue::Null => {
                self.write_indent(indent)?;
                self.write_raw(b"<")?;
                self.write_name(if is_xml_name(tag) { tag } else { "objProp" })?;
                if include_name {
                    self.write_legacy_attribute("name", name)?;
                }
                self.write_attributes(extras, &["name"])?;
                self.write_raw(b"/>")?;
                self.write_raw(b"\n")?;
            }
            scalar => {
                self.write_indent(indent)?;
                self.write_raw(b"<")?;
                self.write_name(if is_xml_name(tag) {
                    tag
                } else {
                    default_property_tag(scalar)
                })?;
                if include_name {
                    self.write_legacy_attribute("name", name)?;
                }
                for attribute in extras {
                    if attribute.name != "name" {
                        self.write_attribute(&attribute.name, &attribute.value)?;
                    }
                }
                let raw_text = match scalar {
                    PropertyValue::Opaque(value) => {
                        std::str::from_utf8(&value.raw).map_err(|_| {
                            Error::semantic(
                                SemanticErrorKind::Encode,
                                None,
                                "opaque property text is not valid UTF-8",
                            )
                        })?
                    }
                    _ => &scalar_text(scalar),
                };
                if let PropertyValue::Opaque(value) = scalar
                    && value.raw.starts_with(b"<")
                {
                    self.validate_opaque_raw(&value.raw)?;
                }
                if let PropertyValue::Opaque(value) = scalar {
                    self.account_opaque_bytes(value.raw.len())?;
                }
                if !raw_text.chars().all(is_xml_char) {
                    return Err(Error::semantic(
                        SemanticErrorKind::Encode,
                        None,
                        "XML property text contains an XML-forbidden control character",
                    ));
                }
                let text = self.legacy_value(raw_text);
                if text.is_empty() {
                    self.write_raw(b"></")?;
                    self.write_name(if is_xml_name(tag) {
                        tag
                    } else {
                        default_property_tag(scalar)
                    })?;
                    self.write_raw(b">\n")?;
                } else {
                    self.write_raw(b">")?;
                    self.write_escaped(&text)?;
                    self.write_raw(b"</")?;
                    self.write_name(if is_xml_name(tag) {
                        tag
                    } else {
                        default_property_tag(scalar)
                    })?;
                    self.write_raw(b">\n")?;
                }
            }
        }
        Ok(())
    }

    fn write_object_value(
        &mut self,
        object: &jmeter_rs_model::ObjectProperty,
        path: &PropertyPath,
        indent: usize,
    ) -> crate::Result<()> {
        self.write_indent(indent)?;
        self.write_raw(b"<value")?;
        let object_attributes = object
            .attributes
            .iter()
            .map(|attribute| SemanticAttribute::new(&attribute.name, &attribute.value))
            .collect::<Vec<_>>();
        let preserve_object_metadata = self
            .document
            .original_property_values
            .get(path)
            .and_then(|value| match value {
                PropertyValue::Object(original) => Some(original),
                _ => None,
            })
            .is_some_and(|original| {
                original.class_name == object.class_name && original.attributes == object.attributes
            });
        if preserve_object_metadata {
            if let Some(metadata) = self.document.object_value_metadata.get(path) {
                self.write_attributes(&metadata.attributes, &[])?;
            } else {
                self.write_attributes(&object_attributes, &[])?;
            }
        } else {
            // `None` means the source attribute was absent, while
            // `Some("")` is an explicit empty `class=""` attribute.  Keep
            // those wire states distinct for new and edited object values.
            if let Some(class_name) = object.class_name.as_deref() {
                self.write_attribute("class", class_name)?;
            }
            let retained_attributes = object_attributes
                .iter()
                .filter(|attribute| {
                    attribute.name != "class"
                        && (attribute.name != "type"
                            || object.class_name.as_deref() == Some(attribute.value.as_str()))
                })
                .cloned()
                .collect::<Vec<_>>();
            self.write_attributes(&retained_attributes, &[])?;
        }
        self.write_raw(b">")?;
        if object.is_opaque_xml() {
            self.validate_opaque_fragment(&object.raw)?;
            self.account_opaque_bytes(object.raw.len())?;
            self.write_raw(&object.raw)?;
        } else {
            self.account_opaque_bytes(object.raw.len())?;
            self.write_escaped_bytes(&object.raw)?;
        }
        self.write_raw(b"</value>\n")
    }
}

impl<'a, W: Write> Encoder<'a, W> {
    fn validate_document(&self) -> crate::Result<()> {
        if self.document.root.name != "jmeterTestPlan" {
            return Err(Error::semantic(
                SemanticErrorKind::InvalidRoot,
                None,
                "canonical JMX root must be jmeterTestPlan",
            ));
        }
        let mut seen = BTreeSet::new();
        for attribute in &self.document.root.attributes {
            if !seen.insert(attribute.name.as_str()) {
                return Err(Error::semantic(
                    SemanticErrorKind::DuplicateMetadata,
                    None,
                    "duplicate root XML attribute during canonical encoding",
                ));
            }
        }
        if let Some(version) = self.document.root.version() {
            if !matches!(version, "1.0" | "1.2") {
                return Err(Error::semantic(
                    SemanticErrorKind::RootMetadata,
                    None,
                    "unsupported JMX wrapper version",
                ));
            }
        } else if !self.document.root.attributes.is_empty() {
            return Err(Error::semantic(
                SemanticErrorKind::RootMetadata,
                None,
                "jmeterTestPlan root metadata must include a version attribute",
            ));
        }
        let node_ids = bounded_preorder_ids(&self.document.tree, MAX_ENCODER_NODES)?;
        self.document
            .tree
            .validate_with_limits(&encoder_validation_limits())
            .map_err(map_encoder_validation_error)?;
        self.validate_event_streams()?;
        for id in node_ids {
            let node = self.document.tree.lookup(id).map_err(|error| {
                Error::semantic(SemanticErrorKind::Encode, None, error.to_string())
            })?;
            let element = node.value();
            if element.test_class().is_empty()
                || element.gui_class().is_empty()
                || element.name().is_empty()
            {
                return Err(Error::semantic(
                    SemanticErrorKind::MissingMetadata,
                    None,
                    format!(
                        "element {id} requires nonempty testclass, guiclass, and testname metadata"
                    ),
                ));
            }
        }
        self.document.registry.validate().map_err(|_error| {
            Error::semantic(
                SemanticErrorKind::Registry,
                None,
                "semantic registry failed validation",
            )
        })
    }

    fn validate_event_streams(&self) -> crate::Result<()> {
        // An empty stream is the explicit source-absent/programmatic form.
        // Once a source event stream exists, every semantic tree slot must be
        // represented exactly once; otherwise an edit would silently drop or
        // invent wire placement.
        if self.document.root_events.is_empty() {
            if !self.document.hash_tree_events.is_empty() {
                return Err(Error::semantic(
                    SemanticErrorKind::Unsupported,
                    None,
                    "hashTree event metadata exists without a wrapper event stream",
                ));
            }
            return Ok(());
        }
        if self
            .document
            .root_events
            .iter()
            .filter(|event| matches!(event, SemanticEvent::RootHashTree))
            .count()
            != 1
        {
            return Err(Error::semantic(
                SemanticErrorKind::Unsupported,
                None,
                "wrapper event stream does not contain exactly one root hashTree",
            ));
        }
        if self.document.root_events.iter().any(|event| {
            matches!(
                event,
                SemanticEvent::Element(_) | SemanticEvent::HashTree(_)
            )
        }) {
            return Err(Error::semantic(
                SemanticErrorKind::Unsupported,
                None,
                "wrapper event stream contains a non-root tree event",
            ));
        }
        let root_ids = self.document.tree.root_ids();
        self.validate_tree_event_stream(None, root_ids)?;
        let node_ids = bounded_preorder_ids(&self.document.tree, MAX_ENCODER_NODES)?;
        for id in node_ids {
            let children = self.document.tree.children(id).map_err(|error| {
                Error::semantic(SemanticErrorKind::Encode, None, error.to_string())
            })?;
            self.validate_tree_event_stream(Some(id), children)?;
        }
        Ok(())
    }

    fn validate_tree_event_stream(
        &self,
        owner: Option<NodeId>,
        expected_children: &[NodeId],
    ) -> crate::Result<()> {
        let Some(events) = self.document.hash_tree_events.get(&owner) else {
            return Err(Error::semantic(
                SemanticErrorKind::Unsupported,
                None,
                "edited semantic tree has no wire event stream for a hashTree",
            ));
        };
        let mut observed = Vec::new();
        let mut pending = None;
        for event in events {
            match event {
                SemanticEvent::Element(id) => {
                    if pending.replace(*id).is_some() {
                        return Err(Error::semantic(
                            SemanticErrorKind::Unsupported,
                            None,
                            "edited semantic tree has adjacent element wire events",
                        ));
                    }
                    observed.push(*id);
                }
                SemanticEvent::HashTree(id) => {
                    if pending.take() != Some(*id) {
                        return Err(Error::semantic(
                            SemanticErrorKind::Unsupported,
                            None,
                            "edited semantic tree has an unmatched hashTree wire event",
                        ));
                    }
                }
                SemanticEvent::Extension(_) => {}
                SemanticEvent::RootHashTree => {
                    return Err(Error::semantic(
                        SemanticErrorKind::Unsupported,
                        None,
                        "edited semantic tree has a nested root hashTree event",
                    ));
                }
            }
        }
        if pending.is_some() || observed != expected_children {
            return Err(Error::semantic(
                SemanticErrorKind::Unsupported,
                None,
                "edited semantic tree cannot be represented by its source wire placement",
            ));
        }
        Ok(())
    }

    fn check_depth(&self, depth: usize, what: &str) -> crate::Result<()> {
        if depth > MAX_ENCODER_DEPTH {
            return Err(self.encoding_limit(what, MAX_ENCODER_DEPTH));
        }
        Ok(())
    }

    fn encoding_limit(&self, what: &str, limit: usize) -> Error {
        Error::semantic(
            SemanticErrorKind::Limit,
            None,
            format!("{what} exceeded encoder limit {limit}"),
        )
    }

    fn write_indent(&mut self, indent: usize) -> crate::Result<()> {
        for _ in 0..indent {
            self.write_raw(b"  ")?;
        }
        Ok(())
    }

    fn write_attribute(&mut self, name: &str, value: &str) -> crate::Result<()> {
        if !is_xml_name(name) {
            return Err(Error::semantic(
                SemanticErrorKind::Encode,
                None,
                "invalid XML attribute name",
            ));
        }
        self.account_metadata(name.len().saturating_add(value.len()))?;
        self.write_raw(b" ")?;
        self.write_name(name)?;
        self.write_raw(b"=\"")?;
        self.write_escaped(value)?;
        self.write_raw(b"\"")
    }

    fn write_attributes(
        &mut self,
        attributes: &[SemanticAttribute],
        skipped: &[&str],
    ) -> crate::Result<()> {
        let mut seen = BTreeSet::new();
        for attribute in attributes {
            if skipped.contains(&attribute.name.as_str()) {
                continue;
            }
            if !seen.insert(attribute.name.as_str()) {
                return Err(Error::semantic(
                    SemanticErrorKind::DuplicateMetadata,
                    None,
                    "duplicate XML attribute during canonical encoding",
                ));
            }
            self.write_attribute(&attribute.name, &attribute.value)?;
        }
        Ok(())
    }

    fn legacy_value(&self, value: &str) -> String {
        if self.document.root.version() == Some("1.0") {
            percent_encode(value)
        } else {
            value.to_owned()
        }
    }

    fn write_legacy_attribute(&mut self, name: &str, value: &str) -> crate::Result<()> {
        if !value.chars().all(is_xml_char) {
            return Err(Error::semantic(
                SemanticErrorKind::Encode,
                None,
                "XML attribute value contains an XML-forbidden control character",
            ));
        }
        let encoded = self.legacy_value(value);
        self.write_attribute(name, &encoded)
    }

    fn write_opaque_xml(&mut self, type_name: &str, raw: &[u8]) -> crate::Result<()> {
        self.account_entries(1)?;
        self.validate_opaque_raw(raw)?;
        self.account_opaque_bytes(raw.len())?;
        if raw.starts_with(b"<") {
            return self.write_raw(raw);
        }
        let name = if is_xml_name(type_name) {
            type_name
        } else {
            "opaque"
        };
        self.write_raw(b"<")?;
        self.write_name(name)?;
        self.write_attribute("type", type_name)?;
        self.write_raw(b">")?;
        self.write_escaped_bytes(raw)?;
        self.write_raw(b"</")?;
        self.write_name(name)?;
        self.write_raw(b">")
    }

    fn validate_opaque_raw(&self, raw: &[u8]) -> crate::Result<()> {
        if raw.len() > MAX_ENCODER_OPAQUE_BYTES {
            return Err(self.encoding_limit("opaque XML bytes", MAX_ENCODER_OPAQUE_BYTES));
        }
        if raw.starts_with(b"<") {
            self.validate_opaque_fragment(raw)
        } else {
            let text = std::str::from_utf8(raw).map_err(|_| {
                Error::semantic(
                    SemanticErrorKind::Encode,
                    None,
                    "opaque XML text is not valid UTF-8",
                )
            })?;
            if text.chars().all(is_xml_char) {
                Ok(())
            } else {
                Err(Error::semantic(
                    SemanticErrorKind::Encode,
                    None,
                    "opaque XML text contains an XML-forbidden control character",
                ))
            }
        }
    }

    fn validate_opaque_fragment(&self, raw: &[u8]) -> crate::Result<()> {
        if raw.len() > MAX_ENCODER_OPAQUE_BYTES {
            return Err(self.encoding_limit("opaque XML payload bytes", MAX_ENCODER_OPAQUE_BYTES));
        }
        let mut wrapped = Vec::with_capacity(raw.len().saturating_add(17));
        wrapped.extend_from_slice(b"<opaquePayload>");
        wrapped.extend_from_slice(raw);
        wrapped.extend_from_slice(b"</opaquePayload>");
        crate::Parser::new()
            .parse(&wrapped)
            .map(|_| ())
            .map_err(|_error| {
                Error::semantic(
                    SemanticErrorKind::Encode,
                    None,
                    "opaque object XML payload is not well-formed",
                )
            })
    }

    fn write_escaped(&mut self, value: &str) -> crate::Result<()> {
        self.write_escaped_bytes(value.as_bytes())
    }

    fn write_escaped_bytes(&mut self, bytes: &[u8]) -> crate::Result<()> {
        let text = std::str::from_utf8(bytes).map_err(|_| {
            Error::semantic(
                SemanticErrorKind::Encode,
                None,
                "opaque XML text is not valid UTF-8",
            )
        })?;
        if !text.chars().all(is_xml_char) {
            return Err(Error::semantic(
                SemanticErrorKind::Encode,
                None,
                "XML text contains an XML-forbidden control character",
            ));
        }
        let text_bytes = text.as_bytes();
        let mut start = 0;
        for (index, character) in text.char_indices() {
            let replacement = match character {
                '&' => Some("&amp;"),
                '<' => Some("&lt;"),
                '>' => Some("&gt;"),
                '"' => Some("&quot;"),
                '\'' => Some("&apos;"),
                _ => None,
            };
            if let Some(replacement) = replacement {
                self.write_raw(&text_bytes[start..index])?;
                self.write_raw(replacement.as_bytes())?;
                start = index + character.len_utf8();
            }
        }
        self.write_raw(&text_bytes[start..])
    }

    fn write_name(&mut self, name: &str) -> crate::Result<()> {
        if !is_xml_name(name) {
            return Err(Error::semantic(
                SemanticErrorKind::Encode,
                None,
                "invalid XML element name",
            ));
        }
        self.write_raw(name.as_bytes())
    }

    fn write_raw(&mut self, bytes: &[u8]) -> crate::Result<()> {
        let observed = self.output_bytes.saturating_add(bytes.len());
        if observed > MAX_ENCODER_OUTPUT_BYTES {
            return Err(self.encoding_limit("total XML output bytes", MAX_ENCODER_OUTPUT_BYTES));
        }
        self.writer.write_all(bytes).map_err(Error::io)?;
        self.output_bytes = observed;
        Ok(())
    }

    fn account_entries(&mut self, count: usize) -> crate::Result<()> {
        let observed = self.entries_written.saturating_add(count);
        if observed > MAX_ENCODER_ENTRIES {
            return Err(self.encoding_limit("property entry count", MAX_ENCODER_ENTRIES));
        }
        self.entries_written = observed;
        Ok(())
    }

    fn account_metadata(&mut self, bytes: usize) -> crate::Result<()> {
        let count = self.metadata_written.saturating_add(1);
        let observed = self.metadata_bytes.saturating_add(bytes);
        if count > MAX_ENCODER_METADATA {
            return Err(self.encoding_limit("XML metadata entry count", MAX_ENCODER_METADATA));
        }
        if observed > MAX_ENCODER_METADATA_BYTES {
            return Err(self.encoding_limit("XML metadata bytes", MAX_ENCODER_METADATA_BYTES));
        }
        self.metadata_written = count;
        self.metadata_bytes = observed;
        Ok(())
    }

    fn account_opaque_bytes(&mut self, bytes: usize) -> crate::Result<()> {
        let observed = self.opaque_bytes_written.saturating_add(bytes);
        if observed > MAX_ENCODER_OPAQUE_BYTES {
            return Err(self.encoding_limit("aggregate opaque XML bytes", MAX_ENCODER_OPAQUE_BYTES));
        }
        self.opaque_bytes_written = observed;
        Ok(())
    }
}

fn is_xml_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !crate::is_name_start_char(first) {
        return false;
    }
    let mut colon_count = usize::from(first == ':');
    for character in chars {
        if !crate::is_name_char(character) {
            return false;
        }
        if character == ':' {
            colon_count = colon_count.saturating_add(1);
        }
    }
    colon_count <= 1 && first != ':' && !name.ends_with(':')
}

fn default_property_tag(value: &PropertyValue) -> &str {
    match value {
        PropertyValue::Null | PropertyValue::Object(_) => "objProp",
        PropertyValue::String(_) => "stringProp",
        PropertyValue::Boolean(_) => "boolProp",
        PropertyValue::Integer(_) => "intProp",
        PropertyValue::Long(_) => "longProp",
        PropertyValue::Float(_) => "floatProp",
        PropertyValue::Double(_) => "doubleProp",
        PropertyValue::Collection(_) | PropertyValue::NamedCollection(_) => "collectionProp",
        PropertyValue::Map(_) => "mapProp",
        PropertyValue::Element(_) => "elementProp",
        PropertyValue::Opaque(value) => {
            if is_xml_name(&value.type_name) {
                value.type_name.as_str()
            } else {
                "opaqueProp"
            }
        }
    }
}

fn wire_tag_compatible(tag: &str, value: &PropertyValue) -> bool {
    match tag {
        "stringProp" => matches!(value, PropertyValue::String(_) | PropertyValue::Opaque(_)),
        "boolProp" => matches!(value, PropertyValue::Boolean(_)),
        "intProp" => matches!(value, PropertyValue::Integer(_)),
        "longProp" => matches!(value, PropertyValue::Long(_)),
        "floatProp" => matches!(value, PropertyValue::Float(_)),
        "doubleProp" => matches!(value, PropertyValue::Double(_)),
        "collectionProp" => matches!(
            value,
            PropertyValue::Collection(_) | PropertyValue::NamedCollection(_)
        ),
        "mapProp" => matches!(value, PropertyValue::Map(_)),
        "elementProp" => matches!(value, PropertyValue::Element(_)),
        "objProp" => matches!(value, PropertyValue::Null | PropertyValue::Object(_)),
        _ => matches!(value, PropertyValue::Opaque(_)),
    }
}

fn scalar_text(value: &PropertyValue) -> String {
    match value {
        PropertyValue::String(value) => value.clone(),
        PropertyValue::Boolean(value) => value.to_string(),
        PropertyValue::Integer(value) => value.to_string(),
        PropertyValue::Long(value) => value.to_string(),
        PropertyValue::Float(value) => java_float_text(*value),
        PropertyValue::Double(value) => java_double_text(*value),
        PropertyValue::Opaque(value) => String::from_utf8_lossy(&value.raw).into_owned(),
        _ => String::new(),
    }
}

fn java_float_text(value: f32) -> String {
    if value.is_nan() {
        "NaN".to_owned()
    } else if value == f32::INFINITY {
        "Infinity".to_owned()
    } else if value == f32::NEG_INFINITY {
        "-Infinity".to_owned()
    } else {
        value.to_string()
    }
}

fn java_double_text(value: f64) -> String {
    if value.is_nan() {
        "NaN".to_owned()
    } else if value == f64::INFINITY {
        "Infinity".to_owned()
    } else if value == f64::NEG_INFINITY {
        "-Infinity".to_owned()
    } else {
        value.to_string()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::*;

    const TOPOLOGY: &[u8] =
        include_bytes!("../../../compat/fixtures/jmeter-5.6.3/jmx-topology/plan.jmx");

    #[test]
    fn all_materialized_profile_jmx_fixtures_round_trip_semantically() {
        fn case_manifest_root(path: &Path, fixtures_root: &Path) -> Option<std::path::PathBuf> {
            let mut candidate = path.parent()?;
            loop {
                if candidate.join("case.json").is_file() {
                    return Some(candidate.to_owned());
                }
                if candidate == fixtures_root {
                    return None;
                }
                candidate = candidate.parent()?;
            }
        }

        fn visit(path: &Path, fixtures_root: &Path, paths: &mut Vec<std::path::PathBuf>) {
            let Ok(entries) = fs::read_dir(path) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    visit(&path, fixtures_root, paths);
                } else if path.extension().is_some_and(|extension| extension == "jmx") {
                    assert!(
                        case_manifest_root(&path, fixtures_root).is_some(),
                        "JMX fixture is not owned by a case.json manifest: {}",
                        path.display()
                    );
                    paths.push(path);
                }
            }
        }
        let fixtures_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../compat/fixtures");
        let mut paths = Vec::new();
        visit(&fixtures_root, &fixtures_root, &mut paths);
        paths.sort();
        for path in paths {
            let source = fs::read(&path).expect("fixture bytes");
            let document = SemanticDocument::from_bytes(&source)
                .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
            let output = document
                .to_canonical_bytes()
                .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
            let reparsed = SemanticDocument::from_bytes(&output)
                .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
            assert_eq!(document, reparsed, "{}", path.display());
        }
    }

    #[test]
    fn decodes_fixture_topology_properties_and_stable_ids() {
        let document = SemanticDocument::from_bytes_with_options(
            TOPOLOGY,
            DecodeOptions::default().with_source_name("fixture/plan.jmx"),
        )
        .expect("fixture is valid semantic JMX");
        assert_eq!(document.root().name, "jmeterTestPlan");
        assert_eq!(document.root().version(), Some("1.2"));
        assert_eq!(document.root().properties_version(), Some("5.0"));
        assert_eq!(document.root().jmeter_version(), Some("5.6.3"));
        assert_eq!(document.tree().preorder_ids().len(), 3);
        assert_eq!(
            document.tree().preorder_ids(),
            vec![NodeId::new(1), NodeId::new(2), NodeId::new(3)]
        );
        let root = document
            .tree()
            .element(NodeId::new(1))
            .expect("root element");
        assert_eq!(root.test_class(), "TestPlan");
        assert_eq!(root.name(), "JMX topology and typed values");
        assert_eq!(
            root.property("TestPlan.functional_mode"),
            Some(&PropertyValue::Boolean(false))
        );
        let property_span = document
            .property_span(NodeId::new(1), &["TestPlan.functional_mode"])
            .expect("property span");
        assert!(!property_span.is_empty());
        assert_eq!(root.source().source_name(), Some("fixture/plan.jmx"));
        assert_eq!(
            document
                .tree()
                .children(NodeId::new(1))
                .expect("children")
                .len(),
            1
        );
        assert!(document.diagnostics().is_empty());
    }

    #[test]
    fn canonical_round_trip_keeps_semantic_shape_and_xml_escaping() {
        let document = SemanticDocument::from_bytes(TOPOLOGY).expect("fixture is valid");
        let bytes = document.to_canonical_bytes().expect("canonical encoding");
        let reparsed = SemanticDocument::from_bytes(&bytes).expect("canonical XML is valid");
        assert_eq!(reparsed.root().attribute("properties"), Some("5.0"));
        assert_eq!(
            reparsed.tree().preorder_ids(),
            document.tree().preorder_ids()
        );
        for id in document.tree().preorder_ids() {
            let left = document.tree().element(id).expect("left");
            let right = reparsed.tree().element(id).expect("right");
            assert_eq!(left.metadata, right.metadata);
            assert_eq!(left.enabled, right.enabled);
            assert_eq!(left.properties, right.properties);
        }
        let text = String::from_utf8(bytes).expect("UTF-8 canonical XML");
        assert!(text.contains("left &amp; right &lt;value&gt;"));
    }

    #[test]
    fn unknown_test_elements_are_opaque_but_round_trip() {
        let source = br#"<jmeterTestPlan version="1.2" properties="5.0" jmeter="5.6.3"><hashTree><MysteryPlugin guiclass="MysteryGui" testclass="com.example.Mystery" testname="unknown" enabled="true"><mysteryProp name="x">raw &amp; value</mysteryProp></MysteryPlugin><hashTree/></hashTree></jmeterTestPlan>"#;
        let document = SemanticDocument::from_bytes(source).expect("unknown nodes are preservable");
        let id = NodeId::new(1);
        assert!(document.is_opaque(id));
        assert_eq!(
            document.diagnostics()[0].code,
            "jmx.semantic.unknown_element"
        );
        let bytes = document
            .to_canonical_bytes()
            .expect("unknown node canonical output");
        let reparsed = SemanticDocument::from_bytes(&bytes).expect("unknown output is valid XML");
        assert!(reparsed.is_opaque(id));
        assert!(
            String::from_utf8(bytes)
                .expect("UTF-8")
                .contains("mysteryProp")
        );
    }

    #[test]
    fn malformed_topology_and_properties_have_stable_codes() {
        let missing_pair = br#"<jmeterTestPlan version="1.2"><hashTree><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="x" enabled="true"/></hashTree></jmeterTestPlan>"#;
        let error = SemanticDocument::from_bytes(missing_pair).expect_err("missing hashTree pair");
        assert_eq!(error.code(), "jmx.semantic.missing_hash_tree");
        let invalid_bool = br#"<jmeterTestPlan version="1.2"><hashTree><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="x" enabled="true"><boolProp name="x">maybe</boolProp></TestPlan><hashTree/></hashTree></jmeterTestPlan>"#;
        let error = SemanticDocument::from_bytes(invalid_bool).expect_err("invalid bool");
        assert_eq!(error.code(), "jmx.semantic.invalid_property_value");
        let missing_name = br#"<jmeterTestPlan version="1.2"><hashTree><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="x" enabled="true"><stringProp>value</stringProp></TestPlan><hashTree/></hashTree></jmeterTestPlan>"#;
        let error = SemanticDocument::from_bytes(missing_name).expect_err("missing property name");
        assert_eq!(error.code(), "jmx.semantic.invalid_property");
    }

    #[test]
    fn all_original_profile_jmx_fixtures_decode_and_canonicalize() {
        let fixtures = [
            &include_bytes!("../../../compat/fixtures/jmeter-5.6.3/jmx-topology/plan.jmx")[..],
            &include_bytes!("../../../compat/fixtures/jmeter-5.6.3/jtl-fields/plan.jmx")[..],
            &include_bytes!("../../../compat/fixtures/jmeter-5.6.3/controllers/plan.jmx")[..],
            &include_bytes!("../../../compat/fixtures/jmeter-5.6.3/assertion-failure/plan.jmx")[..],
            &include_bytes!("../../../compat/fixtures/jmeter-5.6.3/lifecycle-debug/plan.jmx")[..],
        ];
        for fixture in fixtures {
            let document = SemanticDocument::from_bytes(fixture).expect("profile fixture decodes");
            let bytes = document
                .to_canonical_bytes()
                .expect("profile fixture encodes");
            let reparsed = SemanticDocument::from_bytes(&bytes).expect("canonical fixture parses");
            assert_eq!(document, reparsed);
        }
    }

    #[test]
    fn legacy_version_values_and_upgrade_aliases_are_data_only() {
        let source = br#"<jmeterTestPlan version="1.0" properties="5.0" jmeter="2.3"><hashTree><LegacySampler guiclass="HttpTestSampleGui" testclass="org.apache.jmeter.protocol.http.sampler.HTTPSamplerFull" testname="old+name" enabled="true"><stringProp name="legacy.value">a+b%26</stringProp></LegacySampler><hashTree/></hashTree></jmeterTestPlan>"#;
        let document = SemanticDocument::from_bytes(source).expect("legacy JMX decodes");
        let element = document
            .tree()
            .element(NodeId::new(1))
            .expect("legacy element");
        assert_eq!(element.name(), "old name");
        assert_eq!(
            element.property("legacy.value"),
            Some(&PropertyValue::String("a b&".to_owned()))
        );
        assert!(document.is_opaque(NodeId::new(1)));
        let canonical = document
            .to_canonical_bytes()
            .expect("legacy canonical output");
        let text = String::from_utf8(canonical).expect("UTF-8");
        assert!(text.contains("<LegacySampler"));
        assert!(text.contains("a+b%26"));
    }

    #[test]
    fn opaque_property_extensions_are_not_emitted_twice() {
        let source = br#"<jmeterTestPlan version="1.2" properties="5.0" jmeter="5.6.3"><hashTree><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="x" enabled="true"><mysteryProp>raw</mysteryProp><stringProp name="known">value</stringProp></TestPlan><hashTree/></hashTree></jmeterTestPlan>"#;
        let document = SemanticDocument::from_bytes(source).expect("opaque property decodes");
        let text = String::from_utf8(document.to_canonical_bytes().expect("canonical output"))
            .expect("canonical output is UTF-8");
        assert_eq!(text.matches("<mysteryProp>").count(), 1);
        let reparsed = SemanticDocument::from_bytes(text.as_bytes()).expect("output reparses");
        assert_eq!(document, reparsed);
    }

    #[test]
    fn nested_opaque_properties_keep_insertion_order_and_object_metadata() {
        let source = br#"<jmeterTestPlan version="1.2" properties="5.0" jmeter="5.6.3"><hashTree><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="x" enabled="true"><!--keep-comment--><elementProp name="nested" elementType="X"><firstExtension alpha="1"/><stringProp name="a">one</stringProp><secondExtension beta="2"/><boolProp name="b">true</boolProp></elementProp><objProp name="object"><value type="plugin.Type" extra="yes">raw &amp; bytes</value></objProp></TestPlan><hashTree/></hashTree></jmeterTestPlan>"#;
        let document = SemanticDocument::from_bytes(source).expect("nested values decode");
        let text = String::from_utf8(document.to_canonical_bytes().expect("canonical output"))
            .expect("canonical output is UTF-8");
        let first = text.find("<firstExtension").expect("first extension");
        let property_a = text.find("name=\"a\"").expect("first nested property");
        let second = text.find("<secondExtension").expect("second extension");
        let property_b = text.find("name=\"b\"").expect("second nested property");
        assert!(first < property_a && property_a < second && second < property_b);
        assert!(text.contains("<value type=\"plugin.Type\" extra=\"yes\">"));
        assert!(text.contains("<!--keep-comment-->"));
        let reparsed = SemanticDocument::from_bytes(text.as_bytes()).expect("output reparses");
        assert_eq!(document, reparsed);
    }

    #[test]
    fn canonical_encoding_accepts_unicode_extension_names() {
        let source = "<jmeterTestPlan version=\"1.2\"><hashTree><未知元素 guiclass=\"未知Gui\" testclass=\"com.example.Unknown\" testname=\"x\" enabled=\"true\"/><hashTree/></hashTree></jmeterTestPlan>";
        let document = SemanticDocument::from_bytes(source.as_bytes()).expect("unicode decodes");
        let text = String::from_utf8(document.to_canonical_bytes().expect("canonical output"))
            .expect("canonical output is UTF-8");
        assert!(text.contains("<未知元素"));
        assert!(document.is_opaque(NodeId::new(1)));
    }

    #[test]
    fn changed_property_kind_selects_a_compatible_wire_tag() {
        let source = br#"<jmeterTestPlan version="1.2"><hashTree><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="x" enabled="true"><stringProp name="value">old</stringProp></TestPlan><hashTree/></hashTree></jmeterTestPlan>"#;
        let mut document = SemanticDocument::from_bytes(source).expect("source decodes");
        document
            .tree_mut()
            .lookup_mut(NodeId::new(1))
            .expect("root element")
            .value_mut()
            .set_property("value", PropertyValue::Boolean(true));
        let output = document.to_canonical_bytes().expect("canonical output");
        let reparsed = SemanticDocument::from_bytes(&output).expect("output reparses");
        assert_eq!(
            reparsed
                .tree()
                .element(NodeId::new(1))
                .expect("root element")
                .property("value"),
            Some(&PropertyValue::Boolean(true))
        );
    }

    #[test]
    fn topology_preserves_duplicate_names_root_metadata_and_hash_tree_attributes() {
        let source = br#"<jmeterTestPlan version="1.2" properties="5.0" jmeter="5.6.3" profile="fixture"><hashTree root-extra="yes"><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="same" enabled="true"/><hashTree child-extra="first"/><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="same" enabled="false"/><hashTree/></hashTree></jmeterTestPlan>"#;
        let document = SemanticDocument::from_bytes(source).expect("topology decodes");
        assert_eq!(
            document.tree().root_ids(),
            &[NodeId::new(1), NodeId::new(2)]
        );
        assert_eq!(
            document
                .tree()
                .element(NodeId::new(1))
                .expect("first")
                .name(),
            "same"
        );
        assert!(
            !document
                .tree()
                .element(NodeId::new(2))
                .expect("second")
                .is_enabled()
        );
        assert_eq!(document.root().attribute("profile"), Some("fixture"));
        let output = String::from_utf8(document.to_canonical_bytes().expect("canonical output"))
            .expect("UTF-8 output");
        assert!(output.contains("root-extra=\"yes\""));
        assert!(output.contains("child-extra=\"first\""));
        let reparsed = SemanticDocument::from_bytes(output.as_bytes()).expect("reparse");
        assert_eq!(reparsed.tree().root_ids(), document.tree().root_ids());
        assert_eq!(
            reparsed.tree().preorder_ids(),
            document.tree().preorder_ids()
        );
    }

    #[test]
    fn all_structural_property_kinds_keep_order_empty_and_opaque_attributes() {
        let source = br#"<jmeterTestPlan version="1.2" properties="5.0" jmeter="5.6.3"><hashTree><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="typed &amp; empty" enabled="true"><stringProp name="empty"></stringProp><boolProp name="bool">false</boolProp><intProp name="int">-7</intProp><longProp name="long">922337203685477580</longProp><floatProp name="float">1.25</floatProp><doubleProp name="double">-2.5</doubleProp><collectionProp name="collection"><stringProp name="first">one</stringProp><pluginValue name="raw" ext="yes">payload</pluginValue></collectionProp><mapProp name="map"><stringProp name="key">value</stringProp></mapProp><elementProp name="nested" elementType=""><stringProp name="inner"></stringProp></elementProp><objProp name="null"/><objProp name="object"><value class="plugin.Type" extra="yes">raw &amp; bytes</value></objProp></TestPlan><hashTree/></hashTree></jmeterTestPlan>"#;
        let document = SemanticDocument::from_bytes(source).expect("typed JMX decodes");
        let element = document.tree().element(NodeId::new(1)).expect("element");
        assert_eq!(
            element.property("empty"),
            Some(&PropertyValue::String(String::new()))
        );
        assert_eq!(
            element.property("bool"),
            Some(&PropertyValue::Boolean(false))
        );
        assert_eq!(element.property("int"), Some(&PropertyValue::Integer(-7)));
        assert_eq!(
            element.property("long"),
            Some(&PropertyValue::Long(922_337_203_685_477_580))
        );
        assert_eq!(element.property("float"), Some(&PropertyValue::Float(1.25)));
        assert_eq!(
            element.property("double"),
            Some(&PropertyValue::Double(-2.5))
        );
        assert_eq!(element.property("null"), Some(&PropertyValue::Null));
        let PropertyValue::NamedCollection(entries) =
            element.property("collection").expect("collection")
        else {
            panic!("collectionProp must retain named entries");
        };
        assert_eq!(entries[0].name, "first");
        assert!(matches!(entries[1].value, PropertyValue::Opaque(_)));
        let PropertyValue::Element(nested) = element.property("nested").expect("nested") else {
            panic!("elementProp must retain nested values");
        };
        assert_eq!(nested.class_name, Some(String::new()));
        assert_eq!(
            nested.properties.get("inner"),
            Some(&PropertyValue::String(String::new()))
        );
        let output = String::from_utf8(document.to_canonical_bytes().expect("canonical output"))
            .expect("UTF-8 output");
        assert!(output.contains("<pluginValue name=\"raw\" ext=\"yes\">payload</pluginValue>"));
        assert!(
            output.contains("<value class=\"plugin.Type\" extra=\"yes\">raw &amp; bytes</value>")
        );
        let reparsed = SemanticDocument::from_bytes(output.as_bytes()).expect("reparse");
        assert_eq!(reparsed, document);
    }

    #[test]
    fn unknown_element_and_property_data_survive_edits_without_silent_loss() {
        let source = br#"<jmeterTestPlan version="1.2" properties="5.0" jmeter="5.6.3"><hashTree><MysteryPlugin guiclass="MysteryGui" testclass="com.example.Mystery" testname="unknown" enabled="true" plugin-extra="&amp;"><mysteryProp name="opaque" alpha="1">raw</mysteryProp></MysteryPlugin><hashTree/><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="known" enabled="true"><pluginProp name="x" extra="yes">raw &amp; value</pluginProp><stringProp name="known">before</stringProp></TestPlan><hashTree/></hashTree></jmeterTestPlan>"#;
        let mut document = SemanticDocument::from_bytes(source).expect("unknown JMX decodes");
        assert!(document.is_opaque(NodeId::new(1)));
        assert!(
            document
                .opaque_element_bytes(NodeId::new(1))
                .is_some_and(
                    |raw| raw.starts_with(b"<MysteryPlugin") && raw.ends_with(b"</MysteryPlugin>")
                )
        );
        let known = document
            .tree_mut()
            .lookup_mut(NodeId::new(2))
            .expect("known node")
            .value_mut();
        known.set_property("known", PropertyValue::String("after".to_owned()));
        let output = String::from_utf8(document.to_canonical_bytes().expect("canonical output"))
            .expect("UTF-8 output");
        assert!(output.contains("plugin-extra=\"&amp;\""));
        assert!(output.contains("<mysteryProp name=\"opaque\" alpha=\"1\">raw</mysteryProp>"));
        assert!(
            output.contains("<pluginProp name=\"x\" extra=\"yes\">raw &amp; value</pluginProp>")
        );
        assert!(output.contains("<stringProp name=\"known\">after</stringProp>"));
        let reparsed = SemanticDocument::from_bytes(output.as_bytes()).expect("reparse");
        assert!(reparsed.is_opaque(NodeId::new(1)));
    }

    #[test]
    fn semantic_limits_reject_elements_properties_depth_and_opaque_bytes() {
        let element_source = br#"<jmeterTestPlan version="1.2"><hashTree><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="x" enabled="true"/><hashTree/></hashTree></jmeterTestPlan>"#;
        let error = SemanticDocument::from_bytes_with_options(
            element_source,
            DecodeOptions {
                limits: DecodeLimits {
                    max_elements: 0,
                    ..DecodeLimits::default()
                },
                ..DecodeOptions::default()
            },
        )
        .expect_err("element limit");
        assert_eq!(error.code(), "jmx.semantic.limit");

        let property_source = br#"<jmeterTestPlan version="1.2"><hashTree><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="x" enabled="true"><stringProp name="one">1</stringProp><stringProp name="two">2</stringProp></TestPlan><hashTree/></hashTree></jmeterTestPlan>"#;
        let error = SemanticDocument::from_bytes_with_options(
            property_source,
            DecodeOptions {
                limits: DecodeLimits {
                    max_properties: 1,
                    ..DecodeLimits::default()
                },
                ..DecodeOptions::default()
            },
        )
        .expect_err("property limit");
        assert_eq!(error.code(), "jmx.semantic.limit");

        let nested_source = br#"<jmeterTestPlan version="1.2"><hashTree><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="x" enabled="true"><elementProp name="outer"><stringProp name="inner">x</stringProp></elementProp></TestPlan><hashTree/></hashTree></jmeterTestPlan>"#;
        let error = SemanticDocument::from_bytes_with_options(
            nested_source,
            DecodeOptions {
                limits: DecodeLimits {
                    max_property_depth: 0,
                    ..DecodeLimits::default()
                },
                ..DecodeOptions::default()
            },
        )
        .expect_err("nested depth limit");
        assert_eq!(error.code(), "jmx.semantic.limit");

        let opaque_source = br#"<jmeterTestPlan version="1.2"><hashTree><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="x" enabled="true"><unknownProp name="x">opaque</unknownProp></TestPlan><hashTree/></hashTree></jmeterTestPlan>"#;
        let error = SemanticDocument::from_bytes_with_options(
            opaque_source,
            DecodeOptions {
                limits: DecodeLimits {
                    max_opaque_bytes: 1,
                    ..DecodeLimits::default()
                },
                ..DecodeOptions::default()
            },
        )
        .expect_err("opaque byte limit");
        assert_eq!(error.code(), "jmx.semantic.limit");
    }

    #[test]
    fn upgrades_drop_only_explicitly_deleted_properties_and_retain_diagnostics() {
        let source = br#"<jmeterTestPlan version="1.2"><hashTree><JDBCDataSource guiclass="TestBeanGUI" testclass="org.apache.jmeter.protocol.jdbc.config.DataSourceElement" testname="db" enabled="true"><stringProp name="JDBCSampler.connections">old</stringProp><stringProp name="JDBCSampler.maxuse">3</stringProp></JDBCDataSource><hashTree/></hashTree></jmeterTestPlan>"#;
        let document = SemanticDocument::from_bytes(source).expect("upgrade source decodes");
        let element = document.tree().element(NodeId::new(1)).expect("element");
        assert!(element.property("JDBCSampler.connections").is_none());
        assert_eq!(
            element.property("poolMax"),
            Some(&PropertyValue::String("3".to_owned()))
        );
        assert!(
            document
                .dropped_property_bytes(NodeId::new(1), "JDBCSampler.connections")
                .is_some()
        );
        assert_eq!(
            document.dropped_property_inventory(),
            vec![DroppedProperty {
                node_id: NodeId::new(1),
                source_bytes: document
                    .dropped_property_bytes(NodeId::new(1), "JDBCSampler.connections")
                    .expect("dropped property bytes")
                    .len(),
            }]
        );
        assert!(
            document
                .diagnostics()
                .iter()
                .any(|item| item.code == "jmx.semantic.upgraded_property_dropped")
        );
        assert_eq!(
            document
                .diagnostics()
                .iter()
                .find(|item| item.code == "jmx.semantic.upgraded_property_dropped")
                .expect("dropped property diagnostic")
                .message,
            "a source property was removed by the pinned upgrade table"
        );
        let output = String::from_utf8(document.to_canonical_bytes().expect("canonical output"))
            .expect("UTF-8 output");
        assert!(!output.contains("JDBCSampler.connections"));
        assert!(output.contains("poolMax"));
    }

    #[test]
    fn duplicate_upgraded_properties_retain_each_raw_source_subtree() {
        let source = br#"<jmeterTestPlan version="1.2"><hashTree><JDBCDataSource guiclass="TestBeanGUI" testclass="org.apache.jmeter.protocol.jdbc.config.DataSourceElement" testname="db" enabled="true"><stringProp name="JDBCSampler.connections">old</stringProp><stringProp name="JDBCSampler.connections">older-value</stringProp></JDBCDataSource><hashTree/></hashTree></jmeterTestPlan>"#;
        let document = SemanticDocument::from_bytes(source).expect("duplicate upgrade source");
        let inventory = document.dropped_property_inventory();
        assert_eq!(inventory.len(), 2);
        assert_eq!(inventory[0].node_id, NodeId::new(1));
        assert_eq!(inventory[1].node_id, NodeId::new(1));
        assert!(inventory[0].source_bytes < inventory[1].source_bytes);
        assert_eq!(
            document
                .diagnostics()
                .iter()
                .filter(|item| item.code == "jmx.semantic.upgraded_property_dropped")
                .count(),
            2
        );
    }

    #[test]
    fn canonical_encoding_rejects_invalid_xml_names_and_invalid_opaque_utf8() {
        let root = SemanticRootMetadata::new("not valid", Vec::new(), Span { start: 0, end: 0 });
        let document = SemanticDocument::new(root, ElementTree::new());
        let error = document
            .to_canonical_bytes()
            .expect_err("invalid root name");
        assert_eq!(error.code(), "jmx.semantic.invalid_root");

        let root = SemanticRootMetadata::new(
            "jmeterTestPlan",
            vec![
                SemanticAttribute::new("version", "1.2"),
                SemanticAttribute::new("version", "1.2"),
            ],
            Span { start: 0, end: 0 },
        );
        let document = SemanticDocument::new(root, ElementTree::new());
        let error = document
            .to_canonical_bytes()
            .expect_err("duplicate root attributes");
        assert_eq!(error.code(), "jmx.semantic.duplicate_metadata");

        let source = br#"<jmeterTestPlan version="1.2"><hashTree><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="x" enabled="true"><stringProp name="x">value</stringProp></TestPlan><hashTree/></hashTree></jmeterTestPlan>"#;
        let mut document = SemanticDocument::from_bytes(source).expect("source decodes");
        document
            .tree_mut()
            .lookup_mut(NodeId::new(1))
            .expect("element")
            .value_mut()
            .set_property("x", PropertyValue::opaque("plugin.Value", vec![0xFF]));
        let error = document
            .to_canonical_bytes()
            .expect_err("invalid opaque UTF-8");
        assert_eq!(error.code(), "jmx.semantic.encode");
    }

    #[test]
    fn edited_properties_follow_model_order_around_opaque_source_slots() {
        let source = br#"<jmeterTestPlan version="1.2"><hashTree><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="x" enabled="true"><stringProp name="a">a</stringProp><extensionNode flag="keep"/><stringProp name="b">b</stringProp></TestPlan><hashTree/></hashTree></jmeterTestPlan>"#;
        let mut document = SemanticDocument::from_bytes(source).expect("source decodes");
        let element = document
            .tree_mut()
            .lookup_mut(NodeId::new(1))
            .expect("element")
            .value_mut();
        element.remove_property("a");
        element.set_property("a", PropertyValue::String("edited".to_owned()));
        let text = String::from_utf8(document.to_canonical_bytes().expect("canonical output"))
            .expect("UTF-8 output");
        let b = text.find("name=\"b\"").expect("b property");
        let extension = text.find("<extensionNode").expect("opaque extension");
        let a = text.find("name=\"a\"").expect("reinserted a property");
        assert!(b < extension && extension < a);
        let reparsed = SemanticDocument::from_bytes(text.as_bytes()).expect("output reparses");
        assert_eq!(
            reparsed
                .tree()
                .element(NodeId::new(1))
                .expect("element")
                .properties
                .keys()
                .collect::<Vec<_>>(),
            vec!["b", "a"]
        );
    }

    #[test]
    fn positional_collection_children_remain_unnamed_and_typed() {
        let source = br#"<jmeterTestPlan version="1.2"><hashTree><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="x" enabled="true"><collectionProp name="values"><stringProp>one</stringProp><intProp>2</intProp><elementProp elementType="Pair"><stringProp name="part">three</stringProp></elementProp></collectionProp></TestPlan><hashTree/></hashTree></jmeterTestPlan>"#;
        let document = SemanticDocument::from_bytes(source).expect("positional collection decodes");
        let element = document.tree().element(NodeId::new(1)).expect("element");
        assert_eq!(
            element.property("values"),
            Some(&PropertyValue::Collection(vec![
                PropertyValue::String("one".to_owned()),
                PropertyValue::Integer(2),
                PropertyValue::Element({
                    let mut nested = ElementProperty::new("2");
                    nested
                        .properties
                        .try_insert("part", PropertyValue::String("three".to_owned()))
                        .expect("nested property");
                    nested.with_class_name("Pair")
                }),
            ]))
        );
        let text = String::from_utf8(document.to_canonical_bytes().expect("canonical output"))
            .expect("UTF-8 output");
        assert!(text.contains("<stringProp>one</stringProp>"));
        assert!(text.contains("<intProp>2</intProp>"));
        assert!(text.contains("<elementProp elementType=\"Pair\">"));
        assert!(!text.contains("<stringProp name=\"0\">"));
        let reparsed = SemanticDocument::from_bytes(text.as_bytes()).expect("output reparses");
        assert_eq!(reparsed, document);
    }

    #[test]
    fn nested_object_payload_and_metadata_are_preserved_and_validated() {
        let source = br#"<jmeterTestPlan version="1.2"><hashTree><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="x" enabled="true"><objProp name="object"><value type="plugin.Type" custom="yes"><payload attr="v">text</payload><!--keep--></value></objProp></TestPlan><hashTree/></hashTree></jmeterTestPlan>"#;
        let document = SemanticDocument::from_bytes(source).expect("nested object decodes");
        let element = document.tree().element(NodeId::new(1)).expect("element");
        let PropertyValue::Object(object) = element.property("object").expect("object") else {
            panic!("object property expected");
        };
        assert!(object.is_opaque_xml());
        assert_eq!(object.class_name, Some("plugin.Type".to_owned()));
        assert_eq!(object.raw, b"<payload attr=\"v\">text</payload><!--keep-->");
        assert_eq!(object.attributes[0].name, "type");
        let text = String::from_utf8(document.to_canonical_bytes().expect("canonical output"))
            .expect("UTF-8 output");
        assert!(text.contains(
            "<value type=\"plugin.Type\" custom=\"yes\"><payload attr=\"v\">text</payload><!--keep--></value>"
        ));
        let reparsed = SemanticDocument::from_bytes(text.as_bytes()).expect("output reparses");
        assert_eq!(reparsed, document);

        let mut edited = document.clone();
        let PropertyValue::Object(object) = edited
            .tree_mut()
            .lookup_mut(NodeId::new(1))
            .expect("element")
            .value_mut()
            .properties
            .get_mut("object")
            .expect("object property")
        else {
            panic!("object property expected");
        };
        object.class_name = Some("new.Type".to_owned());
        let edited_text = String::from_utf8(edited.to_canonical_bytes().expect("edited output"))
            .expect("UTF-8 output");
        assert!(edited_text.contains("<value class=\"new.Type\" custom=\"yes\"><payload"));
        assert!(!edited_text.contains("plugin.Type"));

        let mut explicitly_empty = document.clone();
        let PropertyValue::Object(object) = explicitly_empty
            .tree_mut()
            .lookup_mut(NodeId::new(1))
            .expect("element")
            .value_mut()
            .properties
            .get_mut("object")
            .expect("object property")
        else {
            panic!("object property expected");
        };
        object.class_name = Some(String::new());
        let explicitly_empty_text = String::from_utf8(
            explicitly_empty
                .to_canonical_bytes()
                .expect("explicitly empty class output"),
        )
        .expect("UTF-8 output");
        assert!(explicitly_empty_text.contains("<value class=\"\" custom=\"yes\"><payload"));
        assert!(!explicitly_empty_text.contains("type=\"plugin.Type\""));
        let explicitly_empty_reparsed =
            SemanticDocument::from_bytes(explicitly_empty_text.as_bytes()).expect("reparse");
        let PropertyValue::Object(reparsed_object) = explicitly_empty_reparsed
            .tree()
            .element(NodeId::new(1))
            .expect("element")
            .property("object")
            .expect("object property")
        else {
            panic!("object property expected after reparse");
        };
        assert_eq!(reparsed_object.class_name, Some(String::new()));

        let mut replaced = document.clone();
        replaced
            .tree_mut()
            .lookup_mut(NodeId::new(1))
            .expect("element")
            .value_mut()
            .set_property(
                "object",
                PropertyValue::Object(jmeter_rs_model::ObjectProperty::new("new.Type", "text")),
            );
        let replaced_text =
            String::from_utf8(replaced.to_canonical_bytes().expect("replaced output"))
                .expect("UTF-8 output");
        assert!(replaced_text.contains("<value class=\"new.Type\">text</value>"));
        assert!(!replaced_text.contains("plugin.Type"));

        let mut invalid = document;
        invalid
            .tree_mut()
            .lookup_mut(NodeId::new(1))
            .expect("element")
            .value_mut()
            .set_property(
                "object",
                PropertyValue::Object(jmeter_rs_model::ObjectProperty::opaque_xml(
                    "plugin.Type",
                    b"<broken".to_vec(),
                    Vec::new(),
                )),
            );
        let error = invalid
            .to_canonical_bytes()
            .expect_err("invalid opaque object XML");
        assert_eq!(error.code(), "jmx.semantic.encode");
    }

    #[test]
    fn canonical_encoding_rejects_xml_controls_and_invalid_wrapper_versions() {
        let source = br#"<jmeterTestPlan version="1.2"><hashTree><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="x" enabled="true"><stringProp name="x">value</stringProp></TestPlan><hashTree/></hashTree></jmeterTestPlan>"#;
        let mut document = SemanticDocument::from_bytes(source).expect("source decodes");
        document
            .tree_mut()
            .lookup_mut(NodeId::new(1))
            .expect("element")
            .value_mut()
            .set_property("x", PropertyValue::String("bad\u{1}".to_owned()));
        let error = document
            .to_canonical_bytes()
            .expect_err("XML control must be rejected");
        assert_eq!(error.code(), "jmx.semantic.encode");

        let root = SemanticRootMetadata::new(
            "jmeterTestPlan",
            vec![SemanticAttribute::new("version", "9.9")],
            Span { start: 0, end: 0 },
        );
        let error = SemanticDocument::new(root, ElementTree::new())
            .to_canonical_bytes()
            .expect_err("unsupported wrapper version");
        assert_eq!(error.code(), "jmx.semantic.root_metadata");

        let mut invalid_opaque = SemanticDocument::from_bytes(source).expect("source decodes");
        invalid_opaque
            .tree_mut()
            .lookup_mut(NodeId::new(1))
            .expect("element")
            .value_mut()
            .set_property(
                "x",
                PropertyValue::opaque("plugin.Value", b"<broken".to_vec()),
            );
        let error = invalid_opaque
            .to_canonical_bytes()
            .expect_err("invalid opaque XML must be rejected");
        assert_eq!(error.code(), "jmx.semantic.encode");
    }

    #[test]
    fn canonical_encoder_bounds_programmatic_nested_values() {
        let mut value = PropertyValue::String("leaf".to_owned());
        for index in 0..(MAX_ENCODER_DEPTH + 8) {
            let mut nested = ElementProperty::new(format!("nested-{index}"));
            nested
                .properties
                .try_insert("child", value)
                .expect("fresh nested child");
            value = PropertyValue::Element(nested);
        }
        let mut element = TestElement::new(ElementMetadata::new("TestPlan", "TestPlanGui", "x"));
        element.set_property("deep", value);
        let mut tree = ElementTree::new();
        tree.insert(None, element).expect("root element");
        let document = SemanticDocument::new(
            SemanticRootMetadata::new(
                "jmeterTestPlan",
                vec![SemanticAttribute::new("version", "1.2")],
                Span { start: 0, end: 0 },
            ),
            tree,
        );
        let error = document
            .to_canonical_bytes()
            .expect_err("encoder depth limit");
        assert_eq!(error.code(), "jmx.semantic.limit");
    }

    #[test]
    fn programmatic_preorder_inventory_is_bounded_before_allocation() {
        let mut tree = ElementTree::new();
        tree.insert(
            None,
            TestElement::new(ElementMetadata::new("TestPlan", "TestPlanGui", "x")),
        )
        .expect("root element");
        let error = bounded_preorder_ids(&tree, 0).expect_err("zero-node budget");
        assert_eq!(error.code(), "jmx.semantic.limit");
    }

    #[test]
    fn canonical_encoder_rejects_oversized_programmatic_trees_before_validation() {
        let mut tree = ElementTree::new();
        let metadata = ElementMetadata::new("TestPlan", "TestPlanGui", "x");
        for _ in 0..=MAX_ENCODER_NODES {
            tree.insert(None, TestElement::new(metadata.clone()))
                .expect("programmatic root element");
        }
        let document = SemanticDocument::new(
            SemanticRootMetadata::new(
                "jmeterTestPlan",
                vec![SemanticAttribute::new("version", "1.2")],
                Span { start: 0, end: 0 },
            ),
            tree,
        );
        let error = document
            .to_canonical_bytes()
            .expect_err("oversized tree must be bounded before validation");
        assert_eq!(error.code(), "jmx.semantic.limit");
    }

    #[test]
    fn semantic_property_comparison_reports_deep_programmatic_values() {
        let mut value = PropertyValue::String("leaf".to_owned());
        for index in 0..(MAX_ENCODER_DEPTH + 8) {
            let mut nested = ElementProperty::new(format!("nested-{index}"));
            nested
                .properties
                .try_insert("child", value)
                .expect("fresh nested child");
            value = PropertyValue::Element(nested);
        }
        let mut tree = ElementTree::new();
        let mut element = TestElement::new(ElementMetadata::new("TestPlan", "TestPlanGui", "x"));
        element.set_property("deep", value);
        tree.insert(None, element).expect("root element");
        let root = SemanticRootMetadata::new(
            "jmeterTestPlan",
            vec![SemanticAttribute::new("version", "1.2")],
            Span { start: 0, end: 0 },
        );
        let left = SemanticDocument::new(root.clone(), tree.clone());
        let right = SemanticDocument::new(root, tree);
        let error = left
            .try_semantic_eq(&right)
            .expect_err("deep comparison must return a typed limit");
        assert_eq!(error.code(), "jmx.semantic.limit");
        assert!(!left.semantic_eq(&right));
    }

    #[test]
    fn disabled_and_absent_nodes_are_not_executable() {
        let source = br#"<jmeterTestPlan version="1.2"><hashTree><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="disabled" enabled="false"/><hashTree/></hashTree></jmeterTestPlan>"#;
        let document = SemanticDocument::from_bytes(source).expect("source decodes");
        assert!(!document.is_executable(NodeId::new(1)));
        assert!(!document.is_executable(NodeId::new(999)));
    }

    #[test]
    fn semantic_decode_rejects_unknown_wrapper_versions_and_empty_metadata() {
        let version = br#"<jmeterTestPlan version="9.9"><hashTree/></jmeterTestPlan>"#;
        let error = SemanticDocument::from_bytes(version).expect_err("version is unsupported");
        assert_eq!(error.code(), "jmx.semantic.root_metadata");
        let missing_version = br#"<jmeterTestPlan><hashTree/></jmeterTestPlan>"#;
        let error = SemanticDocument::from_bytes(missing_version).expect_err("version is required");
        assert_eq!(error.code(), "jmx.semantic.root_metadata");
        let empty_metadata = br#"<jmeterTestPlan version="1.2"><hashTree><TestPlan guiclass="" testclass="TestPlan" testname="x" enabled="true"/><hashTree/></hashTree></jmeterTestPlan>"#;
        let error = SemanticDocument::from_bytes(empty_metadata).expect_err("metadata is nonempty");
        assert_eq!(error.code(), "jmx.semantic.missing_metadata");
    }

    #[test]
    fn known_testclass_under_nonprofile_tag_remains_opaque() {
        let source = br#"<jmeterTestPlan version="1.2"><hashTree><NotAProfileAlias guiclass="TestPlanGui" testclass="TestPlan" testname="x" enabled="true"/><hashTree/></hashTree></jmeterTestPlan>"#;
        let document = SemanticDocument::from_bytes(source).expect("well-formed unknown tag");
        assert!(document.is_opaque(NodeId::new(1)));
        let output = String::from_utf8(document.to_canonical_bytes().expect("canonical output"))
            .expect("UTF-8 output");
        assert!(output.contains("<NotAProfileAlias"));
        assert!(!output.contains("<TestPlan guiclass"));
    }

    #[test]
    fn absent_object_value_class_metadata_is_not_invented() {
        let source = br#"<jmeterTestPlan version="1.2"><hashTree><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="x" enabled="true"><objProp name="object"><value>raw</value></objProp></TestPlan><hashTree/></hashTree></jmeterTestPlan>"#;
        let document = SemanticDocument::from_bytes(source).expect("object decodes");
        let output = String::from_utf8(document.to_canonical_bytes().expect("canonical output"))
            .expect("UTF-8 output");
        assert!(output.contains("<value>raw</value>"));
        assert!(!output.contains("class=\"\""));
    }

    #[test]
    fn java_nonfinite_float_spellings_round_trip_with_nan_semantics() {
        let source = br#"<jmeterTestPlan version="1.2"><hashTree><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="x" enabled="true"><floatProp name="nan">NaN</floatProp><floatProp name="inf">Infinity</floatProp><floatProp name="neginf">-Infinity</floatProp><doubleProp name="doubleNan">NaN</doubleProp><doubleProp name="doubleInf">Infinity</doubleProp></TestPlan><hashTree/></hashTree></jmeterTestPlan>"#;
        let document = SemanticDocument::from_bytes(source).expect("Java values decode");
        let element = document.tree().element(NodeId::new(1)).expect("element");
        assert!(
            matches!(element.property("nan"), Some(PropertyValue::Float(value)) if value.is_nan())
        );
        assert_eq!(
            element.property("inf"),
            Some(&PropertyValue::Float(f32::INFINITY))
        );
        assert_eq!(
            element.property("neginf"),
            Some(&PropertyValue::Float(f32::NEG_INFINITY))
        );
        let output = String::from_utf8(document.to_canonical_bytes().expect("canonical output"))
            .expect("UTF-8 output");
        assert!(output.contains(">NaN</floatProp>"));
        assert!(output.contains(">Infinity</floatProp>"));
        assert!(output.contains(">-Infinity</floatProp>"));
        let reparsed = SemanticDocument::from_bytes(output.as_bytes()).expect("reparse");
        assert_eq!(document, reparsed);
    }

    #[test]
    fn direct_nonwhitespace_text_is_rejected_without_xml_text_extension() {
        let source = br#"<jmeterTestPlan version="1.2"><hashTree><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="x" enabled="true">direct text</TestPlan><hashTree/></hashTree></jmeterTestPlan>"#;
        let error = SemanticDocument::from_bytes(source).expect_err("direct text is unsupported");
        assert_eq!(error.code(), "jmx.semantic.unsupported");
        let cdata = br#"<jmeterTestPlan version="1.2"><hashTree><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="x" enabled="true"><![CDATA[direct text]]></TestPlan><hashTree/></hashTree></jmeterTestPlan>"#;
        let error = SemanticDocument::from_bytes(cdata).expect_err("direct CDATA is unsupported");
        assert_eq!(error.code(), "jmx.semantic.unsupported");
    }

    #[test]
    fn object_property_rejects_unrepresentable_lexical_children() {
        let cases = [
            ("text<value>raw</value>", "jmx.semantic.invalid_property"),
            (
                "<![CDATA[text]]><value>raw</value>",
                "jmx.semantic.invalid_property",
            ),
            (
                "<!--around--><value>raw</value>",
                "jmx.semantic.unsupported",
            ),
            (
                "<value>raw<!--inside--></value>",
                "jmx.semantic.unsupported",
            ),
            (
                "<value>raw<?inside yes?></value>",
                "jmx.semantic.unsupported",
            ),
            ("<value><![CDATA[raw]]></value>", "jmx.semantic.unsupported"),
        ];
        for (body, code) in cases {
            let source = format!(
                r#"<jmeterTestPlan version="1.2"><hashTree><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="x" enabled="true"><objProp name="object">{body}</objProp></TestPlan><hashTree/></hashTree></jmeterTestPlan>"#
            );
            let error = SemanticDocument::from_bytes(source.as_bytes())
                .expect_err("unrepresentable object lexical child must be rejected");
            assert_eq!(error.code(), code, "body {body:?}");
        }
    }

    #[test]
    fn whitespace_cdata_is_structural_formatting_and_normalized() {
        let source = br#"<jmeterTestPlan version="1.2"><hashTree><![CDATA[
 ]]><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="x" enabled="true"><![CDATA[	 ]]><objProp name="object"><![CDATA[ ]]><value>raw</value><![CDATA[
 ]]></objProp><![CDATA[ ]]></TestPlan><hashTree><![CDATA[	 ]]></hashTree><![CDATA[ ]]></hashTree></jmeterTestPlan>"#;
        let document =
            SemanticDocument::from_bytes(source).expect("whitespace CDATA is formatting");
        assert!(document.root_extensions().is_empty());
        assert!(document.root_hash_tree_extensions().is_empty());
        let output = String::from_utf8(document.to_canonical_bytes().expect("canonical output"))
            .expect("UTF-8 output");
        assert!(!output.contains("<![CDATA["));
        let reparsed = SemanticDocument::from_bytes(output.as_bytes()).expect("output reparses");
        assert_eq!(document, reparsed);
    }

    #[test]
    fn decoder_opaque_limit_is_aggregate_across_retained_forms() {
        let wrapper_and_tree_comments = br#"<jmeterTestPlan version="1.2"><!--root--><hashTree><!--tree--><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="x" enabled="true"/><hashTree/></hashTree></jmeterTestPlan>"#;
        let error = SemanticDocument::from_bytes_with_options(
            wrapper_and_tree_comments,
            DecodeOptions {
                limits: DecodeLimits {
                    max_opaque_bytes: 16,
                    ..DecodeLimits::default()
                },
                ..DecodeOptions::default()
            },
        )
        .expect_err("wrapper and hashTree extensions share one byte bound");
        assert_eq!(error.code(), "jmx.semantic.limit");

        let lexical_property = br#"<jmeterTestPlan version="1.2"><hashTree><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="x" enabled="true"><stringProp name="value"><![CDATA[payload]]></stringProp></TestPlan><hashTree/></hashTree></jmeterTestPlan>"#;
        let error = SemanticDocument::from_bytes_with_options(
            lexical_property,
            DecodeOptions {
                limits: DecodeLimits {
                    max_opaque_bytes: 1,
                    ..DecodeLimits::default()
                },
                ..DecodeOptions::default()
            },
        )
        .expect_err("lexical raw property bytes are bounded");
        assert_eq!(error.code(), "jmx.semantic.limit");

        let object_payload = br#"<jmeterTestPlan version="1.2"><hashTree><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="x" enabled="true"><objProp name="object"><value>payload</value></objProp></TestPlan><hashTree/></hashTree></jmeterTestPlan>"#;
        let error = SemanticDocument::from_bytes_with_options(
            object_payload,
            DecodeOptions {
                limits: DecodeLimits {
                    max_opaque_bytes: 1,
                    ..DecodeLimits::default()
                },
                ..DecodeOptions::default()
            },
        )
        .expect_err("object payload bytes are bounded");
        assert_eq!(error.code(), "jmx.semantic.limit");

        let nested_object_payload = br#"<jmeterTestPlan version="1.2"><hashTree><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="x" enabled="true"><objProp name="object"><value><payload>payload</payload></value></objProp></TestPlan><hashTree/></hashTree></jmeterTestPlan>"#;
        let error = SemanticDocument::from_bytes_with_options(
            nested_object_payload,
            DecodeOptions {
                limits: DecodeLimits {
                    max_opaque_bytes: 1,
                    ..DecodeLimits::default()
                },
                ..DecodeOptions::default()
            },
        )
        .expect_err("nested object payload bytes are bounded");
        assert_eq!(error.code(), "jmx.semantic.limit");
    }

    #[test]
    fn decoder_opaque_budget_charges_overlapping_parent_and_child_slots_once_each() {
        let opaque_element = br#"<MysteryPlugin guiclass="MysteryGui" testclass="com.example.Mystery" testname="x" enabled="true"><!--child--></MysteryPlugin>"#;
        let source = [
            &br#"<jmeterTestPlan version="1.2"><hashTree>"#[..],
            &opaque_element[..],
            &br#"<hashTree/></hashTree></jmeterTestPlan>"#[..],
        ]
        .concat();
        let child_comment = b"<!--child-->";
        let expected = opaque_element.len() + child_comment.len();
        let document = SemanticDocument::from_bytes_with_options(
            &source,
            DecodeOptions {
                limits: DecodeLimits {
                    max_opaque_bytes: expected,
                    ..DecodeLimits::default()
                },
                ..DecodeOptions::default()
            },
        )
        .expect("parent and child payload slots fit exactly");
        assert!(document.is_opaque(NodeId::new(1)));

        let error = SemanticDocument::from_bytes_with_options(
            &source,
            DecodeOptions {
                limits: DecodeLimits {
                    max_opaque_bytes: expected.saturating_sub(1),
                    ..DecodeLimits::default()
                },
                ..DecodeOptions::default()
            },
        )
        .expect_err("overlapping parent and child slots share one aggregate budget");
        assert_eq!(error.code(), "jmx.semantic.limit");
    }

    #[test]
    fn deterministic_generated_duplicate_maps_round_trip_semantically() {
        fn next(state: &mut u64) -> u64 {
            *state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            *state
        }

        let names = ["alpha", "beta", "alpha", "gamma"];
        for seed in 0..32_u64 {
            let mut state = seed + 1;
            let count = 1 + (next(&mut state) % 7) as usize;
            let mut entries = String::new();
            for index in 0..count {
                let name = names[(next(&mut state) % names.len() as u64) as usize];
                let marker = next(&mut state) % 10_000;
                entries.push_str(&format!(
                    r#"<stringProp name="{name}" marker="m{marker}">v{index}</stringProp>"#
                ));
            }
            let source = format!(
                r#"<jmeterTestPlan version="1.2"><hashTree><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="x" enabled="true"><mapProp name="generated">{entries}</mapProp></TestPlan><hashTree/></hashTree></jmeterTestPlan>"#
            );
            let document = SemanticDocument::from_bytes(source.as_bytes())
                .expect("deterministic generated map is valid");
            let output = document.to_canonical_bytes().expect("canonical output");
            let reparsed =
                SemanticDocument::from_bytes(&output).expect("canonical output reparses");
            assert_eq!(document, reparsed, "seed {seed}");
        }
    }

    #[test]
    fn wrapper_and_hash_tree_comments_and_processing_instructions_are_preserved() {
        let source = br#"<?xml version="1.0"?><jmeterTestPlan version="1.2"><!--root--><?root-pi yes?><hashTree><!--tree--><?tree-pi yes?><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="x" enabled="true"><!--element--><?element-pi yes?><stringProp name="value"><![CDATA[value]]></stringProp></TestPlan><hashTree/></hashTree></jmeterTestPlan>"#;
        let document = SemanticDocument::from_bytes(source).expect("extensions decode");
        assert_eq!(document.root_extensions().len(), 2);
        assert_eq!(document.root_hash_tree_extensions().len(), 2);
        let output = String::from_utf8(document.to_canonical_bytes().expect("canonical output"))
            .expect("UTF-8 output");
        for marker in [
            "<!--root-->",
            "<?root-pi yes?>",
            "<!--tree-->",
            "<?tree-pi yes?>",
            "<!--element-->",
            "<?element-pi yes?>",
            "<![CDATA[value]]>",
        ] {
            assert!(output.contains(marker), "missing extension {marker}");
        }
    }

    #[test]
    fn duplicate_named_and_positional_entries_follow_source_values_on_reorder() {
        let source = br#"<jmeterTestPlan version="1.2"><hashTree><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="x" enabled="true"><mapProp name="mapped"><pluginValue name="same" marker="first">one</pluginValue><pluginValue name="same" marker="second">two</pluginValue></mapProp><collectionProp name="positional"><pluginValue marker="p-first">one</pluginValue><pluginValue marker="p-second">two</pluginValue></collectionProp></TestPlan><hashTree/></hashTree></jmeterTestPlan>"#;
        let mut document = SemanticDocument::from_bytes(source).expect("duplicate entries decode");
        let element = document
            .tree_mut()
            .lookup_mut(NodeId::new(1))
            .expect("element")
            .value_mut();
        let PropertyValue::Map(mapped) =
            element.properties.get_mut("mapped").expect("map property")
        else {
            panic!("map expected");
        };
        mapped.swap(0, 1);
        let PropertyValue::Collection(positional) = element
            .properties
            .get_mut("positional")
            .expect("collection property")
        else {
            panic!("collection expected");
        };
        positional.swap(0, 1);
        let output = String::from_utf8(document.to_canonical_bytes().expect("canonical output"))
            .expect("UTF-8 output");
        let second = output.find("marker=\"second\"").expect("map second");
        let first = output.find("marker=\"first\"").expect("map first");
        assert!(second < first, "map metadata followed the value reorder");
        let positional_second = output.find("marker=\"p-second\"").expect("position second");
        let positional_first = output.find("marker=\"p-first\"").expect("position first");
        assert!(
            positional_second < positional_first,
            "positional metadata followed the value reorder"
        );

        let mut removed = SemanticDocument::from_bytes(source).expect("duplicate entries decode");
        let element = removed
            .tree_mut()
            .lookup_mut(NodeId::new(1))
            .expect("element")
            .value_mut();
        let PropertyValue::Map(mapped) =
            element.properties.get_mut("mapped").expect("map property")
        else {
            panic!("map expected");
        };
        mapped.remove(0);
        let PropertyValue::Collection(positional) = element
            .properties
            .get_mut("positional")
            .expect("collection property")
        else {
            panic!("collection expected");
        };
        positional.remove(0);
        let removed_output = String::from_utf8(
            removed
                .to_canonical_bytes()
                .expect("canonical output after removal"),
        )
        .expect("UTF-8 output");
        assert!(!removed_output.contains("marker=\"first\""));
        assert!(removed_output.contains("marker=\"second\""));
        assert!(!removed_output.contains("marker=\"p-first\""));
        assert!(removed_output.contains("marker=\"p-second\""));
    }

    #[test]
    fn duplicate_identical_opaque_extensions_are_emitted_by_occurrence() {
        let source = br#"<jmeterTestPlan version="1.2"><hashTree><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="x" enabled="true"><extensionNode/><extensionNode/></TestPlan><hashTree/></hashTree></jmeterTestPlan>"#;
        let mut document = SemanticDocument::from_bytes(source).expect("extensions decode");
        let element = document
            .tree_mut()
            .lookup_mut(NodeId::new(1))
            .expect("element")
            .value_mut();
        assert_eq!(element.opaque_extensions.len(), 2);
        element.opaque_extensions.remove(0);
        let output = String::from_utf8(document.to_canonical_bytes().expect("canonical output"))
            .expect("UTF-8 output");
        assert_eq!(output.matches("<extensionNode/>").count(), 1);
    }

    #[test]
    fn ambiguous_identical_duplicate_metadata_returns_unsupported_after_removal() {
        let source = br#"<jmeterTestPlan version="1.2"><hashTree><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="x" enabled="true"><mapProp name="mapped"><stringProp name="same" marker="first">same</stringProp><stringProp name="same" marker="second">same</stringProp></mapProp></TestPlan><hashTree/></hashTree></jmeterTestPlan>"#;
        let mut document = SemanticDocument::from_bytes(source).expect("duplicate entries decode");
        let element = document
            .tree_mut()
            .lookup_mut(NodeId::new(1))
            .expect("element")
            .value_mut();
        let PropertyValue::Map(mapped) =
            element.properties.get_mut("mapped").expect("map property")
        else {
            panic!("map expected");
        };
        mapped.remove(0);
        let error = document
            .to_canonical_bytes()
            .expect_err("ambiguous occurrence must not be reinterpreted");
        assert_eq!(error.code(), "jmx.semantic.unsupported");
    }

    #[test]
    fn semantic_tree_depth_limit_is_independent_of_xml_parser_depth() {
        let source = br#"<jmeterTestPlan version="1.2"><hashTree><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="outer" enabled="true"/><hashTree><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="inner" enabled="true"/><hashTree/></hashTree></hashTree></jmeterTestPlan>"#;
        let error = SemanticDocument::from_bytes_with_options(
            source,
            DecodeOptions {
                limits: DecodeLimits {
                    max_tree_depth: 0,
                    ..DecodeLimits::default()
                },
                ..DecodeOptions::default()
            },
        )
        .expect_err("nested semantic tree exceeds bound");
        assert_eq!(error.code(), "jmx.semantic.limit");
    }

    #[test]
    fn alias_equivalent_wire_tags_compare_equal_after_canonicalization() {
        let source = br#"<jmeterTestPlan version="1.2"><hashTree><HTTPSampler2 guiclass="HttpTestSampleGui" testclass="HTTPSampler2" testname="x" enabled="true"/><hashTree/></hashTree></jmeterTestPlan>"#;
        let document = SemanticDocument::from_bytes(source).expect("historical alias decodes");
        let output = document.to_canonical_bytes().expect("canonical output");
        let reparsed = SemanticDocument::from_bytes(&output).expect("reparse");
        assert_eq!(document, reparsed);
        assert!(document.semantic_eq(&reparsed));
        assert!(!document.wire_eq(&reparsed));
    }

    #[test]
    fn encoder_bounds_aggregate_programmatic_opaque_bytes() {
        let mut element = TestElement::new(ElementMetadata::new("TestPlan", "TestPlanGui", "x"));
        element.push_opaque_extension(OpaqueValue::new(
            "extension",
            vec![b'x'; MAX_ENCODER_OPAQUE_BYTES / 2 + 1],
        ));
        element.push_opaque_extension(OpaqueValue::new(
            "extension",
            vec![b'y'; MAX_ENCODER_OPAQUE_BYTES / 2 + 1],
        ));
        let mut tree = ElementTree::new();
        tree.insert(None, element).expect("element insertion");
        let document = SemanticDocument::new(
            SemanticRootMetadata::new(
                "jmeterTestPlan",
                vec![SemanticAttribute::new("version", "1.2")],
                Span { start: 0, end: 0 },
            ),
            tree,
        );
        let error = document
            .to_canonical_bytes()
            .expect_err("aggregate opaque bytes are bounded");
        assert_eq!(error.code(), "jmx.semantic.limit");
    }

    #[test]
    fn encoder_accounting_limits_are_atomic_for_entries_metadata_and_output() {
        let document = SemanticDocument::new(
            SemanticRootMetadata::new(
                "jmeterTestPlan",
                vec![SemanticAttribute::new("version", "1.2")],
                Span { start: 0, end: 0 },
            ),
            ElementTree::new(),
        );
        let mut output = Vec::new();

        {
            let mut encoder = Encoder::new(&document, &mut output);
            encoder.entries_written = MAX_ENCODER_ENTRIES;
            let error = encoder
                .account_entries(1)
                .expect_err("entry limit must reject atomically");
            assert_eq!(error.code(), "jmx.semantic.limit");
            assert_eq!(encoder.entries_written, MAX_ENCODER_ENTRIES);
        }

        {
            let mut encoder = Encoder::new(&document, &mut output);
            encoder.metadata_written = MAX_ENCODER_METADATA;
            let error = encoder
                .account_metadata(0)
                .expect_err("metadata count limit must reject atomically");
            assert_eq!(error.code(), "jmx.semantic.limit");
            assert_eq!(encoder.metadata_written, MAX_ENCODER_METADATA);
            assert_eq!(encoder.metadata_bytes, 0);
        }

        {
            let mut encoder = Encoder::new(&document, &mut output);
            encoder.metadata_bytes = MAX_ENCODER_METADATA_BYTES;
            let error = encoder
                .account_metadata(1)
                .expect_err("metadata byte limit must reject atomically");
            assert_eq!(error.code(), "jmx.semantic.limit");
            assert_eq!(encoder.metadata_written, 0);
            assert_eq!(encoder.metadata_bytes, MAX_ENCODER_METADATA_BYTES);
        }

        {
            let mut encoder = Encoder::new(&document, &mut output);
            encoder.output_bytes = MAX_ENCODER_OUTPUT_BYTES;
            let error = encoder
                .write_raw(b"overflow")
                .expect_err("output limit must reject before writing");
            assert_eq!(error.code(), "jmx.semantic.limit");
            assert_eq!(encoder.output_bytes, MAX_ENCODER_OUTPUT_BYTES);
        }

        assert!(output.is_empty(), "failed accounting must not write output");
    }

    #[test]
    fn topology_extensions_retain_exact_interleaving_across_nested_hash_trees() {
        let source = br#"<jmeterTestPlan version="1.2"><!--root-before--><?root-before yes?><hashTree><!--tree-before--><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="outer" enabled="true"/><!--between--><?between yes?><hashTree><!--nested-before--><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="inner" enabled="true"/><hashTree/><!--nested-after--></hashTree><!--tree-after--></hashTree><!--root-after--><?root-after yes?></jmeterTestPlan>"#;
        let document = SemanticDocument::from_bytes(source).expect("interleaved source");
        assert_eq!(
            document.root_events(),
            &[
                SemanticEvent::Extension(OpaqueValue::new(
                    "xml:comment",
                    b"<!--root-before-->".to_vec(),
                )),
                SemanticEvent::Extension(OpaqueValue::new(
                    "xml:processing-instruction",
                    b"<?root-before yes?>".to_vec(),
                )),
                SemanticEvent::RootHashTree,
                SemanticEvent::Extension(OpaqueValue::new(
                    "xml:comment",
                    b"<!--root-after-->".to_vec(),
                )),
                SemanticEvent::Extension(OpaqueValue::new(
                    "xml:processing-instruction",
                    b"<?root-after yes?>".to_vec(),
                )),
            ]
        );
        let output = String::from_utf8(document.to_canonical_bytes().expect("canonical output"))
            .expect("UTF-8 output");
        let markers = [
            "<!--root-before-->",
            "<?root-before yes?>",
            "<!--tree-before-->",
            "<TestPlan",
            "<!--between-->",
            "<?between yes?>",
            "<!--nested-before-->",
            "testname=\"inner\"",
            "<!--nested-after-->",
            "<!--tree-after-->",
            "<!--root-after-->",
            "<?root-after yes?>",
        ];
        let mut previous = 0;
        for marker in markers {
            let position = output.find(marker).expect("marker is retained");
            assert!(position >= previous, "marker order changed at {marker}");
            previous = position;
        }
        let reparsed = SemanticDocument::from_bytes(output.as_bytes()).expect("reparse");
        assert_eq!(document, reparsed);
    }

    #[test]
    fn topology_cdata_is_retained_and_duplicate_extensions_are_not_normalized() {
        let source = br#"<jmeterTestPlan version="1.2"><hashTree><![CDATA[before]]><!--same--><!--same--><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="x" enabled="true"/><hashTree/><?after yes?></hashTree></jmeterTestPlan>"#;
        let document = SemanticDocument::from_bytes(source).expect("CDATA source");
        let output = String::from_utf8(document.to_canonical_bytes().expect("canonical output"))
            .expect("UTF-8 output");
        assert!(output.contains("<![CDATA[before]]>"));
        assert_eq!(output.matches("<!--same-->").count(), 2);
        assert!(output.contains("<?after yes?>"));
        assert_eq!(
            document,
            SemanticDocument::from_bytes(output.as_bytes()).expect("reparse")
        );
    }

    #[test]
    fn source_tree_edits_reject_unrepresentable_wire_placement() {
        let source = br#"<jmeterTestPlan version="1.2"><hashTree><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="x" enabled="true"/><hashTree/></hashTree></jmeterTestPlan>"#;
        let mut document = SemanticDocument::from_bytes(source).expect("source");
        document
            .tree_mut()
            .insert_root(TestElement::named("TestPlan", "TestPlanGui", "new"))
            .expect("new tree node");
        let error = document
            .to_canonical_bytes()
            .expect_err("new node has no source placement");
        assert_eq!(error.code(), "jmx.semantic.unsupported");

        let programmatic = SemanticDocument::new(
            SemanticRootMetadata::new(
                "jmeterTestPlan",
                vec![SemanticAttribute::new("version", "1.2")],
                Span { start: 0, end: 0 },
            ),
            ElementTree::new(),
        );
        assert!(programmatic.to_canonical_bytes().is_ok());
    }

    #[test]
    fn standard_object_property_child_name_shape_round_trips_and_preserves_order() {
        let source = br#"<jmeterTestPlan version="1.2"><hashTree><ResultCollector guiclass="StatVisualizer" testclass="ResultCollector" testname="collector" enabled="true"><objProp name="attributeForm"><value class="Type">payload</value></objProp><objProp><name>saveConfig</name><value custom="yes">payload&apos;value</value></objProp><objProp><name>emptyClass</name><value class="">raw</value></objProp></ResultCollector><hashTree/></hashTree></jmeterTestPlan>"#;
        let document = SemanticDocument::from_bytes(source).expect("standard objProp shape");
        let element = document.tree().element(NodeId::new(1)).expect("collector");
        let PropertyValue::Object(save_config) = element
            .property("saveConfig")
            .expect("child-name object property")
        else {
            panic!("saveConfig object expected");
        };
        assert_eq!(save_config.class_name, None);
        let PropertyValue::Object(empty_class) = element
            .property("emptyClass")
            .expect("empty-class object property")
        else {
            panic!("emptyClass object expected");
        };
        assert_eq!(empty_class.class_name, Some(String::new()));
        let output = String::from_utf8(document.to_canonical_bytes().expect("canonical output"))
            .expect("UTF-8 output");
        let object_start = output
            .find("<name>saveConfig</name>")
            .expect("child-name output");
        let value = output[object_start..]
            .find("<value custom=\"yes\">payload&apos;value</value>")
            .expect("value output");
        assert!(value > 0, "value follows child name");
        assert!(!output.contains("<objProp name=\"saveConfig\">"));
        let reparsed = SemanticDocument::from_bytes(output.as_bytes()).expect("reparse");
        assert_eq!(document, reparsed);
    }

    #[test]
    fn pinned_upgrade_aliases_compare_equal_only_after_their_declared_mapping() {
        let source = br#"<jmeterTestPlan version="1.2"><hashTree><SoapSampler guiclass="SoapSamplerGui" testclass="SoapSampler" testname="legacy" enabled="true"/><hashTree/></hashTree></jmeterTestPlan>"#;
        let document = SemanticDocument::from_bytes(source).expect("legacy SoapSampler");
        let output = document.to_canonical_bytes().expect("canonical output");
        assert!(String::from_utf8_lossy(&output).contains("testclass=\"ConfigTestElement\""));
        let reparsed = SemanticDocument::from_bytes(&output).expect("reparse");
        assert_eq!(document, reparsed);
        let arbitrary = br#"<jmeterTestPlan version="1.2"><hashTree><SoapSampler guiclass="SoapSamplerGui" testclass="OtherSampler" testname="legacy" enabled="true"/><hashTree/></hashTree></jmeterTestPlan>"#;
        let arbitrary_document = SemanticDocument::from_bytes(arbitrary).expect("opaque variant");
        assert_ne!(document, arbitrary_document);
    }

    #[test]
    fn paired_upgrade_migrates_test_class_before_independent_gui_and_properties() {
        let source = br#"<jmeterTestPlan version="1.2"><hashTree><ConfigTestElement guiclass="org.apache.jmeter.protocol.jdbc.config.gui.DbConfigGui" testclass="org.apache.jmeter.config.ConfigTestElement" testname="legacy data source" enabled="true"><stringProp name="JDBCSampler.url">jdbc:example</stringProp><stringProp name="ConfigTestElement.username">fixture-user</stringProp></ConfigTestElement><hashTree/></hashTree></jmeterTestPlan>"#;
        let document = SemanticDocument::from_bytes(source).expect("paired upgrade decodes");
        let element = document.tree().element(NodeId::new(1)).expect("element");
        assert_eq!(element.test_class(), "JDBCDataSource");
        assert_eq!(element.gui_class(), "TestBeanGUI");
        assert_eq!(
            element.property("dbUrl"),
            Some(&PropertyValue::String("jdbc:example".to_owned()))
        );
        assert_eq!(
            element.property("username"),
            Some(&PropertyValue::String("fixture-user".to_owned()))
        );
        assert!(!document.is_opaque(NodeId::new(1)));
        let output = document.to_canonical_bytes().expect("canonical output");
        let reparsed = SemanticDocument::from_bytes(&output).expect("canonical output reparses");
        assert_eq!(document, reparsed);
    }

    #[test]
    fn top_level_comments_and_processing_instructions_are_bounded_and_preserved() {
        let source = br#"<!--before--><?before yes?><jmeterTestPlan version="1.2"><hashTree/></jmeterTestPlan><!--after--><?after yes?>"#;
        let document = SemanticDocument::from_bytes(source).expect("top-level extensions decode");
        assert_eq!(document.leading_extensions().len(), 2);
        assert_eq!(document.trailing_extensions().len(), 2);
        let output = document.to_canonical_bytes().expect("canonical output");
        let output = String::from_utf8(output).expect("UTF-8 output");
        assert!(output.contains("<!--before-->"));
        assert!(output.contains("<?before yes?>"));
        assert!(output.contains("<!--after-->"));
        assert!(output.contains("<?after yes?>"));
        let reparsed = SemanticDocument::from_bytes(output.as_bytes()).expect("reparse");
        assert_eq!(document, reparsed);
    }

    #[test]
    fn invalid_scalar_and_io_errors_do_not_echo_raw_context() {
        let secret = "super-secret-scalar";
        let source = format!(
            r#"<jmeterTestPlan version="1.2"><hashTree><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="x" enabled="true"><intProp name="secret">{secret}</intProp></TestPlan><hashTree/></hashTree></jmeterTestPlan>"#
        );
        let error = SemanticDocument::from_bytes(source.as_bytes()).expect_err("invalid scalar");
        assert!(!error.to_string().contains(secret));
        assert!(!format!("{error:?}").contains(secret));

        let identifier_secret = "secret-property-identifier";
        let duplicate = format!(
            r#"<jmeterTestPlan version="1.2"><hashTree><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="x" enabled="true"><stringProp name="{identifier_secret}">one</stringProp><stringProp name="{identifier_secret}">two</stringProp></TestPlan><hashTree/></hashTree></jmeterTestPlan>"#
        );
        let error = SemanticDocument::from_bytes(duplicate.as_bytes())
            .expect_err("duplicate user-controlled property identifier");
        assert!(!error.to_string().contains(identifier_secret));
        assert!(!format!("{error:?}").contains(identifier_secret));

        const IO_SECRET: &str = "super-secret-io-context";
        struct SecretWriter;
        impl Write for SecretWriter {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    IO_SECRET,
                ))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let error = crate::Parser::new()
            .parse(b"<root/>")
            .expect("XML")
            .write_lossless(SecretWriter)
            .expect_err("I/O error");
        assert!(!error.to_string().contains(secret));
        assert!(!format!("{error:?}").contains(secret));
    }

    #[test]
    fn apostrophes_are_escaped_and_successful_output_fits_default_decoder() {
        let source = br#"<jmeterTestPlan version="1.2"><hashTree><TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="x" enabled="true"><stringProp name="quote">a&apos;b</stringProp></TestPlan><hashTree/></hashTree></jmeterTestPlan>"#;
        let document = SemanticDocument::from_bytes(source).expect("apostrophe source");
        let output = document.to_canonical_bytes().expect("canonical output");
        assert!(String::from_utf8_lossy(&output).contains("a&apos;b"));
        assert_eq!(
            document,
            SemanticDocument::from_bytes(&output).expect("default reparse")
        );
    }
}
