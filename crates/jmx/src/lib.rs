// SPDX-License-Identifier: Apache-2.0
//! A bounded, preservation-first XML syntax layer for JMeter plans.
//!
//! The syntax layer deliberately does not know about JMeter aliases or the
//! semantic model.  It records the source document as an ordered stream of
//! XML events, together with validated metadata and element spans.  A loaded
//! document can therefore be written back byte-for-byte until a later layer
//! intentionally performs an edit.
//!
//! Parsing is UTF-8 only (the encoding used by the current JMeter profile),
//! never resolves entities, and rejects DTD declarations.  All allocations
//! are bounded by [`Limits`] and by the input's configured byte limit.

use std::fmt;
use std::io::{self, Read, Write};

mod registry;
mod semantic;

pub use SemanticErrorKind as SemanticMappingErrorKind;
pub use registry::{
    AliasRegistry, AliasResolution, JmxRegistry, RegistryError, RegistryVersion, UpgradeRegistry,
    UpgradeRule, UpgradedElement,
};
pub use semantic::{
    DecodeLimits, DecodeOptions, Diagnostic, DiagnosticSeverity, DroppedProperty,
    JmxSemanticDocument, SemanticAttribute, SemanticDocument, SemanticElementInfo, SemanticEvent,
    SemanticPlan, SemanticRootMetadata, WireProperty, decode, decode_document, encode_document,
    encode_semantic, parse_semantic,
};

/// The result type returned by this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// A half-open byte range in the original input (`start..end`).
///
/// Event and subtree spans always point into [`Document::source`].  Offsets
/// are byte offsets, not character offsets, so non-ASCII input remains
/// unambiguous.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Span {
    /// First byte included in the span.
    pub start: usize,
    /// First byte after the span.
    pub end: usize,
}

impl Span {
    /// Creates a span when `start <= end`.
    pub const fn new(start: usize, end: usize) -> Option<Self> {
        if start <= end {
            Some(Self { start, end })
        } else {
            None
        }
    }

    /// Returns the number of bytes in the span.
    pub const fn len(self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// Returns whether the span is empty.
    pub const fn is_empty(self) -> bool {
        self.start >= self.end
    }
}

/// A one-based line and column plus a zero-based byte offset.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Position {
    /// Zero-based byte offset.
    pub offset: usize,
    /// One-based line number.
    pub line: usize,
    /// One-based column number measured in Unicode scalar values.
    pub column: usize,
}

impl Position {
    const fn start() -> Self {
        Self {
            offset: 0,
            line: 1,
            column: 1,
        }
    }
}

/// Resource limits applied before or during parsing.
///
/// `max_bytes` bounds the source retained by a document. `max_nodes` counts
/// XML nodes (elements, text, CDATA, comments, and processing instructions;
/// an element's end tag is not a second node). `max_attributes` and
/// `max_attribute_bytes` are document-wide limits. `max_text_bytes` is the
/// document-wide size of decoded text and CDATA content. The defaults are
/// finite so an untrusted input cannot make this crate allocate indefinitely.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum number of source bytes retained and parsed.
    pub max_bytes: usize,
    /// Maximum element nesting depth. The root element has depth one for this
    /// limit, while event [`Event::depth`] is zero-based.
    pub max_depth: usize,
    /// Maximum logical XML nodes.
    pub max_nodes: usize,
    /// Maximum attributes across the document.
    pub max_attributes: usize,
    /// Maximum decoded attribute-value bytes across the document.
    pub max_attribute_bytes: usize,
    /// Maximum decoded text and CDATA bytes across the document.
    pub max_text_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_bytes: 8 * 1024 * 1024,
            max_depth: 256,
            max_nodes: 100_000,
            max_attributes: 100_000,
            max_attribute_bytes: 4 * 1024 * 1024,
            max_text_bytes: 4 * 1024 * 1024,
        }
    }
}

impl Limits {
    /// Returns a conservative limit set useful for small plans and tests.
    pub const fn small() -> Self {
        Self {
            max_bytes: 1024 * 1024,
            max_depth: 64,
            max_nodes: 10_000,
            max_attributes: 10_000,
            max_attribute_bytes: 512 * 1024,
            max_text_bytes: 512 * 1024,
        }
    }
}

/// Stable categories for resource-limit failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LimitKind {
    /// The source exceeded [`Limits::max_bytes`].
    Bytes,
    /// Element nesting exceeded [`Limits::max_depth`].
    Depth,
    /// Logical XML nodes exceeded [`Limits::max_nodes`].
    Nodes,
    /// Attributes exceeded [`Limits::max_attributes`].
    Attributes,
    /// Decoded attribute values exceeded [`Limits::max_attribute_bytes`].
    AttributeBytes,
    /// Decoded text or CDATA exceeded [`Limits::max_text_bytes`].
    TextBytes,
}

impl LimitKind {
    const fn code(self) -> &'static str {
        match self {
            Self::Bytes => "jmx.syntax.limit_bytes",
            Self::Depth => "jmx.syntax.limit_depth",
            Self::Nodes => "jmx.syntax.limit_nodes",
            Self::Attributes => "jmx.syntax.limit_attributes",
            Self::AttributeBytes => "jmx.syntax.limit_attribute_bytes",
            Self::TextBytes => "jmx.syntax.limit_text_bytes",
        }
    }
}

/// Stable categories for well-formed XML failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyntaxErrorKind {
    /// The input ended while a token was still open.
    UnexpectedEof,
    /// A token was not valid XML syntax.
    UnexpectedToken,
    /// A name was not a valid XML/QName.
    InvalidName,
    /// Two attributes on one element had the same lexical name.
    DuplicateAttribute,
    /// An element end tag did not match its start tag.
    MismatchedTag,
    /// More than one document root was present.
    MultipleRoots,
    /// Non-whitespace content appeared outside the root element.
    TextOutsideRoot,
    /// An XML declaration was misplaced or malformed.
    InvalidDeclaration,
    /// A character/entity reference was malformed or unknown.
    InvalidEntity,
    /// A comment violated XML's `--` rules.
    InvalidComment,
    /// An encoding declaration was not UTF-8.
    InvalidEncoding,
}

impl SyntaxErrorKind {
    const fn code(self) -> &'static str {
        match self {
            Self::UnexpectedEof => "jmx.syntax.unexpected_eof",
            Self::UnexpectedToken => "jmx.syntax.unexpected_token",
            Self::InvalidName => "jmx.syntax.invalid_name",
            Self::DuplicateAttribute => "jmx.syntax.duplicate_attribute",
            Self::MismatchedTag => "jmx.syntax.mismatched_tag",
            Self::MultipleRoots => "jmx.syntax.multiple_roots",
            Self::TextOutsideRoot => "jmx.syntax.text_outside_root",
            Self::InvalidDeclaration => "jmx.syntax.invalid_declaration",
            Self::InvalidEntity => "jmx.syntax.invalid_entity",
            Self::InvalidComment => "jmx.syntax.invalid_comment",
            Self::InvalidEncoding => "jmx.syntax.invalid_encoding",
        }
    }
}

/// Features intentionally refused by the syntax layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnsupportedKind {
    /// DTD declarations and external entities are never resolved.
    Dtd,
    /// An encoding other than UTF-8 was declared.
    Encoding,
}

/// Stable categories for semantic JMX mapping failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SemanticErrorKind {
    /// The document root is not the JMeter script wrapper.
    InvalidRoot,
    /// Root metadata is absent, duplicated, or invalid.
    RootMetadata,
    /// A test element is missing one of its required special attributes.
    MissingMetadata,
    /// A special attribute or property appeared more than once.
    DuplicateMetadata,
    /// The element/hashTree alternation is invalid.
    Topology,
    /// A required hashTree companion is absent.
    MissingHashTree,
    /// A hashTree appeared where an element was required.
    UnexpectedHashTree,
    /// A property node has an invalid shape or attribute set.
    InvalidProperty,
    /// A property name was duplicated in one element.
    DuplicateProperty,
    /// A scalar property could not be decoded as its declared type.
    InvalidPropertyValue,
    /// Semantic mapping exceeded a configured element/property/depth limit.
    Limit,
    /// The requested semantic feature is not representable by the model.
    Unsupported,
    /// An embedded or caller-provided semantic registry failed validation.
    Registry,
    /// A canonical writer could not emit a valid value.
    Encode,
}

impl SemanticErrorKind {
    /// Returns the stable machine-readable code for this semantic category.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidRoot => "jmx.semantic.invalid_root",
            Self::RootMetadata => "jmx.semantic.root_metadata",
            Self::MissingMetadata => "jmx.semantic.missing_metadata",
            Self::DuplicateMetadata => "jmx.semantic.duplicate_metadata",
            Self::Topology => "jmx.semantic.topology",
            Self::MissingHashTree => "jmx.semantic.missing_hash_tree",
            Self::UnexpectedHashTree => "jmx.semantic.unexpected_hash_tree",
            Self::InvalidProperty => "jmx.semantic.invalid_property",
            Self::DuplicateProperty => "jmx.semantic.duplicate_property",
            Self::InvalidPropertyValue => "jmx.semantic.invalid_property_value",
            Self::Limit => "jmx.semantic.limit",
            Self::Unsupported => "jmx.semantic.unsupported",
            Self::Registry => "jmx.semantic.registry",
            Self::Encode => "jmx.semantic.encode",
        }
    }
}

impl UnsupportedKind {
    const fn code(self) -> &'static str {
        match self {
            Self::Dtd => "jmx.syntax.dtd_unsupported",
            Self::Encoding => "jmx.syntax.encoding_unsupported",
        }
    }
}

/// A typed parser/writer error with a stable machine-readable code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// The source reader or destination writer failed.
    Io {
        /// The underlying I/O category.
        kind: io::ErrorKind,
        /// A diagnostic message from the I/O operation.
        message: String,
    },
    /// The input was not valid UTF-8.
    InvalidUtf8 {
        /// First invalid byte position.
        position: Position,
    },
    /// The input was well-formed enough to scan but used unsupported syntax.
    Unsupported {
        /// Unsupported feature category.
        kind: UnsupportedKind,
        /// Source position of the feature.
        position: Position,
        /// Additional bounded diagnostic context.
        message: String,
    },
    /// The input was malformed XML.
    Malformed {
        /// Syntax failure category.
        kind: SyntaxErrorKind,
        /// Source position of the failure.
        position: Position,
        /// Additional bounded diagnostic context.
        message: String,
    },
    /// The input exceeded one of the configured resource limits.
    LimitExceeded {
        /// Limit category.
        kind: LimitKind,
        /// Configured maximum.
        limit: usize,
        /// Observed amount at failure (capped to avoid overflow).
        observed: usize,
        /// Source position of the first byte that crossed the limit.
        position: Position,
    },
    /// The XML was syntactically valid but violated JMX semantic structure.
    Semantic {
        /// Semantic failure category.
        kind: SemanticErrorKind,
        /// Source position of the malformed construct, when available.
        position: Option<Position>,
        /// Additional bounded diagnostic context.
        message: String,
    },
}

impl Error {
    /// Returns the stable machine-readable error code.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Io { .. } => "jmx.io",
            Self::InvalidUtf8 { .. } => "jmx.syntax.invalid_utf8",
            Self::Unsupported { kind, .. } => kind.code(),
            Self::Malformed { kind, .. } => kind.code(),
            Self::LimitExceeded { kind, .. } => kind.code(),
            Self::Semantic { kind, .. } => kind.code(),
        }
    }

    /// Returns the source position associated with this error, when known.
    pub const fn position(&self) -> Option<Position> {
        match self {
            Self::Io { .. } => None,
            Self::InvalidUtf8 { position }
            | Self::Unsupported { position, .. }
            | Self::Malformed { position, .. }
            | Self::LimitExceeded { position, .. } => Some(*position),
            Self::Semantic { position, .. } => *position,
        }
    }

    fn io(_error: io::Error) -> Self {
        Self::Io {
            kind: _error.kind(),
            // The standard-library message can contain a path, endpoint, or
            // other caller-controlled context.  Keep the stable I/O kind but
            // never copy that context into a public parse/encode error.
            message: "I/O operation failed".to_owned(),
        }
    }

    fn malformed(kind: SyntaxErrorKind, position: Position, message: impl Into<String>) -> Self {
        Self::Malformed {
            kind,
            position,
            message: message.into(),
        }
    }

    fn unsupported(kind: UnsupportedKind, position: Position, message: impl Into<String>) -> Self {
        Self::Unsupported {
            kind,
            position,
            message: message.into(),
        }
    }

    fn limit(kind: LimitKind, limit: usize, observed: usize, position: Position) -> Self {
        Self::LimitExceeded {
            kind,
            limit,
            observed,
            position,
        }
    }

    pub(crate) fn semantic(
        kind: SemanticErrorKind,
        position: Option<Position>,
        message: impl Into<String>,
    ) -> Self {
        Self::Semantic {
            kind,
            position,
            message: message.into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { message, .. } => write!(formatter, "{}: {message}", self.code()),
            Self::InvalidUtf8 { position } => write!(
                formatter,
                "{} at byte {} (line {}, column {})",
                self.code(),
                position.offset,
                position.line,
                position.column
            ),
            Self::Unsupported {
                position, message, ..
            }
            | Self::Malformed {
                position, message, ..
            } => write!(
                formatter,
                "{} at byte {} (line {}, column {}): {message}",
                self.code(),
                position.offset,
                position.line,
                position.column
            ),
            Self::LimitExceeded {
                limit,
                observed,
                position,
                ..
            } => write!(
                formatter,
                "{} at byte {} (line {}, column {}): observed {observed}, limit {limit}",
                self.code(),
                position.offset,
                position.line,
                position.column
            ),
            Self::Semantic {
                position: Some(position),
                message,
                ..
            } => write!(
                formatter,
                "{} at byte {} (line {}, column {}): {message}",
                self.code(),
                position.offset,
                position.line,
                position.column
            ),
            Self::Semantic {
                position: None,
                message,
                ..
            } => write!(formatter, "{}: {message}", self.code()),
        }
    }
}

impl std::error::Error for Error {}

/// An XML qualified name retaining its lexical prefix and local part.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct QualifiedName {
    raw: String,
    prefix: Option<String>,
    local: String,
}

impl QualifiedName {
    /// Returns the exact lexical name as written in the source.
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// Returns the namespace prefix, if the lexical name had one.
    pub fn prefix(&self) -> Option<&str> {
        self.prefix.as_deref()
    }

    /// Returns the local part of the name.
    pub fn local(&self) -> &str {
        &self.local
    }
}

/// An XML attribute in source order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attribute {
    name: QualifiedName,
    value: String,
    span: Span,
    name_span: Span,
    value_span: Span,
    namespace_declaration: bool,
}

impl Attribute {
    /// Returns the attribute name.
    pub fn name(&self) -> &QualifiedName {
        &self.name
    }

    /// Returns the decoded attribute value. The source spelling remains in
    /// [`Span`]s and in the owning [`Document::source`].
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Returns the complete attribute span, including its quotes.
    pub const fn span(&self) -> Span {
        self.span
    }

    /// Returns the source span of the lexical attribute name.
    pub const fn name_span(&self) -> Span {
        self.name_span
    }

    /// Returns the source span inside the attribute quotes.
    pub const fn value_span(&self) -> Span {
        self.value_span
    }

    /// Returns whether this is `xmlns` or `xmlns:prefix`.
    pub const fn is_namespace_declaration(&self) -> bool {
        self.namespace_declaration
    }
}

/// XML declaration metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XmlDeclaration {
    /// XML version, normally `1.0`.
    pub version: String,
    /// Declared encoding, if present. Only UTF-8 is accepted by this crate.
    pub encoding: Option<String>,
    /// Declared standalone value, if present.
    pub standalone: Option<String>,
}

/// A start-element event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartElement {
    /// Element name.
    pub name: QualifiedName,
    /// Attributes in source order.
    pub attributes: Vec<Attribute>,
}

/// An end-element event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndElement {
    /// Element name.
    pub name: QualifiedName,
}

/// An empty-element event (`<name .../>`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmptyElement {
    /// Element name.
    pub name: QualifiedName,
    /// Attributes in source order.
    pub attributes: Vec<Attribute>,
}

/// Character-data text event with entity references decoded in `value`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Text {
    /// Decoded text value.
    pub value: String,
}

/// CDATA event. Its value is the literal content between `<![CDATA[` and
/// `]]>`; no entity decoding is applied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CData {
    /// Literal CDATA content.
    pub value: String,
}

/// XML comment event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Comment {
    /// Comment content without delimiters.
    pub value: String,
}

/// XML processing-instruction event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessingInstruction {
    /// PI target.
    pub target: QualifiedName,
    /// PI data without the target or delimiters.
    pub data: String,
}

/// A parsed XML event and its source spans.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Event {
    /// Parsed event payload.
    pub kind: EventKind,
    /// Complete source span for this event.
    pub span: Span,
    /// Zero-based element nesting depth at this event.
    pub depth: usize,
    subtree: Option<Span>,
}

impl Event {
    /// Returns the complete source bytes for this event when `source` contains
    /// the event span.
    pub fn raw<'a>(&self, source: &'a [u8]) -> Option<&'a [u8]> {
        source.get(self.span.start..self.span.end)
    }

    /// Returns the matching element subtree span for an element event.
    pub const fn subtree_span(&self) -> Option<Span> {
        self.subtree
    }
}

/// Parsed XML event payloads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EventKind {
    /// XML declaration (`<?xml ...?>`).
    XmlDeclaration(XmlDeclaration),
    /// Non-empty start tag.
    StartElement(StartElement),
    /// End tag.
    EndElement(EndElement),
    /// Empty element tag.
    EmptyElement(EmptyElement),
    /// Character data.
    Text(Text),
    /// CDATA section.
    CData(CData),
    /// Comment.
    Comment(Comment),
    /// Processing instruction other than the XML declaration.
    ProcessingInstruction(ProcessingInstruction),
}

/// Metadata for the document root element.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootMetadata {
    /// Event index containing the root start or empty element.
    pub event_index: usize,
    /// Root qualified name.
    pub name: QualifiedName,
    /// Root attributes in source order.
    pub attributes: Vec<Attribute>,
    /// Complete root subtree span.
    pub span: Span,
}

/// A parsed, source-preserving XML document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Document {
    source: Vec<u8>,
    events: Vec<Event>,
    declaration: Option<XmlDeclaration>,
    root: RootMetadata,
}

impl Document {
    /// Returns the original source bytes, including a UTF-8 BOM if supplied.
    pub fn source(&self) -> &[u8] {
        &self.source
    }

    /// Returns the ordered parsed events.
    pub fn events(&self) -> &[Event] {
        &self.events
    }

    /// Returns the optional XML declaration.
    pub fn declaration(&self) -> Option<&XmlDeclaration> {
        self.declaration.as_ref()
    }

    /// Returns root metadata and its complete source span.
    pub fn root(&self) -> &RootMetadata {
        &self.root
    }

    /// Returns the root start/empty event, if the internal event index is
    /// valid. A valid parser-created document always has this event.
    pub fn root_event(&self) -> Option<&Event> {
        self.events.get(self.root.event_index)
    }

    /// Returns the original source bytes for a checked span.
    pub fn span_bytes(&self, span: Span) -> Option<&[u8]> {
        self.source.get(span.start..span.end)
    }

    /// Returns the original bytes covered by an event owned by this document.
    pub fn event_bytes(&self, event: &Event) -> Option<&[u8]> {
        self.span_bytes(event.span)
    }

    /// Computes a one-based source position for a source byte offset.
    pub fn position(&self, offset: usize) -> Option<Position> {
        if offset > self.source.len() {
            return None;
        }
        Some(position_at(&self.source, offset))
    }

    /// Writes this unedited document byte-for-byte.
    pub fn write_lossless<W: Write>(&self, mut writer: W) -> Result<()> {
        writer.write_all(&self.source).map_err(Error::io)
    }

    /// Writes this unedited document byte-for-byte.
    pub fn write<W: Write>(&self, writer: W) -> Result<()> {
        self.write_lossless(writer)
    }

    /// Returns a byte-for-byte copy suitable for an unedited round trip.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.source.clone()
    }
}

/// Compatibility spelling for callers that prefer an XML-specific name.
pub type XmlDocument = Document;

/// Compatibility spelling for callers that prefer an XML-specific name.
pub type XmlEvent = Event;

/// Compatibility spelling for callers that prefer an XML-specific name.
pub type XmlEventKind = EventKind;

/// Compatibility spelling for callers that prefer an XML-specific name.
pub type XmlParser = Parser;

/// Compatibility spelling for callers that prefer a parse-specific name.
pub type ParseLimits = Limits;

/// A bounded parser for source-preserving XML syntax.
#[derive(Clone, Debug)]
pub struct Parser {
    limits: Limits,
}

impl Default for Parser {
    fn default() -> Self {
        Self::new()
    }
}

impl Parser {
    /// Creates a parser with [`Limits::default`].
    pub const fn new() -> Self {
        Self {
            limits: Limits {
                max_bytes: 8 * 1024 * 1024,
                max_depth: 256,
                max_nodes: 100_000,
                max_attributes: 100_000,
                max_attribute_bytes: 4 * 1024 * 1024,
                max_text_bytes: 4 * 1024 * 1024,
            },
        }
    }

    /// Creates a parser with explicit resource limits.
    pub const fn with_limits(limits: Limits) -> Self {
        Self { limits }
    }

    /// Returns the parser's limits.
    pub const fn limits(&self) -> Limits {
        self.limits
    }

    /// Parses a bounded byte slice as UTF-8 XML.
    pub fn parse(&self, source: &[u8]) -> Result<Document> {
        if source.len() > self.limits.max_bytes {
            return Err(Error::limit(
                LimitKind::Bytes,
                self.limits.max_bytes,
                source.len(),
                position_at(source, self.limits.max_bytes.min(source.len())),
            ));
        }
        if let Some(index) = first_invalid_utf8(source) {
            return Err(Error::InvalidUtf8 {
                position: position_at(source, index),
            });
        }
        Scanner::new(source, self.limits).run()
    }

    /// Parses a bounded byte slice as UTF-8 XML.
    pub fn parse_bytes(&self, source: &[u8]) -> Result<Document> {
        self.parse(source)
    }

    /// Reads and parses XML incrementally, retaining at most
    /// [`Limits::max_bytes`] bytes.
    pub fn parse_reader<R: Read>(&self, mut reader: R) -> Result<Document> {
        let mut source = Vec::with_capacity(self.limits.max_bytes.min(8192));
        let mut buffer = [0_u8; 8192];
        loop {
            let remaining = self.limits.max_bytes.saturating_sub(source.len());
            if remaining == 0 {
                let mut probe = [0_u8; 1];
                let read = reader.read(&mut probe).map_err(Error::io)?;
                if read != 0 {
                    let observed = source.len().saturating_add(read);
                    return Err(Error::limit(
                        LimitKind::Bytes,
                        self.limits.max_bytes,
                        observed,
                        position_at(&source, source.len()),
                    ));
                }
                break;
            }
            let capacity = remaining.min(buffer.len());
            let read = reader.read(&mut buffer[..capacity]).map_err(Error::io)?;
            if read == 0 {
                break;
            }
            let observed = source.len().saturating_add(read);
            if observed > self.limits.max_bytes {
                return Err(Error::limit(
                    LimitKind::Bytes,
                    self.limits.max_bytes,
                    observed,
                    position_at(&source, source.len()),
                ));
            }
            source.extend_from_slice(&buffer[..read]);
        }
        self.parse(&source)
    }
}

/// Parses a source slice with [`Limits::default`].
pub fn parse(source: &[u8]) -> Result<Document> {
    Parser::new().parse(source)
}

/// Parses a reader with [`Limits::default`].
pub fn parse_reader<R: Read>(reader: R) -> Result<Document> {
    Parser::new().parse_reader(reader)
}

struct Scanner<'a> {
    source: &'a [u8],
    limits: Limits,
    offset: usize,
    events: Vec<Event>,
    stack: Vec<OpenElement>,
    root: Option<RootMetadata>,
    declaration: Option<XmlDeclaration>,
    nodes: usize,
    attributes: usize,
    attribute_bytes: usize,
    text_bytes: usize,
    root_closed: bool,
}

struct OpenElement {
    name: QualifiedName,
    event_index: usize,
    start: usize,
}

impl<'a> Scanner<'a> {
    fn new(source: &'a [u8], limits: Limits) -> Self {
        Self {
            source,
            limits,
            offset: if source.starts_with(&[0xEF, 0xBB, 0xBF]) {
                3
            } else {
                0
            },
            events: Vec::new(),
            stack: Vec::new(),
            root: None,
            declaration: None,
            nodes: 0,
            attributes: 0,
            attribute_bytes: 0,
            text_bytes: 0,
            root_closed: false,
        }
    }

    fn run(mut self) -> Result<Document> {
        while self.offset < self.source.len() {
            if self.source[self.offset] == b'<' {
                self.parse_markup()?;
            } else {
                self.parse_text()?;
            }
        }

        if !self.stack.is_empty() {
            return Err(self.error(
                SyntaxErrorKind::UnexpectedEof,
                self.source.len(),
                "element was not closed",
            ));
        }
        let root = match self.root.take() {
            Some(root) => root,
            None => {
                return Err(self.error(
                    SyntaxErrorKind::UnexpectedToken,
                    self.source.len(),
                    "document has no root element",
                ));
            }
        };
        Ok(Document {
            source: self.source.to_vec(),
            events: self.events,
            declaration: self.declaration,
            root,
        })
    }

    fn parse_markup(&mut self) -> Result<()> {
        let start = self.offset;
        let after_lt = start.saturating_add(1);
        let Some(&marker) = self.source.get(after_lt) else {
            return Err(self.error(
                SyntaxErrorKind::UnexpectedEof,
                start,
                "`<` has no following token",
            ));
        };
        match marker {
            b'/' => self.parse_end_tag(start),
            b'?' => self.parse_processing_instruction(start),
            b'!' => {
                if self
                    .source
                    .get(after_lt + 1..)
                    .is_some_and(|tail| tail.starts_with(b"--"))
                {
                    self.parse_comment(start)
                } else if self
                    .source
                    .get(after_lt + 1..)
                    .is_some_and(|tail| tail.starts_with(b"[CDATA["))
                {
                    self.parse_cdata(start)
                } else {
                    Err(Error::unsupported(
                        UnsupportedKind::Dtd,
                        self.position(start),
                        "DTD and declaration markup are disabled",
                    ))
                }
            }
            _ => self.parse_start_tag(start),
        }
    }

    fn parse_comment(&mut self, start: usize) -> Result<()> {
        let content_start = start + 4;
        let Some(relative_end) = find_bytes(&self.source[content_start..], b"-->") else {
            return Err(self.error(
                SyntaxErrorKind::UnexpectedEof,
                start,
                "comment is not terminated",
            ));
        };
        let end = content_start + relative_end + 3;
        let content = &self.source[content_start..content_start + relative_end];
        if content.windows(2).any(|window| window == b"--")
            || content.last().is_some_and(|byte| *byte == b'-')
        {
            return Err(self.error(
                SyntaxErrorKind::InvalidComment,
                content_start,
                "comment content contains a forbidden `--`",
            ));
        }
        if !valid_xml_utf8_content(content) {
            return Err(self.error(
                SyntaxErrorKind::UnexpectedToken,
                content_start,
                "comment contains an XML-forbidden character",
            ));
        }
        self.ensure_node(start)?;
        let value = self.utf8_string(content, content_start)?;
        self.bump_node(start)?;
        self.events.push(Event {
            kind: EventKind::Comment(Comment { value }),
            span: Span { start, end },
            depth: self.stack.len(),
            subtree: None,
        });
        self.offset = end;
        Ok(())
    }

    fn parse_cdata(&mut self, start: usize) -> Result<()> {
        let content_start = start + 9;
        let Some(relative_end) = find_bytes(&self.source[content_start..], b"]]>") else {
            return Err(self.error(
                SyntaxErrorKind::UnexpectedEof,
                start,
                "CDATA section is not terminated",
            ));
        };
        if self.stack.is_empty() {
            return Err(self.error(
                SyntaxErrorKind::TextOutsideRoot,
                start,
                "CDATA is not allowed outside the root element",
            ));
        }
        self.ensure_node(start)?;
        let end = content_start + relative_end + 3;
        let content = &self.source[content_start..content_start + relative_end];
        if content.len() > self.limits.max_text_bytes.saturating_sub(self.text_bytes) {
            let observed = self.text_bytes.saturating_add(content.len());
            return Err(Error::limit(
                LimitKind::TextBytes,
                self.limits.max_text_bytes,
                observed,
                self.position(content_start),
            ));
        }
        if !valid_xml_utf8_content(content) {
            return Err(self.error(
                SyntaxErrorKind::UnexpectedToken,
                content_start,
                "CDATA contains an XML-forbidden character",
            ));
        }
        let value = self.utf8_string(content, content_start)?;
        self.bump_text(value.len(), content_start)?;
        self.bump_node(start)?;
        self.events.push(Event {
            kind: EventKind::CData(CData { value }),
            span: Span { start, end },
            depth: self.stack.len(),
            subtree: None,
        });
        self.offset = end;
        Ok(())
    }

    fn parse_processing_instruction(&mut self, start: usize) -> Result<()> {
        let target_start = start + 2;
        let (target, target_end) = self.parse_name(target_start)?;
        let Some(relative_end) = find_bytes(&self.source[target_end..], b"?>") else {
            return Err(self.error(
                SyntaxErrorKind::UnexpectedEof,
                start,
                "processing instruction is not terminated",
            ));
        };
        let end = target_end + relative_end + 2;
        let remainder = &self.source[target_end..target_end + relative_end];
        if target.raw().eq_ignore_ascii_case("xml") {
            if target.raw() != "xml" || self.declaration.is_some() || !self.events.is_empty() {
                return Err(self.error(
                    SyntaxErrorKind::InvalidDeclaration,
                    start,
                    "XML declaration must be the first event",
                ));
            }
            let declaration = self.parse_declaration(remainder, target_end)?;
            self.declaration = Some(declaration.clone());
            self.events.push(Event {
                kind: EventKind::XmlDeclaration(declaration),
                span: Span { start, end },
                depth: 0,
                subtree: None,
            });
        } else {
            self.ensure_node(start)?;
            if !valid_xml_utf8_content(remainder) {
                return Err(self.error(
                    SyntaxErrorKind::UnexpectedToken,
                    target_end,
                    "processing instruction contains an XML-forbidden character",
                ));
            }
            let data = self.utf8_string(remainder, target_end)?;
            self.bump_node(start)?;
            self.events.push(Event {
                kind: EventKind::ProcessingInstruction(ProcessingInstruction { target, data }),
                span: Span { start, end },
                depth: self.stack.len(),
                subtree: None,
            });
        }
        self.offset = end;
        Ok(())
    }

    fn parse_declaration(&self, remainder: &[u8], body_start: usize) -> Result<XmlDeclaration> {
        let mut cursor = 0;
        let mut seen_version = false;
        let mut seen_encoding = false;
        let mut seen_standalone = false;
        let mut version = None;
        let mut encoding = None;
        let mut standalone = None;
        while cursor < remainder.len() {
            cursor = skip_xml_space(remainder, cursor);
            if cursor == remainder.len() {
                break;
            }
            let absolute = body_start + cursor;
            let (name, after_name) = parse_name_from(remainder, cursor).map_err(|kind| {
                self.error(kind, absolute, "invalid XML declaration pseudo-attribute")
            })?;
            cursor = skip_xml_space(remainder, after_name);
            if remainder.get(cursor) != Some(&b'=') {
                return Err(self.error(
                    SyntaxErrorKind::InvalidDeclaration,
                    body_start + cursor,
                    "declaration attribute is missing `=`",
                ));
            }
            cursor += 1;
            cursor = skip_xml_space(remainder, cursor);
            let quote = match remainder.get(cursor) {
                Some(b'\'') | Some(b'"') => remainder[cursor],
                _ => {
                    return Err(self.error(
                        SyntaxErrorKind::InvalidDeclaration,
                        body_start + cursor,
                        "declaration value must be quoted",
                    ));
                }
            };
            cursor += 1;
            let value_start = cursor;
            while cursor < remainder.len() && remainder[cursor] != quote {
                cursor += 1;
            }
            if cursor == remainder.len() {
                return Err(self.error(
                    SyntaxErrorKind::UnexpectedEof,
                    body_start + value_start,
                    "declaration value is not terminated",
                ));
            }
            let value =
                self.utf8_string(&remainder[value_start..cursor], body_start + value_start)?;
            if !valid_xml_utf8_content(value.as_bytes()) {
                return Err(self.error(
                    SyntaxErrorKind::InvalidDeclaration,
                    body_start + value_start,
                    "declaration value contains an XML-forbidden character",
                ));
            }
            cursor += 1;
            match name.raw() {
                "version" if !seen_version => {
                    if value != "1.0" && value != "1.1" {
                        return Err(self.error(
                            SyntaxErrorKind::InvalidDeclaration,
                            body_start + value_start,
                            "XML version must be 1.0 or 1.1",
                        ));
                    }
                    seen_version = true;
                    version = Some(value);
                }
                "encoding" if seen_version && !seen_encoding => {
                    if !value.eq_ignore_ascii_case("utf-8") {
                        return Err(Error::unsupported(
                            UnsupportedKind::Encoding,
                            self.position(body_start + value_start),
                            "only UTF-8 input is supported",
                        ));
                    }
                    seen_encoding = true;
                    encoding = Some(value);
                }
                "standalone" if seen_version && !seen_standalone => {
                    if value != "yes" && value != "no" {
                        return Err(self.error(
                            SyntaxErrorKind::InvalidDeclaration,
                            body_start + value_start,
                            "standalone must be yes or no",
                        ));
                    }
                    seen_standalone = true;
                    standalone = Some(value);
                }
                _ => {
                    return Err(self.error(
                        SyntaxErrorKind::InvalidDeclaration,
                        absolute,
                        "unknown, duplicate, or out-of-order declaration attribute",
                    ));
                }
            }
        }
        let Some(version) = version else {
            return Err(self.error(
                SyntaxErrorKind::InvalidDeclaration,
                body_start,
                "XML declaration requires version",
            ));
        };
        Ok(XmlDeclaration {
            version,
            encoding,
            standalone,
        })
    }

    fn parse_start_tag(&mut self, start: usize) -> Result<()> {
        let depth = self.stack.len();
        let new_depth = depth.saturating_add(1);
        if new_depth > self.limits.max_depth {
            return Err(Error::limit(
                LimitKind::Depth,
                self.limits.max_depth,
                new_depth,
                self.position(start),
            ));
        }
        self.ensure_node(start)?;
        let (name, mut cursor) = self.parse_name(start + 1)?;
        let attributes = self.parse_attributes(&mut cursor)?;
        let empty = if self.source.get(cursor..cursor + 2) == Some(b"/>") {
            cursor += 2;
            true
        } else if self.source.get(cursor) == Some(&b'>') {
            cursor += 1;
            false
        } else {
            return Err(self.error(
                SyntaxErrorKind::UnexpectedToken,
                cursor,
                "start tag must end with `>` or `/>`",
            ));
        };
        let span = Span { start, end: cursor };
        self.bump_node(start)?;
        if self.stack.is_empty() && (self.root.is_some() || self.root_closed) {
            return Err(self.error(
                SyntaxErrorKind::MultipleRoots,
                start,
                "document has more than one root element",
            ));
        }
        let kind = if empty {
            EventKind::EmptyElement(EmptyElement {
                name: name.clone(),
                attributes: attributes.clone(),
            })
        } else {
            EventKind::StartElement(StartElement {
                name: name.clone(),
                attributes: attributes.clone(),
            })
        };
        let event_index = self.events.len();
        self.events.push(Event {
            kind,
            span,
            depth,
            subtree: empty.then_some(span),
        });
        if self.stack.is_empty() {
            self.root = Some(RootMetadata {
                event_index,
                name: name.clone(),
                attributes,
                span,
            });
        }
        if empty {
            if self.stack.is_empty() {
                self.root_closed = true;
            }
        } else {
            self.stack.push(OpenElement {
                name,
                event_index,
                start,
            });
        }
        self.offset = cursor;
        Ok(())
    }

    fn parse_attributes(&mut self, cursor: &mut usize) -> Result<Vec<Attribute>> {
        let mut attributes = Vec::new();
        loop {
            *cursor = skip_xml_space(self.source, *cursor);
            if self.source.get(*cursor) == Some(&b'>')
                || self.source.get(*cursor..cursor.saturating_add(2)) == Some(b"/>")
            {
                break;
            }
            self.ensure_attribute(*cursor)?;
            let attribute_start = *cursor;
            let (name, after_name) = self.parse_name(*cursor)?;
            *cursor = skip_xml_space(self.source, after_name);
            if self.source.get(*cursor) != Some(&b'=') {
                return Err(self.error(
                    SyntaxErrorKind::UnexpectedToken,
                    *cursor,
                    "attribute is missing `=`",
                ));
            }
            *cursor += 1;
            *cursor = skip_xml_space(self.source, *cursor);
            let quote = match self.source.get(*cursor) {
                Some(b'\'') | Some(b'"') => self.source[*cursor],
                _ => {
                    return Err(self.error(
                        SyntaxErrorKind::UnexpectedToken,
                        *cursor,
                        "attribute value must be quoted",
                    ));
                }
            };
            *cursor += 1;
            let value_start = *cursor;
            while let Some(byte) = self.source.get(*cursor) {
                if *byte == quote {
                    break;
                }
                if *byte == b'<' {
                    return Err(self.error(
                        SyntaxErrorKind::UnexpectedToken,
                        *cursor,
                        "`<` is not allowed in an attribute value",
                    ));
                }
                *cursor += 1;
            }
            if self.source.get(*cursor) != Some(&quote) {
                return Err(self.error(
                    SyntaxErrorKind::UnexpectedEof,
                    value_start,
                    "attribute value is not terminated",
                ));
            }
            let value_end = *cursor;
            let decoded_value_bytes =
                decoded_xml_text_len(&self.source[value_start..value_end], value_start).map_err(
                    |(kind, offset)| self.error(kind, offset, "invalid attribute value"),
                )?;
            if decoded_value_bytes
                > self
                    .limits
                    .max_attribute_bytes
                    .saturating_sub(self.attribute_bytes)
            {
                let observed = self.attribute_bytes.saturating_add(decoded_value_bytes);
                return Err(Error::limit(
                    LimitKind::AttributeBytes,
                    self.limits.max_attribute_bytes,
                    observed,
                    self.position(value_start),
                ));
            }
            let value = decode_xml_text(&self.source[value_start..value_end], value_start)
                .map_err(|(kind, offset)| self.error(kind, offset, "invalid attribute value"))?;
            if attributes
                .iter()
                .any(|item: &Attribute| item.name.raw() == name.raw())
            {
                return Err(self.error(
                    SyntaxErrorKind::DuplicateAttribute,
                    attribute_start,
                    "duplicate attribute name",
                ));
            }
            self.bump_attribute(value.len(), value_start)?;
            *cursor += 1;
            attributes.push(Attribute {
                namespace_declaration: name.raw() == "xmlns" || name.prefix() == Some("xmlns"),
                name,
                value,
                span: Span {
                    start: attribute_start,
                    end: *cursor,
                },
                name_span: Span {
                    start: attribute_start,
                    end: after_name,
                },
                value_span: Span {
                    start: value_start,
                    end: value_end,
                },
            });
        }
        Ok(attributes)
    }

    fn parse_end_tag(&mut self, start: usize) -> Result<()> {
        let (name, mut cursor) = self.parse_name(start + 2)?;
        cursor = skip_xml_space(self.source, cursor);
        if self.source.get(cursor) != Some(&b'>') {
            return Err(self.error(
                SyntaxErrorKind::UnexpectedToken,
                cursor,
                "end tag must end with `>`",
            ));
        }
        cursor += 1;
        let Some(open) = self.stack.pop() else {
            return Err(self.error(
                SyntaxErrorKind::MismatchedTag,
                start,
                "end tag has no matching start tag",
            ));
        };
        if open.name.raw() != name.raw() {
            return Err(self.error(
                SyntaxErrorKind::MismatchedTag,
                start,
                format!("expected </{}>, found </{}>", open.name.raw(), name.raw()),
            ));
        }
        let span = Span { start, end: cursor };
        let subtree = Span {
            start: open.start,
            end: cursor,
        };
        if let Some(event) = self.events.get_mut(open.event_index) {
            event.subtree = Some(subtree);
        }
        self.events.push(Event {
            kind: EventKind::EndElement(EndElement { name }),
            span,
            depth: self.stack.len(),
            subtree: None,
        });
        if self.stack.is_empty() {
            self.root_closed = true;
            if let Some(root) = self.root.as_mut() {
                root.span = subtree;
            }
        }
        self.offset = cursor;
        Ok(())
    }

    fn parse_text(&mut self) -> Result<()> {
        let start = self.offset;
        let end = self
            .source
            .get(start..)
            .and_then(|tail| tail.iter().position(|byte| *byte == b'<'))
            .map_or(self.source.len(), |relative| start + relative);
        let raw = &self.source[start..end];
        if raw.windows(3).any(|window| window == b"]]>") {
            return Err(self.error(
                SyntaxErrorKind::UnexpectedToken,
                start,
                "`]]>` is only valid as a CDATA terminator",
            ));
        }
        self.ensure_node(start)?;
        let decoded_text_bytes = decoded_xml_text_len(raw, start)
            .map_err(|(kind, offset)| self.error(kind, offset, "invalid character data"))?;
        if decoded_text_bytes > self.limits.max_text_bytes.saturating_sub(self.text_bytes) {
            let observed = self.text_bytes.saturating_add(decoded_text_bytes);
            return Err(Error::limit(
                LimitKind::TextBytes,
                self.limits.max_text_bytes,
                observed,
                self.position(start),
            ));
        }
        let value = decode_xml_text(raw, start)
            .map_err(|(kind, offset)| self.error(kind, offset, "invalid character data"))?;
        if self.stack.is_empty() && !value.chars().all(is_xml_space_char) {
            return Err(self.error(
                SyntaxErrorKind::TextOutsideRoot,
                start,
                "non-whitespace text is outside the root element",
            ));
        }
        self.bump_text(value.len(), start)?;
        self.bump_node(start)?;
        self.events.push(Event {
            kind: EventKind::Text(Text { value }),
            span: Span { start, end },
            depth: self.stack.len(),
            subtree: None,
        });
        self.offset = end;
        Ok(())
    }

    fn parse_name(&self, offset: usize) -> Result<(QualifiedName, usize)> {
        parse_name_from(self.source, offset)
            .map_err(|kind| self.error(kind, offset, "invalid XML name"))
    }

    fn bump_node(&mut self, position: usize) -> Result<()> {
        self.ensure_node(position)?;
        self.nodes = self.nodes.saturating_add(1);
        Ok(())
    }

    fn ensure_node(&self, position: usize) -> Result<()> {
        let observed = self.nodes.saturating_add(1);
        if observed > self.limits.max_nodes {
            return Err(Error::limit(
                LimitKind::Nodes,
                self.limits.max_nodes,
                observed,
                self.position(position),
            ));
        }
        Ok(())
    }

    fn ensure_attribute(&self, position: usize) -> Result<()> {
        let observed = self.attributes.saturating_add(1);
        if observed > self.limits.max_attributes {
            return Err(Error::limit(
                LimitKind::Attributes,
                self.limits.max_attributes,
                observed,
                self.position(position),
            ));
        }
        Ok(())
    }

    fn bump_attribute(&mut self, value_bytes: usize, position: usize) -> Result<()> {
        let observed = self.attributes.saturating_add(1);
        if observed > self.limits.max_attributes {
            return Err(Error::limit(
                LimitKind::Attributes,
                self.limits.max_attributes,
                observed,
                self.position(position),
            ));
        }
        let bytes = self.attribute_bytes.saturating_add(value_bytes);
        if bytes > self.limits.max_attribute_bytes {
            return Err(Error::limit(
                LimitKind::AttributeBytes,
                self.limits.max_attribute_bytes,
                bytes,
                self.position(position),
            ));
        }
        self.attributes = observed;
        self.attribute_bytes = bytes;
        Ok(())
    }

    fn bump_text(&mut self, value_bytes: usize, position: usize) -> Result<()> {
        let observed = self.text_bytes.saturating_add(value_bytes);
        if observed > self.limits.max_text_bytes {
            return Err(Error::limit(
                LimitKind::TextBytes,
                self.limits.max_text_bytes,
                observed,
                self.position(position),
            ));
        }
        self.text_bytes = observed;
        Ok(())
    }

    fn utf8_string(&self, bytes: &[u8], offset: usize) -> Result<String> {
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| Error::InvalidUtf8 {
                position: self.position(offset),
            })
    }

    fn position(&self, offset: usize) -> Position {
        position_at(self.source, offset.min(self.source.len()))
    }

    fn error(&self, kind: SyntaxErrorKind, offset: usize, message: impl Into<String>) -> Error {
        Error::malformed(kind, self.position(offset), message)
    }
}

fn parse_name_from(
    source: &[u8],
    offset: usize,
) -> std::result::Result<(QualifiedName, usize), SyntaxErrorKind> {
    let text = std::str::from_utf8(source.get(offset..).ok_or(SyntaxErrorKind::UnexpectedEof)?)
        .map_err(|_| SyntaxErrorKind::InvalidName)?;
    let Some((_, first_char)) = text.char_indices().next() else {
        return Err(SyntaxErrorKind::UnexpectedEof);
    };
    if !is_name_start_char(first_char) {
        return Err(SyntaxErrorKind::InvalidName);
    }
    let mut end = offset + first_char.len_utf8();
    let mut colon_count = usize::from(first_char == ':');
    for (index, character) in text.char_indices().skip(1) {
        if !is_name_char(character) {
            break;
        }
        if character == ':' {
            colon_count = colon_count.saturating_add(1);
        }
        end = offset + index + character.len_utf8();
    }
    let raw =
        std::str::from_utf8(&source[offset..end]).map_err(|_| SyntaxErrorKind::InvalidName)?;
    if colon_count > 1 || raw.starts_with(':') || raw.ends_with(':') {
        return Err(SyntaxErrorKind::InvalidName);
    }
    let (prefix, local) = if let Some(colon) = raw.find(':') {
        (Some(raw[..colon].to_owned()), raw[colon + 1..].to_owned())
    } else {
        (None, raw.to_owned())
    };
    Ok((
        QualifiedName {
            raw: raw.to_owned(),
            prefix,
            local,
        },
        end,
    ))
}

fn decoded_xml_text_len(
    raw: &[u8],
    offset: usize,
) -> std::result::Result<usize, (SyntaxErrorKind, usize)> {
    let mut length = 0_usize;
    let mut cursor = 0;
    while cursor < raw.len() {
        if raw[cursor] != b'&' {
            let start = cursor;
            while cursor < raw.len() && raw[cursor] != b'&' {
                cursor += 1;
            }
            let chunk = std::str::from_utf8(&raw[start..cursor])
                .map_err(|_| (SyntaxErrorKind::InvalidEntity, offset + start))?;
            if !chunk.chars().all(is_xml_char) {
                return Err((SyntaxErrorKind::UnexpectedToken, offset + start));
            }
            length = length
                .checked_add(chunk.len())
                .ok_or((SyntaxErrorKind::InvalidEntity, offset + start))?;
            continue;
        }
        let entity_start = cursor;
        let Some(relative_end) = raw[cursor + 1..].iter().position(|byte| *byte == b';') else {
            return Err((SyntaxErrorKind::InvalidEntity, offset + entity_start));
        };
        let entity_end = cursor + 1 + relative_end;
        let entity = &raw[cursor + 1..entity_end];
        if entity.is_empty() {
            return Err((SyntaxErrorKind::InvalidEntity, offset + entity_start));
        }
        let character = match entity {
            b"amp" => '&',
            b"lt" => '<',
            b"gt" => '>',
            b"apos" => '\'',
            b"quot" => '"',
            _ if entity.first() == Some(&b'#') => {
                let (radix, digits) =
                    if entity.get(1) == Some(&b'x') || entity.get(1) == Some(&b'X') {
                        (16, &entity[2..])
                    } else {
                        (10, &entity[1..])
                    };
                if digits.is_empty() {
                    return Err((SyntaxErrorKind::InvalidEntity, offset + entity_start));
                }
                let text = std::str::from_utf8(digits)
                    .map_err(|_| (SyntaxErrorKind::InvalidEntity, offset + entity_start))?;
                let Some(codepoint) = parse_codepoint(text, radix) else {
                    return Err((SyntaxErrorKind::InvalidEntity, offset + entity_start));
                };
                let Some(character) = char::from_u32(codepoint) else {
                    return Err((SyntaxErrorKind::InvalidEntity, offset + entity_start));
                };
                character
            }
            _ => return Err((SyntaxErrorKind::InvalidEntity, offset + entity_start)),
        };
        if !is_xml_char(character) {
            return Err((SyntaxErrorKind::InvalidEntity, offset + entity_start));
        }
        length = length
            .checked_add(character.len_utf8())
            .ok_or((SyntaxErrorKind::InvalidEntity, offset + entity_start))?;
        cursor = entity_end + 1;
    }
    Ok(length)
}

fn decode_xml_text(
    raw: &[u8],
    offset: usize,
) -> std::result::Result<String, (SyntaxErrorKind, usize)> {
    let mut value = String::new();
    let mut cursor = 0;
    while cursor < raw.len() {
        if raw[cursor] != b'&' {
            let start = cursor;
            while cursor < raw.len() && raw[cursor] != b'&' {
                cursor += 1;
            }
            let chunk = std::str::from_utf8(&raw[start..cursor])
                .map_err(|_| (SyntaxErrorKind::InvalidEntity, offset + start))?;
            if !chunk.chars().all(is_xml_char) {
                return Err((SyntaxErrorKind::UnexpectedToken, offset + start));
            }
            value.push_str(chunk);
            continue;
        }
        let entity_start = cursor;
        let Some(relative_end) = raw[cursor + 1..].iter().position(|byte| *byte == b';') else {
            return Err((SyntaxErrorKind::InvalidEntity, offset + entity_start));
        };
        let entity_end = cursor + 1 + relative_end;
        let entity = &raw[cursor + 1..entity_end];
        if entity.is_empty() {
            return Err((SyntaxErrorKind::InvalidEntity, offset + entity_start));
        }
        match entity {
            b"amp" => value.push('&'),
            b"lt" => value.push('<'),
            b"gt" => value.push('>'),
            b"apos" => value.push('\''),
            b"quot" => value.push('"'),
            _ if entity.first() == Some(&b'#') => {
                let (radix, digits) =
                    if entity.get(1) == Some(&b'x') || entity.get(1) == Some(&b'X') {
                        (16, &entity[2..])
                    } else {
                        (10, &entity[1..])
                    };
                if digits.is_empty() {
                    return Err((SyntaxErrorKind::InvalidEntity, offset + entity_start));
                }
                let text = std::str::from_utf8(digits)
                    .map_err(|_| (SyntaxErrorKind::InvalidEntity, offset + entity_start))?;
                let Some(codepoint) = parse_codepoint(text, radix) else {
                    return Err((SyntaxErrorKind::InvalidEntity, offset + entity_start));
                };
                let Some(character) = char::from_u32(codepoint) else {
                    return Err((SyntaxErrorKind::InvalidEntity, offset + entity_start));
                };
                if !is_xml_char(character) {
                    return Err((SyntaxErrorKind::InvalidEntity, offset + entity_start));
                }
                value.push(character);
            }
            _ => return Err((SyntaxErrorKind::InvalidEntity, offset + entity_start)),
        }
        cursor = entity_end + 1;
    }
    Ok(value)
}

fn valid_xml_utf8_content(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes)
        .ok()
        .is_some_and(|text| text.chars().all(is_xml_char))
}

fn parse_codepoint(text: &str, radix: u32) -> Option<u32> {
    let mut value = 0_u32;
    for digit in text.chars() {
        let number = digit.to_digit(radix)?;
        value = value.checked_mul(radix)?.checked_add(number)?;
    }
    if value == 0 || value > 0x10_FFFF || (0xD800..=0xDFFF).contains(&value) {
        None
    } else {
        Some(value)
    }
}

fn is_name_start_char(character: char) -> bool {
    character == ':'
        || character == '_'
        || character.is_ascii_alphabetic()
        || matches!(character as u32, 0xC0..=0xD6 | 0xD8..=0xF6 | 0xF8..=0x2FF | 0x370..=0x37D | 0x37F..=0x1FFF | 0x200C..=0x200D | 0x2070..=0x218F | 0x2C00..=0x2FEF | 0x3001..=0xD7FF | 0xF900..=0xFDCF | 0xFDF0..=0xFFFD | 0x10000..=0xEFFFF)
}

fn is_name_char(character: char) -> bool {
    is_name_start_char(character)
        || character == '-'
        || character == '.'
        || character.is_ascii_digit()
        || character == '\u{B7}'
        || matches!(character as u32, 0x300..=0x36F | 0x203F..=0x2040)
}

fn is_xml_space_char(character: char) -> bool {
    matches!(character, ' ' | '\t' | '\n' | '\r')
}

fn is_xml_char(character: char) -> bool {
    matches!(
        character as u32,
        0x9 | 0xA | 0xD | 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF
    )
}

fn is_xml_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
}

fn skip_xml_space(source: &[u8], mut offset: usize) -> usize {
    while source.get(offset).is_some_and(|byte| is_xml_space(*byte)) {
        offset += 1;
    }
    offset
}

fn find_bytes(source: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    source
        .windows(needle.len())
        .position(|window| window == needle)
}

fn first_invalid_utf8(source: &[u8]) -> Option<usize> {
    std::str::from_utf8(source)
        .err()
        .map(|error| error.valid_up_to())
}

fn position_at(source: &[u8], offset: usize) -> Position {
    let bounded = offset.min(source.len());
    let mut position = Position::start();
    let mut cursor = 0;
    while cursor < bounded {
        let byte = source[cursor];
        if byte == b'\n' {
            position.line += 1;
            position.column = 1;
            cursor += 1;
            continue;
        }
        if byte == b'\r' {
            position.line += 1;
            position.column = 1;
            cursor += 1;
            if source.get(cursor) == Some(&b'\n') && cursor < bounded {
                cursor += 1;
            }
            continue;
        }
        let width = std::str::from_utf8(&source[cursor..bounded])
            .ok()
            .and_then(|text| text.chars().next().map(char::len_utf8))
            .unwrap_or(1);
        position.column += 1;
        cursor = cursor.saturating_add(width);
    }
    position.offset = bounded;
    position
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::io::{self, Cursor};

    fn parse_ok(source: &str) -> Document {
        Parser::new().parse(source.as_bytes()).expect("valid XML")
    }

    #[test]
    fn parses_minimal_jmx_shape_and_root_metadata() {
        let source = r#"<?xml version="1.0" encoding="UTF-8"?>
<jmeterTestPlan version="1.2"><hashTree/></jmeterTestPlan>"#;
        let document = parse_ok(source);
        assert_eq!(
            document.declaration().map(|item| item.version.as_str()),
            Some("1.0")
        );
        assert_eq!(document.root().name.raw(), "jmeterTestPlan");
        assert_eq!(document.root().attributes[0].value(), "1.2");
        assert_eq!(document.events().len(), 5);
        assert_eq!(
            document.root().span.start,
            source.find("<jmeterTestPlan").expect("root start")
        );
        assert_eq!(document.root().span.end, source.len());
        assert_eq!(document.to_bytes(), source.as_bytes());
    }

    #[test]
    fn preserves_unknown_nodes_attributes_namespaces_and_spans() {
        let source = r#"<root xmlns:x="urn:test" z="&quot;value&quot;"><x:plugin unknown="yes"><child/></x:plugin></root>"#;
        let document = parse_ok(source);
        let start = document
            .events()
            .iter()
            .find(|event| {
                matches!(&event.kind, EventKind::StartElement(element) if element.name.local() == "plugin")
            })
            .expect("plugin event");
        let subtree = start.subtree_span().expect("plugin subtree");
        let plugin_start = source.find("<x:plugin").expect("plugin start");
        let plugin_end = source.find("</x:plugin>").expect("plugin end") + "</x:plugin>".len();
        assert_eq!(
            subtree,
            Span {
                start: plugin_start,
                end: plugin_end
            }
        );
        let EventKind::StartElement(plugin) = &start.kind else {
            panic!("expected start event");
        };
        assert_eq!(plugin.name.prefix(), Some("x"));
        assert_eq!(plugin.attributes[0].value(), "yes");
        assert_eq!(document.to_bytes(), source.as_bytes());
    }

    #[test]
    fn decodes_unicode_and_xml_escapes_but_writes_original_spelling() {
        let source = "<root a='&amp; &#x1F600;'>hé &lt; world<![CDATA[ &amp; ]]> </root>";
        let document = parse_ok(source);
        let EventKind::StartElement(root) = &document.events()[0].kind else {
            panic!("expected root");
        };
        assert_eq!(root.attributes[0].value(), "& 😀");
        assert!(document.events().iter().any(|event| {
            matches!(&event.kind, EventKind::Text(text) if text.value == "hé < world")
        }));
        assert!(document.events().iter().any(|event| {
            matches!(&event.kind, EventKind::CData(cdata) if cdata.value == " &amp; ")
        }));
        assert_eq!(document.to_bytes(), source.as_bytes());
    }

    #[test]
    fn text_and_attribute_limits_measure_decoded_values() {
        let text = Parser::with_limits(Limits {
            max_text_bytes: 1,
            ..Limits::default()
        })
        .parse(b"<root>&amp;</root>")
        .expect("encoded text decodes to one byte");
        assert!(
            text.events().iter().any(|event| {
                matches!(&event.kind, EventKind::Text(value) if value.value == "&")
            })
        );

        let attribute = Parser::with_limits(Limits {
            max_attribute_bytes: 1,
            ..Limits::default()
        })
        .parse(b"<root value=\"&amp;\"/>")
        .expect("encoded attribute decodes to one byte");
        let EventKind::EmptyElement(root) = &attribute.events()[0].kind else {
            panic!("expected empty root");
        };
        assert_eq!(root.attributes[0].value(), "&");
    }

    #[test]
    fn keeps_comments_processing_instructions_and_mixed_whitespace() {
        let source = "\n<!-- before --><?hint data?><root> t </root><!-- after -->\n";
        let document = parse_ok(source);
        assert!(
            document
                .events()
                .iter()
                .any(|event| matches!(event.kind, EventKind::Comment(_)))
        );
        assert!(
            document
                .events()
                .iter()
                .any(|event| {
                    matches!(&event.kind, EventKind::ProcessingInstruction(pi) if pi.target.raw() == "hint" && pi.data == " data")
                })
        );
        assert_eq!(document.to_bytes(), source.as_bytes());
    }

    #[test]
    fn reader_is_bounded_and_lossless() {
        let source = b"<root><child/></root>";
        let parser = Parser::with_limits(Limits {
            max_bytes: source.len(),
            ..Limits::default()
        });
        let document = parser
            .parse_reader(Cursor::new(source))
            .expect("parse reader");
        let mut output = Vec::new();
        document.write_lossless(&mut output).expect("write");
        assert_eq!(output, source);
    }

    #[test]
    fn rejects_malformed_and_truncated_input_with_positions() {
        let cases = [
            ("<root>", "jmx.syntax.unexpected_eof"),
            ("<root a='x'></wrong>", "jmx.syntax.mismatched_tag"),
            ("<root a='x' a='y'/>", "jmx.syntax.duplicate_attribute"),
            ("<root>&wat;</root>", "jmx.syntax.invalid_entity"),
            ("<!DOCTYPE root><root/>", "jmx.syntax.dtd_unsupported"),
        ];
        for (source, code) in cases {
            let error = parse(source.as_bytes()).expect_err("must reject");
            assert_eq!(error.code(), code);
            assert!(error.position().is_some());
        }
    }

    #[test]
    fn rejects_invalid_utf8_without_panicking() {
        let error = parse(b"<root>\xFF</root>").expect_err("invalid UTF-8");
        assert_eq!(error.code(), "jmx.syntax.invalid_utf8");
        assert_eq!(error.position().map(|position| position.offset), Some(6));
    }

    #[test]
    fn enforces_all_resource_limits() {
        let input = b"<root a='123'>text<child/></root>";
        let limits = [
            (
                Limits {
                    max_bytes: 4,
                    ..Limits::default()
                },
                "jmx.syntax.limit_bytes",
            ),
            (
                Limits {
                    max_depth: 1,
                    ..Limits::default()
                },
                "jmx.syntax.limit_depth",
            ),
            (
                Limits {
                    max_nodes: 1,
                    ..Limits::default()
                },
                "jmx.syntax.limit_nodes",
            ),
            (
                Limits {
                    max_attributes: 0,
                    ..Limits::default()
                },
                "jmx.syntax.limit_attributes",
            ),
            (
                Limits {
                    max_attribute_bytes: 2,
                    ..Limits::default()
                },
                "jmx.syntax.limit_attribute_bytes",
            ),
            (
                Limits {
                    max_text_bytes: 2,
                    ..Limits::default()
                },
                "jmx.syntax.limit_text_bytes",
            ),
        ];
        for (limits, code) in limits {
            let error = Parser::with_limits(limits)
                .parse(input)
                .expect_err("limit must reject");
            assert_eq!(error.code(), code);
        }
    }

    #[test]
    fn accepts_bom_and_reports_line_column() {
        let document = parse_ok("\u{FEFF}\n<root>\n<child/>\n</root>");
        let child = document
            .events()
            .iter()
            .find(|event| matches!(&event.kind, EventKind::EmptyElement(_)))
            .expect("child");
        assert_eq!(
            document
                .position(child.span.start)
                .map(|position| position.line),
            Some(3)
        );
        assert_eq!(
            document.to_bytes(),
            "\u{FEFF}\n<root>\n<child/>\n</root>".as_bytes()
        );
    }

    #[test]
    fn writer_reports_io_errors() {
        struct FailingWriter;
        impl Write for FailingWriter {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let error = parse_ok("<root/>")
            .write_lossless(FailingWriter)
            .expect_err("writer fails");
        assert_eq!(error.code(), "jmx.io");
    }
}
