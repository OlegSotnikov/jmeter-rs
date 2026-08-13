#![no_main]

//! Bounded generated-model coverage for save-service provenance resolution.
//!
//! The input is decoded into a small, independent source inventory.  The
//! inventory is then submitted to the pure `SaveConfigResolver`; checks do not
//! derive their expectations from the resolver's output.  In particular, the
//! model exercises explicit precedence, last-operation source semantics,
//! absent/present-empty values, unknown-property retention, wire projection,
//! bounded diagnostics, and canonical identity.
//!
//! Invariants: `SAVE-CONFIG-MODEL-001` checks source-operation conservation,
//! `SAVE-CONFIG-PRECEDENCE-001` independently selects the winning source,
//! `SAVE-CONFIG-UNKNOWN-001` retains unknown fields as unresolved, and
//! `SAVE-CONFIG-CANONICAL-001` checks deterministic bounded serialization.
//! Source-side coverage: ordered save operations, source precedence, field
//! presence, unknown properties, and canonical wire bytes form the independent
//! model inventory before resolver output is inspected.
//! I/O policy: none; save-service provenance resolution is exercised in memory.

use std::collections::BTreeMap;

use jmeter_rs_results::{
    CliMode, FieldPresence, JavaValue, MAX_SAVE_CONFIG_CANONICAL_BYTES, SaveConfigLimits,
    SaveConfigOperation, SaveConfigPrecedence, SaveConfigResolver, SaveConfigSource,
    SaveConfigSourceKind, SaveField, SaveFieldId, SaveOperationKind, SaveValueKind, SaveWireFormat,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 64 * 1024;
const MAX_MODEL_FIELDS: usize = 8;
const MAX_MODEL_OPERATIONS_PER_FIELD: usize = 6;
const MAX_MODEL_OPERATIONS: usize = MAX_MODEL_FIELDS * MAX_MODEL_OPERATIONS_PER_FIELD;
const MODEL_MAX_TEXT_BYTES: usize = 128;
const MODEL_MAX_VALUE_BYTES: usize = 4096;

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn byte(&mut self) -> u8 {
        let value = self.bytes.get(self.offset).copied().unwrap_or_default();
        self.offset = self.offset.saturating_add(1);
        value
    }

    fn pick(&mut self, choices: usize) -> usize {
        debug_assert!(choices > 0);
        usize::from(self.byte()) % choices
    }

    fn token(&mut self, prefix: &str, max_suffix_bytes: usize) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let suffix_len = 1 + self.pick(max_suffix_bytes.max(1));
        let mut value = String::with_capacity(prefix.len() + suffix_len);
        value.push_str(prefix);
        for _ in 0..suffix_len {
            value.push(char::from(HEX[self.pick(HEX.len())]));
        }
        value
    }
}

struct ModelOperation {
    field: SaveField,
    source: SaveConfigSource,
    operation: SaveConfigOperation,
    order: usize,
}

struct Model {
    resolver: SaveConfigResolver,
    precedence: SaveConfigPrecedence,
    wire_format: SaveWireFormat,
    limits: SaveConfigLimits,
    operations: Vec<ModelOperation>,
}

fn decode_wire(byte: u8) -> SaveWireFormat {
    match byte % 4 {
        0 => SaveWireFormat::Csv,
        1 => SaveWireFormat::Xml,
        2 => SaveWireFormat::Properties,
        _ => SaveWireFormat::Unknown,
    }
}

fn decode_precedence(cursor: &mut Cursor<'_>) -> Option<SaveConfigPrecedence> {
    let mut available = SaveConfigSourceKind::all().to_vec();
    let count = 1 + cursor.pick(available.len());
    let mut ordered = Vec::with_capacity(count);
    for _ in 0..count {
        let index = cursor.pick(available.len());
        ordered.push(available.remove(index));
    }
    SaveConfigPrecedence::new("jmeter-5.6.3-fuzz", ordered).ok()
}

fn decode_field(cursor: &mut Cursor<'_>) -> Option<SaveField> {
    let field_id = SaveFieldId::all()[cursor.pick(SaveFieldId::all().len())];
    let name = match cursor.pick(4) {
        0 => field_id.property_name().to_owned(),
        1 => field_id
            .property_aliases()
            .first()
            .copied()
            .unwrap_or(field_id.property_name())
            .to_owned(),
        2 => cursor.token("jmeter.save.saveservice.future.", 10),
        _ => field_id.property_name().to_owned(),
    };
    SaveField::from_property_name(&name).ok()
}

fn decode_source(cursor: &mut Cursor<'_>, kind: SaveConfigSourceKind) -> SaveConfigSource {
    match kind {
        SaveConfigSourceKind::PlanSaveConfig => SaveConfigSource::PlanSaveConfig {
            node_id: u64::from(cursor.byte()).saturating_add(1),
        },
        SaveConfigSourceKind::RunProperties => SaveConfigSource::RunProperties {
            ordinal: u32::from(cursor.byte()),
        },
        SaveConfigSourceKind::CliMode => SaveConfigSource::CliMode {
            mode: match cursor.byte() % 3 {
                0 => CliMode::NormalRun,
                1 => CliMode::ReportAtEnd,
                _ => CliMode::ReportOnly,
            },
        },
        SaveConfigSourceKind::ReportInputMetadata => SaveConfigSource::ReportInputMetadata {
            format: decode_wire(cursor.byte()),
        },
        SaveConfigSourceKind::FormatObservation => SaveConfigSource::FormatObservation {
            format: decode_wire(cursor.byte()),
        },
    }
}

fn value_for_field(field: &SaveField, cursor: &mut Cursor<'_>) -> Option<JavaValue> {
    let Some(field_id) = field.known_id() else {
        return JavaValue::raw(cursor.token("raw-", 12)).ok();
    };
    match field_id.value_kind() {
        SaveValueKind::Boolean => Some(JavaValue::boolean(cursor.byte().is_multiple_of(2))),
        SaveValueKind::Integer => Some(JavaValue::integer(i64::from(cursor.byte()))),
        SaveValueKind::Long => Some(JavaValue::long(i64::from(cursor.byte()))),
        SaveValueKind::String => {
            let value = match field_id {
                SaveFieldId::OutputFormat => {
                    if cursor.byte().is_multiple_of(2) {
                        "csv"
                    } else {
                        "xml"
                    }
                }
                SaveFieldId::TimestampFormat => {
                    if cursor.byte().is_multiple_of(2) {
                        "ms"
                    } else {
                        "yyyy-MM-dd"
                    }
                }
                SaveFieldId::Delimiter => match cursor.byte() % 3 {
                    0 => ",",
                    1 => "\\t",
                    _ => "TAB",
                },
                SaveFieldId::Assertions => "all",
                SaveFieldId::AssertionResults => "all",
                SaveFieldId::DefaultEncoding => "UTF-8",
                _ => "generated-value",
            };
            JavaValue::string(value).ok()
        }
        SaveValueKind::StringList => {
            let first = format!("case_{}", cursor.byte() % 16);
            let second = format!("region_{}", cursor.byte() % 16);
            JavaValue::string_list([first, second]).ok()
        }
        SaveValueKind::Raw => JavaValue::raw(cursor.token("raw-", 12)).ok(),
    }
}

fn decode_operation(field: &SaveField, cursor: &mut Cursor<'_>) -> Option<SaveConfigOperation> {
    match cursor.pick(5) {
        0 => Some(SaveConfigOperation::apply(value_for_field(field, cursor)?)),
        1 => Some(SaveConfigOperation::replace(value_for_field(
            field, cursor,
        )?)),
        2 => Some(SaveConfigOperation::remove()),
        3 => Some(SaveConfigOperation::absent()),
        _ => Some(SaveConfigOperation::present_empty()),
    }
}

fn decode_model(data: &[u8]) -> Option<Model> {
    if data.len() > MAX_INPUT_BYTES {
        return None;
    }
    let mut cursor = Cursor::new(data);
    let precedence = decode_precedence(&mut cursor)?;
    let wire_format = decode_wire(cursor.byte());
    let limits = SaveConfigLimits::new(
        MAX_MODEL_FIELDS * 2,
        MAX_MODEL_OPERATIONS_PER_FIELD * 8,
        MAX_MODEL_OPERATIONS * 2,
        1 + cursor.pick(8),
        MODEL_MAX_TEXT_BYTES,
        MODEL_MAX_VALUE_BYTES,
    )
    .ok()?;
    let mut resolver = SaveConfigResolver::new(precedence.clone(), wire_format, limits).ok()?;
    let mut operations = Vec::new();
    let field_count = 1 + cursor.pick(MAX_MODEL_FIELDS);
    for _ in 0..field_count {
        let field = decode_field(&mut cursor)?;
        let operation_count = 1 + cursor.pick(MAX_MODEL_OPERATIONS_PER_FIELD);
        for _ in 0..operation_count {
            let source_kind =
                SaveConfigSourceKind::all()[cursor.pick(SaveConfigSourceKind::all().len())];
            let source = decode_source(&mut cursor, source_kind);
            let operation = decode_operation(&field, &mut cursor)?;
            let order = resolver
                .push(field.clone(), source, operation.clone())
                .ok()?;
            operations.push(ModelOperation {
                field: field.clone(),
                source,
                operation,
                order,
            });
        }
    }
    Some(Model {
        resolver,
        precedence,
        wire_format,
        limits,
        operations,
    })
}

fn inventory(model: &Model) -> BTreeMap<SaveField, Vec<&ModelOperation>> {
    let mut result = BTreeMap::new();
    for operation in &model.operations {
        result
            .entry(operation.field.clone())
            .or_insert_with(Vec::new)
            .push(operation);
    }
    result
}

fn assert_inventory_conserved(model: &Model) -> BTreeMap<SaveField, Vec<&ModelOperation>> {
    let expected = inventory(model);
    assert_eq!(model.resolver.field_count(), expected.len());
    assert_eq!(model.resolver.operation_count(), model.operations.len());
    for (field, expected_operations) in &expected {
        let actual_operations = model
            .resolver
            .operations(field)
            .expect("accepted model field must retain operations");
        assert_eq!(actual_operations.len(), expected_operations.len());
        for (actual, expected) in actual_operations.iter().zip(expected_operations) {
            assert_eq!(actual.source(), expected.source);
            assert_eq!(actual.operation(), &expected.operation);
            assert_eq!(actual.order(), expected.order);
        }
        assert!(
            actual_operations
                .windows(2)
                .all(|pair| pair[0].order() < pair[1].order())
        );
    }
    expected
}

enum Choice {
    Selected {
        index: usize,
        presence: FieldPresence,
    },
    Ambiguous,
}

struct SourceState {
    kind: SaveConfigSourceKind,
    active: Option<usize>,
    absent: Option<usize>,
}

fn independent_choice(entries: &[&ModelOperation], precedence: &SaveConfigPrecedence) -> Choice {
    let mut states = Vec::<SourceState>::new();
    for (index, entry) in entries.iter().enumerate() {
        let state = if let Some(state) = states
            .iter_mut()
            .find(|state| state.kind == entry.source.kind())
        {
            state
        } else {
            states.push(SourceState {
                kind: entry.source.kind(),
                active: None,
                absent: None,
            });
            states.last_mut().expect("state was inserted")
        };
        match entry.operation.kind() {
            SaveOperationKind::Apply | SaveOperationKind::Replace | SaveOperationKind::Remove => {
                state.active = Some(index);
            }
            SaveOperationKind::PresentEmpty => state.active = Some(index),
            SaveOperationKind::Absent => {
                state.active = None;
                state.absent = Some(index);
            }
        }
    }

    let active = states
        .iter()
        .filter_map(|state| state.active)
        .collect::<Vec<_>>();
    if active
        .iter()
        .any(|index| precedence.rank(entries[*index].source.kind()).is_none())
    {
        return Choice::Ambiguous;
    }
    if let Some(index) = active.into_iter().min_by_key(|index| {
        precedence
            .rank(entries[*index].source.kind())
            .unwrap_or(usize::MAX)
    }) {
        let presence = match entries[index].operation.kind() {
            SaveOperationKind::Remove => FieldPresence::Absent,
            SaveOperationKind::PresentEmpty => FieldPresence::PresentEmpty,
            SaveOperationKind::Apply | SaveOperationKind::Replace => FieldPresence::Present,
            SaveOperationKind::Absent => unreachable!("absent operations are not active"),
        };
        return Choice::Selected { index, presence };
    }

    let index = states
        .iter()
        .filter_map(|state| state.absent)
        .max_by_key(|index| entries[*index].order);
    match index {
        Some(index) => Choice::Selected {
            index,
            presence: FieldPresence::Absent,
        },
        None => unreachable!("a generated field always has an operation"),
    }
}

fn expected_wire_name(field: SaveFieldId, format: SaveWireFormat) -> Option<&'static str> {
    match format {
        SaveWireFormat::Csv => field.csv_header_name(),
        SaveWireFormat::Xml => field.xml_attribute_name(),
        SaveWireFormat::Properties => Some(field.property_name()),
        SaveWireFormat::Unknown => None,
    }
}

fn check_wire(
    field_id: SaveFieldId,
    format: SaveWireFormat,
    presence: FieldPresence,
    value: Option<&JavaValue>,
    wire: &jmeter_rs_results::WireRepresentation,
) {
    assert_eq!(wire.format(), format);
    let name = expected_wire_name(field_id, format);
    assert_eq!(wire.name(), name);
    let expected_value = match (name, presence) {
        (Some(_), FieldPresence::PresentEmpty) => Some(String::new()),
        (Some(_), FieldPresence::Present) => value.map(JavaValue::to_wire_string),
        _ => None,
    };
    assert_eq!(wire.value(), expected_value.as_deref());
}

fn assert_resolution(model: &Model, expected: &BTreeMap<SaveField, Vec<&ModelOperation>>) {
    let resolution = match model.resolver.resolve() {
        Ok(resolution) => resolution,
        Err(error) => {
            // A generated field is always accepted, so the only resolution
            // failure is an explicit missing-precedence or unknown-wire
            // ambiguity.  Its candidates must remain bounded and refer to
            // fields present in the independent inventory.
            assert_eq!(error.stable_code(), "save-config.ambiguous");
            assert!(error.candidates().len() <= model.limits.max_candidates());
            assert!(!error.candidates().is_empty());
            for candidate in error.candidates() {
                assert!(expected.contains_key(candidate.field()));
            }
            return;
        }
    };

    let first_bytes = resolution
        .canonical_bytes()
        .expect("bounded model must canonicalize");
    let second_bytes = resolution
        .canonical_bytes()
        .expect("canonicalization must be repeatable");
    assert_eq!(first_bytes, second_bytes);
    assert!(first_bytes.len() <= MAX_SAVE_CONFIG_CANONICAL_BYTES);
    assert_eq!(
        resolution.canonical_digest().expect("digest"),
        resolution.canonical_digest().expect("repeat digest")
    );
    assert_eq!(resolution.fields().len(), expected.len());
    assert!(
        resolution
            .fields()
            .windows(2)
            .all(|pair| pair[0].field() < pair[1].field())
    );

    for field_resolution in resolution.fields() {
        let field = field_resolution.field();
        let entries = expected.get(field).expect("resolution field was generated");
        assert_eq!(field_resolution.operations().len(), entries.len());
        assert_eq!(
            field_resolution,
            &model
                .resolver
                .resolve_field(field)
                .expect("field resolution must agree with complete resolution")
        );
        if field.known_id().is_none() {
            assert!(field_resolution.is_unresolved());
            assert!(field_resolution.java_value().is_none());
            assert!(field_resolution.provenance().is_none());
            continue;
        }

        let choice = independent_choice(entries, &model.precedence);
        let Choice::Selected { index, presence } = choice else {
            panic!("complete resolution succeeded despite independent ambiguity");
        };
        let selected = entries[index];
        let expected_value = match presence {
            FieldPresence::Absent => None,
            FieldPresence::PresentEmpty => Some(JavaValue::String(String::new())),
            FieldPresence::Present => selected.operation.value().cloned(),
        };
        assert_eq!(field_resolution.final_presence(), Some(presence));
        assert_eq!(field_resolution.java_value(), expected_value.as_ref());
        let provenance = field_resolution.provenance().expect("selected operation");
        assert_eq!(provenance.source(), selected.source);
        assert_eq!(provenance.operation(), selected.operation.kind());
        assert_eq!(provenance.operation_order(), selected.order);
        assert_eq!(
            provenance.precedence_rank(),
            model.precedence.rank(selected.source.kind())
        );
        check_wire(
            field.known_id().expect("known field"),
            model.wire_format,
            presence,
            expected_value.as_ref(),
            field_resolution
                .wire_representation()
                .expect("resolved field has wire state"),
        );
    }
}

fn assert_limit_contract() {
    let limits = SaveConfigLimits::new(1, 1, 2, 1, 8, 8).expect("fixed valid limits");
    let precedence = SaveConfigPrecedence::new(
        "limit-probe",
        [
            SaveConfigSourceKind::PlanSaveConfig,
            SaveConfigSourceKind::RunProperties,
        ],
    )
    .expect("fixed precedence");
    let source = SaveConfigSource::PlanSaveConfig { node_id: 1 };
    let field = SaveField::known(SaveFieldId::OutputFormat);
    let mut resolver = SaveConfigResolver::new(precedence, SaveWireFormat::Properties, limits)
        .expect("fixed resolver");
    resolver
        .push_raw(field.clone(), source, SaveOperationKind::Apply, "csv")
        .expect("first bounded operation");
    let operation_error = resolver
        .push_raw(field.clone(), source, SaveOperationKind::Apply, "xml")
        .expect_err("per-field limit");
    assert_eq!(operation_error.stable_code(), "save-config.limit");
    assert_eq!(resolver.operation_count(), 1);
    let field_error = resolver
        .push_raw(
            SaveField::known(SaveFieldId::PrintFieldNames),
            source,
            SaveOperationKind::Apply,
            "true",
        )
        .expect_err("field limit");
    assert_eq!(field_error.stable_code(), "save-config.limit");
    let text_error = resolver
        .push_raw(field, source, SaveOperationKind::Apply, "123456789")
        .expect_err("text limit");
    assert_eq!(text_error.stable_code(), "save-config.limit");
}

fuzz_target!(|data: &[u8]| {
    assert_limit_contract();
    let Some(model) = decode_model(data) else {
        return;
    };
    let expected = assert_inventory_conserved(&model);
    assert_resolution(&model, &expected);
});

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_stays_bounded_and_conserved() {
        let model = decode_model(&[]).expect("empty input has a deterministic model");
        let expected = assert_inventory_conserved(&model);
        assert_resolution(&model, &expected);
    }

    #[test]
    fn generated_input_retains_unknown_property_operations() {
        let bytes = [2, 3, 7, 0, 1, 2, 9, 4, 3, 1, 8, 2, 6, 5, 4, 3, 2, 1];
        let model = decode_model(&bytes).expect("synthetic model");
        let expected = assert_inventory_conserved(&model);
        assert_resolution(&model, &expected);
    }
}
