#![no_main]

//! Bounded JMeter save-service property configuration target.
//!
//! The target applies the pure `SampleSaveConfiguration` property semantics
//! to a bounded, UTF-8 property stream.  Comments and blank lines follow the
//! Java-properties boundary convention; malformed non-comment lines are
//! rejected by this scanner rather than silently skipped or truncated.
//!
//! The production API intentionally ignores unrelated JMeter properties.  We
//! inventory those keys and compare the mixed stream with its recognized-only
//! projection, so this target asserts the documented ignore contract rather
//! than incorrectly claiming that configuration parsing is no-drop.
//!
//! Invariants: `CONFIG-UNKNOWN-IGNORED-001` checks the explicit unrelated-key
//! contract, `CONFIG-DUPLICATE-001` retains ordered last-write semantics, and
//! `CONFIG-BOUNDS-001` keeps line, byte, and column bounds visible.
//! Source-side coverage: ordered property key/value pairs and the
//! recognized-only projection are inventoried before configuration decoding.
//! I/O policy: none; property text is supplied from bounded memory.

use std::collections::BTreeMap;

use jmeter_rs_results::{JtlError, SampleSaveConfiguration};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 64 * 1024;
const MAX_LINES: usize = 64;
const MAX_LINE_BYTES: usize = 2048;
const MAX_COLUMNS: usize = 64;

const KNOWN_PROPERTY_KEYS: &[&str] = &[
    "jmeter.save.saveservice.output_format",
    "jmeter.save.saveservice.timestamp_format",
    "jmeter.save.saveservice.default_delimiter",
    "jmeter.save.saveservice.print_field_names",
    "jmeter.save.saveservice.time",
    "jmeter.save.saveservice.latency",
    "jmeter.save.saveservice.connect_time",
    "jmeter.save.saveservice.timestamp",
    "jmeter.save.saveservice.successful",
    "jmeter.save.saveservice.label",
    "jmeter.save.saveservice.response_code",
    "jmeter.save.saveservice.response_message",
    "jmeter.save.saveservice.thread_name",
    "jmeter.save.saveservice.data_type",
    "jmeter.save.saveservice.encoding",
    "jmeter.save.saveservice.assertions",
    "jmeter.save.saveservice.assertion_results",
    "jmeter.save.saveservice.subresults",
    "jmeter.save.saveservice.response_data",
    "jmeter.save.saveservice.response_data.on_error",
    "jmeter.save.saveservice.samplerData",
    "jmeter.save.saveservice.responseHeaders",
    "jmeter.save.saveservice.requestHeaders",
    "jmeter.save.saveservice.bytes",
    "jmeter.save.saveservice.sent_bytes",
    "jmeter.save.saveservice.url",
    "jmeter.save.saveservice.filename",
    "jmeter.save.saveservice.hostname",
    "jmeter.save.saveservice.thread_counts",
    "jmeter.save.saveservice.sample_count",
    "jmeter.save.saveservice.error_count",
    "jmeter.save.saveservice.idle_time",
    "jmeter.save.saveservice.assertion_results_failure_message",
    "jmeter.save.saveservice.failure_message",
    "jmeter.save.saveservice.autoflush",
    "jmeter.save.saveservice.xml_pi",
    "jmeter.save.saveservice.base_prefix",
    "sampleresult.timestamp.start",
    "sampleresult.useNanoTime",
    "sampleresult.nanoThreadSleep",
    "subresults.disable_renaming",
    "sampleresult.default.encoding",
    "sample_variables",
    "jmeter.save.saveservice.sample_variables",
];

fn is_known_property(key: &str) -> bool {
    KNOWN_PROPERTY_KEYS.contains(&key)
}

fn expected_unsupported_property(key: &str) -> Option<&'static str> {
    match key {
        "jmeter.save.saveservice.xml_pi" => Some("xml-processing-instruction"),
        "jmeter.save.saveservice.base_prefix" => Some("jtl-base-prefix"),
        _ => None,
    }
}

fn parse_lines(data: &[u8]) -> Option<Vec<(String, String)>> {
    let text = std::str::from_utf8(data).ok()?;
    let mut properties = Vec::new();
    for (line_number, raw_line) in text.split('\n').enumerate() {
        if line_number >= MAX_LINES || raw_line.len() > MAX_LINE_BYTES {
            return None;
        }
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') {
            continue;
        }

        let (key, value) = line
            .split_once('=')
            .or_else(|| line.split_once(':'))
            .or_else(|| {
                line.find(char::is_whitespace)
                    .map(|index| line.split_at(index))
            })?;
        let key = key.trim();
        if key.is_empty() {
            return None;
        }
        properties.push((key.to_owned(), value.trim().to_owned()));
    }
    (!properties.is_empty()).then_some(properties)
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }
    let Some(properties) = parse_lines(data) else {
        return;
    };

    // These properties are recognized deliberately but require an outer
    // document/path policy.  Assert the typed capability error on each one
    // before applying the ordinary recognized/unknown projection.
    for (key, value) in &properties {
        let Some(feature) = expected_unsupported_property(key) else {
            continue;
        };
        let result = SampleSaveConfiguration::from_properties([(key.as_str(), value.as_str())]);
        if !matches!(
            result,
            Err(JtlError::Unsupported {
                feature: actual,
                ..
            }) if actual == feature
        ) {
            panic!("recognized unsupported property returned the wrong error: {key}");
        }
        return;
    }

    let ordered = SampleSaveConfiguration::from_properties(
        properties
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str())),
    );

    // A map is equivalent only when no duplicate key was present.  Keeping
    // this comparison makes duplicate-last-wins behavior explicit while
    // retaining the ordered API as the source of truth.
    let mut map = BTreeMap::new();
    let mut duplicate = false;
    for (key, value) in &properties {
        if map.insert(key.clone(), value.clone()).is_some() {
            duplicate = true;
        }
    }
    if !duplicate {
        let mapped = SampleSaveConfiguration::from_property_map(&map);
        match (&mapped, &ordered) {
            (Ok(left), Ok(right)) if left != right => {
                panic!("property map and ordered configuration semantics diverged")
            }
            (Ok(_), Err(_)) | (Err(_), Ok(_)) => {
                panic!("property map and ordered configuration error semantics diverged")
            }
            _ => {}
        }
    } else {
        // CONFIG-DUPLICATE-001: collapse each key to its final source value
        // while retaining the order of those final occurrences.  The
        // ordered API must have the same last-write semantics as this
        // explicitly collapsed stream.
        let collapsed = properties
            .iter()
            .enumerate()
            .filter_map(|(index, (key, value))| {
                let last = properties
                    .iter()
                    .rposition(|(candidate, _)| candidate == key)?;
                (last == index).then_some((key.as_str(), value.as_str()))
            });
        let collapsed = SampleSaveConfiguration::from_properties(collapsed);
        match (&ordered, &collapsed) {
            (Ok(left), Ok(right)) if left != right => {
                panic!("duplicate property did not use last-write semantics")
            }
            (Ok(_), Err(_)) | (Err(_), Ok(_)) => {
                panic!("duplicate property changed configuration error semantics")
            }
            _ => {}
        }
    }

    let unknown = properties
        .iter()
        .filter(|(key, _)| !is_known_property(key))
        .collect::<Vec<_>>();
    if !unknown.is_empty() {
        // CONFIG-UNKNOWN-IGNORED-001: unknown-only input is accepted and has
        // exactly the default semantics declared by the production API.
        let unknown_only = SampleSaveConfiguration::from_properties(
            unknown
                .iter()
                .map(|entry| (entry.0.as_str(), entry.1.as_str())),
        )
        .expect("unrelated properties must not become configuration errors");
        if unknown_only != SampleSaveConfiguration::default() {
            panic!("unrelated property changed save configuration semantics");
        }

        // Unknown keys are not a no-drop promise.  They are intentionally
        // discarded by this API; compare the mixed stream with the exact
        // recognized-key projection so a future implementation cannot start
        // treating an unknown value as an accidental recognized setting.
        let recognized_only = SampleSaveConfiguration::from_properties(
            properties
                .iter()
                .filter(|(key, _)| is_known_property(key))
                .map(|(key, value)| (key.as_str(), value.as_str())),
        );
        match (&ordered, &recognized_only) {
            (Ok(left), Ok(right)) if left != right => {
                panic!("unknown property changed recognized configuration semantics")
            }
            (Ok(_), Err(_)) | (Err(_), Ok(_)) => {
                panic!("unknown property changed recognized configuration errors")
            }
            _ => {}
        }
    }

    if let Ok(configuration) = &ordered {
        // CONFIG-BOUNDS-001: retain explicit column and input bounds at the
        // fuzz boundary even when the parser accepts a property stream.
        if configuration.columns().len() > MAX_COLUMNS {
            return;
        }
        configuration
            .validate()
            .expect("configuration produced by from_properties must validate");
    }
});
