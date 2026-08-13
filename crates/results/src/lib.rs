// SPDX-License-Identifier: Apache-2.0
//! Pure sample-result and result-event domain types.
//!
//! This crate deliberately has no runtime, filesystem, network, XML, or CSV
//! dependencies.  It models the information that a JMeter result listener can
//! observe.  Fields which can be absent on a JTL wire format are represented by
//! [`Option`]; a present empty string or byte vector remains distinguishable
//! from an absent field.

#![forbid(unsafe_code)]

pub mod csv;
mod data;
mod error;
mod event;
pub mod jtl;
mod result;
pub mod save_config_resolution;
mod timing;
pub mod xml;

pub use csv::{
    CsvDecoder, CsvEncoder, CsvReader, CsvWriter, decode_csv, decode_csv_with_limit, encode_csv,
    read_csv, write_csv,
};
pub use data::{
    BodyDiagnostic, BodyKind, BodyProjection, DataDiagnostic, DataEncoding, DataError,
    DataErrorCode, DataField, DataLimits, DataType, DataTypeDiagnostic, EncodingDiagnostic,
    FileReference, FileReferenceDiagnostic, FileReferenceProjection, HeaderBlock, HeaderDiagnostic,
    RequestData, RequestHeaders, ResponseData, ResponseFileReference, ResponseHeaders, SampleBody,
    SampleData, SampleDataProjection,
};
pub use error::{
    AssertionViolation, HierarchyLimit, InputField, MAX_RESULT_ERROR_CONTEXT_BYTES,
    MAX_RESULT_ERROR_CONTEXT_DEPTH, ResultContextError, ResultError, ResultErrorCode,
    ResultErrorContext, ResultField, ResultRetryability, ResultSourceContext, TimingViolation,
};
pub use event::{
    HostId, HostIdentity, RunId, RunIdentity, SampleEvent, ThreadId, ThreadIdentity,
    TransactionState, VariableSnapshot, VariableValue,
};
pub use jtl::{
    AssertionResults, CsvColumn, CsvField, DateFormatProvider, JavaDateFormatProvider, JtlCounter,
    JtlDecoder, JtlEncoder, JtlError, JtlFormat, JtlLimits, JtlOutputPolicy, LineEnding,
    MAX_DECODE_ALL_EVENTS, MAX_JTL_ATTRIBUTE_BYTES, MAX_JTL_ATTRIBUTES, MAX_JTL_COLUMNS,
    MAX_JTL_DEPTH, MAX_JTL_FIELDS, MAX_JTL_INPUT_BYTES, MAX_JTL_NODES, MAX_JTL_OUTPUT_BYTES,
    MAX_JTL_PAYLOAD_BYTES, MAX_JTL_RECORD_BYTES, MAX_JTL_SAMPLES, SampleSaveConfiguration,
    TimestampFormat, XmlSampleElement, decode_jtl, decode_jtl_with_limit, encode_jtl, read_jtl,
    write_jtl,
};
pub use result::{
    AssertionOutcome, AssertionResult, ByteCount, ConnectTime, ElapsedTime, ErrorCount, IdleTime,
    Latency, LogicalAction, SampleCount, SampleFlags, SampleResult, SampleResultTiming,
    ThreadCount, ValidationLimits,
};
pub use save_config_resolution::*;
pub use timing::{
    SampleTiming, Timestamp, TimestampMillis, TimestampSource, TimingReading, WallTimestamp,
};
pub use xml::{
    XmlDecodeConfiguration, XmlDecoder, XmlEncoder, XmlReader, XmlWriter, decode_xml,
    decode_xml_with_configuration, decode_xml_with_limit, encode_xml, read_xml, write_xml,
};

/// The crate's fallible result alias.
pub type Result<T> = core::result::Result<T, ResultError>;

/// Compatibility alias for the model's hierarchy limits.
pub type HierarchyLimits = ValidationLimits;
/// Compatibility alias for the model's stable error type.
pub type ResultModelError = ResultError;
/// Compatibility alias for errors returned by [`SampleResult`] operations.
pub type SampleResultError = ResultError;

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(depth: usize, nodes: usize) -> ValidationLimits {
        let value = ValidationLimits::new(depth, nodes);
        assert!(value.is_ok(), "test limits must be valid");
        value.unwrap_or_default()
    }

    #[test]
    fn signed_wire_numbers_reject_negative_values() {
        for result in [
            ElapsedTime::try_from(-1_i64).map(|_| ()),
            Latency::try_from(-1_i64).map(|_| ()),
            ConnectTime::try_from(-1_i64).map(|_| ()),
            IdleTime::try_from(-1_i64).map(|_| ()),
            ByteCount::try_from(-1_i64).map(|_| ()),
            ThreadCount::try_from(-1_i64).map(|_| ()),
            SampleCount::try_from(-1_i64).map(|_| ()),
            ErrorCount::try_from(-1_i64).map(|_| ()),
        ] {
            assert!(matches!(
                result,
                Err(ResultError::InvalidInput {
                    field: InputField::NegativeNumber(_)
                })
            ));
        }
    }

    #[test]
    fn checked_arithmetic_reports_overflow() {
        assert_eq!(
            ElapsedTime::from_millis(u64::MAX).checked_add(ElapsedTime::from_millis(1)),
            Err(ResultError::Overflow {
                field: ResultField::Elapsed
            })
        );
        assert_eq!(
            ByteCount::new(u64::MAX).checked_add(ByteCount::new(1)),
            Err(ResultError::Overflow {
                field: ResultField::ReceivedBytes
            })
        );
        assert_eq!(
            WallTimestamp::from_millis(i64::MAX).checked_add_millis(1),
            Err(ResultError::Overflow {
                field: ResultField::Timestamp
            })
        );
        assert_eq!(
            ResultError::Overflow {
                field: ResultField::Timestamp
            }
            .stable_code(),
            "results.overflow"
        );
    }

    #[test]
    fn timing_keeps_distinct_measurements_and_checks_relations() {
        let timing = SampleTiming::from_parts(
            Some(WallTimestamp::from_millis(150)),
            Some(WallTimestamp::from_millis(100)),
            Some(WallTimestamp::from_millis(200)),
            Some(ElapsedTime::from_millis(100)),
            Some(Latency::from_millis(30)),
            Some(ConnectTime::from_millis(20)),
            Some(IdleTime::from_millis(10)),
        );
        assert!(timing.is_ok());
        assert!(timing.is_ok(), "valid timing rejected");
        let timing = timing.unwrap_or_default();
        assert_eq!(timing.timestamp().map(WallTimestamp::as_millis), Some(150));
        assert_eq!(timing.elapsed().map(ElapsedTime::as_millis), Some(100));
        assert_eq!(timing.latency().map(Latency::as_millis), Some(30));
        assert_eq!(timing.connect().map(ConnectTime::as_millis), Some(20));
        assert_eq!(timing.idle().map(IdleTime::as_millis), Some(10));

        assert_eq!(
            SampleTiming::from_parts(
                None,
                Some(WallTimestamp::from_millis(200)),
                Some(WallTimestamp::from_millis(100)),
                None,
                None,
                None,
                None,
            ),
            Err(ResultError::InvalidTiming {
                violation: TimingViolation::EndBeforeStart
            })
        );
        let wire = SampleTiming::from_wire_parts(
            None,
            None,
            None,
            Some(ElapsedTime::from_millis(1)),
            Some(Latency::from_millis(3)),
            Some(ConnectTime::from_millis(4)),
            Some(IdleTime::from_millis(5)),
        );
        assert!(wire.validate().is_err());
        let mut wire_result = SampleResult::new("wire");
        wire_result.set_timing_from_wire(wire);
        assert!(wire_result.validate_wire_with_limits(limits(4, 4)).is_ok());
        assert_eq!(
            SampleTiming::from_parts(
                None,
                None,
                None,
                Some(ElapsedTime::from_millis(2)),
                Some(Latency::from_millis(3)),
                None,
                None,
            ),
            Err(ResultError::InvalidTiming {
                violation: TimingViolation::LatencyExceedsElapsed
            })
        );
    }

    #[test]
    fn absent_and_present_empty_values_are_distinct() {
        let mut result = SampleResult::new("empty-fields");
        assert!(result.has_label());
        assert_eq!(result.label_field(), Some("empty-fields"));
        result.clear_label();
        assert!(!result.has_label());
        assert_eq!(result.label(), "");
        result.set_label("empty-fields");
        assert!(result.response_message().is_none());
        assert!(result.response_data().is_none());
        assert!(result.response_headers().is_none());
        result.set_response_message(Some(String::new()));
        result.set_response_data(Some(SampleData::empty()));
        result.set_response_headers(Some(HeaderBlock::empty()));
        result.set_data_encoding(Some(DataEncoding::new(String::new())));
        assert_eq!(result.response_message(), Some(""));
        assert!(result.response_data().is_some_and(SampleData::is_empty));
        assert!(result.response_headers().is_some_and(HeaderBlock::is_empty));
        assert_eq!(result.data_encoding().map(DataEncoding::as_str), Some(""));
        result.set_response_data(None);
        assert!(result.response_data().is_none());
    }

    #[test]
    fn assertion_flags_retain_independent_wire_states() {
        let error = AssertionResult::from_flags("assert", true, true, None, None);
        let error = match error {
            Ok(value) => value,
            Err(_) => return,
        };
        assert!(error.is_failure());
        assert!(error.is_error());
        let failure = AssertionResult::from_flags("assert", true, false, Some(String::new()), None);
        assert!(failure.is_ok(), "valid assertion rejected");
        let failure = match failure {
            Ok(value) => value,
            Err(_) => return,
        };
        assert!(failure.is_failure());
        assert_eq!(failure.failure_message(), Some(""));
        assert!(!failure.is_error());
    }

    #[test]
    fn aggregation_updates_end_and_counts_without_summing_distinct_timing() {
        let mut parent = SampleResult::new("parent");
        assert!(
            parent
                .set_start_time(Some(WallTimestamp::from_millis(100)))
                .is_ok()
        );
        assert!(
            parent
                .set_end_time(Some(WallTimestamp::from_millis(150)))
                .is_ok()
        );
        assert!(parent.timing().elapsed().is_none());
        parent.set_successful(true);
        parent.set_received_bytes(Some(ByteCount::new(10)));
        parent.set_sent_bytes(Some(ByteCount::new(2)));
        parent.set_sample_count(Some(SampleCount::ONE));
        parent.set_error_count(Some(ErrorCount::ZERO));

        let mut child = SampleResult::new("child");
        assert!(
            child
                .set_start_time(Some(WallTimestamp::from_millis(160)))
                .is_ok()
        );
        assert!(
            child
                .set_end_time(Some(WallTimestamp::from_millis(220)))
                .is_ok()
        );
        assert!(
            child
                .set_elapsed(Some(ElapsedTime::from_millis(60)))
                .is_ok()
        );
        child.set_successful(false);
        child.set_received_bytes(Some(ByteCount::new(3)));
        child.set_sent_bytes(Some(ByteCount::new(4)));
        child.set_sample_count(Some(SampleCount::ONE));
        child.set_error_count(Some(ErrorCount::from_u64(1)));
        assert!(child.set_latency(Some(Latency::from_millis(5))).is_ok());

        assert!(parent.try_add_sub_result(child, limits(8, 8)).is_ok());
        assert_eq!(parent.sub_results().len(), 1);
        assert_eq!(
            parent.timing().end().map(WallTimestamp::as_millis),
            Some(220)
        );
        assert_eq!(
            parent.timing().elapsed().map(ElapsedTime::as_millis),
            Some(120)
        );
        assert_eq!(parent.received_bytes().map(ByteCount::as_u64), Some(13));
        assert_eq!(parent.sent_bytes().map(ByteCount::as_u64), Some(6));
        assert_eq!(parent.sample_count().map(SampleCount::as_u64), Some(2));
        assert_eq!(parent.error_count().map(ErrorCount::as_u64), Some(1));
        assert_eq!(parent.success(), Some(false));
    }

    #[test]
    fn aggregation_is_atomic_on_counter_overflow() {
        let mut parent = SampleResult::new("parent");
        parent.set_received_bytes(Some(ByteCount::new(u64::MAX)));
        let mut child = SampleResult::new("child");
        child.set_received_bytes(Some(ByteCount::new(1)));
        let error = parent.try_add_sub_result(child, limits(4, 4));
        assert_eq!(
            error,
            Err(ResultError::Overflow {
                field: ResultField::ReceivedBytes
            })
        );
        assert!(parent.sub_results().is_empty());
        assert_eq!(
            parent.received_bytes().map(ByteCount::as_u64),
            Some(u64::MAX)
        );
    }

    #[test]
    fn hierarchy_limits_are_checked_iteratively() {
        assert!(matches!(
            ValidationLimits::new(0, 1),
            Err(ResultError::InvalidInput {
                field: InputField::EmptyLimit
            })
        ));
        let wide = limits(64, 64);
        let mut leaf = SampleResult::new("leaf");
        for index in 0..8 {
            let mut parent = SampleResult::new(format!("parent-{index}"));
            assert!(parent.try_add_sub_result(leaf, wide).is_ok());
            leaf = parent;
        }
        assert!(leaf.validate_with_limits(limits(9, 9)).is_ok());
        assert!(matches!(
            leaf.validate_with_limits(limits(8, 9)),
            Err(ResultError::HierarchyLimitExceeded {
                limit: HierarchyLimit::Depth,
                ..
            })
        ));
        assert!(matches!(
            leaf.validate_with_limits(limits(64, 8)),
            Err(ResultError::HierarchyLimitExceeded {
                limit: HierarchyLimit::Nodes,
                ..
            })
        ));
    }

    #[test]
    fn raw_batch_hierarchy_update_is_atomic_and_bounded() {
        let batch_limits = limits(4, 3);
        let mut parent = SampleResult::new("parent");
        let before = parent.clone();
        let result = parent.try_add_sub_results_raw(
            [
                SampleResult::new("one"),
                SampleResult::new("two"),
                SampleResult::new("three"),
            ],
            batch_limits,
        );
        assert!(matches!(
            result,
            Err(ResultError::HierarchyLimitExceeded {
                limit: HierarchyLimit::Nodes,
                ..
            })
        ));
        assert_eq!(parent, before);
        assert!(
            parent
                .try_add_sub_results_raw(
                    [SampleResult::new("one"), SampleResult::new("two")],
                    batch_limits
                )
                .is_ok()
        );
        assert_eq!(parent.sub_results().len(), 2);

        let mut consumed = 0;
        let mut bounded_parent = SampleResult::new("bounded");
        let result = bounded_parent.try_add_sub_results_raw(
            std::iter::from_fn(|| {
                consumed += 1;
                Some(SampleResult::new("child"))
            }),
            limits(4, 2),
        );
        assert!(matches!(
            result,
            Err(ResultError::HierarchyLimitExceeded {
                limit: HierarchyLimit::Nodes,
                ..
            })
        ));
        assert_eq!(
            consumed, 2,
            "batch builder must stop at the first bound breach"
        );
        assert!(bounded_parent.sub_results().is_empty());
    }

    #[test]
    fn deeply_nested_results_use_bounded_iterative_paths() {
        let wide = limits(512, 512);
        let mut leaf = SampleResult::new("leaf");
        for index in 0..256 {
            let mut parent = SampleResult::new(format!("node-{index}"));
            assert!(parent.try_add_sub_result(leaf, wide).is_ok());
            leaf = parent;
        }
        assert!(leaf.validate_with_limits(wide).is_ok());
        // Explicitly exercise the custom iterative Drop implementation.
        drop(leaf);
    }

    #[test]
    fn snapshot_isolation_copies_result_and_variables() {
        let mut result = SampleResult::new("before");
        result.set_response_message(Some(String::from("old")));
        let mut variables = VariableSnapshot::new();
        variables.insert("empty", String::new());
        variables.insert_absent("missing");
        let event = SampleEvent::snapshot(
            &result,
            "run-1",
            ThreadIdentity::new("thread-1"),
            "host-1",
            &variables,
        );
        assert!(event.is_ok(), "valid event rejected");
        let event = match event {
            Ok(value) => value,
            Err(_) => return,
        };

        result.set_label("after");
        result.set_response_message(Some(String::from("new")));
        variables.insert("empty", String::from("changed"));
        variables.insert("new", String::from("value"));

        assert_eq!(event.result().label(), "before");
        assert_eq!(event.result().response_message(), Some("old"));
        assert_eq!(
            event
                .variables()
                .get("empty")
                .and_then(VariableValue::as_str),
            Some("")
        );
        assert_eq!(
            event.variables().get("missing"),
            Some(&VariableValue::Absent)
        );
        assert!(event.variables().get("new").is_none());
        assert_eq!(event.run().as_str(), "run-1");
        assert_eq!(event.thread().name(), "thread-1");
        assert_eq!(event.host().as_str(), "host-1");
    }

    #[test]
    fn data_type_preserves_unknown_wire_values() {
        assert_eq!(DataType::from_wire("text").as_wire(), "text");
        assert_eq!(DataType::from_wire("bin").as_wire(), "bin");
        assert_eq!(DataType::from_wire("extension").as_wire(), "extension");
        assert_eq!(DataType::from_wire("").as_wire(), "");
    }

    #[test]
    fn save_properties_retain_runtime_and_wire_switches() {
        assert!(SampleSaveConfiguration::default().timestamp_start());
        let configuration = SampleSaveConfiguration::from_properties([
            ("jmeter.save.saveservice.timestamp_format", "none"),
            ("jmeter.save.saveservice.default_delimiter", "TAB"),
            ("jmeter.save.saveservice.assertions", "all"),
            ("sampleresult.timestamp.start", "true"),
            ("sampleresult.useNanoTime", "false"),
            ("sampleresult.nanoThreadSleep", "-1"),
            ("subresults.disable_renaming", "true"),
            ("sampleresult.default.encoding", "ISO-8859-1"),
            (
                "jmeter.save.saveservice.sample_variables",
                "case_id,comma_value",
            ),
        ]);
        assert!(configuration.is_ok(), "save configuration should parse");
        let configuration = configuration.unwrap_or_default();
        assert_eq!(configuration.timestamp_format(), &TimestampFormat::None);
        assert_eq!(configuration.delimiter(), '\t');
        assert_eq!(configuration.assertion_results(), AssertionResults::All);
        assert!(configuration.timestamp_start());
        assert!(!configuration.use_nano_time());
        assert_eq!(configuration.nano_thread_sleep(), -1);
        assert!(configuration.subresults_disable_renaming());
        assert_eq!(configuration.default_encoding(), Some("ISO-8859-1"));
        assert_eq!(configuration.sample_variables(), ["case_id", "comma_value"]);
        assert!(matches!(
            SampleSaveConfiguration::from_properties([(
                "jmeter.save.saveservice.sample_variables",
                "case_id,,region",
            )]),
            Err(jtl::JtlError::InvalidConfiguration {
                field: "sample_variables",
                ..
            })
        ));
        let configuration = SampleSaveConfiguration::from_properties([(
            "jmeter.save.saveservice.autoflush",
            "true",
        )]);
        assert!(configuration.is_ok());
        let configuration = configuration.unwrap_or_default();
        assert!(configuration.autoflush());
        assert!(matches!(
            SampleSaveConfiguration::from_properties([(
                "jmeter.save.saveservice.error_count",
                "true",
            )]),
            Err(jtl::JtlError::Unsupported {
                feature: "jtl-save-property",
                ..
            })
        ));
        let mut configuration = SampleSaveConfiguration::default();
        configuration.set_sample_count(true);
        assert!(configuration.save_sample_count());
        assert!(configuration.save_error_count());
        assert!(configuration.saves(CsvField::SampleCount));
        assert!(configuration.saves(CsvField::ErrorCount));
        configuration.set_error_count(false);
        assert!(!configuration.save_sample_count());
        assert!(!configuration.save_error_count());
        assert!(!configuration.saves(CsvField::SampleCount));
        assert!(!configuration.saves(CsvField::ErrorCount));
        assert!(matches!(
            SampleSaveConfiguration::from_properties([(
                "jmeter.save.saveservice.unknown_extension",
                "true",
            )]),
            Err(jtl::JtlError::Unsupported {
                feature: "jtl-save-property",
                ..
            })
        ));
        assert!(matches!(
            SampleSaveConfiguration::from_properties([("jmeter.save.saveservice.xml_pi", "true",)]),
            Err(jtl::JtlError::Unsupported {
                feature: "xml-processing-instruction",
                ..
            })
        ));
        assert!(matches!(
            SampleSaveConfiguration::from_properties([(
                "jmeter.save.saveservice.base_prefix",
                "relative",
            )]),
            Err(jtl::JtlError::Unsupported {
                feature: "jtl-base-prefix",
                ..
            })
        ));
    }

    #[test]
    fn debug_diagnostics_redact_payloads_and_bound_output() {
        let body_secret = "response-body-secret";
        let header_secret = "Authorization: Bearer header-secret";
        let variable_secret = "variable-secret";
        let assertion_secret = "assertion-secret";

        let data_debug = format!("{:?}", SampleData::from(body_secret));
        assert!(data_debug.contains("len:"));
        assert!(!data_debug.contains(body_secret));

        let header_debug = format!("{:?}", HeaderBlock::new(header_secret));
        assert!(header_debug.contains("len:"));
        assert!(!header_debug.contains(header_secret));

        let variable_debug = format!("{:?}", VariableValue::present(variable_secret));
        assert!(variable_debug.contains("len:"));
        assert!(!variable_debug.contains(variable_secret));

        let mut variables = VariableSnapshot::new();
        variables.insert("secret_name", variable_secret);
        let variables_debug = format!("{:?}", variables);
        assert!(variables_debug.contains("entries: 1"));
        assert!(!variables_debug.contains(variable_secret));

        let mut result = SampleResult::new("label-secret");
        result.set_response_data(Some(SampleData::new(vec![b'x'; 1024 * 1024])));
        result.set_response_headers(Some(HeaderBlock::new(header_secret)));
        result.set_sampler_data_text(body_secret);
        result.set_response_file_text("response-file-secret");
        result.set_url_text("https://example.invalid/secret");
        assert!(
            result
                .add_assertion(AssertionResult::failed(
                    assertion_secret,
                    Some(assertion_secret.to_owned()),
                ))
                .is_ok()
        );
        let event = SampleEvent::new(
            result,
            "run-secret",
            ThreadIdentity::new("thread-secret"),
            "host-secret",
            variables,
        );
        let event_debug = format!("{:?}", event);
        for secret in [
            body_secret,
            header_secret,
            variable_secret,
            assertion_secret,
            "label-secret",
            "response-file-secret",
            "https://example.invalid/secret",
            "run-secret",
            "thread-secret",
            "host-secret",
        ] {
            assert!(!event_debug.contains(secret), "debug leaked {secret:?}");
        }
        assert!(event_debug.contains("response_data_len: Some(1048576)"));
        assert!(event_debug.len() < 4096);

        let assertion =
            AssertionResult::failed(assertion_secret, Some(assertion_secret.to_owned()));
        let assertion_debug = format!("{:?}", assertion);
        assert!(!assertion_debug.contains(assertion_secret));
        assert!(assertion_debug.len() < 1024);

        let data_type_debug = format!("{:?}", DataType::Other(variable_secret.to_owned()));
        assert!(!data_type_debug.contains(variable_secret));
        let encoding_debug = format!("{:?}", DataEncoding::new(variable_secret));
        assert!(!encoding_debug.contains(variable_secret));
        let mut save_configuration = SampleSaveConfiguration::default();
        save_configuration.set_default_encoding(Some(variable_secret.to_owned()));
        assert!(
            save_configuration
                .set_sample_variables(["secret_variable"])
                .is_ok()
        );
        let save_debug = format!("{save_configuration:?}");
        assert!(!save_debug.contains(variable_secret));
        assert!(!save_debug.contains("secret_variable"));
        let decode_configuration =
            XmlDecodeConfiguration::new().with_sample_variables(["secret_variable"]);
        assert!(decode_configuration.is_ok());
        let decode_configuration = decode_configuration.unwrap_or_default();
        let decode_debug = format!("{decode_configuration:?}");
        assert!(!decode_debug.contains("secret_variable"));
    }

    #[test]
    fn jtl_error_diagnostics_redact_dynamic_input_in_debug_and_display() {
        let secret = "Authorization: Bearer error-secret /private/response.jtl";
        let errors = [
            JtlError::Io {
                operation: "read CSV input",
                message: secret.to_owned(),
            },
            JtlError::Csv {
                record: 3,
                detail: secret.to_owned(),
            },
            JtlError::Xml {
                offset: 17,
                detail: secret.to_owned(),
            },
            JtlError::Unsupported {
                feature: "xml-version",
                value: secret.to_owned(),
            },
        ];
        for error in errors {
            let debug = format!("{error:?}");
            let display = error.to_string();
            assert!(!debug.contains(secret), "debug leaked dynamic input");
            assert!(!display.contains(secret), "display leaked dynamic input");
            assert!(debug.contains("redacted"));
            assert!(display.contains("redacted"));
            assert!(display.contains(error.stable_code()));
        }
    }
}
