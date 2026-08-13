// SPDX-License-Identifier: Apache-2.0
//! Bounded, replayable input detection for report-only JTL decoding.
//!
//! Report input detection must not consume bytes that the selected CSV/XML
//! decoder needs.  [`ReportInput`] therefore keeps only a bounded probe in a
//! cursor and chains that cursor to the original reader.  It never reads the
//! complete input or asks a caller to provide a filesystem path.

#![forbid(unsafe_code)]
#![allow(
    clippy::module_name_repetitions,
    reason = "the app edge names the report input type and errors explicitly"
)]

use std::fmt;
use std::io::{self, Chain, Cursor, ErrorKind, Read};

use jmeter_rs_results::JtlFormat;

/// Maximum number of bytes used to classify a report input.
///
/// One additional byte is probed, below, so input whose first meaningful byte
/// is just outside this prefix fails closed instead of being classified from a
/// partial observation.
pub(crate) const MAX_REPORT_INPUT_PREFIX_BYTES: usize = 64 * 1024;

const REPORT_INPUT_PROBE_BYTES: usize = MAX_REPORT_INPUT_PREFIX_BYTES + 1;
const UTF8_BOM: [u8; 3] = [0xef, 0xbb, 0xbf];

/// A bounded report-input detection failure.
///
/// The error retains only an [`ErrorKind`] for underlying I/O.  Platform error
/// text can contain paths or other input-controlled data, so it is never
/// copied into this diagnostic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReportInputError {
    /// The input ended before a meaningful format marker was observed.
    Ambiguous,
    /// The first meaningful byte lies beyond the bounded detection prefix.
    PrefixLimit,
    /// The configured format disagrees with the observed format marker.
    FormatMismatch {
        /// Format selected by the caller.
        configured: JtlFormat,
        /// Format observed from the input prefix.
        observed: JtlFormat,
    },
    /// The bounded probe could not be read.
    Io {
        /// Underlying platform error category, without its free-form text.
        kind: ErrorKind,
    },
}

impl ReportInputError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::Ambiguous => "app.report-input.ambiguous",
            Self::PrefixLimit => "app.report-input.prefix-limit",
            Self::FormatMismatch { .. } => "app.report-input.format-mismatch",
            Self::Io { .. } => "app.report-input.io",
        }
    }

    /// Returns the underlying I/O category, if this is an I/O failure.
    #[must_use]
    pub(crate) const fn io_kind(self) -> Option<ErrorKind> {
        match self {
            Self::Io { kind } => Some(kind),
            Self::Ambiguous | Self::PrefixLimit | Self::FormatMismatch { .. } => None,
        }
    }
}

impl fmt::Display for ReportInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ambiguous | Self::PrefixLimit | Self::Io { .. } => {
                formatter.write_str(self.code())
            }
            Self::FormatMismatch {
                configured,
                observed,
            } => write!(
                formatter,
                "{}: configured={configured}, observed={observed}",
                self.code()
            ),
        }
    }
}

impl std::error::Error for ReportInputError {}

/// A format-detected report input that replays its bounded probe.
///
/// The type implements [`Read`], so callers can pass it directly to
/// `jmeter_rs_results::JtlDecoder::new`.  `R` may be a `File`, `BufReader`,
/// or another caller-owned reader; only the probe is retained by this edge.
pub(crate) struct ReportInput<R> {
    reader: Chain<Cursor<Vec<u8>>, R>,
    format: JtlFormat,
}

impl<R> fmt::Debug for ReportInput<R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReportInput")
            .field("format", &self.format)
            .finish_non_exhaustive()
    }
}

impl<R: Read> ReportInput<R> {
    /// Detects a report format and returns a reader that replays every probe
    /// byte before reading from `reader` again.
    ///
    /// Detection strips only a UTF-8 BOM at byte zero for classification.  A
    /// BOM, ASCII whitespace, and all other bytes remain in the replayed
    /// stream.  If `configured_format` is present, it is authoritative and
    /// must agree with detection.
    pub(crate) fn new(
        mut reader: R,
        configured_format: Option<JtlFormat>,
    ) -> Result<Self, ReportInputError> {
        let mut prefix = Vec::with_capacity(REPORT_INPUT_PROBE_BYTES);
        let mut reached_eof = false;

        while prefix.len() < REPORT_INPUT_PROBE_BYTES {
            let remaining = REPORT_INPUT_PROBE_BYTES - prefix.len();
            let mut chunk = [0_u8; 8 * 1024];
            let read_limit = remaining.min(chunk.len());
            let read = reader
                .read(&mut chunk[..read_limit])
                .map_err(|error| ReportInputError::Io { kind: error.kind() })?;
            if read == 0 {
                reached_eof = true;
                break;
            }
            prefix.extend_from_slice(&chunk[..read]);

            if let Some(offset) = meaningful_offset(&prefix, false) {
                if offset < MAX_REPORT_INPUT_PREFIX_BYTES {
                    let observed = format_for_byte(prefix[offset]);
                    return Self::finish(reader, prefix, observed, configured_format);
                }
                return Err(ReportInputError::PrefixLimit);
            }
        }

        if let Some(offset) = meaningful_offset(&prefix, reached_eof) {
            if offset < MAX_REPORT_INPUT_PREFIX_BYTES {
                let observed = format_for_byte(prefix[offset]);
                return Self::finish(reader, prefix, observed, configured_format);
            }
            return Err(ReportInputError::PrefixLimit);
        }

        // A complete EOF is required before all-whitespace input can be
        // called empty/ambiguous.  If the probe filled its bounded allowance,
        // the remainder is intentionally unknown and we fail closed.
        if reached_eof {
            Err(ReportInputError::Ambiguous)
        } else {
            Err(ReportInputError::PrefixLimit)
        }
    }

    /// Returns the format observed by this input.
    #[must_use]
    pub(crate) const fn format(&self) -> JtlFormat {
        self.format
    }

    fn finish(
        reader: R,
        prefix: Vec<u8>,
        observed: JtlFormat,
        configured_format: Option<JtlFormat>,
    ) -> Result<Self, ReportInputError> {
        if let Some(configured) = configured_format
            && configured != observed
        {
            return Err(ReportInputError::FormatMismatch {
                configured,
                observed,
            });
        }
        let format = match configured_format {
            Some(configured) => configured,
            None => observed,
        };
        Ok(Self {
            reader: Cursor::new(prefix).chain(reader),
            format,
        })
    }
}

impl<R: Read> Read for ReportInput<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buffer)
    }
}

fn meaningful_offset(prefix: &[u8], reached_eof: bool) -> Option<usize> {
    let start = if prefix.len() >= UTF8_BOM.len() {
        if prefix.starts_with(&UTF8_BOM) {
            UTF8_BOM.len()
        } else {
            0
        }
    } else if !reached_eof && UTF8_BOM.starts_with(prefix) {
        // A fragmented reader may deliver the BOM over several calls.  Do
        // not classify a partial BOM as CSV until the probe can disambiguate
        // it or the reader reports EOF.
        return None;
    } else {
        0
    };
    prefix[start..]
        .iter()
        .position(|byte| !is_ascii_whitespace(*byte))
        .map(|offset| start + offset)
}

fn is_ascii_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r')
}

fn format_for_byte(byte: u8) -> JtlFormat {
    if byte == b'<' {
        JtlFormat::Xml
    } else {
        JtlFormat::Csv
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::io::{self, Read};
    use std::rc::Rc;

    #[derive(Debug)]
    struct FragmentedReader {
        bytes: Vec<u8>,
        position: usize,
        fragment: usize,
    }

    impl FragmentedReader {
        fn new(bytes: &[u8], fragment: usize) -> Self {
            Self {
                bytes: bytes.to_vec(),
                position: 0,
                fragment,
            }
        }
    }

    impl Read for FragmentedReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.position == self.bytes.len() {
                return Ok(0);
            }
            let count = self
                .fragment
                .min(buffer.len())
                .min(self.bytes.len() - self.position);
            buffer[..count].copy_from_slice(&self.bytes[self.position..self.position + count]);
            self.position += count;
            Ok(count)
        }
    }

    #[derive(Debug)]
    struct ErrorReader {
        bytes: Vec<u8>,
        failed: bool,
    }

    impl Read for ErrorReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if !self.bytes.is_empty() {
                let count = self.bytes.len().min(buffer.len());
                buffer[..count].copy_from_slice(&self.bytes[..count]);
                self.bytes.drain(..count);
                return Ok(count);
            }
            if !self.failed {
                self.failed = true;
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "secret=/tmp/private-report.jtl",
                ));
            }
            Ok(0)
        }
    }

    #[derive(Debug)]
    struct BudgetReader {
        bytes: Vec<u8>,
        position: usize,
        consumed: Rc<Cell<usize>>,
    }

    impl BudgetReader {
        fn new(bytes: Vec<u8>) -> (Self, Rc<Cell<usize>>) {
            let consumed = Rc::new(Cell::new(0));
            (
                Self {
                    bytes,
                    position: 0,
                    consumed: Rc::clone(&consumed),
                },
                consumed,
            )
        }
    }

    impl Read for BudgetReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let remaining = self.bytes.len().saturating_sub(self.position);
            let count = remaining.min(buffer.len());
            if count == 0 {
                return Ok(0);
            }
            buffer[..count].copy_from_slice(&self.bytes[self.position..self.position + count]);
            self.position += count;
            self.consumed.set(self.consumed.get() + count);
            Ok(count)
        }
    }

    fn read_all<R: Read>(mut reader: R) -> Vec<u8> {
        let mut bytes = Vec::new();
        let result = reader.read_to_end(&mut bytes);
        assert!(result.is_ok(), "replay reader should be readable");
        bytes
    }

    #[test]
    fn fragmented_reader_detects_xml_and_replays_every_byte() {
        let input = b" \r\n\t<testResults version=\"1.2\"/>";
        let report = ReportInput::new(FragmentedReader::new(input, 1), None);
        assert!(report.is_ok(), "fragmented XML probe should succeed");
        let report = report.unwrap_or_else(|_| unreachable!("checked above"));
        assert_eq!(report.format(), JtlFormat::Xml);
        assert_eq!(read_all(report), input);
    }

    #[test]
    fn bom_is_only_ignored_for_detection_and_is_replayed() {
        let input = b"\xef\xbb\xbf \n\t<testResults/>";
        let report = ReportInput::new(FragmentedReader::new(input, 2), None);
        assert!(report.is_ok(), "BOM-prefixed XML should succeed");
        let report = report.unwrap_or_else(|_| unreachable!("checked above"));
        assert_eq!(report.format(), JtlFormat::Xml);
        assert_eq!(read_all(report), input);
    }

    #[test]
    fn exact_prefix_boundary_is_accepted_but_the_next_byte_is_limited() {
        let mut within = vec![b' '; MAX_REPORT_INPUT_PREFIX_BYTES - 1];
        within.push(b'<');
        let report = ReportInput::new(FragmentedReader::new(&within, 97), None);
        assert!(report.is_ok(), "meaningful byte at the boundary is valid");
        let report = report.unwrap_or_else(|_| unreachable!("checked above"));
        assert_eq!(report.format(), JtlFormat::Xml);
        assert_eq!(read_all(report), within);

        let mut beyond = vec![b' '; MAX_REPORT_INPUT_PREFIX_BYTES];
        beyond.push(b'<');
        let error = ReportInput::new(FragmentedReader::new(&beyond, 4096), None);
        assert!(matches!(error, Err(ReportInputError::PrefixLimit)));
    }

    #[test]
    fn probe_never_reads_more_than_one_prefix_sentinel() {
        let (reader, consumed) = BudgetReader::new(vec![b' '; REPORT_INPUT_PROBE_BYTES + 32]);
        let error = ReportInput::new(reader, None);
        assert!(matches!(error, Err(ReportInputError::PrefixLimit)));
        assert_eq!(consumed.get(), REPORT_INPUT_PROBE_BYTES);
    }

    #[test]
    fn empty_and_all_whitespace_inputs_are_ambiguous_at_eof() {
        for input in [Vec::new(), b" \t\r\n\x0b\x0c".to_vec()] {
            let error = ReportInput::new(FragmentedReader::new(&input, 1), None);
            assert!(matches!(error, Err(ReportInputError::Ambiguous)));
        }
    }

    #[test]
    fn explicit_format_must_match_observation() {
        let csv = ReportInput::new(
            FragmentedReader::new(b"label,success\nrequest,true\n", 3),
            Some(JtlFormat::Xml),
        );
        assert!(matches!(
            csv,
            Err(ReportInputError::FormatMismatch {
                configured: JtlFormat::Xml,
                observed: JtlFormat::Csv,
            })
        ));

        let xml = ReportInput::new(
            FragmentedReader::new(b"<testResults/>", 2),
            Some(JtlFormat::Csv),
        );
        assert!(matches!(
            xml,
            Err(ReportInputError::FormatMismatch {
                configured: JtlFormat::Csv,
                observed: JtlFormat::Xml,
            })
        ));
    }

    #[test]
    fn configured_matching_format_is_retained() {
        let report = ReportInput::new(
            FragmentedReader::new(b"\xef\xbb\xbf label,success\n", 1),
            Some(JtlFormat::Csv),
        );
        assert!(report.is_ok(), "matching CSV configuration should succeed");
        let report = report.unwrap_or_else(|_| unreachable!("checked above"));
        assert_eq!(report.format(), JtlFormat::Csv);
    }

    #[test]
    fn replay_reads_probe_then_remaining_reader_without_loss() {
        let input = b"\xef\xbb\xbf \tlabel,success\nrequest,true\ntrailing,true\n";
        let report = ReportInput::new(FragmentedReader::new(input, 5), None);
        assert!(report.is_ok(), "CSV probe should succeed");
        let report = report.unwrap_or_else(|_| unreachable!("checked above"));
        assert_eq!(report.format(), JtlFormat::Csv);
        let mut report = report;
        let mut replayed = Vec::new();
        let mut chunk = [0_u8; 3];
        loop {
            let count = report.read(&mut chunk);
            assert!(count.is_ok(), "replay read should succeed");
            let count = count.unwrap_or(0);
            if count == 0 {
                break;
            }
            replayed.extend_from_slice(&chunk[..count]);
        }
        assert_eq!(replayed, input);
    }

    #[test]
    fn replay_reader_can_be_passed_directly_to_jtl_decoder() {
        let mut configuration = jmeter_rs_results::SampleSaveConfiguration::default();
        configuration.set_print_field_names(true);
        configuration.set_timestamp_format(jmeter_rs_results::TimestampFormat::None);
        configuration.set_label(true);
        configuration.set_success(true);
        let report = ReportInput::new(
            FragmentedReader::new(b"label,success\nreplayed,true\n", 2),
            Some(JtlFormat::Csv),
        );
        assert!(report.is_ok(), "configured CSV input should succeed");
        let report = report.unwrap_or_else(|_| unreachable!("checked above"));
        let decoder = jmeter_rs_results::JtlDecoder::new(
            report,
            configuration,
            jmeter_rs_results::JtlLimits::default(),
        );
        assert!(decoder.is_ok(), "JTL decoder should accept ReportInput");
        let mut decoder = decoder.unwrap_or_else(|_| unreachable!("checked above"));
        let event = decoder
            .next_event()
            .unwrap_or_else(|_| unreachable!("valid CSV should decode"))
            .unwrap_or_else(|| unreachable!("CSV row should produce an event"));
        assert_eq!(event.result().label(), "replayed");
        assert_eq!(event.result().success(), Some(true));
        assert!(
            decoder
                .next_event()
                .unwrap_or_else(|_| unreachable!("valid CSV should reach EOF"))
                .is_none()
        );
    }

    #[test]
    fn read_failures_are_typed_and_redacted() {
        let error = match ReportInput::new(
            ErrorReader {
                bytes: b" \t".to_vec(),
                failed: false,
            },
            None,
        ) {
            Err(error) => error,
            Ok(_) => unreachable!("probe I/O failure should be returned"),
        };
        assert_eq!(
            error,
            ReportInputError::Io {
                kind: io::ErrorKind::PermissionDenied,
            }
        );
        assert_eq!(error.io_kind(), Some(io::ErrorKind::PermissionDenied));
        assert_eq!(error.code(), "app.report-input.io");
        assert!(!error.to_string().contains("private-report"));
        assert!(!format!("{error:?}").contains("private-report"));
    }

    #[test]
    fn partial_bom_is_not_misclassified_before_probe_completion() {
        let input = b"\xef\xbb\xbf<testResults/>";
        let report = ReportInput::new(FragmentedReader::new(input, 1), None);
        assert!(report.is_ok(), "fragmented complete BOM should succeed");
        let report = report.unwrap_or_else(|_| unreachable!("checked above"));
        assert_eq!(report.format(), JtlFormat::Xml);
        assert_eq!(read_all(report), input);

        let csv = ReportInput::new(FragmentedReader::new(b"\xef", 1), None);
        assert!(csv.is_ok(), "an incomplete BOM at EOF is data");
        let csv = csv.unwrap_or_else(|_| unreachable!("checked above"));
        assert_eq!(csv.format(), JtlFormat::Csv);
        assert_eq!(read_all(csv), b"\xef");
    }
}
