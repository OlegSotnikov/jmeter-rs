// SPDX-License-Identifier: Apache-2.0
//! Small native component adapters and explicit external boundaries.
//!
//! These adapters are intentionally deterministic and local. They cover the
//! useful runtime seam for variable/configuration/listener tests; regular
//! expression, XPath, JSON, script, and plugin behavior remains an explicit
//! unsupported capability until a pinned engine is supplied.

use std::sync::{Arc, Mutex, MutexGuard};

use jmeter_rs_expr::FunctionResolver;
use jmeter_rs_results::{AssertionResult, SampleEvent};

use crate::{
    Assertion, ComponentError, ComponentFuture, Configuration, Listener, Phase, Postprocessor,
    Preprocessor, SampleContext,
};

fn lock<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
    value
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A configuration adapter that evaluates one expression into a request field.
pub struct ExpressionConfiguration {
    field: String,
    expression: String,
    functions: Arc<dyn FunctionResolver + Send + Sync>,
}

impl ExpressionConfiguration {
    /// Creates an expression-backed configuration element.
    #[must_use]
    pub fn new(
        field: impl Into<String>,
        expression: impl Into<String>,
        functions: Arc<dyn FunctionResolver + Send + Sync>,
    ) -> Self {
        Self {
            field: field.into(),
            expression: expression.into(),
            functions,
        }
    }
}

impl Configuration for ExpressionConfiguration {
    fn apply<'a>(&'a self, context: &'a mut SampleContext<'_>) -> ComponentFuture<'a, ()> {
        Box::pin(async move {
            let value = context
                .execution()
                .evaluate_expression(&self.expression, self.functions.as_ref())
                .map_err(|error| ComponentError::failure(error.to_string()))?;
            context.set_request_value(self.field.clone(), value);
            context.record(Phase::Configuration, "expression")?;
            Ok(())
        })
    }
}

/// A preprocessor that evaluates an expression into a virtual-user variable.
pub struct ExpressionPreprocessor {
    variable: String,
    expression: String,
    functions: Arc<dyn FunctionResolver + Send + Sync>,
}

impl ExpressionPreprocessor {
    /// Creates an expression-backed variable preprocessor.
    #[must_use]
    pub fn new(
        variable: impl Into<String>,
        expression: impl Into<String>,
        functions: Arc<dyn FunctionResolver + Send + Sync>,
    ) -> Self {
        Self {
            variable: variable.into(),
            expression: expression.into(),
            functions,
        }
    }
}

impl Preprocessor for ExpressionPreprocessor {
    fn process<'a>(&'a self, context: &'a mut SampleContext<'_>) -> ComponentFuture<'a, ()> {
        Box::pin(async move {
            let value = context
                .execution()
                .evaluate_expression(&self.expression, self.functions.as_ref())
                .map_err(|error| ComponentError::failure(error.to_string()))?;
            context
                .execution_mut()
                .set_variable(self.variable.clone(), value);
            context.record(Phase::Preprocessor, "expression")?;
            Ok(())
        })
    }
}

/// A bounded literal response extractor for deterministic local fixtures.
///
/// This is deliberately not a regular-expression implementation. It selects
/// the first literal `needle` from UTF-8 response data and stores the text
/// following it up to `capture_bytes`. Plans needing JMeter's regex/XPath/JSON
/// engines must use the typed unsupported adapter until that engine is pinned.
pub struct LiteralExtractor {
    variable: String,
    needle: String,
    capture_bytes: usize,
}

impl LiteralExtractor {
    /// Creates a literal response extractor.
    #[must_use]
    pub fn new(
        variable: impl Into<String>,
        needle: impl Into<String>,
        capture_bytes: usize,
    ) -> Self {
        Self {
            variable: variable.into(),
            needle: needle.into(),
            capture_bytes,
        }
    }
}

impl Postprocessor for LiteralExtractor {
    fn process<'a>(&'a self, context: &'a mut SampleContext<'_>) -> ComponentFuture<'a, ()> {
        Box::pin(async move {
            let Some(result) = context.result() else {
                return Ok(());
            };
            let Some(data) = result.response_data() else {
                return Ok(());
            };
            let text = std::str::from_utf8(data.as_bytes())
                .map_err(|_| ComponentError::failure("literal extractor requires UTF-8"))?;
            let Some(start) = text.find(&self.needle) else {
                context
                    .execution_mut()
                    .set_variable(self.variable.clone(), String::new());
                return Ok(());
            };
            let capture_start = start.saturating_add(self.needle.len());
            let remaining = text[capture_start..].to_owned();
            let mut end = remaining.len().min(self.capture_bytes);
            while end > 0 && !remaining.is_char_boundary(end) {
                end -= 1;
            }
            context
                .execution_mut()
                .set_variable(self.variable.clone(), remaining[..end].to_owned());
            Ok(())
        })
    }
}

/// A listener that snapshots every event into a bounded local vector.
#[derive(Clone, Debug)]
pub struct CapturingListener {
    events: Arc<Mutex<Vec<SampleEvent>>>,
    max_events: usize,
}

impl CapturingListener {
    /// Creates a bounded event collector.
    #[must_use]
    pub fn new(max_events: usize) -> Self {
        Self {
            events: Arc::new(Mutex::new(Vec::new())),
            max_events,
        }
    }

    /// Returns a snapshot of captured events.
    #[must_use]
    pub fn events(&self) -> Vec<SampleEvent> {
        lock(&self.events).clone()
    }
}

impl Listener for CapturingListener {
    fn on_event<'a>(&'a self, event: &'a SampleEvent) -> ComponentFuture<'a, ()> {
        Box::pin(async move {
            let mut events = lock(&self.events);
            if events.len() >= self.max_events {
                return Err(ComponentError::resource_limit("listener event capacity"));
            }
            events.push(event.clone());
            Ok(())
        })
    }
}

/// A typed unsupported boundary for regex/XPath/JSON extraction.
#[derive(Clone, Debug)]
pub struct UnsupportedExtractor {
    capability_id: String,
}

impl UnsupportedExtractor {
    /// Creates an external extractor marker.
    #[must_use]
    pub fn new(capability_id: impl Into<String>) -> Self {
        Self {
            capability_id: capability_id.into(),
        }
    }
}

impl Postprocessor for UnsupportedExtractor {
    fn process<'a>(&'a self, _context: &'a mut SampleContext<'_>) -> ComponentFuture<'a, ()> {
        Box::pin(async move {
            Err(ComponentError::unsupported(format!(
                "extractor capability {:?} requires a pinned external engine",
                self.capability_id
            )))
        })
    }
}

/// A typed unsupported boundary for script/plugin preprocessors/processors.
#[derive(Clone, Debug)]
pub struct UnsupportedProcessor {
    capability_id: String,
}

impl UnsupportedProcessor {
    /// Creates an external processor marker.
    #[must_use]
    pub fn new(capability_id: impl Into<String>) -> Self {
        Self {
            capability_id: capability_id.into(),
        }
    }
}

impl Preprocessor for UnsupportedProcessor {
    fn process<'a>(&'a self, _context: &'a mut SampleContext<'_>) -> ComponentFuture<'a, ()> {
        Box::pin(async move {
            Err(ComponentError::unsupported(format!(
                "processor capability {:?} requires a pinned external engine",
                self.capability_id
            )))
        })
    }
}

impl Postprocessor for UnsupportedProcessor {
    fn process<'a>(&'a self, _context: &'a mut SampleContext<'_>) -> ComponentFuture<'a, ()> {
        Box::pin(async move {
            Err(ComponentError::unsupported(format!(
                "processor capability {:?} requires a pinned external engine",
                self.capability_id
            )))
        })
    }
}

/// A typed unsupported boundary for JVM/plugin samplers.
#[derive(Clone, Debug)]
pub struct UnsupportedSampler {
    capability_id: String,
}

/// A typed unsupported boundary for JVM/plugin configuration elements.
#[derive(Clone, Debug)]
pub struct UnsupportedConfiguration {
    capability_id: String,
}

impl UnsupportedConfiguration {
    /// Creates an external configuration marker.
    #[must_use]
    pub fn new(capability_id: impl Into<String>) -> Self {
        Self {
            capability_id: capability_id.into(),
        }
    }
}

impl Configuration for UnsupportedConfiguration {
    fn apply<'a>(&'a self, _context: &'a mut SampleContext<'_>) -> ComponentFuture<'a, ()> {
        Box::pin(async move {
            Err(ComponentError::unsupported(format!(
                "configuration capability {:?} requires a pinned external engine",
                self.capability_id
            )))
        })
    }
}

/// A typed unsupported boundary for JVM/plugin assertions.
#[derive(Clone, Debug)]
pub struct UnsupportedAssertion {
    capability_id: String,
}

impl UnsupportedAssertion {
    /// Creates an external assertion marker.
    #[must_use]
    pub fn new(capability_id: impl Into<String>) -> Self {
        Self {
            capability_id: capability_id.into(),
        }
    }
}

impl Assertion for UnsupportedAssertion {
    fn evaluate<'a>(
        &'a self,
        _context: &'a mut SampleContext<'_>,
    ) -> ComponentFuture<'a, AssertionResult> {
        Box::pin(async move {
            Err(ComponentError::unsupported(format!(
                "assertion capability {:?} requires a pinned external engine",
                self.capability_id
            )))
        })
    }
}

/// A typed unsupported boundary for listeners that need a JVM/plugin sink.
#[derive(Clone, Debug)]
pub struct UnsupportedListener {
    capability_id: String,
}

impl UnsupportedListener {
    /// Creates an external listener marker.
    #[must_use]
    pub fn new(capability_id: impl Into<String>) -> Self {
        Self {
            capability_id: capability_id.into(),
        }
    }
}

impl Listener for UnsupportedListener {
    fn on_event<'a>(&'a self, _event: &'a SampleEvent) -> ComponentFuture<'a, ()> {
        Box::pin(async move {
            Err(ComponentError::unsupported(format!(
                "listener capability {:?} requires a pinned external engine",
                self.capability_id
            )))
        })
    }
}

impl UnsupportedSampler {
    /// Creates an external sampler marker.
    #[must_use]
    pub fn new(capability_id: impl Into<String>) -> Self {
        Self {
            capability_id: capability_id.into(),
        }
    }
}

impl crate::Sampler for UnsupportedSampler {
    fn sample<'a>(
        &'a self,
        _context: &'a mut SampleContext<'_>,
    ) -> ComponentFuture<'a, crate::SamplerOutput> {
        Box::pin(async move {
            Err(ComponentError::unsupported(format!(
                "sampler capability {:?} requires a pinned external engine",
                self.capability_id
            )))
        })
    }
}

/// A local assertion adapter for a response substring.
#[derive(Clone, Debug)]
pub struct ContainsAssertion {
    needle: String,
}

impl ContainsAssertion {
    /// Creates a response-body substring assertion.
    #[must_use]
    pub fn new(needle: impl Into<String>) -> Self {
        Self {
            needle: needle.into(),
        }
    }
}

impl Assertion for ContainsAssertion {
    fn evaluate<'a>(
        &'a self,
        context: &'a mut SampleContext<'_>,
    ) -> ComponentFuture<'a, jmeter_rs_results::AssertionResult> {
        Box::pin(async move {
            let present = context
                .result()
                .and_then(|result| result.response_data())
                .and_then(|data| std::str::from_utf8(data.as_bytes()).ok())
                .is_some_and(|text| text.contains(&self.needle));
            if present {
                Ok(jmeter_rs_results::AssertionResult::passed("contains"))
            } else {
                Ok(jmeter_rs_results::AssertionResult::failed(
                    "contains",
                    Some(self.needle.clone()),
                ))
            }
        })
    }
}
