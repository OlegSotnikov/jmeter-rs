// SPDX-License-Identifier: Apache-2.0
//! Executor-neutral, bounded DNS contracts for the native HTTP edge.
//!
//! The module deliberately contains no socket, filesystem, environment, or
//! executor code.  A resolver receives an owned, absolute query and returns a
//! standard-library future.  The future is a bounded result hand-off; a
//! concrete resolver may arrange for the I/O to happen on an application-owned
//! actor, but it must not perform that I/O while the caller polls this
//! contract.  The resolver's subordinate identity is
//! `http.dns.explicit/1`; the enclosing `http.native/2` provider identity is
//! owned by `transport_v2`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

/// Canonical identity of the explicit numeric-nameserver DNS policy.
pub const DNS_EXPLICIT_CAPABILITY_ID: &str = "http.dns.explicit/1";
/// Maximum canonical hostname length retained by the DNS boundary.
pub const MAX_DNS_HOSTNAME_BYTES: usize = 253;
/// Maximum bytes of a single DNS label.
pub const MAX_DNS_LABEL_BYTES: usize = 63;
/// Maximum address records retained from one response.
pub const MAX_DNS_ADDRESSES: usize = 32;
/// Maximum bytes retained by one normalized DNS response.
///
/// The budget includes the canonical hostname and the wire-sized address
/// values (four bytes for IPv4 and sixteen bytes for IPv6).  It is deliberately
/// independent from the address-count bound so a response cannot use a large
/// number of small records to evade the retained-data policy.
pub const MAX_DNS_RESPONSE_BYTES: usize = 4096;
/// Maximum static/fake records retained by one resolver.
pub const MAX_DNS_STATIC_RECORDS: usize = 256;
/// Maximum bytes of a hostname copied into an error diagnostic.
pub const MAX_DNS_DIAGNOSTIC_HOST_BYTES: usize = 64;
/// Maximum queue capacity accepted by a concrete actor.
pub const MAX_DNS_QUEUE_CAPACITY: usize = 256;
/// Maximum active requests accepted by a concrete actor.
pub const MAX_DNS_ACTIVE_REQUESTS: usize = 64;
/// Maximum upstream attempts accepted by a concrete resolver.
pub const MAX_DNS_ATTEMPTS: usize = 8;
/// Maximum per-attempt resolver timeout.
pub const MAX_DNS_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);

/// Stable machine-readable DNS error codes.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DnsErrorCode {
    /// The supplied hostname is not a bounded DNS name.
    InvalidHostname = 1,
    /// Resolver configuration violated a finite policy.
    InvalidConfig,
    /// No explicit numeric nameserver was configured.
    NoNameservers,
    /// The bounded request queue is full.
    QueueFull,
    /// The bounded active-request admission limit was reached.
    ActiveLimit,
    /// The resolver owner has stopped or its actor channel is closed.
    Stopped,
    /// The operation was cancelled before completion.
    Cancelled,
    /// The one absolute operation deadline elapsed.
    Deadline,
    /// The authoritative server returned NXDOMAIN.
    NxDomain,
    /// The authoritative server returned no address records.
    NoRecords,
    /// The provider returned malformed or undecodable DNS data.
    MalformedResponse,
    /// The provider returned more records than the configured bound.
    ResponseLimit,
    /// The selected provider failed without a safe, more specific code.
    Provider,
    /// The actor runtime could not be constructed.
    RuntimeUnavailable,
    /// The owner must be shut down before it can be joined.
    ShutdownRequired,
    /// An internal invariant failed while handing off a result.
    Internal,
}

impl DnsErrorCode {
    /// Returns the canonical dotted suffix used in diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidHostname => "invalid-hostname",
            Self::InvalidConfig => "invalid-config",
            Self::NoNameservers => "no-nameservers",
            Self::QueueFull => "queue-full",
            Self::ActiveLimit => "active-limit",
            Self::Stopped => "stopped",
            Self::Cancelled => "cancelled",
            Self::Deadline => "deadline",
            Self::NxDomain => "nxdomain",
            Self::NoRecords => "no-records",
            Self::MalformedResponse => "malformed-response",
            Self::ResponseLimit => "response-limit",
            Self::Provider => "provider",
            Self::RuntimeUnavailable => "runtime-unavailable",
            Self::ShutdownRequired => "shutdown-required",
            Self::Internal => "internal",
        }
    }
}

impl fmt::Display for DnsErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A bounded, redacted hostname diagnostic.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HostnameDiagnostic(String);

impl HostnameDiagnostic {
    fn from_name(name: &CanonicalName) -> Self {
        let value = name.as_str();
        if value.len() <= MAX_DNS_DIAGNOSTIC_HOST_BYTES {
            return Self(value.to_owned());
        }
        let suffix = "...";
        let keep = MAX_DNS_DIAGNOSTIC_HOST_BYTES.saturating_sub(suffix.len());
        let mut end = keep;
        while end > 0 && !value.is_char_boundary(end) {
            end -= 1;
        }
        let mut bounded = value[..end].to_owned();
        bounded.push_str(suffix);
        Self(bounded)
    }

    /// Returns the bounded diagnostic spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for HostnameDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("HostnameDiagnostic")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for HostnameDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A stable DNS error with only a bounded safe-host diagnostic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsError {
    code: DnsErrorCode,
    hostname: Option<HostnameDiagnostic>,
}

impl DnsError {
    /// Creates an error without query data.
    #[must_use]
    pub const fn new(code: DnsErrorCode) -> Self {
        Self {
            code,
            hostname: None,
        }
    }

    /// Creates an error with a bounded, safe hostname diagnostic.
    #[must_use]
    pub fn for_name(code: DnsErrorCode, name: &CanonicalName) -> Self {
        Self {
            code,
            hostname: Some(HostnameDiagnostic::from_name(name)),
        }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(&self) -> DnsErrorCode {
        self.code
    }

    /// Returns the bounded hostname diagnostic, when one is available.
    #[must_use]
    pub fn hostname(&self) -> Option<&HostnameDiagnostic> {
        self.hostname.as_ref()
    }
}

impl fmt::Display for DnsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("http.dns.")?;
        formatter.write_str(self.code.as_str())?;
        if let Some(hostname) = &self.hostname {
            write!(formatter, " ({hostname})")?;
        }
        Ok(())
    }
}

impl std::error::Error for DnsError {}

/// A lower-case, absolute DNS hostname.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CanonicalName(String);

impl CanonicalName {
    /// Parses and canonicalizes an ASCII DNS hostname.
    ///
    /// The accepted form is intentionally conservative: labels contain only
    /// ASCII letters, digits, `_`, or `-`, and an optional final root dot is
    /// normalized to exactly one dot.  IDNA conversion, search domains, and
    /// implicit local naming are outside this boundary.
    pub fn parse(value: &str) -> Result<Self, DnsError> {
        if value.is_empty() || value.len() > MAX_DNS_HOSTNAME_BYTES {
            return Err(DnsError::new(DnsErrorCode::InvalidHostname));
        }
        if value.bytes().any(|byte| byte.is_ascii_whitespace()) {
            return Err(DnsError::new(DnsErrorCode::InvalidHostname));
        }
        let without_root = match value.strip_suffix('.') {
            Some(without_root) => without_root,
            None => value,
        };
        if without_root.is_empty() || without_root.ends_with('.') {
            return Err(DnsError::new(DnsErrorCode::InvalidHostname));
        }

        let mut canonical = String::with_capacity(value.len().saturating_add(1));
        let mut total = 0usize;
        for (index, label) in without_root.split('.').enumerate() {
            if label.is_empty() || label.len() > MAX_DNS_LABEL_BYTES {
                return Err(DnsError::new(DnsErrorCode::InvalidHostname));
            }
            total = total
                .checked_add(label.len())
                .and_then(|length| length.checked_add(1))
                .ok_or_else(|| DnsError::new(DnsErrorCode::InvalidHostname))?;
            if total > MAX_DNS_HOSTNAME_BYTES {
                return Err(DnsError::new(DnsErrorCode::InvalidHostname));
            }
            if index != 0 {
                canonical.push('.');
            }
            for byte in label.bytes() {
                if !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')) {
                    return Err(DnsError::new(DnsErrorCode::InvalidHostname));
                }
                canonical.push(byte.to_ascii_lowercase() as char);
            }
        }
        canonical.push('.');
        if canonical.len() > MAX_DNS_HOSTNAME_BYTES {
            return Err(DnsError::new(DnsErrorCode::InvalidHostname));
        }
        Ok(Self(canonical))
    }

    /// Returns the absolute canonical spelling, including the root dot.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the bounded hostname diagnostic used by typed errors.
    #[must_use]
    pub fn diagnostic(&self) -> HostnameDiagnostic {
        HostnameDiagnostic::from_name(self)
    }
}

impl fmt::Debug for CanonicalName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("CanonicalName")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for CanonicalName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A cancellation capability independent of any async runtime.
#[derive(Clone, Default)]
pub struct DnsCancellationToken {
    state: Arc<CancellationState>,
}

struct CancellationState {
    cancelled: AtomicBool,
    next_registration: AtomicU64,
    callbacks: Mutex<Vec<CancellationCallback>>,
}

type CancellationCallback = (u64, Arc<dyn Fn() + Send + Sync + 'static>);

impl Default for CancellationState {
    fn default() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
            next_registration: AtomicU64::new(1),
            callbacks: Mutex::new(Vec::new()),
        }
    }
}

impl fmt::Debug for DnsCancellationToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DnsCancellationToken")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

impl DnsCancellationToken {
    /// Marks this token cancelled and wakes each registered operation once.
    pub fn cancel(&self) {
        if self.state.cancelled.swap(true, Ordering::AcqRel) {
            return;
        }
        let callbacks = {
            let mut callbacks = lock_recover(&self.state.callbacks);
            std::mem::take(&mut *callbacks)
        };
        for callback in callbacks {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                callback.1();
            }));
        }
    }

    /// Returns whether cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.state.cancelled.load(Ordering::Acquire)
    }

    pub(crate) fn register(
        &self,
        callback: Arc<dyn Fn() + Send + Sync + 'static>,
    ) -> DnsCancellationRegistration {
        let mut callbacks = lock_recover(&self.state.callbacks);
        if self.is_cancelled() {
            drop(callbacks);
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                callback();
            }));
            return DnsCancellationRegistration { state: None, id: 0 };
        }
        let id = self.state.next_registration.fetch_add(1, Ordering::Relaxed);
        callbacks.push((id, callback));
        DnsCancellationRegistration {
            state: Some(Arc::downgrade(&self.state)),
            id,
        }
    }
}

/// Registration returned to a resolver actor for cancellation wake-up.
pub(crate) struct DnsCancellationRegistration {
    state: Option<Weak<CancellationState>>,
    id: u64,
}

impl Drop for DnsCancellationRegistration {
    fn drop(&mut self) {
        let Some(state) = self.state.take().and_then(|state| state.upgrade()) else {
            return;
        };
        let mut callbacks = lock_recover(&state.callbacks);
        callbacks.retain(|(id, _)| *id != self.id);
    }
}

/// An owned DNS query with one absolute monotonic deadline.
#[derive(Clone, Debug)]
pub struct DnsQuery {
    name: CanonicalName,
    deadline: Instant,
    cancellation: DnsCancellationToken,
}

impl DnsQuery {
    /// Creates a query using a fresh cancellation token.
    #[must_use]
    pub fn new(name: CanonicalName, deadline: Instant) -> Self {
        Self {
            name,
            deadline,
            cancellation: DnsCancellationToken::default(),
        }
    }

    /// Creates a query using an explicit cancellation token.
    #[must_use]
    pub fn with_cancellation(
        name: CanonicalName,
        deadline: Instant,
        cancellation: DnsCancellationToken,
    ) -> Self {
        Self {
            name,
            deadline,
            cancellation,
        }
    }

    /// Returns the absolute canonical name.
    #[must_use]
    pub fn name(&self) -> &CanonicalName {
        &self.name
    }

    /// Returns the one absolute deadline.
    #[must_use]
    pub const fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Returns the operation cancellation capability.
    #[must_use]
    pub fn cancellation(&self) -> &DnsCancellationToken {
        &self.cancellation
    }
}

/// A normalized bounded result containing deterministic A-then-AAAA order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsResponse {
    name: CanonicalName,
    addresses: Vec<IpAddr>,
}

impl DnsResponse {
    /// Builds a response, rejecting an over-limit input before truncation.
    pub fn from_addresses(
        name: CanonicalName,
        addresses: impl IntoIterator<Item = IpAddr>,
        maximum: usize,
    ) -> Result<Self, DnsError> {
        Self::from_addresses_with_limits(name, addresses, maximum, MAX_DNS_RESPONSE_BYTES)
    }

    /// Builds a response under explicit address-count and retained-byte
    /// budgets, rejecting a response rather than truncating it.
    pub fn from_addresses_with_limits(
        name: CanonicalName,
        addresses: impl IntoIterator<Item = IpAddr>,
        maximum_addresses: usize,
        maximum_bytes: usize,
    ) -> Result<Self, DnsError> {
        if maximum_addresses == 0 || maximum_addresses > MAX_DNS_ADDRESSES {
            return Err(DnsError::new(DnsErrorCode::InvalidConfig));
        }
        if maximum_bytes == 0 || maximum_bytes > MAX_DNS_RESPONSE_BYTES {
            return Err(DnsError::new(DnsErrorCode::InvalidConfig));
        }
        let mut ipv4 = BTreeSet::new();
        let mut ipv6 = BTreeSet::new();
        let mut records = 0usize;
        let mut retained_bytes = name.as_str().len();
        if retained_bytes > maximum_bytes {
            return Err(DnsError::for_name(DnsErrorCode::ResponseLimit, &name));
        }
        for address in addresses {
            records = records
                .checked_add(1)
                .ok_or_else(|| DnsError::for_name(DnsErrorCode::ResponseLimit, &name))?;
            if records > maximum_addresses {
                return Err(DnsError::for_name(DnsErrorCode::ResponseLimit, &name));
            }
            match address {
                IpAddr::V4(address) => {
                    if !ipv4.contains(&address) {
                        let next = retained_bytes
                            .checked_add(std::mem::size_of::<std::net::Ipv4Addr>())
                            .ok_or_else(|| {
                                DnsError::for_name(DnsErrorCode::ResponseLimit, &name)
                            })?;
                        if next > maximum_bytes {
                            return Err(DnsError::for_name(DnsErrorCode::ResponseLimit, &name));
                        }
                        retained_bytes = next;
                        ipv4.insert(address);
                    }
                }
                IpAddr::V6(address) => {
                    if !ipv6.contains(&address) {
                        let next = retained_bytes
                            .checked_add(std::mem::size_of::<std::net::Ipv6Addr>())
                            .ok_or_else(|| {
                                DnsError::for_name(DnsErrorCode::ResponseLimit, &name)
                            })?;
                        if next > maximum_bytes {
                            return Err(DnsError::for_name(DnsErrorCode::ResponseLimit, &name));
                        }
                        retained_bytes = next;
                        ipv6.insert(address);
                    }
                }
            }
        }
        if ipv4.is_empty() && ipv6.is_empty() {
            return Err(DnsError::for_name(DnsErrorCode::NoRecords, &name));
        }
        let mut ordered = Vec::with_capacity(ipv4.len().saturating_add(ipv6.len()));
        ordered.extend(ipv4.into_iter().map(IpAddr::V4));
        ordered.extend(ipv6.into_iter().map(IpAddr::V6));
        let response = Self {
            name,
            addresses: ordered,
        };
        // Keep the final accounting coupled to the retained representation as
        // a guard against future changes that add response-owned fields. The
        // per-record checks above still happen before each vector insertion.
        if response.retained_bytes() > maximum_bytes {
            return Err(DnsError::for_name(
                DnsErrorCode::ResponseLimit,
                response.name(),
            ));
        }
        Ok(response)
    }

    /// Returns the query name associated with this response.
    #[must_use]
    pub fn name(&self) -> &CanonicalName {
        &self.name
    }

    /// Returns deterministic A-then-AAAA addresses.
    #[must_use]
    pub fn addresses(&self) -> &[IpAddr] {
        &self.addresses
    }

    /// Returns the bounded retained-byte accounting for this response.
    #[must_use]
    pub fn retained_bytes(&self) -> usize {
        self.name.as_str().len()
            + self
                .addresses
                .iter()
                .map(|address| match address {
                    IpAddr::V4(_) => std::mem::size_of::<std::net::Ipv4Addr>(),
                    IpAddr::V6(_) => std::mem::size_of::<std::net::Ipv6Addr>(),
                })
                .sum::<usize>()
    }

    /// Consumes the response into its ordered addresses.
    #[must_use]
    pub fn into_addresses(self) -> Vec<IpAddr> {
        self.addresses
    }
}

/// Standard-library future returned by every resolver implementation.
pub type DnsFuture<'a> = Pin<Box<dyn Future<Output = Result<DnsResponse, DnsError>> + Send + 'a>>;

/// Executor-neutral DNS resolution capability.
pub trait DnsResolver: Send + Sync {
    /// Submits one bounded query without performing DNS or socket I/O inline.
    fn resolve(&self, query: DnsQuery) -> DnsFuture<'static>;
}

/// A deterministic resolver backed solely by explicitly supplied records.
#[derive(Clone, Debug)]
pub struct StaticDnsResolver {
    records: Arc<BTreeMap<CanonicalName, Vec<IpAddr>>>,
    maximum_addresses: usize,
}

impl StaticDnsResolver {
    /// Creates an empty resolver with a bounded response size.
    pub fn new(maximum_addresses: usize) -> Result<Self, DnsError> {
        if maximum_addresses == 0 || maximum_addresses > MAX_DNS_ADDRESSES {
            return Err(DnsError::new(DnsErrorCode::InvalidConfig));
        }
        Ok(Self {
            records: Arc::new(BTreeMap::new()),
            maximum_addresses,
        })
    }

    /// Adds or replaces one explicit record set.
    pub fn insert(
        &mut self,
        name: CanonicalName,
        addresses: impl IntoIterator<Item = IpAddr>,
    ) -> Result<(), DnsError> {
        let response =
            DnsResponse::from_addresses(name.clone(), addresses, self.maximum_addresses)?;
        let records = Arc::make_mut(&mut self.records);
        if !records.contains_key(&name) && records.len() >= MAX_DNS_STATIC_RECORDS {
            return Err(DnsError::new(DnsErrorCode::ResponseLimit));
        }
        records.insert(name, response.into_addresses());
        Ok(())
    }

    /// Returns the configured maximum response address count.
    #[must_use]
    pub const fn maximum_addresses(&self) -> usize {
        self.maximum_addresses
    }
}

impl DnsResolver for StaticDnsResolver {
    fn resolve(&self, query: DnsQuery) -> DnsFuture<'static> {
        let records = self.records.clone();
        let maximum = self.maximum_addresses;
        Box::pin(async move {
            if query.cancellation().is_cancelled() {
                return Err(DnsError::for_name(DnsErrorCode::Cancelled, query.name()));
            }
            if Instant::now() >= query.deadline() {
                return Err(DnsError::for_name(DnsErrorCode::Deadline, query.name()));
            }
            let Some(addresses) = records.get(query.name()) else {
                return Err(DnsError::for_name(DnsErrorCode::NxDomain, query.name()));
            };
            DnsResponse::from_addresses(query.name().clone(), addresses.iter().copied(), maximum)
        })
    }
}

/// One deterministic fake outcome used by tests and offline harnesses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FakeDnsOutcome {
    /// Explicit address records.
    Addresses(Vec<IpAddr>),
    /// A stable typed failure without provider text.
    Error(DnsErrorCode),
}

/// A configurable, executor-neutral fake resolver.
#[derive(Clone, Debug)]
pub struct FakeDnsResolver {
    outcomes: Arc<BTreeMap<CanonicalName, FakeDnsOutcome>>,
    maximum_addresses: usize,
}

impl FakeDnsResolver {
    /// Creates an empty fake resolver with a bounded response size.
    pub fn new(maximum_addresses: usize) -> Result<Self, DnsError> {
        if maximum_addresses == 0 || maximum_addresses > MAX_DNS_ADDRESSES {
            return Err(DnsError::new(DnsErrorCode::InvalidConfig));
        }
        Ok(Self {
            outcomes: Arc::new(BTreeMap::new()),
            maximum_addresses,
        })
    }

    /// Adds an address outcome, validating its bound immediately.
    pub fn insert_addresses(
        &mut self,
        name: CanonicalName,
        addresses: impl IntoIterator<Item = IpAddr>,
    ) -> Result<(), DnsError> {
        let mut values = Vec::new();
        for address in addresses {
            if values.len() >= self.maximum_addresses {
                return Err(DnsError::for_name(DnsErrorCode::ResponseLimit, &name));
            }
            values.push(address);
        }
        DnsResponse::from_addresses(name.clone(), values.iter().copied(), self.maximum_addresses)?;
        self.insert_outcome(name, FakeDnsOutcome::Addresses(values))
    }

    /// Adds a typed fake error for a name.
    pub fn insert_error(
        &mut self,
        name: CanonicalName,
        code: DnsErrorCode,
    ) -> Result<(), DnsError> {
        if !matches!(
            code,
            DnsErrorCode::NxDomain
                | DnsErrorCode::NoRecords
                | DnsErrorCode::MalformedResponse
                | DnsErrorCode::Provider
        ) {
            return Err(DnsError::new(DnsErrorCode::InvalidConfig));
        }
        self.insert_outcome(name, FakeDnsOutcome::Error(code))
    }

    fn insert_outcome(
        &mut self,
        name: CanonicalName,
        outcome: FakeDnsOutcome,
    ) -> Result<(), DnsError> {
        let outcomes = Arc::make_mut(&mut self.outcomes);
        if !outcomes.contains_key(&name) && outcomes.len() >= MAX_DNS_STATIC_RECORDS {
            return Err(DnsError::new(DnsErrorCode::ResponseLimit));
        }
        outcomes.insert(name, outcome);
        Ok(())
    }
}

impl DnsResolver for FakeDnsResolver {
    fn resolve(&self, query: DnsQuery) -> DnsFuture<'static> {
        let outcomes = self.outcomes.clone();
        let maximum = self.maximum_addresses;
        Box::pin(async move {
            if query.cancellation().is_cancelled() {
                return Err(DnsError::for_name(DnsErrorCode::Cancelled, query.name()));
            }
            if Instant::now() >= query.deadline() {
                return Err(DnsError::for_name(DnsErrorCode::Deadline, query.name()));
            }
            match outcomes.get(query.name()) {
                Some(FakeDnsOutcome::Addresses(addresses)) => DnsResponse::from_addresses(
                    query.name().clone(),
                    addresses.iter().copied(),
                    maximum,
                ),
                Some(FakeDnsOutcome::Error(code)) => Err(DnsError::for_name(*code, query.name())),
                None => Err(DnsError::for_name(DnsErrorCode::NxDomain, query.name())),
            }
        })
    }
}

/// Shared result cell used by an application-owned asynchronous actor.
pub(crate) struct PromiseState {
    result: Mutex<Option<Result<DnsResponse, DnsError>>>,
    waker: Mutex<Option<Waker>>,
    cancel_requested: AtomicBool,
    abort_requested: AtomicBool,
}

impl PromiseState {
    /// Creates a pending bounded result cell.
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            result: Mutex::new(None),
            waker: Mutex::new(None),
            cancel_requested: AtomicBool::new(false),
            abort_requested: AtomicBool::new(false),
        })
    }

    /// Marks cancellation and returns whether this was the first request.
    pub(crate) fn request_cancel(&self) -> bool {
        let first = !self.cancel_requested.swap(true, Ordering::AcqRel);
        self.abort_requested.store(true, Ordering::Release);
        first
    }

    /// Marks the operation aborting for a deadline without changing the
    /// cancellation severity used by finalization.
    pub(crate) fn request_abort(&self) -> bool {
        !self.abort_requested.swap(true, Ordering::AcqRel)
    }

    /// Returns whether cancellation was requested.
    pub(crate) fn cancellation_requested(&self) -> bool {
        self.cancel_requested.load(Ordering::Acquire)
    }

    /// Stores one terminal result and wakes the pending future.
    pub(crate) fn complete(&self, result: Result<DnsResponse, DnsError>) {
        self.store_result(result, false);
    }

    /// Completes this promise with cancellation, overriding a provider result
    /// that raced with the cancellation observation.
    pub(crate) fn complete_cancelled(&self, name: &CanonicalName) {
        self.complete_prioritized(DnsErrorCode::Cancelled, name);
    }

    fn complete_prioritized(&self, code: DnsErrorCode, name: &CanonicalName) {
        let should_wake = {
            let mut slot = lock_recover(&self.result);
            if code == DnsErrorCode::Cancelled {
                // Cancellation and terminal-slot replacement share the same
                // lock. This gives callback-vs-provider finalization one
                // deterministic linearization point.
                self.cancel_requested.store(true, Ordering::Release);
            }
            self.abort_requested.store(true, Ordering::Release);
            *slot = Some(Err(DnsError::for_name(code, name)));
            true
        };
        if should_wake && let Some(waker) = lock_recover(&self.waker).take() {
            waker.wake();
        }
    }

    /// Finalizes a provider task using one atomic terminal-policy observation.
    /// Cancellation has precedence over deadline, which has precedence over a
    /// provider result.  The checks and result-slot update share the result
    /// lock so a finalization race cannot expose the lower-priority outcome.
    pub(crate) fn complete_observed(
        &self,
        query: &DnsQuery,
        result: Result<DnsResponse, DnsError>,
    ) {
        let should_wake = {
            let mut slot = lock_recover(&self.result);
            let cancelled = self.cancellation_requested() || query.cancellation().is_cancelled();
            let (terminal, prioritized) = if cancelled {
                (
                    Err(DnsError::for_name(DnsErrorCode::Cancelled, query.name())),
                    true,
                )
            } else if Instant::now() >= query.deadline() {
                (
                    Err(DnsError::for_name(DnsErrorCode::Deadline, query.name())),
                    true,
                )
            } else {
                (result, false)
            };
            if prioritized || slot.is_none() {
                *slot = Some(terminal);
                true
            } else {
                false
            }
        };
        if should_wake && let Some(waker) = lock_recover(&self.waker).take() {
            waker.wake();
        }
    }

    /// Observes one promise from a caller future.  The same cancellation /
    /// deadline policy as task finalization is applied at this boundary.
    pub(crate) fn observe(&self, query: &DnsQuery) -> Option<Result<DnsResponse, DnsError>> {
        let mut slot = lock_recover(&self.result);
        if self.cancellation_requested() || query.cancellation().is_cancelled() {
            *slot = Some(Err(DnsError::for_name(
                DnsErrorCode::Cancelled,
                query.name(),
            )));
        } else if Instant::now() >= query.deadline() {
            *slot = Some(Err(DnsError::for_name(
                DnsErrorCode::Deadline,
                query.name(),
            )));
        }
        slot.take()
    }

    fn store_result(&self, result: Result<DnsResponse, DnsError>, replace: bool) {
        let should_wake = {
            let mut slot = lock_recover(&self.result);
            if replace || slot.is_none() {
                *slot = Some(result);
                true
            } else {
                false
            }
        };
        if should_wake && let Some(waker) = lock_recover(&self.waker).take() {
            waker.wake();
        }
    }

    fn take_result(&self) -> Option<Result<DnsResponse, DnsError>> {
        lock_recover(&self.result).take()
    }

    fn set_waker(&self, waker: &Waker) {
        let mut slot = lock_recover(&self.waker);
        *slot = Some(waker.clone());
    }
}

/// Future implementation used by actor-backed resolvers.
pub(crate) struct PromiseFuture {
    state: Arc<PromiseState>,
    cancellation: DnsCancellationToken,
    name: CanonicalName,
    deadline: Instant,
    on_cancel: Option<Box<dyn FnOnce(DnsErrorCode) + Send + 'static>>,
    finished: bool,
}

impl PromiseFuture {
    /// Creates a future over a promise and an actor cancellation callback.
    pub(crate) fn new(
        state: Arc<PromiseState>,
        query: &DnsQuery,
        on_cancel: Box<dyn FnOnce(DnsErrorCode) + Send + 'static>,
    ) -> Self {
        Self {
            state,
            cancellation: query.cancellation.clone(),
            name: query.name.clone(),
            deadline: query.deadline,
            on_cancel: Some(on_cancel),
            finished: false,
        }
    }

    fn request_abort(&mut self, code: DnsErrorCode) {
        let first = if code == DnsErrorCode::Cancelled {
            self.state.request_cancel()
        } else {
            self.state.request_abort()
        };
        if first {
            self.invoke_cancel_callback(code);
        }
    }

    fn cancel_and_complete(&mut self, code: DnsErrorCode) {
        let first = if code == DnsErrorCode::Cancelled {
            self.state.request_cancel()
        } else {
            self.state.request_abort()
        };
        self.state.complete_prioritized(code, &self.name);
        self.finished = true;
        if first {
            self.invoke_cancel_callback(code);
        }
    }

    fn invoke_cancel_callback(&mut self, code: DnsErrorCode) {
        let Some(on_cancel) = self.on_cancel.take() else {
            return;
        };
        // The terminal promise is already visible before this callback runs.
        // A resolver callback is an actor wake-up optimization, so a panic in
        // it must not turn cancellation into an uncompleted caller future.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            on_cancel(code);
        }));
    }

    fn observe(&mut self) -> Option<Result<DnsResponse, DnsError>> {
        let query = DnsQuery {
            name: self.name.clone(),
            deadline: self.deadline,
            cancellation: self.cancellation.clone(),
        };
        let result = self.state.observe(&query);
        if let Some(Err(error)) = &result
            && matches!(
                error.code(),
                DnsErrorCode::Cancelled | DnsErrorCode::Deadline
            )
        {
            self.request_abort(error.code());
        }
        result
    }
}

impl Future for PromiseFuture {
    type Output = Result<DnsResponse, DnsError>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        if self.finished {
            return Poll::Ready(Err(DnsError::for_name(DnsErrorCode::Internal, &self.name)));
        }
        if self.cancellation.is_cancelled() {
            self.cancel_and_complete(DnsErrorCode::Cancelled);
            return Poll::Ready(self.take_result_or_internal());
        }
        if Instant::now() >= self.deadline {
            self.cancel_and_complete(DnsErrorCode::Deadline);
            return Poll::Ready(self.take_result_or_internal());
        }
        self.state.set_waker(context.waker());
        if self.cancellation.is_cancelled() {
            self.cancel_and_complete(DnsErrorCode::Cancelled);
            Poll::Ready(self.take_result_or_internal())
        } else if Instant::now() >= self.deadline {
            self.cancel_and_complete(DnsErrorCode::Deadline);
            Poll::Ready(self.take_result_or_internal())
        } else if let Some(result) = self.observe() {
            self.finished = true;
            self.on_cancel.take();
            Poll::Ready(result)
        } else {
            Poll::Pending
        }
    }
}

impl PromiseFuture {
    fn take_result_or_internal(&self) -> Result<DnsResponse, DnsError> {
        match self.state.take_result() {
            Some(result) => result,
            None => Err(DnsError::for_name(DnsErrorCode::Internal, &self.name)),
        }
    }
}

impl Drop for PromiseFuture {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        if self.state.request_cancel() {
            self.state
                .complete_prioritized(DnsErrorCode::Cancelled, &self.name);
            self.invoke_cancel_callback(DnsErrorCode::Cancelled);
        }
    }
}

/// Creates an immediately-ready executor-neutral result future.
pub(crate) fn ready_future(result: Result<DnsResponse, DnsError>) -> DnsFuture<'static> {
    Box::pin(std::future::ready(result))
}

fn lock_recover<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}
