// SPDX-License-Identifier: Apache-2.0
//! Seeded, scoped deterministic random streams.

use crate::error::{ErrorCode, StableError};
use std::fmt;
use std::ops::{Range, RangeInclusive};
use std::sync::{Arc, Mutex};

/// A recorded random seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RandomSeed(u64);

impl RandomSeed {
    /// Creates a seed from a raw 64-bit value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the raw seed value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

impl From<u64> for RandomSeed {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

/// Finite bounds for derived random scope paths.
///
/// Scope names are test-plan input.  Keeping both dimensions explicit avoids
/// a deep tree of tiny names and a single enormous name consuming unbounded
/// memory while a fixture is being assembled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RandomLimits {
    /// Maximum number of nested scope components.
    pub max_scope_depth: usize,
    /// Maximum UTF-8 bytes across all scope components.
    pub max_scope_bytes: usize,
}

impl RandomLimits {
    /// Creates explicit finite scope bounds.
    #[must_use]
    pub const fn new(max_scope_depth: usize, max_scope_bytes: usize) -> Self {
        Self {
            max_scope_depth,
            max_scope_bytes,
        }
    }

    /// A useful finite bound for deterministic fixture streams.
    #[must_use]
    pub const fn default_bounded() -> Self {
        Self::new(64, 4 * 1024)
    }
}

impl Default for RandomLimits {
    fn default() -> Self {
        Self::default_bounded()
    }
}

/// Errors returned by random range and scope helpers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RandomError {
    /// The requested half-open or inclusive range contains no values.
    EmptyRange,
    /// A derived scope would exceed the configured nesting bound.
    ScopeDepthExceeded {
        /// Requested depth after adding the component.
        depth: usize,
        /// Configured depth bound.
        limit: usize,
    },
    /// A derived scope path would exceed the configured byte bound.
    ScopeBytesExceeded {
        /// Requested aggregate scope bytes after adding the component.
        bytes: usize,
        /// Configured aggregate byte bound.
        limit: usize,
    },
}

impl RandomError {
    /// Returns the stable error code.
    #[must_use]
    pub const fn code(self) -> ErrorCode {
        match self {
            Self::EmptyRange => ErrorCode::RandomEmptyRange,
            Self::ScopeDepthExceeded { .. } => ErrorCode::RandomScopeDepth,
            Self::ScopeBytesExceeded { .. } => ErrorCode::RandomScopeBytes,
        }
    }
}

impl fmt::Display for RandomError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyRange => formatter.write_str(self.code().as_str()),
            Self::ScopeDepthExceeded { depth, limit } => write!(
                formatter,
                "{}: scope depth {depth} exceeds {limit}",
                self.code()
            ),
            Self::ScopeBytesExceeded { bytes, limit } => write!(
                formatter,
                "{}: scope bytes {bytes} exceed {limit}",
                self.code()
            ),
        }
    }
}

impl std::error::Error for RandomError {}
impl StableError for RandomError {
    fn code(&self) -> ErrorCode {
        (*self).code()
    }
}

/// An executor-neutral random source used by runtime tests.
pub trait RandomSource {
    /// Returns the next reproducible 64-bit value.
    fn next_u64(&self) -> u64;

    /// Returns a reproducible value in `[start, end)`.
    fn range_u64(&self, range: Range<u64>) -> Result<u64, RandomError>;
}

#[derive(Debug)]
struct RandomState {
    state: u64,
}

/// A cloneable deterministic random stream.
///
/// The stream uses the fixed SplitMix64 transition (not the host RNG, thread
/// scheduler, or platform entropy source).  Clones share the stream cursor;
/// calling `next_u64` through one clone advances the sequence observed by all
/// other clones.  [`Self::scoped`] derives a fresh stream from the root seed
/// and a length-delimited scope path, so creating or advancing an unrelated
/// scope never perturbs this stream.
#[derive(Clone)]
pub struct DeterministicRandom {
    root_seed: RandomSeed,
    /// The seed used to initialize this stream's cursor.
    ///
    /// The root seed is retained separately so a fixture can record one
    /// replay seed while diagnostics can still identify a derived stream.
    stream_seed: RandomSeed,
    path: Arc<[String]>,
    scope_bytes: usize,
    limits: RandomLimits,
    state: Arc<Mutex<RandomState>>,
}

impl fmt::Debug for DeterministicRandom {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeterministicRandom")
            .field("root_seed", &self.root_seed)
            .field("stream_seed", &self.stream_seed)
            .field("scope_depth", &self.path.len())
            .field("scope_bytes", &self.scope_bytes)
            .field("limits", &self.limits)
            .finish()
    }
}

impl DeterministicRandom {
    /// Creates a root stream from a recorded seed.
    #[must_use]
    pub fn new(seed: impl Into<RandomSeed>) -> Self {
        Self::with_limits(seed, RandomLimits::default())
    }

    /// Creates a root stream with explicit finite scope bounds.
    #[must_use]
    pub fn with_limits(seed: impl Into<RandomSeed>, limits: RandomLimits) -> Self {
        let root_seed = seed.into();
        let stream_seed = RandomSeed::new(derive_seed(root_seed.value(), &[]));
        Self {
            root_seed,
            stream_seed,
            path: Arc::from([]),
            scope_bytes: 0,
            limits,
            state: Arc::new(Mutex::new(RandomState {
                state: stream_seed.value(),
            })),
        }
    }

    /// Returns the seed used to derive this stream.
    #[must_use]
    pub const fn root_seed(&self) -> RandomSeed {
        self.root_seed
    }

    /// Returns the recorded root seed.
    ///
    /// This spelling is convenient for fixture metadata and is equivalent to
    /// [`Self::root_seed`].  A child stream still reports the same root seed;
    /// use [`Self::stream_seed`] to identify its derived cursor seed.
    #[must_use]
    pub const fn seed(&self) -> RandomSeed {
        self.root_seed
    }

    /// Returns the deterministic seed used to initialize this stream's
    /// cursor.  The root stream's value is derived from its root seed, while
    /// a scoped stream's value additionally includes its length-delimited
    /// path.
    #[must_use]
    pub const fn stream_seed(&self) -> RandomSeed {
        self.stream_seed
    }

    /// Returns the scope path used to derive this stream.
    #[must_use]
    pub fn scope_path(&self) -> Vec<String> {
        self.path.iter().cloned().collect()
    }

    /// Returns the finite scope limits used by this stream.
    #[must_use]
    pub const fn limits(&self) -> RandomLimits {
        self.limits
    }

    /// Returns the current scope depth.
    #[must_use]
    pub fn scope_depth(&self) -> usize {
        self.path.len()
    }

    /// Returns aggregate UTF-8 bytes in the current scope path.
    #[must_use]
    pub const fn scope_bytes(&self) -> usize {
        self.scope_bytes
    }

    /// Creates an independently seeded stream for a bounded child scope.
    pub fn try_scoped(&self, scope: impl AsRef<str>) -> Result<Self, RandomError> {
        let scope = scope.as_ref();
        let depth = self
            .path
            .len()
            .checked_add(1)
            .ok_or(RandomError::ScopeDepthExceeded {
                depth: usize::MAX,
                limit: self.limits.max_scope_depth,
            })?;
        if depth > self.limits.max_scope_depth {
            return Err(RandomError::ScopeDepthExceeded {
                depth,
                limit: self.limits.max_scope_depth,
            });
        }
        let scope_bytes =
            self.scope_bytes
                .checked_add(scope.len())
                .ok_or(RandomError::ScopeBytesExceeded {
                    bytes: usize::MAX,
                    limit: self.limits.max_scope_bytes,
                })?;
        if scope_bytes > self.limits.max_scope_bytes {
            return Err(RandomError::ScopeBytesExceeded {
                bytes: scope_bytes,
                limit: self.limits.max_scope_bytes,
            });
        }
        let mut path = self.scope_path();
        path.push(scope.to_owned());
        let stream_seed = RandomSeed::new(derive_seed(self.root_seed.value(), &path));
        Ok(Self {
            root_seed: self.root_seed,
            stream_seed,
            path: Arc::from(path),
            scope_bytes,
            limits: self.limits,
            state: Arc::new(Mutex::new(RandomState {
                state: stream_seed.value(),
            })),
        })
    }

    /// Creates an independent stream for a length-delimited child scope.
    ///
    /// The child starts at the same sequence every time this method is called
    /// on the same parent/path.  Use a distinct scope for each logical plan,
    /// thread group, virtual user, or function invocation that should not
    /// perturb another stream.
    pub fn scoped(&self, scope: impl AsRef<str>) -> Result<Self, RandomError> {
        self.try_scoped(scope)
    }

    /// Fallible alias for [`Self::try_scoped`].
    pub fn try_fork(&self, scope: impl AsRef<str>) -> Result<Self, RandomError> {
        self.try_scoped(scope)
    }

    /// Alias for [`Self::scoped`] that reads naturally at a runtime seam.
    pub fn fork(&self, scope: impl AsRef<str>) -> Result<Self, RandomError> {
        self.scoped(scope)
    }

    /// Returns a clone sharing this stream's cursor.
    #[must_use]
    pub fn shared(&self) -> Self {
        self.clone()
    }

    /// Returns the next reproducible 64-bit value.
    #[must_use]
    pub fn next_u64(&self) -> u64 {
        let mut state = recover_lock(&self.state);
        state.state = state.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        splitmix64(state.state)
    }

    /// Returns the next 32-bit value.
    #[must_use]
    pub fn next_u32(&self) -> u32 {
        self.next_u64() as u32
    }

    /// Returns the next deterministic boolean.
    #[must_use]
    pub fn next_bool(&self) -> bool {
        self.next_u64() & 1 == 1
    }

    /// Returns a value in `[start, end)` using rejection sampling to avoid
    /// modulo bias.
    pub fn range_u64(&self, range: Range<u64>) -> Result<u64, RandomError> {
        let width = range
            .end
            .checked_sub(range.start)
            .ok_or(RandomError::EmptyRange)?;
        if width == 0 {
            return Err(RandomError::EmptyRange);
        }
        let threshold = width.wrapping_neg() % width;
        loop {
            let value = self.next_u64();
            if value >= threshold {
                return Ok(range.start + value % width);
            }
        }
    }

    /// Returns a value in an inclusive range.
    pub fn range_inclusive_u64(&self, range: RangeInclusive<u64>) -> Result<u64, RandomError> {
        let start = *range.start();
        let end = *range.end();
        if end < start {
            return Err(RandomError::EmptyRange);
        }
        let width = end - start;
        if width == u64::MAX {
            // A full-width range contains 2^64 values, which cannot be
            // represented as a u64 width.  Every generated value is an
            // already-valid offset in this one case.
            return Ok(start.wrapping_add(self.next_u64()));
        }
        let offset = self.range_u64(0..width + 1)?;
        Ok(start + offset)
    }

    /// Fills a byte slice from the deterministic stream in little-endian
    /// chunks.
    pub fn fill_bytes(&self, bytes: &mut [u8]) {
        for chunk in bytes.chunks_mut(8) {
            let value = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&value[..chunk.len()]);
        }
    }

    /// Returns a cursor snapshot that can later be restored on this stream.
    #[must_use]
    pub fn checkpoint(&self) -> u64 {
        recover_lock(&self.state).state
    }

    /// Restores a previously captured cursor value.
    pub fn restore(&self, state: u64) {
        recover_lock(&self.state).state = state;
    }
}

impl RandomSource for DeterministicRandom {
    fn next_u64(&self) -> u64 {
        Self::next_u64(self)
    }

    fn range_u64(&self, range: Range<u64>) -> Result<u64, RandomError> {
        Self::range_u64(self, range)
    }
}

fn recover_lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn derive_seed(root: u64, path: &[String]) -> u64 {
    // FNV-1a with an explicit length prefix prevents the common `a/b` versus
    // `ab` scope collision.  SplitMix64 then diffuses the resulting hash.
    let mut hash = 0xcbf2_9ce4_8422_2325_u64 ^ root;
    for component in path {
        let length = component.len() as u64;
        for byte in length.to_le_bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
        }
        for byte in component.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
        }
    }
    splitmix64(hash)
}

fn splitmix64(mut value: u64) -> u64 {
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^ (value >> 31)
}

#[cfg(test)]
mod tests {
    // Test fixtures use unwrap to keep the assertion setup concise; every
    // value is deliberately within the bounds being tested.
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn same_seed_and_scope_reproduce() {
        let first = DeterministicRandom::new(41_u64)
            .scoped("virtual-user/0")
            .unwrap();
        let second = DeterministicRandom::new(41_u64)
            .scoped("virtual-user/0")
            .unwrap();
        let first_values = (0..16).map(|_| first.next_u64()).collect::<Vec<_>>();
        let second_values = (0..16).map(|_| second.next_u64()).collect::<Vec<_>>();
        assert_eq!(first_values, second_values);
    }

    #[test]
    fn recorded_root_and_derived_stream_seeds_are_stable() {
        let root = DeterministicRandom::new(RandomSeed::new(41));
        let child = root.scoped("virtual-user/0").unwrap();
        let same_child = DeterministicRandom::new(41_u64)
            .scoped("virtual-user/0")
            .unwrap();

        assert_eq!(root.seed(), RandomSeed::new(41));
        assert_eq!(root.root_seed(), root.seed());
        assert_eq!(child.root_seed(), root.seed());
        assert_eq!(child.stream_seed(), same_child.stream_seed());
        assert_ne!(root.stream_seed(), child.stream_seed());
    }

    #[test]
    fn scope_component_boundaries_are_part_of_the_seed() {
        let root = DeterministicRandom::new(17_u64);
        let slash_component = root.scoped("a/b").unwrap();
        let nested_components = root.scoped("a").unwrap().scoped("b").unwrap();
        let first_pair = root.scoped("a").unwrap().scoped("bc").unwrap();
        let second_pair = root.scoped("ab").unwrap().scoped("c").unwrap();

        assert_ne!(
            slash_component.stream_seed(),
            nested_components.stream_seed()
        );
        assert_ne!(first_pair.stream_seed(), second_pair.stream_seed());
    }

    #[test]
    fn unrelated_scopes_are_independent() {
        let root = DeterministicRandom::new(99_u64);
        let root_checkpoint = root.checkpoint();
        let user_zero = root.scoped("user/0").unwrap();
        let expected = user_zero.next_u64();
        let user_one = root.scoped("user/1").unwrap();
        for _ in 0..100 {
            let _ = user_one.next_u64();
        }
        assert_eq!(root.checkpoint(), root_checkpoint);
        assert_eq!(root.scoped("user/0").unwrap().next_u64(), expected);
    }

    #[test]
    fn clones_share_cursor_but_scopes_start_independently() {
        let stream = DeterministicRandom::new(7_u64);
        let clone = stream.clone();
        let checkpoint = stream.checkpoint();
        let first = stream.next_u64();
        let second_from_clone = clone.next_u64();
        let expected = DeterministicRandom::new(7_u64);
        expected.restore(checkpoint);
        assert_eq!(first, expected.next_u64());
        assert_eq!(second_from_clone, expected.next_u64());

        let child = stream.scoped("child").unwrap();
        let child_clone = child.clone();
        let child_checkpoint = child.checkpoint();
        let child_first = child.next_u64();
        let child_second_from_clone = child_clone.next_u64();
        let child_expected = DeterministicRandom::new(7_u64).scoped("child").unwrap();
        child_expected.restore(child_checkpoint);
        assert_eq!(child_first, child_expected.next_u64());
        assert_eq!(child_second_from_clone, child_expected.next_u64());
        assert_ne!(first, child_first);
    }

    #[test]
    fn range_errors_and_bounds_are_deterministic() {
        let random = DeterministicRandom::new(12_u64);
        let checkpoint = random.checkpoint();
        assert_eq!(
            random.range_u64(3..3).unwrap_err().code(),
            ErrorCode::RandomEmptyRange
        );
        assert_eq!(
            random
                .range_inclusive_u64(std::ops::RangeInclusive::new(4, 3))
                .unwrap_err()
                .code(),
            ErrorCode::RandomEmptyRange
        );
        assert_eq!(random.checkpoint(), checkpoint);
        for _ in 0..256 {
            let value = random.range_u64(10..15).unwrap();
            assert!((10..15).contains(&value));
        }
    }

    #[test]
    fn generated_ranges_stay_in_bounds_at_u64_edges() {
        let widths = [1, 2, 3, 7, u64::MAX - 1, u64::MAX];
        let starts = [0, 1, u64::MAX / 2];

        for width in widths {
            for start in starts {
                if start > u64::MAX - width {
                    continue;
                }
                let end = start + width;
                let stream_name = format!("range/{start}/{width}");
                let random = DeterministicRandom::new(0xA11C_E5E5_u64)
                    .scoped(stream_name)
                    .unwrap();
                for _ in 0..64 {
                    let value = random.range_u64(start..end).unwrap();
                    assert!(value >= start);
                    assert!(value < end);
                }
            }
        }
    }

    #[test]
    fn range_rejection_sampling_matches_an_independent_cursor() {
        let ranges = [0..1, 1..3, 7..12, 0..u64::MAX, u64::MAX - 2..u64::MAX];

        for (index, range) in ranges.into_iter().enumerate() {
            let random = DeterministicRandom::new(0xC0FF_EE_u64)
                .scoped(format!("range-reference/{index}"))
                .unwrap();
            let reference = DeterministicRandom::new(0xC0FF_EE_u64)
                .scoped(format!("range-reference/{index}"))
                .unwrap();
            let width = range.end - range.start;
            let threshold = (0_u64.wrapping_sub(width)) % width;
            let expected = loop {
                let value = reference.next_u64();
                if value >= threshold {
                    break range.start + value % width;
                }
            };

            assert_eq!(random.range_u64(range).unwrap(), expected);
            assert_eq!(random.checkpoint(), reference.checkpoint());
        }
    }

    #[test]
    fn inclusive_ranges_cover_singleton_and_full_domains_without_overflow() {
        let random = DeterministicRandom::new(0xB0_u64);
        assert_eq!(
            random.range_inclusive_u64(u64::MAX..=u64::MAX).unwrap(),
            u64::MAX
        );

        let full_domain = DeterministicRandom::new(0xB0_u64);
        let reference = DeterministicRandom::new(0xB0_u64);
        let expected = reference.next_u64();
        assert_eq!(
            full_domain.range_inclusive_u64(0..=u64::MAX).unwrap(),
            expected
        );
        assert_eq!(full_domain.checkpoint(), reference.checkpoint());

        for _ in 0..64 {
            let value = random
                .range_inclusive_u64((u64::MAX - 2)..=u64::MAX)
                .unwrap();
            assert!((u64::MAX - 2..=u64::MAX).contains(&value));
        }
    }

    #[test]
    fn checkpoint_and_restore_replay_the_same_values() {
        let random = DeterministicRandom::new(100_u64);
        let checkpoint = random.checkpoint();
        let expected = (0..8).map(|_| random.next_u64()).collect::<Vec<_>>();
        random.restore(checkpoint);
        let actual = (0..8).map(|_| random.next_u64()).collect::<Vec<_>>();
        assert_eq!(expected, actual);
    }

    #[test]
    fn scope_depth_and_bytes_are_checked_before_allocation() {
        let random = DeterministicRandom::with_limits(9_u64, RandomLimits::new(1, 3));
        let child = random.try_scoped("abc").unwrap();
        assert_eq!(child.scope_depth(), 1);
        assert_eq!(child.scope_bytes(), 3);
        assert_eq!(
            child.try_scoped("x").unwrap_err(),
            RandomError::ScopeDepthExceeded { depth: 2, limit: 1 }
        );
        assert_eq!(
            random.try_scoped("abcd").unwrap_err(),
            RandomError::ScopeBytesExceeded { bytes: 4, limit: 3 }
        );
        assert_eq!(
            random.scoped("abcd").unwrap_err(),
            RandomError::ScopeBytesExceeded { bytes: 4, limit: 3 }
        );
    }

    #[test]
    fn rejected_scope_keeps_path_and_cursor_unchanged() {
        let random = DeterministicRandom::with_limits(9_u64, RandomLimits::new(1, 3));
        let before_path = random.scope_path();
        let before_cursor = random.checkpoint();
        let error = random.try_scoped("abcd").unwrap_err();

        assert_eq!(
            error,
            RandomError::ScopeBytesExceeded { bytes: 4, limit: 3 }
        );
        assert_eq!(random.scope_path(), before_path);
        assert_eq!(random.checkpoint(), before_cursor);
    }

    #[test]
    fn scope_byte_addition_overflow_is_rejected_without_allocation() {
        let mut random = DeterministicRandom::new(9_u64);
        random.scope_bytes = usize::MAX;
        let before_path = random.scope_path();
        let before_cursor = random.checkpoint();

        let error = random.try_scoped("x").unwrap_err();
        assert_eq!(
            error,
            RandomError::ScopeBytesExceeded {
                bytes: usize::MAX,
                limit: random.limits.max_scope_bytes,
            }
        );
        assert_eq!(random.scope_path(), before_path);
        assert_eq!(random.checkpoint(), before_cursor);
    }

    #[test]
    fn random_debug_does_not_include_scope_text() {
        let random = DeterministicRandom::new(1_u64)
            .scoped("scope-secret")
            .unwrap();
        let output = format!("{random:?}");
        assert!(!output.contains("scope-secret"));
        assert!(output.contains("scope_bytes"));
    }
}
