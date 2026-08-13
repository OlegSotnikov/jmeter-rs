// SPDX-License-Identifier: Apache-2.0
//! Explicit coordination capabilities for controller-owned critical sections.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Mutex, MutexGuard};

const MAX_LOCK_NAME_BYTES: usize = 4_096;
const MAX_HELD_LOCKS: usize = 65_536;

fn lock<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
    value
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Typed failures from a critical-section coordinator.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(
    missing_docs,
    reason = "error payload fields are documented by variant semantics"
)]
pub enum CriticalSectionError {
    /// A lock name was empty or exceeded the bounded name size.
    InvalidName,
    /// The bounded coordinator has no room for another held lock.
    Capacity { limit: usize },
    /// Another virtual user currently owns the requested lock.
    Busy { name: String, owner: u64 },
    /// A release did not match the owner that acquired the lock.
    NotOwner { name: String, owner: u64 },
}

impl CriticalSectionError {
    /// Returns a stable diagnostic code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidName => "runtime.critical-section.invalid-name",
            Self::Capacity { .. } => "runtime.critical-section.capacity",
            Self::Busy { .. } => "runtime.critical-section.busy",
            Self::NotOwner { .. } => "runtime.critical-section.not-owner",
        }
    }
}

impl fmt::Display for CriticalSectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName => write!(formatter, "{}", self.code()),
            Self::Capacity { limit } => write!(formatter, "{}: limit {limit}", self.code()),
            Self::Busy { name, owner } => {
                write!(formatter, "{}: {name:?} owned by {owner}", self.code())
            }
            Self::NotOwner { name, owner } => {
                write!(formatter, "{}: {name:?} owner {owner}", self.code())
            }
        }
    }
}

impl std::error::Error for CriticalSectionError {}

/// Executor-neutral critical-section coordinator.
pub trait CriticalSectionCoordinator: Send + Sync {
    /// Attempts to acquire a named section for one lifecycle identity.
    fn try_acquire(&self, name: &str, lifecycle_id: u64) -> Result<(), CriticalSectionError>;

    /// Releases a section held by one lifecycle identity.
    fn release(&self, name: &str, lifecycle_id: u64) -> Result<(), CriticalSectionError>;
}

/// Bounded deterministic coordinator used by default and by tests.
#[derive(Debug)]
pub struct DeterministicCriticalSectionCoordinator {
    held: Mutex<BTreeMap<String, u64>>,
    max_held: usize,
}

impl Default for DeterministicCriticalSectionCoordinator {
    fn default() -> Self {
        Self::new(MAX_HELD_LOCKS)
    }
}

impl DeterministicCriticalSectionCoordinator {
    /// Creates a coordinator with a finite held-lock bound.
    #[must_use]
    pub fn new(max_held: usize) -> Self {
        Self {
            held: Mutex::new(BTreeMap::new()),
            max_held: max_held.min(MAX_HELD_LOCKS),
        }
    }
}

impl CriticalSectionCoordinator for DeterministicCriticalSectionCoordinator {
    fn try_acquire(&self, name: &str, lifecycle_id: u64) -> Result<(), CriticalSectionError> {
        if name.is_empty() || name.len() > MAX_LOCK_NAME_BYTES {
            return Err(CriticalSectionError::InvalidName);
        }
        let mut held = lock(&self.held);
        if let Some(owner) = held.get(name).copied() {
            return Err(CriticalSectionError::Busy {
                name: name.to_owned(),
                owner,
            });
        }
        if held.len() >= self.max_held {
            return Err(CriticalSectionError::Capacity {
                limit: self.max_held,
            });
        }
        held.insert(name.to_owned(), lifecycle_id);
        Ok(())
    }

    fn release(&self, name: &str, lifecycle_id: u64) -> Result<(), CriticalSectionError> {
        let mut held = lock(&self.held);
        match held.get(name).copied() {
            Some(owner) if owner == lifecycle_id => {
                held.remove(name);
                Ok(())
            }
            Some(owner) => Err(CriticalSectionError::NotOwner {
                name: name.to_owned(),
                owner,
            }),
            None => Err(CriticalSectionError::NotOwner {
                name: name.to_owned(),
                owner: lifecycle_id,
            }),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "deterministic coordinator setup")]
mod tests {
    use super::*;

    #[test]
    fn coordinator_has_owner_and_capacity_semantics() {
        let coordinator = DeterministicCriticalSectionCoordinator::new(1);
        coordinator.try_acquire("gate", 1).expect("first owner");
        assert!(matches!(
            coordinator.try_acquire("gate", 2),
            Err(CriticalSectionError::Busy { owner: 1, .. })
        ));
        assert!(matches!(
            coordinator.try_acquire("other", 2),
            Err(CriticalSectionError::Capacity { limit: 1 })
        ));
        assert!(matches!(
            coordinator.release("gate", 2),
            Err(CriticalSectionError::NotOwner { .. })
        ));
        coordinator.release("gate", 1).expect("owner release");
    }
}
