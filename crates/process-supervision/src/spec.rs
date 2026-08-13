// SPDX-License-Identifier: Apache-2.0
//! Private, bounded launch descriptions.
//!
//! No caller receives a `Command`, a raw process identifier, a raw handle, or
//! an arbitrary creation hook.  The application boundary will mint these
//! values after its executable/path policy has been checked.

use crate::error::{ErrorCategory, ErrorCode, SupervisionError};
use crate::policy::PurposeMarker;
use std::marker::PhantomData;
use std::path::Path;
use std::time::{Duration, Instant};

pub(crate) const MAX_EXECUTABLE_BYTES: usize = 1024;
pub(crate) const MAX_ARGUMENTS: usize = 32;
pub(crate) const MAX_ARGUMENT_BYTES: usize = 4096;
pub(crate) const MAX_ENVIRONMENT: usize = 32;
pub(crate) const MAX_ENVIRONMENT_BYTES: usize = 4096;
pub(crate) const MAX_WORKING_ROOT_BYTES: usize = 1024;

/// A bounded UTF-8 value used only after the application policy has accepted
/// the corresponding OS encoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BoundedText<const LIMIT: usize>(String);

impl<const LIMIT: usize> BoundedText<LIMIT> {
    pub(crate) fn new(value: impl AsRef<str>) -> Result<Self, SupervisionError> {
        let value = value.as_ref();
        if value.len() > LIMIT || value.contains('\0') {
            return Err(SupervisionError::new(
                ErrorCode::Configuration,
                ErrorCategory::Setup,
                false,
                "launch text is empty, oversized, or contains NUL",
            ));
        }
        Ok(Self(value.to_owned()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// Absolute executable identity minted by the application allowlist.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExecutableRef(BoundedText<MAX_EXECUTABLE_BYTES>);

impl ExecutableRef {
    pub(crate) fn new(path: impl AsRef<str>) -> Result<Self, SupervisionError> {
        let text = BoundedText::new(path)?;
        if text.as_str().is_empty() || !Path::new(text.as_str()).is_absolute() {
            return Err(SupervisionError::new(
                ErrorCode::Configuration,
                ErrorCategory::Setup,
                false,
                "executable must be an absolute allowlisted path",
            ));
        }
        Ok(Self(text))
    }

    pub(crate) fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// Fixed-capacity argument vector preserving exact boundaries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BoundedArguments {
    values: [Option<BoundedText<MAX_ARGUMENT_BYTES>>; MAX_ARGUMENTS],
    length: usize,
    total_bytes: usize,
}

impl Default for BoundedArguments {
    fn default() -> Self {
        Self {
            values: std::array::from_fn(|_| None),
            length: 0,
            total_bytes: 0,
        }
    }
}

impl BoundedArguments {
    pub(crate) fn push(&mut self, value: impl AsRef<str>) -> Result<(), SupervisionError> {
        let item = BoundedText::new(value)?;
        let next_total = self.total_bytes.saturating_add(item.as_str().len());
        if self.length == MAX_ARGUMENTS || next_total > MAX_ARGUMENT_BYTES {
            return Err(SupervisionError::new(
                ErrorCode::Configuration,
                ErrorCategory::Setup,
                false,
                "argument count or byte bound exceeded",
            ));
        }
        self.values[self.length] = Some(item);
        self.length += 1;
        self.total_bytes = next_total;
        Ok(())
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &str> {
        self.values[..self.length]
            .iter()
            .filter_map(|value| value.as_ref().map(BoundedText::as_str))
    }
}

/// One bounded allowlisted environment entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EnvironmentEntry {
    key: BoundedText<MAX_ARGUMENT_BYTES>,
    value: BoundedText<MAX_ARGUMENT_BYTES>,
}

/// Fixed-capacity environment with duplicate-key rejection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BoundedEnvironment {
    entries: [Option<EnvironmentEntry>; MAX_ENVIRONMENT],
    length: usize,
    total_bytes: usize,
}

impl Default for BoundedEnvironment {
    fn default() -> Self {
        Self {
            entries: std::array::from_fn(|_| None),
            length: 0,
            total_bytes: 0,
        }
    }
}

impl BoundedEnvironment {
    pub(crate) fn insert(
        &mut self,
        key: impl AsRef<str>,
        value: impl AsRef<str>,
    ) -> Result<(), SupervisionError> {
        let key = BoundedText::new(key)?;
        let value = BoundedText::new(value)?;
        if key.as_str().is_empty() {
            return Err(SupervisionError::new(
                ErrorCode::Configuration,
                ErrorCategory::Setup,
                false,
                "environment keys cannot be empty",
            ));
        }
        if self.entries[..self.length]
            .iter()
            .flatten()
            .any(|entry| entry.key.as_str().eq_ignore_ascii_case(key.as_str()))
        {
            return Err(SupervisionError::new(
                ErrorCode::Configuration,
                ErrorCategory::Setup,
                false,
                "environment keys must be unique under platform comparison",
            ));
        }
        let next_total = self
            .total_bytes
            .saturating_add(key.as_str().len())
            .saturating_add(value.as_str().len());
        if self.length == MAX_ENVIRONMENT || next_total > MAX_ENVIRONMENT_BYTES {
            return Err(SupervisionError::new(
                ErrorCode::Configuration,
                ErrorCategory::Setup,
                false,
                "environment count or byte bound exceeded",
            ));
        }
        self.entries[self.length] = Some(EnvironmentEntry { key, value });
        self.length += 1;
        self.total_bytes = next_total;
        Ok(())
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries[..self.length].iter().filter_map(|entry| {
            entry
                .as_ref()
                .map(|entry| (entry.key.as_str(), entry.value.as_str()))
        })
    }
}

/// An allowlisted working directory/root.  Revalidation is a filesystem-edge
/// responsibility and is deliberately not performed by this pure crate yet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WorkingRootRef(BoundedText<MAX_WORKING_ROOT_BYTES>);

impl WorkingRootRef {
    pub(crate) fn new(path: impl AsRef<str>) -> Result<Self, SupervisionError> {
        let text = BoundedText::new(path)?;
        if text.as_str().is_empty() || !Path::new(text.as_str()).is_absolute() {
            return Err(SupervisionError::new(
                ErrorCode::Configuration,
                ErrorCategory::Setup,
                false,
                "working root must be an absolute allowlisted path",
            ));
        }
        Ok(Self(text))
    }

    pub(crate) fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// Closed stdio policy.  Null endpoints are the only stage-one launch mode;
/// framed endpoints will be added through the same bounded capability type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StdioContract {
    Null,
}

/// A monotonic absolute deadline copied into the request before queueing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MonotonicDeadline(Instant);

impl MonotonicDeadline {
    pub(crate) fn after(duration: Duration) -> Self {
        Self(
            Instant::now()
                .checked_add(duration)
                .unwrap_or_else(Instant::now),
        )
    }

    pub(crate) fn instant(self) -> Instant {
        self.0
    }
}

/// Required containment is selected by the sealed purpose marker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RequiredContainment {
    ExactChild,
    ProcessTree,
}

/// Private typed launch request.  The generic marker prevents a process-tree
/// caller from selecting the exact-child policy by changing a runtime flag.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SpawnSpec<P: PurposeMarker> {
    pub(crate) executable: ExecutableRef,
    pub(crate) arguments: BoundedArguments,
    pub(crate) working_root: WorkingRootRef,
    pub(crate) environment: BoundedEnvironment,
    pub(crate) stdio: StdioContract,
    pub(crate) setup_deadline: MonotonicDeadline,
    pub(crate) required_containment: RequiredContainment,
    marker: PhantomData<P>,
}

impl<P: PurposeMarker> SpawnSpec<P> {
    pub(crate) fn deadline(&self) -> MonotonicDeadline {
        self.setup_deadline
    }
}

impl<P: PurposeMarker> SpawnSpec<P> {
    pub(crate) fn new(
        executable: ExecutableRef,
        arguments: BoundedArguments,
        working_root: WorkingRootRef,
        environment: BoundedEnvironment,
        setup_deadline: MonotonicDeadline,
    ) -> Self {
        Self {
            executable,
            arguments,
            working_root,
            environment,
            stdio: StdioContract::Null,
            setup_deadline,
            required_containment: if P::KIND.requires_tree() {
                RequiredContainment::ProcessTree
            } else {
                RequiredContainment::ExactChild
            },
            marker: PhantomData,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), SupervisionError> {
        P::KIND.validate_platform()?;
        if self.required_containment
            != match P::KIND {
                crate::policy::PolicyKind::ExactChild => RequiredContainment::ExactChild,
                crate::policy::PolicyKind::ProcessTree => RequiredContainment::ProcessTree,
            }
        {
            return Err(SupervisionError::new(
                ErrorCode::Configuration,
                ErrorCategory::Setup,
                false,
                "launch purpose and containment marker disagree",
            ));
        }
        if self.setup_deadline.instant() <= Instant::now() {
            return Err(SupervisionError::new(
                ErrorCode::Configuration,
                ErrorCategory::Setup,
                false,
                "launch setup deadline has elapsed",
            ));
        }
        Ok(())
    }
}

pub(crate) struct LaunchSpec {
    pub(crate) executable: ExecutableRef,
    pub(crate) arguments: BoundedArguments,
    pub(crate) working_root: WorkingRootRef,
    pub(crate) environment: BoundedEnvironment,
    pub(crate) stdio: StdioContract,
    pub(crate) setup_deadline: MonotonicDeadline,
    pub(crate) required_containment: RequiredContainment,
    kind: crate::policy::PolicyKind,
}

impl LaunchSpec {
    pub(crate) const fn kind(&self) -> crate::policy::PolicyKind {
        self.kind
    }

    pub(crate) fn validate(&self) -> Result<(), SupervisionError> {
        self.kind.validate_platform()?;
        let expected = match self.kind {
            crate::policy::PolicyKind::ExactChild => RequiredContainment::ExactChild,
            crate::policy::PolicyKind::ProcessTree => RequiredContainment::ProcessTree,
        };
        if self.required_containment != expected {
            return Err(SupervisionError::new(
                ErrorCode::Configuration,
                ErrorCategory::Setup,
                false,
                "launch purpose and containment policy disagree",
            ));
        }
        if self.setup_deadline.instant() <= Instant::now() {
            return Err(SupervisionError::new(
                ErrorCode::Configuration,
                ErrorCategory::Setup,
                false,
                "launch setup deadline has elapsed",
            ));
        }
        Ok(())
    }

    pub(crate) fn deadline(&self) -> MonotonicDeadline {
        self.setup_deadline
    }
}

impl<P: PurposeMarker> From<SpawnSpec<P>> for LaunchSpec {
    fn from(spec: SpawnSpec<P>) -> Self {
        Self {
            executable: spec.executable,
            arguments: spec.arguments,
            working_root: spec.working_root,
            environment: spec.environment,
            stdio: spec.stdio,
            setup_deadline: spec.setup_deadline,
            required_containment: spec.required_containment,
            kind: P::KIND,
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn empty_argument_and_environment_value_preserve_boundaries() {
        let mut arguments = BoundedArguments::default();
        arguments.push("").expect("empty argv item is valid");
        assert_eq!(arguments.iter().collect::<Vec<_>>(), vec![""]);

        let mut environment = BoundedEnvironment::default();
        environment
            .insert("EMPTY", "")
            .expect("empty environment value is valid");
        assert_eq!(environment.iter().collect::<Vec<_>>(), vec![("EMPTY", "")]);
        assert!(environment.insert("", "value").is_err());
    }

    #[test]
    fn launch_spec_rechecks_containment_policy_after_type_erasure() {
        let spec = LaunchSpec {
            executable: ExecutableRef::new("/bin/true").expect("absolute executable"),
            arguments: BoundedArguments::default(),
            working_root: WorkingRootRef::new("/").expect("absolute root"),
            environment: BoundedEnvironment::default(),
            stdio: StdioContract::Null,
            setup_deadline: MonotonicDeadline::after(Duration::from_secs(1)),
            required_containment: RequiredContainment::ProcessTree,
            kind: crate::policy::PolicyKind::ExactChild,
        };
        assert_eq!(
            spec.validate().expect_err("mismatched policy").code(),
            ErrorCode::Configuration
        );
    }
}
