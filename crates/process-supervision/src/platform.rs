// SPDX-License-Identifier: Apache-2.0
//! Target dispatch for the private platform ownership boundaries.

use crate::error::SupervisionError;

#[cfg(unix)]
pub(crate) use crate::unix::{PlatformToken, RootHandle};
#[cfg(windows)]
pub(crate) use crate::windows::{PlatformToken, RootHandle};

/// A failed platform handoff may still own exact resources.  The service
/// installs these cells into the already-reserved slot before exposing the
/// typed error, so setup failure cannot drop or hide a live root/handle.
#[derive(Debug)]
pub(crate) struct CreateFailure {
    pub(crate) error: SupervisionError,
    pub(crate) root: Option<RootHandle>,
    pub(crate) token: Option<PlatformToken>,
}

impl CreateFailure {
    pub(crate) fn without_resources(error: SupervisionError) -> Self {
        Self {
            error,
            root: None,
            token: None,
        }
    }

    pub(crate) fn with_resources(
        error: SupervisionError,
        root: Option<RootHandle>,
        token: Option<PlatformToken>,
    ) -> Self {
        Self { error, root, token }
    }
}

impl From<SupervisionError> for CreateFailure {
    fn from(error: SupervisionError) -> Self {
        Self::without_resources(error)
    }
}

#[cfg(not(any(unix, windows)))]
mod unsupported {
    use super::*;
    use crate::policy::PolicyKind;
    use crate::process::{CleanupAttempt, ExitInfo, RootObservation};
    use crate::spec::LaunchSpec;
    use std::time::Instant;

    /// No process resource exists on an unsupported target.
    #[derive(Debug)]
    pub(crate) struct RootHandle;
    /// No platform token exists on an unsupported target.
    #[derive(Debug)]
    pub(crate) struct PlatformToken;

    #[allow(clippy::result_large_err)]
    pub(crate) fn create_root(
        _: &LaunchSpec,
    ) -> Result<(RootHandle, Option<PlatformToken>), CreateFailure> {
        Err(CreateFailure::without_resources(SupervisionError::new(
            crate::error::ErrorCode::UnsupportedPlatform,
            crate::error::ErrorCategory::Unsupported,
            false,
            "process supervision is unsupported on this target",
        )))
    }

    pub(crate) fn validate(
        _: &mut RootHandle,
        _: &mut Option<PlatformToken>,
        _: PolicyKind,
    ) -> Result<(), SupervisionError> {
        Err(SupervisionError::new(
            crate::error::ErrorCode::UnsupportedPlatform,
            crate::error::ErrorCategory::Unsupported,
            false,
            "process supervision is unsupported on this target",
        ))
    }

    pub(crate) fn observe(_: &mut RootHandle) -> Result<RootObservation, SupervisionError> {
        Err(SupervisionError::new(
            crate::error::ErrorCode::UnsupportedPlatform,
            crate::error::ErrorCategory::Unsupported,
            false,
            "process supervision is unsupported on this target",
        ))
    }

    pub(crate) fn cleanup(
        _: &mut RootHandle,
        _: &mut Option<PlatformToken>,
        _: PolicyKind,
        _: Instant,
    ) -> CleanupAttempt {
        CleanupAttempt::retained(SupervisionError::new(
            crate::error::ErrorCode::UnsupportedPlatform,
            crate::error::ErrorCategory::Unsupported,
            false,
            "process supervision is unsupported on this target",
        ))
    }

    pub(crate) fn close_token(_: &mut PlatformToken) -> Result<(), SupervisionError> {
        Err(SupervisionError::new(
            crate::error::ErrorCode::UnsupportedPlatform,
            crate::error::ErrorCategory::Unsupported,
            false,
            "platform token is unsupported on this target",
        ))
    }

    pub(crate) fn root_exit(_: &RootHandle) -> Option<ExitInfo> {
        None
    }
}

#[cfg(not(any(unix, windows)))]
pub(crate) use unsupported::{PlatformToken, RootHandle};
#[cfg(not(any(unix, windows)))]
pub(crate) use unsupported::{cleanup, close_token, create_root, observe, root_exit, validate};

#[cfg(unix)]
pub(crate) use crate::unix::{cleanup, close_token, create_root, observe, root_exit, validate};

#[cfg(unix)]
pub(crate) fn close_root(_: &mut RootHandle) -> Result<(), SupervisionError> {
    Ok(())
}

#[cfg(windows)]
pub(crate) use crate::windows::{cleanup, close_token, create_root, observe, root_exit, validate};

#[cfg(windows)]
pub(crate) use crate::windows::close_root;
