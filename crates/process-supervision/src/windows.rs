// SPDX-License-Identifier: Apache-2.0
//! Private Windows suspended-create/Job boundary.
//!
//! Runtime containment evidence is not accepted yet, so the public capability
//! report keeps Windows process-tree support disabled.  The compile-checked
//! backend below is deliberately fail-closed until a disposable-VM evidence
//! lane proves the complete lifecycle.  It uses raw `CreateProcessW` with an
//! unnamed Job and exact `PROCESS_INFORMATION` handles; it never uses
//! `std::process::Command`, PID reopening, or process enumeration.

use crate::error::{CleanupState, ErrorCategory, ErrorCode, SupervisionError};
use crate::platform::CreateFailure;
use crate::policy::PolicyKind;
use crate::process::{CleanupAttempt, ExitInfo, RootObservation};
use crate::spec::LaunchSpec;
use std::cmp::Ordering;
use std::ffi::c_void;
use std::mem::size_of;
use std::ptr::{null, null_mut};
use std::time::Instant;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE, WAIT_FAILED, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
    QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
    GetExitCodeProcess, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION, ResumeThread, STARTUPINFOEXW,
    UpdateProcThreadAttribute, WaitForSingleObject,
};

const MAX_ATTRIBUTE_BYTES: usize = 4096;
const MAX_LAUNCH_UNITS: usize = 8192;
const STILL_ACTIVE: u32 = 259;

/// Fixed-capacity UTF-16 storage used for every Windows launch field.  The
/// buffer reserves one unit for the final NUL and never grows or moves after
/// it is handed to an OS call.
struct Utf16Buffer {
    values: [u16; MAX_LAUNCH_UNITS],
    len: usize,
}

impl Utf16Buffer {
    fn new() -> Self {
        Self {
            values: [0; MAX_LAUNCH_UNITS],
            len: 0,
        }
    }

    fn push_unit(&mut self, value: u16) -> Result<(), SupervisionError> {
        if self.len + 1 >= self.values.len() {
            return Err(SupervisionError::new(
                ErrorCode::Configuration,
                ErrorCategory::Setup,
                false,
                "Windows UTF-16 launch field exceeded its fixed bound",
            ));
        }
        self.values[self.len] = value;
        self.len += 1;
        Ok(())
    }

    fn push_char(&mut self, value: char) -> Result<(), SupervisionError> {
        let mut units = [0; 2];
        for unit in value.encode_utf16(&mut units) {
            self.push_unit(*unit)?;
        }
        Ok(())
    }

    fn push_str(&mut self, value: &str) -> Result<(), SupervisionError> {
        if value.contains('\0') {
            return Err(SupervisionError::new(
                ErrorCode::Configuration,
                ErrorCategory::Setup,
                false,
                "Windows launch text contains an embedded NUL",
            ));
        }
        for value in value.chars() {
            self.push_char(value)?;
        }
        Ok(())
    }

    fn finish(mut self) -> Result<Self, SupervisionError> {
        self.push_unit(0)?;
        Ok(self)
    }

    fn is_empty_payload(&self) -> bool {
        self.len == 0
    }

    fn as_ptr(&self) -> *const u16 {
        self.values.as_ptr()
    }

    fn as_mut_ptr(&mut self) -> *mut u16 {
        self.values.as_mut_ptr()
    }
}

/// Raw-handle lifecycle.  A failed or ambiguous close never clears `raw`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HandleState {
    Empty,
    Owned,
    Closing,
    Closed,
    OutcomeUnknown,
}

/// A fixed ownership cell.  `usize` keeps the slot `Send` without exposing a
/// raw pointer to safe code; conversion back to `HANDLE` occurs only inside
/// this audited module immediately at an API call.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct OwnedHandle {
    raw: usize,
    state: HandleState,
}

impl OwnedHandle {
    fn empty() -> Self {
        Self {
            raw: 0,
            state: HandleState::Empty,
        }
    }

    fn from_raw(handle: HANDLE) -> Result<Self, SupervisionError> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(SupervisionError::new(
                ErrorCode::HandoffFailed,
                ErrorCategory::Setup,
                false,
                "Windows API returned an invalid owned handle",
            ));
        }
        Ok(Self {
            raw: handle as usize,
            state: HandleState::Owned,
        })
    }

    /// Converts a process-information handle without a fallible handoff.  A
    /// malformed API result is represented as an explicit empty cell so the
    /// already-created sibling handle(s) can still be transferred to the
    /// reserved slot and diagnosed there instead of being lost with a local.
    fn from_raw_or_empty(handle: HANDLE) -> Self {
        Self {
            raw: if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                0
            } else {
                handle as usize
            },
            state: if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                HandleState::Empty
            } else {
                HandleState::Owned
            },
        }
    }

    fn handle(&self) -> HANDLE {
        self.raw as *mut c_void
    }

    fn is_owned(&self) -> bool {
        matches!(self.state, HandleState::Owned | HandleState::Closing)
    }

    fn close(&mut self) -> Result<(), SupervisionError> {
        if self.state == HandleState::Empty || self.state == HandleState::Closed {
            return Ok(());
        }
        if self.state == HandleState::OutcomeUnknown {
            return Err(SupervisionError::new(
                ErrorCode::HandleStateUnknown,
                ErrorCategory::Cleanup,
                false,
                "Windows handle close outcome is unknown; raw ownership is quarantined",
            ));
        }
        let handle = self.handle();
        self.state = HandleState::Closing;
        // SAFETY: `handle` was returned by a Windows creation API and remains
        // owned by this cell.  No other thread can access the service-thread
        // slot.  A successful result is the only condition that clears raw.
        let closed = unsafe { CloseHandle(handle) } != 0;
        if closed {
            self.raw = 0;
            self.state = HandleState::Closed;
            Ok(())
        } else {
            // CloseHandle failure is contractually treated as preserving
            // ownership; the cell remains retryable and observable.
            self.state = HandleState::Owned;
            Err(SupervisionError::new(
                ErrorCode::HandleCloseFailed,
                ErrorCategory::Cleanup,
                true,
                "CloseHandle failed; the raw handle remains owned for retry",
            )
            .with_os_error(unsafe { GetLastError() } as i32))
        }
    }

    #[cfg(test)]
    fn close_probe(&mut self, outcome: CloseProbe) -> Result<(), SupervisionError> {
        match outcome {
            CloseProbe::Success => {
                self.raw = 0;
                self.state = HandleState::Closed;
                Ok(())
            }
            CloseProbe::KnownFailure => {
                self.state = HandleState::Owned;
                Err(SupervisionError::cleanup(
                    ErrorCode::HandleCloseFailed,
                    "injected known close failure retains raw ownership",
                ))
            }
            CloseProbe::Unknown => {
                self.state = HandleState::OutcomeUnknown;
                Err(SupervisionError::new(
                    ErrorCode::HandleStateUnknown,
                    ErrorCategory::Cleanup,
                    false,
                    "injected ambiguous close outcome quarantines raw ownership",
                ))
            }
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CloseProbe {
    Success,
    KnownFailure,
    Unknown,
}

/// Exact root process handle and diagnostic process ID.  The ID is never a
/// cleanup target; termination uses this retained process handle only.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct WindowsRoot {
    pub(crate) process: OwnedHandle,
    pub(crate) pid: u32,
    pub(crate) exit: Option<ExitInfo>,
    pub(crate) reaped: bool,
}

/// Job plus suspended primary-thread ownership cells.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct WindowsJobToken {
    pub(crate) job: OwnedHandle,
    pub(crate) thread: OwnedHandle,
    pub(crate) assigned: bool,
    pub(crate) resumed: bool,
}

pub(crate) type RootHandle = WindowsRoot;
pub(crate) type PlatformToken = WindowsJobToken;

/// Evidence gate.  It intentionally remains false until the dedicated VM
/// lifecycle lane proves assignment, unrelated-sibling safety, nested-job
/// behavior, and no handle leak.
pub(crate) const fn runtime_evidence_accepted() -> bool {
    false
}

// The failure carries exact raw-handle ownership by value; boxing at this
// panic-sensitive boundary could lose a live handle if allocation failed.
#[allow(clippy::result_large_err)]
pub(crate) fn create_root(
    spec: &LaunchSpec,
) -> Result<(RootHandle, Option<PlatformToken>), CreateFailure> {
    if !runtime_evidence_accepted() {
        return Err(CreateFailure::without_resources(SupervisionError::new(
            ErrorCode::UnsupportedPlatform,
            ErrorCategory::Unsupported,
            false,
            "Windows suspended process supervision awaits independent runtime evidence",
        )));
    }
    create_suspended(spec)
}

/// Builds and launches the exact suspended root.  Every unsafe operation in
/// this function is adjacent to the invariant it relies on; returned handles
/// are wrapped before any fallible setup call can run.
#[allow(dead_code, clippy::result_large_err)]
fn create_suspended(
    spec: &LaunchSpec,
) -> Result<(RootHandle, Option<PlatformToken>), CreateFailure> {
    spec.validate()?;
    let application = utf16_nul(spec.executable.as_str())?;
    let mut command_line = command_line(spec)?;
    let working_root = utf16_nul(spec.working_root.as_str())?;
    let environment = environment_block(spec)?;

    // The Job is unnamed, kill-on-close, and no breakaway flag is ever set.
    // SAFETY: null security attributes request a private unnamed Job; null
    // name prevents another process from reopening it by name.
    let job_raw = unsafe { CreateJobObjectW(null::<SECURITY_ATTRIBUTES>(), null()) };
    let mut job = OwnedHandle::from_raw(job_raw).map_err(|error| {
        CreateFailure::without_resources(error.with_secondary(SupervisionError::new(
            ErrorCode::JobCreateFailed,
            ErrorCategory::Setup,
            false,
            "CreateJobObjectW returned no valid handle",
        )))
    })?;
    if let Err(error) = configure_job(&mut job) {
        return Err(CreateFailure::with_resources(
            error,
            None,
            Some(WindowsJobToken {
                job,
                thread: OwnedHandle::empty(),
                assigned: false,
                resumed: false,
            }),
        ));
    }

    let mut startup = STARTUPINFOEXW::default();
    // Stage-one launches expose only the Null stdio contract, so there are no
    // child handles to inherit.  Do not manufacture an empty
    // PROC_THREAD_ATTRIBUTE_HANDLE_LIST: Windows treats that attribute as a
    // real allowlist and a zero-sized update is not a valid proof.  A future
    // bounded endpoint implementation must provide a nonempty typed handle
    // array and use the audited attribute-list builder below.
    startup.StartupInfo.cb =
        size_of::<windows_sys::Win32::System::Threading::STARTUPINFOW>() as u32;
    startup.lpAttributeList = null_mut();
    let mut process_info = PROCESS_INFORMATION::default();
    let flags = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT;
    // SAFETY: all UTF-16 buffers are NUL-terminated and live across the call;
    // `command_line` is mutable as required by CreateProcessW; the startup
    // extension has no attribute list because the Null stdio contract has no
    // child handles; no ambient inherited handles are enabled.
    let created = unsafe {
        CreateProcessW(
            application.as_ptr(),
            command_line.as_mut_ptr(),
            null(),
            null(),
            0,
            flags,
            if environment.is_empty_payload() {
                null()
            } else {
                environment.as_ptr().cast::<c_void>()
            },
            working_root.as_ptr(),
            &startup.StartupInfo,
            &mut process_info,
        )
    } != 0;
    if !created {
        return Err(CreateFailure::with_resources(
            last_error(
                ErrorCode::SpawnFailed,
                ErrorCategory::Setup,
                "CreateProcessW failed before a root was returned",
            ),
            None,
            Some(WindowsJobToken {
                job,
                thread: OwnedHandle::empty(),
                assigned: false,
                resumed: false,
            }),
        ));
    }

    // Handoff invariant: both exact PROCESS_INFORMATION handles are wrapped
    // immediately, before assignment/resume or any logging/allocation.
    let process = OwnedHandle::from_raw_or_empty(process_info.hProcess);
    let thread = OwnedHandle::from_raw_or_empty(process_info.hThread);
    let mut token = WindowsJobToken {
        job,
        thread,
        assigned: false,
        resumed: false,
    };
    let root = WindowsRoot {
        process,
        pid: process_info.dwProcessId,
        exit: None,
        reaped: false,
    };
    if root.process.state == HandleState::Empty || token.thread.state == HandleState::Empty {
        return Err(CreateFailure::with_resources(
            SupervisionError::new(
                ErrorCode::HandoffFailed,
                ErrorCategory::Setup,
                false,
                "CreateProcessW did not return both exact process/thread handles",
            ),
            Some(root),
            Some(token),
        ));
    }
    // SAFETY: process handle is the exact hProcess from the immediately prior
    // PROCESS_INFORMATION return and the Job is still owned by this token.
    if unsafe { AssignProcessToJobObject(token.job.handle(), root.process.handle()) } == 0 {
        return Err(CreateFailure::with_resources(
            last_error(
                ErrorCode::JobAssignmentFailed,
                ErrorCategory::Containment,
                "AssignProcessToJobObject failed before resume",
            ),
            Some(root),
            Some(token),
        ));
    }
    token.assigned = true;
    // SAFETY: this is the exact primary hThread returned for the suspended
    // root; no thread is rediscovered by ID.  Windows documents a previous
    // suspend count of one as proof that this call resumed the initial state.
    let previous = unsafe { ResumeThread(token.thread.handle()) };
    if previous != 1 {
        return Err(CreateFailure::with_resources(
            SupervisionError::new(
                ErrorCode::ThreadResumeFailed,
                ErrorCategory::Containment,
                false,
                "ResumeThread did not return the required initial count of one",
            ),
            Some(root),
            Some(token),
        ));
    }
    token.resumed = true;
    Ok((root, Some(token)))
}

fn configure_job(job: &mut OwnedHandle) -> Result<(), SupervisionError> {
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: `limits` is initialized to the exact structure size required by
    // JobObjectExtendedLimitInformation and `job` is the owned Job handle.
    let ok = unsafe {
        SetInformationJobObject(
            job.handle(),
            JobObjectExtendedLimitInformation,
            (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast::<c_void>(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    } != 0;
    if ok {
        Ok(())
    } else {
        Err(last_error(
            ErrorCode::JobCreateFailed,
            ErrorCategory::Setup,
            "SetInformationJobObject(KILL_ON_JOB_CLOSE) failed",
        ))
    }
}

fn attribute_list(
    handles: &[HANDLE; 0],
) -> Result<
    (
        LPPROC_THREAD_ATTRIBUTE_LIST,
        [usize; MAX_ATTRIBUTE_BYTES / size_of::<usize>()],
    ),
    SupervisionError,
> {
    let mut bytes = 0usize;
    // SAFETY: the first call intentionally probes the required fixed buffer
    // size with a null list and valid size pointer.
    let _ = unsafe { InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut bytes) };
    if bytes == 0 || bytes > MAX_ATTRIBUTE_BYTES {
        return Err(SupervisionError::new(
            ErrorCode::Configuration,
            ErrorCategory::Setup,
            false,
            "Windows attribute-list size exceeded the fixed bound",
        ));
    }
    let mut storage = [0usize; MAX_ATTRIBUTE_BYTES / size_of::<usize>()];
    let list = storage.as_mut_ptr().cast::<c_void>();
    // SAFETY: storage is fixed, aligned to usize, and large enough for the
    // size returned by the probe; the list remains live through process create.
    let initialized = unsafe { InitializeProcThreadAttributeList(list, 1, 0, &mut bytes) } != 0;
    if !initialized {
        return Err(last_error(
            ErrorCode::Configuration,
            ErrorCategory::Setup,
            "InitializeProcThreadAttributeList failed",
        ));
    }
    // An empty allowlist is explicit: no inherited handles are permitted.
    // SAFETY: the empty list has no elements and is paired with a zero byte
    // size; no pointer is dereferenced by this call's value argument.
    let updated = unsafe {
        UpdateProcThreadAttribute(
            list,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            handles.as_ptr().cast::<c_void>(),
            0,
            null_mut(),
            null(),
        )
    } != 0;
    if !updated {
        // SAFETY: the list was initialized above and is still exclusively held.
        unsafe { DeleteProcThreadAttributeList(list) };
        return Err(last_error(
            ErrorCode::Configuration,
            ErrorCategory::Setup,
            "UpdateProcThreadAttribute(handle allowlist) failed",
        ));
    }
    Ok((list, storage))
}

fn utf16_nul(value: &str) -> Result<Utf16Buffer, SupervisionError> {
    let mut result = Utf16Buffer::new();
    result.push_str(value)?;
    result.finish()
}

fn command_line(spec: &LaunchSpec) -> Result<Utf16Buffer, SupervisionError> {
    let mut text = Utf16Buffer::new();
    append_quoted(&mut text, spec.executable.as_str())?;
    for argument in spec.arguments.iter() {
        text.push_char(' ')?;
        append_quoted(&mut text, argument)?;
    }
    text.finish()
}

fn append_quoted(output: &mut Utf16Buffer, value: &str) -> Result<(), SupervisionError> {
    output.push_char('"')?;
    let mut backslashes = 0usize;
    for value in value.chars() {
        if value == '\\' {
            backslashes = backslashes.saturating_add(1);
            continue;
        }
        if value == '"' {
            push_backslashes(output, backslashes.saturating_mul(2).saturating_add(1))?;
        } else {
            push_backslashes(output, backslashes)?;
        }
        backslashes = 0;
        output.push_char(value)?;
    }
    push_backslashes(output, backslashes.saturating_mul(2))?;
    output.push_char('"')
}

fn push_backslashes(output: &mut Utf16Buffer, count: usize) -> Result<(), SupervisionError> {
    for _ in 0..count {
        output.push_char('\\')?;
    }
    Ok(())
}

fn environment_block(spec: &LaunchSpec) -> Result<Utf16Buffer, SupervisionError> {
    const MAX_ENVIRONMENT_ENTRIES: usize = 32;
    let mut entries: [Option<(&str, &str)>; MAX_ENVIRONMENT_ENTRIES] =
        [None; MAX_ENVIRONMENT_ENTRIES];
    let mut length = 0usize;
    for entry in spec.environment.iter() {
        if length == entries.len() {
            return Err(SupervisionError::new(
                ErrorCode::Configuration,
                ErrorCategory::Setup,
                false,
                "Windows environment entry bound exceeded",
            ));
        }
        entries[length] = Some(entry);
        length += 1;
    }
    entries[..length].sort_unstable_by(|left, right| {
        let Some(left) = left else {
            return Ordering::Equal;
        };
        let Some(right) = right else {
            return Ordering::Equal;
        };
        let left = left.0;
        let right = right.0;
        ascii_case_insensitive_cmp(left, right)
    });
    let mut block = Utf16Buffer::new();
    for (index, entry) in entries[..length].iter().enumerate() {
        if index != 0 {
            block.push_unit(0)?;
        }
        let Some((key, value)) = entry else {
            return Err(SupervisionError::new(
                ErrorCode::InvariantViolation,
                ErrorCategory::Internal,
                false,
                "Windows environment cell was unexpectedly empty",
            ));
        };
        block.push_str(key)?;
        block.push_char('=')?;
        block.push_str(value)?;
    }
    // The environment block is terminated by two NUL code units.  `finish`
    // appends the second one after the explicit entry-list terminator.
    block.push_unit(0)?;
    block.finish()
}

fn ascii_case_insensitive_cmp(left: &str, right: &str) -> Ordering {
    left.bytes()
        .map(|value| value.to_ascii_lowercase())
        .cmp(right.bytes().map(|value| value.to_ascii_lowercase()))
}

pub(crate) fn validate(
    root: &mut RootHandle,
    token: &mut Option<PlatformToken>,
    kind: PolicyKind,
) -> Result<(), SupervisionError> {
    if kind.requires_tree()
        && token
            .as_ref()
            .is_none_or(|token| !token.assigned || !token.resumed)
    {
        return Err(SupervisionError::new(
            ErrorCode::ContainmentLost,
            ErrorCategory::Containment,
            false,
            "Windows root was not assigned and resumed through the Job protocol",
        ));
    }
    if root.process.state == HandleState::Empty {
        return Err(SupervisionError::new(
            ErrorCode::HandoffFailed,
            ErrorCategory::Setup,
            false,
            "Windows exact process handle was not retained",
        ));
    }
    Ok(())
}

pub(crate) fn observe(root: &mut RootHandle) -> Result<RootObservation, SupervisionError> {
    if root.reaped {
        return root.exit.map(RootObservation::Waitable).ok_or_else(|| {
            SupervisionError::new(
                ErrorCode::InvariantViolation,
                ErrorCategory::Internal,
                false,
                "reaped Windows root has no cached exit status",
            )
        });
    }
    if !root.process.is_owned() {
        return Err(SupervisionError::new(
            ErrorCode::HandoffFailed,
            ErrorCategory::Setup,
            false,
            "Windows exact process handle is not available for observation",
        ));
    }
    // SAFETY: the process handle is the exact retained PROCESS_INFORMATION
    // value and remains owned by this service-thread slot.
    let result = unsafe { WaitForSingleObject(root.process.process_handle(), 0) };
    match result {
        WAIT_OBJECT_0 => {
            let info = exit_code(root.process.process_handle())?;
            root.exit = Some(info);
            Ok(RootObservation::Waitable(info))
        }
        WAIT_TIMEOUT => Ok(RootObservation::Live),
        WAIT_FAILED => Err(last_error(
            ErrorCode::WaitFailed,
            ErrorCategory::Reaping,
            "WaitForSingleObject observation failed",
        )),
        _ => Err(SupervisionError::new(
            ErrorCode::WaitFailed,
            ErrorCategory::Reaping,
            true,
            "WaitForSingleObject returned an unrecognized status",
        )),
    }
}

pub(crate) fn root_exit(root: &RootHandle) -> Option<ExitInfo> {
    root.exit
}

pub(crate) fn cleanup(
    root: &mut RootHandle,
    token: &mut Option<PlatformToken>,
    kind: PolicyKind,
    deadline: Instant,
) -> CleanupAttempt {
    match observe(root) {
        Ok(RootObservation::Waitable(_)) => return reap_and_close(root, token, deadline),
        Ok(RootObservation::Live) => {}
        Err(error) => return CleanupAttempt::retained(error),
    }
    let terminated = if kind.requires_tree() {
        if let Some(token_value) = token.as_ref()
            && token_value.assigned
        {
            // SAFETY: the Job handle is the unnamed Job assigned before
            // resume; no PID or rediscovered handle is involved.
            (unsafe { TerminateJobObject(token_value.job.handle(), 1) }) != 0
        } else {
            // Containment setup may have failed after the exact root was
            // created but before Job assignment.  The exact process handle is
            // still a safe fallback; the caller's tree diagnostic is retained
            // separately by the slot state machine.
            // SAFETY: the process handle is the exact PROCESS_INFORMATION
            // handle retained in this slot.
            (unsafe {
                windows_sys::Win32::System::Threading::TerminateProcess(root.process.handle(), 1)
            }) != 0
        }
    } else {
        // SAFETY: exact process handle retained in the slot; this is the only
        // exact-child termination target on Windows.
        (unsafe {
            windows_sys::Win32::System::Threading::TerminateProcess(root.process.handle(), 1)
        }) != 0
    };
    if !terminated {
        return CleanupAttempt::retained(last_error(
            if kind.requires_tree() {
                ErrorCode::JobTerminationFailed
            } else {
                ErrorCode::ExactChildSignalFailed
            },
            ErrorCategory::Reaping,
            "Windows termination API failed",
        ));
    }
    reap_and_close(root, token, deadline)
}

pub(crate) fn close_token(token: &mut PlatformToken) -> Result<(), SupervisionError> {
    if token.thread.state == HandleState::OutcomeUnknown
        || token.job.state == HandleState::OutcomeUnknown
    {
        return Err(SupervisionError::new(
            ErrorCode::HandleStateUnknown,
            ErrorCategory::Cleanup,
            false,
            "Windows Job/token close outcome is unknown; ownership remains quarantined",
        ));
    }
    let mut first = None;
    if token.thread.is_owned()
        && let Err(error) = token.thread.close()
    {
        first = Some(error);
    }
    if first.is_none()
        && token.job.is_owned()
        && let Err(error) = token.job.close()
    {
        first = Some(error);
    }
    first.map_or(Ok(()), Err)
}

pub(crate) fn close_root(root: &mut RootHandle) -> Result<(), SupervisionError> {
    root.process.close()
}

fn reap_and_close(
    root: &mut RootHandle,
    token: &mut Option<PlatformToken>,
    deadline: Instant,
) -> CleanupAttempt {
    let remaining = deadline.saturating_duration_since(Instant::now());
    let millis = u32::try_from(remaining.as_millis()).unwrap_or(u32::MAX);
    // SAFETY: exact retained process handle; bounded timeout derived from one
    // absolute deadline and never infinite.
    let waited = unsafe { WaitForSingleObject(root.process.process_handle(), millis) };
    if waited != WAIT_OBJECT_0 {
        return CleanupAttempt::retained(if waited == WAIT_TIMEOUT {
            SupervisionError::cleanup(ErrorCode::CleanupTimedOut, "Windows root wait timed out")
        } else {
            last_error(
                ErrorCode::WaitFailed,
                ErrorCategory::Reaping,
                "Windows root wait failed",
            )
        });
    }
    let exit = match exit_code(root.process.process_handle()) {
        Ok(exit) => exit,
        Err(error) => return CleanupAttempt::retained(error),
    };
    root.exit = Some(exit);
    root.reaped = true;
    if let Some(token) = token.as_mut()
        && token.assigned
        && let Err(error) = ensure_job_empty(token)
    {
        return CleanupAttempt::retained(error);
    }
    if let Some(token) = token.as_mut()
        && let Err(error) = close_token(token)
    {
        return CleanupAttempt::retained(error);
    }
    if let Err(error) = close_root(root) {
        return CleanupAttempt::retained(error);
    }
    CleanupAttempt {
        state: CleanupState::Reaped,
        error: None,
    }
}

fn ensure_job_empty(token: &WindowsJobToken) -> Result<(), SupervisionError> {
    let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
    let mut returned = 0u32;
    // SAFETY: `accounting` is initialized writable storage of the exact
    // documented class size; the Job handle is the retained service-thread
    // token and the returned byte count is bounded to that structure.
    let queried = unsafe {
        QueryInformationJobObject(
            token.job.handle(),
            JobObjectBasicAccountingInformation,
            (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast::<c_void>(),
            size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
            &mut returned,
        )
    } != 0;
    if !queried {
        return Err(last_error(
            ErrorCode::WaitFailed,
            ErrorCategory::Reaping,
            "QueryInformationJobObject failed while proving Job drain",
        ));
    }
    if returned < size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32 {
        return Err(SupervisionError::new(
            ErrorCode::WaitFailed,
            ErrorCategory::Reaping,
            false,
            "Job accounting response was truncated",
        ));
    }
    if accounting.ActiveProcesses != 0 {
        return Err(SupervisionError::cleanup(
            ErrorCode::CleanupTimedOut,
            "Windows Job still reports active processes after root wait",
        ));
    }
    Ok(())
}

fn exit_code(handle: HANDLE) -> Result<ExitInfo, SupervisionError> {
    let mut code = 0u32;
    // SAFETY: `handle` is an owned process handle and `code` is initialized
    // writable storage for the API's documented output.
    let ok = unsafe { GetExitCodeProcess(handle, &mut code) } != 0;
    if ok {
        Ok(ExitInfo {
            code: code as i32,
            // GetExitCodeProcess exposes the exit value, not the terminating
            // signal distinction used by Unix wait status.  A waitable root
            // has a stable exit value; do not infer a false signal bit from
            // an ordinary non-259 exit code.
            signaled: false,
        })
    } else {
        Err(last_error(
            ErrorCode::WaitFailed,
            ErrorCategory::Reaping,
            "GetExitCodeProcess failed",
        ))
    }
}

impl OwnedHandle {
    fn process_handle(&self) -> HANDLE {
        self.handle()
    }
}

fn last_error(code: ErrorCode, category: ErrorCategory, context: &str) -> SupervisionError {
    SupervisionError::new(code, category, true, context).with_os_error(unsafe {
        // SAFETY: GetLastError is thread-local and has no pointer/ownership
        // precondition; this call only copies its bounded numeric value.
        GetLastError()
    } as i32)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn close_failure_never_clears_owned_raw_value() {
        let mut handle = OwnedHandle {
            raw: 7,
            state: HandleState::Owned,
        };
        assert!(handle.close_probe(CloseProbe::KnownFailure).is_err());
        assert_eq!(handle.raw, 7);
        assert_eq!(handle.state, HandleState::Owned);
        assert!(handle.close_probe(CloseProbe::Success).is_ok());
        assert_eq!(handle.raw, 0);
        assert_eq!(handle.state, HandleState::Closed);
    }

    #[test]
    fn unknown_close_outcome_is_terminal_and_retains_token() {
        let mut handle = OwnedHandle {
            raw: 9,
            state: HandleState::Owned,
        };
        assert_eq!(
            handle
                .close_probe(CloseProbe::Unknown)
                .expect_err("unknown close")
                .code(),
            ErrorCode::HandleStateUnknown
        );
        assert_eq!(handle.raw, 9);
        assert_eq!(handle.state, HandleState::OutcomeUnknown);
        assert!(handle.close_probe(CloseProbe::Success).is_err());
    }

    #[test]
    fn runtime_evidence_gate_is_fail_closed() {
        assert!(!runtime_evidence_accepted());
    }
}
