//! Process exit codes, following BSD sysexits(3) where one applies.

use spectranet_capture::CaptureError;

pub const SUCCESS: i32 = 0;
pub const FAILURE: i32 = 1;
pub const USAGE: i32 = 2;
/// EX_UNAVAILABLE: live capture is not supported on this platform.
pub const UNAVAILABLE: i32 = 69;
/// EX_NOPERM: the capture backend lacks the privileges it needs.
pub const NOPERM: i32 = 77;

/// Exit codes and their meaning, rendered into the man pages.
pub const DOCUMENTED: [(i32, &str); 5] = [
    (SUCCESS, "Success."),
    (FAILURE, "An unexpected error occurred."),
    (USAGE, "Invalid command-line arguments."),
    (
        UNAVAILABLE,
        "Live capture is not available on this platform, or a command needs snetd and it is not running.",
    ),
    (NOPERM, "Insufficient privileges for live capture."),
];

/// Picks the exit code for an error returned by a command.
pub fn code_for(err: &anyhow::Error) -> i32 {
    if err.downcast_ref::<crate::daemon::Unavailable>().is_some() {
        return UNAVAILABLE;
    }
    match err.downcast_ref::<CaptureError>() {
        Some(CaptureError::Unsupported) => UNAVAILABLE,
        Some(CaptureError::PermissionDenied(_)) => NOPERM,
        _ => FAILURE,
    }
}
