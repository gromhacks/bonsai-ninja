//! Portable advisory-lock error classification.
//!
//! `fs2` delegates to the host lock API. Unix maps lock contention to
//! [`std::io::ErrorKind::WouldBlock`], while Windows currently exposes
//! `ERROR_LOCK_VIOLATION` as [`std::io::ErrorKind::Uncategorized`]. Cache
//! ownership code needs one portable result so contention remains an expected
//! retry/skip condition on every supported host.

/// Normalize a non-blocking advisory-lock error across supported hosts.
///
/// Errors unrelated to lock contention are returned unchanged.
#[must_use]
pub fn normalize_advisory_lock_error(error: std::io::Error) -> std::io::Error {
    if error.kind() == std::io::ErrorKind::WouldBlock {
        return error;
    }

    #[cfg(windows)]
    {
        // Win32 ERROR_LOCK_VIOLATION. Rust 1.88 classifies this as
        // Uncategorized even though it is the direct equivalent of EWOULDBLOCK
        // for a failed LockFileEx(LOCKFILE_FAIL_IMMEDIATELY) request.
        const ERROR_LOCK_VIOLATION: i32 = 33;
        if error.raw_os_error() == Some(ERROR_LOCK_VIOLATION) {
            return std::io::Error::new(std::io::ErrorKind::WouldBlock, error);
        }
    }

    error
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn would_block_is_preserved() {
        let normalized = normalize_advisory_lock_error(std::io::Error::from(std::io::ErrorKind::WouldBlock));
        assert_eq!(normalized.kind(), std::io::ErrorKind::WouldBlock);
    }

    #[cfg(windows)]
    #[test]
    fn windows_lock_violation_is_would_block() {
        let normalized = normalize_advisory_lock_error(std::io::Error::from_raw_os_error(33));
        assert_eq!(normalized.kind(), std::io::ErrorKind::WouldBlock);
    }
}
