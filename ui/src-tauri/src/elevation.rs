//! Cross-platform "am I running elevated / as root?" check.
//!
//! Windows: query the process token for ``TOKEN_ELEVATION`` via
//! ``GetTokenInformation``. Returns false on any API failure rather than
//! erroring upward — the UI just renders the banner.
//!
//! Non-Windows: always returns true. Live ``\\.\PhysicalDrive`` collection
//! is Windows-only in Phase 1, and there's no equivalent gate on dev
//! macOS/Linux runs.

#[cfg(windows)]
pub fn is_elevated() -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let process = GetCurrentProcess();
        let mut token = Default::default();
        if OpenProcessToken(process, TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned_len: u32 = 0;
        let result = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned_len,
        );
        let _ = CloseHandle(token);
        result.is_ok() && elevation.TokenIsElevated != 0
    }
}

#[cfg(not(windows))]
pub fn is_elevated() -> bool {
    true
}
