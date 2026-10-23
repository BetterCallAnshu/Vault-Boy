//! Windows platform layer.
//!
//! Every `unsafe` block in Vaultly lives under this module, each with a
//! `// SAFETY:` justification. Everything else is compiled with
//! `#![deny(unsafe_code)]` at the crate root.
#![allow(unsafe_code)]

pub mod acl;
pub mod capture;
pub mod clipboard;
pub mod dpapi;
pub mod files;
pub mod memory;
pub mod mitigations;
pub mod process;
pub mod session;
pub mod singleton;
pub mod webview;

use std::fmt;

/// A platform failure with a stable, non-sensitive message for the UI.
#[derive(Debug)]
pub struct PlatformError {
    pub operation: &'static str,
    pub code: u32,
}

impl PlatformError {
    pub fn new(operation: &'static str) -> Self {
        let code = unsafe {
            // SAFETY: GetLastError takes no arguments and has no preconditions.
            windows::Win32::Foundation::GetLastError().0
        };
        PlatformError { operation, code }
    }

    pub fn with_code(operation: &'static str, code: u32) -> Self {
        PlatformError { operation, code }
    }
}

impl fmt::Display for PlatformError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} failed (win32 error {})", self.operation, self.code)
    }
}

impl std::error::Error for PlatformError {}

impl From<PlatformError> for std::io::Error {
    fn from(error: PlatformError) -> Self {
        std::io::Error::other(error.to_string())
    }
}

pub type PlatformResult<T> = Result<T, PlatformError>;
