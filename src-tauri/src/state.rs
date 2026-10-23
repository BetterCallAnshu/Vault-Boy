//! Shared application state.

use std::sync::Mutex;
use std::time::Instant;

use serde::Serialize;
use vaultly_core::Vault;

use crate::backoff::Backoff;
use crate::platform_windows::files::VaultPaths;
use crate::platform_windows::mitigations::MitigationReport;
use crate::settings::Settings;

/// `NoVault` and `Locked` hold no key material at all.
pub enum Session {
    NoVault,
    Locked,
    Unlocked {
        // Boxed: the unlocked variant is far larger than the others and the
        // whole enum lives behind one mutex.
        vault: Box<Vault>,
        last_active: Instant,
    },
}

pub struct AppState {
    pub session: Mutex<Session>,
    pub paths: VaultPaths,
    pub settings: Mutex<Settings>,
    pub backoff: Mutex<Backoff>,
    pub mitigations: MitigationReport,
    pub remote_session: bool,
    pub debugger_detected: bool,
    pub acl_ok: bool,
    pub elevated: bool,
}

/// Everything the UI needs before it knows whether a vault exists.
#[derive(Debug, Serialize)]
pub struct Status {
    pub has_vault: bool,
    pub locked: bool,
    pub auto_lock_minutes: u32,
    pub capture_protection: bool,
    pub clipboard_clear_seconds: u32,
    pub theme: String,
    pub lock_on_session_events: bool,
    pub remote_session: bool,
    pub debugger_detected: bool,
    pub acl_ok: bool,
    pub elevated: bool,
    pub mitigations: MitigationReport,
    pub hello_available: bool,
    pub rate_limited_ms: u64,
    pub backoff_tampered: bool,
}
