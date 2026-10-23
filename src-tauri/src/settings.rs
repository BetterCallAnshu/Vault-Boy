//! Non-secret application settings.
//!
//! Nothing here is sensitive: auto-lock timing, capture protection, clipboard
//! clear delay and theme. Stored as JSON next to the vault.

use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Inactivity minutes before the vault locks itself.
    pub auto_lock_minutes: u32,
    /// `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` on the main window.
    pub capture_protection: bool,
    /// Seconds before a copied secret is cleared (only if unchanged).
    pub clipboard_clear_seconds: u32,
    /// "system" | "light" | "dark"
    pub theme: String,
    /// Lock when the Windows session locks or the machine suspends.
    pub lock_on_session_events: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            auto_lock_minutes: 5,
            capture_protection: true,
            clipboard_clear_seconds: 20,
            theme: "system".to_string(),
            lock_on_session_events: true,
        }
    }
}

impl Settings {
    pub fn sanitize(&mut self) {
        self.auto_lock_minutes = self.auto_lock_minutes.clamp(1, 120);
        self.clipboard_clear_seconds = self.clipboard_clear_seconds.clamp(5, 120);
        if !matches!(self.theme.as_str(), "system" | "light" | "dark") {
            self.theme = "system".to_string();
        }
    }
}

pub fn load(path: &Path) -> Settings {
    let Ok(bytes) = std::fs::read(path) else {
        return Settings::default();
    };
    let mut settings: Settings = serde_json::from_slice(&bytes).unwrap_or_default();
    settings.sanitize();
    settings
}

pub fn save(path: &Path, settings: &Settings) -> std::io::Result<()> {
    let bytes = serde_json::to_vec_pretty(settings)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    crate::platform_windows::files::atomic_write(path, &bytes)
        .map_err(std::io::Error::from)
}
