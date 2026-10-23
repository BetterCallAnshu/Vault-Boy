//! Screen-capture exclusion via `SetWindowDisplayAffinity`.
//!
//! `WDA_EXCLUDEFROMCAPTURE` is honoured by Windows 10 2004+ for most capture
//! APIs, but not by every third-party capturer and not by a camera pointed at
//! the screen. It is a speed bump, not a guarantee.

use tauri::WebviewWindow;
use windows::Win32::Foundation::HWND;
use windows::Win32::UI::WindowsAndMessaging::{
    SetWindowDisplayAffinity, WDA_EXCLUDEFROMCAPTURE, WDA_NONE,
};

use super::{PlatformError, PlatformResult};

/// Apply or clear capture exclusion on a window.
pub fn set_excluded_for(window: &WebviewWindow, enabled: bool) -> PlatformResult<bool> {
    let hwnd = window
        .hwnd()
        .map_err(|_| PlatformError::with_code("hwnd", 0))?;
    let hwnd = HWND(hwnd.0);
    let affinity = if enabled { WDA_EXCLUDEFROMCAPTURE } else { WDA_NONE };
    // SAFETY: hwnd belongs to this process's window, which Tauri keeps alive
    // for the duration of the call.
    unsafe { SetWindowDisplayAffinity(hwnd, affinity) }
        .map_err(|_| PlatformError::new("SetWindowDisplayAffinity"))?;
    Ok(enabled)
}
