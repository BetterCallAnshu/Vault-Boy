//! WebView2 hardening.
//!
//! Tauri's configuration already disables DevTools and sets a strict CSP. These
//! settings go further and turn off the browser features a password manager
//! never needs: context menus, status bar, accelerator keys, password saving,
//! autofill and zoom controls.

use tauri::WebviewWindow;
use webview2_com::Microsoft::Web::WebView2::Win32::{
    ICoreWebView2Settings3, ICoreWebView2Settings4,
};
use windows::core::Interface;

/// Apply release hardening to the WebView2 settings.
pub fn harden(window: &WebviewWindow) -> tauri::Result<()> {
    window.with_webview(|webview| {
        // SAFETY: `with_webview` invokes this closure on the UI thread with a
        // live controller; the COM calls below do not retain pointers.
        unsafe {
            let controller = webview.controller();
            let Ok(core) = controller.CoreWebView2() else {
                return;
            };
            let Ok(settings) = core.Settings() else {
                return;
            };
            let _ = settings.SetAreDevToolsEnabled(false);
            let _ = settings.SetAreDefaultContextMenusEnabled(false);
            let _ = settings.SetAreDefaultScriptDialogsEnabled(false);
            let _ = settings.SetIsStatusBarEnabled(false);
            let _ = settings.SetIsZoomControlEnabled(false);
            // Frames that arrived in later WebView2 interface revisions.
            if let Ok(settings3) = settings.cast::<ICoreWebView2Settings3>() {
                let _ = settings3.SetAreBrowserAcceleratorKeysEnabled(false);
            }
            if let Ok(settings4) = settings.cast::<ICoreWebView2Settings4>() {
                let _ = settings4.SetIsPasswordAutosaveEnabled(false);
                let _ = settings4.SetIsGeneralAutofillEnabled(false);
            }
        }
    })
}
