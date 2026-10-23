//! Vaultly application shell.
//!
//! Startup order matters: the process hardens itself (crash reporting, DLL
//! search path, mitigation policies, debugger check) *before* the vault is
//! touched, then the session watcher and auto-lock timer are armed, and only
//! then does the frontend get a window.

#![deny(unsafe_code)]

pub mod backoff;
pub mod commands;
pub mod platform_windows;
pub mod settings;
pub mod state;

use std::sync::Mutex;
use std::time::{Duration, Instant};

use tauri::{AppHandle, Emitter, Manager};
use vaultly_core::crypto::keys::install_page_locker;

use crate::backoff::Backoff;
use crate::platform_windows::files::VaultPaths;
use crate::platform_windows::mitigations;
use crate::platform_windows::session::{self, SessionEvent};
use crate::platform_windows::{acl, capture, process, singleton, webview};
use crate::state::{AppState, Session};

/// How often the auto-lock timer checks for inactivity.
const AUTO_LOCK_TICK: Duration = Duration::from_secs(5);

fn panic_hook() {
    // A panic message could contain a path or a slice of data. Print one fixed
    // line, then abort so no unwinding leaves partially wiped keys behind.
    let _ = std::io::Write::write_all(
        &mut std::io::stderr(),
        b"vaultly: unrecoverable internal error\n",
    );
    std::process::abort();
}

fn lock_now(app: &AppHandle) {
    let state = app.state::<AppState>();
    let Ok(mut session) = state.session.lock() else {
        return;
    };
    if !matches!(&*session, Session::Unlocked { .. }) {
        return;
    }
    // Dropping the session drops the Vault, which zeroizes the root key and the
    // decrypted index. Nothing needs to be written: every mutation is persisted
    // before the command returns.
    *session = if state.paths.vault.exists() {
        Session::Locked
    } else {
        Session::NoVault
    };
    drop(session);
    let _ = app.emit("vault-locked", ());
}

fn start_auto_lock(app: &AppHandle) {
    let handle = app.clone();
    std::thread::Builder::new()
        .name("vaultly-autolock".into())
        .spawn(move || loop {
            std::thread::sleep(AUTO_LOCK_TICK);
            let state = handle.state::<AppState>();
            let minutes = state
                .settings
                .lock()
                .map(|settings| settings.auto_lock_minutes)
                .unwrap_or(5)
                .max(1) as u64;
            let expired = {
                let Ok(session) = state.session.lock() else {
                    continue;
                };
                match &*session {
                    Session::Unlocked { last_active, .. } => {
                        last_active.elapsed() >= Duration::from_secs(minutes * 60)
                    }
                    _ => false,
                }
            };
            if expired {
                lock_now(&handle);
            }
        })
        .ok();
}

fn start_session_watcher(app: &AppHandle) {
    let handle = app.clone();
    let started = session::start(move |event| {
        let should_lock = {
            let state = handle.state::<AppState>();
            state
                .settings
                .lock()
                .map(|settings| settings.lock_on_session_events)
                .unwrap_or(true)
        };
        match event {
            // Suspension always locks: a sleeping machine is an unattended one.
            SessionEvent::Suspend | SessionEvent::Shutdown => lock_now(&handle),
            _ if should_lock => lock_now(&handle),
            _ => {}
        }
    });
    if let Err(error) = started {
        eprintln!("vaultly: session watcher unavailable ({error})");
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    std::panic::set_hook(Box::new(|_| panic_hook()));

    // Fail closed and early: no elevation, ever, unless the manifest is wrong.
    if process::is_elevated() {
        process::fatal_dialog(
            "Vaultly",
            "Vaultly must not run elevated. Close this instance and start it normally.",
        );
        std::process::exit(1);
    }

    process::suppress_crash_reporting();
    if let Err(error) = process::harden_dll_search() {
        eprintln!("vaultly: DLL search hardening failed ({error})");
    }

    let report = mitigations::apply(cfg!(not(debug_assertions)));
    let debugger_detected = cfg!(not(debug_assertions)) && process::debugger_present();
    let remote_session = process::is_remote_session();

    // Page-lock every key buffer the crypto layer allocates.
    let _ = install_page_locker(Box::new(platform_windows::memory::WindowsPageLocker));

    let paths = match VaultPaths::discover() {
        Ok(paths) => paths,
        Err(error) => {
            process::fatal_dialog("Vaultly", &format!("Cannot locate %LOCALAPPDATA%: {error}"));
            std::process::exit(1);
        }
    };

    if let Err(error) = acl::ensure_private_directory(&paths.directory) {
        process::fatal_dialog(
            "Vaultly",
            &format!("Cannot secure the vault directory: {error}"),
        );
        std::process::exit(1);
    }
    let acl_ok = acl::verify_private(&paths.directory).unwrap_or(false);
    if !acl_ok {
        process::fatal_dialog(
            "Vaultly",
            "The vault directory permissions were changed and could not be restored.",
        );
        std::process::exit(1);
    }

    let settings = settings::load(&paths.settings);
    let backoff = Backoff::load(&paths.lockout, &paths.device_key);
    let has_vault = paths.vault.exists();

    let state = AppState {
        session: Mutex::new(if has_vault {
            Session::Locked
        } else {
            Session::NoVault
        }),
        settings: Mutex::new(settings),
        backoff: Mutex::new(backoff),
        paths,
        mitigations: report,
        remote_session,
        debugger_detected,
        acl_ok,
        elevated: false,
    };

    // Single instance: a second launch only restores the first window and
    // exits. There is no command channel between instances.
    match singleton::acquire() {
        Ok(Some(guard)) => {
            // The mutex must live for the whole process. Leaking the handle is
            // intentional; the OS releases it at exit.
            std::mem::forget(guard);
        }
        Ok(None) => {
            singleton::focus_running_instance();
            return;
        }
        Err(error) => {
            eprintln!("vaultly: single-instance mutex unavailable ({error})");
        }
    }

    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            commands::get_status,
            commands::create_vault,
            commands::unlock,
            commands::unlock_with_recovery,
            commands::lock,
            commands::list_entries,
            commands::search_entries,
            commands::reveal_field,
            commands::get_entry_for_edit,
            commands::copy_field,
            commands::copy_text,
            commands::create_entry,
            commands::update_entry,
            commands::delete_entry,
            commands::restore_entry,
            commands::empty_trash,
            commands::entry_history,
            commands::restore_revision,
            commands::generate_password,
            commands::totp_code,
            commands::health_report,
            commands::verify_master_password,
            commands::change_master_password,
            commands::preview_import,
            commands::import_csv,
            commands::export_backup,
            commands::export_csv,
            commands::get_settings,
            commands::update_settings,
            commands::hello_status,
        ])
        .setup(|app| {
            let handle = app.handle().clone();
            if let Some(window) = app.get_webview_window("main") {
                let capture_on = handle
                    .state::<AppState>()
                    .settings
                    .lock()
                    .map(|settings| settings.capture_protection)
                    .unwrap_or(true);
                if let Err(error) = webview::harden(&window) {
                    eprintln!("vaultly: webview hardening failed ({error})");
                }
                if let Err(error) = capture::set_excluded_for(&window, capture_on) {
                    eprintln!("vaultly: capture exclusion failed ({error})");
                }
            }
            start_session_watcher(&handle);
            start_auto_lock(&handle);
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                // Leaving the window hides nothing: lock before teardown so a
                // crash during shutdown cannot leave keys in a heap dump.
                lock_now(window.app_handle());
            }
        });

    if let Err(error) = builder.run(tauri::generate_context!()) {
        eprintln!("vaultly: startup failed ({error})");
        std::process::exit(1);
    }
}

/// Timestamp helper shared by the shell (kept here so tests can reason about it).
#[allow(dead_code)]
fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

/// Duration since the session was last touched, for diagnostics.
#[allow(dead_code)]
fn idle_for(session: &Session) -> Option<Duration> {
    match session {
        Session::Unlocked { last_active, .. } => Some(Instant::now().saturating_duration_since(*last_active)),
        _ => None,
    }
}
