//! Tauri IPC commands.
//!
//! Every command validates its arguments, operates on at most one entry's
//! secrets, and returns a typed error with a stable code. No command exposes
//! the vault root key or the on-disk ciphertext.

use std::path::PathBuf;
use std::sync::MutexGuard;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use uuid::Uuid;
use vaultly_core::crypto::kdf::calibrate;
use vaultly_core::vault::csvio;
use vaultly_core::vault::generator::{self, GeneratorOptions, GeneratedSecret};
use vaultly_core::vault::health::HealthReport;
use vaultly_core::vault::totp::TotpCode;
use vaultly_core::{
    CreateOptions, EntryDraft, EntryMeta, EntryPatch, EntrySecrets, SecretField, Vault, VaultError,
};
use zeroize::Zeroizing;

use crate::platform_windows::{acl, clipboard, files, PlatformError};
use crate::settings::Settings;
use crate::state::{AppState, Session, Status};

/// A stable, non-sensitive error shape for the UI.
#[derive(Debug, Serialize)]
pub struct ApiError {
    pub code: &'static str,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

impl ApiError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        ApiError {
            code,
            message: message.into(),
            retry_after_ms: None,
        }
    }

    fn rate_limited(wait_ms: u64) -> Self {
        ApiError {
            code: "rate_limited",
            message: "Too many failed attempts. Wait before trying again.".to_string(),
            retry_after_ms: Some(wait_ms),
        }
    }

    fn locked() -> Self {
        ApiError::new("locked", "The vault is locked.")
    }
}

impl From<VaultError> for ApiError {
    fn from(error: VaultError) -> Self {
        let code = match error {
            VaultError::InvalidPassword => "invalid_password",
            VaultError::NotFound => "not_found",
            VaultError::InvalidInput => "invalid_input",
            VaultError::Corrupt => "corrupt",
            VaultError::UnsupportedVersion(_) | VaultError::BadMagic => "unsupported_vault",
            VaultError::Crypto => "crypto_error",
            VaultError::Csv => "invalid_csv",
            VaultError::Unsupported => "unsupported",
        };
        ApiError::new(code, error.to_string())
    }
}

impl From<PlatformError> for ApiError {
    fn from(error: PlatformError) -> Self {
        ApiError::new(
            "platform_error",
            format!("{} failed (win32 {})", error.operation, error.code),
        )
    }
}

impl From<std::io::Error> for ApiError {
    fn from(_: std::io::Error) -> Self {
        ApiError::new("io_error", "A file operation failed.")
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

fn parse_id(id: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(id).map_err(|_| ApiError::new("invalid_input", "Invalid entry id."))
}

fn session_guard(state: &AppState) -> Result<MutexGuard<'_, Session>, ApiError> {
    state
        .session
        .lock()
        .map_err(|_| ApiError::new("internal", "State unavailable."))
}

fn with_vault<T>(
    state: &AppState,
    action: impl FnOnce(&mut Vault) -> Result<T, VaultError>,
) -> Result<T, ApiError> {
    let mut session = session_guard(state)?;
    match &mut *session {
        Session::Unlocked { vault, last_active } => {
            *last_active = Instant::now();
            action(vault).map_err(ApiError::from)
        }
        _ => Err(ApiError::locked()),
    }
}

fn persist(state: &AppState, vault: &Vault) -> Result<(), ApiError> {
    let bytes = vault.to_bytes()?;
    files::atomic_write(&state.paths.vault, &bytes)?;
    acl::apply_private_file(&state.paths.vault)?;
    Ok(())
}

fn with_vault_persist<T>(
    state: &AppState,
    action: impl FnOnce(&mut Vault) -> Result<T, VaultError>,
) -> Result<T, ApiError> {
    let mut session = session_guard(state)?;
    match &mut *session {
        Session::Unlocked { vault, last_active } => {
            *last_active = Instant::now();
            let result = action(vault).map_err(ApiError::from)?;
            let bytes = vault.to_bytes()?;
            drop(session);
            files::atomic_write(&state.paths.vault, &bytes)?;
            acl::apply_private_file(&state.paths.vault)?;
            Ok(result)
        }
        _ => Err(ApiError::locked()),
    }
}

// ---------------------------------------------------------------- lifecycle

#[tauri::command]
pub fn get_status(state: State<'_, AppState>) -> Result<Status, ApiError> {
    let settings = state
        .settings
        .lock()
        .map_err(|_| ApiError::new("internal", "State unavailable."))?
        .clone();
    let (locked, has_vault) = {
        let session = session_guard(&state)?;
        (
            matches!(&*session, Session::Locked | Session::NoVault),
            state.paths.vault.exists(),
        )
    };
    let backoff = state
        .backoff
        .lock()
        .map_err(|_| ApiError::new("internal", "State unavailable."))?;

    Ok(Status {
        has_vault,
        locked,
        auto_lock_minutes: settings.auto_lock_minutes,
        capture_protection: settings.capture_protection,
        clipboard_clear_seconds: settings.clipboard_clear_seconds,
        theme: settings.theme,
        lock_on_session_events: settings.lock_on_session_events,
        remote_session: state.remote_session,
        debugger_detected: state.debugger_detected,
        acl_ok: state.acl_ok,
        elevated: state.elevated,
        mitigations: state.mitigations,
        hello_available: false,
        rate_limited_ms: backoff.remaining_ms(now_ms()),
        backoff_tampered: backoff.is_tampered(),
    })
}

#[tauri::command]
pub fn create_vault(
    state: State<'_, AppState>,
    app: AppHandle,
    password: String,
    recovery: bool,
) -> Result<Option<String>, ApiError> {
    if state.paths.vault.exists() {
        return Err(ApiError::new("exists", "A vault already exists."));
    }
    let password = Zeroizing::new(password);
    let kdf = calibrate(Duration::from_millis(500));
    let created = Vault::create(
        password.as_bytes(),
        CreateOptions {
            kdf,
            recovery,
            now: now_ms(),
        },
    )?;
    let bytes = created.vault.to_bytes()?;
    acl::ensure_private_directory(&state.paths.directory)?;
    files::atomic_write(&state.paths.vault, &bytes)?;
    acl::apply_private_file(&state.paths.vault)?;

    *session_guard(&state)? = Session::Unlocked {
        vault: Box::new(created.vault),
        last_active: Instant::now(),
    };
    let _ = app.emit("vault-unlocked", ());
    Ok(created.recovery_key.map(|key| key.to_string()))
}

#[tauri::command]
pub fn unlock(
    state: State<'_, AppState>,
    app: AppHandle,
    password: String,
) -> Result<(), ApiError> {
    let now = now_ms();
    let password = Zeroizing::new(password);
    {
        let backoff = state
            .backoff
            .lock()
            .map_err(|_| ApiError::new("internal", "State unavailable."))?;
        let wait = backoff.remaining_ms(now);
        if wait > 0 {
            return Err(ApiError::rate_limited(wait));
        }
    }

    let bytes = files::read_limited(&state.paths.vault, 256 * 1024 * 1024)?;
    match Vault::unlock(&bytes, password.as_bytes()) {
        Ok(mut vault) => {
            let purged = vault.purge_expired(now);
            if purged > 0 {
                persist(&state, &vault)?;
            }
            state
                .backoff
                .lock()
                .map_err(|_| ApiError::new("internal", "State unavailable."))?
                .record_success();
            *session_guard(&state)? = Session::Unlocked {
                vault: Box::new(vault),
                last_active: Instant::now(),
            };
            let _ = app.emit("vault-unlocked", ());
            Ok(())
        }
        Err(VaultError::InvalidPassword) => {
            let mut backoff = state
                .backoff
                .lock()
                .map_err(|_| ApiError::new("internal", "State unavailable."))?;
            backoff.record_failure(now);
            Err(ApiError::rate_limited(backoff.remaining_ms(now)))
        }
        Err(error) => Err(error.into()),
    }
}

#[tauri::command]
pub fn unlock_with_recovery(
    state: State<'_, AppState>,
    app: AppHandle,
    recovery_key: String,
) -> Result<(), ApiError> {
    let key = Zeroizing::new(recovery_key);
    let bytes = files::read_limited(&state.paths.vault, 256 * 1024 * 1024)?;
    let vault = Vault::unlock_with_recovery(&bytes, &key)?;
    *session_guard(&state)? = Session::Unlocked {
        vault: Box::new(vault),
        last_active: Instant::now(),
    };
    let _ = app.emit("vault-unlocked", ());
    Ok(())
}

#[tauri::command]
pub fn lock(state: State<'_, AppState>, app: AppHandle) -> Result<(), ApiError> {
    let mut session = session_guard(&state)?;
    let was_unlocked = matches!(&*session, Session::Unlocked { .. });
    if was_unlocked {
        *session = if state.paths.vault.exists() {
            Session::Locked
        } else {
            Session::NoVault
        };
    }
    drop(session);
    if was_unlocked {
        let _ = app.emit("vault-locked", ());
    }
    Ok(())
}

// ------------------------------------------------------------------ entries

#[tauri::command]
pub fn list_entries(state: State<'_, AppState>) -> Result<Vec<EntryMeta>, ApiError> {
    with_vault(&state, |vault| Ok(vault.list().to_vec()))
}

#[tauri::command]
pub fn search_entries(state: State<'_, AppState>, query: String) -> Result<Vec<Uuid>, ApiError> {
    with_vault(&state, |vault| Ok(vault.search(&query)))
}

#[tauri::command]
pub fn reveal_field(
    state: State<'_, AppState>,
    id: String,
    field: SecretField,
) -> Result<String, ApiError> {
    let id = parse_id(&id)?;
    let value = with_vault(&state, |vault| {
        let secrets = vault.secrets(id)?;
        secrets
            .field(field)
            .map(str::to_string)
            .ok_or(VaultError::NotFound)
    })?;
    Ok(value)
}

#[tauri::command]
pub fn get_entry_for_edit(
    state: State<'_, AppState>,
    id: String,
) -> Result<EntrySecrets, ApiError> {
    let id = parse_id(&id)?;
    with_vault(&state, |vault| vault.secrets(id))
}

#[derive(Debug, Serialize)]
pub struct CopyResult {
    pub seconds: u32,
}

#[tauri::command]
pub fn copy_field(
    state: State<'_, AppState>,
    id: String,
    field: SecretField,
) -> Result<CopyResult, ApiError> {
    let id = parse_id(&id)?;
    let seconds = state
        .settings
        .lock()
        .map_err(|_| ApiError::new("internal", "State unavailable."))?
        .clipboard_clear_seconds;
    let value = Zeroizing::new(with_vault(&state, |vault| {
        let secrets = vault.secrets(id)?;
        secrets
            .field(field)
            .map(str::to_string)
            .ok_or(VaultError::NotFound)
    })?);

    let sequence = clipboard::copy_secret(&value)?;
    let clear_after = seconds;
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(clear_after as u64));
        let _ = clipboard::clear_if_sequence(sequence);
    });
    Ok(CopyResult { seconds })
}

/// Copy an arbitrary secret (a freshly generated password, a recovery key) with
/// the same clipboard protections and auto-clear as a vault field.
#[tauri::command]
pub fn copy_text(state: State<'_, AppState>, text: String) -> Result<CopyResult, ApiError> {
    if text.len() > 8192 {
        return Err(ApiError::new("invalid_input", "Value is too long to copy."));
    }
    let seconds = state
        .settings
        .lock()
        .map_err(|_| ApiError::new("internal", "State unavailable."))?
        .clipboard_clear_seconds;
    let value = Zeroizing::new(text);
    let sequence = clipboard::copy_secret(&value)?;
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(seconds as u64));
        let _ = clipboard::clear_if_sequence(sequence);
    });
    Ok(CopyResult { seconds })
}

#[tauri::command]
pub fn create_entry(
    state: State<'_, AppState>,
    draft: EntryDraft,
) -> Result<Uuid, ApiError> {
    with_vault_persist(&state, |vault| vault.create_entry(draft, now_ms()))
}

#[tauri::command]
pub fn update_entry(
    state: State<'_, AppState>,
    id: String,
    patch: EntryPatch,
) -> Result<(), ApiError> {
    let id = parse_id(&id)?;
    with_vault_persist(&state, |vault| vault.update_entry(id, patch, now_ms()))
}

#[tauri::command]
pub fn delete_entry(state: State<'_, AppState>, id: String) -> Result<(), ApiError> {
    let id = parse_id(&id)?;
    with_vault_persist(&state, |vault| vault.delete_entry(id, now_ms()))
}

#[tauri::command]
pub fn restore_entry(state: State<'_, AppState>, id: String) -> Result<(), ApiError> {
    let id = parse_id(&id)?;
    with_vault_persist(&state, |vault| vault.restore_entry(id, now_ms()))
}

#[tauri::command]
pub fn empty_trash(state: State<'_, AppState>) -> Result<usize, ApiError> {
    with_vault_persist(&state, |vault| Ok(vault.empty_trash()))
}

#[tauri::command]
pub fn entry_history(state: State<'_, AppState>, id: String) -> Result<Vec<i64>, ApiError> {
    let id = parse_id(&id)?;
    with_vault(&state, |vault| vault.history_timestamps(id))
}

#[tauri::command]
pub fn restore_revision(
    state: State<'_, AppState>,
    id: String,
    revision_index: usize,
) -> Result<(), ApiError> {
    let id = parse_id(&id)?;
    with_vault_persist(&state, |vault| {
        vault.restore_revision(id, revision_index, now_ms())
    })
}

// ------------------------------------------------------------------ features

#[tauri::command]
pub fn generate_password(options: GeneratorOptions) -> Result<GeneratedSecret, ApiError> {
    generator::generate(&options).map_err(ApiError::from)
}

#[tauri::command]
pub fn totp_code(state: State<'_, AppState>, id: String) -> Result<TotpCode, ApiError> {
    let id = parse_id(&id)?;
    with_vault(&state, |vault| vault.totp_code(id, now_ms()))
}

#[tauri::command]
pub fn health_report(state: State<'_, AppState>) -> Result<HealthReport, ApiError> {
    with_vault(&state, |vault| vault.health_report(now_ms()))
}

#[tauri::command]
pub fn verify_master_password(
    state: State<'_, AppState>,
    password: String,
) -> Result<bool, ApiError> {
    let password = Zeroizing::new(password);
    with_vault(&state, |vault| Ok(vault.verify_password(password.as_bytes())))
}

#[tauri::command]
pub fn change_master_password(
    state: State<'_, AppState>,
    current_password: String,
    new_password: String,
) -> Result<(), ApiError> {
    let current = Zeroizing::new(current_password);
    let new = Zeroizing::new(new_password);
    with_vault_persist(&state, |vault| {
        if !vault.verify_password(current.as_bytes()) {
            return Err(VaultError::InvalidPassword);
        }
        let kdf = vault.header().kdf;
        vault.change_password(new.as_bytes(), kdf)
    })
}

// ------------------------------------------------------------------ import/export

#[derive(Debug, Deserialize)]
pub struct PathRequest {
    pub path: String,
}

#[derive(Debug, Serialize)]
pub struct ImportPreview {
    pub count: usize,
    pub samples: Vec<String>,
}

#[tauri::command]
pub fn preview_import(request: PathRequest) -> Result<ImportPreview, ApiError> {
    let text = read_text(&request.path)?;
    let entries = csvio::parse(&text).map_err(ApiError::from)?;
    Ok(ImportPreview {
        count: entries.len(),
        samples: entries.iter().take(5).map(|entry| entry.title.clone()).collect(),
    })
}

#[tauri::command]
pub fn import_csv(
    state: State<'_, AppState>,
    request: PathRequest,
) -> Result<csvio::ImportSummary, ApiError> {
    let text = read_text(&request.path)?;
    let entries = csvio::parse(&text).map_err(ApiError::from)?;
    with_vault_persist(&state, |vault| vault.import_entries(entries, now_ms()))
}

#[tauri::command]
pub fn export_backup(state: State<'_, AppState>, request: PathRequest) -> Result<(), ApiError> {
    let bytes = with_vault(&state, |vault| vault.export_backup())?;
    files::atomic_write(&PathBuf::from(&request.path), &bytes)?;
    acl::apply_private_file(&PathBuf::from(&request.path))?;
    Ok(())
}

#[tauri::command]
pub fn export_csv(
    state: State<'_, AppState>,
    request: PathRequest,
    password: String,
) -> Result<(), ApiError> {
    let password = Zeroizing::new(password);
    let csv = with_vault(&state, |vault| {
        if !vault.verify_password(password.as_bytes()) {
            return Err(VaultError::InvalidPassword);
        }
        vault.export_csv()
    })?;
    let path = PathBuf::from(&request.path);
    std::fs::write(&path, csv.as_bytes())?;
    acl::apply_private_file(&path)?;
    Ok(())
}

fn read_text(path: &str) -> Result<String, ApiError> {
    let bytes = files::read_limited(&PathBuf::from(path), 32 * 1024 * 1024)?;
    String::from_utf8(bytes).map_err(|_| ApiError::new("invalid_csv", "The file is not UTF-8 text."))
}

// ------------------------------------------------------------------ settings

#[tauri::command]
pub fn get_settings(state: State<'_, AppState>) -> Result<Settings, ApiError> {
    Ok(state
        .settings
        .lock()
        .map_err(|_| ApiError::new("internal", "State unavailable."))?
        .clone())
}

#[tauri::command]
pub fn update_settings(
    state: State<'_, AppState>,
    app: AppHandle,
    mut settings: Settings,
) -> Result<Settings, ApiError> {
    settings.sanitize();
    crate::settings::save(&state.paths.settings, &settings)?;
    *state
        .settings
        .lock()
        .map_err(|_| ApiError::new("internal", "State unavailable."))? = settings.clone();

    if let Some(window) = app.get_webview_window("main") {
        let _ = crate::platform_windows::capture::set_excluded_for(&window, settings.capture_protection);
    }
    Ok(settings)
}

#[derive(Debug, Serialize)]
pub struct HelloStatus {
    pub available: bool,
    pub reason: &'static str,
}

#[tauri::command]
pub fn hello_status() -> HelloStatus {
    HelloStatus {
        available: false,
        reason: "Windows Hello quick unlock is not enabled in this build.",
    }
}
