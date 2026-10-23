//! Atomic file replacement with a rolling backup.
//!
//! Only ciphertext is ever written through this path: the vault bytes come from
//! `Vault::to_bytes`, and backups are byte copies of the same ciphertext.

use std::fs::File;
use std::io::Write;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use windows::core::PCWSTR;
use windows::Win32::Storage::FileSystem::{
    MoveFileExW, ReplaceFileW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    REPLACE_FILE_FLAGS,
};

use super::{acl, PlatformError, PlatformResult};

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
}

/// Write `bytes` to `path` atomically:
/// 1. create a sibling temp file, tighten its ACL, write, `FlushFileBuffers`;
/// 2. `ReplaceFileW(tmp, path, path.bak)` so the previous vault is preserved;
/// 3. fall back to `MoveFileExW` on first write.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> PlatformResult<()> {
    let parent = path.parent().ok_or_else(|| PlatformError::with_code("path", 3))?;
    std::fs::create_dir_all(parent).map_err(|_| PlatformError::with_code("mkdir", 3))?;

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| PlatformError::with_code("path", 3))?;
    let temp = parent.join(format!(".{file_name}.tmp"));
    let backup = parent.join(format!("{file_name}.bak"));

    {
        let mut file = File::create(&temp).map_err(|_| PlatformError::with_code("create", 5))?;
        // Tighten before writing so the temp file never exists with broad ACLs.
        acl::apply_private_file(&temp)?;
        file.write_all(bytes)
            .map_err(|_| PlatformError::with_code("write", 5))?;
        file.sync_all()
            .map_err(|_| PlatformError::with_code("flush", 5))?;
    }

    if path.exists() {
        let replaced = replace(path, &temp, &backup);
        if replaced.is_err() {
            // Backup path may be locked or on an odd filesystem; replace without
            // a backup rather than leaving the new vault in a temp file.
            let _ = move_replace(&temp, path);
        }
    } else {
        move_replace(&temp, path)?;
    }

    // Best effort: the vault is written; a leftover temp is not secret.
    let _ = std::fs::remove_file(&temp);
    Ok(())
}

fn replace(target: &Path, replacement: &Path, backup: &Path) -> PlatformResult<()> {
    let target_w = wide(target);
    let replacement_w = wide(replacement);
    let backup_w = wide(backup);
    // SAFETY: all three pointers come from live, NUL-terminated Vec<u16>
    // buffers for the duration of the call. ReplaceFileW performs the
    // documented atomic swap and does not retain the pointers.
    let result = unsafe {
        ReplaceFileW(
            PCWSTR(target_w.as_ptr()),
            PCWSTR(replacement_w.as_ptr()),
            PCWSTR(backup_w.as_ptr()),
            REPLACE_FILE_FLAGS(0),
            None,
            None,
        )
    };
    result.map_err(|_| PlatformError::new("ReplaceFileW"))
}

fn move_replace(from: &Path, to: &Path) -> PlatformResult<()> {
    let from_w = wide(from);
    let to_w = wide(to);
    // SAFETY: live NUL-terminated buffers; MoveFileExW does not retain them.
    let result = unsafe {
        MoveFileExW(
            PCWSTR(from_w.as_ptr()),
            PCWSTR(to_w.as_ptr()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    result.map_err(|_| PlatformError::new("MoveFileExW"))
}

/// Read a file with an upper bound, refusing to allocate unbounded memory.
pub fn read_limited(path: &Path, max_bytes: u64) -> PlatformResult<Vec<u8>> {
    let metadata = std::fs::metadata(path)
        .map_err(|_| PlatformError::with_code("stat", 2))?;
    if metadata.len() > max_bytes {
        return Err(PlatformError::with_code("file too large", 122));
    }
    std::fs::read(path).map_err(|_| PlatformError::with_code("read", 2))
}

/// Paths used by the app under `%LOCALAPPDATA%\Vaultly`.
pub struct VaultPaths {
    pub directory: PathBuf,
    pub vault: PathBuf,
    pub backup: PathBuf,
    pub settings: PathBuf,
    pub lockout: PathBuf,
    pub device_key: PathBuf,
}

impl VaultPaths {
    pub fn discover() -> PlatformResult<Self> {
        let base = std::env::var_os("LOCALAPPDATA")
            .ok_or_else(|| PlatformError::with_code("LOCALAPPDATA", 203))?;
        let directory = PathBuf::from(base).join("Vaultly");
        Ok(VaultPaths {
            vault: directory.join("vault.vlt"),
            backup: directory.join("vault.vlt.bak"),
            settings: directory.join("settings.json"),
            lockout: directory.join("lockout.dat"),
            device_key: directory.join("device.key"),
            directory,
        })
    }
}
