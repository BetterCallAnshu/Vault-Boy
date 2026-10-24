//! Clipboard verification — **gated off by default** because it overwrites the
//! desktop clipboard. Enable only with `VAULTLY_ALLOW_CLIPBOARD_TESTS=1` (the
//! tools/verify/run-all.ps1 `-IncludeClipBoard` switch sets it, after warning).
//!
//! Checks: the three exclusion marker formats are present with a DWORD-0
//! payload, `clear_if_sequence` refuses to wipe someone else's content, it does
//! clear our own fresh value, and the original clipboard text is restored on
//! exit even if a test panics.

use std::ffi::c_void;

use windows::core::PCWSTR;
use windows::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, GetClipboardData, OpenClipboard, RegisterClipboardFormatW,
    SetClipboardData,
};
use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};
use windows::Win32::System::Ole::CF_UNICODETEXT;
use vaultly_lib::platform_windows::clipboard;

const MARKERS: [&str; 3] = [
    "ExcludeClipboardContentFromMonitorProcessing",
    "CanIncludeInClipboardHistory",
    "CanUploadToCloudClipboard",
];

fn enabled() -> bool {
    std::env::var("VAULTLY_ALLOW_CLIPBOARD_TESTS").is_ok_and(|v| v == "1")
}

/// Opens the clipboard for one operation and always closes it again.
struct ClipboardOpen;

impl ClipboardOpen {
    fn open() -> Option<Self> {
        // SAFETY: documented no-owner open; closed by Drop on success only.
        unsafe { OpenClipboard(None) }.ok().map(|_| ClipboardOpen)
    }
}

impl Drop for ClipboardOpen {
    fn drop(&mut self) {
        // SAFETY: balanced with the successful OpenClipboard above.
        unsafe {
            let _ = CloseClipboard();
        }
    }
}

/// Allocate a GMEM_MOVEABLE block holding `bytes` (ownership passes to
/// `SetClipboardData` on success).
fn alloc(bytes: &[u8]) -> Option<windows::Win32::Foundation::HGLOBAL> {
    // SAFETY: explicit size; the block lives until the clipboard takes it.
    let handle = unsafe { GlobalAlloc(GMEM_MOVEABLE, bytes.len()) }.ok()?;
    // SAFETY: handle is a live GMEM_MOVEABLE block of bytes.len() bytes.
    let pointer = unsafe { GlobalLock(handle) };
    if pointer.is_null() {
        return None;
    }
    // SAFETY: destination is the locked block, source is the caller's slice.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), pointer as *mut u8, bytes.len());
        let _ = GlobalUnlock(handle);
    }
    Some(handle)
}

/// Write plain UTF-16 text (no marker formats) — used to simulate an external
/// writer and to restore the user's original clipboard text.
fn write_plain(text: &str) -> bool {
    let utf16: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    let bytes: &[u8] = unsafe {
        // SAFETY: reinterpreting a live &[u16] as bytes for a memcpy only.
        std::slice::from_raw_parts(utf16.as_ptr().cast::<u8>(), utf16.len() * 2)
    };
    let Some(_guard) = ClipboardOpen::open() else {
        return false;
    };
    // SAFETY: clipboard is open and owned by this thread.
    unsafe {
        if EmptyClipboard().is_err() {
            return false;
        }
    }
    let Some(handle) = alloc(bytes) else {
        return false;
    };
    // SAFETY: clipboard open; on success it owns the handle.
    unsafe { SetClipboardData(CF_UNICODETEXT.0 as u32, Some(windows::Win32::Foundation::HANDLE(handle.0))).is_ok() }
}

/// Current CF_UNICODETEXT contents, `None` when empty or unreadable.
fn read_text() -> Option<String> {
    let _guard = ClipboardOpen::open()?;
    // SAFETY: clipboard is open; requesting a standard format.
    let handle = unsafe { GetClipboardData(CF_UNICODETEXT.0 as u32) }.ok()?;
    let global = windows::Win32::Foundation::HGLOBAL(handle.0);
    // SAFETY: handle is a live CF_UNICODETEXT allocation owned by the clipboard.
    let pointer = unsafe { GlobalLock(global) };
    if pointer.is_null() {
        return None;
    }
    let text = unsafe {
        // SAFETY: clipboard text is NUL-terminated UTF-16; cap the scan at 64K
        // units so a broken source cannot run away.
        let base = pointer as *const u16;
        let mut len = 0usize;
        while len < 65_536 && *base.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(base, len))
    };
    unsafe {
        let _ = GlobalUnlock(global);
    }
    Some(text)
}

/// DWORD payload of a clipboard format, `None` when absent.
fn format_dword(format: u32) -> Option<u32> {
    let _guard = ClipboardOpen::open()?;
    // SAFETY: clipboard is open; format id was registered by this process.
    let handle = unsafe { GetClipboardData(format) }.ok()?;
    let global = windows::Win32::Foundation::HGLOBAL(handle.0);
    // SAFETY: live allocation the clipboard just handed us.
    let pointer = unsafe { GlobalLock(global) };
    if pointer.is_null() {
        return None;
    }
    // SAFETY: marker formats are written as a single DWORD (see clipboard.rs).
    let value = unsafe { *(pointer as *const u32) };
    unsafe {
        let _ = GlobalUnlock(global);
    }
    Some(value)
}

fn register(name: &str) -> u32 {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: wide is NUL-terminated and alive for the call.
    unsafe { RegisterClipboardFormatW(PCWSTR(wide.as_ptr())) }
}

fn format_available(format: u32) -> bool {
    let _guard = ClipboardOpen::open();
    // SAFETY: clipboard open (or the call harmlessly fails); queries presence.
    unsafe { GetClipboardData(format).is_ok() }
}

/// Restores the user's original text (or empties the clipboard if there was
/// none) when the test ends — including on panic.
struct ClipboardRestore(Option<String>);

impl Drop for ClipboardRestore {
    fn drop(&mut self) {
        match &self.0 {
            Some(text) => {
                let _ = write_plain(text);
            }
            None => {
                if let Some(_guard) = ClipboardOpen::open() {
                    // SAFETY: clipboard open; clearing our probe residue.
                    unsafe {
                        let _ = EmptyClipboard();
                    }
                }
            }
        }
    }
}

#[test]
fn exclusion_markers_sequence_guard_and_preservation() {
    if !enabled() {
        eprintln!(
            "SKIP: clipboard tests disabled — set VAULTLY_ALLOW_CLIPBOARD_TESTS=1 \
             (they overwrite the desktop clipboard)"
        );
        return;
    }

    let original = read_text();
    let _restore = ClipboardRestore(original.clone());
    println!(
        "clipboard snapshot: {}",
        original
            .as_ref()
            .map(|t| format!("{} chars", t.len()))
            .unwrap_or_else(|| "empty".to_string())
    );

    let ids: Vec<u32> = MARKERS.iter().map(|name| register(name)).collect();
    for (name, id) in MARKERS.iter().zip(&ids) {
        assert!(*id != 0, "FAIL: RegisterClipboardFormatW failed for {name}");
    }

    let secret = "vaultly-clipboard-probe-0123456789";
    let seq = clipboard::copy_secret(secret).expect("copy_secret");
    assert!(seq > 0, "FAIL: sequence number must be non-zero");

    // Marker 1: all three exclusion formats present with a DWORD-0 payload.
    assert!(
        format_available(CF_UNICODETEXT.0 as u32),
        "FAIL: CF_UNICODETEXT missing after copy_secret"
    );
    for (name, id) in MARKERS.iter().zip(&ids) {
        assert!(format_available(*id), "FAIL: marker format missing: {name}");
        assert_eq!(
            format_dword(*id),
            Some(0),
            "FAIL: marker payload must be DWORD 0: {name}"
        );
    }
    println!("PASS: three exclusion marker formats present with DWORD-0 payload");

    // Marker 2: an external writer bumps the sequence; our clear must refuse.
    assert!(write_plain("external-writer-probe"), "FAIL: external write");
    let external_seq = clipboard::sequence();
    assert!(external_seq > seq, "FAIL: sequence did not bump after an external write");
    assert!(
        !clipboard::clear_if_sequence(seq),
        "FAIL: clear must refuse when the clipboard content changed"
    );
    assert_eq!(
        read_text().as_deref(),
        Some("external-writer-probe"),
        "FAIL: external clipboard value was destroyed"
    );
    println!("PASS: sequence guard preserves externally written content");

    // Marker 3: clearing our own fresh value works.
    let ours = clipboard::copy_secret(secret).expect("copy_secret again");
    assert!(
        clipboard::clear_if_sequence(ours),
        "FAIL: clear_if_sequence refused our own fresh value"
    );
    assert!(
        !format_available(CF_UNICODETEXT.0 as u32),
        "FAIL: clipboard not empty after our clear"
    );
    println!("PASS: auto-clear removes exactly our own value");

    // _restore's Drop puts the user's original text back now.
}
