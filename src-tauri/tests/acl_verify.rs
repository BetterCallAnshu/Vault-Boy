//! Repeatable ACL verification: the positive ensure/verify path plus a real
//! tamper negative (`icacls /reset`) that the startup check must detect.
//!
//! Every test builds its own temp directory and removes it on drop, even when
//! a test panics. Real vault data is never touched.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use vaultly_lib::platform_windows::acl;

/// Temp directory removed on drop, including when a test panics.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "vaultly-acl-verify-{name}-{}-{unique}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create temp dir");
        TempDir(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Print the SDDL PowerShell reports for the path (informational only; a
/// failure here never decides PASS/FAIL).
fn print_sddl(path: &Path) {
    let quoted = path.to_string_lossy().replace('\'', "''");
    let script = format!("(Get-Acl -LiteralPath '{quoted}').Sddl");
    let output = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output();
    match output {
        Ok(out) if out.status.success() => {
            println!(
                "SDDL (Get-Acl): {}",
                String::from_utf8_lossy(&out.stdout).trim()
            );
        }
        other => println!("SDDL display unavailable: {other:?}"),
    }
}

#[test]
fn ensure_then_verify_accepts_a_fresh_directory() {
    let dir = TempDir::new("positive");
    acl::ensure_private_directory(&dir.0).expect("ensure_private_directory failed");
    let verified = acl::verify_private(&dir.0).expect("verify_private failed");
    assert!(verified, "FAIL: freshly secured directory did not verify");
    print_sddl(&dir.0);
    println!("PASS: ensure_private_directory then verify_private");
}

#[test]
fn tampered_acl_is_detected_like_the_startup_check() {
    let dir = TempDir::new("tamper");
    acl::ensure_private_directory(&dir.0).expect("secure directory");
    assert!(
        acl::verify_private(&dir.0).expect("verify"),
        "precondition: directory verifies before tampering"
    );

    // Negative: reset to the inherited (broad) ACL — the same class of change
    // a local attacker or a misbehaving installer could make.
    let status = Command::new("icacls")
        .arg(&dir.0)
        .args(["/reset", "/T", "/Q"])
        .status()
        .expect("run icacls");
    assert!(status.success(), "FAIL: icacls reset did not succeed");

    let verified =
        acl::verify_private(&dir.0).expect("verify_private must still run after tampering");
    assert!(!verified, "FAIL: verify_private missed a broadened ACL");
    print_sddl(&dir.0);
    println!("PASS: tampered (reset) ACL detected by verify_private");
}
