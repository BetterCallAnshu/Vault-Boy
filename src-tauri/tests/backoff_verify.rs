//! Failed-unlock backoff: persistence across reload, tamper rejection (flipped
//! MAC byte and forged counter), reset on success, private DACL on both state
//! files, and a DPAPI round-trip with a tamper negative.
//!
//! All state lives in a throwaway temp directory; real vault data is never
//! touched.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use vaultly_lib::backoff::Backoff;
use vaultly_lib::platform_windows::{acl, dpapi};

/// Mirrors `MAX_DELAY_SECONDS = 300` in src-tauri/src/backoff.rs (private).
const MAX_DELAY_MS: u64 = 300_000;

/// Temp directory removed on drop, including when a test panics.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "vaultly-backoff-verify-{name}-{}-{unique}",
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

#[test]
fn dpapi_round_trip_and_tamper_rejection() {
    let plaintext = b"vaultly dpapi round trip probe";
    let blob = dpapi::protect(plaintext).expect("CryptProtectData failed");
    assert!(
        !blob.windows(plaintext.len()).any(|w| w == plaintext),
        "FAIL: DPAPI output contains the plaintext"
    );
    let restored = dpapi::unprotect(&blob).expect("CryptUnprotectData failed");
    assert_eq!(restored, plaintext, "FAIL: DPAPI round trip mismatch");
    println!("PASS: DPAPI protect/unprotect round trip (ciphertext ≠ plaintext)");

    // Negative: a flipped byte anywhere in the blob must be rejected.
    let mut tampered_blob = blob.clone();
    let mid = tampered_blob.len() / 2;
    tampered_blob[mid] ^= 0x01;
    assert!(
        dpapi::unprotect(&tampered_blob).is_err(),
        "FAIL: DPAPI accepted a tampered blob"
    );
    println!("PASS: tampered DPAPI blob rejected");
}

#[test]
fn backoff_persists_rejects_tampering_and_resets_on_success() {
    let dir = TempDir::new("state");
    let state = dir.0.join("lockout.dat");
    let key = dir.0.join("device.key");

    let mut backoff = Backoff::load(&state, &key);
    backoff.record_failure(1_000);
    backoff.record_failure(1_000);
    drop(backoff);

    // Both persisted files must carry the user-only DACL.
    assert!(
        acl::verify_private(&key).expect("verify device.key acl"),
        "FAIL: device.key is not private to the user"
    );
    assert!(
        acl::verify_private(&state).expect("verify lockout.dat acl"),
        "FAIL: lockout.dat is not private to the user"
    );
    println!("PASS: backoff files carry the user-only DACL");

    let pristine = std::fs::read(&state).expect("read pristine state");
    let reloaded = Backoff::load(&state, &key);
    assert_eq!(reloaded.failures(), 2, "FAIL: failures not persisted");
    assert_eq!(
        reloaded.remaining_ms(1_000),
        2_000,
        "FAIL: delay after 2 failures must be 2s"
    );
    assert!(!reloaded.is_tampered(), "FAIL: pristine state flagged tampered");
    println!("PASS: backoff counter persists across reload");
    drop(reloaded);

    // Negative 1: flip one byte inside the stored HMAC.
    let mut flipped = pristine.clone();
    let flip_index = flipped.len().checked_sub(3).expect("state file too small");
    flipped[flip_index] ^= 0x01;
    std::fs::write(&state, &flipped).expect("write flipped state");
    let tampered = Backoff::load(&state, &key);
    assert!(tampered.is_tampered(), "FAIL: flipped MAC byte not detected");
    assert!(
        tampered.remaining_ms(0) >= MAX_DELAY_MS,
        "FAIL: tampered state must enforce the maximum delay"
    );
    drop(tampered);
    println!("PASS: flipped MAC byte rejected with the maximum delay");

    // Negative 2: forge a lower failure counter, keep the original MAC.
    let mut forged = serde_json::from_slice::<serde_json::Value>(&pristine)
        .expect("state is JSON")
        .clone();
    forged["failures"] = serde_json::json!(1);
    std::fs::write(&state, serde_json::to_vec(&forged).expect("serialize forged state"))
        .expect("write forged state");
    let forged_state = Backoff::load(&state, &key);
    assert!(forged_state.is_tampered(), "FAIL: forged counter not detected");
    drop(forged_state);
    println!("PASS: forged failure counter rejected");

    // A successful unlock rewrites a valid state and clears the delay.
    let mut recovered = Backoff::load(&state, &key);
    assert!(recovered.is_tampered(), "precondition: starts tampered");
    recovered.record_success();
    drop(recovered);
    let clean = Backoff::load(&state, &key);
    assert!(!clean.is_tampered(), "FAIL: record_success must rewrite a valid state");
    assert_eq!(clean.failures(), 0, "FAIL: failures must reset on success");
    assert_eq!(clean.remaining_ms(0), 0, "FAIL: delay must clear after success");
    println!("PASS: unlock success rewrites valid state and clears the delay");
}
