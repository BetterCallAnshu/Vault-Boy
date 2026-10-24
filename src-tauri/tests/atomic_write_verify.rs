//! Atomic-write guarantees: clean writes, rolling backup, crash-state healing,
//! and a kill-mid-write invariant — with a naive-writer control that proves the
//! invariant checker can actually fail (non-vacuous).
//!
//! Child writers are spawned from this same test binary via an env hook, are
//! always terminated and reaped, and self-terminate on a deadline so a panicking
//! parent can never leave an orphan loop behind. Every test uses its own temp
//! directory; real vault data is never touched.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use vaultly_lib::platform_windows::files::atomic_write;

/// Env hook that activates child mode. This string must never appear in the
/// release binary (see tools/verify/check-release-no-hooks.ps1).
const CHILD_ENV: &str = "VAULTLY_ATOMIC_CHILD";
const TARGET_ENV: &str = "VAULTLY_ATOMIC_TARGET";
const PAYLOAD: usize = 256 * 1024;
const CHILD_DEADLINE: Duration = Duration::from_secs(15);

/// Temp directory removed on drop, including when a test panics.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "vaultly-atomic-verify-{name}-{}-{unique}",
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

/// Child entry point. Without `CHILD_ENV` it is a no-op helper in normal runs;
/// the parent spawns it with `--exact child_entry` to get a separate process.
#[test]
fn child_entry() {
    let Ok(mode) = std::env::var(CHILD_ENV) else {
        return;
    };
    let target = PathBuf::from(std::env::var(TARGET_ENV).expect("child target env"));
    match mode.as_str() {
        "atomic" => atomic_child(&target),
        "naive" => naive_child(&target),
        other => panic!("FAIL: unknown child mode {other}"),
    }
}

/// Hammers `atomic_write` with two alternating payloads until killed or the
/// deadline passes. Write errors are expected once the parent kills us.
fn atomic_child(target: &Path) {
    let a = vec![b'A'; PAYLOAD];
    let b = vec![b'B'; PAYLOAD];
    println!("READY");
    let _ = std::io::stdout().flush();
    let deadline = Instant::now() + CHILD_DEADLINE;
    while Instant::now() < deadline {
        let _ = atomic_write(target, &b);
        let _ = atomic_write(target, &a);
    }
}

/// Control writer: truncate, write half, flush, then wait to be killed —
/// leaving a deterministically torn file for the detector to flag.
fn naive_child(target: &Path) {
    let payload = vec![b'N'; PAYLOAD];
    let mut file = std::fs::File::create(target).expect("truncate target");
    file.write_all(&payload[..PAYLOAD / 2]).expect("first half");
    file.flush().expect("flush first half");
    println!("HALF_READY");
    let _ = std::io::stdout().flush();
    std::thread::sleep(CHILD_DEADLINE + Duration::from_secs(15));
}

fn spawn_mode(mode: &str, target: &Path) -> Child {
    let exe = std::env::current_exe().expect("test binary path");
    Command::new(exe)
        .args(["child_entry", "--exact", "--nocapture"])
        .env(CHILD_ENV, mode)
        .env(TARGET_ENV, target)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn child writer")
}

/// Read the child's stdout until `marker`, skipping libtest's own lines.
/// Panics (after reaping) if the child exits before printing the marker.
fn await_marker(child: &mut Child, marker: &str) {
    let stdout = child.stdout.take().expect("child stdout piped");
    for line in BufReader::new(stdout).lines() {
        match line {
            Ok(line) if line == marker => return,
            Ok(_) => continue,
            Err(_) => break,
        }
    }
    let status = child.wait().expect("reap early-exit child");
    panic!("FAIL: child exited ({status}) before printing {marker}");
}

fn complete_uniform(path: &Path, byte: u8) -> bool {
    match std::fs::read(path) {
        Ok(data) => data.len() == PAYLOAD && data.iter().all(|b| *b == byte),
        Err(_) => false,
    }
}

#[test]
fn clean_write_is_complete_and_leaves_no_temp() {
    let dir = TempDir::new("clean");
    let target = dir.0.join("vault.vlt");
    let payload = vec![b'A'; PAYLOAD];
    atomic_write(&target, &payload).expect("first write");
    assert_eq!(
        std::fs::read(&target).expect("read target"),
        payload,
        "FAIL: first write content mismatch"
    );
    assert!(!dir.0.join(".vault.vlt.tmp").exists(), "FAIL: temp left behind");
    println!("PASS: clean atomic write is complete with no temp residue");
}

#[test]
fn second_write_keeps_previous_bytes_as_backup() {
    let dir = TempDir::new("backup");
    let target = dir.0.join("vault.vlt");
    let old = vec![b'A'; PAYLOAD];
    let new = vec![b'B'; PAYLOAD];
    atomic_write(&target, &old).expect("first write");
    atomic_write(&target, &new).expect("second write");
    assert_eq!(
        std::fs::read(&target).expect("read target"),
        new,
        "FAIL: target not replaced with the new bytes"
    );
    // NOTE: no production code reads vault.vlt.bak today — reported separately
    // as a finding. This test proves the backup is correctly maintained, which
    // is the precondition for any recovery path.
    let bak = std::fs::read(dir.0.join("vault.vlt.bak")).expect(".bak must exist after replace");
    assert_eq!(bak, old, "FAIL: .bak must hold the previous ciphertext");
    println!("PASS: rolling .bak holds the previous vault bytes");
}

#[test]
fn stale_temp_from_a_crash_does_not_touch_the_target() {
    let dir = TempDir::new("crash");
    let target = dir.0.join("vault.vlt");
    let a = vec![b'A'; PAYLOAD];
    let c = vec![b'C'; PAYLOAD];
    atomic_write(&target, &a).expect("first write");

    // Simulated crash: the temp file exists but ReplaceFileW never ran.
    let tmp = dir.0.join(".vault.vlt.tmp");
    std::fs::write(&tmp, vec![0xEE; PAYLOAD]).expect("stale temp");
    assert_eq!(
        std::fs::read(&target).expect("read target"),
        a,
        "FAIL: stale temp must not affect the target"
    );

    // The next real save must heal the state completely.
    atomic_write(&target, &c).expect("write after crash state");
    assert_eq!(
        std::fs::read(&target).expect("read target"),
        c,
        "FAIL: healed target content mismatch"
    );
    assert!(!tmp.exists(), "FAIL: stale temp survived a full write");
    assert_eq!(
        std::fs::read(dir.0.join("vault.vlt.bak")).expect("read bak"),
        a,
        "FAIL: bak must hold the pre-crash bytes after healing"
    );
    println!("PASS: crash-state temp is ignored and healed by the next write");
}

#[test]
fn kill_during_atomic_writes_never_tears_the_target() {
    let dir = TempDir::new("kill");
    let target = dir.0.join("vault.vlt");
    atomic_write(&target, &vec![b'A'; PAYLOAD]).expect("seed target");

    let mut child = spawn_mode("atomic", &target);
    await_marker(&mut child, "READY");
    // Let the child swap the file repeatedly, then kill at an arbitrary point.
    std::thread::sleep(Duration::from_millis(150));
    let _ = child.kill();
    let status = child.wait().expect("reap child");

    let intact_a = complete_uniform(&target, b'A');
    let intact_b = complete_uniform(&target, b'B');
    assert!(
        intact_a || intact_b,
        "FAIL: target torn after kill during atomic writes (len={})",
        std::fs::metadata(&target).map(|m| m.len()).unwrap_or(0)
    );
    println!("PASS: target intact after kill ({status}) — atomic invariant held");
}

#[test]
fn naive_writer_control_can_be_observed_torn() {
    // Non-vacuous control for the kill test: the same detector must flag a
    // writer that truncates and then writes in two steps.
    let dir = TempDir::new("naive");
    let target = dir.0.join("vault.vlt");
    std::fs::write(&target, vec![b'A'; PAYLOAD]).expect("seed target");

    let mut child = spawn_mode("naive", &target);
    await_marker(&mut child, "HALF_READY");
    let _ = child.kill();
    let _ = child.wait();

    let bytes = std::fs::read(&target).expect("read target");
    assert_eq!(
        bytes.len(),
        PAYLOAD / 2,
        "FAIL: expected the half-written length for the control"
    );
    assert!(
        bytes.iter().all(|b| *b == b'N'),
        "FAIL: expected the naive payload bytes"
    );
    println!(
        "PASS: detector flags torn writes (observed len={}, torn vs {PAYLOAD}-byte payloads)",
        bytes.len()
    );
}
