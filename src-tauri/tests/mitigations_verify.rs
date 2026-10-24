//! Process mitigation verification: `apply()` requests the four core policies,
//! then `read_back()` queries the kernel via `GetProcessMitigationPolicy` to
//! prove Windows actually enforces them — not merely that the setter returned
//! success.
//!
//! This runs in its own process (its own test binary), so the permanent
//! per-process policies cannot affect anything else. The signature policy is
//! deliberately NOT applied (the test binary is unsigned); its read-back
//! staying `false` is the control that proves `read_back` reports per-policy
//! state instead of always answering "on".

use vaultly_lib::platform_windows::mitigations;

#[test]
fn apply_is_confirmed_by_kernel_read_back() {
    let before = mitigations::read_back();
    println!("read_back() baseline (fresh process): {before:?}");

    let applied = mitigations::apply(false);
    println!("apply(false) accepted:            {applied:?}");
    assert!(applied.dynamic_code_prohibited, "FAIL: SetProcessMitigationPolicy(ACG) refused");
    assert!(applied.strict_handles, "FAIL: SetProcessMitigationPolicy(strict handles) refused");
    assert!(applied.extension_points_disabled, "FAIL: SetProcessMitigationPolicy(extension points) refused");
    assert!(applied.image_load_restricted, "FAIL: SetProcessMitigationPolicy(image load) refused");
    assert!(!applied.signature_policy, "FAIL: apply(false) must not attempt the signature policy");

    let after = mitigations::read_back();
    println!("read_back() after apply:          {after:?}");
    assert!(after.dynamic_code_prohibited, "FAIL: kernel reports ACG not enforced");
    assert!(after.strict_handles, "FAIL: kernel reports strict handles not enforced");
    assert!(after.extension_points_disabled, "FAIL: kernel reports extension points not enforced");
    assert!(after.image_load_restricted, "FAIL: kernel reports image load restriction not enforced");

    // Non-vacuous control: the signature policy was never applied, so a
    // read_back that always returned true would be caught right here.
    assert!(
        !after.signature_policy,
        "FAIL: read_back claimed the signature policy without it being set"
    );

    println!(
        "PASS: 4 core policies applied and confirmed by GetProcessMitigationPolicy; \
         signature policy correctly reported off (control)"
    );
}
