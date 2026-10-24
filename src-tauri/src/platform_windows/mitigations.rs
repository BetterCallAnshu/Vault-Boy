//! Process mitigation policies applied at startup.
//!
//! Every policy is applied individually and the result recorded, because some
//! (binary-signature enforcement in particular) depend on how the binary was
//! signed and on the Windows build. The UI shows the actual state rather than
//! claiming a policy is active.

use std::ffi::c_void;

use serde::Serialize;
use windows::Win32::System::SystemServices::{
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY, PROCESS_MITIGATION_DYNAMIC_CODE_POLICY,
    PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY, PROCESS_MITIGATION_IMAGE_LOAD_POLICY,
    PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY,
};
use windows::Win32::System::Threading::{
    GetProcessMitigationPolicy, SetProcessMitigationPolicy, GetCurrentProcess,
    ProcessDynamicCodePolicy, ProcessExtensionPointDisablePolicy, ProcessImageLoadPolicy,
    ProcessSignaturePolicy, ProcessStrictHandleCheckPolicy, PROCESS_MITIGATION_POLICY,
};

/// Which mitigations the OS accepted for this process.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct MitigationReport {
    /// ACG: no dynamic code generation in this process.
    pub dynamic_code_prohibited: bool,
    /// Invalid handle usage raises instead of being ignored.
    pub strict_handles: bool,
    /// Legacy extension points (AppInit, IME, etc.) disabled.
    pub extension_points_disabled: bool,
    /// No remote or low-integrity images may load into the process.
    pub image_load_restricted: bool,
    /// Only Microsoft-signed images (release builds only; may be refused).
    pub signature_policy: bool,
}

fn set_policy<T>(policy: PROCESS_MITIGATION_POLICY, value: &T) -> bool {
    let size = std::mem::size_of::<T>();
    // SAFETY: `value` is a live, correctly-sized mitigation policy structure
    // and the API only reads `size` bytes from it.
    unsafe {
        SetProcessMitigationPolicy(policy, value as *const T as *const c_void, size).is_ok()
    }
}

/// Apply the mitigation set. `include_signature_policy` should only be true for
/// release builds whose binaries are Authenticode-signed.
pub fn apply(include_signature_policy: bool) -> MitigationReport {
    let mut report = MitigationReport::default();

    let mut dynamic = PROCESS_MITIGATION_DYNAMIC_CODE_POLICY::default();
    // Bit 0: ProhibitDynamicCode.
    dynamic.Anonymous.Flags = 0x1;
    report.dynamic_code_prohibited = set_policy(ProcessDynamicCodePolicy, &dynamic);

    let mut strict = PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY::default();
    // Bit 0: RaiseExceptionOnInvalidHandleReference, bit 1: permanent.
    strict.Anonymous.Flags = 0x3;
    report.strict_handles = set_policy(ProcessStrictHandleCheckPolicy, &strict);

    let mut extension = PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY::default();
    extension.Anonymous.Flags = 0x1;
    report.extension_points_disabled = set_policy(ProcessExtensionPointDisablePolicy, &extension);

    let mut images = PROCESS_MITIGATION_IMAGE_LOAD_POLICY::default();
    // Bit 0: NoRemoteImages, bit 1: NoLowMandatoryLabelImages.
    images.Anonymous.Flags = 0x3;
    report.image_load_restricted = set_policy(ProcessImageLoadPolicy, &images);

    if include_signature_policy {
        let mut signature = PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY::default();
        // Bit 0: MicrosoftSignedOnly.
        signature.Anonymous.Flags = 0x1;
        report.signature_policy = set_policy(ProcessSignaturePolicy, &signature);
    }

    report
}

fn query_policy<T>(policy: PROCESS_MITIGATION_POLICY, value: &mut T) -> bool {
    let size = std::mem::size_of::<T>();
    // SAFETY: `value` is a live, correctly-sized buffer the API fills with
    // `size` bytes; the current-process pseudo-handle is always valid and the
    // policy enum selects the matching structure layout.
    unsafe {
        GetProcessMitigationPolicy(
            GetCurrentProcess(),
            policy,
            value as *mut T as *mut c_void,
            size,
        )
        .is_ok()
    }
}

/// Read the **actual** process mitigation state back from the kernel.
///
/// `apply` only reports whether each `SetProcessMitigationPolicy` call was
/// accepted; this re-queries the OS so callers (tests, diagnostics, the UI)
/// verify a policy is really enforced rather than merely requested.
pub fn read_back() -> MitigationReport {
    let mut report = MitigationReport::default();

    let mut dynamic = PROCESS_MITIGATION_DYNAMIC_CODE_POLICY::default();
    if query_policy(ProcessDynamicCodePolicy, &mut dynamic) {
        // SAFETY: `dynamic` is zero-initialized by `default()` and
        // `query_policy` filled its full size above, so the union `Flags`
        // member holds the dword the OS wrote.
        report.dynamic_code_prohibited = unsafe { dynamic.Anonymous.Flags } & 0x1 != 0;
    }

    let mut strict = PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY::default();
    if query_policy(ProcessStrictHandleCheckPolicy, &mut strict) {
        // SAFETY: same as above — zero-initialized, then fully filled by the
        // successful query before the union member is read.
        report.strict_handles = unsafe { strict.Anonymous.Flags } & 0x1 != 0;
    }

    let mut extension = PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY::default();
    if query_policy(ProcessExtensionPointDisablePolicy, &mut extension) {
        // SAFETY: zero-initialized structure, entirely overwritten by the
        // successful `GetProcessMitigationPolicy` call before this read.
        report.extension_points_disabled = unsafe { extension.Anonymous.Flags } & 0x1 != 0;
    }

    let mut images = PROCESS_MITIGATION_IMAGE_LOAD_POLICY::default();
    if query_policy(ProcessImageLoadPolicy, &mut images) {
        // SAFETY: zero-initialized structure, entirely overwritten by the
        // successful `GetProcessMitigationPolicy` call before this read.
        report.image_load_restricted = unsafe { images.Anonymous.Flags } & 0x3 != 0;
    }

    let mut signature = PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY::default();
    if query_policy(ProcessSignaturePolicy, &mut signature) {
        // SAFETY: zero-initialized structure, entirely overwritten by the
        // successful `GetProcessMitigationPolicy` call before this read.
        report.signature_policy = unsafe { signature.Anonymous.Flags } & 0x1 != 0;
    }

    report
}
