// Copyright (C) Microsoft Corporation. All rights reserved.

use std::process::Command;

#[cfg(windows)]
fn supported_host() -> bool {
    use windows_sys::Win32::System::SystemInformation::IMAGE_FILE_MACHINE_AMD64;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, IsWow64Process2};

    let mut process_machine = 0;
    let mut native_machine = 0;
    // Both output pointers are valid, and GetCurrentProcess returns a process pseudo-handle.
    let result = unsafe {
        IsWow64Process2(
            GetCurrentProcess(),
            &mut process_machine,
            &mut native_machine,
        )
    };
    assert_ne!(result, 0, "IsWow64Process2 failed");
    std::env::consts::ARCH == "x86_64" && native_machine == IMAGE_FILE_MACHINE_AMD64
}

#[cfg(not(windows))]
fn supported_host() -> bool {
    false
}

#[test]
fn cli_reports_argument_error_and_nonzero_exit() {
    let output = Command::new(env!("CARGO_BIN_EXE_aci-image-runner"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "aci-image-runner: missing -- separator before the guest program\n"
    );
}

#[test]
fn cli_uses_the_production_host_check_and_manifest_pin() {
    let bundle = tempfile::tempdir().unwrap();
    let manifest = bundle.path().join("SOURCE-MANIFEST.json");
    std::fs::write(&manifest, b"not the approved manifest").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_aci-image-runner"))
        .arg("--bundle")
        .arg(bundle.path())
        .arg("--state-root")
        .arg(bundle.path().join("state"))
        .args(["--image", "alpine", "--", "true"])
        .output()
        .unwrap();
    let expected = if supported_host() {
        format!(
            "aci-image-runner: SHA-256 mismatch for {}\n",
            manifest.display()
        )
    } else {
        format!(
            "aci-image-runner: unsupported host or process architecture ({}/{}): native Windows x64 with WHP is required\n",
            std::env::consts::OS,
            std::env::consts::ARCH
        )
    };
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(String::from_utf8(output.stderr).unwrap(), expected);
}
