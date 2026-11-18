// Copyright (C) Microsoft Corporation. All rights reserved.

use std::process::Command;

#[cfg(windows)]
fn supported_host() -> Result<bool, String> {
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::System::LibraryLoader::{
        GET_MODULE_HANDLE_EX_FLAG_PIN, GetModuleHandleExA, GetProcAddress,
    };
    use windows_sys::Win32::System::SystemInformation::IMAGE_FILE_MACHINE_AMD64;
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    type Query = unsafe extern "system" fn(HANDLE, *mut u16, *mut u16) -> i32;

    let mut module = std::ptr::null_mut();
    // Both pointers are valid; pinning keeps kernel32 loaded through the query.
    let result = unsafe {
        GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_PIN,
            c"kernel32.dll".as_ptr().cast(),
            &mut module,
        )
    };
    if result == 0 {
        return Err(format!(
            "cannot find kernel32.dll: {}",
            std::io::Error::last_os_error()
        ));
    }
    // This export has the Query ABI and signature.
    let address = unsafe { GetProcAddress(module, c"IsWow64Process2".as_ptr().cast()) }.ok_or(
        "unsupported host: IsWow64Process2 is unavailable; native Windows x64 cannot be verified",
    )?;
    let query =
        unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, Query>(address) };

    let mut process_machine = 0;
    let mut native_machine = 0;
    // Both output pointers are valid, and GetCurrentProcess returns a process pseudo-handle.
    let result = unsafe {
        query(
            GetCurrentProcess(),
            &mut process_machine,
            &mut native_machine,
        )
    };
    if result == 0 {
        return Err(format!(
            "cannot determine native host architecture: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(std::env::consts::ARCH == "x86_64" && native_machine == IMAGE_FILE_MACHINE_AMD64)
}

#[cfg(not(windows))]
fn supported_host() -> Result<bool, String> {
    Ok(false)
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
    let expected = match supported_host() {
        Ok(true) => format!(
            "aci-image-runner: SHA-256 mismatch for {}\n",
            manifest.display()
        ),
        Ok(false) => format!(
            "aci-image-runner: unsupported host or process architecture ({}/{}): native Windows x64 with WHP is required\n",
            std::env::consts::OS,
            std::env::consts::ARCH
        ),
        Err(error) => format!("aci-image-runner: {error}\n"),
    };
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(String::from_utf8(output.stderr).unwrap(), expected);
}
