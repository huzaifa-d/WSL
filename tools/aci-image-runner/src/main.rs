// Copyright (C) Microsoft Corporation. All rights reserved.

mod arguments;
mod bundle;

use arguments::Arguments;

fn validate_host(os: &str, arch: &str, native_x64: bool) -> Result<(), String> {
    if os != "windows" || arch != "x86_64" || !native_x64 {
        return Err(format!(
            "unsupported host or process architecture ({os}/{arch}): native Windows x64 with WHP is required"
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn native_x64() -> Result<bool, String> {
    use windows_sys::Win32::System::SystemInformation::IMAGE_FILE_MACHINE_AMD64;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, IsWow64Process2};

    let mut process_machine = 0;
    let mut native_machine = 0;
    // Both output pointers are valid, and GetCurrentProcess returns a process pseudo-handle.
    let success = unsafe {
        IsWow64Process2(
            GetCurrentProcess(),
            &mut process_machine,
            &mut native_machine,
        )
    };
    if success == 0 {
        return Err(format!(
            "cannot determine native host architecture: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(native_machine == IMAGE_FILE_MACHINE_AMD64)
}

#[cfg(not(windows))]
fn native_x64() -> Result<bool, String> {
    Ok(false)
}

fn run() -> Result<(), String> {
    let args = Arguments::parse(std::env::args_os().skip(1))?;
    validate_host(std::env::consts::OS, std::env::consts::ARCH, native_x64()?)?;
    let _config = bundle::agent_config(&args.bundle, &args.state_root)?;
    Err("execution is not implemented".into())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("aci-image-runner: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_unsupported_hosts() {
        assert!(validate_host("windows", "x86_64", true).is_ok());
        assert!(validate_host("windows", "x86_64", false).is_err());
        assert!(validate_host("windows", "aarch64", false).is_err());
        assert!(validate_host("windows", "x86", true).is_err());
        assert!(validate_host("linux", "x86_64", true).is_err());
    }
}
