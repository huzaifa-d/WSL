// Copyright (C) Microsoft Corporation. All rights reserved.

mod arguments;
mod bundle;

use arguments::Arguments;
use bundle::BundleTrust;
use std::ffi::OsString;
use std::fmt;

const ERROR_EXIT_CODE: i32 = 1;

#[derive(Debug, PartialEq, Eq)]
enum RunnerError {
    Arguments(String),
    Host(String),
    Bundle(String),
    NotImplemented,
}

impl fmt::Display for RunnerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Arguments(message) | Self::Host(message) | Self::Bundle(message) => {
                write!(formatter, "aci-image-runner: {message}")
            }
            Self::NotImplemented => {
                write!(formatter, "aci-image-runner: execution is not implemented")
            }
        }
    }
}

fn validate_host(os: &str, arch: &str, native_x64: bool) -> Result<(), String> {
    if os != "windows" || arch != "x86_64" || !native_x64 {
        return Err(format!(
            "unsupported host or process architecture ({os}/{arch}): native Windows x64 with WHP is required"
        ));
    }
    Ok(())
}

#[cfg(windows)]
type IsWow64Process2Fn = unsafe extern "system" fn(
    windows_sys::Win32::Foundation::HANDLE,
    *mut windows_sys::Win32::System::SystemInformation::IMAGE_FILE_MACHINE,
    *mut windows_sys::Win32::System::SystemInformation::IMAGE_FILE_MACHINE,
) -> windows_sys::core::BOOL;

#[cfg(windows)]
fn resolve_is_wow64_process2() -> Result<Option<IsWow64Process2Fn>, String> {
    use windows_sys::Win32::System::LibraryLoader::{
        GET_MODULE_HANDLE_EX_FLAG_PIN, GetModuleHandleExA, GetProcAddress,
    };

    let mut module = std::ptr::null_mut();
    // The string and output pointer are valid; pinning keeps kernel32 loaded for the function pointer.
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

    // The named export has the IsWow64Process2 Windows ABI declared above.
    let address = unsafe { GetProcAddress(module, c"IsWow64Process2".as_ptr().cast()) };
    Ok(address.map(|function| unsafe {
        std::mem::transmute::<unsafe extern "system" fn() -> isize, IsWow64Process2Fn>(function)
    }))
}

#[cfg(windows)]
fn native_x64_with_api(api: Option<IsWow64Process2Fn>) -> Result<bool, String> {
    use windows_sys::Win32::System::SystemInformation::IMAGE_FILE_MACHINE_AMD64;
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    let query = api.ok_or(
        "unsupported host: IsWow64Process2 is unavailable; native Windows x64 cannot be verified",
    )?;
    let mut process_machine = 0;
    let mut native_machine = 0;
    // Both output pointers are valid, and GetCurrentProcess returns a process pseudo-handle.
    let success = unsafe {
        query(
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

#[cfg(windows)]
fn check_windows_host(
    os: &str,
    arch: &str,
    resolve: impl FnOnce() -> Result<Option<IsWow64Process2Fn>, String>,
) -> Result<(), String> {
    validate_host(os, arch, native_x64_with_api(resolve()?)?)
}

#[cfg(windows)]
fn check_current_host() -> Result<(), String> {
    check_windows_host(
        std::env::consts::OS,
        std::env::consts::ARCH,
        resolve_is_wow64_process2,
    )
}

#[cfg(not(windows))]
fn check_current_host() -> Result<(), String> {
    validate_host(std::env::consts::OS, std::env::consts::ARCH, false)
}

fn run(
    args: impl IntoIterator<Item = OsString>,
    host_check: impl FnOnce() -> Result<(), String>,
    trust: BundleTrust,
) -> Result<(), RunnerError> {
    let args = Arguments::parse(args).map_err(RunnerError::Arguments)?;
    host_check().map_err(RunnerError::Host)?;
    let _config = trust
        .agent_config(&args.bundle, &args.state_root)
        .map_err(RunnerError::Bundle)?;
    Err(RunnerError::NotImplemented)
}

fn main() {
    if let Err(error) = run(
        std::env::args_os().skip(1),
        check_current_host,
        BundleTrust::approved(),
    ) {
        eprintln!("{error}");
        std::process::exit(ERROR_EXIT_CODE);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::fs;
    use std::path::PathBuf;

    struct Fixture {
        dir: tempfile::TempDir,
        trust: bundle::BundleTrust,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            fs::create_dir(dir.path().join("bin")).unwrap();
            fs::write(dir.path().join("SOURCE-MANIFEST.json"), b"manifest fixture").unwrap();
            fs::write(
                dir.path().join("bin").join("aci_edge_agent.dll"),
                b"library fixture",
            )
            .unwrap();
            let trust = bundle::BundleTrust::for_test(
                decode("8f36ab2b3fd94e8d14eae1e5904e6b9be0d43de0dad112009a6ca8b91080f85b"),
                decode("839ee8f3f1e8f507a466946654bf1a255b11a3e20871725ddd2668980b5aaea3"),
            );
            Self { dir, trust }
        }

        fn args(&self, image_option: &str, image: OsString) -> Vec<OsString> {
            vec![
                "--bundle".into(),
                self.dir.path().as_os_str().into(),
                "--state-root".into(),
                self.dir.path().join("state").into_os_string(),
                image_option.into(),
                image,
                "--".into(),
                "printf".into(),
                "hello world".into(),
                "a;$(touch nope)".into(),
                "".into(),
            ]
        }

        fn run(&self) -> Result<(), RunnerError> {
            run(self.args("--image", "alpine".into()), || Ok(()), self.trust)
        }

        fn manifest(&self) -> PathBuf {
            self.dir.path().join("SOURCE-MANIFEST.json")
        }

        fn library(&self) -> PathBuf {
            self.dir.path().join("bin").join("aci_edge_agent.dll")
        }
    }

    fn decode(hex: &str) -> [u8; 32] {
        assert_eq!(hex.len(), 64);
        std::array::from_fn(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
    }

    #[test]
    fn refuses_unsupported_hosts() {
        assert_eq!(validate_host("windows", "x86_64", true), Ok(()));
        for (os, arch, native_x64) in [
            ("windows", "x86_64", false),
            ("windows", "aarch64", false),
            ("windows", "x86", true),
            ("linux", "x86_64", true),
        ] {
            assert_eq!(
                validate_host(os, arch, native_x64),
                Err(format!(
                    "unsupported host or process architecture ({os}/{arch}): native Windows x64 with WHP is required"
                ))
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn runner_reports_optional_host_api_and_native_architecture() {
        use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, HANDLE, SetLastError};
        use windows_sys::Win32::System::SystemInformation::{
            IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64, IMAGE_FILE_MACHINE_UNKNOWN,
        };

        unsafe extern "system" fn native_amd64(
            _: HANDLE,
            process: *mut u16,
            native: *mut u16,
        ) -> i32 {
            // The caller supplies writable pointers for both output values.
            unsafe {
                *process = IMAGE_FILE_MACHINE_UNKNOWN;
                *native = IMAGE_FILE_MACHINE_AMD64;
            }
            1
        }

        unsafe extern "system" fn emulated_amd64(
            _: HANDLE,
            process: *mut u16,
            native: *mut u16,
        ) -> i32 {
            // The caller supplies writable pointers for both output values.
            unsafe {
                *process = IMAGE_FILE_MACHINE_AMD64;
                *native = IMAGE_FILE_MACHINE_ARM64;
            }
            1
        }

        unsafe extern "system" fn failed_query(_: HANDLE, _: *mut u16, _: *mut u16) -> i32 {
            // SetLastError sets this thread's error code for the caller to report.
            unsafe { SetLastError(ERROR_ACCESS_DENIED) };
            0
        }

        let fixture = Fixture::new();
        let args = || fixture.args("--image", "alpine".into());
        assert_eq!(
            run(
                args(),
                || check_windows_host("windows", "x86_64", || Ok(None)),
                fixture.trust,
            ),
            Err(RunnerError::Host(
                "unsupported host: IsWow64Process2 is unavailable; native Windows x64 cannot be verified".into()
            ))
        );
        assert_eq!(
            run(
                args(),
                || check_windows_host("windows", "x86_64", || Ok(Some(native_amd64))),
                fixture.trust,
            ),
            Err(RunnerError::NotImplemented)
        );
        assert_eq!(
            run(
                args(),
                || check_windows_host("windows", "x86_64", || Ok(Some(emulated_amd64))),
                fixture.trust,
            ),
            Err(RunnerError::Host(
                "unsupported host or process architecture (windows/x86_64): native Windows x64 with WHP is required".into()
            ))
        );
        assert_eq!(
            run(
                args(),
                || check_windows_host("windows", "x86_64", || Ok(Some(failed_query))),
                fixture.trust,
            ),
            Err(RunnerError::Host(format!(
                "cannot determine native host architecture: {}",
                std::io::Error::from_raw_os_error(ERROR_ACCESS_DENIED as i32)
            )))
        );
        assert_eq!(
            run(
                args(),
                || check_windows_host("windows", "x86_64", || Err("module lookup failed".into())),
                fixture.trust,
            ),
            Err(RunnerError::Host("module lookup failed".into()))
        );
    }

    #[test]
    fn rejects_repeated_or_mixed_image_selectors() {
        let fixture = Fixture::new();
        let image = fixture.dir.path().join("image.vhd").into_os_string();
        let other_image = fixture.dir.path().join("other.vhd").into_os_string();
        let cases = [
            (
                "--image-file",
                image.clone(),
                "--image",
                OsString::from("alpine"),
            ),
            (
                "--image",
                OsString::from("alpine"),
                "--image-file",
                image.clone(),
            ),
            (
                "--image",
                OsString::from("alpine"),
                "--image",
                OsString::from("ubuntu"),
            ),
            (
                "--image",
                OsString::from("alpine"),
                "--image",
                OsString::from("alpine"),
            ),
            ("--image-file", image.clone(), "--image-file", image.clone()),
            ("--image-file", image, "--image-file", other_image),
        ];
        for (first, first_value, second, second_value) in cases {
            let mut args = fixture.args(first, first_value);
            args.splice(6..6, [OsString::from(second), second_value]);
            assert_eq!(
                run(args, || Ok(()), fixture.trust),
                Err(RunnerError::Arguments(format!(
                    "{second} is repeated or conflicts with another option"
                ))),
                "{first} followed by {second}"
            );
        }
    }

    #[test]
    fn production_runner_refuses_tampered_manifest_and_library() {
        let fixture = Fixture::new();
        assert_eq!(fixture.run(), Err(RunnerError::NotImplemented));

        fs::write(fixture.manifest(), b"modified manifest").unwrap();
        assert_eq!(
            fixture.run(),
            Err(RunnerError::Bundle(format!(
                "SHA-256 mismatch for {}",
                fixture.manifest().display()
            )))
        );
        fs::write(fixture.manifest(), b"manifest fixture").unwrap();
        fs::write(fixture.library(), b"modified library").unwrap();
        assert_eq!(
            fixture.run(),
            Err(RunnerError::Bundle(format!(
                "SHA-256 mismatch for {}",
                fixture.library().display()
            )))
        );
    }

    #[test]
    fn checked_configuration_keeps_the_same_trust_pins() {
        use aci_edge_sandboxes::agent::RuntimeSource;

        let fixture = Fixture::new();
        let state = fixture.dir.path().join("state");
        let config = fixture
            .trust
            .agent_config(fixture.dir.path(), &state)
            .unwrap();
        assert_eq!(config.setup.state_root, state);
        match config.setup.runtime {
            RuntimeSource::Bundle(source) => {
                assert_eq!(source.path, fixture.dir.path());
                assert_eq!(
                    source.manifest_sha256,
                    decode("8f36ab2b3fd94e8d14eae1e5904e6b9be0d43de0dad112009a6ca8b91080f85b")
                );
            }
            _ => panic!("expected bundle source"),
        }
        assert_eq!(config.library, fixture.library());
        assert_eq!(
            config.library_sha256,
            decode("839ee8f3f1e8f507a466946654bf1a255b11a3e20871725ddd2668980b5aaea3")
        );
    }

    #[test]
    fn production_runner_reports_open_failures_for_each_bundle_file() {
        let fixture = Fixture::new();
        fs::remove_file(fixture.manifest()).unwrap();
        let cause = fs::File::open(fixture.manifest()).unwrap_err();
        assert_eq!(
            fixture.run(),
            Err(RunnerError::Bundle(format!(
                "cannot open {}: {cause}",
                fixture.manifest().display()
            )))
        );
        fs::write(fixture.manifest(), b"manifest fixture").unwrap();
        fs::remove_file(fixture.library()).unwrap();
        let cause = fs::File::open(fixture.library()).unwrap_err();
        assert_eq!(
            fixture.run(),
            Err(RunnerError::Bundle(format!(
                "cannot open {}: {cause}",
                fixture.library().display()
            )))
        );
    }

    #[test]
    fn production_runner_accepts_both_image_forms_before_unimplemented_error() {
        let fixture = Fixture::new();
        assert_eq!(fixture.run(), Err(RunnerError::NotImplemented));
        assert_eq!(
            run(
                fixture.args(
                    "--image-file",
                    fixture.dir.path().join("image.vhd").into_os_string()
                ),
                || Ok(()),
                fixture.trust,
            ),
            Err(RunnerError::NotImplemented)
        );
    }

    #[test]
    fn runner_reports_precise_cli_and_host_errors() {
        let fixture = Fixture::new();
        assert_eq!(
            run(
                Vec::<OsString>::new(),
                || panic!("host check must follow parsing"),
                fixture.trust
            ),
            Err(RunnerError::Arguments(
                "missing -- separator before the guest program".into()
            ))
        );
        assert_eq!(
            run(
                fixture.args("--image", "alpine".into()),
                || validate_host("windows", "x86_64", false),
                fixture.trust,
            ),
            Err(RunnerError::Host(
                "unsupported host or process architecture (windows/x86_64): native Windows x64 with WHP is required".into()
            ))
        );
        for (error, message) in [
            (RunnerError::Arguments("bad option".into()), "bad option"),
            (
                RunnerError::Host("unsupported host".into()),
                "unsupported host",
            ),
            (RunnerError::Bundle("bad digest".into()), "bad digest"),
            (RunnerError::NotImplemented, "execution is not implemented"),
        ] {
            assert_eq!(format!("{error}"), format!("aci-image-runner: {message}"));
        }
        assert_eq!(ERROR_EXIT_CODE, 1);
    }

    #[cfg(windows)]
    #[test]
    fn production_runner_rejects_non_unicode_program_and_argument() {
        use std::os::windows::ffi::OsStringExt;

        let fixture = Fixture::new();
        for index in [7, 8] {
            let mut args = fixture.args("--image", "alpine".into());
            args[index] = OsString::from_wide(&[0xD800]);
            assert_eq!(
                run(args, || Ok(()), fixture.trust),
                Err(RunnerError::Arguments(
                    "guest program and arguments must be Unicode".into()
                ))
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn production_runner_accepts_read_only_bundle_files() {
        let fixture = Fixture::new();
        let files = [fixture.manifest(), fixture.library()].map(|path| {
            let original = fs::metadata(&path).unwrap().permissions();
            let mut permissions = original.clone();
            permissions.set_readonly(true);
            fs::set_permissions(&path, permissions).unwrap();
            (path, original)
        });
        let result = fixture.run();
        for (path, permissions) in files {
            fs::set_permissions(path, permissions).unwrap();
        }
        assert_eq!(result, Err(RunnerError::NotImplemented));
    }
}
