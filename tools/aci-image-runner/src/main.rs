// Copyright (C) Microsoft Corporation. All rights reserved.

mod arguments;
mod bundle;
mod lifecycle;
mod output;
mod streams;

#[cfg(test)]
mod runtime_tests;
use aci_edge_sandboxes::agent::{AgentBackend, AgentConfig, SandboxDefaults};
use aci_edge_sandboxes::{AciEdgeSandbox, Backend, ImageSource};
use arguments::{Arguments, Image};
use bundle::BundleTrust;
use std::ffi::OsString;
use std::fmt;
use std::io::Write;
use std::sync::Arc;

const ERROR_EXIT_CODE: i32 = 1;

#[derive(Debug, PartialEq, Eq)]
enum RunnerError {
    Arguments(String),
    Host(String),
    Bundle(String),
    Runtime(String),
}

enum AgentFailure {
    Backend(aci_edge_sandboxes::Error),
    StillOwned,
}

impl AgentFailure {
    fn diagnostic(&self) -> String {
        match self {
            Self::Backend(error) => backend_error(error),
            Self::StillOwned => "agent backend still has owners".to_owned(),
        }
    }
}

fn backend_error(error: &aci_edge_sandboxes::Error) -> String {
    format!(
        "{} (backend details suppressed: may contain command or image)",
        error.code().as_str()
    )
}

impl fmt::Display for RunnerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Arguments(message)
            | Self::Host(message)
            | Self::Bundle(message)
            | Self::Runtime(message) => {
                write!(formatter, "aci-image-runner: {message}")
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
    use windows_sys::Win32::System::LibraryLoader::GetProcAddress;

    resolve_is_wow64_process2_with(|module, name| {
        // The resolver supplies a pinned module and the named export's valid C string.
        let address = unsafe { GetProcAddress(module, name) };
        // The named export has the IsWow64Process2 Windows ABI declared above.
        address.map(|function| unsafe {
            std::mem::transmute::<unsafe extern "system" fn() -> isize, IsWow64Process2Fn>(function)
        })
    })
}

#[cfg(windows)]
fn resolve_is_wow64_process2_with(
    find: impl FnOnce(
        windows_sys::Win32::Foundation::HMODULE,
        windows_sys::core::PCSTR,
    ) -> Option<IsWow64Process2Fn>,
) -> Result<Option<IsWow64Process2Fn>, String> {
    use windows_sys::Win32::System::LibraryLoader::{
        GET_MODULE_HANDLE_EX_FLAG_PIN, GetModuleHandleExA,
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

    Ok(find(module, c"IsWow64Process2".as_ptr().cast()))
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
) -> Result<i32, RunnerError> {
    run_with(
        args,
        host_check,
        trust,
        |config| {
            let backend = Arc::new(AgentBackend::new(config).map_err(AgentFailure::Backend)?);
            Ok((backend, |backend: Arc<AgentBackend>| {
                Arc::try_unwrap(backend)
                    .map_err(|_| AgentFailure::StillOwned)?
                    .close()
                    .map_err(AgentFailure::Backend)
            }))
        },
        output::writers,
    )
}

fn run_with<B, C, W, E>(
    args: impl IntoIterator<Item = OsString>,
    host_check: impl FnOnce() -> Result<(), String>,
    trust: BundleTrust,
    open: impl FnOnce(AgentConfig) -> Result<(Arc<B>, C), AgentFailure>,
    prepare_output: impl FnOnce() -> Result<(W, E), String>,
) -> Result<i32, RunnerError>
where
    B: Backend + 'static,
    C: FnOnce(Arc<B>) -> Result<(), AgentFailure>,
    W: Write + Send + 'static,
    E: Write + Send + 'static,
{
    let args = Arguments::parse(args).map_err(RunnerError::Arguments)?;
    host_check().map_err(RunnerError::Host)?;
    let mut config = trust
        .agent_config(&args.bundle, &args.state_root)
        .map_err(RunnerError::Bundle)?;
    let image = match args.image {
        Image::Reference(reference) => ImageSource::Reference(reference),
        Image::File(path) => ImageSource::Path(path),
    };
    config.setup = config
        .setup
        .with_defaults(SandboxDefaults::default().with_image(image));
    config
        .setup
        .validate()
        .map_err(|error| RunnerError::Runtime(format!("setup: {}", backend_error(&error))))?;
    let (stdout, stderr) =
        prepare_output().map_err(|error| RunnerError::Runtime(format!("output: {error}")))?;
    // AgentBackend::new may discard a host-close failure after opening the host.
    let (backend, close) = open(config).map_err(|error| {
        RunnerError::Runtime(format!(
            "open agent: {}; agent host cleanup status may be unknown",
            error.diagnostic()
        ))
    })?;
    let client = AciEdgeSandbox::from_shared(backend.clone());
    let lifecycle = lifecycle::execute(&client, args.command, stdout, stderr);
    drop(client);
    if !lifecycle.backend_safe_to_close {
        // Dropping AgentBackend would implicitly close the host while its control worker is active.
        std::mem::forget(backend);
        let detail = match lifecycle.result {
            Ok(completed) => format!(
                "sandbox {}: guest exited with status {}",
                completed.sandbox_id, completed.exit_code
            ),
            Err(error) => error,
        };
        return Err(RunnerError::Runtime(format!(
            "{detail}; close agent skipped: backend retained until process exit; late execution and close errors cannot be collected"
        )));
    }
    let closed = close(backend).map_err(|error| error.diagnostic());
    match (lifecycle.result, closed) {
        (Ok(completed), Ok(())) => Ok(completed.exit_code),
        (Err(error), Ok(())) => Err(RunnerError::Runtime(error)),
        (Ok(completed), Err(error)) if completed.exit_code != 0 => {
            Err(RunnerError::Runtime(format!(
                "sandbox {}: guest exited with status {}; close agent: {error}",
                completed.sandbox_id, completed.exit_code,
            )))
        }
        (Ok(completed), Err(error)) => Err(RunnerError::Runtime(format!(
            "sandbox {}: close agent: {error}",
            completed.sandbox_id
        ))),
        (Err(primary), Err(error)) => Err(RunnerError::Runtime(format!(
            "{primary}; close agent: {error}"
        ))),
    }
}

fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let mut stderr = std::io::stderr().lock();
        if let Some(location) = info.location() {
            let _ = write!(stderr, "aci-image-runner: panic at {location}; ");
        } else {
            let _ = write!(stderr, "aci-image-runner: panic; ");
        }
        let _ = writeln!(stderr, "details suppressed: may contain command or image");
    }));
}

fn main() {
    install_panic_hook();
    match run(
        std::env::args_os().skip(1),
        check_current_host,
        BundleTrust::approved(),
    ) {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(ERROR_EXIT_CODE);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aci_edge_sandboxes::testing::MockBackend;
    use std::ffi::OsString;
    use std::fs;
    use std::path::PathBuf;

    type MockOpenResult = Result<
        (
            Arc<MockBackend>,
            fn(Arc<MockBackend>) -> Result<(), AgentFailure>,
        ),
        AgentFailure,
    >;

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
                "\"quoted\"".into(),
            ]
        }

        fn run(&self) -> Result<i32, RunnerError> {
            Self::run_fake(self.args("--image", "alpine".into()), || Ok(()), self.trust)
        }

        fn run_fake(
            args: impl IntoIterator<Item = OsString>,
            host_check: impl FnOnce() -> Result<(), String>,
            trust: BundleTrust,
        ) -> Result<i32, RunnerError> {
            run_with(
                args,
                host_check,
                trust,
                |_| {
                    Ok((
                        Arc::new(aci_edge_sandboxes::testing::MockBackend::new()),
                        |backend: Arc<aci_edge_sandboxes::testing::MockBackend>| {
                            assert!(Arc::try_unwrap(backend).is_ok());
                            Ok(())
                        },
                    ))
                },
                || Ok((std::io::sink(), std::io::sink())),
            )
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
    fn backend_error_suppresses_message_and_source() {
        let error = aci_edge_sandboxes::Error::backend_error("secret")
            .with_source(std::io::Error::other("secret source"));
        assert_eq!(
            backend_error(&error),
            "backend_error (backend details suppressed: may contain command or image)"
        );
    }

    #[test]
    fn agent_initialization_failure_reports_uncertain_cleanup_and_redacts_values() {
        let fixture = Fixture::new();
        for (secret, image) in [("e", "e"), ("secret\"argument", "private.example/image")] {
            let mut args = fixture.args("--image", image.into());
            args.push(secret.into());
            let result = run_with(
                args,
                || Ok(()),
                fixture.trust,
                |_| -> MockOpenResult {
                    Err(AgentFailure::Backend(
                        aci_edge_sandboxes::Error::backend_error(format!(
                            "startup failure: raw={secret}; debug={secret:?}; image={image}"
                        )),
                    ))
                },
                || Ok((std::io::sink(), std::io::sink())),
            );
            assert_eq!(
                result,
                Err(RunnerError::Runtime(
                    "open agent: backend_error (backend details suppressed: may contain command or image); agent host cleanup status may be unknown".into()
                ))
            );
        }
    }

    #[test]
    fn actual_agent_constructor_failure_reports_uncertain_cleanup() {
        let fixture = Fixture::new();
        let error = run(
            fixture.args("--image", "alpine".into()),
            || Ok(()),
            fixture.trust,
        )
        .unwrap_err();
        let RunnerError::Runtime(message) = error else {
            panic!("expected agent startup error, got {error:?}");
        };
        assert!(message.starts_with("open agent: "), "{message}");
        assert!(
            message.ends_with("; agent host cleanup status may be unknown"),
            "{message}"
        );
        assert_ne!(
            message,
            "open agent: ; agent host cleanup status may be unknown"
        );
    }

    #[test]
    fn failures_before_agent_initialization_do_not_report_uncertain_cleanup() {
        fn never_open(_: AgentConfig) -> MockOpenResult {
            panic!("agent constructor must not run")
        }

        let fixture = Fixture::new();
        let args = || fixture.args("--image", "alpine".into());
        let arguments_error = run_with(
            Vec::<OsString>::new(),
            || panic!("host check must not run"),
            fixture.trust,
            never_open,
            || Ok((std::io::sink(), std::io::sink())),
        )
        .unwrap_err();
        assert_eq!(
            arguments_error,
            RunnerError::Arguments("missing -- separator before the guest program".into())
        );

        let host_error = run_with(
            args(),
            || Err("host check failed".into()),
            fixture.trust,
            never_open,
            || Ok((std::io::sink(), std::io::sink())),
        )
        .unwrap_err();
        assert_eq!(host_error, RunnerError::Host("host check failed".into()));

        fs::remove_file(fixture.manifest()).unwrap();
        let bundle_error = run_with(
            args(),
            || Ok(()),
            fixture.trust,
            never_open,
            || Ok((std::io::sink(), std::io::sink())),
        )
        .unwrap_err();
        assert!(matches!(bundle_error, RunnerError::Bundle(_)));
        assert!(!bundle_error.to_string().contains("cleanup status"));
        fs::write(fixture.manifest(), b"manifest fixture").unwrap();

        let setup_error = run_with(
            fixture.args("--image", "invalid reference".into()),
            || Ok(()),
            fixture.trust,
            never_open,
            || -> Result<(std::io::Sink, std::io::Sink), String> {
                panic!("output setup must not run")
            },
        )
        .unwrap_err();
        assert!(setup_error.to_string().contains("setup: malformed_request (backend details suppressed: may contain command or image)"), "{setup_error}");
        assert!(!setup_error.to_string().contains("invalid reference"));
        assert!(!setup_error.to_string().contains("cleanup status"));

        let output_error = run_with(
            args(),
            || Ok(()),
            fixture.trust,
            never_open,
            || -> Result<(std::io::Sink, std::io::Sink), String> {
                Err("output unavailable".into())
            },
        )
        .unwrap_err();
        assert_eq!(
            output_error,
            RunnerError::Runtime("output: output unavailable".into())
        );
    }

    #[test]
    fn empty_guest_argument_is_rejected_before_host_check() {
        let fixture = Fixture::new();
        for index in [8, 9, 10] {
            let mut args = fixture.args("--image", "alpine".into());
            args[index] = "".into();
            assert_eq!(
                run(args, || panic!("host check must not run"), fixture.trust),
                Err(RunnerError::Arguments(
                    "empty guest arguments are not supported".into()
                ))
            );
        }
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
    fn production_runner_rejects_32_bit_windows_before_bundle() {
        use windows_sys::Win32::Foundation::HANDLE;
        use windows_sys::Win32::System::SystemInformation::{
            IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_I386,
        };

        unsafe extern "system" fn x86_on_x64(
            _: HANDLE,
            process: *mut u16,
            native: *mut u16,
        ) -> i32 {
            // The caller supplies writable pointers for both output values.
            unsafe {
                *process = IMAGE_FILE_MACHINE_I386;
                *native = IMAGE_FILE_MACHINE_AMD64;
            }
            1
        }

        let fixture = Fixture::new();
        fs::remove_file(fixture.manifest()).unwrap();
        let error = run(
            fixture.args("--image", "alpine".into()),
            || check_windows_host("windows", "x86", || Ok(Some(x86_on_x64))),
            fixture.trust,
        )
        .unwrap_err();
        let message = "unsupported host or process architecture (windows/x86): native Windows x64 with WHP is required";
        assert_eq!(error, RunnerError::Host(message.into()));
        assert_eq!(error.to_string(), format!("aci-image-runner: {message}"));
        assert_eq!(ERROR_EXIT_CODE, 1);
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
        let error = run(
            args(),
            || {
                check_windows_host("windows", "x86_64", || {
                    resolve_is_wow64_process2_with(|module, name| {
                        assert!(!module.is_null());
                        // The resolver supplies a valid, NUL-terminated export name.
                        assert_eq!(
                            unsafe { std::ffi::CStr::from_ptr(name.cast()) },
                            c"IsWow64Process2"
                        );
                        None
                    })
                })
            },
            fixture.trust,
        )
        .unwrap_err();
        let message = "unsupported host: IsWow64Process2 is unavailable; native Windows x64 cannot be verified";
        assert_eq!(error, RunnerError::Host(message.into()));
        assert_eq!(error.to_string(), format!("aci-image-runner: {message}"));
        assert_eq!(ERROR_EXIT_CODE, 1);
        assert_eq!(
            Fixture::run_fake(
                args(),
                || check_windows_host("windows", "x86_64", || Ok(Some(native_amd64))),
                fixture.trust,
            ),
            Ok(0)
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
        assert_eq!(fixture.run(), Ok(0));

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
    fn production_runner_accepts_both_image_forms() {
        let fixture = Fixture::new();
        assert_eq!(fixture.run(), Ok(0));
        assert_eq!(
            Fixture::run_fake(
                fixture.args(
                    "--image-file",
                    fixture.dir.path().join("image.vhd").into_os_string()
                ),
                || Ok(()),
                fixture.trust,
            ),
            Ok(0)
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
            (
                RunnerError::Runtime("runtime failure".into()),
                "runtime failure",
            ),
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
        assert_eq!(result, Ok(0));
    }
}
