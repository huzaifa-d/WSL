// Copyright (C) Microsoft Corporation. All rights reserved.

use crate::ffi::WslcAciBytes;
use crate::request::AciOneShot;
use aci_edge_sandboxes::agent::{AgentBackend, BundledAgent, ImageDigest};
use aci_edge_sandboxes::{
    AciEdgeSandbox, Canceller, ErrorCode, ExecOutcome, Execution, ImageSource, SandboxId,
};
use mxc_sdk::mxc_common::filesystem_security::{
    LockedDirectoryPath, lock_owner_only_directory_path,
};
use std::ffi::{OsStr, OsString, c_void};
use std::fmt::Write as _;
use std::io::PipeReader;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::IntoRawHandle;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::ptr;
use std::slice;
use std::sync::{Arc, Mutex};

struct Host {
    backend: Option<Arc<AgentBackend>>,
    client: Option<AciEdgeSandbox>,
    sandbox: Option<SandboxId>,
    started: bool,
    _state: LockedDirectoryPath,
}

impl Host {
    fn open(local_app_data: PathBuf) -> Result<Self, String> {
        let bundle = BundledAgent::discover().map_err(|error| error.to_string())?;
        let mut bundle_key = String::new();
        for byte in &bundle.manifest_sha256()[..8] {
            write!(&mut bundle_key, "{byte:02x}").map_err(|error| error.to_string())?;
        }
        let state = lock_owner_only_directory_path(
            &local_app_data,
            &[OsStr::new("wslc-aci"), OsStr::new(&bundle_key)],
            0,
        )
        .map_err(|error| error.to_string())?;
        let config = bundle.config(bundle.setup(state.path()));
        let backend = Arc::new(AgentBackend::new(config).map_err(|error| error.to_string())?);
        let client = AciEdgeSandbox::from_shared(backend.clone());
        Ok(Self {
            backend: Some(backend),
            client: Some(client),
            sandbox: None,
            started: false,
            _state: state,
        })
    }

    fn start(&mut self, input: AciOneShot) -> Result<Execution, String> {
        let reference = match input.provision.spec.image.as_ref() {
            Some(ImageSource::Reference(reference)) => reference,
            _ => return Err("an image reference is required".into()),
        };
        let backend = self.backend.as_ref().ok_or("ACI host is closed")?;
        backend
            .register_reference(reference, ImageDigest::Compute)
            .map_err(|error| format!("cannot register image: {error}"))?;

        let client = self.client.as_ref().ok_or("ACI host is closed")?;
        let provisioned = client
            .provision_with(&input.provision.request, &input.provision.spec)
            .map_err(|error| {
                format!("cannot provision sandbox; its state may be unknown: {error}")
            })?;
        self.sandbox = Some(provisioned.sandbox_id);
        let sandbox = self.sandbox.as_ref().ok_or("sandbox is unavailable")?;
        self.started = true;
        client
            .start(sandbox)
            .map_err(|error| format!("cannot start sandbox: {error}"))?;
        client
            .exec(sandbox, &input.exec)
            .map_err(|error| format!("cannot start command: {error}"))
    }

    fn cleanup(&mut self) -> Result<(), String> {
        let mut errors = Vec::new();
        if let (Some(client), Some(sandbox)) = (&self.client, &self.sandbox) {
            if self.started {
                match client.stop(sandbox) {
                    Ok(_) => self.started = false,
                    Err(error) if error.code() == ErrorCode::AlreadyStopped => self.started = false,
                    Err(error) => errors.push(format!("cannot stop sandbox: {error}")),
                }
            }
            if !self.started {
                match client.deprovision(sandbox) {
                    Ok(_) => self.sandbox = None,
                    Err(error) => errors.push(format!("cannot remove sandbox: {error}")),
                }
            }
        }
        drop(self.client.take());
        if let Some(backend) = self.backend.take() {
            match Arc::try_unwrap(backend) {
                Ok(backend) => {
                    if let Err(error) = backend.close() {
                        errors.push(format!("cannot close ACI host: {error}"));
                    }
                }
                Err(_) => {
                    errors.push("ACI host still has active owners; cleanup is unknown".into())
                }
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

struct Running {
    host: Host,
    execution: Execution,
}

fn output_streams(
    stdout: Option<PipeReader>,
    stderr: Option<PipeReader>,
) -> Option<(PipeReader, PipeReader)> {
    stdout.zip(stderr)
}

pub struct WslcAciRun {
    running: Mutex<Option<Running>>,
    canceller: Mutex<Option<Canceller>>,
}

impl WslcAciRun {
    fn cancel(&self) -> Result<(), String> {
        let canceller = self
            .canceller
            .lock()
            .map_err(|_| "cannot access cancellation state")?
            .clone()
            .ok_or("the command is no longer running")?;
        canceller
            .cancel()
            .map_err(|error| format!("cannot cancel command: {error}"))
    }

    fn finish(&self, cancel_first: bool) -> Result<Option<i32>, String> {
        let mut errors = Vec::new();
        let running = match self.running.lock() {
            Ok(mut running) => running.take(),
            Err(poisoned) => {
                errors.push("command state was poisoned".to_string());
                poisoned.into_inner().take()
            }
        };
        let Some(Running {
            mut host,
            execution,
        }) = running
        else {
            return if !errors.is_empty() {
                Err(errors.join("; "))
            } else if cancel_first {
                Ok(None)
            } else {
                Err("the command result was already collected".into())
            };
        };

        if cancel_first && let Err(error) = self.cancel() {
            errors.push(error);
        }
        let outcome = execution.wait();
        if outcome.is_err()
            && !cancel_first
            && let Err(error) = self.cancel()
        {
            errors.push(error);
        }
        let canceller = match self.canceller.lock() {
            Ok(mut canceller) => canceller.take(),
            Err(poisoned) => {
                errors.push("cancellation state was poisoned".to_string());
                poisoned.into_inner().take()
            }
        };
        drop(canceller);
        if let Err(error) = host.cleanup() {
            errors.push(error);
        }

        let code = match outcome {
            Ok(ExecOutcome::Exited(code)) => Some(code),
            Ok(ExecOutcome::TimedOut) => {
                errors.push("workload timed out".into());
                None
            }
            Ok(ExecOutcome::Cancelled) if cancel_first => None,
            Ok(ExecOutcome::Cancelled) => {
                errors.push("workload was cancelled".into());
                None
            }
            Ok(other) => {
                errors.push(format!("workload did not exit normally: {other}"));
                None
            }
            Err(error) => {
                errors.push(format!(
                    "cannot wait for workload; its outcome may be unknown: {error}"
                ));
                None
            }
        };
        if errors.is_empty() {
            Ok(code)
        } else {
            Err(errors.join("; "))
        }
    }
}

fn start(
    input: &[u8],
    local_app_data: &[u16],
) -> Result<(WslcAciRun, *mut c_void, *mut c_void), String> {
    let input: AciOneShot =
        serde_json::from_slice(input).map_err(|_| "invalid translated ACI request")?;
    let base = PathBuf::from(OsString::from_wide(local_app_data));
    let mut host = Host::open(base)?;
    let mut execution = match host.start(input) {
        Ok(execution) => execution,
        Err(error) => {
            return match host.cleanup() {
                Ok(()) => Err(error),
                Err(cleanup) => Err(format!("{error}; {cleanup}")),
            };
        }
    };
    let canceller = execution.canceller();
    let stdout = execution.take_stdout();
    let stderr = execution.take_stderr();
    match output_streams(stdout, stderr) {
        Some((stdout, stderr)) => Ok((
            WslcAciRun {
                running: Mutex::new(Some(Running { host, execution })),
                canceller: Mutex::new(Some(canceller)),
            },
            stdout.into_raw_handle(),
            stderr.into_raw_handle(),
        )),
        None => {
            let mut errors = vec!["ACI output streams are unavailable".to_string()];
            if let Err(error) = canceller.cancel() {
                errors.push(format!("cannot cancel command: {error}"));
            }
            if let Err(error) = execution.wait() {
                errors.push(format!("cannot wait for command: {error}"));
            }
            drop(canceller);
            if let Err(error) = host.cleanup() {
                errors.push(error);
            }
            Err(errors.join("; "))
        }
    }
}

fn ffi_result<T>(
    result: Result<Result<T, String>, Box<dyn std::any::Any + Send>>,
    error: *mut WslcAciBytes,
) -> Option<T> {
    match result {
        Ok(Ok(value)) => Some(value),
        Ok(Err(message)) => {
            unsafe { ptr::write(error, WslcAciBytes::from_vec(message.into_bytes())) };
            None
        }
        Err(_) => {
            unsafe {
                ptr::write(
                    error,
                    WslcAciBytes::from_vec(
                        b"ACI operation failed unexpectedly; cleanup may be incomplete".to_vec(),
                    ),
                )
            };
            None
        }
    }
}

/// # Safety
///
/// Inputs must be readable for their lengths and output pointers must be writable and distinct.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wslc_aci_start(
    request: *const u8,
    request_length: usize,
    local_app_data: *const u16,
    local_app_data_length: usize,
    run: *mut *mut WslcAciRun,
    stdout: *mut *mut c_void,
    stderr: *mut *mut c_void,
    error: *mut WslcAciBytes,
) -> i32 {
    if run.is_null() || stdout.is_null() || stderr.is_null() || error.is_null() {
        return 1;
    }
    unsafe {
        ptr::write(run, ptr::null_mut());
        ptr::write(stdout, ptr::null_mut());
        ptr::write(stderr, ptr::null_mut());
        ptr::write(error, WslcAciBytes::empty());
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        if request.is_null()
            || local_app_data.is_null()
            || request_length > isize::MAX as usize
            || local_app_data_length > isize::MAX as usize / size_of::<u16>()
        {
            return Err("invalid ACI request buffer".into());
        }
        let request = unsafe { slice::from_raw_parts(request, request_length) };
        let local_app_data =
            unsafe { slice::from_raw_parts(local_app_data, local_app_data_length) };
        start(request, local_app_data)
    }));
    match ffi_result(result, error) {
        Some((operation, out, err)) => {
            unsafe {
                ptr::write(run, Box::into_raw(Box::new(operation)));
                ptr::write(stdout, out);
                ptr::write(stderr, err);
            }
            0
        }
        None => 1,
    }
}

/// # Safety
///
/// `run` must be a live operation returned by `wslc_aci_start`, and outputs must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wslc_aci_wait(
    run: *mut WslcAciRun,
    exit_code: *mut i32,
    error: *mut WslcAciBytes,
) -> i32 {
    if run.is_null() || exit_code.is_null() || error.is_null() {
        return 1;
    }
    unsafe { ptr::write(error, WslcAciBytes::empty()) };
    let result = catch_unwind(AssertUnwindSafe(|| unsafe { &*run }.finish(false)));
    match ffi_result(result, error) {
        Some(Some(code)) => {
            unsafe { ptr::write(exit_code, code) };
            0
        }
        Some(None) => {
            unsafe {
                ptr::write(
                    error,
                    WslcAciBytes::from_vec(b"workload outcome is unavailable".to_vec()),
                )
            };
            1
        }
        None => 1,
    }
}

/// # Safety
///
/// `run` must remain live for the duration of this call, and `error` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wslc_aci_cancel(run: *mut WslcAciRun, error: *mut WslcAciBytes) -> i32 {
    if run.is_null() || error.is_null() {
        return 1;
    }
    unsafe { ptr::write(error, WslcAciBytes::empty()) };
    let result = catch_unwind(AssertUnwindSafe(|| unsafe { &*run }.cancel()));
    i32::from(ffi_result(result, error).is_none())
}

/// # Safety
///
/// `run` must be an unfreed operation returned by `wslc_aci_start`. No calls may be in flight.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wslc_aci_release(run: *mut WslcAciRun, error: *mut WslcAciBytes) -> i32 {
    if run.is_null() || error.is_null() {
        return 1;
    }
    unsafe { ptr::write(error, WslcAciBytes::empty()) };
    let run = unsafe { Box::from_raw(run) };
    let result = catch_unwind(AssertUnwindSafe(|| run.finish(true)));
    i32::from(ffi_result(result, error).is_none())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Write};

    #[test]
    fn closes_any_partial_output_before_cleanup() {
        for stdout_is_present in [true, false] {
            let (reader, mut writer) = io::pipe().unwrap();
            let streams = if stdout_is_present {
                output_streams(Some(reader), None)
            } else {
                output_streams(None, Some(reader))
            };
            assert!(streams.is_none());
            assert!(writer.write_all(b"data").is_err());
        }
    }
}
