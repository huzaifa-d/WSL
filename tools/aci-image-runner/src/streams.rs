// Copyright (C) Microsoft Corporation. All rights reserved.

use mxc_sdk::v1::{MxcProcess, WaitResult};
use std::io::{self, Read, Write};
use std::thread::{self, JoinHandle};
use std::time::Duration;

type Worker = (&'static str, JoinHandle<io::Result<()>>);

fn pump(mut reader: impl Read, mut writer: impl Write) -> io::Result<()> {
    io::copy(&mut reader, &mut writer)?;
    writer.flush()
}

fn start(
    name: &'static str,
    reader: Box<dyn Read + Send>,
    writer: impl Write + Send + 'static,
) -> io::Result<Worker> {
    thread::Builder::new()
        .name(format!("{name}-forward"))
        .spawn(move || pump(reader, writer))
        .map(|worker| (name, worker))
}

fn collect(worker: Worker, errors: &mut Vec<String>) {
    match worker.1.join() {
        Ok(Ok(())) => {}
        Ok(Err(error)) => errors.push(format!("{} forwarding failed: {error}", worker.0)),
        Err(_) => errors.push(format!("{} forwarding thread panicked", worker.0)),
    }
}

fn close_streams(process: &MxcProcess) {
    if let Some(closer) = process.stdout_closer() {
        closer.close();
    }
    if let Some(closer) = process.stderr_closer() {
        closer.close();
    }
}

fn stop_after_setup_failure(
    process: &mut MxcProcess,
    workers: Vec<Worker>,
    mut errors: Vec<String>,
) -> String {
    close_streams(process);
    match process.kill() {
        Ok(()) => {
            if let Err(error) = process.wait_detailed() {
                errors.push(format!("process wait failed: {error}"));
            }
        }
        Err(error) => errors.push(format!("process kill failed: {error}")),
    }
    for worker in workers {
        collect(worker, &mut errors);
    }
    errors.join("; ")
}

pub fn forward(
    process: &mut MxcProcess,
    stdout: impl Write + Send + 'static,
    stderr: impl Write + Send + 'static,
) -> Result<WaitResult, String> {
    let stdout_reader = match process.take_stdout() {
        Some(reader) => reader,
        None => {
            return Err(stop_after_setup_failure(
                process,
                Vec::new(),
                vec!["stdout is unavailable".into()],
            ));
        }
    };
    let stderr_reader = match process.take_stderr() {
        Some(reader) => reader,
        None => {
            return Err(stop_after_setup_failure(
                process,
                Vec::new(),
                vec!["stderr is unavailable".into()],
            ));
        }
    };
    let stdout_worker = match start("stdout", stdout_reader, stdout) {
        Ok(worker) => worker,
        Err(error) => {
            return Err(stop_after_setup_failure(
                process,
                Vec::new(),
                vec![format!("cannot start stdout forwarding: {error}")],
            ));
        }
    };
    let stderr_worker = match start("stderr", stderr_reader, stderr) {
        Ok(worker) => worker,
        Err(error) => {
            return Err(stop_after_setup_failure(
                process,
                vec![stdout_worker],
                vec![format!("cannot start stderr forwarding: {error}")],
            ));
        }
    };
    let mut workers = vec![stdout_worker, stderr_worker];
    let mut errors = Vec::new();
    let mut outcome = None;
    let mut kill_requested = false;
    loop {
        let mut index = 0;
        while index < workers.len() {
            if workers[index].1.is_finished() {
                collect(workers.swap_remove(index), &mut errors);
            } else {
                index += 1;
            }
        }
        if !errors.is_empty() && outcome.is_none() && !kill_requested {
            kill_requested = true;
            if let Err(error) = process.kill() {
                errors.push(format!("process kill failed: {error}"));
                close_streams(process);
                break;
            }
        }
        if outcome.is_none() {
            match process.try_wait_detailed() {
                Ok(Some(result)) => outcome = Some(result),
                Ok(None) => {}
                Err(error) => {
                    errors.push(format!("process wait failed: {error}"));
                    if !kill_requested && let Err(error) = process.kill() {
                        errors.push(format!("process kill failed: {error}"));
                    }
                    close_streams(process);
                    break;
                }
            }
        }
        if outcome.is_some() && workers.is_empty() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    for worker in workers {
        collect(worker, &mut errors);
    }
    if !errors.is_empty() {
        Err(errors.join("; "))
    } else {
        outcome.ok_or_else(|| "process outcome is unavailable".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pump_preserves_binary_bytes() {
        let input = [0, 0xff, b'\n', 0x80];
        let mut output = Vec::new();
        pump(input.as_slice(), &mut output).unwrap();
        assert_eq!(output, input);
    }
}
