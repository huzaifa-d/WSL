// Copyright (C) Microsoft Corporation. All rights reserved.

use std::io::{self, Read, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use aci_edge_sandboxes::{Canceller, ExecOutcome, Execution};

enum WorkerError {
    Io(io::Error),
    Backend(aci_edge_sandboxes::Error),
    Panicked,
}

fn describe_error(stage: &str, error: WorkerError) -> String {
    match error {
        WorkerError::Io(error) => format!("{stage} failed: {}", io_diagnostic(&error)),
        WorkerError::Backend(error) => format!("{stage} failed: {}", crate::backend_error(&error)),
        WorkerError::Panicked => format!("{stage} panicked"),
    }
}

fn io_diagnostic(error: &io::Error) -> String {
    // Only the native OS-error representation has a system-generated message.
    if error.raw_os_error().is_some() {
        format!("{:?}: {error}", error.kind())
    } else {
        format!(
            "{:?} (I/O details suppressed: may contain command or image)",
            error.kind()
        )
    }
}

fn drain<R: Read, W: Write>(mut reader: R, mut writer: W) -> Result<(), WorkerError> {
    let result = catch_unwind(AssertUnwindSafe(|| {
        io::copy(&mut reader, &mut writer)?;
        writer.flush()
    }));
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(WorkerError::Io(error)),
        Err(_) => Err(WorkerError::Panicked),
    }
}

enum Event {
    Output(&'static str, Result<(), WorkerError>),
    Wait(Result<ExecOutcome, WorkerError>),
    Cancel(Result<(), WorkerError>),
}

// Only fault recovery is bounded. A successful guest command has no deadline.
#[cfg(not(test))]
const FAILURE_GRACE: Duration = Duration::from_secs(5);
#[cfg(test)]
const FAILURE_GRACE: Duration = Duration::from_secs(1);

type Job = Box<dyn FnOnce() + Send>;
type Worker = thread::JoinHandle<()>;

fn spawn(name: &str, job: Job) -> io::Result<Worker> {
    thread::Builder::new().name(name.into()).spawn(job)
}

fn request_cancel(
    canceller: Canceller,
    tx: mpsc::Sender<Event>,
    spawn: &impl Fn(&str, Job) -> io::Result<Worker>,
) -> io::Result<Worker> {
    spawn(
        "execution-cancel",
        Box::new(move || {
            let result = catch_unwind(AssertUnwindSafe(|| canceller.cancel()))
                .map_err(|_| WorkerError::Panicked)
                .and_then(|result| result.map_err(WorkerError::Backend));
            drop(canceller);
            let _ = tx.send(Event::Cancel(result));
        }),
    )
}

#[cfg(test)]
pub(crate) fn forward<W: Write + Send + 'static, E: Write + Send + 'static>(
    execution: Execution,
    stdout: W,
    stderr: E,
) -> Result<ExecOutcome, String> {
    forward_with_spawner(execution, stdout, stderr, spawn).into_result()
}

pub(crate) fn forward_safe<W: Write + Send + 'static, E: Write + Send + 'static>(
    execution: Execution,
    stdout: W,
    stderr: E,
) -> Forward {
    forward_with_spawner(execution, stdout, stderr, spawn)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WorkerKind {
    Output(&'static str),
    Wait,
    Cancel,
}

pub(crate) struct Forward {
    rx: mpsc::Receiver<Event>,
    workers: Vec<(WorkerKind, Worker)>,
    pending_output: usize,
    waiting: bool,
    cancelling: bool,
    outcome: Option<ExecOutcome>,
    errors: Vec<String>,
}

impl Forward {
    fn controls_done(&self) -> bool {
        !self.waiting
            && !self.cancelling
            && !self
                .workers
                .iter()
                .any(|(kind, _)| matches!(kind, WorkerKind::Wait | WorkerKind::Cancel))
    }

    fn all_done(&self) -> bool {
        self.controls_done() && self.pending_output == 0 && self.workers.is_empty()
    }

    fn poll(&mut self) {
        if let Ok(event) = self.rx.recv_timeout(Duration::from_millis(20)) {
            match event {
                Event::Output(name, result) => {
                    self.pending_output -= 1;
                    if let Err(error) = result {
                        self.errors
                            .push(describe_error(&format!("{name} forwarding"), error));
                    }
                }
                Event::Wait(result) => {
                    self.waiting = false;
                    match result {
                        Ok(value) => self.outcome = Some(value),
                        Err(error) => self.errors.push(describe_error("execution wait", error)),
                    }
                }
                Event::Cancel(result) => {
                    self.cancelling = false;
                    if let Err(error) = result {
                        self.errors.push(describe_error("cancellation", error));
                    }
                }
            }
        }

        let mut index = 0;
        while index < self.workers.len() {
            if !self.workers[index].1.is_finished() {
                index += 1;
                continue;
            }
            let (kind, worker) = self.workers.swap_remove(index);
            if worker.join().is_err() {
                match kind {
                    WorkerKind::Output(name) => {
                        self.pending_output = self.pending_output.saturating_sub(1);
                        self.errors
                            .push(format!("{name} forwarding thread panicked"));
                    }
                    WorkerKind::Wait => {
                        self.waiting = false;
                        self.errors
                            .push("execution wait thread panicked; outcome unknown".into());
                    }
                    WorkerKind::Cancel => {
                        self.cancelling = false;
                        self.errors.push("cancellation thread panicked".into());
                    }
                }
            }
        }
    }

    pub(crate) fn finish_after_stop(&mut self) -> bool {
        let deadline = Instant::now() + FAILURE_GRACE;
        while !self.all_done() && Instant::now() < deadline {
            self.poll();
        }
        let controls_done = self.controls_done();
        if !controls_done {
            self.errors.push(
                "backend wait or cancellation worker is still active after stop; deprovision and explicit agent close cannot safely proceed".into(),
            );
        }
        if self.pending_output != 0
            || self
                .workers
                .iter()
                .any(|(kind, _)| matches!(kind, WorkerKind::Output(_)))
        {
            self.errors.push("host output forwarding worker did not finish after stop; its writer may be blocked".into());
        }
        controls_done
    }

    pub(crate) fn into_result(mut self) -> Result<ExecOutcome, String> {
        if self.errors.is_empty() {
            Ok(self.outcome.expect("completed wait supplies an outcome"))
        } else {
            if let Some(ExecOutcome::Exited(code)) = self.outcome
                && code != 0
            {
                self.errors.push(format!("guest exited with status {code}"));
            }
            Err(self.errors.join("; "))
        }
    }
}

fn forward_with_spawner<W: Write + Send + 'static, E: Write + Send + 'static>(
    mut execution: Execution,
    stdout: W,
    stderr: E,
    spawn: impl Fn(&str, Job) -> io::Result<Worker>,
) -> Forward {
    let canceller = execution.canceller();
    let stdout_pipe = execution.take_stdout();
    let stderr_pipe = execution.take_stderr();
    let (tx, rx) = mpsc::channel();
    let mut forward = Forward {
        rx,
        workers: Vec::new(),
        pending_output: 0,
        waiting: false,
        cancelling: false,
        outcome: None,
        errors: Vec::new(),
    };
    if stdout_pipe.is_none() || stderr_pipe.is_none() {
        forward
            .errors
            .push("execution output stream was already taken".to_owned());
    }
    macro_rules! start_output {
        ($pipe:expr, $writer:expr, $name:literal) => {
            if let Some(pipe) = $pipe {
                let tx = tx.clone();
                match spawn(
                    concat!($name, "-forward"),
                    Box::new(move || {
                        let _ = tx.send(Event::Output($name, drain(pipe, $writer)));
                    }),
                ) {
                    Ok(worker) => {
                        forward.pending_output += 1;
                        forward.workers.push((WorkerKind::Output($name), worker));
                    }
                    Err(error) => forward.errors.push(format!(
                        "could not start {} forwarding: {}",
                        $name,
                        io_diagnostic(&error)
                    )),
                }
            }
        };
    }
    start_output!(stdout_pipe, stdout, "stdout");
    start_output!(stderr_pipe, stderr, "stderr");

    let wait_tx = tx.clone();
    match spawn(
        "execution-wait",
        Box::new(move || {
            let result = catch_unwind(AssertUnwindSafe(|| execution.wait()))
                .map_err(|_| WorkerError::Panicked)
                .and_then(|result| result.map_err(WorkerError::Backend));
            let _ = wait_tx.send(Event::Wait(result));
        }),
    ) {
        Ok(worker) => {
            forward.waiting = true;
            forward.workers.push((WorkerKind::Wait, worker));
        }
        Err(error) => {
            forward.errors.push(format!(
                "could not start execution wait; outcome unknown: {}",
                io_diagnostic(&error)
            ));
        }
    }
    let mut cancellation_requested = false;
    let mut deadline = None;
    loop {
        if !forward.errors.is_empty() && !cancellation_requested {
            cancellation_requested = true;
            deadline = Some(Instant::now() + FAILURE_GRACE);
            match request_cancel(canceller.clone(), tx.clone(), &spawn) {
                Ok(worker) => {
                    forward.cancelling = true;
                    forward.workers.push((WorkerKind::Cancel, worker));
                }
                Err(error) => forward.errors.push(format!(
                    "could not start cancellation: {}",
                    io_diagnostic(&error)
                )),
            }
        }
        if forward.all_done() {
            break;
        }
        if deadline.is_some_and(|until| Instant::now() >= until) {
            forward.errors.push(format!(
                "fault recovery timed out; execution outcome or stream/cancellation completion is unknown (wait={}, streams={}, cancel={})",
                forward.waiting, forward.pending_output, forward.cancelling
            ));
            break;
        }
        forward.poll();
    }
    forward
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    };
    use std::time::Duration;

    use aci_edge_sandboxes::{
        AciEdgeSandbox, Backend, Capabilities, DeprovisionResult, Error, ExecControl, ExecIo,
        ExecRequest, OutputCloser, ProvisionRequest, ProvisionResult, SandboxId, StartResult,
        StopResult,
        testing::{MockBackend, MockExec},
    };

    const SIZE: usize = 1024 * 1024;
    const CHUNK: usize = 4096;

    struct Shared<T>(Arc<Mutex<T>>);

    impl<T: Default> Default for Shared<T> {
        fn default() -> Self {
            Self(Arc::new(Mutex::new(T::default())))
        }
    }

    impl<T> Clone for Shared<T> {
        fn clone(&self) -> Self {
            Self(self.0.clone())
        }
    }

    impl<T: Write> Write for Shared<T> {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().write(data)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.0.lock().unwrap().flush()
        }
    }

    fn bytes(seed: u8) -> Vec<u8> {
        (0..SIZE).map(|i| (i as u8).wrapping_add(seed)).collect()
    }

    fn execute(backend: impl Backend + 'static) -> Execution {
        let client = AciEdgeSandbox::new(backend);
        let id = client
            .provision(&ProvisionRequest::new())
            .unwrap()
            .sandbox_id;
        client.start(&id).unwrap();
        client.exec(&id, &ExecRequest::argv(["test"])).unwrap()
    }

    fn finish<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            tx.send(f()).ok();
        });
        rx.recv_timeout(Duration::from_secs(10))
            .expect("forwarding did not finish promptly")
    }

    #[test]
    fn mock_backend_forwards_binary_output_without_truncation() {
        let execution = execute(MockBackend::new().with_exec_handler(|_| MockExec {
            stdout: bytes(0),
            stderr: bytes(71),
            ..Default::default()
        }));
        let (result, stdout, stderr) = finish(move || {
            let stdout = Shared::<Vec<u8>>::default();
            let stderr = Shared::<Vec<u8>>::default();
            let result = forward(execution, stdout.clone(), stderr.clone());
            (
                result,
                stdout.0.lock().unwrap().clone(),
                stderr.0.lock().unwrap().clone(),
            )
        });
        assert_eq!(result.unwrap(), ExecOutcome::Exited(0));
        assert_eq!(stdout, bytes(0));
        assert_eq!(stderr, bytes(71));
    }

    #[derive(Debug, Default)]
    struct State {
        done: bool,
        cancelled: bool,
    }

    #[derive(Debug)]
    struct Control {
        state: Arc<(Mutex<State>, Condvar)>,
        closers: Vec<OutputCloser>,
        cancel_calls: Arc<AtomicUsize>,
        fail_cancel: bool,
        fail_wait: bool,
        fail_wait_immediately: bool,
        delay_cancel_until_done: bool,
    }

    impl ExecControl for Control {
        fn wait(&self) -> aci_edge_sandboxes::Result<ExecOutcome> {
            if self.fail_wait_immediately {
                return Err(Error::backend_error("injected immediate wait error"));
            }
            let (lock, changed) = &*self.state;
            let mut state = lock.lock().unwrap();
            while !state.done {
                state = changed.wait(state).unwrap();
            }
            if self.fail_wait {
                Err(Error::backend_error("injected wait error"))
            } else if state.cancelled {
                Ok(ExecOutcome::Cancelled)
            } else {
                Ok(ExecOutcome::Exited(0))
            }
        }

        fn cancel(&self) -> aci_edge_sandboxes::Result<()> {
            self.cancel_calls.fetch_add(1, Ordering::SeqCst);
            if self.delay_cancel_until_done {
                let (lock, changed) = &*self.state;
                let mut state = lock.lock().unwrap();
                while !state.done {
                    state = changed.wait(state).unwrap();
                }
            }
            if self.fail_cancel {
                return Err(Error::backend_error("injected cancel error"));
            }
            let (lock, changed) = &*self.state;
            lock.lock().unwrap().cancelled = true;
            for closer in &self.closers {
                closer.close();
            }
            changed.notify_all();
            Ok(())
        }
    }

    // The public mock supplies lifecycle handling; this backend alternates writes
    // explicitly so the test cannot pass with sequential pipe consumption.
    #[derive(Debug)]
    struct InterleavedBackend {
        mock: MockBackend,
        cancel_calls: Arc<AtomicUsize>,
        linger: bool,
        fail_cancel: bool,
        fail_wait: bool,
        fail_wait_immediately: bool,
        delay_cancel_until_done: bool,
    }

    impl Backend for InterleavedBackend {
        fn name(&self) -> &str {
            "interleaved-test"
        }

        fn capabilities(&self) -> Capabilities {
            self.mock.capabilities()
        }

        fn probe(&self) -> aci_edge_sandboxes::Result<()> {
            self.mock.probe()
        }

        fn provision(
            &self,
            request: &ProvisionRequest,
        ) -> aci_edge_sandboxes::Result<ProvisionResult> {
            self.mock.provision(request)
        }

        fn start(&self, id: &SandboxId) -> aci_edge_sandboxes::Result<StartResult> {
            self.mock.start(id)
        }

        fn stop(&self, id: &SandboxId) -> aci_edge_sandboxes::Result<StopResult> {
            self.mock.stop(id)
        }

        fn deprovision(&self, id: &SandboxId) -> aci_edge_sandboxes::Result<DeprovisionResult> {
            self.mock.deprovision(id)
        }

        fn exec(
            &self,
            _id: &SandboxId,
            _request: &ExecRequest,
            mut io: ExecIo,
        ) -> aci_edge_sandboxes::Result<Box<dyn ExecControl>> {
            let state = Arc::new((Mutex::new(State::default()), Condvar::new()));
            let closers = [io.stdout.close_handle(), io.stderr.close_handle()]
                .into_iter()
                .flatten()
                .collect();
            let control = Control {
                state: state.clone(),
                closers,
                cancel_calls: self.cancel_calls.clone(),
                fail_cancel: self.fail_cancel,
                fail_wait: self.fail_wait,
                fail_wait_immediately: self.fail_wait_immediately,
                delay_cancel_until_done: self.delay_cancel_until_done,
            };
            let linger = self.linger;
            thread::spawn(move || {
                let stdout = bytes(0);
                let stderr = bytes(71);
                for (out, err) in stdout.chunks(CHUNK).zip(stderr.chunks(CHUNK)) {
                    if io.stdout.write(out).is_err() || io.stderr.write(err).is_err() {
                        break;
                    }
                }
                let (lock, changed) = &*state;
                let mut state = lock.lock().unwrap();
                if linger {
                    let (next, _) = changed
                        .wait_timeout_while(state, Duration::from_secs(30), |s| !s.cancelled)
                        .unwrap();
                    state = next;
                }
                state.done = true;
                changed.notify_all();
                drop(io);
            });
            Ok(Box::new(control))
        }
    }

    fn interleaved(
        linger: bool,
        fail_cancel: bool,
        fail_wait: bool,
    ) -> (Execution, Arc<AtomicUsize>) {
        let cancel_calls = Arc::new(AtomicUsize::new(0));
        let backend = InterleavedBackend {
            mock: MockBackend::new(),
            cancel_calls: cancel_calls.clone(),
            linger,
            fail_cancel,
            fail_wait,
            fail_wait_immediately: false,
            delay_cancel_until_done: false,
        };
        (execute(backend), cancel_calls)
    }

    #[test]
    fn interleaved_binary_streams_are_drained_concurrently() {
        let (execution, _) = interleaved(false, false, false);
        let (result, stdout, stderr) = finish(move || {
            let stdout = Shared::<Vec<u8>>::default();
            let stderr = Shared::<Vec<u8>>::default();
            let result = forward(execution, stdout.clone(), stderr.clone());
            (
                result,
                stdout.0.lock().unwrap().clone(),
                stderr.0.lock().unwrap().clone(),
            )
        });
        assert_eq!(result.unwrap(), ExecOutcome::Exited(0));
        assert_eq!(stdout, bytes(0));
        assert_eq!(stderr, bytes(71));
    }

    #[derive(Clone, Default)]
    struct ShortWriter {
        bytes: Vec<u8>,
        interrupted: bool,
        flushed: bool,
    }

    impl Write for ShortWriter {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(io::ErrorKind::Interrupted.into());
            }
            let count = data.len().min(97);
            self.bytes.extend_from_slice(&data[..count]);
            Ok(count)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushed = true;
            Ok(())
        }
    }

    #[test]
    fn handles_short_and_interrupted_writes_and_flushes() {
        let (execution, _) = interleaved(false, false, false);
        let (result, stdout, stderr) = finish(move || {
            let stdout = Shared::<ShortWriter>::default();
            let stderr = Shared::<ShortWriter>::default();
            let result = forward(execution, stdout.clone(), stderr.clone());
            (
                result,
                stdout.0.lock().unwrap().clone(),
                stderr.0.lock().unwrap().clone(),
            )
        });
        assert_eq!(result.unwrap(), ExecOutcome::Exited(0));
        assert!(stdout.flushed && stderr.flushed);
        assert_eq!(stdout.bytes, bytes(0));
        assert_eq!(stderr.bytes, bytes(71));
    }

    #[test]
    fn reports_an_already_taken_stream() {
        let mut execution = execute(MockBackend::new().with_exec_handler(|_| MockExec {
            stdout: bytes(0),
            stderr: bytes(71),
            duration: Duration::from_secs(30),
            ..Default::default()
        }));
        drop(execution.take_stdout());
        let error = finish(move || forward(execution, io::sink(), io::sink())).unwrap_err();
        assert!(error.contains("already taken"), "{error}");
    }

    struct Fails;

    impl Write for Fails {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("injected writer error"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct FlushFails;

    impl Write for FlushFails {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            Ok(data.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("injected flush error"))
        }
    }

    #[test]
    fn writer_failure_cancels_the_live_execution() {
        for fail_stdout in [true, false] {
            let (execution, cancel_calls) = interleaved(true, false, false);
            let result = finish(move || {
                if fail_stdout {
                    forward(execution, Fails, io::sink())
                } else {
                    forward(execution, io::sink(), Fails)
                }
            });
            let error = result.unwrap_err();
            assert!(
                error.contains(if fail_stdout { "stdout" } else { "stderr" }),
                "{error}"
            );
            assert!(error.contains("forwarding failed: Other"), "{error}");
            assert!(cancel_calls.load(Ordering::SeqCst) > 0);
        }
    }

    #[test]
    fn mock_backend_writer_failure_interrupts_long_running_execution() {
        for fail_stdout in [true, false] {
            let execution = execute(MockBackend::new().with_exec_handler(|_| MockExec {
                stdout: bytes(0),
                stderr: bytes(71),
                duration: Duration::from_secs(30),
                ..Default::default()
            }));
            let result = finish(move || {
                if fail_stdout {
                    forward(execution, Fails, io::sink())
                } else {
                    forward(execution, io::sink(), Fails)
                }
            });
            let error = result.unwrap_err();
            assert!(
                error.contains(if fail_stdout { "stdout" } else { "stderr" }),
                "{error}"
            );
            assert!(error.contains("forwarding failed: Other"), "{error}");
        }
    }

    #[test]
    fn flush_failure_is_reported_for_either_stream() {
        for fail_stdout in [true, false] {
            let (execution, cancel_calls) = interleaved(false, false, false);
            let result = finish(move || {
                if fail_stdout {
                    forward(execution, FlushFails, io::sink())
                } else {
                    forward(execution, io::sink(), FlushFails)
                }
            });
            let error = result.unwrap_err();
            assert!(
                error.contains(if fail_stdout { "stdout" } else { "stderr" }),
                "{error}"
            );
            assert!(error.contains("forwarding failed: Other"), "{error}");
            assert!(cancel_calls.load(Ordering::SeqCst) > 0);
        }
    }

    #[test]
    fn failed_cancellation_does_not_block_either_pipe() {
        for fail_stdout in [true, false] {
            let (execution, cancel_calls) = interleaved(false, true, false);
            let result = finish(move || {
                if fail_stdout {
                    forward(execution, Fails, io::sink())
                } else {
                    forward(execution, io::sink(), Fails)
                }
            });
            let error = result.unwrap_err();
            assert!(error.contains("forwarding failed: Other"), "{error}");
            assert!(
                error.contains("cancellation failed: backend_error"),
                "{error}"
            );
            assert!(cancel_calls.load(Ordering::SeqCst) > 0);
        }
    }

    #[test]
    fn cancellation_waiting_for_producer_does_not_block_either_pipe() {
        for fail_stdout in [true, false] {
            let cancel_calls = Arc::new(AtomicUsize::new(0));
            let execution = execute(InterleavedBackend {
                mock: MockBackend::new(),
                cancel_calls: cancel_calls.clone(),
                linger: false,
                fail_cancel: true,
                fail_wait: false,
                fail_wait_immediately: false,
                delay_cancel_until_done: true,
            });
            let result = finish(move || {
                if fail_stdout {
                    forward(execution, Fails, io::sink())
                } else {
                    forward(execution, io::sink(), Fails)
                }
            });
            let error = result.unwrap_err();
            assert!(error.contains("forwarding failed: Other"), "{error}");
            assert!(
                error.contains("cancellation failed: backend_error"),
                "{error}"
            );
            assert!(cancel_calls.load(Ordering::SeqCst) > 0);
        }
    }

    #[test]
    fn cancellation_and_wait_errors_are_not_lost() {
        let (execution, cancel_calls) = interleaved(false, true, true);
        let error = finish(move || forward(execution, Fails, io::sink())).unwrap_err();
        assert!(error.contains("forwarding failed: Other"), "{error}");
        assert!(
            error.contains("cancellation failed: backend_error"),
            "{error}"
        );
        assert!(
            error.contains("execution wait failed: backend_error"),
            "{error}"
        );
        assert!(cancel_calls.load(Ordering::SeqCst) > 0);
    }

    #[test]
    fn failed_cancellation_with_no_backend_completion_is_bounded() {
        let (execution, cancel_calls) = interleaved(true, true, false);
        let error = finish(move || forward(execution, Fails, io::sink())).unwrap_err();
        assert!(error.contains("forwarding failed: Other"), "{error}");
        assert!(
            error.contains("cancellation failed: backend_error"),
            "{error}"
        );
        assert!(
            error.contains("outcome or stream/cancellation completion is unknown"),
            "{error}"
        );
        assert!(cancel_calls.load(Ordering::SeqCst) > 0);
    }

    #[test]
    fn wait_error_with_retained_pipes_and_failed_cancel_is_bounded() {
        let execution = execute(InterleavedBackend {
            mock: MockBackend::new(),
            cancel_calls: Arc::new(AtomicUsize::new(0)),
            linger: true,
            fail_cancel: true,
            fail_wait: false,
            fail_wait_immediately: true,
            delay_cancel_until_done: false,
        });
        let error = finish(move || forward(execution, io::sink(), io::sink())).unwrap_err();
        assert!(
            error.contains("execution wait failed: backend_error"),
            "{error}"
        );
        assert!(
            error.contains("cancellation failed: backend_error"),
            "{error}"
        );
        assert!(error.contains("unknown"), "{error}");
    }

    #[test]
    fn stream_failure_retains_nonzero_guest_outcome() {
        let execution = execute(MockBackend::new().with_exec_handler(|_| MockExec {
            stdout: vec![1],
            outcome: Some(ExecOutcome::Exited(7)),
            ..Default::default()
        }));
        let error = finish(move || forward(execution, FlushFails, io::sink())).unwrap_err();
        assert!(error.contains("forwarding failed: Other"), "{error}");
        assert!(error.contains("guest exited with status 7"), "{error}");
    }

    #[test]
    fn short_secret_does_not_corrupt_stream_error_stage() {
        let execution = execute(MockBackend::new().with_exec_handler(|_| MockExec {
            stdout: vec![1],
            ..Default::default()
        }));
        let error =
            finish(move || forward_safe(execution, Fails, io::sink()).into_result()).unwrap_err();
        assert!(error.contains("stdout forwarding failed:"), "{error}");
        assert!(!error.contains("injected writer error"), "{error}");
    }

    #[test]
    fn io_diagnostics_distinguish_os_and_untrusted_errors() {
        let os_error = io::Error::from_raw_os_error(2);
        assert_eq!(
            io_diagnostic(&os_error),
            format!("{:?}: {os_error}", os_error.kind())
        );
        for secret in ["e", "private\"argument\\line\n"] {
            let detail = format!("raw={secret}; debug={secret:?}");
            let error = io::Error::other(detail);
            assert_eq!(
                io_diagnostic(&error),
                "Other (I/O details suppressed: may contain command or image)"
            );
        }
    }

    #[test]
    fn backend_worker_errors_suppress_raw_debug_and_source_details() {
        for secret in ["e", "private\"argument\\line\n"] {
            for stage in ["execution wait", "cancellation"] {
                let detail = format!("raw={secret}; debug={secret:?}");
                let error =
                    Error::backend_error(detail.clone()).with_source(io::Error::other(detail));
                assert_eq!(
                    describe_error(stage, WorkerError::Backend(error)),
                    format!(
                        "{stage} failed: backend_error (backend details suppressed: may contain command or image)"
                    )
                );
            }
        }
    }

    #[test]
    fn panic_hook_reports_caught_worker_panics_without_payload() {
        const CHILD: &str = "ACI_RUNNER_PANIC_TEST_CHILD";
        if std::env::var_os(CHILD).is_some() {
            crate::install_panic_hook();
            struct PanicWriter;
            impl Write for PanicWriter {
                fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                    let secret = "private\"argument\\line\n";
                    panic!("raw={secret}; debug={secret:?}");
                }
                fn flush(&mut self) -> io::Result<()> {
                    Ok(())
                }
            }
            let error = drain(&b"data"[..], PanicWriter).err().unwrap();
            eprintln!("{}", describe_error("stdout forwarding", error));
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "streams::tests::panic_hook_reports_caught_worker_panics_without_payload",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(output.status.success());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            stderr.contains("details suppressed: may contain command or image"),
            "{stderr}"
        );
        assert!(stderr.contains("streams.rs:"), "{stderr}");
        assert!(stderr.contains("stdout forwarding panicked"), "{stderr}");
        assert!(!stderr.contains("raw="), "{stderr}");
        assert!(!stderr.contains("debug="), "{stderr}");
    }

    #[test]
    fn worker_and_cancellation_start_failures_cannot_enter_blocking_drain() {
        for failed_thread in [
            "stdout-forward",
            "stderr-forward",
            "execution-wait",
            "execution-cancel",
        ] {
            let (execution, _) = interleaved(true, true, false);
            let error = finish(move || {
                forward_with_spawner(execution, Fails, io::sink(), |name, job| {
                    if name == failed_thread {
                        Err(io::Error::other("injected thread startup error"))
                    } else {
                        spawn(name, job)
                    }
                })
                .into_result()
            })
            .unwrap_err();
            assert!(
                error.contains("Other (I/O details suppressed: may contain command or image)"),
                "{failed_thread}: {error}"
            );
            assert!(error.contains("unknown"), "{failed_thread}: {error}");
        }
    }
}
