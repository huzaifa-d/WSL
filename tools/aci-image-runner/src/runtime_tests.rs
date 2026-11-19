// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;
use aci_edge_sandboxes::agent::{Hypervisor, RuntimeSource};
use aci_edge_sandboxes::testing::{MockBackend, MockExec};
use aci_edge_sandboxes::{
    Capabilities, Command, DeprovisionResult, Error, ExecControl, ExecIo, ExecOutcome, ExecRequest,
    ProvisionRequest, ProvisionResult, SandboxId, StartResult, StdinMode, StopResult,
};
use std::io;
use std::sync::{Condvar, Mutex};
use std::time::Duration;

#[derive(Debug, Clone, Copy)]
enum CancelBehavior {
    Fail,
    EndAfterStop,
    WaitForRelease,
}

#[derive(Debug, Default)]
struct GateState {
    stopped: bool,
    released: bool,
}

#[derive(Debug)]
struct Gate {
    state: Mutex<GateState>,
    changed: Condvar,
    cancel: CancelBehavior,
    wait_for_release: bool,
}

impl Gate {
    fn new(cancel: CancelBehavior) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(GateState::default()),
            changed: Condvar::new(),
            cancel,
            wait_for_release: false,
        })
    }

    fn with_stalled_wait() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(GateState::default()),
            changed: Condvar::new(),
            cancel: CancelBehavior::EndAfterStop,
            wait_for_release: true,
        })
    }

    fn signal_stop(&self) {
        self.state.lock().unwrap().stopped = true;
        self.changed.notify_all();
    }

    fn release(&self) {
        self.state.lock().unwrap().released = true;
        self.changed.notify_all();
    }
}

#[derive(Debug, Default)]
struct State {
    events: Vec<&'static str>,
    faults: Vec<&'static str>,
    id: Option<String>,
    request: Option<ExecRequest>,
    exit_code: i32,
    image: Option<ImageSource>,
    cancels: usize,
    detail: String,
    gate: Option<Arc<Gate>>,
}

#[derive(Debug)]
struct Fake {
    mock: MockBackend,
    state: Arc<Mutex<State>>,
}

impl Fake {
    fn step(&self, name: &'static str) -> aci_edge_sandboxes::Result<()> {
        let mut state = self.state.lock().unwrap();
        state.events.push(name);
        if state.faults.contains(&name) {
            Err(
                Error::backend_error(format!("{name} failed {}", state.detail))
                    .with_source(io::Error::other(format!("source {}", state.detail))),
            )
        } else {
            Ok(())
        }
    }
}

impl Backend for Fake {
    fn name(&self) -> &str {
        "fake"
    }
    fn capabilities(&self) -> Capabilities {
        let mut caps = self.mock.capabilities();
        let mut state = self.state.lock().unwrap();
        state.events.push("capabilities");
        caps.exec.argv = !state.faults.contains(&"argv");
        caps.exec.cancel = !state.faults.contains(&"cancel");
        caps
    }
    fn probe(&self) -> aci_edge_sandboxes::Result<()> {
        self.step("probe")
    }
    fn provision(&self, request: &ProvisionRequest) -> aci_edge_sandboxes::Result<ProvisionResult> {
        self.step("provision")?;
        let result = self.mock.provision(request)?;
        self.state.lock().unwrap().id = Some(result.sandbox_id.to_string());
        Ok(result)
    }
    fn start(&self, id: &SandboxId) -> aci_edge_sandboxes::Result<StartResult> {
        self.step("start")?;
        self.mock.start(id)
    }
    fn exec(
        &self,
        id: &SandboxId,
        request: &ExecRequest,
        mut io: ExecIo,
    ) -> aci_edge_sandboxes::Result<Box<dyn ExecControl>> {
        self.step("exec")?;
        assert!(io.stdin.is_none());
        self.state.lock().unwrap().request = Some(request.clone());
        let gate = self.state.lock().unwrap().gate.clone();
        if let Some(gate) = gate {
            io.stdout
                .write(b"out")
                .map_err(|error| Error::backend_error(error.to_string()))?;
            io.stderr
                .write(b"err")
                .map_err(|error| Error::backend_error(error.to_string()))?;
            return Ok(Box::new(GatedControl {
                state: self.state.clone(),
                gate,
                streams: Mutex::new(Some(io)),
            }));
        }
        let inner = self.mock.exec(id, request, io)?;
        Ok(Box::new(RecordingControl {
            inner,
            state: self.state.clone(),
        }))
    }
    fn stop(&self, id: &SandboxId) -> aci_edge_sandboxes::Result<StopResult> {
        let result = self.step("stop");
        if let Some(gate) = self.state.lock().unwrap().gate.clone() {
            gate.signal_stop();
        }
        result?;
        if self
            .state
            .lock()
            .unwrap()
            .faults
            .contains(&"already_stopped")
        {
            return Err(Error::already_stopped("injected already stopped"));
        }
        self.mock.stop(id)
    }
    fn deprovision(&self, id: &SandboxId) -> aci_edge_sandboxes::Result<DeprovisionResult> {
        self.step("deprovision")?;
        self.mock.deprovision(id)
    }
}

struct GatedControl {
    state: Arc<Mutex<State>>,
    gate: Arc<Gate>,
    streams: Mutex<Option<ExecIo>>,
}

impl Drop for GatedControl {
    fn drop(&mut self) {
        self.state.lock().unwrap().events.push("control-drop");
    }
}

impl ExecControl for GatedControl {
    fn wait(&self) -> aci_edge_sandboxes::Result<ExecOutcome> {
        self.state.lock().unwrap().events.push("wait-enter");
        let mut gate = self.gate.state.lock().unwrap();
        while !gate.released && (!gate.stopped || self.gate.wait_for_release) {
            gate = self.gate.changed.wait(gate).unwrap();
        }
        drop(gate);
        drop(self.streams.lock().unwrap().take());
        self.state.lock().unwrap().events.push("wait-end");
        Err(Error::backend_error("late wait failure"))
    }

    fn cancel(&self) -> aci_edge_sandboxes::Result<()> {
        self.state.lock().unwrap().events.push("cancel-enter");
        let mut gate = self.gate.state.lock().unwrap();
        match self.gate.cancel {
            CancelBehavior::Fail => {}
            CancelBehavior::EndAfterStop => {
                while !gate.stopped && !gate.released {
                    gate = self.gate.changed.wait(gate).unwrap();
                }
            }
            CancelBehavior::WaitForRelease => {
                while !gate.released {
                    gate = self.gate.changed.wait(gate).unwrap();
                }
            }
        }
        drop(gate);
        self.state.lock().unwrap().events.push("cancel-end");
        Err(Error::backend_error("late cancel failure"))
    }
}

struct RecordingControl {
    inner: Box<dyn ExecControl>,
    state: Arc<Mutex<State>>,
}

impl ExecControl for RecordingControl {
    fn wait(&self) -> aci_edge_sandboxes::Result<ExecOutcome> {
        self.inner.wait()
    }
    fn cancel(&self) -> aci_edge_sandboxes::Result<()> {
        self.state.lock().unwrap().cancels += 1;
        self.inner.cancel()
    }
    fn wait_unacknowledged(&self) -> aci_edge_sandboxes::Result<ExecOutcome> {
        self.inner.wait_unacknowledged()
    }
    fn acknowledge_wait(&self) {
        self.inner.acknowledge_wait()
    }
    fn abandon(&self) {
        self.inner.abandon()
    }
}

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);
impl Write for Capture {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct FailWriter;
impl Write for FailWriter {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("writer failed"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct FlushFail;
impl Write for FlushFail {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("flush failed"))
    }
}

fn fixture() -> (tempfile::TempDir, BundleTrust) {
    use sha2::{Digest, Sha256};
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("bin")).unwrap();
    std::fs::write(dir.path().join("SOURCE-MANIFEST.json"), b"manifest").unwrap();
    std::fs::write(
        dir.path().join("bin").join("aci_edge_agent.dll"),
        b"library",
    )
    .unwrap();
    let trust = BundleTrust::for_test(
        Sha256::digest(b"manifest").into(),
        Sha256::digest(b"library").into(),
    );
    (dir, trust)
}

fn invoke<W: Write + Send + 'static, E: Write + Send + 'static>(
    state: Arc<Mutex<State>>,
    image: (&str, OsString),
    stdout: W,
    stderr: E,
) -> Result<i32, RunnerError> {
    invoke_with_command(
        state,
        image,
        stdout,
        stderr,
        vec![
            "printf".into(),
            "hello world".into(),
            "a;$(touch nope)".into(),
            "\"quoted\"".into(),
        ],
    )
}

fn invoke_with_command<W: Write + Send + 'static, E: Write + Send + 'static>(
    state: Arc<Mutex<State>>,
    image: (&str, OsString),
    stdout: W,
    stderr: E,
    command: Vec<OsString>,
) -> Result<i32, RunnerError> {
    let (dir, trust) = fixture();
    let mut args = vec![
        "--bundle".into(),
        dir.path().into(),
        "--state-root".into(),
        dir.path().join("state").into(),
        image.0.into(),
        image.1,
        "--".into(),
    ];
    args.extend(command);
    run_with(
        args,
        || Ok(()),
        trust,
        |config| {
            assert_eq!(config.setup.hypervisor, Some(Hypervisor::Whp));
            assert!(config.setup.platform_snapshots.is_none());
            assert!(matches!(config.setup.runtime, RuntimeSource::Bundle(_)));
            config.setup.validate().unwrap();
            state.lock().unwrap().image = config.setup.defaults.image.clone();
            let worker_state = state.clone();
            let mock = MockBackend::new().with_exec_handler(move |_| MockExec {
                stdout: vec![0, 0xff, b'a'],
                stderr: vec![0xfe, b'b'],
                outcome: Some(ExecOutcome::Exited(worker_state.lock().unwrap().exit_code)),
                ..MockExec::default()
            });
            let backend = Arc::new(Fake {
                mock,
                state: state.clone(),
            });
            Ok((backend, move |backend: Arc<Fake>| {
                assert!(
                    Arc::try_unwrap(backend).is_ok(),
                    "client must be dropped before close"
                );
                let mut state = state.lock().unwrap();
                state.events.push("close");
                if state.faults.contains(&"close") {
                    Err(AgentFailure::Backend(Error::backend_error(format!(
                        "close failed {}",
                        state.detail
                    ))))
                } else {
                    Ok(())
                }
            }))
        },
        || Ok((stdout, stderr)),
    )
}

fn run_case(
    faults: &[&'static str],
    exit_code: i32,
) -> (Result<i32, RunnerError>, Arc<Mutex<State>>) {
    let state = Arc::new(Mutex::new(State {
        faults: faults.to_vec(),
        exit_code,
        ..State::default()
    }));
    let result = invoke(
        state.clone(),
        ("--image", "example".into()),
        io::sink(),
        io::sink(),
    );
    (result, state)
}

#[test]
fn production_path_preserves_arguments_streams_stdin_and_exit_status() {
    for exit_code in [0, 7] {
        let state = Arc::new(Mutex::new(State {
            exit_code,
            ..State::default()
        }));
        let stdout = Capture::default();
        let stderr = Capture::default();
        assert_eq!(
            invoke(
                state.clone(),
                ("--image", "example".into()),
                stdout.clone(),
                stderr.clone()
            ),
            Ok(exit_code)
        );
        assert_eq!(*stdout.0.lock().unwrap(), [0, 0xff, b'a']);
        assert_eq!(*stderr.0.lock().unwrap(), [0xfe, b'b']);
        let state = state.lock().unwrap();
        assert_eq!(
            state.events,
            [
                "capabilities",
                "probe",
                "capabilities",
                "provision",
                "start",
                "capabilities",
                "exec",
                "stop",
                "deprovision",
                "close"
            ]
        );
        let request = state.request.as_ref().unwrap();
        assert_eq!(
            request.process.command,
            Command::Argv(vec![
                "printf".into(),
                "hello world".into(),
                "a;$(touch nope)".into(),
                "\"quoted\"".into()
            ])
        );
        assert!(matches!(request.stdin, StdinMode::Null));
        assert!(
            matches!(&state.image, Some(ImageSource::Reference(reference)) if reference == "example")
        );
    }
}

#[test]
fn image_file_is_passed_as_the_default_path() {
    let state = Arc::new(Mutex::new(State::default()));
    let path = std::env::current_dir().unwrap().join("an image.vhd");
    assert_eq!(
        invoke(
            state.clone(),
            ("--image-file", path.clone().into_os_string()),
            io::sink(),
            io::sink()
        ),
        Ok(0)
    );
    assert!(
        matches!(&state.lock().unwrap().image, Some(ImageSource::Path(actual)) if *actual == path)
    );
}

#[test]
fn lifecycle_failures_keep_cleanup_order_and_sandbox_id() {
    for (fault, events) in [
        ("probe", &["capabilities", "probe", "close"][..]),
        (
            "provision",
            &[
                "capabilities",
                "probe",
                "capabilities",
                "provision",
                "close",
            ],
        ),
        (
            "start",
            &[
                "capabilities",
                "probe",
                "capabilities",
                "provision",
                "start",
                "stop",
                "deprovision",
                "close",
            ],
        ),
        (
            "exec",
            &[
                "capabilities",
                "probe",
                "capabilities",
                "provision",
                "start",
                "capabilities",
                "exec",
                "stop",
                "deprovision",
                "close",
            ],
        ),
        (
            "stop",
            &[
                "capabilities",
                "probe",
                "capabilities",
                "provision",
                "start",
                "capabilities",
                "exec",
                "stop",
                "close",
            ],
        ),
        (
            "deprovision",
            &[
                "capabilities",
                "probe",
                "capabilities",
                "provision",
                "start",
                "capabilities",
                "exec",
                "stop",
                "deprovision",
                "close",
            ],
        ),
        (
            "close",
            &[
                "capabilities",
                "probe",
                "capabilities",
                "provision",
                "start",
                "capabilities",
                "exec",
                "stop",
                "deprovision",
                "close",
            ],
        ),
    ] {
        let (result, state) = run_case(&[fault], 0);
        let message = result.unwrap_err().to_string();
        let stage = if fault == "close" {
            "close agent"
        } else {
            fault
        };
        assert!(
            message.contains(&format!("{stage}: backend_error")),
            "{message}"
        );
        let state = state.lock().unwrap();
        assert_eq!(state.events, events, "{fault}");
        if let Some(id) = &state.id {
            assert!(message.contains(id), "{fault}: {message}");
        }
    }
}

#[test]
fn failed_start_and_cleanup_and_close_are_all_reported() {
    let (result, state) = run_case(&["start", "deprovision", "close"], 0);
    let message = result.unwrap_err().to_string();
    for text in [
        "start: backend_error",
        "deprovision: backend_error",
        "close agent: backend_error",
    ] {
        assert!(message.contains(text), "{message}");
    }
    assert_eq!(
        state.lock().unwrap().events,
        [
            "capabilities",
            "probe",
            "capabilities",
            "provision",
            "start",
            "stop",
            "deprovision",
            "close"
        ]
    );
}

#[test]
fn already_stopped_only_permits_cleanup_after_failed_start() {
    let (result, state) = run_case(&["already_stopped"], 0);
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("stop: already_stopped")
    );
    assert!(!state.lock().unwrap().events.contains(&"deprovision"));
    let (result, state) = run_case(&["start", "already_stopped"], 0);
    assert!(result.is_err());
    assert!(state.lock().unwrap().events.contains(&"deprovision"));
}

#[test]
fn unsupported_argv_or_cancel_never_provisions_and_always_closes() {
    for fault in ["argv", "cancel"] {
        let (result, state) = run_case(&[fault], 0);
        assert!(result.is_err());
        assert_eq!(state.lock().unwrap().events, ["capabilities", "close"]);
    }
}

#[test]
fn output_failure_still_stops_deprovisions_and_closes() {
    for (stream, flush) in [
        ("stdout", false),
        ("stderr", false),
        ("stdout", true),
        ("stderr", true),
    ] {
        let state = Arc::new(Mutex::new(State::default()));
        let result = match (stream, flush) {
            ("stdout", false) => invoke(
                state.clone(),
                ("--image", "example".into()),
                FailWriter,
                io::sink(),
            ),
            ("stderr", false) => invoke(
                state.clone(),
                ("--image", "example".into()),
                io::sink(),
                FailWriter,
            ),
            ("stdout", true) => invoke(
                state.clone(),
                ("--image", "example".into()),
                FlushFail,
                io::sink(),
            ),
            _ => invoke(
                state.clone(),
                ("--image", "example".into()),
                io::sink(),
                FlushFail,
            ),
        };
        let error = result.unwrap_err().to_string();
        assert!(error.contains(stream), "{error}");
        assert!(error.contains("forwarding failed: Other"), "{error}");
        let state = state.lock().unwrap();
        assert!(state.cancels > 0);
        assert_eq!(
            state.events,
            [
                "capabilities",
                "probe",
                "capabilities",
                "provision",
                "start",
                "capabilities",
                "exec",
                "stop",
                "deprovision",
                "close"
            ]
        );
    }
}

fn position(events: &[&str], event: &str) -> usize {
    events
        .iter()
        .position(|candidate| *candidate == event)
        .unwrap_or_else(|| panic!("missing {event}: {events:?}"))
}

#[test]
fn stopped_backend_workers_finish_before_deprovision_and_close() {
    for (behavior, stop_fails) in [
        (CancelBehavior::Fail, false),
        (CancelBehavior::EndAfterStop, false),
        (CancelBehavior::EndAfterStop, true),
    ] {
        let gate = Gate::new(behavior);
        let state = Arc::new(Mutex::new(State {
            faults: if stop_fails {
                vec!["stop", "close"]
            } else {
                vec!["close"]
            },
            gate: Some(gate),
            ..State::default()
        }));
        let error = invoke(
            state.clone(),
            ("--image", "example".into()),
            FailWriter,
            io::sink(),
        )
        .unwrap_err()
        .to_string();
        for expected in [
            "stdout forwarding failed: Other",
            "execution wait failed: backend_error",
            "cancellation failed: backend_error",
            "close agent: backend_error",
        ] {
            assert!(error.contains(expected), "{behavior:?}: {error}");
        }
        let state = state.lock().unwrap();
        let events = &state.events;
        assert!(
            position(events, "stop") < position(events, "wait-end"),
            "{events:?}"
        );
        if matches!(behavior, CancelBehavior::EndAfterStop) {
            assert!(
                position(events, "stop") < position(events, "cancel-end"),
                "{events:?}"
            );
        }
        assert!(
            position(events, "wait-end") < position(events, "control-drop"),
            "{events:?}"
        );
        assert!(
            position(events, "cancel-end") < position(events, "control-drop"),
            "{events:?}"
        );
        assert!(
            position(events, "control-drop") < position(events, "close"),
            "{events:?}"
        );
        assert_eq!(events.iter().filter(|event| **event == "close").count(), 1);
        if stop_fails {
            assert!(error.contains("stop: backend_error"), "{error}");
            assert!(!events.contains(&"deprovision"), "{events:?}");
        } else {
            assert!(
                position(events, "control-drop") < position(events, "deprovision"),
                "{events:?}"
            );
            assert!(
                position(events, "deprovision") < position(events, "close"),
                "{events:?}"
            );
        }
    }
}

#[test]
fn stuck_cancel_retains_backend_and_skips_deprovision_and_close() {
    let gate = Gate::new(CancelBehavior::WaitForRelease);
    let state = Arc::new(Mutex::new(State {
        gate: Some(gate.clone()),
        ..State::default()
    }));
    let error = invoke(
        state.clone(),
        ("--image", "example".into()),
        FailWriter,
        io::sink(),
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("stdout forwarding failed: Other"), "{error}");
    assert!(
        error.contains("execution wait failed: backend_error"),
        "{error}"
    );
    assert!(
        error.contains("backend wait or cancellation worker is still active"),
        "{error}"
    );
    assert!(error.contains("close agent skipped"), "{error}");
    {
        let state = state.lock().unwrap();
        assert!(state.events.contains(&"stop"));
        assert!(!state.events.contains(&"deprovision"));
        assert!(!state.events.contains(&"close"));
        assert!(error.contains(state.id.as_ref().unwrap()));
    }
    gate.release();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !state.lock().unwrap().events.contains(&"control-drop") {
        assert!(
            std::time::Instant::now() < deadline,
            "released test worker did not finish"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!state.lock().unwrap().events.contains(&"close"));
}

#[test]
fn stuck_wait_retains_backend_and_does_not_hide_the_unknown_outcome() {
    let gate = Gate::with_stalled_wait();
    let state = Arc::new(Mutex::new(State {
        gate: Some(gate.clone()),
        ..State::default()
    }));
    let error = invoke(
        state.clone(),
        ("--image", "example".into()),
        FailWriter,
        io::sink(),
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("stdout forwarding failed: Other"), "{error}");
    assert!(
        error.contains("cancellation failed: backend_error"),
        "{error}"
    );
    assert!(
        error.contains("outcome") && error.contains("unknown"),
        "{error}"
    );
    assert!(error.contains("close agent skipped"), "{error}");
    assert!(
        error.contains("late execution and close errors cannot be collected"),
        "{error}"
    );
    {
        let state = state.lock().unwrap();
        assert!(state.events.contains(&"stop"));
        assert!(state.events.contains(&"cancel-end"));
        assert!(!state.events.contains(&"wait-end"));
        assert!(!state.events.contains(&"deprovision"));
        assert!(!state.events.contains(&"close"));
        assert!(error.contains(state.id.as_ref().unwrap()));
    }
    gate.release();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !state.lock().unwrap().events.contains(&"control-drop") {
        assert!(
            std::time::Instant::now() < deadline,
            "released test worker did not finish"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!state.lock().unwrap().events.contains(&"close"));
}

#[derive(Default)]
struct HostWriterState {
    entered: bool,
    released: bool,
}

#[derive(Clone, Default)]
struct HostWriterGate(Arc<(Mutex<HostWriterState>, Condvar)>);

struct BlockingWriter(HostWriterGate);
impl Write for BlockingWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let (lock, changed) = &*self.0.0;
        let mut state = lock.lock().unwrap();
        state.entered = true;
        changed.notify_all();
        while !state.released {
            state = changed.wait(state).unwrap();
        }
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct FailAfterWriterBlocks(HostWriterGate);
impl Write for FailAfterWriterBlocks {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        let (lock, changed) = &*self.0.0;
        let mut state = lock.lock().unwrap();
        while !state.entered {
            let (next, timeout) = changed.wait_timeout(state, Duration::from_secs(5)).unwrap();
            state = next;
            if timeout.timed_out() {
                return Err(io::Error::other("host writer never blocked"));
            }
        }
        Err(io::Error::other("stderr writer failed"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn blocked_host_writer_does_not_prevent_safe_backend_close() {
    let gate = Gate::new(CancelBehavior::EndAfterStop);
    let host = HostWriterGate::default();
    let state = Arc::new(Mutex::new(State {
        gate: Some(gate),
        ..State::default()
    }));
    let error = invoke(
        state.clone(),
        ("--image", "example".into()),
        BlockingWriter(host.clone()),
        FailAfterWriterBlocks(host.clone()),
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("stderr forwarding failed: Other"), "{error}");
    assert!(
        error.contains("host output forwarding worker did not finish"),
        "{error}"
    );
    {
        let state = state.lock().unwrap();
        let events = &state.events;
        assert!(
            position(events, "control-drop") < position(events, "deprovision"),
            "{events:?}"
        );
        assert!(
            position(events, "deprovision") < position(events, "close"),
            "{events:?}"
        );
        assert_eq!(events.iter().filter(|event| **event == "close").count(), 1);
    }
    let (lock, changed) = &*host.0;
    lock.lock().unwrap().released = true;
    changed.notify_all();
}

#[test]
fn primary_and_cleanup_errors_redact_raw_and_escaped_guest_values() {
    let state = Arc::new(Mutex::new(State {
        faults: vec!["exec", "stop", "close"],
        detail: "hello world \"\\\"quoted\\\"\" example".into(),
        ..State::default()
    }));
    let error = invoke(
        state.clone(),
        ("--image", "example".into()),
        io::sink(),
        io::sink(),
    )
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("exec:") && error.contains("stop:") && error.contains("close agent:"),
        "{error}"
    );
    for secret in ["hello world", "example", "\\\"quoted\\\""] {
        assert!(!error.contains(secret), "{error}");
    }
    let state = state.lock().unwrap();
    assert!(!state.events.contains(&"deprovision"));
    assert!(error.contains(state.id.as_ref().unwrap()));
}

#[test]
fn all_backend_stages_suppress_short_and_escaped_details() {
    for detail in ["e", "private\"argument\\line\n"] {
        let image = if detail == "e" {
            "e"
        } else {
            "private.example/image"
        };
        for fault in [
            "probe",
            "provision",
            "start",
            "exec",
            "stop",
            "deprovision",
            "close",
        ] {
            let state = Arc::new(Mutex::new(State {
                faults: vec![fault],
                detail: format!("raw={detail}; debug={detail:?}; image={image}"),
                ..State::default()
            }));
            let error = invoke_with_command(
                state.clone(),
                ("--image", image.into()),
                io::sink(),
                io::sink(),
                vec!["printf".into(), detail.into()],
            )
            .unwrap_err()
            .to_string();
            let stage = if fault == "close" {
                "close agent"
            } else {
                fault
            };
            assert!(error.contains(&format!("{stage}: backend_error (backend details suppressed: may contain command or image)")), "{error}");
            assert!(!error.contains("raw="), "{error}");
            assert!(!error.contains("debug="), "{error}");
            assert!(!error.contains("source "), "{error}");
            assert!(!error.contains("image="), "{error}");
            if detail.len() > 1 {
                assert!(!error.contains(detail), "{error}");
                assert!(!error.contains(&format!("{detail:?}")), "{error}");
            }
            if let Some(id) = &state.lock().unwrap().id {
                assert!(error.contains(id), "{error}");
            }
        }
    }
}
