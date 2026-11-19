// Copyright (C) Microsoft Corporation. All rights reserved.

use aci_edge_sandboxes::{
    AciEdgeSandbox, ErrorCode, ExecOutcome, ExecRequest, ProvisionRequest, SandboxId, StdinMode,
};
use std::io::Write;

pub(crate) struct Completed {
    pub(crate) sandbox_id: SandboxId,
    pub(crate) exit_code: i32,
}

pub(crate) struct Lifecycle {
    pub(crate) result: Result<Completed, String>,
    pub(crate) backend_safe_to_close: bool,
}

pub(crate) fn execute<W: Write + Send + 'static, E: Write + Send + 'static>(
    client: &AciEdgeSandbox,
    argv: Vec<String>,
    stdout: W,
    stderr: E,
    redact: &impl Fn(String) -> String,
) -> Lifecycle {
    let mut backend_safe_to_close = true;
    let result = (|| {
        let capabilities = client.capabilities();
        if !capabilities.exec.argv {
            return Err("backend does not support exact argv execution".into());
        }
        if !capabilities.exec.cancel {
            return Err("backend does not support execution cancellation".into());
        }
        client
            .probe()
            .map_err(|error| format!("probe: {}", redact(crate::error_chain(&error))))?;

        let id = client
            .provision(&ProvisionRequest::new())
            .map_err(|error| format!("provision: {}", redact(crate::error_chain(&error))))?
            .sandbox_id;

        let mut started = false;
        let mut forwarding = None;
        let mut execution = match client.start(&id) {
            Ok(_) => {
                started = true;
                let request = ExecRequest::argv(argv).with_stdin(StdinMode::Null);
                client
                    .exec(&id, &request)
                    .map_err(|error| format!("exec: {}", redact(crate::error_chain(&error))))
                    .map(|execution| {
                        forwarding = Some(crate::streams::forward_redacted(
                            execution, stdout, stderr, redact,
                        ));
                        0
                    })
            }
            Err(error) => Err(format!("start: {}", redact(crate::error_chain(&error)))),
        };

        let stopped = match client.stop(&id) {
            Ok(_) => Ok(()),
            Err(error) if !started && error.code() == ErrorCode::AlreadyStopped => Ok(()),
            Err(error) => Err(format!("stop: {}", redact(crate::error_chain(&error)))),
        };
        if let Some(mut forwarding) = forwarding {
            backend_safe_to_close = forwarding.finish_after_stop(redact);
            execution = forwarding
                .into_result()
                .map_err(|error| format!("execution: {error}"))
                .and_then(|outcome| match outcome {
                    ExecOutcome::Exited(code) => Ok(code),
                    outcome => Err(format!("execution: {}", redact(outcome.to_string()))),
                });
        }
        let deprovisioned = if stopped.is_ok() && backend_safe_to_close {
            client
                .deprovision(&id)
                .map(|_| ())
                .map_err(|error| format!("deprovision: {}", redact(crate::error_chain(&error))))
        } else {
            Ok(())
        };

        let mut failures = Vec::new();
        if let Err(error) = &execution {
            failures.push(error.clone());
        }
        if let Err(error) = stopped {
            failures.push(error);
        }
        if let Err(error) = deprovisioned {
            failures.push(error);
        }
        if failures.is_empty() {
            execution.map(|exit_code| Completed {
                sandbox_id: id,
                exit_code,
            })
        } else {
            if let Ok(code) = execution
                && code != 0
            {
                failures.insert(0, format!("guest exited with status {code}"));
            }
            Err(format!("sandbox {id}: {}", failures.join("; ")))
        }
    })();
    Lifecycle {
        result,
        backend_safe_to_close,
    }
}
