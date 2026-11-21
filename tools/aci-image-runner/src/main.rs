// Copyright (C) Microsoft Corporation. All rights reserved.

mod arguments;
mod output;
mod streams;

use arguments::Arguments;
use mxc_sdk::mxc_contract::dev::{self as contract, OneShotContainment, Request};
use mxc_sdk::v1::{WaitResult, dev};
use std::ffi::OsString;

fn validate_scope(json: &str) -> Result<(), String> {
    match contract::parse_request(json).map_err(|error| error.to_string())? {
        Request::OneShot(request)
            if matches!(
                request.containment.as_ref(),
                Some(OneShotContainment::Microvm)
            ) =>
        {
            Ok(())
        }
        Request::OneShot(_) => Err("only one-shot MicroVM containment is supported".into()),
        _ => Err("lifecycle phase requests are not supported".into()),
    }
}

fn run(args: impl IntoIterator<Item = OsString>) -> Result<i32, String> {
    let args = Arguments::parse(args)?;
    let json = std::fs::read_to_string(&args.config)
        .map_err(|error| format!("cannot read config file: {error}"))?;
    validate_scope(&json)?;
    let (stdout, stderr) = output::writers()?;
    let mut process = dev::spawn_json(&json, dev::JsonOptions { experimental: true })
        .map_err(|error| error.to_string())?;
    let result = streams::forward(&mut process, stdout, stderr)?;
    for warning in process.warnings() {
        eprintln!("aci-image-runner: {warning}");
    }
    match result {
        WaitResult::Exited(code) => Ok(code),
        WaitResult::TimedOut => Err("workload timed out".into()),
    }
}

fn main() {
    match run(std::env::args_os().skip(1)) {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("aci-image-runner: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_accepts_only_one_shot_microvm() {
        let one_shot = r#"{"version":"1.1.0-alpha","containment":"microvm","microvm":{"image":"example.com/repo:tag"},"process":{"commandLine":"true"}}"#;
        assert!(validate_scope(one_shot).is_ok());
        for json in [
            r#"{"version":"1.1.0-alpha","containment":"process","process":{"commandLine":"true"}}"#,
            r#"{"version":"1.1.0-alpha","process":{"commandLine":"true"}}"#,
            r#"{"version":"1.1.0-alpha","phase":"start","sandboxId":"microvm:00000000000000000000000000000000"}"#,
            r#"{"version":"1.1.0-alpha","containment":"microvm","microvm":{"image":"example.com/repo:tag"},"process":{"commandLine":"true"},"unknown":true}"#,
        ] {
            assert!(validate_scope(json).is_err());
        }
    }
}
