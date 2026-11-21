// Copyright (C) Microsoft Corporation. All rights reserved.

use std::process::Command;

fn runner() -> Command {
    Command::new(env!("CARGO_BIN_EXE_aci-image-runner"))
}

#[test]
fn rejects_legacy_arguments() {
    for option in ["--image", "--image-file", "--bundle", "--state-root", "--"] {
        let output = runner().args([option, "value"]).output().unwrap();
        assert_eq!(output.status.code(), Some(1), "{option}");
        assert!(output.stdout.is_empty(), "{option}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("expected --config"));
    }
}

#[test]
fn rejects_other_backends_and_lifecycle_before_spawn() {
    let root = tempfile::tempdir().unwrap();
    for (name, json, message) in [
        (
            "process",
            r#"{"version":"1.1.0-alpha","containment":"process","process":{"commandLine":"true"}}"#,
            "only one-shot MicroVM containment is supported",
        ),
        (
            "start",
            r#"{"version":"1.1.0-alpha","phase":"start","sandboxId":"microvm:00000000000000000000000000000000"}"#,
            "lifecycle phase requests are not supported",
        ),
    ] {
        let path = root.path().join(format!("{name}.json"));
        std::fs::write(&path, json).unwrap();
        let output = runner().arg("--config").arg(path).output().unwrap();
        assert_eq!(output.status.code(), Some(1), "{name}");
        assert!(output.stdout.is_empty(), "{name}");
        assert!(String::from_utf8_lossy(&output.stderr).contains(message));
    }
}

#[test]
fn rejects_non_utf8_and_missing_config_files() {
    let root = tempfile::tempdir().unwrap();
    let invalid = root.path().join("invalid.json");
    std::fs::write(&invalid, [0xff, 0x80]).unwrap();
    for path in [invalid, root.path().join("missing.json")] {
        let output = runner().arg("--config").arg(path).output().unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("cannot read config file"));
    }
}
