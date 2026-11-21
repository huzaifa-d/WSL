// Copyright (C) Microsoft Corporation. All rights reserved.

use std::ffi::OsString;
use std::path::PathBuf;

pub struct Arguments {
    pub config: PathBuf,
}

impl Arguments {
    pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Self, String> {
        let mut args = args.into_iter();
        if args.next().as_deref() != Some(std::ffi::OsStr::new("--config")) {
            return Err("expected --config <JSON-file>".into());
        }
        let config = args
            .next()
            .filter(|value| !value.is_empty() && !value.to_string_lossy().starts_with("--"))
            .ok_or("--config requires a file path")?;
        if args.next().is_some() {
            return Err("unexpected argument after --config <JSON-file>".into());
        }
        Ok(Self {
            config: PathBuf::from(config),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_a_config_file() {
        let args = Arguments::parse(["--config", "config.json"].map(OsString::from)).unwrap();
        assert_eq!(args.config, PathBuf::from("config.json"));
        for values in [
            vec![],
            vec!["--config"],
            vec!["--config", ""],
            vec!["--config", "--image"],
            vec!["--config", "config.json", "--", "true"],
            vec!["--image", "example"],
            vec!["--image-file", "example"],
            vec!["--bundle", "example"],
            vec!["--state-root", "example"],
        ] {
            assert!(Arguments::parse(values.into_iter().map(OsString::from)).is_err());
        }
    }
}
