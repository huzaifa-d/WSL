// Copyright (C) Microsoft Corporation. All rights reserved.

use std::ffi::OsString;
use std::path::PathBuf;

#[derive(Debug, PartialEq, Eq)]
pub enum Image {
    Reference(String),
    File(PathBuf),
}

#[derive(Debug, PartialEq, Eq)]
pub struct Arguments {
    pub bundle: PathBuf,
    pub state_root: PathBuf,
    pub image: Image,
    pub command: Vec<String>,
}

impl Arguments {
    pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Self, String> {
        let mut args = args.into_iter();
        let mut bundle = None;
        let mut state_root = None;
        let mut image = None;
        let mut separator = false;

        while let Some(option) = args.next() {
            if option == "--" {
                separator = true;
                break;
            }
            let name = option.to_str().ok_or("option names must be Unicode")?;
            if !matches!(
                name,
                "--bundle" | "--state-root" | "--image" | "--image-file"
            ) {
                return Err(format!("unknown option: {name}"));
            }
            let value = args
                .next()
                .filter(|value| {
                    !value.is_empty()
                        && !value.to_str().is_some_and(|value| value.starts_with("--"))
                })
                .ok_or_else(|| format!("{name} requires a nonempty value"))?;
            match name {
                "--bundle" => set_once(&mut bundle, absolute_path(value, name)?, name)?,
                "--state-root" => set_once(&mut state_root, absolute_path(value, name)?, name)?,
                "--image" => {
                    let value = value
                        .into_string()
                        .map_err(|_| "--image must be Unicode".to_owned())?;
                    set_once(&mut image, Image::Reference(value), name)?;
                }
                "--image-file" => {
                    set_once(&mut image, Image::File(absolute_path(value, name)?), name)?;
                }
                _ => unreachable!(),
            }
        }

        if !separator {
            return Err("missing -- separator before the guest program".into());
        }
        let command = args
            .map(|arg| {
                arg.into_string()
                    .map_err(|_| "guest program and arguments must be Unicode".to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?;
        if command.first().is_none_or(String::is_empty) {
            return Err("a nonempty guest program is required after --".into());
        }

        Ok(Self {
            bundle: bundle.ok_or("--bundle is required")?,
            state_root: state_root.ok_or("--state-root is required")?,
            image: image.ok_or("exactly one of --image and --image-file is required")?,
            command,
        })
    }
}

fn set_once<T>(slot: &mut Option<T>, value: T, name: &str) -> Result<(), String> {
    if slot.is_some() {
        return Err(format!(
            "{name} is repeated or conflicts with another option"
        ));
    }
    *slot = Some(value);
    Ok(())
}

fn absolute_path(value: OsString, name: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(format!("{name} must be an absolute path"));
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    fn parse(values: &[&str]) -> Result<Arguments, String> {
        Arguments::parse(values.iter().map(OsString::from))
    }

    fn absolute_path(name: &str) -> String {
        std::env::current_dir()
            .unwrap()
            .join(name)
            .to_str()
            .unwrap()
            .to_owned()
    }

    #[test]
    fn preserves_guest_argument_boundaries_and_metacharacters() {
        let bundle = absolute_path("bundle");
        let state = absolute_path("state");
        let parsed = parse(&[
            "--bundle",
            &bundle,
            "--state-root",
            &state,
            "--image",
            "alpine:latest",
            "--",
            "printf",
            "hello world",
            "a;$(touch nope)",
            "",
            "--image",
        ])
        .unwrap();
        assert_eq!(parsed.bundle, std::path::PathBuf::from(bundle));
        assert_eq!(parsed.state_root, std::path::PathBuf::from(state));
        assert_eq!(parsed.image, Image::Reference("alpine:latest".into()));
        assert_eq!(
            parsed.command,
            vec!["printf", "hello world", "a;$(touch nope)", "", "--image"]
        );
    }

    #[test]
    fn accepts_an_absolute_image_file() {
        let bundle = absolute_path("bundle");
        let state = absolute_path("state");
        let image = absolute_path("image.vhd");
        let parsed = parse(&[
            "--bundle",
            &bundle,
            "--state-root",
            &state,
            "--image-file",
            &image,
            "--",
            "true",
        ])
        .unwrap();
        assert_eq!(parsed.image, Image::File(image.into()));
    }

    #[test]
    fn rejects_missing_or_empty_values() {
        let bundle = absolute_path("bundle");
        let state = absolute_path("state");
        for option in ["--bundle", "--state-root", "--image", "--image-file"] {
            for values in [vec![option], vec![option, "--"], vec![option, ""]] {
                assert_eq!(
                    parse(&values),
                    Err(format!("{option} requires a nonempty value")),
                    "{values:?}"
                );
            }
        }
        assert_eq!(
            parse(&[
                "--bundle",
                &bundle,
                "--state-root",
                &state,
                "--image",
                "",
                "--",
                "true",
            ]),
            Err("--image requires a nonempty value".into())
        );
        assert_eq!(
            parse(&[
                "--bundle",
                &bundle,
                "--state-root",
                &state,
                "--image",
                "--state-root",
                &state,
                "--",
                "true",
            ]),
            Err("--image requires a nonempty value".into())
        );
    }

    #[test]
    fn rejects_missing_separator_or_program() {
        let bundle = absolute_path("bundle");
        let state = absolute_path("state");
        for (tail, expected) in [
            (&[][..], "missing -- separator before the guest program"),
            (&["true"][..], "unknown option: true"),
            (&["--"][..], "a nonempty guest program is required after --"),
            (
                &["--", ""][..],
                "a nonempty guest program is required after --",
            ),
        ] {
            let mut values = vec![
                "--bundle",
                &bundle,
                "--state-root",
                &state,
                "--image",
                "alpine",
            ];
            values.extend_from_slice(tail);
            assert_eq!(parse(&values), Err(expected.into()), "{tail:?}");
        }
    }

    #[test]
    fn rejects_relative_paths_and_conflicting_image_options() {
        let bundle = absolute_path("bundle");
        let state = absolute_path("state");
        let image = absolute_path("image.vhd");
        for (values, expected) in [
            (
                vec![
                    "--bundle",
                    "relative",
                    "--state-root",
                    &state,
                    "--image",
                    "a",
                    "--",
                    "true",
                ],
                "--bundle must be an absolute path",
            ),
            (
                vec![
                    "--bundle",
                    &bundle,
                    "--state-root",
                    "relative",
                    "--image",
                    "a",
                    "--",
                    "true",
                ],
                "--state-root must be an absolute path",
            ),
            (
                vec![
                    "--bundle",
                    &bundle,
                    "--state-root",
                    &state,
                    "--image-file",
                    "relative",
                    "--",
                    "true",
                ],
                "--image-file must be an absolute path",
            ),
            (
                vec![
                    "--bundle",
                    &bundle,
                    "--state-root",
                    &state,
                    "--image",
                    "a",
                    "--image-file",
                    &image,
                    "--",
                    "true",
                ],
                "--image-file is repeated or conflicts with another option",
            ),
        ] {
            assert_eq!(parse(&values), Err(expected.into()), "{values:?}");
        }
    }

    #[test]
    fn rejects_missing_duplicate_and_unknown_options() {
        let bundle = absolute_path("bundle");
        let state = absolute_path("state");
        for (values, expected) in [
            (
                vec!["--state-root", &state, "--image", "a", "--", "true"],
                "--bundle is required",
            ),
            (
                vec!["--bundle", &bundle, "--image", "a", "--", "true"],
                "--state-root is required",
            ),
            (
                vec!["--bundle", &bundle, "--state-root", &state, "--", "true"],
                "exactly one of --image and --image-file is required",
            ),
            (
                vec![
                    "--bundle",
                    &bundle,
                    "--bundle",
                    &bundle,
                    "--state-root",
                    &state,
                    "--image",
                    "a",
                    "--",
                    "true",
                ],
                "--bundle is repeated or conflicts with another option",
            ),
            (
                vec![
                    "--bundle",
                    &bundle,
                    "--state-root",
                    &state,
                    "--image",
                    "a",
                    "--unknown",
                    "--",
                    "true",
                ],
                "unknown option: --unknown",
            ),
        ] {
            assert_eq!(parse(&values), Err(expected.into()), "{values:?}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn rejects_non_unicode_guest_arguments() {
        use std::os::windows::ffi::OsStringExt;
        let mut values = vec![
            OsString::from("--bundle"),
            OsString::from(absolute_path("bundle")),
            OsString::from("--state-root"),
            OsString::from(absolute_path("state")),
            OsString::from("--image"),
            OsString::from("alpine"),
            OsString::from("--"),
            OsString::from("true"),
        ];
        values.push(OsString::from_wide(&[0xD800]));
        assert_eq!(
            Arguments::parse(values),
            Err("guest program and arguments must be Unicode".into())
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_path_forms_are_checked_for_each_path_option() {
        for (index, option) in [(1, "--bundle"), (3, "--state-root"), (5, "--image-file")] {
            for path in [r"C:\bundle", r"\\server\share\bundle", r"\\?\C:\bundle"] {
                let mut values = vec![
                    "--bundle",
                    r"C:\bundle",
                    "--state-root",
                    r"C:\state",
                    "--image-file",
                    r"C:\image.vhd",
                    "--",
                    "true",
                ];
                values[index] = path;
                let parsed = parse(&values).unwrap();
                let actual = match option {
                    "--bundle" => parsed.bundle,
                    "--state-root" => parsed.state_root,
                    "--image-file" => match parsed.image {
                        Image::File(path) => path,
                        _ => panic!("expected image file"),
                    },
                    _ => unreachable!(),
                };
                assert_eq!(actual, std::path::PathBuf::from(path), "{option}: {path}");
            }
            for path in [r"C:bundle", r"\bundle", r"bundle", r"C:"] {
                let mut values = vec![
                    "--bundle",
                    r"C:\bundle",
                    "--state-root",
                    r"C:\state",
                    "--image-file",
                    r"C:\image.vhd",
                    "--",
                    "true",
                ];
                values[index] = path;
                assert_eq!(
                    parse(&values),
                    Err(format!("{option} must be an absolute path")),
                    "{option}: {path}"
                );
            }
        }
    }
}
