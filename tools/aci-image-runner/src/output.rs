// Copyright (C) Microsoft Corporation. All rights reserved.

#[cfg(windows)]
pub(crate) fn writers() -> Result<(std::fs::File, std::fs::File), String> {
    use windows_sys::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE};

    // GetStdHandle returns borrowed handles; duplicate them before creating owned Files.
    let stdout = duplicate(unsafe { GetStdHandle(STD_OUTPUT_HANDLE) }, "stdout")?;
    let stderr = duplicate(unsafe { GetStdHandle(STD_ERROR_HANDLE) }, "stderr")?;
    Ok((stdout, stderr))
}

#[cfg(windows)]
fn duplicate(
    source: windows_sys::Win32::Foundation::HANDLE,
    name: &str,
) -> Result<std::fs::File, String> {
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{
        DUPLICATE_SAME_ACCESS, DuplicateHandle, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    if source.is_null() || source == INVALID_HANDLE_VALUE {
        return Err(format!("{name} handle is unavailable"));
    }
    let process = unsafe { GetCurrentProcess() };
    let mut duplicated = std::ptr::null_mut();
    // The source is borrowed and the successful duplicate is independently owned.
    let success = unsafe {
        DuplicateHandle(
            process,
            source,
            process,
            &mut duplicated,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if success == 0 {
        return Err(format!(
            "cannot duplicate {name} handle: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(unsafe { std::fs::File::from_raw_handle(duplicated) })
}

#[cfg(not(windows))]
pub(crate) fn writers() -> Result<(std::io::Stdout, std::io::Stderr), String> {
    Ok((std::io::stdout(), std::io::stderr()))
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;

    #[test]
    fn refuses_unavailable_handles() {
        for handle in [std::ptr::null_mut(), INVALID_HANDLE_VALUE] {
            assert_eq!(
                duplicate(handle, "stdout").unwrap_err(),
                "stdout handle is unavailable"
            );
        }
    }

    #[test]
    fn duplicate_writes_arbitrary_bytes_to_a_redirected_pipe() {
        let (mut reader, writer) = std::io::pipe().unwrap();
        let mut duplicate = duplicate(writer.as_raw_handle(), "stdout").unwrap();
        drop(writer);
        duplicate.write_all(&[0, 0xff, 0x80, b'\n']).unwrap();
        drop(duplicate);
        let mut output = Vec::new();
        reader.read_to_end(&mut output).unwrap();
        assert_eq!(output, [0, 0xff, 0x80, b'\n']);
    }
}
