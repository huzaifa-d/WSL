// Copyright (C) Microsoft Corporation. All rights reserved.

use crate::ffi::WslcAciBytes;
use std::panic::catch_unwind;
use std::ptr;
use std::slice;

/// # Safety
///
/// The input must be readable for `length` bytes. Output pointers must be distinct and writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wslc_aci_translate(
    json: *const u8,
    length: usize,
    request: *mut WslcAciBytes,
    error: *mut WslcAciBytes,
) -> i32 {
    if request.is_null() || error.is_null() || request == error {
        return 1;
    }
    unsafe {
        ptr::write(request, WslcAciBytes::empty());
        ptr::write(error, WslcAciBytes::empty());
    }

    let result = catch_unwind(|| -> Result<Vec<u8>, String> {
        if length > isize::MAX as usize || (json.is_null() && length != 0) {
            return Err("invalid request buffer".into());
        }
        let bytes = if length == 0 {
            &[]
        } else {
            unsafe { slice::from_raw_parts(json, length) }
        };
        let input = std::str::from_utf8(bytes).map_err(|_| "request must be UTF-8")?;
        let translated = crate::translate::translate(input)?;
        serde_json::to_vec(&translated).map_err(|_| "cannot encode ACI request".into())
    });

    match result {
        Ok(Ok(bytes)) => {
            unsafe { ptr::write(request, WslcAciBytes::from_vec(bytes)) };
            0
        }
        Ok(Err(message)) => {
            unsafe { ptr::write(error, WslcAciBytes::from_vec(message.into_bytes())) };
            1
        }
        Err(_) => {
            unsafe {
                ptr::write(
                    error,
                    WslcAciBytes::from_vec(b"request translation failed".to_vec()),
                )
            };
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translates_and_frees_repeatedly() {
        let input = br#"{"version":"1.1.0-alpha","containment":"microvm","microvm":{"image":"example.com/repo:tag"},"process":{"commandLine":"true"}}"#;
        for _ in 0..100 {
            let mut request = WslcAciBytes::empty();
            let mut error = WslcAciBytes::empty();
            let status = unsafe {
                wslc_aci_translate(input.as_ptr(), input.len(), &mut request, &mut error)
            };
            assert_eq!(status, 0);
            assert!(error.data.is_null());
            let bytes = unsafe { slice::from_raw_parts(request.data, request.length) };
            let value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
            assert_eq!(value["exec"]["process"]["commandLine"], "true");
            unsafe {
                crate::ffi::wslc_aci_free(request);
                crate::ffi::wslc_aci_free(error);
            }
        }
    }

    #[test]
    fn invalid_utf8_fails_without_returning_a_request() {
        let input = [0xff];
        let mut request = WslcAciBytes::empty();
        let mut error = WslcAciBytes::empty();
        let status =
            unsafe { wslc_aci_translate(input.as_ptr(), input.len(), &mut request, &mut error) };
        assert_eq!(status, 1);
        assert!(request.data.is_null());
        let bytes = unsafe { slice::from_raw_parts(error.data, error.length) };
        assert_eq!(bytes, b"request must be UTF-8");
        unsafe {
            crate::ffi::wslc_aci_free(request);
            crate::ffi::wslc_aci_free(error);
        }
    }

    #[test]
    fn rejects_null_and_aliased_output_pointers() {
        let mut output = WslcAciBytes::empty();
        assert_eq!(
            unsafe { wslc_aci_translate(ptr::null(), 0, ptr::null_mut(), &mut output) },
            1
        );
        let same = &raw mut output;
        assert_eq!(unsafe { wslc_aci_translate(ptr::null(), 0, same, same) }, 1);
    }
}
