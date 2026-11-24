// Copyright (C) Microsoft Corporation. All rights reserved.

use std::ptr;

#[repr(C)]
pub struct WslcAciBytes {
    pub(crate) data: *mut u8,
    pub(crate) length: usize,
}

impl WslcAciBytes {
    pub(crate) fn empty() -> Self {
        Self {
            data: ptr::null_mut(),
            length: 0,
        }
    }

    pub(crate) fn from_vec(value: Vec<u8>) -> Self {
        let value = value.into_boxed_slice();
        let length = value.len();
        Self {
            data: Box::into_raw(value).cast::<u8>(),
            length,
        }
    }
}

/// # Safety
///
/// The buffer must be an unfreed value returned by the bridge.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wslc_aci_free(buffer: WslcAciBytes) {
    if !buffer.data.is_null() {
        unsafe {
            drop(Box::from_raw(ptr::slice_from_raw_parts_mut(
                buffer.data,
                buffer.length,
            )));
        }
    }
}
