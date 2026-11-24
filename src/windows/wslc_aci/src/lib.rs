// Copyright (C) Microsoft Corporation. All rights reserved.

#[cfg(any(feature = "translator", feature = "agent"))]
mod request;

#[cfg(any(feature = "translator", feature = "agent"))]
mod ffi;

#[cfg(feature = "translator")]
pub mod translate;

#[cfg(feature = "translator")]
mod translate_ffi;

#[cfg(all(feature = "agent", target_os = "windows", target_arch = "x86_64"))]
mod host;
