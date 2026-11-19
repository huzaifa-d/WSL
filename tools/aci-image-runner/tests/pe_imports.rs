// Copyright (C) Microsoft Corporation. All rights reserved.

#![cfg(windows)]

use object::read::pe::PeFile64;
use object::read::{ImportFlags, NameOrOrdinal, Object};

#[derive(Debug)]
struct ImportSummary {
    normal: usize,
    delayed: usize,
    has_resolver: bool,
}

fn inspect_imports(bytes: &[u8]) -> Result<ImportSummary, String> {
    let pe = PeFile64::parse(bytes).map_err(|error| format!("invalid PE: {error}"))?;
    let mut summary = ImportSummary {
        normal: 0,
        delayed: 0,
        has_resolver: false,
    };

    for import in pe
        .imports()
        .map_err(|error| format!("cannot read imports: {error}"))?
    {
        let import = import.map_err(|error| format!("cannot read import: {error}"))?;
        let delay = match import.flags() {
            ImportFlags::Pe { delay } => delay,
            _ => return Err("unexpected non-PE import".into()),
        };
        if delay {
            summary.delayed += 1;
        } else {
            summary.normal += 1;
        }
        let name = match import.name() {
            NameOrOrdinal::Name(name) => name,
            NameOrOrdinal::Ordinal(ordinal) => {
                return Err(format!("cannot verify ordinal import {ordinal}"));
            }
        };
        if name == b"IsWow64Process2" {
            return Err(format!(
                "{} import of IsWow64Process2 from {}",
                if delay { "delay" } else { "normal" },
                String::from_utf8_lossy(import.library())
            ));
        }
        if !delay && name == b"GetProcAddress" {
            summary.has_resolver = true;
        }
    }

    Ok(summary)
}

#[test]
fn production_runner_has_no_static_or_delayed_is_wow64_process2_import() {
    let bytes = std::fs::read(env!("CARGO_BIN_EXE_aci-image-runner"))
        .expect("cannot read the linked production runner");
    let summary = inspect_imports(&bytes).expect("unsafe or malformed production PE imports");
    assert!(summary.normal > 0, "normal import table was not traversed");
    assert!(summary.has_resolver, "GetProcAddress import was not found");
    println!(
        "checked {} normal and {} delay imports",
        summary.normal, summary.delayed
    );
}

fn pe_fixture(delay: bool, symbol: &[u8]) -> Vec<u8> {
    fn u16_at(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn u32_at(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn u64_at(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    // Minimal PE32+ image with one .rdata section at RVA 0x1000 and file offset 0x200.
    let mut bytes = vec![0; 0x600];
    bytes[..2].copy_from_slice(b"MZ");
    u32_at(&mut bytes, 0x3c, 0x80);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    u16_at(&mut bytes, 0x84, 0x8664);
    u16_at(&mut bytes, 0x86, 1);
    u16_at(&mut bytes, 0x94, 0xf0);
    u16_at(&mut bytes, 0x96, 0x22);

    let optional = 0x98;
    u16_at(&mut bytes, optional, 0x20b);
    u64_at(&mut bytes, optional + 24, 0x140000000);
    u32_at(&mut bytes, optional + 32, 0x1000);
    u32_at(&mut bytes, optional + 36, 0x200);
    u32_at(&mut bytes, optional + 56, 0x2000);
    u32_at(&mut bytes, optional + 60, 0x200);
    u16_at(&mut bytes, optional + 68, 3);
    u32_at(&mut bytes, optional + 108, 16);
    let directory = optional + 112 + (if delay { 13 } else { 1 }) * 8;
    u32_at(&mut bytes, directory, 0x1000);
    u32_at(&mut bytes, directory + 4, if delay { 64 } else { 40 });

    let section = 0x188;
    bytes[section..section + 6].copy_from_slice(b".rdata");
    u32_at(&mut bytes, section + 8, 0x400);
    u32_at(&mut bytes, section + 12, 0x1000);
    u32_at(&mut bytes, section + 16, 0x400);
    u32_at(&mut bytes, section + 20, 0x200);
    u32_at(&mut bytes, section + 36, 0x40000040);

    if delay {
        u32_at(&mut bytes, 0x200, 1);
        u32_at(&mut bytes, 0x204, 0x1080);
        u32_at(&mut bytes, 0x20c, 0x10a0);
        u32_at(&mut bytes, 0x210, 0x10a0);
    } else {
        u32_at(&mut bytes, 0x200, 0x10a0);
        u32_at(&mut bytes, 0x20c, 0x1080);
        u32_at(&mut bytes, 0x210, 0x10a0);
    }
    bytes[0x280..0x28d].copy_from_slice(b"kernel32.dll\0");
    u64_at(&mut bytes, 0x2a0, 0x10b0);
    bytes[0x2b2..0x2b2 + symbol.len()].copy_from_slice(symbol);
    bytes
}

#[test]
fn pe_import_check_detects_normal_and_delay_imports() {
    for delay in [false, true] {
        let safe = inspect_imports(&pe_fixture(delay, b"GetProcAddress")).unwrap();
        assert_eq!(
            (safe.normal, safe.delayed),
            if delay { (0, 1) } else { (1, 0) }
        );
        assert_eq!(
            inspect_imports(&pe_fixture(delay, b"IsWow64Process2")).unwrap_err(),
            format!(
                "{} import of IsWow64Process2 from kernel32.dll",
                if delay { "delay" } else { "normal" }
            )
        );
        let mut ordinal = pe_fixture(delay, b"unused");
        ordinal[0x2a0..0x2a8].copy_from_slice(&0x8000000000000001u64.to_le_bytes());
        assert_eq!(
            inspect_imports(&ordinal).unwrap_err(),
            "cannot verify ordinal import 1"
        );
    }
    assert!(
        inspect_imports(b"not a PE file")
            .unwrap_err()
            .starts_with("invalid PE:")
    );
}
