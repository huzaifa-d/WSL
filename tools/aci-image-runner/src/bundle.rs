// Copyright (C) Microsoft Corporation. All rights reserved.

use aci_edge_sandboxes::agent::{
    AgentConfig, BundleSource, Hypervisor, RuntimeSource, SetupConfig,
};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;

// Pins are from the independently verified public v0.2.0-build189870623 archive
// (SHA-256 35de02f4d7decf840f336111b19dc04d36522629b965615bddf5865ea374f704).
const MANIFEST_SHA256: [u8; 32] = [
    0x9b, 0xae, 0xc7, 0xd3, 0x01, 0x03, 0x50, 0xb3, 0xf0, 0xe1, 0x30, 0x3d, 0xb6, 0xc1, 0xb7, 0x09,
    0xfe, 0x36, 0x86, 0x6d, 0xbd, 0x63, 0x88, 0xa2, 0x81, 0x0e, 0x46, 0xf4, 0xb4, 0x0a, 0xf0, 0x28,
];
const LIBRARY_SHA256: [u8; 32] = [
    0xeb, 0xa0, 0xd5, 0x77, 0x82, 0xe0, 0xcd, 0xb1, 0x72, 0xd2, 0xf2, 0xea, 0xd0, 0xff, 0x16, 0x4f,
    0xbc, 0x3e, 0x0e, 0x39, 0xd0, 0x0e, 0x72, 0x23, 0xc4, 0xc9, 0xb7, 0x77, 0x17, 0xf1, 0xc9, 0x9a,
];

#[derive(Clone, Copy)]
pub(crate) struct BundleTrust {
    manifest_sha256: [u8; 32],
    library_sha256: [u8; 32],
}

impl BundleTrust {
    pub(crate) const fn approved() -> Self {
        Self {
            manifest_sha256: MANIFEST_SHA256,
            library_sha256: LIBRARY_SHA256,
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(manifest_sha256: [u8; 32], library_sha256: [u8; 32]) -> Self {
        Self {
            manifest_sha256,
            library_sha256,
        }
    }

    pub(crate) fn agent_config(
        self,
        bundle: &Path,
        state_root: &Path,
    ) -> Result<AgentConfig, String> {
        // This preflight does not seal the files; the agent must recheck these pins when it loads them.
        verify_files(bundle, &self.manifest_sha256, &self.library_sha256)?;
        Ok(self.make_config(bundle, state_root))
    }

    fn make_config(self, bundle: &Path, state_root: &Path) -> AgentConfig {
        let runtime = RuntimeSource::Bundle(BundleSource {
            path: bundle.to_owned(),
            manifest_sha256: self.manifest_sha256,
        });
        let setup = SetupConfig::new(state_root, runtime).with_hypervisor(Hypervisor::Whp);
        AgentConfig::new(
            setup,
            bundle.join("bin").join("aci_edge_agent.dll"),
            self.library_sha256,
        )
    }
}

fn verify_files(
    bundle: &Path,
    manifest_digest: &[u8; 32],
    library_digest: &[u8; 32],
) -> Result<(), String> {
    verify_file(&bundle.join("SOURCE-MANIFEST.json"), manifest_digest)?;
    verify_file(
        &bundle.join("bin").join("aci_edge_agent.dll"),
        library_digest,
    )
}

fn verify_file(path: &Path, expected: &[u8; 32]) -> Result<(), String> {
    let file =
        File::open(path).map_err(|error| format!("cannot open {}: {error}", path.display()))?;
    verify_reader(file, path, expected)
}

fn verify_reader(mut file: impl Read, path: &Path, expected: &[u8; 32]) -> Result<(), String> {
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    let actual: [u8; 32] = hash.finalize().into();
    if &actual != expected {
        return Err(format!("SHA-256 mismatch for {}", path.display()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_the_pinned_digests_to_the_official_configuration() {
        let bundle = std::env::current_dir().unwrap().join("bundle");
        let state = std::env::current_dir().unwrap().join("state");
        let config = BundleTrust::approved().make_config(&bundle, &state);
        assert_eq!(config.setup.state_root, state);
        assert_eq!(config.setup.hypervisor, Some(Hypervisor::Whp));
        match config.setup.runtime {
            RuntimeSource::Bundle(source) => {
                assert_eq!(source.path, bundle);
                assert_eq!(
                    hex(&source.manifest_sha256),
                    "9baec7d3010350b3f0e1303db6c1b709fe36866dbd6388a2810e46f4b40af028"
                );
            }
            _ => panic!("expected bundle source"),
        }
        assert_eq!(
            config.library,
            bundle.join("bin").join("aci_edge_agent.dll")
        );
        assert_eq!(
            hex(&config.library_sha256),
            "eba0d57782e0cdb172d2f2ead0ff164fbc3e0e39d00e7223c4c9b77717f1c99a"
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn reports_missing_bundle_files() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("SOURCE-MANIFEST.json");
        let cause = File::open(&manifest).unwrap_err();
        let error = BundleTrust::approved()
            .agent_config(dir.path(), dir.path())
            .unwrap_err();
        assert_eq!(
            error,
            format!("cannot open {}: {cause}", manifest.display())
        );
    }

    #[test]
    fn propagates_read_error_with_file_context() {
        struct BrokenReader;
        impl Read for BrokenReader {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("synthetic read failure"))
            }
        }
        let path = Path::new("fixture");
        assert_eq!(
            verify_reader(BrokenReader, path, &[0; 32]),
            Err(format!(
                "cannot read {}: synthetic read failure",
                path.display()
            ))
        );
    }
}
