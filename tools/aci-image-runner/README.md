# ACI image runner

This standalone prototype runs one MXC development-contract MicroVM request.
It is not part of the WSL service or CLI. It requires native Windows x64,
hardware virtualization, Windows Hypervisor Platform, a current Rust toolchain,
and the x64 MSVC build tools.

The runner pins `mxc-sdk` to
[`40eebd39ab5e5a02d350169a8c96c28b33ddba7e`](https://github.com/microsoft/mxc/tree/40eebd39ab5e5a02d350169a8c96c28b33ddba7e)
with its `microvm` feature. The SDK build stages the complete signed agent
bundle and verifies its approved hashes and signatures; it requires access to
the release and Windows certificate trust and revocation services. Keep the
staged `aci-edge-sandboxes` directory beside the executable. Do not copy only
individual runtime files. MXC also supports a trusted
`ACI_EDGE_SANDBOXES_AGENT_ARTIFACTS_DIR` runtime override; see the pinned
[NVX documentation](https://github.com/microsoft/mxc/blob/40eebd39ab5e5a02d350169a8c96c28b33ddba7e/docs/backends/nvx/nvx.md)
for bundle discovery and trust assumptions.

## Build and run

```powershell
cargo build --manifest-path tools\aci-image-runner\Cargo.toml --locked --target x86_64-pc-windows-msvc
$runner = Join-Path (Get-Location) 'tools\aci-image-runner\target\x86_64-pc-windows-msvc\debug\aci-image-runner.exe'
& $runner --config C:\path\to\request.json
```

The example assumes Cargo's default target directory. An example request:

```json
{
  "version": "1.1.0-alpha",
  "containment": "microvm",
  "microvm": { "image": "mcr.microsoft.com/azurelinux/base/core:3.0" },
  "network": {
    "egress": { "default": "deny" },
    "ingress": { "default": "deny" }
  },
  "process": {
    "commandLine": "printf 'hello from the guest\\n'",
    "timeout": 30000
  }
}
```

The config must be UTF-8. MXC parses and validates the complete JSON and
receives it unchanged; it owns policy defaults, supported fields and
enforcement, including filesystem, network, proxy, memory, working directory,
environment and timeout. Selecting this runner authorizes the experimental
MicroVM backend. Other containment backends and lifecycle `phase` requests
are rejected. This runner does not offer MXC lifecycle or captured-output
APIs, prepared disk images, or the old direct-argument CLI.

`process.commandLine` is interpreted by the guest POSIX shell. Stdout and
stderr are streamed separately as bytes, and the guest exit code is returned.
MXC or native runtime diagnostics and warnings can also appear on stderr.
A workload timeout is reported as an error. Images must be registry
references; MXC handles bundle discovery, image acquisition and caching.

MXC stores sandbox records, registered images and platform templates under
`%LOCALAPPDATA%\Microsoft\MXC\nvx\<bundle>` and protects that directory for
the current user and Local SYSTEM. The state and image cache are reused and
are not deleted by the runner. MXC rejects reparse points in the state path.
Long paths may also be rejected by the native agent; use a short, owned,
physical directory for isolated test state.

## Tests

```powershell
python -m unittest discover -s tools\aci-image-runner\tests -p test_oci_layers.py
if ($LASTEXITCODE -ne 0) { throw 'OCI fixture unit tests failed' }
python tools\aci-image-runner\tests\nvx_policy.py --runner $runner --scratch $scratch
if ($LASTEXITCODE -ne 0) { throw 'NVX policy tests failed' }
python tools\aci-image-runner\tests\oci_layers.py --runner $runner --scratch $scratch
if ($LASTEXITCODE -ne 0) { throw 'OCI layer acceptance test failed' }
foreach ($mutant in @('missing-added', 'wrong-replacement', 'missing-delete', 'missing-opaque')) {
    python tools\aci-image-runner\tests\oci_layers.py --runner $runner --scratch $scratch --mutant $mutant
    if ($LASTEXITCODE -ne 0) { throw "OCI layer mutant did not fail as expected: $mutant" }
}
foreach ($case in @('deleted', 'delete-marker', 'opaque-lower', 'opaque-nested', 'opaque-marker')) {
    python tools\aci-image-runner\tests\oci_layers.py --runner $runner --scratch $scratch --symlink-case $case
    if ($LASTEXITCODE -ne 0) { throw "Dangling symlink was not detected: $case" }
}
```

For the opt-in live tests, `$scratch` must be an existing, absolute,
user-owned physical directory with no reparse-point ancestors. Each fixture
sets `LOCALAPPDATA` only for its child processes and retains test state and
results beneath its scratch directory. The policy tests adapt the one-shot
filesystem and network cases and seven one-shot fixtures from the pinned MXC
`nvx_e2e.rs`, `nvx_e2e/network.rs` and `fixtures/microvm` tests. They use
owned files and controlled host ports;
they require a reachable host IPv4 route and do not modify firewall rules.
The OCI fixture fetches a digest-pinned public base image, checks generated
layers, and serves the test image from an unauthenticated registry bound only
to loopback. Its child proxy environment is isolated from the parent.

The OCI fixture requires the exact guest success or failure output, while
allowing known native snapshot diagnostics on stderr; raw output is retained.
It tests the positive image, four deliberately broken layer variants and five
dangling-symlink cases. It does not impose a whole-process timeout.

## Limitations

The native agent's shared output pump can backpressure both streams and the
guest if either host consumer stops reading. Native calls, including
execution, cancellation and cleanup, can hang indefinitely; timeout and
stream-failure handling do not guarantee bounded process exit or VM cleanup.
The SDK may emit operational diagnostics on stderr, and guest output may
itself contain sensitive data. This prototype does not install a console
interrupt handler or provide persistent lifecycle operations.
