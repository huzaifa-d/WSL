# WSLC ACI image runner

## Start here

This prototype runs a command in a small Linux virtual machine:

1. You put an image name and command in a JSON file.
2. The runner sends the request to WSLC.
3. WSLC uses the ACI agent to pull the image and start OpenVMM.
4. The command runs in the virtual machine. Its output and exit code come back
   to you.

The runner forwards any supported policies to ACI. ACI checks and enforces
them. The runner does not start the agent itself.

### Where to find the code

These paths are relative to the root of the WSL repository:

| Folder or file | What it contains |
|---|---|
| `tools\aci-image-runner\` | The prototype runner. Its entry point is `main.cpp`. |
| `src\windows\wslc\` | The `wslc` command, including `wslc aci run`. |
| `src\windows\common\wslc\services\WslcAciClient.cpp` | The shared code that calls the WSLC session. |
| `src\windows\wslcsession\` | The WSLC session code that starts the ACI operation. |
| `src\windows\wslc_aci\` | The request translator and ACI agent bridge. |

After installation, WSL is normally under `C:\Program Files\WSL\`.

### ACI binaries

The ACI agent, image tool and OpenVMM are in the official
[ACI Edge Sandboxes bundle](https://github.com/Azure/aci-edge-sandbox/releases/download/v0.2.0-build189870623/aci-edge-sandboxes-0.2.0-build189870623.zip).
The ZIP's SHA-256 is
`35de02f4d7decf840f336111b19dc04d36522629b965615bddf5865ea374f704`.

| File in the ZIP | SHA-256 |
|---|---|
| `bin\aci_edge_agent.dll` | `eba0d57782e0cdb172d2f2ead0ff164fbc3e0e39d00e7223c4c9b77717f1c99a` |
| `bin\direct-images.exe` | `03dfa4d44083e071e73d145724a742a023843377fe2b7da8a72a7549a091b6a3` |
| `bin\openvmm.exe` | `05869020fee476b877d37519356929fc9e9b9cc473ea12bb3c9428250440f66f` |

Keep the complete bundle, including its guest files. The bundled licence
restricts redistribution of the ACI agent and image tool. The runner and
matching WSL binaries are built from this source; they are not in that ZIP.

### Try it

You need Windows x64, Windows Hypervisor Platform, a matching WSL build, and the
verified ACI bundle. This branch contains source, not the binaries; the bundle
is subject to its own licence. Installing a development WSL build can replace
your existing installation. See **Build and run** below before proceeding.

Save this as `request.json` in UTF-8:

```json
{
  "version": "1.1.0-alpha",
  "containment": "microvm",
  "microvm": { "image": "docker.io/library/python:3.12-alpine" },
  "process": {
    "commandLine": "python3 -c \"print('Hello from Python')\"",
    "timeout": 90000
  }
}
```

From the repository root, after building and installing the matching WSL build:

```powershell
.\out\wslc-aci\bin\x64\Debug\aci-image-runner.exe --config .\request.json
```

You can also run the same file with:

```powershell
.\out\wslc-aci\bin\x64\Debug\wslc.exe aci run --config .\request.json
```

The expected output is `Hello from Python`.

## Details

This prototype runs one MXC development-contract MicroVM request through an
opt-in WSLC path. The C++ runner and `wslc aci run` share a request translator;
the per-user `wslcsession.exe` calls the ACI agent, which uses OpenVMM.
Existing WSLC container commands continue to use their normal runtime.

The translator reads the `1.1.0-alpha` one-shot MXC JSON format using the pinned
MXC SDK revision
[`40eebd39ab5e5a02d350169a8c96c28b33ddba7e`](https://github.com/microsoft/mxc/tree/40eebd39ab5e5a02d350169a8c96c28b33ddba7e).
It converts representable fields into ACI requests; it does not call MXC's
NVX execution path. ACI performs its own checks and enforces the policies.
Unrepresentable requested policies fail rather than being ignored. ACI's
accepted inputs and error messages need not exactly match MXC's.

## Build and run

Native Windows x64, Windows Hypervisor Platform, Visual Studio, Windows SDK
26100 and a current Rust toolchain with the `x86_64-pc-windows-msvc` target
are required. The normal x64 build stages the pinned
`aci_edge_sandboxes` 0.1.2 agent bundle
`v0.2.0-build189870623` (sandbox ABI 3). The bundle is verified by the crate
at build time and by the agent at runtime. Build-time access to the release
and Windows certificate trust and revocation services is required.

```powershell
cmake -S . -B .\out\wslc-aci -A x64 -DCMAKE_BUILD_TYPE=Debug
cmake --build .\out\wslc-aci --config Debug -- -m
$runner = Join-Path (Get-Location) 'out\wslc-aci\bin\x64\Debug\aci-image-runner.exe'
$wslc = Join-Path (Get-Location) 'out\wslc-aci\bin\x64\Debug\wslc.exe'
& $runner --config C:\path\to\request.json
& $wslc aci run --config C:\path\to\request.json
```

Both entry points require a matching WSL service and `wslcsession.exe` build.
The WSLC command honours the global `--session` option; without it, both entry
points use the default session.
Use an isolated test VM or profile for development rather than replacing a
shared host installation. Keep the complete `aci-edge-sandboxes` bundle beside
the `wslcsession.exe` that runs the request. This prototype does not add the
bundle to shipping packages.

An example request:

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

The file must be UTF-8. `process.commandLine` is interpreted by the guest POSIX
shell. Stdout and stderr are streamed separately as bytes; the guest exit code
is returned. A timeout is reported as an error. Lifecycle `phase` requests,
other containment backends, prepared disk-image inputs and the former
direct-argument CLI are not supported.

The translator forwards filesystem, network/loopback, proxy, memory and process
fields that the agent can represent. If a requested field cannot be represented,
the request fails. One-shot lifecycle defaults are `destroyOnExit: true` and
`preservePolicy: false`; the opposite values cannot be represented by this
disposable run and are rejected.

The agent caches registry images by reference text. A moving tag may therefore
reuse an older image; use a digest reference (`repository@sha256:...`) when
exact image identity matters. The WSLC session uses a protected
`%LOCALAPPDATA%\wslc-aci\<bundle>` state directory for the current user.
State and image caches are retained after a run. Reparse-point ancestors and
unsafe ownership or permissions are rejected.

## Tests

Build the **entire** WSL project before running tests. The TAEF tests require
Administrator privileges and a matching test installation. Run live tests only
in a dedicated test VM or test-user profile: `LOCALAPPDATA` overrides on the
runner do not change the WSLC session process's actual profile.

```powershell
cmake --build .\out\wslc-aci --config Debug -- -m
cargo test --manifest-path src\windows\wslc_aci\Cargo.toml --locked --no-default-features --features translator
.\out\wslc-aci\bin\x64\Debug\test.bat /name:*WSLCAciTests*
$env:WSLC_ACI_RUNNER = $runner
python -m unittest discover -s tools\aci-image-runner\tests -p test_*.py

# Only in the dedicated test profile; the scripts verify this is the actual
# LocalAppData directory and require the explicit confirmation flag.
$scratch = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
python tools\aci-image-runner\tests\nvx_policy.py --runner $runner --scratch $scratch --isolated-profile
python tools\aci-image-runner\tests\nvx_policy.py --wslc $wslc --scratch $scratch --isolated-profile
python tools\aci-image-runner\tests\oci_layers.py --runner $runner --scratch $scratch --isolated-profile
```

The policy tests adapt the one-shot filesystem and network cases and seven
unmodified JSON fixtures from the MIT-licensed MXC `nvx_e2e.rs`,
`nvx_e2e/network.rs` and `fixtures/microvm` at the pinned revision. UDP checks
count host receipts as well as guest replies. The OCI fixture uses a
digest-pinned base image and a test-owned loopback registry. An isolated test
profile must also have suitable proxy settings for the WSLC session process;
removing proxy variables only from the runner does not reconfigure that process.

The OCI fixture supports `--wslc` instead of `--runner`, `--mutant` values
`missing-added`, `wrong-replacement`, `missing-delete`, `missing-opaque`, and
`--symlink-case` values `deleted`, `delete-marker`, `opaque-lower`,
`opaque-nested`, `opaque-marker`. It does not impose a whole-process timeout.

## Limitations

The bundled ACI agent is currently x64-only; ARM64 reports the path as
unsupported. Native calls, cancellation and cleanup can hang. A blocked host
output consumer can backpressure both streams and the guest. A workload
timeout or forced termination does not guarantee that the VM was removed.
Guest output and native diagnostics can contain sensitive data.
