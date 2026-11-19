# ACI image runner

This standalone prototype runs one command in a sandbox using a public OCI image
or a prepared image file. It is not part of the WSL service or CLI.

## Requirements

- Native Windows x64 with hardware virtualization and Windows Hypervisor
  Platform available.
- A recent stable Rust toolchain, Cargo, and the x64 MSVC build tools.
- A separately supplied Windows x64 agent bundle. This runner pins
  `aci_edge_sandboxes` 0.1.2 and does not use its `agent-bundled` feature.
- Network access to the public registry when using `--image`, or an existing
  prepared GPT image when using `--image-file`.

The approved bundle is
[`v0.2.0-build189870623`](https://github.com/Azure/aci-edge-sandbox/releases/tag/v0.2.0-build189870623).
Review the bundle's `bin\EULA.txt` and other notices before use. From PowerShell
7, the following downloads it into a new user-owned directory and verifies the
archive before extraction:

```powershell
$ErrorActionPreference = 'Stop'
$root = Join-Path $env:LOCALAPPDATA ("aci-runner-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $root | Out-Null
$archive = Join-Path $root 'bundle.zip'
$url = 'https://github.com/Azure/aci-edge-sandbox/releases/download/v0.2.0-build189870623/aci-edge-sandboxes-0.2.0-build189870623.zip'
Invoke-WebRequest -Uri $url -OutFile $archive
$expected = '35de02f4d7decf840f336111b19dc04d36522629b965615bddf5865ea374f704'
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $expected) {
    throw 'Agent bundle archive SHA-256 mismatch'
}
$bundle = Join-Path $root 'bundle'
Expand-Archive -LiteralPath $archive -DestinationPath $bundle
$state = Join-Path $root 'state'
```

The bundle directory must contain `SOURCE-MANIFEST.json` and
`bin\aci_edge_agent.dll`. The runner checks their independently pinned digests;
the agent verifies the runtime files or checks their existing seals when opening
the host.

## Build and run

From the repository root in the same PowerShell session:

```powershell
cargo build --manifest-path tools\aci-image-runner\Cargo.toml --locked --target x86_64-pc-windows-msvc
if ($LASTEXITCODE -ne 0) { throw 'Runner build failed' }
$runner = Join-Path (Get-Location) 'tools\aci-image-runner\target\x86_64-pc-windows-msvc\debug\aci-image-runner.exe'
& $runner --bundle $bundle --state-root $state --image 'mcr.microsoft.com/azurelinux/base/core:3.0' -- /bin/sh -c 'printf %s ACI_OK'
```

The example assumes Cargo's default target directory. To use a prepared image
instead, set `$imageFile` to its absolute path; the command below assumes that
image contains `/bin/sh`:

```powershell
$imageFile = 'C:\path\to\prepared-image.vhd'
& $runner --bundle $bundle --state-root $state --image-file $imageFile -- /bin/sh -c 'printf %s ACI_OK'
```

All paths must be absolute. Choose exactly one image option. The arguments after
`--` are passed as an argument vector without shell interpolation by the runner;
the example explicitly chooses a guest shell. The program and its arguments
must be Unicode and nonempty. Stdin is closed. When execution and cleanup
succeed, the runner returns the guest exit status.

The state root contains agent state and an image cache. The runner does not
delete the user-supplied state root or shared cache.

## Output and lifecycle limitations

The runner forwards guest stdout and stderr separately, without modifying their
bytes. The agent uses a shared output pump: if either host output consumer stops
reading and the buffers fill, output on both streams and the guest command can
pause until that consumer resumes. Backpressure does not cause the runner to
discard output.

Native agent calls, including exec initiation, cancellation and stop, can
block indefinitely. The process may hang, and sandbox or VM cleanup may remain
unresolved. The agent's operation timeouts do not guarantee whole-process
exit, cancellation, guest termination or cleanup.

When a failure returns after a sandbox ID is known, the error includes that ID
and relevant cleanup failures; it does not assert that cleanup succeeded.
Agent initialization failures report that host cleanup status may be unknown.
If a call hangs, the runner may be unable to report an ID or cleanup outcome.
