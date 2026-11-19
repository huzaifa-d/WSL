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

## Opt-in OCI layer acceptance test

The test uses the real runner and approved bundle on Windows x64/WHP. It
downloads a digest-pinned public Azure Linux amd64 base image from Microsoft
Container Registry, checks its manifest, config, compressed layer and
uncompressed layer digests, and adds two locally generated OCI layers. No
Docker daemon or credentials are required. A temporary unauthenticated registry
is bound only to `127.0.0.1`; it is stopped when the runner returns. The script
uses a fresh tag and creates a new state directory for each run beneath the
specified existing, absolute scratch directory. It does not modify the bundle
or an existing guest image.

After building the runner as above, choose a user-owned scratch directory and
run:

```powershell
$scratch = Join-Path $root 'oci-tests'
New-Item -ItemType Directory -Path $scratch | Out-Null
python tools\aci-image-runner\tests\oci_layers.py --bundle $bundle --runner $runner --scratch $scratch
if ($LASTEXITCODE -ne 0) { throw 'OCI layer acceptance test failed' }
foreach ($mutant in @('missing-added', 'wrong-replacement', 'missing-delete', 'missing-opaque')) {
    python tools\aci-image-runner\tests\oci_layers.py --bundle $bundle --runner $runner --scratch $scratch --mutant $mutant
    if ($LASTEXITCODE -ne 0) { throw "OCI layer mutant did not fail as expected: $mutant" }
}
foreach ($case in @('deleted', 'delete-marker', 'opaque-lower', 'opaque-nested', 'opaque-marker')) {
    python tools\aci-image-runner\tests\oci_layers.py --bundle $bundle --runner $runner --scratch $scratch --symlink-case $case
    if ($LASTEXITCODE -ne 0) { throw "Dangling symlink was not detected: $case" }
}
```

The script inspects both generated tar archives before starting the runner. The
lower layer contains files to replace, remove and hide; the upper layer contains
the replacement, addition, `.wh.deleted` and `opaque/.wh..wh..opq`. The
opaque marker follows an upper-layer sibling in the tar to verify that it hides
lower entries, including nested descendants, without hiding the sibling. The
guest also checks that the markers themselves are absent and an unrelated lower
file remains. Success requires exit code zero, stdout exactly `OCI_LAYERS_OK`
followed by a newline, and empty stderr. Each mutant succeeds as a *test* only
when the guest exits 1 with its exact expected failure on stderr and no stdout.
Each symlink case creates one dangling link in the running guest after the image
has been materialized, then requires the exact failure for that forbidden path.
It does not change the image or whiteout tar semantics.

Each run retains `fixture.json`, `manifest.json`, the inspected `lower.tar` and
`upper.tar`, the exact runner argument vector in `command.json`, separate
`stdout` and `stderr` files, and agent state in its own scratch directory.
The fixture reports content and manifest SHA-256 digests. It needs network
access only to fetch the public base; the agent pulls the test image from the
local registry. The public fetch retains the host's normal proxy policy.
Loopback checks use a proxy-free opener; the runner child receives no inherited
`*_proxy` variables and gets `NO_PROXY=*`, without modifying the parent
environment. The normal native-call hang and cleanup limitations below still
apply; this test does not impose a whole-process timeout.

The fixture's local construction and registry checks can also run without an
agent or network:

```powershell
python -m unittest discover -s tools\aci-image-runner\tests -p test_oci_layers.py
```

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

Runner-generated host and bundle diagnostics retain their paths and OS errors.
Agent and backend errors instead report the operation and stable error code but
suppress their messages and causes, since those can contain the image reference
or guest arguments, including escaped or very short values. Stream failures
report their stage and I/O kind, preserving OS-generated diagnostics when
available, but suppress other potentially sensitive details. A process-wide
panic hook explicitly reports a panic and its source location while suppressing
its payload: Rust calls the hook even for worker panics caught during cleanup. Stage-specific worker
failure reports and normal panic/exit behaviour remain in effect.
This intentionally sacrifices backend detail to avoid exposing secrets. Guest
stdout and stderr are passed through unchanged and may themselves contain secrets.
