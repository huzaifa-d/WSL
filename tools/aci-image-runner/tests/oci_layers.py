# Copyright (C) Microsoft Corporation. All rights reserved.

"""Opt-in real-agent OCI layer acceptance fixture. See the runner README."""

import argparse
import gzip
import hashlib
import http.server
import io
import json
import os
import pathlib
import subprocess
import tarfile
import tempfile
import threading
import urllib.request
import uuid
from wslc_test_environment import require_isolated_profile


BASE = "https://mcr.microsoft.com/v2/azurelinux/base/core"
BASE_MANIFEST = "sha256:a15e3aa31a1d88db10aa9659b1a8a582ec1697b73a56ef1b8ff52d80340d343f"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_LAYER = "application/vnd.oci.image.layer.v1.tar+gzip"
PREFIX = "oci-layer-acceptance"
MUTANTS = ("missing-added", "wrong-replacement", "missing-delete", "missing-opaque")
SYMLINK_CASES = {
    "deleted": "deleted",
    "delete-marker": ".wh.deleted",
    "opaque-lower": "opaque/lower",
    "opaque-nested": "opaque/nested",
    "opaque-marker": "opaque/.wh..wh..opq",
}

GUEST_CHECK = r"""
set -eu
fail() { printf 'FAIL:%s\n' "$1" >&2; exit 1; }
absent() { [ ! -e "$1" ] && [ ! -L "$1" ]; }
p=/oci-layer-acceptance
[ -f "$p/added" ] && [ "$(cat "$p/added")" = upper-added ] && [ "$(wc -c < "$p/added")" -eq 11 ] || fail added
[ -f "$p/replaced" ] && [ "$(cat "$p/replaced")" = upper-replaced ] && [ "$(wc -c < "$p/replaced")" -eq 14 ] || fail replaced
absent "$p/deleted" || fail deleted
absent "$p/.wh.deleted" || fail delete-marker
[ -f "$p/unchanged" ] && [ "$(cat "$p/unchanged")" = lower-unchanged ] && [ "$(wc -c < "$p/unchanged")" -eq 15 ] || fail unchanged
absent "$p/opaque/lower" || fail opaque-lower
absent "$p/opaque/nested" || fail opaque-nested
absent "$p/opaque/.wh..wh..opq" || fail opaque-marker
[ -f "$p/opaque/upper" ] && [ "$(cat "$p/opaque/upper")" = upper-opaque ] && [ "$(wc -c < "$p/opaque/upper")" -eq 12 ] || fail opaque-upper
printf 'OCI_LAYERS_OK\n'
""".strip()


def registry_opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def registry_child_environment(environment):
    child = {key: value for key, value in environment.items() if not key.lower().endswith("_proxy")}
    child["NO_PROXY"] = "*"
    child["no_proxy"] = "*"
    return child


def runner_request(image, script):
    return {
        "version": "1.1.0-alpha",
        "containment": "microvm",
        "microvm": {"image": image},
        "process": {"commandLine": script, "timeout": 30000},
    }


def guest_script(symlink_case):
    if symlink_case is None:
        return GUEST_CHECK
    path = SYMLINK_CASES[symlink_case]
    target = "/oci-layer-acceptance-missing-" + uuid.uuid4().hex
    link = f"/{PREFIX}/{path}"
    return (
        f"set -eu\n[ ! -e '{target}' ] && [ ! -L '{target}' ]\n"
        f"ln -s '{target}' '{link}'\n"
        f"[ -L '{link}' ] && [ ! -e '{link}' ]\n{GUEST_CHECK}"
    )


def validate_result(result, mutant, symlink_case):
    stderr = b"".join(
        line for line in result.stderr.splitlines(keepends=True)
        if not (
            (line.startswith(b"aci_edge_agent: template store ") and b": captured generation " in line)
            or line.startswith(b"aci-image-runner: NVX platform snapshots are unavailable, so sandboxes cold boot:")
        )
    )
    expected_failures = {
        "missing-added": b"FAIL:added\n",
        "wrong-replacement": b"FAIL:replaced\n",
        "missing-delete": b"FAIL:deleted\n",
        "missing-opaque": b"FAIL:opaque-lower\n",
    }
    if symlink_case is not None:
        expected = f"FAIL:{symlink_case}\n".encode()
    elif mutant != "none":
        expected = expected_failures[mutant]
    else:
        if result.returncode != 0 or result.stdout != b"OCI_LAYERS_OK\n" or stderr:
            raise RuntimeError("real runner did not produce the exact successful guest result")
        return
    if result.returncode != 1 or result.stdout or stderr != expected:
        raise RuntimeError("negative case did not produce its exact expected guest failure")


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def fetch(path, expected, size=None):
    request = urllib.request.Request(
        BASE + path,
        headers={"Accept": "application/vnd.docker.distribution.manifest.v2+json"},
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        data = response.read()
    if digest(data) != expected or (size is not None and len(data) != size):
        raise ValueError(f"public base content failed digest or size verification: {expected}")
    return data


def make_tar(entries):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, value in entries.items():
            contents = value.encode()
            info = tarfile.TarInfo(name)
            info.size = len(contents)
            info.mode = 0o644
            info.mtime = 0
            archive.addfile(info, io.BytesIO(contents))
    return buffer.getvalue()


def fixture_entries(mutant):
    lower = {
        f"{PREFIX}/replaced": "lower-replaced",
        f"{PREFIX}/deleted": "lower-deleted",
        f"{PREFIX}/unchanged": "lower-unchanged",
        f"{PREFIX}/opaque/lower": "lower-opaque",
        f"{PREFIX}/opaque/nested/child": "lower-nested",
    }
    # Put the opaque marker after the upper sibling: it must not hide that sibling.
    upper = {
        f"{PREFIX}/added": "upper-added",
        f"{PREFIX}/replaced": "upper-replaced",
        f"{PREFIX}/.wh.deleted": "",
        f"{PREFIX}/opaque/upper": "upper-opaque",
        f"{PREFIX}/opaque/.wh..wh..opq": "",
    }
    if mutant == "missing-added":
        del upper[f"{PREFIX}/added"]
    elif mutant == "wrong-replacement":
        upper[f"{PREFIX}/replaced"] = "wrong"
    elif mutant == "missing-delete":
        del upper[f"{PREFIX}/.wh.deleted"]
    elif mutant == "missing-opaque":
        del upper[f"{PREFIX}/opaque/.wh..wh..opq"]
    elif mutant != "none":
        raise ValueError(f"unknown mutant {mutant}")
    return lower, upper


def inspect_tar(data, expected):
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        members = archive.getmembers()
        if [member.name for member in members] != list(expected):
            raise ValueError("fixture tar entries differ from the expected ordered entries")
        for member in members:
            if not member.isfile() or archive.extractfile(member).read() != expected[member.name].encode():
                raise ValueError(f"fixture tar content mismatch: {member.name}")


def make_fixture(base_manifest, base_config, base_blobs, mutant):
    manifest = json.loads(base_manifest)
    config = json.loads(base_config)
    if manifest["config"]["digest"] != digest(base_config):
        raise ValueError("base config digest mismatch")
    if (config["os"], config["architecture"]) != ("linux", "amd64"):
        raise ValueError("base image must be Linux amd64")
    if len(config["rootfs"]["diff_ids"]) != len(manifest["layers"]):
        raise ValueError("base layer count does not match rootfs diff IDs")
    blobs = {}
    layers = []
    for descriptor, diff_id in zip(manifest["layers"], config["rootfs"]["diff_ids"]):
        blob = base_blobs[descriptor["digest"]]
        if digest(blob) != descriptor["digest"] or len(blob) != descriptor["size"]:
            raise ValueError("base layer digest or size mismatch")
        raw = gzip.decompress(blob)
        if digest(raw) != diff_id:
            raise ValueError("base layer uncompressed diff ID mismatch")
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            for member in archive:
                path = member.name.removeprefix("./")
                if path == PREFIX or path.startswith(PREFIX + "/"):
                    raise ValueError("base image overlaps the fixture directory")
        blobs[digest(blob)] = blob
        layers.append({"mediaType": OCI_LAYER, "size": len(blob), "digest": digest(blob)})

    reports = []
    for name, entries in zip(("lower", "upper"), fixture_entries(mutant)):
        raw = make_tar(entries)
        inspect_tar(raw, entries)
        compressed = gzip.compress(raw, mtime=0)
        layer_digest = digest(compressed)
        blobs[layer_digest] = compressed
        layers.append({"mediaType": OCI_LAYER, "size": len(compressed), "digest": layer_digest})
        config["rootfs"]["diff_ids"].append(digest(raw))
        config.setdefault("history", []).append({"created_by": f"oci-layers fixture {name}"})
        reports.append({"layer": name, "digest": layer_digest, "diff_id": digest(raw), "entries": list(entries)})
    config_data = json_bytes(config)
    blobs[digest(config_data)] = config_data
    result = json_bytes({
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST,
        "config": {"mediaType": OCI_CONFIG, "size": len(config_data), "digest": digest(config_data)},
        "layers": layers,
    })
    return result, blobs, reports


def load_public_base():
    manifest = fetch("/manifests/" + BASE_MANIFEST, BASE_MANIFEST)
    descriptors = json.loads(manifest)
    config_descriptor = descriptors["config"]
    config = fetch("/blobs/" + config_descriptor["digest"], config_descriptor["digest"], config_descriptor["size"])
    blobs = {
        descriptor["digest"]: fetch("/blobs/" + descriptor["digest"], descriptor["digest"], descriptor["size"])
        for descriptor in descriptors["layers"]
    }
    return manifest, config, blobs


def serve_fixture(manifest, blobs, tag):
    manifest_digest = digest(manifest)

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_HEAD(self):
            self.respond(False)

        def do_GET(self):
            self.respond(True)

        def respond(self, send_body):
            path = self.path.split("?", 1)[0]
            body = None
            content_type = "application/octet-stream"
            if path in ("/v2", "/v2/"):
                body = b"{}"
                content_type = "application/json"
            elif path in (f"/v2/fixture/manifests/{tag}", f"/v2/fixture/manifests/{manifest_digest}"):
                body = manifest
                content_type = OCI_MANIFEST
            elif path.startswith("/v2/fixture/blobs/"):
                body = blobs.get(path.removeprefix("/v2/fixture/blobs/"))
            if body is None:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Docker-Distribution-Api-Version", "registry/2.0")
            self.send_header("Docker-Content-Digest", digest(body))
            self.end_headers()
            if send_body:
                self.wfile.write(body)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    try:
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
    except Exception:
        server.server_close()
        raise
    return server, thread


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    entry = parser.add_mutually_exclusive_group(required=True)
    entry.add_argument("--runner", type=pathlib.Path)
    entry.add_argument("--wslc", type=pathlib.Path)
    parser.add_argument("--scratch", type=pathlib.Path, required=True)
    parser.add_argument("--isolated-profile", action="store_true")
    parser.add_argument("--mutant", choices=("none",) + MUTANTS, default="none")
    parser.add_argument("--symlink-case", choices=tuple(SYMLINK_CASES))
    args = parser.parse_args()
    if args.mutant != "none" and args.symlink_case is not None:
        parser.error("--symlink-case cannot be combined with --mutant")
    executable = args.runner if args.runner else args.wslc
    for path in (executable, args.scratch):
        if not path.is_absolute() or not path.exists():
            parser.error(f"path must be absolute and exist: {path}")
    try:
        state = require_isolated_profile(args.scratch, args.isolated_profile)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    root = pathlib.Path(tempfile.mkdtemp(prefix="oci-layers-", dir=args.scratch))
    print(f"scratch={root}", flush=True)
    manifest, config, base_blobs = load_public_base()
    image, blobs, reports = make_fixture(manifest, config, base_blobs, args.mutant)
    (root / "manifest.json").write_bytes(image)
    for report in reports:
        (root / f"{report['layer']}.tar").write_bytes(gzip.decompress(blobs[report["digest"]]))
    details = {
        "base_manifest": BASE_MANIFEST,
        "base_config": digest(config),
        "base_layers": list(base_blobs),
        "manifest": digest(image),
        "config": json.loads(image)["config"]["digest"],
        "mutant": args.mutant,
        "symlink_case": args.symlink_case,
        "fixture_layers": reports,
    }
    (root / "fixture.json").write_text(json.dumps(details, indent=2) + "\n", encoding="utf-8")
    tag = uuid.uuid4().hex
    server, thread = serve_fixture(image, blobs, tag)
    try:
        reference = f"127.0.0.1:{server.server_port}/fixture:{tag}"
        config = root / "request.json"
        config.write_text(json.dumps(runner_request(reference, guest_script(args.symlink_case))), encoding="utf-8")
        entrypoint = [str(executable)] if args.runner else [str(executable), "aci", "run"]
        command = [*entrypoint, "--config", str(config)]
        environment = registry_child_environment(os.environ)
        environment.pop("ACI_EDGE_SANDBOXES_AGENT_ARTIFACTS_DIR", None)
        with registry_opener().open(f"http://127.0.0.1:{server.server_port}/v2/", timeout=5) as response:
            if response.read() != b"{}":
                raise RuntimeError("local registry readiness check failed")
        (root / "command.json").write_text(json.dumps(command, indent=2) + "\n", encoding="utf-8")
        print(f"runner image={reference} test-profile ACI state={state}", flush=True)
        result = subprocess.run(command, capture_output=True, check=False,
                                env=environment)
    finally:
        try:
            server.shutdown()
        finally:
            try:
                server.server_close()
            finally:
                thread.join()
    (root / "stdout").write_bytes(result.stdout)
    (root / "stderr").write_bytes(result.stderr)
    if not state.is_dir():
        raise RuntimeError("WSLC ACI state was not created in the isolated test profile")
    print(f"runner exit={result.returncode} stdout={root / 'stdout'} stderr={root / 'stderr'}", flush=True)
    print(f"stdout={result.stdout!r}\nstderr={result.stderr!r}", flush=True)
    validate_result(result, args.mutant, args.symlink_case)
    print("PASS", flush=True)


if __name__ == "__main__":
    main()
