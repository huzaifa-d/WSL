# Copyright (C) Microsoft Corporation. All rights reserved.

import gzip
import http.server
import json
import os
import pathlib
import subprocess
import sys
import threading
import unittest
import urllib.error
import urllib.request

import oci_layers


class FixtureTests(unittest.TestCase):
    def base(self):
        raw = oci_layers.make_tar({"bin/example": "base"})
        layer = gzip.compress(raw, mtime=0)
        config = oci_layers.json_bytes({
            "architecture": "amd64",
            "os": "linux",
            "rootfs": {"type": "layers", "diff_ids": [oci_layers.digest(raw)]},
            "history": [{"created_by": "base"}],
        })
        manifest = oci_layers.json_bytes({
            "config": {"digest": oci_layers.digest(config)},
            "layers": [{"digest": oci_layers.digest(layer), "size": len(layer)}],
        })
        return manifest, config, {oci_layers.digest(layer): layer}

    def test_fixture_has_verified_ordered_layers_and_descriptors(self):
        image, blobs, reports = oci_layers.make_fixture(*self.base(), "none")
        manifest = json.loads(image)
        config = json.loads(blobs[manifest["config"]["digest"]])
        self.assertEqual(len(manifest["layers"]), 3)
        self.assertEqual(len(config["history"]), 3)
        for descriptor, diff_id in zip(manifest["layers"], config["rootfs"]["diff_ids"]):
            blob = blobs[descriptor["digest"]]
            self.assertEqual(oci_layers.digest(blob), descriptor["digest"])
            self.assertEqual(len(blob), descriptor["size"])
            self.assertEqual(oci_layers.digest(gzip.decompress(blob)), diff_id)
        for report, entries in zip(reports, oci_layers.fixture_entries("none")):
            oci_layers.inspect_tar(gzip.decompress(blobs[report["digest"]]), entries)
        upper = reports[1]["entries"]
        self.assertIn(f"{oci_layers.PREFIX}/.wh.deleted", upper)
        self.assertLess(
            upper.index(f"{oci_layers.PREFIX}/opaque/upper"),
            upper.index(f"{oci_layers.PREFIX}/opaque/.wh..wh..opq"),
        )

    def test_mutants_change_only_intended_upper_entry(self):
        _, expected = oci_layers.fixture_entries("none")
        changes = {
            "missing-added": (f"{oci_layers.PREFIX}/added", None),
            "wrong-replacement": (f"{oci_layers.PREFIX}/replaced", "wrong"),
            "missing-delete": (f"{oci_layers.PREFIX}/.wh.deleted", None),
            "missing-opaque": (f"{oci_layers.PREFIX}/opaque/.wh..wh..opq", None),
        }
        for mutant, (path, value) in changes.items():
            with self.subTest(mutant=mutant):
                _, actual = oci_layers.fixture_entries(mutant)
                expected_mutant = expected.copy()
                if value is None:
                    del expected_mutant[path]
                else:
                    expected_mutant[path] = value
                self.assertEqual(actual, expected_mutant)
                with self.assertRaises(ValueError):
                    oci_layers.inspect_tar(oci_layers.make_tar(actual), expected)

    def test_corrupt_base_is_rejected(self):
        manifest, config, blobs = self.base()
        key = next(iter(blobs))
        blobs[key] += b"corrupt"
        with self.assertRaisesRegex(ValueError, "base layer digest or size mismatch"):
            oci_layers.make_fixture(manifest, config, blobs, "none")

    def test_base_cannot_overlap_the_fixture_directory(self):
        manifest, config, _ = self.base()
        raw = oci_layers.make_tar({f"./{oci_layers.PREFIX}/unexpected": "base"})
        layer = gzip.compress(raw, mtime=0)
        config = json.loads(config)
        config["rootfs"]["diff_ids"] = [oci_layers.digest(raw)]
        config = oci_layers.json_bytes(config)
        manifest = json.loads(manifest)
        manifest["config"]["digest"] = oci_layers.digest(config)
        manifest["layers"] = [{"digest": oci_layers.digest(layer), "size": len(layer)}]
        with self.assertRaisesRegex(ValueError, "base image overlaps"):
            oci_layers.make_fixture(
                oci_layers.json_bytes(manifest), config, {oci_layers.digest(layer): layer}, "none"
            )

    def test_loopback_registry_serves_exact_content_and_stops(self):
        image, blobs, _ = oci_layers.make_fixture(*self.base(), "none")
        server, thread = oci_layers.serve_fixture(image, blobs, "test-tag")
        base = f"http://127.0.0.1:{server.server_port}"
        opener = oci_layers.registry_opener()
        try:
            with opener.open(base + "/v2/") as response:
                self.assertEqual(response.read(), b"{}")
            for reference in ("test-tag", oci_layers.digest(image)):
                request = urllib.request.Request(base + "/v2/fixture/manifests/" + reference)
                with opener.open(request) as response:
                    self.assertEqual(response.read(), image)
                    self.assertEqual(response.headers["Docker-Content-Digest"], oci_layers.digest(image))
            key = next(iter(blobs))
            request = urllib.request.Request(base + "/v2/fixture/blobs/" + key, method="HEAD")
            with opener.open(request) as response:
                self.assertEqual(int(response.headers["Content-Length"]), len(blobs[key]))
                self.assertEqual(response.read(), b"")
            with self.assertRaises(urllib.error.HTTPError) as error:
                opener.open(base + "/v2/other/blobs/" + key)
            self.assertEqual(error.exception.code, 404)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
        self.assertFalse(thread.is_alive())

    def test_child_proxy_environment_is_isolated_without_mutating_input(self):
        inherited = {
            "HTTP_PROXY": "http://example.invalid",
            "https_proxy": "http://example.invalid",
            "ALL_PROXY": "http://example.invalid",
            "NO_PROXY": "",
            "Path": "preserved",
        }
        original = inherited.copy()
        child = oci_layers.registry_child_environment(inherited)
        self.assertEqual(inherited, original)
        self.assertEqual(child["Path"], "preserved")
        self.assertEqual(child["NO_PROXY"], "*")
        self.assertFalse(any(key.lower() in ("http_proxy", "https_proxy", "all_proxy") for key in child))

    def test_dangling_symlink_cases_require_exact_guest_failures(self):
        for case, path in oci_layers.SYMLINK_CASES.items():
            with self.subTest(case=case):
                script = oci_layers.guest_script(case)
                self.assertIn(f"'/{oci_layers.PREFIX}/{path}'", script)
                self.assertIn(f'absent "$p/{path}" || fail {case}', script)
                self.assertIn('[ ! -L "$1" ]', script)
                result = subprocess.CompletedProcess([], 1, b"", f"FAIL:{case}\n".encode())
                oci_layers.validate_result(result, "none", case)
                for bad in (
                    subprocess.CompletedProcess([], 0, b"OCI_LAYERS_OK\n", b""),
                    subprocess.CompletedProcess([], 1, b"", b"FAIL:wrong\n"),
                    subprocess.CompletedProcess([], 1, b"unexpected", result.stderr),
                ):
                    with self.assertRaises(RuntimeError):
                        oci_layers.validate_result(bad, "none", case)

    def test_loopback_opener_bypasses_inherited_proxy(self):
        class Trap(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.server.requests += 1
                self.send_error(502)

            def log_message(self, fmt, *args):
                pass

        image, blobs, _ = oci_layers.make_fixture(*self.base(), "none")
        proxy = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Trap)
        proxy.requests = 0
        proxy_thread = threading.Thread(target=proxy.serve_forever)
        proxy_thread.start()
        try:
            registry, registry_thread = oci_layers.serve_fixture(image, blobs, "proxy-test")
            try:
                env = {key: value for key, value in os.environ.items() if not key.lower().endswith("_proxy")}
                env["HTTP_PROXY"] = f"http://127.0.0.1:{proxy.server_port}"
                env["NO_PROXY"] = ""
                url = f"http://127.0.0.1:{registry.server_port}/v2/"
                control = """
import sys, urllib.error, urllib.request
try:
    urllib.request.urlopen(sys.argv[1], timeout=5)
except urllib.error.HTTPError as error:
    assert error.code == 502
else:
    raise AssertionError('proxy positive control did not intercept request')
"""
                safe_opener = """
import sys, oci_layers
with oci_layers.registry_opener().open(sys.argv[1], timeout=5) as response:
    assert response.read() == b'{}'
"""
                child_request = """
import sys, urllib.request
with urllib.request.urlopen(sys.argv[1], timeout=5) as response:
    assert response.read() == b'{}'
"""
                def run(script, child_env):
                    result = subprocess.run(
                        [sys.executable, "-c", script, url],
                        cwd=pathlib.Path(__file__).parent, env=child_env, capture_output=True, timeout=30,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))

                run(control, env)
                self.assertEqual(proxy.requests, 1)
                proxy.requests = 0
                run(safe_opener, env)
                run(child_request, oci_layers.registry_child_environment(env))
                self.assertEqual(proxy.requests, 0)
            finally:
                registry.shutdown()
                registry.server_close()
                registry_thread.join()
        finally:
            proxy.shutdown()
            proxy.server_close()
            proxy_thread.join()


if __name__ == "__main__":
    unittest.main()
