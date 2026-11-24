# Copyright (C) Microsoft Corporation. All rights reserved.

import os
import pathlib
import subprocess
import tempfile
import unittest


@unittest.skipUnless(os.environ.get("WSLC_ACI_RUNNER"), "WSLC_ACI_RUNNER is not set")
class RunnerCliTests(unittest.TestCase):
    def run_runner(self, *args):
        executable = pathlib.Path(os.environ["WSLC_ACI_RUNNER"])
        self.assertTrue(executable.is_absolute())
        self.assertTrue(executable.is_file())
        return subprocess.run([str(executable), *map(str, args)], capture_output=True, check=False)

    def test_requires_exact_config_argument(self):
        for args in [(), ("--image", "example"), ("--config",), ("--config", "file", "extra")]:
            with self.subTest(args=args):
                result = self.run_runner(*args)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, b"")
                self.assertIn(b"--config", result.stderr)

    def test_rejects_non_utf8_unknown_backend_and_lifecycle(self):
        with tempfile.TemporaryDirectory() as root:
            for name, contents, expected in [
                ("utf8", b"\xff\x80", b"request must be UTF-8"),
                ("backend", b'{"version":"1.1.0-alpha","containment":"process","process":{"commandLine":"true"}}',
                 b"only MicroVM containment is supported"),
                ("phase", b'{"version":"1.1.0-alpha","phase":"start"}', None),
            ]:
                with self.subTest(name=name):
                    path = pathlib.Path(root) / f"{name}.json"
                    path.write_bytes(contents)
                    result = self.run_runner("--config", path)
                    self.assertEqual(result.returncode, 1)
                    self.assertEqual(result.stdout, b"")
                    self.assertTrue(result.stderr)
                    if expected is not None:
                        self.assertIn(expected, result.stderr)

    def test_missing_config_fails(self):
        with tempfile.TemporaryDirectory() as root:
            result = self.run_runner("--config", pathlib.Path(root) / "missing.json")
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, b"")
            self.assertTrue(result.stderr)
