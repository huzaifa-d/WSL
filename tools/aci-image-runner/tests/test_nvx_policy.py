# Copyright (C) Microsoft Corporation. All rights reserved.

import contextlib
import errno
import io
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import nvx_policy


class LifecyclePolicyRegressionTests(unittest.TestCase):
    def test_silently_ignored_flags_cannot_pass_rejection_oracle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            marker = root / "guest-marker"
            state = root / "Microsoft" / "MXC" / "nvx"
            for flag in ("destroyOnExit", "preservePolicy"):
                with self.subTest(flag=flag):
                    expected = f"NVX requires lifecycle.{flag}={'true' if flag == 'destroyOnExit' else 'false'}"
                    rejected = subprocess.CompletedProcess(
                        [], 1, b"", f"aci-image-runner: policy_validation: {expected}\n".encode()
                    )
                    nvx_policy.assert_lifecycle_rejected(rejected, expected, marker, state)
                    silently_ignored = subprocess.CompletedProcess([], 0, b"LIFECYCLE_OK", b"")
                    with self.assertRaisesRegex(AssertionError, "lifecycle request"):
                        nvx_policy.assert_lifecycle_rejected(silently_ignored, expected, marker, state)
                    wrong_diagnostic = subprocess.CompletedProcess([], 1, b"", b"wrong policy\n")
                    with self.assertRaisesRegex(AssertionError, "lifecycle request"):
                        nvx_policy.assert_lifecycle_rejected(wrong_diagnostic, expected, marker, state)
                    marker.write_bytes(b"STARTED")
                    with self.assertRaisesRegex(AssertionError, "guest marker"):
                        nvx_policy.assert_lifecycle_rejected(rejected, expected, marker, state)
                    marker.unlink()
                    state.mkdir(parents=True)
                    with self.assertRaisesRegex(AssertionError, "created NVX state"):
                        nvx_policy.assert_lifecycle_rejected(rejected, expected, marker, state)
                    state.rmdir()


class StreamingCleanupTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(nvx_policy, "CLEANUP_GRACE", 1)
        patcher.start()
        self.addCleanup(patcher.stop)

    def start_tracked(self, children):
        original = subprocess.Popen
        def start(*args, **kwargs):
            child = original(*args, **kwargs)
            children.append(child)
            return child
        return start

    def test_live_output_mismatch_reaps_owned_child(self):
        children = []
        with tempfile.TemporaryDirectory() as root:
            ack = pathlib.Path(root) / "ack"
            command = [sys.executable, "-c",
                       "import sys,time; sys.stdout.buffer.write(b'WRONG!'); sys.stdout.flush(); time.sleep(60)"]
            try:
                with mock.patch.object(nvx_policy.subprocess, "Popen", side_effect=self.start_tracked(children)):
                    with self.assertRaises(AssertionError):
                        nvx_policy.check_live_output(command, os.environ.copy(), ack, timeout=3)
                self.assertEqual(len(children), 1)
                self.assertIsNotNone(children[0].poll(), "owned child was not reaped")
            finally:
                for child in children:
                    if child.poll() is None:
                        child.kill()
                        child.wait()

    def test_broken_writer_readiness_failure_reaps_owned_child(self):
        children = []
        command = [sys.executable, "-c",
                   "import sys,time; sys.stderr.buffer.write(b'WRONG\\n'); sys.stderr.flush(); time.sleep(60)"]
        try:
            with mock.patch.object(nvx_policy.subprocess, "Popen", side_effect=self.start_tracked(children)):
                with self.assertRaises((AssertionError, TimeoutError)):
                    nvx_policy.check_broken_writer(command, os.environ.copy(), readiness_timeout=1, exit_timeout=3)
            self.assertEqual(len(children), 1)
            self.assertIsNotNone(children[0].poll(), "owned child was not reaped")
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                    child.wait()

    def test_broken_writer_unexpected_eof_reaps_owned_child(self):
        children = []
        command = [sys.executable, "-c", "import time; time.sleep(60)"]
        start = self.start_tracked(children)
        class EmptyReader:
            def __init__(self, stream):
                self.stream = stream
            def __iter__(self):
                return iter(())
            @property
            def closed(self):
                return self.stream.closed
            def close(self):
                self.stream.close()
        def start_with_eof(*args, **kwargs):
            child = start(*args, **kwargs)
            child.stderr = EmptyReader(child.stderr)
            return child
        try:
            with mock.patch.object(nvx_policy.subprocess, "Popen", side_effect=start_with_eof):
                with self.assertRaisesRegex(AssertionError, "guest did not report writer readiness"):
                    nvx_policy.check_broken_writer(command, os.environ.copy(), readiness_timeout=3)
            self.assertEqual(len(children), 1)
            self.assertIsNotNone(children[0].poll(), "owned child was not reaped")
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                    child.wait()

    def test_missing_live_output_times_out_and_reaps_owned_child(self):
        children = []
        with tempfile.TemporaryDirectory() as root:
            ack = pathlib.Path(root) / "ack"
            command = [sys.executable, "-c", "import time; time.sleep(60)"]
            try:
                with mock.patch.object(nvx_policy.subprocess, "Popen", side_effect=self.start_tracked(children)):
                    with self.assertRaisesRegex(TimeoutError, "live stdout"):
                        nvx_policy.check_live_output(command, os.environ.copy(), ack, timeout=1)
                self.assertEqual(len(children), 1)
                self.assertIsNotNone(children[0].poll(), "owned child was not reaped")
            finally:
                for child in children:
                    if child.poll() is None:
                        child.kill()
                        child.wait()

    def test_bad_output_acknowledges_and_reaps_cooperative_child(self):
        children = []
        with tempfile.TemporaryDirectory() as root:
            ack = pathlib.Path(root) / "ack"
            script = (
                "import pathlib,sys,time; p=pathlib.Path(sys.argv[1]); "
                "sys.stdout.buffer.write(b'WRONG!'); sys.stdout.flush(); "
                "deadline=time.monotonic()+10; "
                "\nwhile not p.exists() and time.monotonic()<deadline: time.sleep(0.02)\n"
                "assert p.exists()"
            )
            try:
                with mock.patch.object(nvx_policy.subprocess, "Popen", side_effect=self.start_tracked(children)):
                    with self.assertRaises(AssertionError):
                        nvx_policy.check_live_output([sys.executable, "-c", script, str(ack)],
                                                     os.environ.copy(), ack, timeout=3)
                self.assertTrue(ack.exists())
                self.assertEqual(children[0].poll(), 0)
            finally:
                for child in children:
                    if child.poll() is None:
                        child.kill()
                        child.wait()

    def test_reader_thread_start_failure_reaps_owned_child(self):
        for kind in ("live", "broken"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as root:
                children = []
                command = [sys.executable, "-c", "import time; time.sleep(60)"]
                try:
                    with (mock.patch.object(nvx_policy.subprocess, "Popen", side_effect=self.start_tracked(children)),
                          mock.patch.object(threading.Thread, "start", side_effect=RuntimeError("thread unavailable"))):
                        with self.assertRaisesRegex(RuntimeError, "thread unavailable"):
                            if kind == "live":
                                nvx_policy.check_live_output(command, os.environ.copy(), pathlib.Path(root) / "ack", timeout=1)
                            else:
                                nvx_policy.check_broken_writer(command, os.environ.copy(), readiness_timeout=1)
                    self.assertEqual(len(children), 1)
                    self.assertIsNotNone(children[0].poll(), "owned child was not reaped")
                finally:
                    for child in children:
                        if child.poll() is None:
                            child.kill()
                            child.wait()

    def test_live_output_remains_live_when_reader_is_delayed(self):
        with tempfile.TemporaryDirectory() as root:
            ack = pathlib.Path(root) / "ack"
            script = (
                "import pathlib,sys,time; p=pathlib.Path(sys.argv[1]); "
                "sys.stdout.buffer.write(b'BEFORE'); sys.stdout.flush(); "
                "deadline=time.monotonic()+10; "
                "\nwhile not p.exists() and time.monotonic()<deadline: time.sleep(0.02)\n"
                "assert p.exists(); sys.stdout.buffer.write(b'AFTER'); sys.stdout.flush()"
            )
            get = nvx_policy.queue.Queue.get
            def delayed_get(queue, *args, **kwargs):
                time.sleep(2.2)
                return get(queue, *args, **kwargs)
            with mock.patch.object(nvx_policy.queue.Queue, "get", delayed_get):
                nvx_policy.check_live_output([sys.executable, "-c", script, str(ack)],
                                             os.environ.copy(), ack, timeout=8)


class ProbeRegressionTests(unittest.TestCase):
    def test_denied_udp_delivery_with_dropped_replies_fails_the_oracle(self):
        delivered = []

        class DroppedReply:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def settimeout(self, _):
                pass

            def sendto(self, payload, address):
                delivered.append((payload, address))

            def recv(self, _):
                raise TimeoutError()

            def recvfrom(self, _):
                raise TimeoutError()

        environment = {"NVX_HOST": "127.0.0.1", "NVX_PORTS": "[12345, 12346]", "NVX_NONCE": "regression"}
        output = io.StringIO()
        with (
            mock.patch.dict(os.environ, environment),
            mock.patch.object(socket, "create_connection", side_effect=ConnectionRefusedError(errno.ECONNREFUSED, "refused")),
            mock.patch.object(socket, "socket", side_effect=lambda *args: DroppedReply()),
            contextlib.redirect_stdout(output),
        ):
            exec(nvx_policy.NETWORK_PROBE, {})
        result = json.loads(output.getvalue())
        self.assertEqual(result, {"tcp": ["blocked", "blocked"], "udp": ["blocked", "blocked"]})
        self.assertEqual(delivered, [
            (b"regression:12345", ("127.0.0.1", 12345)),
            (b"regression:12346", ("127.0.0.1", 12346)),
        ])
        with self.assertRaisesRegex(AssertionError, "delivery count"):
            nvx_policy.assert_network_probe(result, ["blocked", "blocked"], ["blocked", "blocked"], [1, 1], [1, 1])

    def test_real_host_receipts_detect_dropped_replies_and_allow_controls(self):
        for drop in (False, True):
            with self.subTest(drop=drop):
                services = nvx_policy.ControlledServices(host="127.0.0.1", drop_udp_replies=drop)
                try:
                    nonce = "unique-drop" if drop else "unique-allow"
                    environment = os.environ.copy()
                    environment.update({
                        "NVX_HOST": services.host,
                        "NVX_PORTS": json.dumps(services.ports),
                        "NVX_NONCE": nonce,
                    })
                    before = services.receipt_counts()
                    result = subprocess.run(
                        [sys.executable, "-c", nvx_policy.NETWORK_PROBE],
                        env=environment, capture_output=True, check=True, timeout=15,
                    )
                    outcomes = json.loads(result.stdout)
                    after = services.receipt_counts()
                    deltas = [end - start for start, end in zip(before, after)]
                    correlated = services.receipt_counts(nonce)
                    if drop:
                        self.assertEqual(outcomes["udp"], ["blocked", "blocked"])
                        with self.assertRaisesRegex(AssertionError, "delivery count"):
                            nvx_policy.assert_network_probe(
                                outcomes, ["reached", "reached"], ["blocked", "blocked"], deltas, correlated
                            )
                    else:
                        nvx_policy.assert_network_probe(
                            outcomes, ["reached", "reached"], ["reached", "reached"], deltas, correlated
                        )
                finally:
                    services.close()

    def test_unexpected_socket_errors_are_not_classified_as_denial(self):
        environment = {"NVX_HOST": "127.0.0.1", "NVX_PORTS": "[12345, 12346]", "NVX_NONCE": "regression"}
        unexpected = OSError(errno.EINVAL, "unexpected")
        with (
            mock.patch.dict(os.environ, environment),
            mock.patch.object(socket, "create_connection", side_effect=unexpected),
        ):
            with self.assertRaisesRegex(OSError, "unexpected"):
                exec(nvx_policy.NETWORK_PROBE, {})

        datagram = mock.MagicMock()
        datagram.__enter__.return_value = datagram
        datagram.sendto.side_effect = unexpected
        with (
            mock.patch.dict(os.environ, environment),
            mock.patch.object(socket, "create_connection", side_effect=ConnectionRefusedError(errno.ECONNREFUSED, "refused")),
            mock.patch.object(socket, "socket", return_value=datagram),
        ):
            with self.assertRaisesRegex(OSError, "unexpected"):
                exec(nvx_policy.NETWORK_PROBE, {})

    def test_partial_service_startup_cleans_up_owned_resources(self):
        created = {}

        def fail_after_start(services):
            listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            listener.bind(("127.0.0.1", 0))
            services.sockets.append(listener)
            worker = threading.Thread(target=services.stop.wait)
            worker.start()
            services.threads.append(worker)
            created.update(listener=listener, worker=worker)
            raise OSError(errno.EINVAL, "startup failure")

        with mock.patch.object(nvx_policy.ControlledServices, "start", fail_after_start):
            with self.assertRaisesRegex(OSError, "startup failure"):
                nvx_policy.ControlledServices(host="127.0.0.1")
        self.assertEqual(created["listener"].fileno(), -1)
        self.assertFalse(created["worker"].is_alive())

    def test_service_worker_failures_are_reported(self):
        services = nvx_policy.ControlledServices(host="127.0.0.1")
        def fail(_):
            raise OSError("worker failure")
        services.worker(fail, None)
        with self.assertRaisesRegex(RuntimeError, "controlled host service failed"):
            services.close()
