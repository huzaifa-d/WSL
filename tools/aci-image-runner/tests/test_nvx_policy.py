# Copyright (C) Microsoft Corporation. All rights reserved.

import contextlib
import errno
import io
import json
import os
import socket
import subprocess
import sys
import threading
import unittest
from unittest import mock

import nvx_policy


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
