# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Adapted for this runner from microsoft/mxc at
# 40eebd39ab5e5a02d350169a8c96c28b33ddba7e:
# src/mxc-sdk/tests/nvx_e2e.rs, nvx_e2e/network.rs, and fixtures/microvm.

"""Opt-in Windows x64/WHP one-shot policy tests. See the runner README."""

import argparse
import errno
import ipaddress
import json
import os
import pathlib
import re
import shlex
import socket
import subprocess
import tempfile
import threading
import time
import unittest
import uuid


IMAGE = "docker.io/library/python:3.12-alpine"
RUNNER = None
SCRATCH = None


def guest_path(path):
    path = str(path.resolve())
    if path.startswith("\\\\?\\"):
        path = path[4:]
    if len(path) < 3 or path[1:3] != ":\\":
        raise ValueError("fixture requires a drive-letter path")
    return "/mnt/" + path[0].lower() + "/" + path[3:].replace("\\", "/")


def request(command, **fields):
    result = {
        "version": "1.1.0-alpha",
        "containment": "microvm",
        "microvm": {"image": IMAGE},
        "process": {"commandLine": command, "timeout": 30000},
    }
    result.update(fields)
    return result


def python_command(script):
    return "python3 -c " + shlex.quote(script)


class ControlledServices:
    def __init__(self, host=None, drop_udp_replies=False):
        explicit_host = host is not None
        if host is None:
            route = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                route.connect(("192.0.2.1", 9))
                host = route.getsockname()[0]
            finally:
                route.close()
        self.host = host
        if self.host.startswith("10.0.0.") or (not explicit_host and self.host.startswith("127.")):
            raise RuntimeError("controlled endpoints require a non-loopback host outside 10.0.0.0/24")
        self.drop_udp_replies = drop_udp_replies
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.errors = []
        self.datagrams = {}
        self.sockets = []
        self.threads = []
        self.ports = []
        try:
            self.start()
        except Exception:
            self.close()
            raise

    def start(self):
        for _ in range(2):
            for attempt in range(64):
                udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                except OSError:
                    udp.close()
                    raise
                try:
                    first, second = (udp, tcp) if attempt % 2 == 0 else (tcp, udp)
                    first.bind((self.host, 0))
                    second.bind(first.getsockname())
                    break
                except OSError as error:
                    tcp.close()
                    udp.close()
                    if (error.errno not in (errno.EACCES, errno.EADDRINUSE, 10013, 10048)
                            and getattr(error, "winerror", None) not in (10013, 10048)) or attempt == 63:
                        raise
            self.sockets.extend((tcp, udp))
            tcp.listen()
            tcp.settimeout(0.1)
            udp.settimeout(0.1)
            port = tcp.getsockname()[1]
            self.ports.append(port)
            self.datagrams[port] = {}
            for target, sock in ((self.serve_tcp, tcp), (self.serve_udp, udp)):
                thread = threading.Thread(target=self.worker, args=(target, sock))
                thread.start()
                self.threads.append(thread)
        self.ports.sort()

    def worker(self, target, listener):
        try:
            target(listener)
        except Exception as error:
            with self.lock:
                self.errors.append(error)

    def check_errors(self):
        with self.lock:
            error = self.errors[0] if self.errors else None
        if error is not None:
            raise RuntimeError("controlled host service failed") from error

    def receipt_counts(self, nonce=None):
        self.check_errors()
        with self.lock:
            if nonce is None:
                return [sum(self.datagrams[port].values()) for port in self.ports]
            return [self.datagrams[port].get(f"{nonce}:{port}".encode(), 0) for port in self.ports]

    def serve_tcp(self, listener):
        while not self.stop.is_set():
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            with connection:
                connection.settimeout(5)
                connection.sendall(b"NVX_DIRECT_OK")

    def serve_udp(self, listener):
        while not self.stop.is_set():
            try:
                data, peer = listener.recvfrom(1024)
            except socket.timeout:
                continue
            port = listener.getsockname()[1]
            with self.lock:
                counts = self.datagrams[port]
                counts[data] = counts.get(data, 0) + 1
            if not self.drop_udp_replies:
                listener.sendto(b"NVX_DIRECT_OK" + data, peer)

    def close(self):
        self.stop.set()
        for thread in self.threads:
            thread.join()
        for sock in self.sockets:
            sock.close()
        self.check_errors()


def assert_network_probe(result, tcp, udp, deltas, correlated):
    if result != {"tcp": tcp, "udp": udp}:
        raise AssertionError("guest network probe outcomes differ from expected")
    expected = [int(value == "reached") for value in udp]
    if deltas != expected:
        raise AssertionError(f"UDP endpoint delivery count: expected {expected}, got {deltas}")
    if correlated != expected:
        raise AssertionError(f"UDP correlated delivery count: expected {expected}, got {correlated}")


def assert_lifecycle_rejected(result, expected, marker, state):
    diagnostic = f"aci-image-runner: policy_validation: {expected}\n".encode()
    if result.returncode != 1 or result.stdout or result.stderr != diagnostic:
        raise AssertionError(f"lifecycle request did not return the expected rejection: {expected}")
    if marker.exists():
        raise AssertionError("rejected lifecycle request wrote the guest marker")
    if state.exists():
        raise AssertionError("rejected lifecycle request created NVX state")


NETWORK_PROBE = """
import errno, json, os, socket
host = os.environ["NVX_HOST"]
ports = json.loads(os.environ["NVX_PORTS"])
nonce = os.environ["NVX_NONCE"]
def blocked(error):
    return isinstance(error, TimeoutError) or error.errno in (
        errno.EACCES, errno.EPERM, errno.ENETUNREACH, errno.EHOSTUNREACH,
        errno.ECONNREFUSED, errno.ETIMEDOUT
    )
def tcp(port):
    try:
        connection = socket.create_connection((host, port), timeout=2)
    except OSError as error:
        if blocked(error):
            return "blocked"
        raise
    with connection, connection.makefile("rb") as reader:
        assert reader.read(len(b"NVX_DIRECT_OK")) == b"NVX_DIRECT_OK"
    return "reached"
def udp(port):
    payload = (nonce + ":" + str(port)).encode()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
            connection.settimeout(2)
            connection.sendto(payload, (host, port))
            reply, peer = connection.recvfrom(1024)
    except OSError as error:
        if blocked(error):
            return "blocked"
        raise
    assert peer == (host, port), peer
    assert reply == b"NVX_DIRECT_OK" + payload, reply
    return "reached"
print(json.dumps({"tcp": [tcp(p) for p in ports], "udp": [udp(p) for p in ports]}))
"""

INGRESS_GUEST = """
import json, os, pathlib, select, socket, time
root = pathlib.Path(os.environ["NVX_ROOT"])
ports = json.loads(os.environ["NVX_PORTS"])
tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
tcp.bind(("0.0.0.0", ports[0]))
udp.bind(("0.0.0.0", ports[1]))
tcp.listen()
def local_control():
    with socket.create_connection(("127.0.0.1", ports[0]), timeout=2) as client:
        client.sendall(b"local")
        connection, _ = tcp.accept()
        with connection:
            assert connection.recv(16) == b"local"
            connection.sendall(b"reply")
        assert client.recv(16) == b"reply"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(2)
        client.sendto(b"local", ("127.0.0.1", ports[1]))
        data, peer = udp.recvfrom(16)
        assert data == b"local"
        udp.sendto(b"reply", peer)
        assert client.recv(16) == b"reply"
local_control()
(root / "ready").write_text("ready")
hits = [0, 0]
deadline = time.monotonic() + 55
while not (root / "stop").exists() and time.monotonic() < deadline:
    readable, _, _ = select.select([tcp, udp], [], [], 0.1)
    if tcp in readable:
        connection, _ = tcp.accept()
        with connection:
            if connection.recv(16) == b"probe":
                hits[0] += 1
                connection.sendall(b"reply")
    if udp in readable:
        data, peer = udp.recvfrom(16)
        if data == b"probe":
            hits[1] += 1
            udp.sendto(b"reply", peer)
local_control()
print(json.dumps(hits))
"""


class NvxPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.local = pathlib.Path(tempfile.mkdtemp(prefix="p", dir=SCRATCH))
        cls.env = os.environ.copy()
        cls.env["LOCALAPPDATA"] = str(cls.local)
        cls.env.pop("ACI_EDGE_SANDBOXES_AGENT_ARTIFACTS_DIR", None)
        cls.counter = 0
        print(f"owned LOCALAPPDATA={cls.local}", flush=True)

    @classmethod
    def command(cls, config):
        cls.counter += 1
        path = cls.local / f"request-{cls.counter}.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        return [str(RUNNER), "--config", str(path)]

    def run_request(self, config):
        return self.run_config_file(pathlib.Path(self.command(config)[2]))

    def run_config_file(self, path):
        result = subprocess.run([str(RUNNER), "--config", str(path)], env=self.env, capture_output=True, check=False)
        self.assertTrue((self.local / "Microsoft" / "MXC" / "nvx").is_dir())
        return result

    def success(self, config):
        result = self.run_request(config)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        return result.stdout

    def probe_network(self, services, policy, tcp, udp):
        nonce = uuid.uuid4().hex
        before = services.receipt_counts()
        config = request(python_command(NETWORK_PROBE), network={"egress": policy})
        config["process"].update({
            "env": [
                "NVX_HOST=" + services.host,
                "NVX_PORTS=" + json.dumps(services.ports),
                "NVX_NONCE=" + nonce,
            ],
            "inheritDefaultEnv": True,
        })
        result = json.loads(self.success(config))
        time.sleep(0.1)
        after = services.receipt_counts()
        assert_network_probe(result, tcp, udp, [end - start for start, end in zip(before, after)],
                             services.receipt_counts(nonce))

    def lifecycle_marker_request(self, root, name):
        config = request(f'printf STARTED > "$NVX_LIFECYCLE_ROOT/{name}"; printf LIFECYCLE_OK',
                         filesystem={"readwritePaths": [str(root)]})
        config["process"].update({
            "env": ["NVX_LIFECYCLE_ROOT=" + guest_path(root)],
            "inheritDefaultEnv": True,
        })
        return config

    def test_one_shot_lifecycle_defaults_and_explicit_valid(self):
        root = pathlib.Path(tempfile.mkdtemp(prefix="l", dir=SCRATCH))
        cases = [
            ("absent", None),
            ("empty", {}),
            ("destroy-default", {"destroyOnExit": True}),
            ("preserve-default", {"preservePolicy": False}),
            ("explicit", {"destroyOnExit": True, "preservePolicy": False}),
        ]
        for name, policy in cases:
            with self.subTest(case=name):
                marker = root / name
                self.assertFalse(marker.exists())
                config = self.lifecycle_marker_request(root, name)
                if policy is not None:
                    config["lifecycle"] = policy
                result = self.run_request(config)
                self.assertEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"LIFECYCLE_OK")
                self.assertEqual(marker.read_bytes(), b"STARTED")

    def test_one_shot_lifecycle_invalid_and_precedence(self):
        root = pathlib.Path(tempfile.mkdtemp(prefix="l", dir=SCRATCH))
        destroy_error = "NVX requires lifecycle.destroyOnExit=true"
        preserve_error = "NVX requires lifecycle.preservePolicy=false"
        cases = [
            ("destroy", {"destroyOnExit": False}, destroy_error),
            ("preserve", {"preservePolicy": True}, preserve_error),
            ("combined", {"destroyOnExit": False, "preservePolicy": True}, destroy_error),
        ]
        controls = []
        for name, policy, expected in cases:
            with self.subTest(case=name):
                local = pathlib.Path(tempfile.mkdtemp(prefix="s", dir=SCRATCH))
                environment = self.env.copy()
                environment["LOCALAPPDATA"] = str(local)
                state = local / "Microsoft" / "MXC" / "nvx"
                marker = root / name
                self.assertFalse(marker.exists())
                config = self.lifecycle_marker_request(root, name)
                config["lifecycle"] = policy.copy()
                result = subprocess.run(self.command(config), env=environment, capture_output=True, check=False)
                assert_lifecycle_rejected(result, expected, marker, state)
                if name == "combined":
                    config["lifecycle"].pop("destroyOnExit")
                    result = subprocess.run(self.command(config), env=environment, capture_output=True, check=False)
                    assert_lifecycle_rejected(result, preserve_error, marker, state)
                config["lifecycle"] = {}
                controls.append((name, config, environment, state))
        for name, config, environment, state in controls:
            with self.subTest(control=name):
                marker = root / name
                self.assertFalse(marker.exists())
                result = subprocess.run(self.command(config), env=environment, capture_output=True, check=False)
                self.assertEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"LIFECYCLE_OK")
                self.assertEqual(marker.read_bytes(), b"STARTED")
                self.assertTrue(state.is_dir())

    def test_one_shot_fallback_variants_and_host_cpu_profile(self):
        self.assertIn(b"Processor (host profile)", self.success(request("cat /proc/cpuinfo")))
        marker = "mxc-" + uuid.uuid4().hex
        command = (f"test ! -e /tmp/{marker} || exit 99; touch /tmp/{marker}; "
                   f"printf '{marker}'; printf 'fallback-stderr\\n' >&2; exit 42")
        for name, fallback in [
            ("absent", None),
            ("empty", {}),
            ("enabled", {"allowDaclMutation": True}),
            ("disabled", {"allowDaclMutation": False}),
        ]:
            with self.subTest(case=name):
                config = request(command)
                if fallback is not None:
                    config["fallback"] = fallback
                result = self.run_request(config)
                self.assertEqual(result.returncode, 42)
                self.assertEqual(result.stdout, marker.encode())
                self.assertIn(b"fallback-stderr\n", result.stderr)

    def test_one_shot_recovers_after_timeout(self):
        config = request("printf partial-out; printf 'partial-err\\n' >&2; sleep 5")
        config["process"]["timeout"] = 200
        timeout = self.run_request(config)
        self.assertEqual(timeout.returncode, 1)
        self.assertEqual(timeout.stdout, b"partial-out")
        self.assertIn(b"partial-err\n", timeout.stderr)
        self.assertIn(b"workload timed out", timeout.stderr)
        recovered = self.run_request(request("printf after-timeout"))
        self.assertEqual(recovered.returncode, 0)
        self.assertEqual(recovered.stdout, b"after-timeout")

    def test_process_streams_exit_cwd_env_timeout_and_memory(self):
        result = self.run_request(request("printf '\\000\\377A'; printf '\\200B' >&2; exit 7"))
        self.assertEqual(result.returncode, 7)
        self.assertEqual(result.stdout, b"\x00\xffA")
        self.assertTrue(result.stderr.endswith(b"\x80B"))
        config = request('test "$PWD" = /tmp && test "$NVX_TEST" = value && printf ENV_OK')
        config["process"].update({"cwd": "/tmp", "env": ["NVX_TEST=value"], "inheritDefaultEnv": True})
        config["microvm"]["provision"] = {"memoryMib": 512}
        self.assertEqual(self.success(config), b"ENV_OK")
        config = request("sleep 120; printf forbidden")
        config["process"]["timeout"] = 1000
        result = self.run_request(config)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(b"forbidden", result.stdout)
        self.assertIn(b"workload timed out", result.stderr)

    def test_upstream_one_shot_fixtures(self):
        fixture_dir = pathlib.Path(__file__).parent / "fixtures" / "microvm"
        fixtures = [
            ("hello", 0, b"Hello from MicroVM! sum=100\n"),
            ("exit_code", 42, b""),
            ("multiline", 0, b"".join(f"fib({i}) = {value}\n".encode() for i, value in enumerate([0, 1, 1, 2, 3, 5, 8, 13, 21, 34]))),
            ("stdlib", 0, b"shell=posix\nLinux\n"),
            ("error", 1, b""),
            ("timeout", 1, b""),
            ("large_output", 0, b"".join(f"line {i}: ".encode() + b"x" * 80 + b"\n" for i in range(1000))),
        ]
        for name, status, expected in fixtures:
            with self.subTest(fixture=name):
                result = self.run_config_file(fixture_dir / f"microvm_{name}.json")
                self.assertEqual(result.returncode, status, name)
                self.assertEqual(result.stdout, expected, name)
                if name == "error":
                    self.assertIn(b"intentional test error\n", result.stderr)
                if name == "timeout":
                    self.assertIn(b"workload timed out", result.stderr)

    def test_streams_are_live_and_a_broken_writer_stops_the_guest(self):
        config = request("printf BEFORE; sleep 2; printf AFTER")
        process = subprocess.Popen(self.command(config), env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(process.stdout.read(6), b"BEFORE")
        self.assertIsNone(process.poll(), "first output arrived only after the guest exited")
        stdout, stderr = process.communicate()
        self.assertEqual(process.returncode, 0, stderr.decode(errors="replace"))
        self.assertEqual(stdout, b"AFTER")
        config = request(python_command('import os\nos.write(2, b"WRITER_READY\\n")\nwhile True: os.write(1, b"x" * 65536)'))
        config["process"]["timeout"] = 30000
        process = subprocess.Popen(self.command(config), env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.stdout.close()
        while True:
            line = process.stderr.readline()
            self.assertTrue(line, "guest did not report writer readiness")
            if b"WRITER_READY\n" in line:
                break
        start = time.monotonic()
        stderr = process.stderr.read()
        process.stderr.close()
        self.assertEqual(process.wait(), 1)
        self.assertIn(b"stdout forwarding failed", stderr)
        self.assertLess(time.monotonic() - start, 25, "writer failure did not stop the workload before its timeout")

    def test_invalid_memory_environment_and_ui_are_rejected(self):
        cases = []
        config = request("printf forbidden")
        config["microvm"]["provision"] = {"memoryMib": 0}
        cases.append((config, b"memorymib must be greater than zero"))
        config = request("printf forbidden", ui={"disable": True})
        cases.append((config, b"does not support ui policy"))
        config = request("printf forbidden")
        config["process"].update({"env": ["MISSING_EQUALS"], "inheritDefaultEnv": True})
        config["network"] = {"ingress": {"default": "deny", "hostLoopback": "allow"}}
        cases.append((config, b"process.env entries must be key=value"))
        config = request("printf forbidden")
        config["process"]["cwd"] = "relative"
        cases.append((config, b"process.cwd must be an absolute"))
        config = request("printf forbidden")
        config["process"]["timeout"] = 3600001
        cases.append((config, b"process.timeout must not exceed"))
        config = request("printf forbidden")
        config["process"]["env"] = ["NVX_TEST=value"]
        cases.append((config, b"requires inheritdefaultenv=true"))
        for config, message in cases:
            result = subprocess.run(self.command(config), env=self.env, capture_output=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(b"forbidden", result.stdout)
            self.assertIn(message, result.stderr.lower())

    def test_filesystem_readonly_readwrite_and_deny(self):
        parent = pathlib.Path(tempfile.mkdtemp(prefix="f", dir=SCRATCH))
        actual = parent / "PolicyAlias"
        actual.mkdir()
        root = parent / "pOLICYalias"
        self.assertTrue(os.path.samefile(actual, root))
        self.assertEqual(guest_path(actual), guest_path(root))
        ro, rw = root / "ro", root / "rw"
        ro.mkdir()
        rw.mkdir()
        (ro / "input").write_bytes(b"read-ok")
        (rw / "secret").write_bytes(b"secret")
        (root / "ungranted").write_bytes(b"ungranted")
        script = """
import errno, os, pathlib
root = pathlib.Path(os.environ["NVX_ROOT"])
assert (root / "ro" / "input").read_bytes() == b"read-ok"
for path, write, expected in [
    (root / "ro" / "input", True, (errno.EACCES, errno.EROFS)),
    (root / "rw" / "secret", False, (errno.EACCES,)),
    (root / "rw" / "secret", True, (errno.EACCES,)),
    (root / "ungranted", False, (errno.EACCES, errno.ENOENT)),
    (root / "ungranted", True, (errno.EACCES, errno.ENOENT, errno.EROFS)),
]:
    try:
        if write:
            with path.open("r+b") as output:
                output.write(b"forbidden")
        else:
            path.read_bytes()
    except OSError as error:
        assert error.errno in expected, error
    else:
        raise AssertionError("policy unexpectedly permitted access")
(root / "rw" / "result").write_bytes(b"write-ok")
print("NVX_FILESYSTEM_OK", end="")
"""
        config = request(python_command(script), network={}, filesystem={
            "readonlyPaths": [str(ro)], "readwritePaths": [str(rw)],
            "deniedPaths": [str(rw / "secret")],
        })
        config["process"].update({"env": ["NVX_ROOT=" + guest_path(root)], "inheritDefaultEnv": True})
        self.assertEqual(self.success(config), b"NVX_FILESYSTEM_OK")
        self.assertEqual((ro / "input").read_bytes(), b"read-ok")
        self.assertEqual((rw / "secret").read_bytes(), b"secret")
        self.assertEqual((rw / "result").read_bytes(), b"write-ok")
        self.assertEqual((root / "ungranted").read_bytes(), b"ungranted")

    def test_credentialed_proxy_rejection_withholds_details_and_run_state(self):
        username = "mxc-test-user-" + uuid.uuid4().hex
        password = "mxc-test-password-" + uuid.uuid4().hex
        cases = [
            ("credentialed-loopback", f"http://{username}:{password}@[::1]:3128",
             (b"validate_provision", b"withheld")),
            ("user-only-loopback", f"http://{username}@[::1]:3128",
             (b"validate_provision", b"withheld")),
            ("loopback", "http://[::1]:3128", (b"OpenVMM reaches host loopback",)),
            ("credentialed-remote", f"http://{username}:{password}@192.0.2.1:3128", (b"localhost",)),
        ]
        for name, proxy, expected in cases:
            with self.subTest(case=name):
                local = pathlib.Path(tempfile.mkdtemp(prefix="c", dir=SCRATCH))
                environment = self.env.copy()
                environment["LOCALAPPDATA"] = str(local)
                config = request("printf forbidden", network={"egress": {"default": "deny"}},
                                 runtimeConfig={"networkProxy": proxy})
                command = self.command(config)
                try:
                    result = subprocess.run(command, env=environment, capture_output=True, check=False)
                finally:
                    pathlib.Path(command[2]).unlink()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(b"forbidden" in result.stdout, "rejected request ran its guest command")
                self.assertFalse(any(value.encode() in result.stdout + result.stderr for value in (username, password)),
                                 "proxy diagnostics leaked synthetic credentials")
                for text in expected:
                    self.assertTrue(text in result.stderr, f"{name}: expected proxy diagnostic absent")
                state = local / "Microsoft" / "MXC" / "nvx"
                if state.is_dir():
                    roots = [state, *(child for child in state.iterdir() if child.is_dir())]
                    self.assertFalse(any((root / "templates").exists() for root in roots),
                                     "rejected request created a template store")
                    self.assertFalse(any(
                        re.fullmatch(r"[0-9a-f]{32}", entry.name)
                        for root in roots for entry in root.iterdir() if entry.is_dir()
                    ), "rejected request retained a sandbox record")

    def test_egress_cidr_protocol_ports_and_deny(self):
        services = ControlledServices()
        try:
            host, ports = services.host, services.ports
            low, high = ports
            destination = {"cidr": host + "/32"}
            rule = lambda protocol, port: {"to": [destination], "ports": [{"protocol": protocol, "port": port}]}
            port_range = lambda protocol, start, end: {
                "to": [destination], "ports": [{"protocol": protocol, "port": start, "endPort": end}]
            }
            other_host = str(ipaddress.IPv4Address(int(ipaddress.IPv4Address(host)) ^ 1))
            cases = [
                ({"default": "allow"}, ["reached", "reached"], ["reached", "reached"]),
                ({"allow": [rule("tcp", ports[0])]}, ["reached", "blocked"], ["blocked", "blocked"]),
                ({"allow": [rule("tcp", ports[1])]}, ["blocked", "reached"], ["blocked", "blocked"]),
                ({"allow": [rule("udp", ports[0])]}, ["blocked", "blocked"], ["reached", "blocked"]),
                ({"allow": [rule("udp", ports[1])]}, ["blocked", "blocked"], ["blocked", "reached"]),
                ({"allow": [{"to": [destination]}], "deny": [rule("tcp", ports[0])]},
                 ["blocked", "reached"], ["reached", "reached"]),
                ({"allow": [{"to": [destination]}], "deny": [port_range("udp", low, high)]},
                 ["reached", "reached"], ["blocked", "blocked"]),
                ({"allow": [port_range("tcp", low, high)]}, ["reached", "reached"], ["blocked", "blocked"]),
                ({"allow": [port_range("udp", low, high)]}, ["blocked", "blocked"], ["reached", "reached"]),
                ({"allow": [port_range("tcp", low + 1, high)]}, ["blocked", "reached"], ["blocked", "blocked"]),
                ({"allow": [port_range("tcp", low, high - 1)]}, ["reached", "blocked"], ["blocked", "blocked"]),
                ({"allow": [port_range("udp", low + 1, high)]}, ["blocked", "blocked"], ["blocked", "reached"]),
                ({"allow": [port_range("udp", low, high - 1)]}, ["blocked", "blocked"], ["reached", "blocked"]),
                ({"allow": [port_range("any", low, high)]}, ["reached", "reached"], ["reached", "reached"]),
                ({"allow": [{"to": [{"cidr": other_host + "/32"}]}]}, ["blocked", "blocked"], ["blocked", "blocked"]),
                ({"allow": [{"to": [{"cidr": "0.0.0.0/0"}]}]}, ["reached", "reached"], ["reached", "reached"]),
                ({"allow": [{"to": [{"cidr": "0.0.0.0/0", "except": [host + "/32"]}]}]},
                 ["blocked", "blocked"], ["blocked", "blocked"]),
                ({}, ["blocked", "blocked"], ["blocked", "blocked"]),
                ({"default": "allow"}, ["reached", "reached"], ["reached", "reached"]),
            ]
            for index, (policy, tcp, udp) in enumerate(cases):
                with self.subTest(case=index):
                    self.probe_network(services, policy, tcp, udp)
        finally:
            services.close()

    def test_runtime_proxy_with_deny_default(self):
        services = ControlledServices()
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(60)
        port = listener.getsockname()[1]
        received = []
        def serve():
            try:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(10)
                    data = b""
                    while not data.endswith(b"\r\n\r\n") and len(data) < 8192:
                        byte = connection.recv(1)
                        if not byte:
                            raise OSError("proxy client closed before its headers")
                        data += byte
                    received.append(data)
                    connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\nNVX_PROXY_OK")
            except OSError as error:
                received.append(error)
        worker = threading.Thread(target=serve)
        worker.start()
        try:
            self.probe_network(services, {"default": "allow"}, ["reached", "reached"], ["reached", "reached"])
            script = """
import errno, json, os, socket, urllib.request
try:
    connection = socket.create_connection((os.environ["NVX_HOST"], int(os.environ["NVX_PORT"])), timeout=2)
except OSError as error:
    if not (isinstance(error, TimeoutError) or error.errno in (
        errno.EACCES, errno.EPERM, errno.ENETUNREACH, errno.EHOSTUNREACH,
        errno.ECONNREFUSED, errno.ETIMEDOUT
    )):
        raise
    direct = "blocked"
else:
    with connection, connection.makefile("rb") as reader:
        assert reader.read(len(b"NVX_DIRECT_OK")) == b"NVX_DIRECT_OK"
    direct = "reached"
proxy = urllib.request.urlopen("http://mxc-policy.invalid/probe", timeout=10).read().decode()
print(json.dumps({"direct": direct, "proxy": proxy}))
"""
            config = request(python_command(script), network={"egress": {}},
                             runtimeConfig={"networkProxy": f"http://127.0.0.1:{port}"})
            config["process"].update({
                "env": ["NVX_HOST=" + services.host, "NVX_PORT=" + str(services.ports[0])],
                "inheritDefaultEnv": True,
            })
            self.assertEqual(json.loads(self.success(config)), {"direct": "blocked", "proxy": "NVX_PROXY_OK"})
            self.probe_network(services, {"default": "allow"}, ["reached", "reached"], ["reached", "reached"])
        finally:
            worker.join()
            listener.close()
            services.close()
        self.assertTrue(received and isinstance(received[0], bytes))
        self.assertTrue(received[0].startswith(b"GET http://mxc-policy.invalid/probe HTTP/1.1\r\n"))

    def test_host_loopback_ingress_allow_and_deny(self):
        tcp = socket.socket()
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        tcp.bind(("127.0.0.1", 0))
        udp.bind(("127.0.0.1", 0))
        ports = [tcp.getsockname()[1], udp.getsockname()[1]]
        tcp.close()
        udp.close()
        for posture, egress in [("allow", "allow"), ("deny", "allow"), ("allow", "deny")]:
            with self.subTest(posture=posture, egress=egress):
                root = pathlib.Path(tempfile.mkdtemp(prefix="i", dir=SCRATCH))
                config = request(python_command(INGRESS_GUEST),
                                 filesystem={"readwritePaths": [str(root)]},
                                 network={"egress": {"default": egress},
                                          "ingress": {"default": "deny", "hostLoopback": posture}})
                config["process"].update({"timeout": 60000, "inheritDefaultEnv": True,
                                          "env": ["NVX_ROOT=" + guest_path(root), "NVX_PORTS=" + json.dumps(ports)]})
                process = subprocess.Popen(self.command(config), env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                observed = [False, False]
                try:
                    deadline = time.monotonic() + 120
                    while not (root / "ready").exists() and process.poll() is None and time.monotonic() < deadline:
                        time.sleep(0.05)
                    self.assertTrue((root / "ready").exists(), "guest listeners did not become ready")
                    time.sleep(1.5)
                    for index, port in enumerate(ports):
                        deadline = time.monotonic() + (8 if posture == "allow" else 3)
                        while time.monotonic() < deadline:
                            try:
                                with socket.socket(socket.AF_INET, socket.SOCK_STREAM if index == 0 else socket.SOCK_DGRAM) as client:
                                    client.settimeout(0.5)
                                    if index == 0:
                                        client.connect(("127.0.0.1", port))
                                        client.sendall(b"probe")
                                    else:
                                        client.sendto(b"probe", ("127.0.0.1", port))
                                    if client.recv(16) == b"reply":
                                        observed[index] = True
                                        break
                            except (ConnectionRefusedError, ConnectionResetError, TimeoutError, BlockingIOError):
                                time.sleep(0.05)
                finally:
                    (root / "stop").write_text("stop")
                    stdout, stderr = process.communicate()
                self.assertEqual(process.returncode, 0, stderr.decode(errors="replace"))
                self.assertEqual(observed, [posture == "allow"] * 2)
                hits = json.loads(stdout)
                self.assertEqual([count > 0 for count in hits], observed)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runner", required=True, type=pathlib.Path)
    parser.add_argument("--scratch", required=True, type=pathlib.Path)
    parser.add_argument("tests", nargs="*", help="optional unittest names")
    args = parser.parse_args()
    RUNNER = args.runner.resolve(strict=True)
    SCRATCH = args.scratch.resolve(strict=True)
    if os.name != "nt" or not SCRATCH.is_dir():
        parser.error("requires Windows and an existing owned scratch directory")
    unittest.main(argv=[__file__, *args.tests], verbosity=2)
