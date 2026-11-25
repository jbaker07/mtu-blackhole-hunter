"""Tests for mtu_hunter.py.

The unit tests replace ping, curl and the TCP connect with fakes, so they need no network
and run the same on any machine. The loopback test runs the real tool against 127.0.0.1.
The stand in ping test runs the real tool with tests/fake_ping/ping first in PATH, which
acts like a path with a 1300 byte link, so the low MTU branch runs without root.
The internet test runs it against example.com and is skipped when that cannot be reached.
On Linux as root, a namespace lab puts a real 1300 byte link in the path.
On macOS with MTU_HUNTER_LO0_TEST=1, the loopback MTU is set to 1300 with sudo for the
real ping, then put back. It changes a system setting, so it only runs when asked.

Run from the repository root:
    python3 -m unittest discover -s tests -v
"""
import io
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_DIR)
import mtu_hunter  # noqa: E402

TOOL = os.path.join(REPO_DIR, "mtu_hunter.py")


def fake_ping_run(largest_working_size):
    """A stand-in for mtu_hunter.run where DF pings up to largest_working_size get a reply."""
    commands_seen = []

    def fake_run(cmd, timeout=None):
        commands_seen.append(cmd)
        size = int(cmd[cmd.index("-s") + 1])
        if largest_working_size is not None and size <= largest_working_size:
            return 0, "", ""
        return 1, "", ""

    return fake_run, commands_seen


class DfPingTests(unittest.TestCase):

    def test_linux_command_sets_df_with_dash_M_do(self):
        fake_run, commands_seen = fake_ping_run(1472)
        with mock.patch.object(mtu_hunter, "run", fake_run), \
             mock.patch.object(mtu_hunter, "have", return_value=True), \
             mock.patch.object(mtu_hunter.sys, "platform", "linux"):
            mtu_hunter.df_ping("192.0.2.10")
        self.assertEqual(commands_seen[0], ["ping", "-c", "1", "-W", "2", "-M", "do", "-s", "1472", "192.0.2.10"])

    def test_macos_command_sets_df_with_dash_D_and_a_seconds_timeout(self):
        fake_run, commands_seen = fake_ping_run(1472)
        with mock.patch.object(mtu_hunter, "run", fake_run), \
             mock.patch.object(mtu_hunter, "have", return_value=True), \
             mock.patch.object(mtu_hunter.sys, "platform", "darwin"):
            mtu_hunter.df_ping("192.0.2.10")
        # -W on macOS is milliseconds, so the tool must use -t (seconds) there
        self.assertEqual(commands_seen[0], ["ping", "-c", "1", "-t", "2", "-D", "-s", "1472", "192.0.2.10"])

    def test_ladder_walks_1472_down_to_1232_in_40_byte_steps(self):
        self.assertEqual(mtu_hunter.SIZES, [1472, 1432, 1392, 1352, 1312, 1272, 1232])

    def test_best_is_the_largest_size_that_works(self):
        fake_run, _ = fake_ping_run(1360)
        with mock.patch.object(mtu_hunter, "run", fake_run), \
             mock.patch.object(mtu_hunter, "have", return_value=True):
            best, ladder = mtu_hunter.df_ping("192.0.2.10")
        self.assertEqual(best, 1352)
        self.assertEqual([size for size, ok in ladder if not ok], [1472, 1432, 1392])

    def test_no_size_works(self):
        fake_run, _ = fake_ping_run(None)
        with mock.patch.object(mtu_hunter, "run", fake_run), \
             mock.patch.object(mtu_hunter, "have", return_value=True):
            best, ladder = mtu_hunter.df_ping("192.0.2.10")
        self.assertIsNone(best)
        self.assertEqual(len(ladder), 7)


def ladder_for(best):
    return [(size, best is not None and size <= best) for size in mtu_hunter.SIZES]


CURL_OK = "lookup:0.001 connect:0.010 tls:0.030 ttfb:0.050 total:0.051"


class VerdictTests(unittest.TestCase):

    def verdict(self, best, tcp_ok, curl_t, icmp_ok=True):
        return mtu_hunter.summarize(best, ladder_for(best), tcp_ok, 0.012 if tcp_ok else None,
                                    curl_t, "", "example.test", 443, icmp_ok)

    def test_healthy_path_exits_0(self):
        text, code = self.verdict(1472, True, CURL_OK)
        self.assertEqual(code, 0)
        self.assertIn("No clear MTU issue detected.", text)

    def test_largest_df_size_below_1400_exits_2(self):
        text, code = self.verdict(1352, True, CURL_OK)
        self.assertEqual(code, 2)
        self.assertIn("Probable MTU/PMTUD issue.", text)
        self.assertIn("DF probes fail at common sizes (below 1400)", text)

    def test_no_df_size_at_all_exits_2(self):
        text, code = self.verdict(None, True, CURL_OK)
        self.assertEqual(code, 2)

    def test_tcp_works_but_tls_fails_exits_2(self):
        text, code = self.verdict(1472, True, None)
        self.assertEqual(code, 2)
        self.assertIn("TCP handshake OK but TLS fetch failed", text)

    def test_tcp_failure_without_mtu_signs_exits_3(self):
        text, code = self.verdict(1472, False, None)
        self.assertEqual(code, 3)
        self.assertIn("TCP connectivity failure", text)

    def test_host_that_ignores_ping_is_not_an_mtu_problem(self):
        # every DF ping fails because the host drops ICMP, but TCP and TLS work
        text, code = self.verdict(None, True, CURL_OK, icmp_ok=False)
        self.assertEqual(code, 0)
        self.assertIn("no reply to a plain ping", text)

    def test_host_that_ignores_ping_with_tls_failure_still_exits_2(self):
        text, code = self.verdict(None, True, None, icmp_ok=False)
        self.assertEqual(code, 2)
        self.assertNotIn("DF probes fail at common sizes", text)

    def test_remediation_lists_mss_clamping(self):
        text, _ = self.verdict(1352, True, CURL_OK)
        self.assertIn("MSS clamping", text)


class CommandLineTests(unittest.TestCase):

    def test_dns_failure_exits_4(self):
        with mock.patch.object(mtu_hunter.socket, "getaddrinfo", side_effect=socket.gaierror("no such host")), \
             mock.patch.object(sys, "argv", ["mtu_hunter.py", "--dest", "no-such-host.invalid"]), \
             mock.patch("sys.stderr", new_callable=io.StringIO):
            with self.assertRaises(SystemExit) as raised:
                mtu_hunter.main()
        self.assertEqual(raised.exception.code, 4)

    def test_missing_dest_is_a_usage_error(self):
        with mock.patch.object(sys, "argv", ["mtu_hunter.py"]), \
             mock.patch("sys.stderr", new_callable=io.StringIO):
            with self.assertRaises(SystemExit) as raised:
                mtu_hunter.main()
        self.assertEqual(raised.exception.code, 2)

    def test_main_prints_the_report_and_exits_with_the_verdict(self):
        with mock.patch.object(mtu_hunter.socket, "getaddrinfo", return_value=[]), \
             mock.patch.object(mtu_hunter, "icmp_reachable", return_value=True), \
             mock.patch.object(mtu_hunter, "df_ping", return_value=(1312, ladder_for(1312))), \
             mock.patch.object(mtu_hunter, "trace_path", return_value=""), \
             mock.patch.object(mtu_hunter, "tcp_handshake", return_value=(True, 0.02)), \
             mock.patch.object(mtu_hunter, "curl_tls_timing", return_value=None), \
             mock.patch.object(sys, "argv", ["mtu_hunter.py", "--dest", "example.test"]):
            output = io.StringIO()
            with redirect_stdout(output), self.assertRaises(SystemExit) as raised:
                mtu_hunter.main()
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("DF probe: first success at payload 1312 bytes", output.getvalue())

    def test_slow_command_is_cut_off(self):
        rc, out, err = mtu_hunter.run([sys.executable, "-c", "import time; print('started', flush=True); time.sleep(5)"], timeout=1)
        self.assertEqual(rc, 124)
        self.assertIn("timed out", err)


class StandInPingTests(unittest.TestCase):

    @unittest.skipUnless(mtu_hunter.have("ping"), "ping is not installed")
    def test_1300_byte_link_with_the_stand_in_ping(self):
        log_dir = tempfile.mkdtemp()
        log_path = os.path.join(log_dir, "ping.log")
        env = dict(os.environ)
        env["REAL_PING"] = shutil.which("ping")
        env["FAKE_PING_LOG"] = log_path
        env["PATH"] = os.path.join(REPO_DIR, "tests", "fake_ping") + os.pathsep + env["PATH"]
        try:
            result = subprocess.run([sys.executable, TOOL, "--dest", "127.0.0.1", "--port", "9"], env=env,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120)
            with open(log_path) as f:
                calls = f.read().splitlines()
        finally:
            shutil.rmtree(log_dir, ignore_errors=True)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("DF probe: first success at payload 1272 bytes", result.stdout)
        self.assertIn("DF ladder FAIL: [1472, 1432, 1392, 1352, 1312]", result.stdout)
        if sys.platform == "darwin":
            self.assertIn("-c 1 -t 2 -D -s 1472 127.0.0.1", calls)
        else:
            self.assertIn("-c 1 -W 2 -M do -s 1472 127.0.0.1", calls)


@unittest.skipUnless(sys.platform == "darwin" and os.environ.get("MTU_HUNTER_LO0_TEST") == "1",
                     "needs macOS, passwordless sudo and MTU_HUNTER_LO0_TEST=1")
class MacLoopbackMtuTests(unittest.TestCase):
    """Sets lo0 to MTU 1300 with sudo and adds a test address, so the real macOS ping hits a 1300 byte limit."""

    ADDRESS = "192.0.2.98"

    @classmethod
    def setUpClass(cls):
        out = subprocess.run(["ifconfig", "lo0"], stdout=subprocess.PIPE, text=True).stdout
        cls.mtu_before = out.split(" mtu ")[1].split()[0]
        # registered first, so lo0 is put back even if a step below fails
        cls.addClassCleanup(cls.restore_lo0)
        # the alias is added after the MTU change, so its route is created with the small MTU
        subprocess.run(["sudo", "-n", "ifconfig", "lo0", "mtu", "1300"], check=True)
        subprocess.run(["sudo", "-n", "ifconfig", "lo0", "alias", cls.ADDRESS, "netmask", "255.255.255.255"], check=True)

    @classmethod
    def restore_lo0(cls):
        subprocess.run(["sudo", "-n", "ifconfig", "lo0", "-alias", cls.ADDRESS])
        subprocess.run(["sudo", "-n", "ifconfig", "lo0", "mtu", cls.mtu_before])

    def test_real_ping_sees_the_1300_byte_limit(self):
        fits = subprocess.run(["ping", "-c", "1", "-t", "2", "-D", "-s", "1272", self.ADDRESS],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        too_big = subprocess.run(["ping", "-c", "1", "-t", "2", "-D", "-s", "1273", self.ADDRESS],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.assertEqual(fits.returncode, 0)
        self.assertNotEqual(too_big.returncode, 0)

    def test_tool_reports_the_1300_byte_loopback_path(self):
        result = subprocess.run([sys.executable, TOOL, "--dest", self.ADDRESS, "--port", "9"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=180)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("DF probe: first success at payload 1272 bytes", result.stdout)
        self.assertIn("Probable MTU/PMTUD issue.", result.stdout)


def internet_reachable():
    try:
        with socket.create_connection(("example.com", 443), timeout=3):
            return True
    except OSError:
        return False


class RealNetworkTests(unittest.TestCase):

    @unittest.skipUnless(mtu_hunter.have("ping"), "ping is not installed")
    def test_loopback_ladder_passes_and_closed_port_exits_3(self):
        # loopback has a large MTU, so every DF size gets through. Port 9 is closed, so TCP fails.
        result = subprocess.run([sys.executable, TOOL, "--dest", "127.0.0.1", "--port", "9"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120)
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("DF ladder OK: [1472, 1432, 1392, 1352, 1312, 1272, 1232]", result.stdout)
        self.assertIn("DF ladder FAIL: none", result.stdout)

    @unittest.skipUnless(internet_reachable(), "example.com:443 is not reachable, internet test skipped")
    def test_example_com_has_no_mtu_issue(self):
        result = subprocess.run([sys.executable, TOOL, "--dest", "example.com", "--port", "443"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=180)
        self.assertIn("TCP handshake to example.com:443: OK", result.stdout)
        self.assertIn("curl timing → lookup:", result.stdout)


def can_build_namespaces():
    return sys.platform.startswith("linux") and hasattr(os, "geteuid") and os.geteuid() == 0 \
        and mtu_hunter.have("ip") and mtu_hunter.have("ping")


@unittest.skipUnless(can_build_namespaces(), "needs Linux, root and iproute2 (sudo python3 -m unittest ...)")
class NamespaceLabTests(unittest.TestCase):
    """client 10.78.1.2 -> router -> server 10.78.2.2, with a 1300 byte link between router and server.

    The router answers oversized DF packets with ICMP fragmentation needed, like a real hop.
    A small TCP listener on the server makes the handshake work, while the TLS fetch fails
    because the listener does not speak TLS.
    """

    NAMESPACES = ["mh_client", "mh_router", "mh_server"]

    @classmethod
    def sh(cls, *args):
        subprocess.run(list(args), check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @classmethod
    def setUpClass(cls):
        cls.tearDownClass()
        for ns in cls.NAMESPACES:
            cls.sh("ip", "netns", "add", ns)
            cls.sh("ip", "-n", ns, "link", "set", "lo", "up")
        cls.sh("ip", "link", "add", "mh_c0", "type", "veth", "peer", "name", "mh_r0")
        cls.sh("ip", "link", "add", "mh_r1", "type", "veth", "peer", "name", "mh_s0")
        for dev, ns in [("mh_c0", "mh_client"), ("mh_r0", "mh_router"), ("mh_r1", "mh_router"), ("mh_s0", "mh_server")]:
            cls.sh("ip", "link", "set", dev, "netns", ns)
        for ns, dev, addr in [("mh_client", "mh_c0", "10.78.1.2/24"), ("mh_router", "mh_r0", "10.78.1.1/24"),
                              ("mh_router", "mh_r1", "10.78.2.1/24"), ("mh_server", "mh_s0", "10.78.2.2/24")]:
            cls.sh("ip", "-n", ns, "addr", "add", addr, "dev", dev)
            cls.sh("ip", "-n", ns, "link", "set", dev, "up")
        cls.sh("ip", "-n", "mh_router", "link", "set", "mh_r1", "mtu", "1300")
        cls.sh("ip", "-n", "mh_server", "link", "set", "mh_s0", "mtu", "1300")
        cls.sh("ip", "-n", "mh_client", "route", "add", "default", "via", "10.78.1.1")
        cls.sh("ip", "-n", "mh_server", "route", "add", "default", "via", "10.78.2.1")
        cls.sh("ip", "netns", "exec", "mh_router", "sysctl", "-qw", "net.ipv4.ip_forward=1")
        cls.listener = subprocess.Popen(["ip", "netns", "exec", "mh_server", sys.executable, "-c",
                                         "import socket\n"
                                         "s = socket.socket()\n"
                                         "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
                                         "s.bind(('10.78.2.2', 8443))\n"
                                         "s.listen(8)\n"
                                         "while True:\n"
                                         "    c, _ = s.accept()\n"
                                         "    c.close()\n"],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @classmethod
    def tearDownClass(cls):
        listener = getattr(cls, "listener", None)
        if listener is not None:
            listener.kill()
            listener.wait()
        for ns in cls.NAMESPACES:
            subprocess.run(["ip", "netns", "del", ns], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def test_1300_byte_hop_is_reported_as_probable_mtu_issue(self):
        result = subprocess.run(["ip", "netns", "exec", "mh_client", sys.executable, TOOL,
                                 "--dest", "10.78.2.2", "--port", "8443"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=180)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        # 1272 bytes of payload plus 28 bytes of IP and ICMP headers is the 1300 byte link
        self.assertIn("DF probe: first success at payload 1272 bytes", result.stdout)
        self.assertIn("DF ladder FAIL: [1472, 1432, 1392, 1352, 1312]", result.stdout)
        self.assertIn("TCP handshake to 10.78.2.2:8443: OK", result.stdout)
        self.assertIn("Probable MTU/PMTUD issue.", result.stdout)
        if mtu_hunter.have("tracepath"):
            self.assertIn("pmtu 1300", result.stdout)


if __name__ == "__main__":
    unittest.main()
