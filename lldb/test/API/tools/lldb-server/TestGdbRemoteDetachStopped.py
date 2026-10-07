"""Test PID-specific and detach-all packets that leave inferiors stopped."""

import os
from pathlib import Path
import signal
import time

from fork_testbase import GdbRemoteForkTestBase
from lldbsuite.test.decorators import skipIf, skipIfRemote, no_match


@skipIf(oslist=no_match(["linux"]))
@skipIfRemote
class TestGdbRemoteDetachStopped(GdbRemoteForkTestBase):
    def assert_stopped(self, pid):
        deadline = time.monotonic() + 5
        while True:
            state = next(
                line for line in Path(f"/proc/{pid}/status").read_text().splitlines()
                if line.startswith("State:")
            )
            if "T (stopped)" in state:
                return
            self.assertLess(time.monotonic(), deadline, state)
            time.sleep(0.01)

    def check_detach(self, variant="fork", detach_parent=False, detach_all=False):
        parent_pid, parent_tid, child_pid, child_tid = self.start_fork_test([variant], variant)
        detach_pid = parent_pid if detach_parent else child_pid
        pids = [parent_pid, child_pid] if detach_all else [detach_pid]

        def cleanup():
            for pid in pids:
                try:
                    os.kill(int(pid, 16), signal.SIGKILL)
                except ProcessLookupError:
                    pass

        self.addTearDownHook(cleanup)
        self.test_sequence.add_log_lines([
            "read packet: $qSupportsDetachAndStayStopped:#00",
            "send packet: $OK#00",
            "read packet: $D1{}#00".format("" if detach_all else ";" + detach_pid),
            "send packet: $OK#00",
        ], True)
        self.expect_gdbremote_sequence()
        self.reset_test_sequence()
        for pid in pids:
            self.assert_stopped(int(pid, 16))

        # The detached process is no longer selectable, while the other
        # process remains available on the original connection.
        lines = []
        for pid, tid in ((parent_pid, parent_tid), (child_pid, child_tid)):
            lines += [
                f"read packet: $Hgp{pid}.{tid}#00",
                "send packet: ${}#00".format("Eff" if pid in pids else "OK"),
            ]
        self.test_sequence.add_log_lines(lines, True)
        self.expect_gdbremote_sequence()

    def test_fork_child(self):
        self.check_detach()

    def test_fork_parent(self):
        self.check_detach(detach_parent=True)

    def test_vfork_child(self):
        self.check_detach(variant="vfork")

    def test_detach_all(self):
        self.check_detach(detach_all=True)

    def test_malformed_packets(self):
        self.build()
        self.prep_debug_monitor_and_inferior()
        for packet in ("D2", "D1;", "D1;1junk", "D1;10000000000000000"):
            self.test_sequence.add_log_lines([
                f"read packet: ${packet}#00",
                {"direction": "send", "regex": r"^\$E[0-9a-f]+.*#"},
            ], True)
        self.expect_gdbremote_sequence()
