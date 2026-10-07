"""Detach-and-stay-stopped works at signal, breakpoint, fork and exec stops."""

import os
from pathlib import Path
import signal
import time

import lldb
from lldbsuite.test import lldbutil
from lldbsuite.test.decorators import skipIf, skipIfRemote, no_match
from lldbsuite.test.lldbtest import TestBase


@skipIf(oslist=no_match(["linux"]))
@skipIfRemote
class DetachStoppedTestCase(TestBase):
    NO_DEBUG_INFO_TESTCASE = True

    def check_detach(self, mode, reattach=False):
        self.build()
        marker = self.getBuildArtifact(self._testMethodName + ".resumed")
        ready = self.getBuildArtifact(self._testMethodName + ".ready")
        for path in (marker, ready):
            Path(path).unlink(missing_ok=True)

        # Keep the inferior's real parent alive across detach. A launched
        # inferior's separate process group becomes orphaned when its server
        # exits; Linux then sends SIGHUP and SIGCONT to a stopped group.
        popen = self.spawnSubprocess(self.getBuildArtifact(), [mode, marker, ready])
        lldbutil.wait_for_file_on_target(self, ready)
        target = self.dbg.CreateTarget(self.getBuildArtifact())
        error = lldb.SBError()
        process = target.AttachToProcessWithID(self.dbg.GetListener(), popen.pid, error)
        self.assertSuccess(error)
        target.BreakpointCreateByName("before_detach")
        self.runCmd("expression -- start = true")
        self.assertSuccess(process.Continue())
        self.assertState(process.GetState(), lldb.eStateStopped)
        if mode == "signal":
            os.kill(process.GetProcessID(), signal.SIGSTOP)
            self.assertSuccess(process.Continue())
            self.assertEqual(process.GetSelectedThread().GetStopReason(), lldb.eStopReasonSignal)
        elif mode in ("fork", "vfork"):
            self.runCmd(f"settings set target.process.stop-on-{mode} true")
            self.assertSuccess(process.Continue())
            reason = lldb.eStopReasonFork if mode == "fork" else lldb.eStopReasonVFork
            self.assertEqual(process.GetSelectedThread().GetStopReason(), reason)
        elif mode == "exec":
            self.assertSuccess(process.Continue())
            self.assertEqual(process.GetSelectedThread().GetStopReason(), lldb.eStopReasonExec)

        pid = process.GetProcessID()

        def cleanup():
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

        self.addTearDownHook(cleanup)
        self.assertSuccess(process.Detach(True))
        self.assertState(process.GetState(), lldb.eStateDetached)

        # Inspect every thread, since a process-wide stop can complete after
        # PTRACE_DETACH returns. No thread may execute the marker write.
        deadline = time.monotonic() + 5
        while True:
            states = [
                next(line for line in status.read_text().splitlines() if line.startswith("State:"))
                for status in Path(f"/proc/{pid}/task").glob("*/status")
            ]
            if states and all("T (stopped)" in state for state in states):
                break
            self.assertLess(time.monotonic(), deadline, states)
            time.sleep(0.01)
        time.sleep(0.1)
        self.assertFalse(os.path.exists(marker), "detached threads must not run")

        if reattach:
            other_target = self.dbg.CreateTarget(self.getBuildArtifact())
            error = lldb.SBError()
            other_process = other_target.AttachToProcessWithID(self.dbg.GetListener(), pid, error)
            self.assertSuccess(error)
            self.assertFalse(os.path.exists(marker), "attach must not run the process")
            self.assertSuccess(other_process.Continue())
            thread = other_process.GetSelectedThread()
            self.assertState(other_process.GetState(), lldb.eStateExited,
                             f"reason={thread.GetStopReason()}, signal={thread.GetStopReasonDataAtIndex(0)}")
            self.assertEqual(other_process.GetExitStatus(), 0)
        else:
            os.kill(pid, signal.SIGCONT)
            lldbutil.wait_for_file_on_target(self, marker)
        self.assertEqual(popen.wait(timeout=10), 0)

    def test_signal(self):
        self.check_detach("signal")

    def test_breakpoint(self):
        self.check_detach("breakpoint")

    def test_threads(self):
        self.check_detach("threads")

    def test_fork_event(self):
        self.check_detach("fork")

    def test_vfork_event(self):
        self.check_detach("vfork")

    def test_exec_event(self):
        self.check_detach("exec")

    def test_reattach(self):
        self.check_detach("breakpoint", reattach=True)

    def test_reattach_threads(self):
        self.check_detach("threads", reattach=True)
