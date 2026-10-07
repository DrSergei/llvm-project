"""
Make sure that we stop on fork and follow mode works.
"""

import lldb
import lldbsuite.test.lldbutil as lldbutil
from lldbsuite.test.lldbtest import *
from lldbsuite.test.decorators import *


@skipIfWindows
@skipIfDarwin
@skipIfWasm  # no fork() on WebAssembly
class TestStopOnForkAndVFork(TestBase):
    NO_DEBUG_INFO_TESTCASE = True

    def do_test(self, mode, fork, stop=True):
        self.build()

        args = [fork]
        launch_info = lldb.SBLaunchInfo(args)
        launch_info.SetWorkingDirectory(self.get_process_working_directory())

        (_, process, _, _) = lldbutil.run_to_source_breakpoint(
            self, "// break here", lldb.SBFileSpec("main.c"), launch_info
        )
        if stop:
            self.runCmd(f"settings set target.process.stop-on-{fork} true")
        self.runCmd(f"settings set target.process.follow-fork-mode {mode}")

        pid = process.GetProcessID()

        self.assertSuccess(process.Continue())
        if not stop:
            self.assertState(process.GetState(), lldb.eStateExited)
            self.assertEqual(process.GetExitStatus(), 0 if mode == "parent" else 47)
            return

        self.assertState(
            process.GetState(),
            lldb.eStateStopped,
            f"Process should be stopped at {fork}",
        )
        threads = lldbutil.get_stopped_threads(
            process, lldb.eStopReasonVFork if fork == "vfork" else lldb.eStopReasonFork
        )
        self.assertEqual(len(threads), 1, f"We got a thread stopped for {fork}.")

        self.assertEqual(threads[0].GetStopReasonDataCount(), 1)
        child_pid = threads[0].GetStopReasonDataAtIndex(0)
        self.assertNotEqual(child_pid, lldb.LLDB_INVALID_PROCESS_ID)
        self.assertGreater(child_pid, 0)
        self.assertNotEqual(child_pid, pid)
        if mode == "child":
            self.assertEqual(process.GetProcessID(), child_pid)

        if mode == "parent":
            self.assertEqual(
                self.dbg.GetSelectedTarget().GetProcess().GetProcessID(), pid
            )
            self.expect(
                "continue",
                substrs=[f"exited with status = 0"],
            )
        else:  # child
            self.assertNotEqual(
                self.dbg.GetSelectedTarget().GetProcess().GetProcessID(), pid
            )
            self.expect(
                "continue",
                substrs=[f"exited with status = 47"],
            )

    def test_stop_on_fork_and_follow_parent(self):
        self.do_test("parent", "fork")

    def test_stop_on_fork_and_follow_child(self):
        self.do_test("child", "fork")

    def test_stop_on_vfork_and_follow_parent(self):
        self.do_test("parent", "vfork")

    def test_stop_on_vfork_and_follow_child(self):
        self.do_test("child", "vfork")

    def test_fork_does_not_stop_by_default(self):
        self.do_test("parent", "fork", stop=False)

    def test_vfork_does_not_stop_by_default(self):
        self.do_test("parent", "vfork", stop=False)
