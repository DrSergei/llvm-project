"""Hand off stopped fork children to independent debug adapters."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from queue import Queue
import time

from lldbgdbserverutils import Pipe

from lldbsuite.test.decorators import skipIf, skipIfRemote, no_match
from lldbsuite.test.tools.lldb_dap import DAPTestCaseBase
from lldbsuite.test.tools.lldb_dap.types import (
    AttachArgs,
    LaunchArgs,
    StartDebuggingRequestType,
    dict_to_message,
)


@skipIf(oslist=no_match(["linux"]))
@skipIfRemote
class TestDAP_fork(DAPTestCaseBase):
    def setUpCommands(self):
        # Server sessions share LLDB's global settings. Clearing them when a
        # second session connects would mask the policy lifetime tests.
        return [
            cmd for cmd in super().setUpCommands() if cmd != "settings clear --all"
        ]

    def require_child_attach(self):
        scope = Path("/proc/sys/kernel/yama/ptrace_scope")
        # A detached child is no longer a descendant of the new adapter.
        # These end-to-end tests require permission to attach by PID.
        if scope.exists() and int(scope.read_text()) != 0:
            caps = next(
                line
                for line in Path("/proc/self/status").read_text().splitlines()
                if line.startswith("CapEff:")
            ).split()[1]
            if not int(caps, 16) & (1 << 19):
                self.skipTest(
                    "child PID attach requires ptrace_scope=0 or CAP_SYS_PTRACE"
                )

    def make_session(self, adapter=None, accepted=True, disconnect_automatically=True):
        session = self.create_session(
            adapter, disconnect_automatically=disconnect_automatically
        )
        session.update_initialize_args(supportsStartDebuggingRequest=True)
        requests = Queue()

        def start_debugging(request):
            requests.put(request)
            return accepted

        session.start_debugging_handler = start_debugging
        return session, requests

    def launch_parent(
        self,
        mode="fork",
        enabled=True,
        accepted=True,
        disconnect_automatically=True,
        adapter=None,
        preRunCommands=None,
    ):
        self.build()
        marker = self.getBuildArtifact(self._testMethodName + ".child")
        for path in Path(marker).parent.glob(Path(marker).name + ".*"):
            path.unlink()
        parent, requests = self.make_session(
            adapter=adapter,
            accepted=accepted,
            disconnect_automatically=disconnect_automatically,
        )
        with parent.configure(
            LaunchArgs(
                self.getBuildArtifact(),
                args=[mode, marker],
                debugChildProcesses=enabled,
                preRunCommands=preRunCommands,
                sourceMap=[["/not-a-real-source-prefix", "/mapped-source"]],
            )
        ) as ctx:
            [breakpoint] = parent.resolve_function_breakpoints(["parent_breakpoint"])
        stopped = parent.wait_until_any_breakpoint_hit(
            [breakpoint], after=ctx.process_event
        )
        return parent, requests, marker, ctx.process_event, stopped

    def assert_child_stopped(self, pid, marker):
        state = next(
            line
            for line in Path(f"/proc/{pid}/status").read_text().splitlines()
            if line.startswith("State:")
        )
        self.assertIn("T (stopped)", state)
        self.assertFalse(
            Path(f"{marker}.{pid}").exists(), "child must not run before attach"
        )

    def attach_child(self, request, marker):
        self.assertEqual(request.arguments.request, StartDebuggingRequestType.ATTACH)
        config = request.arguments.configuration
        self.assertTrue(config["debugChildProcesses"])
        self.assertFalse(config["stopOnEntry"])
        self.assertEqual(
            config["sourceMap"], [["/not-a-real-source-prefix", "/mapped-source"]]
        )
        pid = config["pid"]
        self.assert_child_stopped(pid, marker)
        child, requests = self.make_session(self.create_debug_adapter())
        with child.configure(dict_to_message(AttachArgs, config)) as ctx:
            [breakpoint] = child.resolve_function_breakpoints(["child_breakpoint"])
            self.assertFalse(
                Path(f"{marker}.{pid}").exists(),
                "configuration must precede child execution",
            )
        self.assertEqual(ctx.process_event.body.systemProcessId, pid)
        return child, requests, breakpoint, ctx.process_event

    def fork_hook_commands(self, ready=None, release=None):
        script = Path(self.getSourceDir()) / "fork_hook.py"
        command = "target stop-hook add -P fork_hook.ForkHook"
        if ready:
            command += f' -k ready -v "{ready}" -k release -v "{release}"'
        return [f'command script import "{script}"', command]

    def wait_for_marker(self, marker):
        deadline = time.monotonic() + self.DEFAULT_TIMEOUT
        while not Path(marker).exists():
            self.assertLess(time.monotonic(), deadline, marker)
            time.sleep(0.01)

    def test_auto_continuing_fork_hook(self):
        parent, requests, marker, _, _ = self.launch_parent(
            accepted=False, preRunCommands=self.fork_hook_commands()
        )
        request = requests.get(timeout=self.DEFAULT_TIMEOUT)
        parent.continue_to_exit()
        self.assertTrue(
            Path(f"{marker}.{request.arguments.configuration['pid']}").exists()
        )
        self.assertTrue(
            requests.empty(), "one request despite the restarted fork event"
        )

    def check_custom_remote_connection(self, launch):
        self.build()
        pipe_dir = Path(self.getBuildDir()) / self._testMethodName
        pipe_dir.mkdir(exist_ok=True)
        pipe_path = pipe_dir / "stub_port_number"
        pipe_path.unlink(missing_ok=True)
        pipe = Pipe(str(pipe_dir))
        self.addTearDownHook(pipe.close)
        pipe.finish_connection(self.DEFAULT_TIMEOUT)
        marker = self.getBuildArtifact("remote.child")
        self.spawnSubprocess(
            str(self.get_debug_server_path()),
            [
                "gdbserver",
                "localhost:0",
                "--named-pipe",
                pipe.name,
                "--",
                self.getBuildArtifact(),
                "fork",
                marker,
            ],
            install_remote=False,
        )
        port = int(pipe.read(10, self.DEFAULT_TIMEOUT).rstrip(b"\0"))
        session, requests = self.make_session()
        session.initialize_sequence(session.initialize_args)
        command = f"gdb-remote localhost:{port}"
        config = (
            LaunchArgs(
                self.getBuildArtifact(),
                launchCommands=[command],
                debugChildProcesses=True,
            )
            if launch
            else AttachArgs(
                program=self.getBuildArtifact(),
                attachCommands=[command],
                debugChildProcesses=True,
            )
        )
        pending = session.send_request(config)
        session.configuration_done().result_or_error()
        error = pending.error()
        self.assertIn(
            "standard local launch" if launch else "standard local attach",
            error.body.error.format,
        )
        self.assertTrue(requests.empty())

    def test_remote_attach_commands_rejected(self):
        self.check_custom_remote_connection(launch=False)

    def test_remote_launch_commands_rejected(self):
        self.check_custom_remote_connection(launch=True)

    def test_disconnect_before_fork_event_dispatch(self):
        self.build()
        marker = self.getBuildArtifact("late.child")
        ready = self.getBuildArtifact("fork-hook.ready")
        release = self.getBuildArtifact("fork-hook.release")
        for path in (ready, release):
            Path(path).unlink(missing_ok=True)
        for path in Path(marker).parent.glob(Path(marker).name + ".*"):
            path.unlink()
        proc = self.spawnSubprocess(
            self.getBuildArtifact(), args=["attach-fork", marker]
        )
        deadline = time.monotonic() + self.DEFAULT_TIMEOUT
        while "T (stopped)" not in Path(f"/proc/{proc.pid}/status").read_text():
            self.assertIsNone(proc.poll())
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.01)
        parent, requests = self.make_session(disconnect_automatically=False)
        with parent.configure(
            AttachArgs(
                program=self.getBuildArtifact(),
                pid=proc.pid,
                debugChildProcesses=True,
                preRunCommands=self.fork_hook_commands(ready, release),
            )
        ):
            pass
        # The child was detached, but the event handler has not run: it is
        # still inside DoOnRemoval's stop hook. Close the session in that gap.
        self.wait_for_marker(ready)
        self.assertTrue(requests.empty())
        children = (
            Path(f"/proc/{proc.pid}/task/{proc.pid}/children").read_text().split()
        )
        self.assertEqual(len(children), 1)
        child_pid = int(children[0])
        self.assert_child_stopped(child_pid, marker)
        with ThreadPoolExecutor(max_workers=1) as executor:
            pending = executor.submit(parent.disconnect, terminateDebuggee=False)
            try:
                self.wait_for_marker(f"{marker}.{child_pid}")
            finally:
                Path(release).touch()
            pending.result(timeout=self.DEFAULT_TIMEOUT)
        self.assertEqual(proc.wait(timeout=self.DEFAULT_TIMEOUT), 0)
        self.assertTrue(requests.empty(), "no handoff after shutdown")

    def test_fork(self):
        self.require_child_attach()
        parent, requests, marker, process_event, stopped = self.launch_parent()
        request = requests.get(timeout=self.DEFAULT_TIMEOUT)
        child, child_requests, breakpoint, child_event = self.attach_child(
            request, marker
        )
        child.wait_until_any_breakpoint_hit([breakpoint], after=child_event)
        self.assertTrue(child_requests.empty())
        self.assertTrue(requests.empty(), "one handoff request per child")
        self.assertNotEqual(
            process_event.body.systemProcessId, child_event.body.systemProcessId
        )
        # The original session still owns the parent and its breakpoint.
        self.assertEqual(stopped.body.reason, "breakpoint")
        child.continue_to_exit(exitCode=47)
        parent.continue_to_exit()

    def test_attach_stopped_child_configuration(self):
        # Linux Yama does not inherit PR_SET_PTRACER across fork. Exercise
        # the emitted attach configuration with an independently stopped
        # process which can grant permission before stopping itself.
        parent, requests, marker, _, _ = self.launch_parent(accepted=False)
        request = requests.get(timeout=self.DEFAULT_TIMEOUT)
        parent.continue_to_exit()
        proc = self.spawnSubprocess(self.getBuildArtifact(), args=["stopped", marker])
        deadline = time.monotonic() + self.DEFAULT_TIMEOUT
        while True:
            self.assertIsNone(proc.poll())
            state = Path(f"/proc/{proc.pid}/status").read_text()
            if "T (stopped)" in state:
                break
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.01)
        request.arguments.configuration["pid"] = proc.pid
        child, _, breakpoint, child_event = self.attach_child(request, marker)
        child.wait_until_any_breakpoint_hit([breakpoint], after=child_event)
        child.continue_to_exit(exitCode=47)
        self.assertEqual(proc.wait(timeout=self.DEFAULT_TIMEOUT), 47)

    def test_disabled_session_does_not_inherit_policy(self):
        parent, requests, _, _, _ = self.launch_parent(accepted=False)
        requests.get(timeout=self.DEFAULT_TIMEOUT)
        parent.continue_to_exit()
        # In server mode, both sessions share LLDB's process defaults.
        adapter = self._adapter if self.run_as_server else self.create_debug_adapter()
        other, other_requests, _, _, _ = self.launch_parent(
            enabled=None, adapter=adapter
        )
        other.continue_to_exit()
        self.assertTrue(other_requests.empty())

    def test_preserve_existing_global_settings(self):
        if not self.run_as_server:
            self.skipTest("requires sessions sharing global LLDB settings")
        parent, requests, _, _, _ = self.launch_parent(
            accepted=False,
            preRunCommands=[
                "settings set target.process.stop-on-fork true",
                "settings set target.process.detach-keeps-stopped true",
            ],
        )
        requests.get(timeout=self.DEFAULT_TIMEOUT)
        parent.continue_to_exit()
        other, _ = self.make_session(adapter=self._adapter)
        with other.configure(
            LaunchArgs(
                self.getBuildArtifact(),
                args=["fork", self.getBuildArtifact("preserved-settings.child")],
            )
        ) as ctx:
            [breakpoint] = other.resolve_function_breakpoints(["before_fork"])
        other.wait_until_any_breakpoint_hit([breakpoint], after=ctx.process_event)
        for setting in ("stop-on-fork", "detach-keeps-stopped"):
            result = other.evaluate(
                f"settings show target.process.{setting}", context="repl"
            )
            self.assertIn("true", result.result)
            other.evaluate(
                f"settings set target.process.{setting} false", context="repl"
            )
        other.continue_to_exit()

    def test_concurrent_disabled_session_releases_child(self):
        parent, requests, marker, _, _ = self.launch_parent(
            accepted=None, disconnect_automatically=False
        )
        request = requests.get(timeout=self.DEFAULT_TIMEOUT)
        pid = request.arguments.configuration["pid"]
        self.assert_child_stopped(pid, marker)
        adapter = self._adapter if self.run_as_server else self.create_debug_adapter()
        other, other_requests, _, _, _ = self.launch_parent(
            enabled=None, adapter=adapter
        )
        other.continue_to_exit()
        self.assertTrue(other_requests.empty())
        parent.disconnect(terminateDebuggee=False)
        self.wait_for_marker(f"{marker}.{pid}")

    def test_nested_fork(self):
        self.require_child_attach()
        parent, requests, marker, _, _ = self.launch_parent(mode="nested")
        child, child_requests, child_bp, child_event = self.attach_child(
            requests.get(timeout=self.DEFAULT_TIMEOUT), marker
        )
        grandchild, _, grandchild_bp, grandchild_event = self.attach_child(
            child_requests.get(timeout=self.DEFAULT_TIMEOUT), marker
        )
        grandchild.wait_until_any_breakpoint_hit(
            [grandchild_bp], after=grandchild_event
        )
        grandchild.continue_to_exit(exitCode=47)
        child.wait_until_any_breakpoint_hit([child_bp], after=child_event)
        child.continue_to_exit(exitCode=47)
        parent.continue_to_exit()

    def test_restart_releases_pending_child(self):
        parent, requests, marker, _, stopped = self.launch_parent(
            mode="restart", accepted=None
        )
        old_child = requests.get(timeout=self.DEFAULT_TIMEOUT).arguments.configuration[
            "pid"
        ]
        self.assert_child_stopped(old_child, marker)
        parent.restart()
        new_child = requests.get(timeout=self.DEFAULT_TIMEOUT).arguments.configuration[
            "pid"
        ]
        self.assertNotEqual(new_child, old_child)
        self.assert_child_stopped(new_child, marker)
        parent.wait_until_any_breakpoint_hit(
            stopped.body.hitBreakpointIds, after=stopped
        )
        deadline = time.monotonic() + self.DEFAULT_TIMEOUT
        while not Path(f"{marker}.{old_child}").exists():
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.01)
        # The client leaves the request unanswered. Disconnect will resume the
        # second child during test cleanup.

    def test_disabled_by_default(self):
        parent, requests, _, _, _ = self.launch_parent(enabled=None)
        parent.continue_to_exit()
        self.assertTrue(requests.empty())

    def test_vfork_is_not_handed_off(self):
        parent, requests, _, _, _ = self.launch_parent(mode="vfork")
        parent.continue_to_exit()
        self.assertTrue(requests.empty())

    def test_rejected_request_resumes_child(self):
        parent, requests, marker, _, _ = self.launch_parent(accepted=False)
        request = requests.get(timeout=self.DEFAULT_TIMEOUT)
        parent.continue_to_exit()
        self.assertTrue(
            Path(f"{marker}.{request.arguments.configuration['pid']}").exists()
        )
        self.assertIn("Unable to start debugging forked child", parent.get_important())

    def test_disconnect_resumes_pending_child(self):
        parent, requests, marker, _, _ = self.launch_parent(
            accepted=None, disconnect_automatically=False
        )
        request = requests.get(timeout=self.DEFAULT_TIMEOUT)
        pid = request.arguments.configuration["pid"]
        self.assert_child_stopped(pid, marker)
        # The child must be resumed even without a client reply.
        parent.disconnect(terminateDebuggee=False)
        deadline = time.monotonic() + self.DEFAULT_TIMEOUT
        while not Path(f"{marker}.{pid}").exists():
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.01)

    def test_client_capability_required(self):
        self.build()
        session = self.create_session()
        session.update_initialize_args(supportsStartDebuggingRequest=False)
        session.initialize_sequence(session.initialize_args)
        launch = session.send_request(
            LaunchArgs(self.getBuildArtifact(), debugChildProcesses=True)
        )
        session.configuration_done().result_or_error()
        response = launch.error()
        self.assertIn("supportsStartDebuggingRequest", response.body.error.format)

    def test_expression_fork_is_not_handed_off(self):
        self.build()
        parent, requests = self.make_session()
        with parent.configure(
            LaunchArgs(
                self.getBuildArtifact(),
                args=["fork", self.getBuildArtifact("expression.child")],
                debugChildProcesses=True,
            )
        ) as ctx:
            [breakpoint] = parent.resolve_function_breakpoints(["before_fork"])
        parent.wait_until_any_breakpoint_hit([breakpoint], after=ctx.process_event)
        self.assertIn(
            "42",
            parent.evaluate("fork_from_expression()", context="repl").result,
        )
        self.assertTrue(requests.empty())
