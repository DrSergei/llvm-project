"""Test capability negotiation and detach error replies."""

import lldb
from lldbsuite.test.gdbclientutils import MockGDBServerResponder
from lldbsuite.test.lldbgdbclient import GDBRemoteTestBase


class TestDetachStopped(GDBRemoteTestBase):
    def check_detach(self, multiprocess=False, supported=True, response="OK"):
        class Responder(MockGDBServerResponder):
            def qSupported(self, client_supported):
                features = super().qSupported(client_supported)
                return features + (";multiprocess+" if multiprocess else "")

            def qfThreadInfo(self):
                return "mp400.10200" if multiprocess else "m10200"

            def other(self, packet):
                if packet == "qSupportsDetachAndStayStopped:":
                    return "OK" if supported else ""
                return super().other(packet)

            def D(self, packet):
                return response

        self.server.responder = Responder()
        process = self.connect(self.dbg.CreateTarget(""))
        error = process.Detach(True)
        self.assertPacketLogReceived(["qSupportsDetachAndStayStopped:"])
        if not supported:
            self.assertFalse(any(packet.startswith("D") for packet in self.server.responder.packetLog.get_received()))
            self.assertFalse(error.Success())
        else:
            self.assertPacketLogReceived(["D1;0000000000000400" if multiprocess else "D1"])
            if response == "OK":
                self.assertSuccess(error)
                self.assertState(process.GetState(), lldb.eStateDetached)
            else:
                self.assertFalse(error.Success())
                self.assertState(process.GetState(), lldb.eStateStopped)
                # Allow teardown to detach normally.
                self.server.responder.D = lambda packet: "OK"

    def test_detach_stopped(self):
        self.check_detach()

    def test_detach_stopped_pid(self):
        self.check_detach(multiprocess=True)

    def test_unsupported(self):
        self.check_detach(supported=False)

    def test_error(self):
        self.check_detach(response="E01")

    def test_empty_response(self):
        self.check_detach(response="")
