from pathlib import Path
import time

import lldb


class ForkHook:
    def __init__(self, target, extra_args, internal_dict):
        self.ready = extra_args.GetValueForKey("ready").GetStringValue(1024)
        self.release = extra_args.GetValueForKey("release").GetStringValue(1024)

    def handle_stop(self, exe_ctx, stream):
        if exe_ctx.GetThread().GetStopReason() != lldb.eStopReasonFork:
            return True
        if self.ready:
            Path(self.ready).touch()
            deadline = time.monotonic() + 60
            while not Path(self.release).exists():
                if time.monotonic() > deadline:
                    raise RuntimeError("test did not release fork stop hook")
                time.sleep(0.01)
        # Resume this stop, preserving the subsequent parent breakpoint.
        return False
