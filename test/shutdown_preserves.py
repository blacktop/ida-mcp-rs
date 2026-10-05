"""Shutdown must save while analysis is active and allow a slow database pack."""

import argparse
import http.client
import os
import shutil
import signal
import tempfile
import time
from pathlib import Path

from http_stuck_call import Client as HttpClient
from http_stuck_call import Server, wait_until
from stdio_client import Client as StdioClient
from stdio_reopen import decode


def run_case(binary, fixture, root, transport, scenario):
    directory = root / f"{transport}-{scenario}"
    directory.mkdir()
    database = directory / "mini.i64"
    entered = directory / "entered"
    completed = directory / "completed"
    release = directory / "release"
    shutil.copy2(fixture, database)
    server = Server(binary, directory) if transport == "http" else None
    client = HttpClient(server) if server else StdioClient(
        binary, directory, ("--workspace",) if transport == "workspace" else ())
    process = server.process if server else client.process
    finish = server.finish if server else client.finish
    stream = None
    try:
        opened = decode(client.call("open_idb", {"path": str(database)}))
        binding = {"database_id": opened["database_id"]} if transport == "workspace" else {}
        code = "import ida_idp, ida_name, ida_ida, ida_auto, ida_bytes, time\nfrom pathlib import Path\n"
        if scenario == "analysis":
            code += f"""
class ReviewSlowAnalysis(ida_idp.IDP_Hooks):
    delayed = False
    armed = False
    def ev_ana_insn(self, insn):
        if self.armed and not self.delayed:
            self.delayed = True
            Path({str(entered)!r}).write_text('entered')
            deadline = time.monotonic() + 20
            while not Path({str(release)!r}).exists() and time.monotonic() < deadline:
                time.sleep(0.05)
        return 0
review_hook = ReviewSlowAnalysis()
assert review_hook.hook()
review_ea = ida_name.get_name_ea(0xffffffffffffffff, 'interesting_function')
# Without a dSYM the Mach-O symbol keeps its leading underscore.
if review_ea == 0xffffffffffffffff:
    review_ea = ida_name.get_name_ea(0xffffffffffffffff, '_interesting_function')
assert review_ea != 0xffffffffffffffff
ida_bytes.del_items(review_ea, ida_bytes.DELIT_SIMPLE, 4)
"""
        else:
            code += f"""
class ReviewSlowClose(ida_idp.IDB_Hooks):
    def closebase(self):
        Path({str(entered)!r}).write_text('entered')
        time.sleep(12)
        Path({str(completed)!r}).write_text('completed')
review_hook = ReviewSlowClose()
assert review_hook.hook()
review_ea = ida_name.get_name_ea(0xffffffffffffffff, 'interesting_function')
# Without a dSYM the Mach-O symbol keeps its leading underscore.
if review_ea == 0xffffffffffffffff:
    review_ea = ida_name.get_name_ea(0xffffffffffffffff, '_interesting_function')
assert review_ea != 0xffffffffffffffff
"""
        code += "\nassert ida_name.set_name(review_ea, 'review_shutdown_saved', ida_name.SN_FORCE)\nreview_ea\n"
        if scenario == "analysis":
            code += "ida_auto.auto_mark_range(review_ea, review_ea + 4, ida_auto.AU_CODE)\nreview_hook.armed = True\nreview_ea\n"
        expected_address = decode(client.call("run_script", {**binding, "code": code}))["result"]
        if scenario == "analysis":
            assert not entered.exists(), "analysis hook ran before analyze_funcs"
            task = decode(client.call("analyze_funcs", {**binding, "background": True}))
            assert task.get("task_id"), task
            wait_until(entered.exists, 15)
        elif server:
            # Keep an SSE response open while SIGTERM drives graceful drain.
            stream = http.client.HTTPConnection("127.0.0.1", server.port, timeout=45)
            stream.request("GET", "/", headers={"Accept": "text/event-stream",
                           "Mcp-Session-Id": client.session, "Origin": "http://localhost"})
            response = stream.getresponse()
            assert response.status == 200, response.status
        if os.name == "nt":
            process.stdin.close()
        else:
            process.send_signal(signal.SIGTERM)
        if scenario == "analysis":
            # The old cancel-first shutdown kills the child after five seconds.
            # Keep native analysis in flight beyond that retirement deadline.
            time.sleep(8)
            release.write_text("finish")
        assert process.wait(timeout=45) == 0, f"{transport}-{scenario}: exit {process.returncode}"
        assert entered.exists(), f"{scenario} callback did not run"
        if scenario == "slow-close":
            assert completed.exists(), "shutdown interrupted the database close"
    finally:
        release.touch(exist_ok=True)
        if stream:
            stream.close()
        finish()

    restart = root / f"{transport}-{scenario}-restart"
    restart.mkdir()
    check = StdioClient(binary, restart)
    try:
        decode(check.call("open_idb", {"path": str(database)}))
        resolved = decode(check.call("run_script", {"code": "import ida_name\n"
                          "ida_name.get_name_ea(0xffffffffffffffff, 'review_shutdown_saved')"}))["result"]
        assert resolved == expected_address, (resolved, expected_address)
        decode(check.call("close_idb", {}))
    finally:
        check.finish()
    shutdown = "EOF" if os.name == "nt" else "SIGTERM"
    print(f"{transport}-{scenario}: {shutdown} saved the unsaved rename and exited cleanly", flush=True)


def run(binary, fixture):
    with tempfile.TemporaryDirectory(prefix="ida-mcp-shutdown-preserves-") as temporary:
        root = Path(temporary)
        transports = ("stdio", "workspace") if os.name == "nt" else ("stdio", "workspace", "http")
        for transport in transports:
            for scenario in ("analysis", "slow-close"):
                run_case(binary, fixture, root, transport, scenario)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    arguments = parser.parse_args()
    run(arguments.binary.resolve(), arguments.fixture.resolve())
