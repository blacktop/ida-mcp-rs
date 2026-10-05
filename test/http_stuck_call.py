"""Shared HTTP database ownership and recovery after a stuck IDA call."""

import argparse
import concurrent.futures
import http.client
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path

from stdio_reopen import decode


MODERN = "2026-07-28"
CLIENT = {"name": "http-stuck-call-test", "version": "1"}


def wait_until(check, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(0.1)
    raise AssertionError("condition did not settle within its deadline")


def alive(pid):
    if os.name == "nt":
        result = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, check=True, timeout=10,
        )
        return f'"{pid}"' in result.stdout
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def tool_error(response, message):
    result = response.get("result", {})
    assert result.get("isError"), response
    assert message in json.dumps(result), response


class Server:
    def __init__(self, binary, directory, stateless=False):
        self.log_path = directory / "server.log"
        self.log = self.log_path.open("w", encoding="utf-8")
        self.process = subprocess.Popen(
            [str(binary), "serve-http", "--bind", "127.0.0.1:0",
             *(["--stateless", "--json-response"] if stateless else [])],
            stdin=subprocess.DEVNULL, stdout=self.log, stderr=self.log,
            cwd=directory, env={**os.environ, "RUST_LOG": "ida_mcp=info"},
        )
        self.port = None
        try:
            def listening():
                assert self.process.poll() is None, self.process.returncode
                match = re.search(r"MCP HTTP server listening on http://127\.0\.0\.1:(\d+)",
                                  self.log_path.read_text(encoding="utf-8", errors="replace"))
                if match:
                    self.port = int(match.group(1))
                return self.port is not None
            wait_until(listening, 90)
        except BaseException:
            self.finish()
            raise

    def finish(self):
        already_exited = self.process.poll() is not None
        try:
            if self.process.poll() is None:
                self.process.terminate()
            try:
                self.process.wait(timeout=25)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)
                raise AssertionError("HTTP server exceeded its shutdown deadline")
            if not already_exited and os.name != "nt":
                assert self.process.returncode == 0, self.log_path.read_text(errors="replace")
        finally:
            self.log.close()


class Client:
    def __init__(self, server, modern=False):
        self.server = server
        self.modern = modern
        self.session = None
        self.request_id = 0
        if modern:
            response = self.request("server/discover", {})
            assert "error" not in response, response
        else:
            response = self.request("initialize", {
                "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": CLIENT,
            })
            assert response["result"]["protocolVersion"] == "2025-11-25", response
            assert self.session
            self.request("notifications/initialized", {}, notification=True)

    def request(self, method, params, timeout=180, notification=False, allow_cancelled=False):
        self.request_id += 1
        request_id = self.request_id
        headers = {"Content-Type": "application/json",
                   "Accept": "application/json, text/event-stream", "Origin": "http://localhost"}
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        if self.modern:
            headers.update({"MCP-Protocol-Version": MODERN, "Mcp-Method": method})
            if method == "tools/call":
                headers["Mcp-Name"] = params["name"]
            params = {**params, "_meta": {
                "io.modelcontextprotocol/protocolVersion": MODERN,
                "io.modelcontextprotocol/clientInfo": CLIENT,
                "io.modelcontextprotocol/clientCapabilities": {},
            }}
        message = {"jsonrpc": "2.0", "method": method, "params": params}
        if not notification:
            message["id"] = request_id
        connection = http.client.HTTPConnection("127.0.0.1", self.server.port, timeout=timeout)
        try:
            connection.request("POST", "/", json.dumps(message), headers)
            response = connection.getresponse()
            self.session = response.getheader("Mcp-Session-Id") or self.session
            body = response.read().decode()
            assert response.status in (200, 202), (response.status, body)
            if notification:
                return None
            if allow_cancelled and not body:
                return None
            for line in body.splitlines():
                candidate = line.removeprefix("data: ")
                try:
                    frame = json.loads(candidate)
                except ValueError:
                    continue
                if frame.get("id") == request_id:
                    return frame
            raise AssertionError(body)
        finally:
            connection.close()

    def call(self, name, arguments, timeout=180, allow_cancelled=False):
        return self.request("tools/call", {"name": name, "arguments": arguments}, timeout,
                            allow_cancelled=allow_cancelled)

    def pid(self):
        return int(decode(self.call("run_script", {"code": "import os\nos.getpid()"}))["result"])


def cancel_preserves_database(server, database):
    owner = Client(server)
    observer = Client(server, modern=True)
    opened = decode(owner.call("open_idb", {"path": str(database)}))
    child = owner.pid()
    decode(owner.call("run_script", {"code": "import ida_name, ida_ida\n"
                     "ida_name.set_name(ida_ida.inf_get_min_ea(), 'http_unsaved_cancel_marker', ida_name.SN_FORCE)"}))
    request_id = owner.request_id + 1
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        pending = executor.submit(owner.call, "run_script", {
            "code": "import time\ntime.sleep(4)\nhttp_cancel_marker = 7", "timeout_secs": 30,
        }, allow_cancelled=True)
        wait_until(lambda: (decode(observer.call("recent_operations", {}))
                            .get("active_operation") or {}).get("phase") == "executing")
        owner.request("notifications/cancelled", {"requestId": request_id}, notification=True)
        response = pending.result(timeout=15)
        if response is not None:
            assert "cancelled" in json.dumps(response).lower(), response
            assert "killed worker" not in json.dumps(response), response
    assert observer.pid() == child
    assert decode(observer.call("run_script", {"code": "http_cancel_marker"}))["result"] == 7
    assert decode(observer.call("run_script", {"code": "import ida_name, ida_ida\n"
                    "ida_name.get_name(ida_ida.inf_get_min_ea())"}))["result"] == "http_unsaved_cancel_marker"
    decode(observer.call("close_idb", {"token": opened["close_token"]}))
    print("shared HTTP cancellation preserved the worker and unsaved edits")


def lifecycle(server, database, modern):
    owner = Client(server, modern)
    other = Client(server, modern)
    opened = decode(owner.call("open_idb", {"path": str(database)}))
    token = opened["close_token"]
    old_pid = owner.pid()
    denied = decode(other.call("close_idb", {}))
    assert denied["closed"] is False, denied
    same_database = decode(other.call("open_idb", {"path": str(database)}))
    assert "close_token" not in same_database, same_database
    alternate = database.with_name("alternate.i64")
    shutil.copy2(database, alternate)
    tool_error(other.call("open_idb", {"path": str(alternate)}), "already open")
    decode(owner.call("run_script", {"code": "import ida_name, ida_ida\n"
                                    "saved_ea = ida_ida.inf_get_min_ea()\n"
                                    "ida_name.set_name(saved_ea, 'http_saved_marker', ida_name.SN_FORCE)"}))
    decode(owner.call("save_idb", {}))
    start = time.monotonic()
    retired = owner.call("run_script", {"code": "import time\ntime.sleep(600)",
                                        "timeout_secs": 2}, 35)
    tool_error(retired, "killed worker")
    # Reopen immediately, before a poll or sleep could hide a lease-release race.
    reopened = other.call("open_idb", {"path": str(database)})
    assert time.monotonic() - start < 70
    replacement = decode(reopened)
    assert replacement["close_token"] != token, replacement
    new_pid = other.pid()
    assert old_pid != new_pid and new_pid != server.process.pid, (old_pid, new_pid)
    wait_until(lambda: not alive(old_pid))
    assert decode(other.call("run_script", {"code": "import ida_name, ida_ida\n"
                                           "ida_name.get_name(ida_ida.inf_get_min_ea())"}))["result"] == "http_saved_marker"
    stale = decode(owner.call("close_idb", {"token": token}))
    assert stale["closed"] is False, stale
    # A queued timeout must leave the healthy child and its Python state intact.
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        finite = executor.submit(other.call, "run_script", {
            "code": "import time\nhttp_queue_marker = 7\ntime.sleep(20)", "timeout_secs": 45,
        })
        wait_until(lambda: (decode(owner.call("recent_operations", {}))
                            .get("active_operation") or {}).get("phase") == "executing")
        tool_error(owner.call("list_functions", {"limit": 1, "timeout_secs": 1}),
                   "waiting for the IDA worker")
        decode(finite.result(timeout=30))
    assert other.pid() == new_pid
    assert decode(other.call("run_script", {"code": "http_queue_marker + 1"}))["result"] == 8
    decode(other.call("run_script", {"code": "import ida_idp, time\n"
                     "class SleepOnOutput(ida_idp.IDP_Hooks):\n"
                     "    def ev_out_insn(self, ctx):\n        time.sleep(600)\n        return 0\n"
                     "http_sleep_hook = SleepOnOutput()\nhttp_sleep_hook.hook()"}))
    tool_error(other.call("search", {"targets": ["ret"], "kind": "text", "limit": 5,
                                      "timeout_secs": 1}, 35), "killed worker")
    tool_error(owner.call("idb_meta", {}), "No database is currently open")
    decode(other.call("open_idb", {"path": str(database)}))
    # A worker exit inside a batch read must be a top-level fatal result.
    decode(other.call("run_script", {"code": "import ida_idp, os\n"
                     "class ExitOnOutput(ida_idp.IDP_Hooks):\n"
                     "    def ev_out_insn(self, ctx):\n        os._exit(3)\n"
                     "http_exit_hook = ExitOnOutput()\nhttp_exit_hook.hook()"}))
    tool_error(other.call("search", {"targets": ["ret"], "kind": "text", "limit": 5,
                                      "timeout_secs": 10}), "crashed or disconnected")
    tool_error(owner.call("idb_meta", {}), "No database is currently open")
    replacement = decode(other.call("open_idb", {"path": str(database)}))
    assert other.pid() != new_pid
    if os.name != "nt":
        crash_pid = other.pid()
        tool_error(other.call("run_script", {
            "code": "import signal\nsignal.raise_signal(signal.SIGSEGV)", "timeout_secs": 15,
        }, 35), "crashed inside the IDA SDK")
        tool_error(owner.call("idb_meta", {}), "No database is currently open")
        replacement = decode(other.call("open_idb", {"path": str(database)}))
        assert other.pid() != crash_pid
    decode(other.call("close_idb", {"token": replacement["close_token"]}))
    tool_error(owner.call("idb_meta", {}), "No database is currently open")
    print(f"{'sessionless' if modern else 'legacy'}: retired {old_pid}, reopened {new_pid}, ownership and queue survived")


def orphan(server, database):
    owner = Client(server, modern=True)
    observer = Client(server, modern=True)
    decode(owner.call("open_idb", {"path": str(database)}))
    child = owner.pid()
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        blocked = executor.submit(owner.call, "run_script", {
            "code": "import time\ntime.sleep(600)", "timeout_secs": 300,
        }, 60)
        wait_until(lambda: (decode(observer.call("recent_operations", {}))
                            .get("active_operation") or {}).get("phase") == "executing")
        server.process.kill()
        server.process.wait(timeout=10)
        try:
            response = blocked.result(timeout=15)
        except (OSError, http.client.HTTPException):
            pass
        else:
            raise AssertionError(f"request survived parent death: {response}")
    wait_until(lambda: not alive(child), 45)
    print(f"parent death: child {child} exited without an orphan")


def shutdown_saves(binary, root, fixture):
    if os.name == "nt":
        print("Windows signal-driven HTTP shutdown: not exercised by this harness")
        return
    directory = root / "shutdown"
    directory.mkdir()
    database = directory / "mini.i64"
    shutil.copy2(fixture, database)
    server = Server(binary, directory)
    try:
        owner = Client(server, modern=True)
        decode(owner.call("open_idb", {"path": str(database)}))
        child = owner.pid()
        decode(owner.call("run_script", {"code": "import ida_name, ida_ida\n"
                         "ida_name.set_name(ida_ida.inf_get_min_ea(), 'http_shutdown_marker', ida_name.SN_FORCE)"}))
        server.process.send_signal(signal.SIGTERM)
        assert server.process.wait(timeout=20) == 0, server.log_path.read_text(errors="replace")
        wait_until(lambda: not alive(child))
    finally:
        server.finish()
    restart = root / "shutdown-restart"
    restart.mkdir()
    server = Server(binary, restart)
    try:
        owner = Client(server, modern=True)
        opened = decode(owner.call("open_idb", {"path": str(database)}))
        assert decode(owner.call("run_script", {"code": "import ida_name, ida_ida\n"
                     "ida_name.get_name(ida_ida.inf_get_min_ea())"}))["result"] == "http_shutdown_marker"
        decode(owner.call("close_idb", {"token": opened["close_token"]}))
    finally:
        server.finish()
    print("SIGTERM saved the open HTTP database and reaped its child")


def run(binary, fixture):
    with tempfile.TemporaryDirectory(prefix="ida-mcp-http-stuck-") as temporary:
        root = Path(temporary)
        for stateless in (False, True):
            directory = root / ("stateless" if stateless else "stateful")
            directory.mkdir()
            database = directory / "mini.i64"
            shutil.copy2(fixture, database)
            server = Server(binary, directory, stateless)
            try:
                if not stateless:
                    cancel_preserves_database(server, database)
                    lifecycle(server, database, modern=False)
                lifecycle(server, database, modern=True)
                orphan(server, database)
            except BaseException:
                print(server.log_path.read_text(encoding="utf-8", errors="replace"))
                raise
            finally:
                server.finish()
        shutdown_saves(binary, root, fixture)
    print("HTTP retirement, immediate reopen, saved edits, and close ownership passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    arguments = parser.parse_args()
    run(arguments.binary.resolve(), arguments.fixture.resolve())
