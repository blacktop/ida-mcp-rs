#!/usr/bin/env python3
"""End-to-end coverage for typed raw-target configuration over stdio."""

from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import ExitStack
from pathlib import Path
from typing import Any, TextIO


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BINARY = ROOT / "target" / "release" / (
    "ida-mcp.exe" if os.name == "nt" else "ida-mcp"
)
DATABASE_SUFFIXES = (".i64", ".idb", ".id0", ".id1", ".id2", ".nam", ".til")


class StdioClient:
    def __init__(self, binary: Path) -> None:
        env = os.environ.copy()
        env.setdefault("RUST_LOG", "ida_mcp=trace")
        self.process = subprocess.Popen(
            [str(binary)],
            cwd=ROOT,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        assert self.process.stdin is not None
        assert self.process.stdout is not None
        assert self.process.stderr is not None
        self.stdin: TextIO = self.process.stdin
        self.stdout_queue: queue.Queue[str | None] = queue.Queue()
        self.stderr_lines: list[str] = []
        self.pending: dict[int, dict[str, Any]] = {}
        self.stdout_thread = threading.Thread(
            target=self._read_stdout, args=(self.process.stdout,), daemon=True
        )
        self.stderr_thread = threading.Thread(
            target=self._read_stderr, args=(self.process.stderr,), daemon=True
        )
        self.stdout_thread.start()
        self.stderr_thread.start()

    def _read_stdout(self, stream: TextIO) -> None:
        for line in stream:
            self.stdout_queue.put(line)
        self.stdout_queue.put(None)

    def _read_stderr(self, stream: TextIO) -> None:
        for line in stream:
            self.stderr_lines.append(line)

    def send(self, message: dict[str, Any]) -> None:
        self.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
        self.stdin.flush()

    def response(self, request_id: int, timeout: float) -> dict[str, Any]:
        if request_id in self.pending:
            return self.pending.pop(request_id)

        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"timed out waiting for response id={request_id}")
            try:
                line = self.stdout_queue.get(timeout=remaining)
            except queue.Empty as exc:
                raise TimeoutError(
                    f"timed out waiting for response id={request_id}"
                ) from exc
            if line is None:
                try:
                    status = self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    status = None
                raise RuntimeError(
                    f"server exited while waiting for response id={request_id} "
                    f"(status={status})"
                )
            try:
                message = json.loads(line)
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"non-JSON server output: {line.rstrip()!r}") from exc
            response_id = message.get("id")
            if response_id == request_id:
                return message
            if isinstance(response_id, int):
                self.pending[response_id] = message

    def close(self) -> None:
        if not self.stdin.closed:
            self.stdin.close()
        try:
            self.process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
            raise RuntimeError("server did not exit after stdin was closed")
        if self.process.returncode != 0:
            raise RuntimeError(f"server exited with status {self.process.returncode}")
        self.stdout_thread.join(timeout=1)
        self.stderr_thread.join(timeout=1)

    def abort(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.stdout_thread.join(timeout=1)
        self.stderr_thread.join(timeout=1)

    def logs(self) -> str:
        return "".join(self.stderr_lines)


def request(request_id: int, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }


def assert_success(response: dict[str, Any], label: str) -> None:
    if "error" in response or response.get("result", {}).get("isError") is True:
        raise AssertionError(f"{label} failed: {json.dumps(response, indent=2)}")


def tool_payload(response: dict[str, Any], label: str) -> Any:
    assert_success(response, label)
    try:
        text = response["result"]["content"][0]["text"]
        return json.loads(text)
    except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
        raise AssertionError(
            f"{label} returned an invalid tool payload: {json.dumps(response, indent=2)}"
        ) from exc


def assert_failure(response: dict[str, Any], label: str) -> None:
    if "error" not in response and response.get("result", {}).get("isError") is not True:
        raise AssertionError(f"{label} unexpectedly succeeded: {json.dumps(response, indent=2)}")


def wait_for_file(path: Path, timeout: float = 10) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.is_file() and path.stat().st_size > 0:
            return
        time.sleep(0.1)
    raise AssertionError(f"database was not saved: {path}")


def main() -> int:
    configured_binary = os.environ.get("MCP_STDIO_BIN") or os.environ.get("SERVER_BIN")
    binary = Path(configured_binary).resolve() if configured_binary else DEFAULT_BINARY
    if not binary.is_file():
        raise FileNotFoundError(f"missing server binary: {binary}")

    client: StdioClient | None = None
    try:
        with ExitStack() as cleanup:
            temp_dir = cleanup.enter_context(
                tempfile.TemporaryDirectory(prefix="ida-mcp-raw-target-")
            )
            work = Path(temp_dir)
            raw = work / "blob.bin"
            raw.write_bytes(bytes.fromhex("55 89 e5 31 c0 5d c3"))

            client = StdioClient(binary)
            # ExitStack unwinds in reverse order, so a failed test stops IDA
            # before TemporaryDirectory tries to remove an open database.
            cleanup.callback(client.abort)
            client.send(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "clientInfo": {"name": "raw-target", "version": "0.1"},
                        "capabilities": {},
                    },
                }
            )
            assert_success(client.response(1, 20), "initialize")
            client.send(
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/initialized",
                    "params": {},
                }
            )

            client.send(
                request(
                    2,
                    "open_idb",
                    {
                        "path": str(raw),
                        "processor": "metapc:80386p",
                        "bitness": 32,
                        "base_address": "0x401000",
                        "entry_point": "0x401000",
                        "auto_analyse": False,
                    },
                )
            )
            opened = tool_payload(client.response(2, 120), "open_idb")
            expected_metadata = {
                "file_type": "BIN",
                "processor_short": "metapc",
                "bits": 32,
                "base_address": "0x401000",
                "entry_point": "0x401000",
            }
            for field, expected in expected_metadata.items():
                actual = opened.get(field)
                if actual != expected:
                    raise AssertionError(
                        f"open_idb {field} mismatch: expected {expected!r}, got {actual!r}"
                    )

            client.send(request(3, "segments", {}))
            segments = tool_payload(client.response(3, 30), "segments")
            if not any(
                segment.get("start") == "0x401000" and segment.get("bitness") == 1
                for segment in segments
            ):
                raise AssertionError(
                    "segments did not contain a 32-bit segment based at 0x401000: "
                    + json.dumps(segments, indent=2)
                )

            client.send(request(4, "close_idb", {}))
            assert_success(client.response(4, 30), "close_idb")
            wait_for_file(Path(f"{raw}.i64"))

            invalid_raw = work / "invalid.bin"
            invalid_raw.write_bytes(bytes.fromhex("55 89 e5 31 c0 5d c3"))
            client.send(
                request(
                    5,
                    "open_idb",
                    {
                        "path": str(invalid_raw),
                        "processor": "processor_that_does_not_exist",
                        "bitness": 32,
                        "base_address": "0x501000",
                        "entry_point": "0x501000",
                        "auto_analyse": False,
                    },
                )
            )
            assert_failure(client.response(5, 60), "invalid-processor open_idb")
            leftovers = [
                Path(f"{invalid_raw}{suffix}")
                for suffix in DATABASE_SUFFIXES
                if Path(f"{invalid_raw}{suffix}").exists()
            ]
            if leftovers:
                raise AssertionError(
                    "failed raw open left database artifacts: "
                    + ", ".join(str(path) for path in leftovers)
                )

            client.close()
            client = None
    except Exception:
        if client is not None:
            client.abort()
            logs = client.logs()
            if logs:
                print("--- ida-mcp stderr ---", file=sys.stderr)
                print(logs, file=sys.stderr, end="" if logs.endswith("\n") else "\n")
        raise

    print("raw-target integration test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
