"""Reopen immediately after retirement, using native pipes without polling sleeps."""

import argparse
import json
import shutil
import tempfile
from pathlib import Path

from stdio_client import Client


def decode(response):
    if "error" in response:
        raise AssertionError(response["error"])
    result = response["result"]
    text = next(
        (part["text"] for part in result.get("content", []) if part.get("type") == "text"),
        "",
    )
    if result.get("isError"):
        raise AssertionError(text)
    if "structuredContent" in result:
        return result["structuredContent"]
    try:
        return json.loads(text)
    except ValueError:
        return text


def run(binary, fixture):
    with tempfile.TemporaryDirectory(prefix="ida-mcp-reopen-") as temporary:
        directory = Path(temporary)
        database = directory / "mini.i64"
        shutil.copy2(fixture, database)
        client = Client(binary, directory)
        try:
            decode(client.call("open_idb", {"path": str(database)}, 180))
            first_pid = decode(client.call("run_script", {"code": "import os\nos.getpid()"}))["result"]
            retired = client.call("run_script", {"code": "import time\ntime.sleep(600)", "timeout_secs": 2}, 30)
            # Send the reopen before inspecting the retirement response:
            # no intervening tool call, sleep, or process-exit poll.
            reopened = client.call("open_idb", {"path": str(database)}, 180)
            error = retired["result"]
            assert error.get("isError"), error
            assert any("killed worker" in part.get("text", "") for part in error.get("content", [])), error
            decode(reopened)
            second_pid = decode(client.call("run_script", {"code": "import os\nos.getpid()"}))["result"]
            assert first_pid != second_pid, (first_pid, second_pid)
            decode(client.call("close_idb", {}))
            client.process.stdin.close()
            assert client.process.wait(timeout=25) == 0, client.process.returncode
        except BaseException:
            print(client.log_path.read_text(encoding="utf-8", errors="replace"))
            raise
        finally:
            client.finish()
        print("Immediate reopen succeeded on a new worker without retrying")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    arguments = parser.parse_args()
    run(arguments.binary.resolve(), arguments.fixture.resolve())
