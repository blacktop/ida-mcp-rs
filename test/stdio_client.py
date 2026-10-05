"""Small MCP client using native subprocess pipes on every supported platform."""

import json
import os
import queue
import subprocess
import threading
import time


class Client:
    def __init__(self, binary, directory, args=()):
        self.log_path = directory / "server.log"
        self.log = self.log_path.open("w", encoding="utf-8")
        try:
            self.process = subprocess.Popen(
                [str(binary), *args, "serve"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=self.log, text=True, encoding="utf-8", cwd=directory,
                env={**os.environ, "RUST_LOG": "ida_mcp=info"},
            )
        except BaseException:
            self.log.close()
            raise
        self.responses = queue.Queue()
        self.request_id = 0

        def read():
            try:
                for line in self.process.stdout:
                    self.responses.put(json.loads(line))
            except (OSError, ValueError) as error:
                self.responses.put(error)
            finally:
                self.responses.put(None)

        self.reader = threading.Thread(target=read, daemon=True)
        self.reader.start()
        try:
            self.request("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                                         "clientInfo": {"name": "maintenance-test", "version": "1"}})
            self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        except BaseException:
            self.finish()
            raise

    def send(self, message):
        self.process.stdin.write(json.dumps(message) + "\n")
        self.process.stdin.flush()

    def request(self, method, params, timeout=180):
        self.request_id += 1
        self.send({"jsonrpc": "2.0", "id": self.request_id, "method": method, "params": params})
        deadline = time.monotonic() + timeout
        while True:
            response = self.responses.get(timeout=max(0, deadline - time.monotonic()))
            assert isinstance(response, dict), response
            if response.get("id") == self.request_id:
                return response

    def call(self, name, arguments, timeout=180):
        return self.request("tools/call", {"name": name, "arguments": arguments}, timeout)

    def finish(self):
        try:
            try:
                self.process.stdin.close()
            except OSError:
                pass
            try:
                self.process.wait(timeout=130)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)
        finally:
            self.reader.join(timeout=2)
            self.process.stdout.close()
            self.log.close()
