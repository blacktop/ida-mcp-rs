"""Keep the full IDA 9.4 tool inventory, schemas, and compatibility dispatch."""

import argparse
import copy
import json
import platform
import shutil
import sys
import tempfile
from pathlib import Path

from stdio_client import Client
from stdio_reopen import decode


def stable_tools():
    baseline = json.loads(Path(__file__).with_name("fixtures").joinpath(
        "stable-api-v9.4.4.json").read_text(encoding="utf-8"))
    assert baseline["source"] == "a9649d37b81b770cfe0cd44f35d96f6de21fb1dd"
    tools = baseline["tools"]
    assert len(tools) == 82
    tools["save_idb"] = copy.deepcopy(tools["analysis_status"])
    # The only existing input-schema changes are the deliberate #60 repairs.
    for name, description in (
        ("read_struct", "Address(es) of struct instances (string/number or array)"),
        ("stack_frame", "One address (string/number); a one-element array is accepted"),
    ):
        for schema in ("inputSchema", "helpSchema"):
            tools[name][schema]["properties"]["address"]["description"] = description
    tools["stack_frame"]["helpSchema"].update({
        "title": "SingleAddressRequest",
        "description": "One address for a tool that returns one result; a one-element array is\n"
                       "accepted, anything longer is refused.",
    })
    return tools


def assert_inventory(inventory, tools, *, workspace=False, debugger=False):
    actual = {tool["name"]: tool["inputSchema"] for tool in inventory}
    assert len(actual) == len(inventory), "duplicate advertised tool"
    expected = {}
    for name, tool in tools.items():
        requirements = tool["requirements"]
        if requirements["workspace"] and not workspace:
            continue
        if requirements["debugger"] and not debugger:
            continue
        schema = copy.deepcopy(tool["inputSchema"])
        if workspace and tool["scope"] == "database":
            schema.setdefault("properties", {})["database_id"] = {
                "type": "string", "format": "uuid",
                "description": "Opaque database handle returned by open_idb/open_dsc in workspace mode",
            }
            schema.setdefault("required", []).append("database_id")
        expected[name] = schema
    assert actual.keys() == expected.keys(), {
        "missing": sorted(expected.keys() - actual.keys()),
        "unexpected": sorted(actual.keys() - expected.keys()),
    }
    for name, schema in expected.items():
        assert actual[name] == schema, {
            "tool": name, "expected": schema, "actual": actual[name],
        }


def run(binary, fixture):
    tools = stable_tools()
    with tempfile.TemporaryDirectory(prefix="ida-mcp-stable-api-") as temporary:
        directory = Path(temporary)
        database = directory / "mini.i64"
        shutil.copy2(fixture, database)
        client = Client(binary, directory)
        try:
            inventory = client.request("tools/list", {})["result"]["tools"]
            assert_inventory(inventory, tools)
            save = next(tool for tool in inventory if tool["name"] == "save_idb")
            assert save["annotations"]["readOnlyHint"] is False, save
            converted = decode(client.call("int_convert", {"inputs": ["0x41", "0b10"]}))
            assert [entry["value"] for entry in converted["results"]] == [65, 2], converted
            decode(client.call("open_idb", {"path": str(database)}))
            arguments = {"filter": "interesting_function", "limit": 10}
            functions = decode(client.call("list_funcs", arguments))
            assert functions == decode(client.call("list_functions", arguments)), functions
            assert functions["functions"], functions
            address = functions["functions"][0]["address"]
            for bits in (8, 16, 32, 64):
                single = decode(client.call(f"get_u{bits}", {"address": address}))
                batch = decode(client.call(f"get_u{bits}", {"address": [address, address]}))
                assert [entry["value"] for entry in batch["results"]] == [single, single], batch
            decode(client.call("save_idb", {}))
            decode(client.call("close_idb", {}))
        except BaseException:
            print(client.log_path.read_text(encoding="utf-8", errors="replace"))
            raise
        finally:
            client.finish()
        assert client.process.returncode == 0, client.process.returncode

        modes = [("workspace", ("--workspace",), False)]
        if sys.platform == "darwin" and platform.machine() == "arm64":
            modes.append(("workspace-debugger", ("--workspace", "--enable-debugger"), True))
        for name, args, debugger in modes:
            mode_directory = directory / name
            mode_directory.mkdir()
            client = Client(binary, mode_directory, args)
            try:
                inventory = client.request("tools/list", {})["result"]["tools"]
                assert_inventory(inventory, tools, workspace=True, debugger=debugger)
            except BaseException:
                print(client.log_path.read_text(encoding="utf-8", errors="replace"))
                raise
            finally:
                client.finish()
            assert client.process.returncode == 0, (name, client.process.returncode)
        print("Full stable tool inventory and schemas match v9.4.4 plus the declared changes; "
              "compatibility tools dispatch through the child")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    arguments = parser.parse_args()
    run(arguments.binary.resolve(), arguments.fixture.resolve())
