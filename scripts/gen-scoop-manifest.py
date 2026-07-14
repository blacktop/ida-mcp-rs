#!/usr/bin/env python3
"""Generate the Scoop manifest for ida-mcp with IDADIR auto-detection hooks."""

import json
import sys

IDA_PATHS = [
    r"C:\Program Files\IDA Professional 9.4",
    r"C:\Program Files\IDA Pro 9.4",
    r"C:\Program Files\IDA Home 9.4",
    r"C:\Program Files\IDA Essential 9.4",
]


def paths_array_ps() -> str:
    joined = ",".join(f"'{p}'" for p in IDA_PATHS)
    return f"@({joined})"


def build_manifest(version: str, x86_64_sha256: str, arm64_sha256: str) -> dict:
    paths_ps = paths_array_ps()
    base_url = (
        f"https://github.com/blacktop/ida-mcp-rs/releases/download/"
        f"v{version}/ida-mcp_{version}_Windows"
    )
    return {
        "version": version,
        "architecture": {
            "64bit": {
                "url": f"{base_url}_x86_64.zip",
                "bin": ["ida-mcp.exe"],
                "hash": x86_64_sha256,
            },
            "arm64": {
                "url": f"{base_url}_arm64.zip",
                "bin": ["ida-mcp.exe"],
                "hash": arm64_sha256,
            },
        },
        "homepage": "https://github.com/blacktop/ida-mcp-rs",
        "license": "MIT",
        "description": (
            "Headless IDA Pro MCP Server for AI-powered binary analysis"
        ),
        "post_install": [
            f"$idaPaths = {paths_ps}",
            '$found = $idaPaths | Where-Object { Test-Path "$_\\idalib.dll" }'
            " | Select-Object -First 1",
            "$selected = if ($env:IDADIR -and"
            ' (Test-Path "$env:IDADIR\\idalib.dll")) { $env:IDADIR } else {'
            " $found }",
            "if ($selected) {",
            "  if (-not $env:IDADIR) {",
            "    [Environment]::SetEnvironmentVariable('IDADIR', $selected, 'User')",
            "    [Environment]::SetEnvironmentVariable("
            "'IDA_MCP_MANAGED_IDADIR', $selected, 'User')",
            "    $env:IDADIR = $selected",
            "  }",
            "  $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')",
            "  $pathEntries = @($userPath -split ';' | Where-Object { $_ })",
            "  if (-not ($pathEntries -contains $selected)) {",
            "    $newPath = @($pathEntries + $selected) -join ';'",
            "    [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')",
            "    [Environment]::SetEnvironmentVariable("
            "'IDA_MCP_MANAGED_IDA_PATH', $selected, 'User')",
            "  }",
            "  $env:Path = \"$selected;$env:Path\"",
            '  Write-Host "IDA runtime configured from $selected"',
            "} else {",
            "  Write-Host 'IDA Pro not found in standard locations."
            " Set IDADIR and add the same directory to PATH.'",
            "}",
        ],
        "post_uninstall": [
            "$managedIdaDir = [Environment]::GetEnvironmentVariable("
            "'IDA_MCP_MANAGED_IDADIR', 'User')",
            "$current = [Environment]::GetEnvironmentVariable('IDADIR', 'User')",
            "if ($managedIdaDir -and ($current -eq $managedIdaDir)) {",
            "  [Environment]::SetEnvironmentVariable('IDADIR', $null, 'User')",
            "}",
            "[Environment]::SetEnvironmentVariable("
            "'IDA_MCP_MANAGED_IDADIR', $null, 'User')",
            "$managedPath = [Environment]::GetEnvironmentVariable("
            "'IDA_MCP_MANAGED_IDA_PATH', 'User')",
            "if ($managedPath) {",
            "  $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')",
            "  $pathEntries = @($userPath -split ';' | Where-Object {"
            " $_ -and ($_ -ne $managedPath) })",
            "  [Environment]::SetEnvironmentVariable("
            "'Path', ($pathEntries -join ';'), 'User')",
            "}",
            "[Environment]::SetEnvironmentVariable("
            "'IDA_MCP_MANAGED_IDA_PATH', $null, 'User')",
        ],
        "notes": (
            "Requires IDA Pro 9.4 with a valid license."
            " IDADIR is auto-detected from standard install paths."
        ),
    }


def main() -> None:
    if len(sys.argv) != 4:
        print(
            f"Usage: {sys.argv[0]} <version> <x86_64-sha256> <arm64-sha256>",
            file=sys.stderr,
        )
        sys.exit(1)
    version, x86_64_sha256, arm64_sha256 = sys.argv[1:]
    manifest = build_manifest(version, x86_64_sha256, arm64_sha256)
    json.dump(manifest, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
