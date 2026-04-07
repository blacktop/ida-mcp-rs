#!/usr/bin/env python3
"""Generate the Scoop manifest for ida-mcp with IDADIR auto-detection hooks."""

import json
import sys

IDA_PATHS = [
    r"C:\Program Files\IDA Professional 9.3",
    r"C:\Program Files\IDA Pro 9.3",
    r"C:\Program Files\IDA Home 9.3",
    r"C:\Program Files\IDA Essential 9.3",
    r"C:\Program Files\IDA Professional 9.2",
    r"C:\Program Files\IDA Pro 9.2",
]


def paths_array_ps() -> str:
    joined = ",".join(f"'{p}'" for p in IDA_PATHS)
    return f"@({joined})"


def build_manifest(version: str, sha256: str) -> dict:
    paths_ps = paths_array_ps()
    url = (
        f"https://github.com/blacktop/ida-mcp-rs/releases/download/"
        f"v{version}/ida-mcp_{version}_Windows_x86_64.zip"
    )
    return {
        "version": version,
        "architecture": {
            "64bit": {
                "url": url,
                "bin": ["ida-mcp.exe"],
                "hash": sha256,
            }
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
            "if ($found -and -not $env:IDADIR) {",
            "  [Environment]::SetEnvironmentVariable('IDADIR', $found, 'User')",
            "  $env:IDADIR = $found",
            '  Write-Host "IDADIR set to $found"',
            "} elseif (-not $found) {",
            "  Write-Host 'IDA Pro not found in standard locations."
            " Set IDADIR manually or add IDA to PATH.'",
            "}",
        ],
        "post_uninstall": [
            f"$idaPaths = {paths_ps}",
            "$current = [Environment]::GetEnvironmentVariable('IDADIR', 'User')",
            "if ($current -and ($idaPaths -contains $current)) {",
            "  [Environment]::SetEnvironmentVariable('IDADIR', $null, 'User')",
            "  Write-Host 'Removed IDADIR environment variable'",
            "}",
        ],
        "notes": (
            "Requires IDA Pro 9.x with a valid license."
            " IDADIR is auto-detected from standard install paths."
        ),
    }


def main() -> None:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <version> <sha256>", file=sys.stderr)
        sys.exit(1)
    version, sha256 = sys.argv[1], sys.argv[2]
    manifest = build_manifest(version, sha256)
    json.dump(manifest, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
