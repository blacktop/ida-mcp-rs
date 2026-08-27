#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
python="${PYTHON:-python3}"
command -v "$python" >/dev/null || {
  echo "$python required" >&2
  exit 1
}

exec "$python" "$script_dir/stdio_raw_target.py"
