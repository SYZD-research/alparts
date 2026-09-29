"""Run an implementation harness; unavailable/incomplete evidence must fail closed."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent
LOADER = REPO / 'packages/server/node_modules/tsx/dist/loader.mjs'


class HarnessError(Exception):
    pass


def run_harness(name: str, payload=None):
    node = shutil.which('node')
    if node is None or not LOADER.exists():
        raise HarnessError('Node >=24.8 and the installed server tsx loader are required')
    try:
        version = subprocess.run([node, '--version'], capture_output=True, text=True, check=True, timeout=10)
        parts = tuple(int(part) for part in version.stdout.strip().lstrip('v').split('.'))
        if parts < (24, 8, 0):
            raise HarnessError(f'Node >=24.8 is required, found {version.stdout.strip()}')
        result = subprocess.run(
            [node, '--import', str(LOADER), str(ROOT / 'conformance' / name)],
            input=json.dumps(payload) if payload is not None else None,
            capture_output=True, text=True, cwd=REPO / 'packages/server', timeout=300,
        )
        if result.returncode:
            raise HarnessError(f'{name} failed: {result.stderr.strip()[-800:]}')
        return json.loads(result.stdout)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise HarnessError(f'{name}: {error}') from error


def require_rows(output, count: int) -> list[dict]:
    if not isinstance(output, list) or len(output) != count or not all(isinstance(row, dict) for row in output):
        raise HarnessError(f'Expected exactly {count} result objects; incomplete or malformed output')
    return output
