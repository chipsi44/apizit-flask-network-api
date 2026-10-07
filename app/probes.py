"""Hard wall-clock deadline, including OS DNS resolution; no surviving child process."""

import json
import os
import subprocess
import sys
from pathlib import Path


def run(action, payload):
    environment = {k: os.environ[k] for k in ("SystemRoot", "PATH") if k in os.environ}
    root = str(Path(__file__).resolve().parent.parent)
    environment["PYTHONPATH"] = root
    deadline = min(float(payload.get("timeout", 4)) + 1.5, 9.5)
    process = subprocess.Popen(
        [sys.executable, "-m", "app.worker"],
        cwd=root,
        env=environment,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    try:
        output, _ = process.communicate(
            json.dumps({"action": action, "payload": payload}).encode(), timeout=deadline
        )
        if process.returncode or len(output) > 32768:
            raise ValueError
        result = json.loads(output)
        if not isinstance(result, dict):
            raise ValueError
        return result
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        return {
            "ok": False,
            "error": {
                "type": "timeout",
                "message": "Total probe deadline exceeded (including DNS).",
            },
        }
    except (ValueError, OSError):
        return {"ok": False, "error": {"type": "probe_failure", "message": "Probe failed."}}
