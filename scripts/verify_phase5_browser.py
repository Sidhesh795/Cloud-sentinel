import subprocess
import sys
import time
from pathlib import Path
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "frontend"


def wait_for(url, seconds=30):
    deadline = time.time() + seconds
    last_error = None
    while time.time() < deadline:
        try:
            with urlopen(url, timeout=3) as response:
                return response.status
        except OSError as exc:
            last_error = exc
            time.sleep(0.5)
    raise RuntimeError(f"{url} did not become ready: {last_error}")


def main():
    backend = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1", "--port", "8000"],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    frontend = subprocess.Popen(
        ["npm.cmd", "run", "dev", "--", "--host", "127.0.0.1", "--port", "5173"],
        cwd=FRONTEND,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        wait_for("http://127.0.0.1:8000/api/health")
        wait_for("http://127.0.0.1:5173")
        result = subprocess.run(
            ["npx.cmd", "playwright", "test", "e2e/phase5.spec.js", "--browser=chromium", "--reporter=line"],
            cwd=FRONTEND,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=90,
        )
        sys.stdout.buffer.write((result.stdout or "").encode("utf-8", errors="replace"))
        if result.stderr:
            sys.stderr.buffer.write(result.stderr.encode("utf-8", errors="replace"))
        return result.returncode
    finally:
        for proc in (frontend, backend):
            proc.terminate()
        for proc in (frontend, backend):
            try:
                proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    raise SystemExit(main())
