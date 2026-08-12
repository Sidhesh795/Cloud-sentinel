import json
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "frontend"


def request_json(url, method="GET", token=None, body=None):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = Request(url, data=data, headers=headers, method=method)
    with urlopen(req, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def request_text(url):
    with urlopen(url, timeout=5) as response:
        return response.status, response.read().decode("utf-8", errors="ignore")


def wait_for(name, fn, seconds=30):
    deadline = time.time() + seconds
    last_error = None
    while time.time() < deadline:
        try:
            return fn()
        except (URLError, TimeoutError, ConnectionError, OSError) as exc:
            last_error = exc
            time.sleep(0.5)
    raise RuntimeError(f"{name} did not become ready: {last_error}")


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
        wait_for("backend", lambda: request_json("http://127.0.0.1:8000/api/health"))
        status, html = wait_for("frontend", lambda: request_text("http://127.0.0.1:5173"))
        login = request_json(
            "http://127.0.0.1:8000/api/auth/login",
            method="POST",
            body={"username": "developer01", "password": "CloudDemo123!"},
        )
        token = login["access_token"]
        user_id = login["user"]["id"]
        risk = request_json(f"http://127.0.0.1:8000/api/users/{user_id}/risk")
        posture = request_json(f"http://127.0.0.1:8000/api/users/{user_id}/posture")
        matrix = request_json(f"http://127.0.0.1:8000/api/users/{user_id}/access-matrix", token=token)
        events = request_json("http://127.0.0.1:8000/api/events")
        print(
            json.dumps(
                {
                    "frontend_status": status,
                    "frontend_has_root": 'id="root"' in html,
                    "login_user": login["user"]["username"],
                    "risk": f"{risk['risk_score']} {risk['risk_level']}",
                    "posture_tags": len(posture["security_tags"]),
                    "access_rows": len(matrix),
                    "events": len(events),
                },
                indent=2,
            )
        )
    finally:
        for proc in (frontend, backend):
            proc.terminate()
        for proc in (frontend, backend):
            try:
                proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    main()
