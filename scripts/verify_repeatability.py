import json
import subprocess
import sys
import time
from pathlib import Path
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]


def request_json(url, method="GET", token=None, body=None):
    payload = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(url, data=payload, headers=headers, method=method)
    with urlopen(request, timeout=8) as response:
        return json.loads(response.read().decode("utf-8"))


def wait_for_backend():
    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            return request_json("http://127.0.0.1:8000/api/health")
        except OSError:
            time.sleep(0.5)
    raise RuntimeError("Backend did not become ready")


def main():
    backend = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1", "--port", "8000"],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        wait_for_backend()
        login = request_json(
            "http://127.0.0.1:8000/api/auth/login",
            method="POST",
            body={"username": "developer01", "password": "CloudDemo123!"},
        )
        token = login["access_token"]
        user_id = login["user"]["id"]
        request_json("http://127.0.0.1:8000/api/simulation/reset", method="POST", token=token, body={"user_id": user_id})

        cycles = []
        for index in range(3):
            attack = request_json("http://127.0.0.1:8000/api/simulation/attack", method="POST", token=token, body={"user_id": user_id})
            attack_matrix = {item["application"]: item["decision"] for item in attack["access_matrix"]}
            if attack["state"] != "COMPROMISED" or attack["risk_level"] not in {"HIGH", "CRITICAL"}:
                raise AssertionError(f"Attack cycle {index + 1} did not compromise state")
            if attack_matrix["Customer Database"] != "DENY" or attack_matrix["Admin Console"] != "DENY":
                raise AssertionError(f"Attack cycle {index + 1} did not restrict critical resources")

            reset = request_json("http://127.0.0.1:8000/api/simulation/reset", method="POST", token=token, body={"user_id": user_id})
            reset_matrix = {item["application"]: item["decision"] for item in reset["access_matrix"]}
            if reset["state"] != "NORMAL" or reset["risk_level"] != "LOW":
                raise AssertionError(f"Reset cycle {index + 1} did not restore normal state")
            if reset_matrix["Email"] != "ALLOW" or reset_matrix["Cloud Storage"] != "ALLOW":
                raise AssertionError(f"Reset cycle {index + 1} did not restore normal access")
            cycles.append({"cycle": index + 1, "attack": attack["risk_level"], "reset": reset["risk_level"]})

        final = request_json(f"http://127.0.0.1:8000/api/simulation/status/{user_id}", token=token)
        print(json.dumps({"cycles": cycles, "final": final}, indent=2))
    finally:
        backend.terminate()
        try:
            backend.wait(timeout=8)
        except subprocess.TimeoutExpired:
            backend.kill()


if __name__ == "__main__":
    main()
