import argparse
import json
import logging
import os
import platform
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from agent import __version__
from agent.collectors import collect

log = logging.getLogger("cloudsentinel.agent")


def config_path() -> Path:
    override = os.getenv("CLOUDSENTINEL_AGENT_CONFIG")
    if override:
        return Path(override)
    base = os.getenv("LOCALAPPDATA") if os.name == "nt" else None
    return Path(base) / "CloudSentinel" / "agent.json" if base else Path.home() / ".cloudsentinel" / "agent.json"


def save_config(data: dict, path: Path | None = None) -> None:
    path = path or config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh)


def load_config(path: Path | None = None) -> dict:
    path = path or config_path()
    if not path.exists():
        raise SystemExit(f"Not enrolled. Run: python -m agent enroll --server URL --token TOKEN (looked in {path})")
    return json.loads(path.read_text(encoding="utf-8"))


def validate_server(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    local = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and not (parsed.scheme == "http" and local):
        raise SystemExit("Server URL must use https (http is allowed only for localhost).")
    return url.rstrip("/")


class ApiError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(f"HTTP {status}: {detail}")
        self.status = status


def post(server: str, path: str, body: dict, secret: str | None = None) -> dict:
    headers = {"Content-Type": "application/json", "User-Agent": f"cloudsentinel-agent/{__version__}"}
    if secret:
        headers["Authorization"] = f"Bearer {secret}"
    req = urllib.request.Request(f"{server}/api{path}", json.dumps(body).encode(), headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        raise ApiError(exc.code, exc.read().decode(errors="replace")[:300]) from exc
    except urllib.error.URLError as exc:
        raise ApiError(0, str(exc.reason)) from exc


def cmd_enroll(args: argparse.Namespace) -> int:
    server = validate_server(args.server)
    host = platform.node() or "unknown-host"
    result = post(
        server,
        "/agent/enroll",
        {
            "token": args.token,
            "device_name": args.name or host,
            "hostname": host,
            "platform": {"Darwin": "macOS"}.get(platform.system(), platform.system()),
            "platform_version": platform.platform()[:120],
            "agent_version": __version__,
        },
    )
    save_config({"server": server, "device_id": result["device_id"], "device_secret": result["device_secret"]})
    print(f"Enrolled as {result['device_id']}. Credentials saved to {config_path()}")
    return 0


def cmd_once(args: argparse.Namespace) -> int:
    print(json.dumps(collect(), indent=2))
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    cfg = load_config()
    server, secret = cfg["server"], cfg["device_secret"]
    interval, last_posture, failures, loops = 30, 0.0, 0, 0
    while True:
        try:
            hb = post(server, "/agent/heartbeat", {"agent_version": __version__}, secret)
            interval = max(10, int(hb.get("next_heartbeat_seconds", 30)))
            if time.monotonic() - last_posture >= args.posture_interval or last_posture == 0.0:
                res = post(server, "/agent/posture", collect(), secret)
                last_posture = time.monotonic()
                log.info("posture=%s reasons=%s", res.get("posture_status"), res.get("reasons"))
            failures = 0
            delay = interval
        except ApiError as exc:
            if exc.status == 401:
                log.error("Credential rejected (revoked or invalid). Re-enroll. Exiting.")
                return 2
            failures += 1
            delay = min(300, interval * 2**min(failures, 4))
            log.warning("%s; retrying in %ss", exc, delay)
        loops += 1
        if args.max_loops and loops >= args.max_loops:
            return 0
        time.sleep(delay)


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    parser = argparse.ArgumentParser(prog="python -m agent")
    sub = parser.add_subparsers(dest="command", required=True)
    e = sub.add_parser("enroll")
    e.add_argument("--server", required=True)
    e.add_argument("--token", required=True)
    e.add_argument("--name")
    e.set_defaults(func=cmd_enroll)
    sub.add_parser("once", help="Print collected posture without sending").set_defaults(func=cmd_once)
    r = sub.add_parser("run")
    r.add_argument("--posture-interval", type=int, default=300)
    r.add_argument("--max-loops", type=int, default=0, help=argparse.SUPPRESS)
    r.set_defaults(func=cmd_run)
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except ApiError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
