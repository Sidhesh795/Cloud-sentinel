import json
import platform
import re
import shutil
import subprocess
from datetime import datetime, timezone

from agent import __version__

_WIN_SCRIPT = r"""
$r=@{}
try{$m=Get-MpComputerStatus;$r.av=@{active=[bool]$m.RealTimeProtectionEnabled;name='Microsoft Defender'}}catch{}
try{$r.fw=@(Get-NetFirewallProfile|ForEach-Object{[bool]$_.Enabled})}catch{}
try{$h=Get-HotFix|Where-Object{$_.InstalledOn}|Sort-Object InstalledOn -Descending|Select-Object -First 1;if($h){$r.hotfix=$h.InstalledOn.ToUniversalTime().ToString('o')}}catch{}
try{$v=Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop;$r.bitlocker=[string]$v.ProtectionStatus}catch{}
$r|ConvertTo-Json -Depth 4 -Compress
"""


def _run(cmd: list[str], timeout: int = 30) -> str | None:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout if out.returncode == 0 else None


def patch_state_from_days(days: int | None) -> str | None:
    if days is None:
        return None
    if days <= 45:
        return "UP_TO_DATE"
    if days <= 90:
        return "OUTDATED"
    return "CRITICAL"


def _days_since(iso: str | None) -> int | None:
    if not iso:
        return None
    try:
        when = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0, (datetime.now(timezone.utc) - when).days)


def _windows() -> dict:
    ps = shutil.which("powershell") or shutil.which("pwsh")
    raw = _run([ps, "-NoProfile", "-NonInteractive", "-Command", _WIN_SCRIPT], 60) if ps else None
    try:
        data = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        data = {}
    fw = data.get("fw")
    bl = data.get("bitlocker")
    av = data.get("av") or {}
    days = _days_since(data.get("hotfix"))
    return {
        "firewall_enabled": all(fw) if isinstance(fw, list) and fw else None,
        "encryption_enabled": (bl.strip().lower() in {"on", "1"}) if bl else None,
        "security_product_active": av.get("active"),
        "security_product_name": av.get("name"),
        "last_update_days": days,
    }


def _macos() -> dict:
    fv = _run(["fdesetup", "status"])
    fw = _run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
    return {
        "firewall_enabled": ("enabled" in fw.lower()) if fw else None,
        "encryption_enabled": ("on" in fv.lower()) if fv else None,
    }


def _linux() -> dict:
    fw = None
    ufw = _run(["ufw", "status"])
    if ufw:
        fw = "status: active" in ufw.lower()
    elif shutil.which("systemctl"):
        state = _run(["systemctl", "is-active", "firewalld"])
        fw = True if state and state.strip() == "active" else None
    enc = None
    lsblk = _run(["lsblk", "-J", "-o", "NAME,TYPE,MOUNTPOINT"])
    if lsblk:
        try:
            enc = True if re.search(r'"type":\s*"crypt"', lsblk) else None
        except re.error:
            enc = None
    return {"firewall_enabled": fw, "encryption_enabled": enc}


def collect() -> dict:
    system = platform.system()
    signals = {"Windows": _windows, "Darwin": _macos, "Linux": _linux}.get(system, lambda: {})()
    days = signals.get("last_update_days")
    unknown = sorted(k for k in ("firewall_enabled", "encryption_enabled", "security_product_active") if signals.get(k) is None)
    return {
        "os": {"Darwin": "macOS"}.get(system, system or "Unknown"),
        "os_version": platform.platform()[:120],
        "firewall_enabled": signals.get("firewall_enabled"),
        "encryption_enabled": signals.get("encryption_enabled"),
        "security_product_active": signals.get("security_product_active"),
        "security_product_name": signals.get("security_product_name"),
        "patch_state": patch_state_from_days(days),
        "last_update_days": days,
        "screen_lock_enabled": None,
        "metadata": {
            "hostname": platform.node(),
            "agent_version": __version__,
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "unknown_signals": unknown,
        },
    }
