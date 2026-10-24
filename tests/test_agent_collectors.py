import pytest

from agent import cli, collectors


@pytest.mark.parametrize("days,state", [(None, None), (10, "UP_TO_DATE"), (60, "OUTDATED"), (200, "CRITICAL")])
def test_patch_state(days, state):
    assert collectors.patch_state_from_days(days) == state


def test_collect_marks_unknown_as_none(monkeypatch):
    monkeypatch.setattr(collectors.platform, "system", lambda: "Linux")
    monkeypatch.setattr(collectors, "_run", lambda *a, **k: None)
    monkeypatch.setattr(collectors.shutil, "which", lambda *_: None)
    data = collectors.collect()
    assert data["firewall_enabled"] is None and data["encryption_enabled"] is None
    assert "firewall_enabled" in data["metadata"]["unknown_signals"]


def test_windows_parsing(monkeypatch):
    raw = '{"av":{"active":true,"name":"Microsoft Defender"},"fw":[true,true,false],"bitlocker":"On"}'
    monkeypatch.setattr(collectors, "_run", lambda *a, **k: raw)
    monkeypatch.setattr(collectors.shutil, "which", lambda *_: "powershell")
    out = collectors._windows()
    assert out["firewall_enabled"] is False and out["encryption_enabled"] is True and out["security_product_active"] is True


def test_server_url_must_be_https():
    assert cli.validate_server("https://x.example.com/") == "https://x.example.com"
    assert cli.validate_server("http://localhost:8000") == "http://localhost:8000"
    with pytest.raises(SystemExit):
        cli.validate_server("http://evil.example.com")


def test_config_roundtrip(tmp_path):
    p = tmp_path / "a.json"
    cli.save_config({"server": "s", "device_id": "d", "device_secret": "x"}, p)
    assert cli.load_config(p)["device_id"] == "d"
