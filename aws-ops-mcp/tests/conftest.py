import json

import pytest


@pytest.fixture(autouse=True)
def offline(monkeypatch, tmp_path):
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.delenv("AWS_OPS_CONFIG", raising=False)
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "no-config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "no-credentials"))


@pytest.fixture
def configured(monkeypatch, tmp_path):
    path = tmp_path / "accounts.json"
    path.write_text(json.dumps({"accounts": {"test": {
        "account_id": "000000000000", "regions": ["us-east-1"]
    }}}), encoding="utf-8")
    monkeypatch.setenv("AWS_OPS_CONFIG", str(path))
    return path
