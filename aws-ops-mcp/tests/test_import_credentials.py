import configparser
import json
from unittest.mock import patch

import boto3
from botocore.exceptions import ClientError
from botocore.stub import Stubber
import pytest

from aws_ops_mcp.aws import ec2_client
from aws_ops_mcp.config import resolve
from aws_ops_mcp.import_credentials import ImportFailure, import_batch


def entry(alias="dev", token="example-session-token"):
    return {"alias": alias, "regions": ["us-east-1"], "aws_access_key_id": "example-access-key",
            "aws_secret_access_key": "example-secret-key", "aws_session_token": token}


def test_multiple_accounts_profiles_and_refresh(tmp_path, monkeypatch):
    config, credentials = tmp_path / "accounts.json", tmp_path / "credentials"
    monkeypatch.setenv("AWS_OPS_CONFIG", str(config))
    result = import_batch({"accounts": [entry("dev"), entry("prod")]}, config, credentials,
                          verify=lambda item: "111111111111" if item.alias == "dev" else "222222222222")
    assert len(result["registered"]) == 2
    assert "example-secret-key" not in json.dumps(result)
    assert "example-session-token" not in config.read_text()
    dev, prod = resolve("dev", "us-east-1"), resolve("prod", "us-east-1")
    assert dev.profile != prod.profile
    import_batch({"accounts": [entry("dev", "replacement-token")]}, config, credentials,
                 verify=lambda _: "111111111111")
    profiles = configparser.RawConfigParser()
    profiles.read(credentials)
    assert profiles[dev.profile]["aws_session_token"] == "replacement-token"
    assert profiles[prod.profile]["aws_session_token"] == "example-session-token"


def test_existing_account_cannot_silently_switch(tmp_path):
    config, credentials = tmp_path / "accounts.json", tmp_path / "credentials"
    import_batch({"accounts": [entry()]}, config, credentials, verify=lambda _: "111111111111")
    previous = config.read_bytes(), credentials.read_bytes()
    with pytest.raises(ImportFailure, match="account_mismatch"):
        import_batch({"accounts": [entry()]}, config, credentials, verify=lambda _: "222222222222")
    assert previous == (config.read_bytes(), credentials.read_bytes())


def test_failed_batch_writes_no_account_or_credentials(tmp_path):
    def verify(item):
        if item.alias == "prod":
            raise ClientError({"Error": {"Code": "ExpiredToken", "Message": "never expose token"}}, "GetCallerIdentity")
        return "111111111111"
    config, credentials = tmp_path / "accounts.json", tmp_path / "credentials"
    with pytest.raises(ImportFailure, match="authentication_expired_or_invalid") as error:
        import_batch({"accounts": [entry("dev"), entry("prod")]}, config, credentials, verify=verify)
    assert "never expose" not in str(error.value)
    assert not config.exists() and not credentials.exists()


@pytest.mark.parametrize("bad", [dict(entry(), aws_session_token=""),
    dict(entry(), aws_session_token="injected\n[profile]"), dict(entry(), regions=["*"])])
def test_invalid_input_rejected_before_authentication(tmp_path, bad):
    with pytest.raises(ImportFailure, match="invalid_input"):
        import_batch({"accounts": [bad]}, tmp_path / "config", tmp_path / "credentials",
                     verify=lambda _: pytest.fail("Must not call AWS"))


def test_custom_profile_loads_session_token_and_checks_identity(tmp_path, monkeypatch):
    config, credentials = tmp_path / "accounts.json", tmp_path / "credentials"
    import_batch({"accounts": [entry()]}, config, credentials, verify=lambda _: "111111111111")
    monkeypatch.setenv("AWS_OPS_CONFIG", str(config))
    account = resolve("dev", "us-east-1")
    actual_session = boto3.Session
    captured = []

    def session_factory(**kwargs):
        session = actual_session(**kwargs)
        frozen = session.get_credentials().get_frozen_credentials()
        assert frozen.access_key == "example-access-key"
        assert frozen.token == "example-session-token"
        captured.append(session)
        sts = session.client("sts")
        stub = Stubber(sts)
        stub.add_response("get_caller_identity", {"Account": "111111111111"})
        stub.activate()
        original_client = session.client
        session.client = lambda name, **options: sts if name == "sts" else original_client(name, **options)
        return session

    with patch("aws_ops_mcp.aws.boto3.Session", side_effect=session_factory):
        client = ec2_client(account, "us-east-1")
        assert client.meta.service_model.service_name == "ec2"
        client.close()
    assert len(captured) == 1


def test_same_alias_in_other_configuration_has_separate_profile(tmp_path):
    credentials = tmp_path / "credentials"
    for name, identity in (("first", "111111111111"), ("second", "222222222222")):
        import_batch({"accounts": [entry()]}, tmp_path / name, credentials, verify=lambda _, value=identity: value)
    first = json.loads((tmp_path / "first").read_text())["accounts"]["dev"]
    second = json.loads((tmp_path / "second").read_text())["accounts"]["dev"]
    assert first["profile"] != second["profile"]


def test_overlapping_import_refused(tmp_path):
    (tmp_path / "credentials.import.lock").touch()
    with pytest.raises(ImportFailure, match="import_in_progress"):
        import_batch({"accounts": [entry()]}, tmp_path / "config", tmp_path / "credentials")


def test_original_placeholder_is_replaced_without_manual_editing(tmp_path):
    config = tmp_path / "config"
    config.write_text(json.dumps({"accounts": {"minha-conta": {
        "account_id": "000000000000", "profile": "SUBSTITUA_PELO_SEU_PROFILE", "regions": ["us-east-1"]
    }}}))
    import_batch({"accounts": [entry("minha-conta")]}, config, tmp_path / "credentials",
                 verify=lambda _: "111111111111")
    assert json.loads(config.read_text())["accounts"]["minha-conta"]["account_id"] == "111111111111"
